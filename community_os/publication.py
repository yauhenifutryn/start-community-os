"""Explicit public staging boundary. Never deploy a mixed release directory."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from datetime import datetime
from typing import Sequence

from community_os.privacy_operations import ReleaseEvidence, ReleaseState, evaluate_release
from community_os.privacy_text import STABLE_PSEUDONYM_RE


_PUBLIC_SOURCE_NAMES = frozenset({
    "talent-brief.real.html", "talent-brief.real.pdf",
})
_PUBLIC_PDF_NAME = "partner-talent-brief.pdf"
_PUBLIC_TRANSFORM_VERSION = "neutral-public-artifact-names-v1"
_PUBLIC_BUNDLE_NAMES = frozenset({"index.html", _PUBLIC_PDF_NAME})
_PUBLIC_BUNDLE_NAME_BY_SOURCE = {
    "talent-brief.real.html": "index.html",
    "talent-brief.real.pdf": _PUBLIC_PDF_NAME,
}
_FORBIDDEN_TEXT = (
    re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    re.compile(r"(?:/Users/|/home/|[A-Za-z]:\\Users\\)"),
    re.compile(r"(?:linkedin\.com/in/|github\.com/[A-Za-z0-9-]+)", re.IGNORECASE),
    re.compile(r"(?:operator-state|internal-qa|protected/|raw_payload)", re.IGNORECASE),
    re.compile(r"\bcoresignal\b", re.IGNORECASE),
    STABLE_PSEUDONYM_RE,
)
_BASE_ELEMENT_RE = re.compile(r"<base\b", re.IGNORECASE)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def artifact_set_sha256(paths: Sequence[Path]) -> str:
    """Hash the exact named artifact set so one approval binds every surface."""
    material = {
        path.name: _sha256(path) for path in sorted(paths, key=lambda item: item.name)
    }
    canonical = json.dumps(material, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _copied_artifact_set_sha256(
    sources: Sequence[Path], copied: Sequence[Path],
) -> str:
    """Rebuild the approved source-named set hash from renamed copied bytes."""

    if len(sources) != len(copied):
        raise ValueError("copied publication artifact set is incomplete")
    material = {
        source.name: _sha256(copy)
        for source, copy in zip(sources, copied, strict=True)
    }
    canonical = json.dumps(material, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _pdf_text(path: Path) -> str:
    try:
        result = subprocess.run(
            ["pdftotext", "-raw", str(path), "-"], check=True, capture_output=True,
            text=True, timeout=30,
        )
    except (FileNotFoundError, subprocess.SubprocessError, UnicodeError) as error:
        raise ValueError("PDF privacy extraction failed closed") from error
    raw = path.read_bytes().decode("latin-1", errors="ignore")
    return raw + "\n" + result.stdout


def _validate_relative_pdf_action(html: str, *, pdf_name: str) -> None:
    """Require a bundle-local PDF action whose URL cannot be rebased externally."""

    relative_action = re.compile(
        r"<a\b[^>]*\bhref\s*=\s*([\"'])"
        + re.escape(pdf_name)
        + r"(?:[?#][^\"']*)?\1",
        re.IGNORECASE,
    )
    if _BASE_ELEMENT_RE.search(html) or relative_action.search(html) is None:
        raise ValueError(
            "public HTML requires a relative PDF view or download action"
        )


def _public_html_bytes(source: bytes) -> bytes:
    """Apply the sole approved public transform: remove internal PDF naming."""

    try:
        html = source.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("public HTML is not valid UTF-8") from error
    internal_name = "talent-brief.real.pdf"
    if internal_name not in html:
        raise ValueError("public HTML does not reference the approved source PDF")
    return html.replace(internal_name, _PUBLIC_PDF_NAME).encode("utf-8")


def _install_publication_set(staged: Path, target: Path) -> None:
    """Swap a complete verified directory set, restoring the prior set on failure."""

    backup: Path | None = None
    if target.exists():
        backup = Path(tempfile.mkdtemp(
            prefix=f".{target.name}.backup-", dir=target.parent,
        ))
        backup.rmdir()
        os.replace(target, backup)
    try:
        os.replace(staged, target)
    except Exception as install_error:
        if backup is not None:
            try:
                os.replace(backup, target)
            except Exception as rollback_error:
                raise RuntimeError(
                    "publication set install and rollback both failed"
                ) from rollback_error
        raise install_error
    if backup is not None:
        shutil.rmtree(backup, ignore_errors=True)


def stage_publication(
    release_root: str | Path, destination: str | Path, *, allowlist: Sequence[str],
    evidence: ReleaseEvidence, now: datetime, analytics_key: str | None = None,
) -> dict[str, object]:
    """Copy only approved aggregate artifacts after privacy and approval gates pass."""
    if evaluate_release(evidence, now=now) is not ReleaseState.SAFE_TO_PUBLISH:
        raise PermissionError("publication is blocked until release state and approval are final")
    if analytics_key is not None:
        raise PermissionError("analytics activation is a separate post-publication action")
    names = tuple(allowlist)
    if not names or len(set(names)) != len(names) or any(
        name not in _PUBLIC_SOURCE_NAMES for name in names
    ):
        raise ValueError("publication allowlist contains an unapproved artifact")
    if set(names) != _PUBLIC_SOURCE_NAMES:
        raise ValueError("complete partner artifact set is required for publication")
    root = Path(release_root)
    target = Path(destination)
    sources = [root / name for name in names]
    if any(not path.is_file() for path in sources):
        raise ValueError("publication artifact is missing")
    if not hmac.compare_digest(artifact_set_sha256(sources), evidence.report_hash):
        raise PermissionError("publication approval does not match the current artifact set")
    for path in sources:
        if path.suffix in {".html", ".json"}:
            text = path.read_text(encoding="utf-8")
        elif path.suffix == ".pdf":
            text = _pdf_text(path)
        else:
            text = ""
        if any(pattern.search(text) for pattern in _FORBIDDEN_TEXT):
            raise ValueError("public artifact contains forbidden personal or protected data")
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.is_symlink() or (target.exists() and not target.is_dir()):
        raise ValueError("publication destination is not a trusted directory")
    unexpected = [
        path for path in target.iterdir()
        if path.name not in _PUBLIC_BUNDLE_NAMES | {"publication-manifest.json"}
    ] if target.exists() else []
    if unexpected:
        raise ValueError("publication destination contains an unapproved file")
    with tempfile.TemporaryDirectory(
        prefix="start-community-os-publication-",
        dir=target.parent,
    ) as temporary_directory:
        temporary_root = Path(temporary_directory)
        copied = []
        for source in sources:
            destination_path = (
                temporary_root / _PUBLIC_BUNDLE_NAME_BY_SOURCE[source.name]
            )
            shutil.copy2(source, destination_path)
            copied.append(destination_path)
        # Verify the exact approved source bytes before applying the sole public
        # transform, a deterministic internal-to-neutral PDF name replacement.
        for path in copied:
            if path.suffix in {".html", ".json"}:
                text = path.read_text(encoding="utf-8")
            elif path.suffix == ".pdf":
                text = _pdf_text(path)
            else:
                text = ""
            if any(pattern.search(text) for pattern in _FORBIDDEN_TEXT):
                raise ValueError("public artifact contains forbidden personal or protected data")
            if path.name == "index.html":
                _validate_relative_pdf_action(
                    text, pdf_name="talent-brief.real.pdf",
                )
        if not hmac.compare_digest(
            _copied_artifact_set_sha256(sources, copied), evidence.report_hash,
        ):
            raise PermissionError(
                "publication approval does not match the copied artifact set"
            )
        index_path = temporary_root / "index.html"
        index_path.write_bytes(_public_html_bytes(index_path.read_bytes()))
        final_html = index_path.read_text(encoding="utf-8")
        _validate_relative_pdf_action(final_html, pdf_name=_PUBLIC_PDF_NAME)
        if any(pattern.search(final_html) for pattern in _FORBIDDEN_TEXT):
            raise ValueError("public artifact contains forbidden personal or protected data")
        hashes = {path.name: _sha256(path) for path in sorted(copied)}
        manifest = {
            "analytics_enabled": False,
            "artifact_set_sha256": evidence.report_hash,
            "artifact_hashes": hashes,
            "entrypoint": "index.html",
            "manifest_version": "partner-static-bundle-v1",
            "pdf": _PUBLIC_PDF_NAME,
            "privacy_state": "aggregate_only",
            "public_transform_version": _PUBLIC_TRANSFORM_VERSION,
            "release_state": ReleaseState.SAFE_TO_PUBLISH.value,
        }
        (temporary_root / "publication-manifest.json").write_text(
            json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        temporary_root.chmod(0o755)
        _install_publication_set(temporary_root, target)
    return manifest
