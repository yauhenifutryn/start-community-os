"""Export the HTML artifact through a local Chromium browser."""

from __future__ import annotations

from datetime import UTC, datetime
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import tempfile
import time


MAC_CHROME = Path("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
_PDF_DATE = re.compile(
    rb"/(CreationDate|ModDate) \(D:\d{14}(?:[+-]\d{2}'\d{2}'|Z)\)"
)
_DEFAULT_STABLE_TIMESTAMP = "2000-01-01T00:00:00Z"


def find_chromium() -> str | None:
    configured = os.environ.get("COMMUNITY_OS_CHROMIUM_EXECUTABLE", "").strip()
    if configured:
        candidate = Path(configured).expanduser()
        if not candidate.is_absolute():
            return None
        resolved = candidate.resolve()
        if (
            resolved == MAC_CHROME.resolve()
            or not resolved.is_file()
            or not os.access(resolved, os.X_OK)
        ):
            return None
        return str(resolved)
    for name in ("chrome-headless-shell", "chromium", "chromium-browser"):
        executable = shutil.which(name)
        if not executable:
            continue
        resolved = Path(executable).resolve()
        if resolved != MAC_CHROME.resolve() and os.access(resolved, os.X_OK):
            return str(resolved)
    return None


def _terminate_browser_process_group(process: subprocess.Popen[str]) -> None:
    """Stop the isolated renderer group even if its launcher exited first."""

    pid = getattr(process, "pid", None)
    group_signaled = False
    if isinstance(pid, int) and pid > 0:
        try:
            os.killpg(pid, signal.SIGTERM)
            group_signaled = True
        except (PermissionError, ProcessLookupError):
            pass
    if process.poll() is not None:
        return
    if not group_signaled:
        process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        if group_signaled:
            try:
                os.killpg(pid, signal.SIGKILL)
            except (PermissionError, ProcessLookupError):
                process.kill()
        else:
            process.kill()
        process.wait(timeout=5)


def _normalize_pdf_metadata(path: Path, stable_timestamp: str | None) -> None:
    """Replace Chromium wall-clock metadata without changing PDF structure."""

    raw_timestamp = stable_timestamp or _DEFAULT_STABLE_TIMESTAMP
    try:
        parsed = datetime.fromisoformat(raw_timestamp.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("stable PDF timestamp must be ISO-8601") from error
    if parsed.tzinfo is None:
        raise ValueError("stable PDF timestamp must include a timezone")
    pdf_timestamp = parsed.astimezone(UTC).strftime("D:%Y%m%d%H%M%S+00'00'").encode("ascii")
    payload = path.read_bytes()

    def replace_date(match: re.Match[bytes]) -> bytes:
        replacement = b"/" + match.group(1) + b" (" + pdf_timestamp + b")"
        if len(replacement) != len(match.group(0)):
            raise RuntimeError("PDF metadata rewrite would change byte length and invalidate offsets")
        return replacement

    normalized, count = _PDF_DATE.subn(replace_date, payload)
    if count not in {0, 2}:
        raise RuntimeError(f"unexpected Chromium PDF metadata date count: {count}")
    if normalized == payload:
        return
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_bytes(normalized)
    temporary.chmod(path.stat().st_mode & 0o777)
    temporary.replace(path)


def export_pdf(
    html_path: str | Path,
    pdf_path: str | Path,
    *,
    stable_timestamp: str | None = None,
) -> Path:
    source = Path(html_path).resolve()
    destination = Path(pdf_path).resolve()
    browser = find_chromium()
    if browser is None:
        raise RuntimeError("an isolated Chromium executable is required for PDF export")
    if not source.exists():
        raise FileNotFoundError(source)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.unlink(missing_ok=True)
    with tempfile.TemporaryDirectory(prefix="community-os-chrome-") as profile:
        command = [
            browser, "--headless=new", "--disable-gpu", "--no-pdf-header-footer",
            f"--user-data-dir={profile}", f"--print-to-pdf={destination}", source.as_uri(),
        ]
        process = subprocess.Popen(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            start_new_session=True,
        )
        deadline = time.monotonic() + 90
        error = ""
        try:
            while time.monotonic() < deadline:
                if destination.exists():
                    payload = destination.read_bytes()
                    if payload.startswith(b"%PDF-") and payload.rstrip().endswith(b"%%EOF"):
                        break
                returncode = process.poll()
                if returncode is not None:
                    _, error = process.communicate()
                    if returncode != 0:
                        raise RuntimeError(f"PDF export failed: {error.strip()}")
                    # Chrome's parent can exit before its renderer child has
                    # atomically finished the file. A clean exit is therefore
                    # not sufficient; keep waiting for a complete PDF marker.
                time.sleep(0.05)
            else:
                raise RuntimeError("PDF export timed out before a complete PDF was written")
        finally:
            _terminate_browser_process_group(process)
    _normalize_pdf_metadata(destination, stable_timestamp)
    return destination
