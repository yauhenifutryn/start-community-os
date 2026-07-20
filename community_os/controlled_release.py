"""Lazy production wiring for the protected, approval-bound release action."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
import hashlib
import hmac
from html import unescape
from html.parser import HTMLParser
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import subprocess
import tempfile
import time
from typing import Callable, Mapping, Sequence

from community_os.enrichment.cache import CanonicalJsonCache
from community_os.enrichment.classification import ProcessorApproval, SemanticClassifier
from community_os.enrichment.coresignal import CoresignalAdapter
from community_os.enrichment.evidence_vault import ProtectedEvidenceVault
from community_os.enrichment.gates import CoresignalGate, PublicSourceGate
from community_os.enrichment.github import GitHubAdapter
from community_os.enrichment.openai_classification import (
    OpenAIHTTPSResponsesTransport, OpenAIResponsesProvider,
)
from community_os.enrichment.openai_rich_semantic_assessment import (
    OpenAIRichSemanticAssessmentProvider,
)
from community_os.enrichment.public_pages import PublicPageAdapter
from community_os.enrichment.state import StageStatus
from community_os.enrichment.transport import PinnedHttpsTransport
from community_os.coresignal_career_evaluation import (
    CoresignalCareerEvaluationStore,
)
from community_os.event_approval import validate_event_approval_record
from community_os.event_definition import EventDefinition
from community_os.release_operations import (
    Operation, ProductionOperationRegistry, ReconciliationInputs, build_adapter_service,
    build_local_classification_service, build_reconcile_service,
    build_reviewed_override, build_rich_semantic_proposal_service,
    load_reviewed_classification_projection, rich_semantic_subject_ref,
    _application_subject_identity_literals, _rich_identity_corpus,
)


def _now() -> datetime:
    return datetime.now(UTC)


def load_transient_github_token(*, runner: Callable[..., object] = subprocess.run) -> str | None:
    """Read an authenticated gh credential into memory without printing or persisting it."""
    try:
        result = runner(
            ["gh", "auth", "token"], capture_output=True, text=True,
            timeout=5, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if getattr(result, "returncode", 1) != 0:
        return None
    token = str(getattr(result, "stdout", "")).strip()
    return token or None


def resolve_github_token(
    managed_token: str | None, supplier: Callable[[], str | None],
) -> str:
    """Resolve one in-memory GitHub credential, failing before network transport."""
    token = managed_token.strip() if isinstance(managed_token, str) else ""
    if not token:
        supplied = supplier()
        token = supplied.strip() if isinstance(supplied, str) else ""
    if not token:
        raise PermissionError("GitHub enrichment requires an authenticated gh credential")
    return token


def _authoritative_person_projection(
    state: object,
    *,
    semantic_aggregate: Mapping[str, object] | None,
    pseudonym_secret: bytes,
    application_loader: Callable[[object], Sequence[Mapping[str, object]]],
) -> Mapping[str, Mapping[str, set[str]]] | None:
    """Use one classification authority, never merge legacy and rich paths."""

    if semantic_aggregate is not None:
        return None
    return load_reviewed_classification_projection(
        state,
        pseudonym_secret=pseudonym_secret,
        application_loader=application_loader,
    )


def finalize_reviewed_evidence(
    *, vault: ProtectedEvidenceVault, caches: Sequence[CanonicalJsonCache],
    projection: Mapping[str, Mapping[str, set[str]]],
    semantic_projection: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Bind deletion receipts to every durable reviewed output, then clear caches."""
    serializable = {
        subject: {dimension: sorted(labels) for dimension, labels in sorted(dimensions.items())}
        for subject, dimensions in sorted(projection.items())
    }
    semantic_projection_sha256 = (
        hashlib.sha256(json.dumps(
            semantic_projection,
            allow_nan=False,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")).hexdigest()
        if semantic_projection is not None else None
    )
    projection_sha256 = hashlib.sha256(json.dumps(
        {
            "binding_version": "reviewed-evidence-output-v2",
            "classification_projection": serializable,
            "semantic_projection_sha256": semantic_projection_sha256,
        },
        ensure_ascii=True, sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")).hexdigest()
    receipts = vault.delete_all(
        reason="reviewed_projection", projection_sha256=projection_sha256,
    )
    cache_deleted = sum(cache.delete_all() for cache in caches)
    return {
        "projection_sha256": projection_sha256,
        "semantic_projection_sha256": semantic_projection_sha256,
        "raw_evidence_deleted": len(receipts),
        "transient_cache_deleted": cache_deleted,
    }


@dataclass(frozen=True)
class ControlledReleaseRuntime:
    approval_bundle: Path
    pseudonym_secret: bytes = field(repr=False)
    event_definition: EventDefinition | None = field(default=None, repr=False)
    github_token: str | None = field(default=None, repr=False)
    coresignal_token: str | None = field(default=None, repr=False)
    openai_api_key: str | None = field(default=None, repr=False)
    coresignal_career_evaluation_root: Path | None = field(
        default=None, repr=False,
    )
    github_token_supplier: Callable[[], str | None] = field(
        default=load_transient_github_token, repr=False, compare=False,
    )
    openai_model: str = "gpt-5.6-terra"
    openai_reasoning_effort: str = "medium"
    openai_input_cost_per_million_usd_micros: int | None = None
    openai_output_cost_per_million_usd_micros: int | None = None
    transport_factory: Callable[[], object] = PinnedHttpsTransport
    clock: Callable[[], datetime] = _now
    sleeper: Callable[[float], None] = time.sleep

    def __post_init__(self) -> None:
        object.__setattr__(self, "approval_bundle", Path(self.approval_bundle))
        if self.event_definition is None:
            raise ValueError("controlled release event definition is required")
        if self.coresignal_career_evaluation_root is not None:
            object.__setattr__(
                self,
                "coresignal_career_evaluation_root",
                Path(self.coresignal_career_evaluation_root),
            )
        if len(self.pseudonym_secret) < 16:
            raise ValueError("pseudonym secret must contain at least 16 bytes")
        for value in (
            self.openai_input_cost_per_million_usd_micros,
            self.openai_output_cost_per_million_usd_micros,
        ):
            if value is not None and (
                isinstance(value, bool) or not isinstance(value, int) or value < 0
            ):
                raise ValueError("OpenAI pricing inputs must be non-negative integers")


def _openai_transport(*, region: str) -> OpenAIHTTPSResponsesTransport:
    """Construct only the built-in transport for the reviewed processor route."""
    return OpenAIHTTPSResponsesTransport(region=region)


def _build_rich_semantic_provider(
    runtime: ControlledReleaseRuntime, identity_corpus: tuple[str, ...],
) -> OpenAIRichSemanticAssessmentProvider:
    """Build the single reviewed global rich-semantic provider posture."""
    if not runtime.openai_api_key:
        raise PermissionError("OpenAI API key is missing from the managed runtime secret")
    if not identity_corpus:
        raise PermissionError("rich semantic identity corpus is empty")
    return OpenAIRichSemanticAssessmentProvider(
        api_key=runtime.openai_api_key,
        sleeper=runtime.sleeper,
        known_identity_literals=identity_corpus,
        model=runtime.openai_model,
        reasoning_effort=runtime.openai_reasoning_effort,
        transport=_openai_transport(region="global"),
        region="global",
    )


def persist_internal_rich_semantic_aggregate(
    state: object,
    *,
    expected_subject_refs: Sequence[str] | None = None,
    binding_context: Mapping[str, str] | None = None,
    generated_at: datetime | None = None,
    minimum_group_size: int = 5,
    membership_by_subject: Mapping[str, Mapping[str, str]] | None = None,
    reviewed_cohort_totals: Mapping[str, int] | None = None,
) -> dict[str, object] | None:
    """Persist a private non-release aggregate only after every rich review finalizes."""
    path = Path(getattr(state, "root")) / "protected" / "rich-semantic-internal.aggregate.json"
    cohort_path = path.with_name(
        "rich-semantic-internal.cohorts.aggregate.json",
    )
    cases = tuple(
        case for case in getattr(state, "review_repository").list(kind="classification")
        if case.version == "rich_semantic_review_v1"
    )
    if not cases:
        try:
            for stale_path in (path, cohort_path):
                if stale_path.is_symlink() or stale_path.is_file():
                    stale_path.unlink()
                elif stale_path.exists():
                    raise PermissionError("stale rich semantic aggregate path is unsafe")
        except OSError as error:
            raise PermissionError("stale rich semantic aggregate could not be removed") from error
        if any(stale_path.is_symlink() or stale_path.exists() for stale_path in (path, cohort_path)):
            raise PermissionError("stale rich semantic aggregate could not be removed")
        return None
    if any(case.status != "resolved" for case in cases):
        raise PermissionError("rich semantic review remains open")
    store = getattr(state, "rich_semantic_reviews")
    finalized = store.finalized_case_codes()
    expected = frozenset(case.case_code for case in cases)
    if finalized != expected:
        raise PermissionError("rich semantic reviewed facts are incomplete")
    if (
        expected_subject_refs is None
        or binding_context is None
        or generated_at is None
    ):
        raise PermissionError("rich semantic authoritative population context is missing")
    aggregate = store.build_population_aggregate(
        expected_subject_refs=tuple(expected_subject_refs),
        binding_context=binding_context,
        generated_at=generated_at,
        minimum_group_size=minimum_group_size,
    )
    cohort_bundle = None
    if membership_by_subject is not None:
        cohort_bundle = store.build_population_aggregate(
            expected_subject_refs=tuple(expected_subject_refs),
            binding_context=binding_context,
            generated_at=generated_at,
            minimum_group_size=minimum_group_size,
            membership_by_subject=membership_by_subject,
            reviewed_cohort_totals=reviewed_cohort_totals,
        )
        if (
            not isinstance(cohort_bundle, dict)
            or tuple(cohort_bundle) != ("all", "accepted", "attended")
            or not isinstance(aggregate, dict)
        ):
            raise PermissionError("rich semantic cohort aggregate is invalid")
        cohort_bundle = {**cohort_bundle, "all": aggregate}
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.parent.chmod(0o700)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(
        json.dumps(
            aggregate, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
            allow_nan=False,
        ) + "\n",
        encoding="utf-8",
    )
    temporary.chmod(0o600)
    temporary.replace(path)
    if cohort_bundle is not None:
        cohort_temporary = cohort_path.with_name(cohort_path.name + ".tmp")
        cohort_temporary.write_text(
            json.dumps(
                cohort_bundle,
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ) + "\n",
            encoding="utf-8",
        )
        cohort_temporary.chmod(0o600)
        cohort_temporary.replace(cohort_path)
        cohort_path.chmod(0o600)
    else:
        cohort_path.unlink(missing_ok=True)
    return aggregate


def _load_bundle(path: Path) -> dict[str, object]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite,
        )
    except PermissionError:
        raise
    except (OSError, json.JSONDecodeError) as error:
        raise PermissionError("controlled release approval bundle is missing or unreadable") from error
    expected = {
        "bundle_version", "coresignal", "generated_at", "publication_approval",
        "event_approval", "privacy_operations", "public_sources", "semantic_processor",
    }
    if not isinstance(value, dict) or set(value) != expected:
        raise PermissionError("controlled release approval bundle has invalid keys")
    if value["bundle_version"] != "controlled-release-v2":
        raise PermissionError("controlled release approval bundle version is unsupported")
    try:
        generated = datetime.fromisoformat(str(value["generated_at"]).replace("Z", "+00:00"))
    except ValueError as error:
        raise PermissionError("controlled release generation timestamp is invalid") from error
    if generated.tzinfo is None:
        raise PermissionError("controlled release generation timestamp requires a timezone")
    sources = value["public_sources"]
    if not isinstance(sources, dict) or set(sources) != {"github", "public_pages"}:
        raise PermissionError("public-source approval records are incomplete")
    if sources["github"] is None:
        raise PermissionError("GitHub public-source approval is required")
    if not isinstance(sources["github"], dict):
        raise PermissionError("GitHub public-source approval is invalid")
    if sources["public_pages"] is not None and not isinstance(
        sources["public_pages"], dict,
    ):
        raise PermissionError("public-page approval must be a record or explicit null")
    if not isinstance(value["event_approval"], dict):
        raise PermissionError("controlled release event approval is invalid")
    return value


def _replace_controlled_release_bundle(path: str | Path, payload: bytes) -> None:
    """Replace one existing private approval bundle without following temp links."""

    target = Path(path)
    if not isinstance(payload, bytes) or not payload:
        raise ValueError("controlled release approval payload is invalid")
    parent = target.parent
    if parent.is_symlink() or not parent.is_dir():
        raise PermissionError("controlled release approval directory is unsafe")
    directory_descriptor = os.open(
        parent,
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0),
    )
    temporary_name = f".{target.name}.{secrets.token_hex(12)}.tmp"
    file_descriptor: int | None = None
    try:
        metadata = os.stat(
            target.name,
            dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
        if not stat.S_ISREG(metadata.st_mode):
            raise PermissionError("controlled release approval bundle is unsafe")
        file_descriptor = os.open(
            temporary_name,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=directory_descriptor,
        )
        os.fchmod(file_descriptor, 0o600)
        view = memoryview(payload)
        written = 0
        while written < len(view):
            count = os.write(file_descriptor, view[written:])
            if count <= 0:
                raise OSError("controlled release approval write made no progress")
            written += count
        os.fsync(file_descriptor)
        os.close(file_descriptor)
        file_descriptor = None
        os.replace(
            temporary_name,
            target.name,
            src_dir_fd=directory_descriptor,
            dst_dir_fd=directory_descriptor,
        )
        os.fsync(directory_descriptor)
    except BaseException:
        if file_descriptor is not None:
            os.close(file_descriptor)
        try:
            os.unlink(temporary_name, dir_fd=directory_descriptor)
        except FileNotFoundError:
            pass
        raise
    finally:
        os.close(directory_descriptor)


def _bundle_disabled_optional_stages(
    bundle: Mapping[str, object],
) -> tuple[str, ...]:
    public_sources = bundle.get("public_sources")
    if not isinstance(public_sources, dict):
        raise PermissionError("public-source approval records are incomplete")
    return ("public_pages",) if public_sources.get("public_pages") is None else ()


class _ControlledReleaseOperationFactory:
    """Callable factory with an approval-bound, non-secret optional-stage policy."""

    def __init__(
        self,
        approval_bundle: Path,
        builder: Callable[[object, dict[str, object]], Mapping[str, Operation]],
    ) -> None:
        self._approval_bundle = approval_bundle
        self._builder = builder
        self._bound_disabled_optional_stages: tuple[str, ...] | None = None

    def _validate_current_policy(
        self,
        bundle: Mapping[str, object],
    ) -> tuple[str, ...]:
        current = _bundle_disabled_optional_stages(bundle)
        if (
            self._bound_disabled_optional_stages is not None
            and current != self._bound_disabled_optional_stages
        ):
            raise PermissionError(
                "optional-stage approval changed; restart the release operator",
            )
        return current

    @property
    def disabled_optional_stages(self) -> tuple[str, ...] | None:
        # Keep operator startup lazy. The policy becomes authoritative only when
        # this factory successfully validates the approval bundle in __call__.
        return self._bound_disabled_optional_stages

    def __call__(self, state: object) -> Mapping[str, Operation]:
        bundle = _load_bundle(self._approval_bundle)
        current_policy = self._validate_current_policy(bundle)
        operations = self._builder(state, bundle)
        if self._bound_disabled_optional_stages is None:
            self._bound_disabled_optional_stages = current_policy
        return operations


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise PermissionError(f"controlled release contains duplicate key: {key}")
        result[key] = value
    return result


def _reject_nonfinite(value: str) -> None:
    raise PermissionError(f"controlled release contains non-finite value: {value}")


def _timestamp(value: object, field: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError as error:
        raise PermissionError(f"{field} is invalid") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise PermissionError(f"{field} requires a timezone")
    return parsed


def _validate_privacy_operations(
    value: object,
    *,
    definition: EventDefinition,
) -> None:
    if not isinstance(value, dict) or set(value) != {
        "accountable_owner", "approval", "allowed_uses", "excluded_subject_refs",
        "notice_sent_at", "notice_version", "retention_deadline", "rights",
    }:
        raise PermissionError("privacy operations record is incomplete")
    if not isinstance(value["accountable_owner"], str) or not re.fullmatch(
        r"[a-z][a-z0-9_]{2,63}", value["accountable_owner"],
    ):
        raise PermissionError("privacy operations accountable owner is invalid")
    if not isinstance(value["notice_version"], str) or not re.fullmatch(
        r"[a-z][a-z0-9_.-]{2,63}", value["notice_version"],
    ):
        raise PermissionError("privacy notice version is invalid")
    _timestamp(value["notice_sent_at"], "privacy notice timestamp")
    _timestamp(value["retention_deadline"], "privacy retention deadline")
    approval = value["approval"]
    if not isinstance(approval, dict) or set(approval) != {
        "actor_code", "approved_at", "expires_at",
    }:
        raise PermissionError("privacy processing approval is incomplete")
    approved_at = _timestamp(approval["approved_at"], "privacy processing approval")
    expires_at = _timestamp(approval["expires_at"], "privacy processing approval expiry")
    if expires_at <= approved_at:
        raise PermissionError("privacy processing approval expiry is invalid")
    if not isinstance(approval["actor_code"], str) or not re.fullmatch(
        r"[a-z][a-z0-9_]{2,63}", approval["actor_code"],
    ):
        raise PermissionError("privacy processing approver is invalid")
    configured_sources = {source.role for source in definition.sources}
    expected_sources = configured_sources | {
        "classification", "coresignal", "github", "partner_report", "public_pages",
    }
    uses = value["allowed_uses"]
    if not isinstance(uses, dict) or set(uses) != expected_sources:
        raise PermissionError("privacy allowed-use inventory is incomplete")
    if any(
        not isinstance(items, list) or not items
        or any(not isinstance(item, str) or not item for item in items)
        for items in uses.values()
    ):
        raise PermissionError("privacy allowed-use inventory is invalid")
    expected_uses = {
        **{source: ["aggregate"] for source in configured_sources},
        "github": ["classify"], "public_pages": ["classify"],
        "coresignal": ["classify"], "classification": ["aggregate"],
        "partner_report": ["publish"],
    }
    if uses != expected_uses:
        raise PermissionError("privacy allowed uses exceed the release allowlist")
    rights = value["rights"]
    if not isinstance(rights, dict) or set(rights) != {
        "deletion_status", "exclusion_status", "objection_status", "reconciled",
        "suppression_status",
    }:
        raise PermissionError("privacy rights record is incomplete")
    if rights != {
        "deletion_status": "not_requested", "exclusion_status": "included",
        "objection_status": "none", "reconciled": True,
        "suppression_status": "not_requested",
    }:
        raise PermissionError("privacy rights are unresolved")
    excluded = value["excluded_subject_refs"]
    if not isinstance(excluded, list) or any(not isinstance(item, str) for item in excluded):
        raise PermissionError("privacy excluded-subject registry is invalid")
    try:
        from community_os.privacy_operations import build_subject_exclusion_plan

        build_subject_exclusion_plan(
            excluded_subject_refs=excluded, known_subject_refs=excluded,
        )
    except ValueError as error:
        raise PermissionError("privacy excluded-subject registry is invalid") from error


def _record_gate(state: object, stage: str, gate: object, *, now: datetime) -> None:
    pipeline = getattr(state, "pipeline")
    current = pipeline.stage(stage)
    expected = getattr(gate, "authorization_hash")(stage, now=now)
    if current.status is not StageStatus.LOCKED and (
        current.authorization_hash is None
        or not hmac.compare_digest(current.authorization_hash, expected)
    ):
        getattr(state, "revoke_stage_authorization")(
            stage, reason_code="authorization_replaced",
        )
        current = pipeline.stage(stage)
    if current.status is StageStatus.LOCKED:
        if stage == "coresignal":
            getattr(state, "record_coresignal_authorization")(gate, now=now)
        else:
            getattr(state, "record_public_source_authorization")(stage, gate, now=now)
        return
    if not hmac.compare_digest(str(current.authorization_hash), expected):
        raise PermissionError(f"persisted {stage} authorization does not match the approval bundle")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


_LOCAL_PARTNER_SHARE_NAMES = (
    "talent-brief.real.html",
    "talent-brief.real.pdf",
)
_LOCAL_PARTNER_SHARE_DIRECTORY = "partner-share"


def withdraw_local_partner_share(release_root: str | Path) -> None:
    """Remove the local share boundary before rebuilding or invalidating it."""

    configured = Path(release_root)
    if configured.is_symlink():
        raise PermissionError("local partner share release root is unsafe")
    if not configured.exists():
        return
    if not configured.is_dir():
        raise PermissionError("local partner share release root is unsafe")
    target = configured.resolve() / _LOCAL_PARTNER_SHARE_DIRECTORY
    if target.is_symlink() or (target.exists() and not target.is_dir()):
        target.unlink(missing_ok=True)
    elif target.is_dir():
        shutil.rmtree(target)


def _scan_local_partner_share(
    sources: Mapping[str, Path],
) -> dict[str, str]:
    """Fail closed unless the exact four share surfaces are safe to copy."""

    from community_os.publication import _FORBIDDEN_TEXT, _pdf_text

    if tuple(sources) != _LOCAL_PARTNER_SHARE_NAMES:
        raise PermissionError("local partner share artifact set is incomplete")
    hashes: dict[str, str] = {}
    for name in _LOCAL_PARTNER_SHARE_NAMES:
        path = sources[name]
        if path.name != name or path.is_symlink() or not path.is_file():
            raise PermissionError("local partner share artifact is missing or unsafe")
        try:
            text = (
                _pdf_text(path)
                if path.suffix == ".pdf"
                else path.read_text(encoding="utf-8")
            )
        except (OSError, UnicodeError, ValueError) as error:
            raise PermissionError(
                "local partner share privacy scan failed closed",
            ) from error
        if any(pattern.search(text) for pattern in _FORBIDDEN_TEXT):
            raise PermissionError(
                "local partner share contains forbidden personal or protected data",
            )
        hashes[name] = _sha256(path)
    return hashes


def materialize_local_partner_share(
    release_root: str | Path,
    *,
    sources: Mapping[str, Path] | None = None,
) -> dict[str, object]:
    """Create one local folder containing only privacy-scanned partner files."""

    root = Path(release_root)
    if root.is_symlink() or (root.exists() and not root.is_dir()):
        raise PermissionError("local partner share root is unsafe")
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    if root.is_symlink() or not root.is_dir():
        raise PermissionError("local partner share root is unsafe")
    root = root.resolve()
    target = root / _LOCAL_PARTNER_SHARE_DIRECTORY
    withdraw_local_partner_share(root)
    selected = dict(sources or {
        name: root / name for name in _LOCAL_PARTNER_SHARE_NAMES
    })
    ordered = {name: selected[name] for name in _LOCAL_PARTNER_SHARE_NAMES} if (
        set(selected) == set(_LOCAL_PARTNER_SHARE_NAMES)
    ) else selected
    source_hashes = _scan_local_partner_share(ordered)
    try:
        with tempfile.TemporaryDirectory(
            prefix=".partner-share-", dir=root,
        ) as directory:
            staged = Path(directory)
            for name in _LOCAL_PARTNER_SHARE_NAMES:
                copied = staged / name
                shutil.copyfile(ordered[name], copied)
                copied.chmod(0o600)
            staged.chmod(0o700)
            copied_sources = {
                name: staged / name for name in _LOCAL_PARTNER_SHARE_NAMES
            }
            copied_hashes = _scan_local_partner_share(copied_sources)
            if copied_hashes != source_hashes:
                raise PermissionError("local partner share changed while copying")
            os.replace(staged, target)
    except Exception:
        withdraw_local_partner_share(root)
        raise
    return {
        "artifact_hashes": source_hashes,
        "directory": str(target),
        "state": "privacy_scanned",
    }


def _observed_record_count(records: list[object], *, stage: str) -> int:
    count = 0
    for record in records:
        if not isinstance(record, dict) or record.get("state") not in {"observed", "unknown"}:
            raise ValueError(f"protected {stage} coverage record is invalid")
        if record["state"] == "observed":
            count += 1
    return count


def _is_semantic_binding_promotion(
    candidate: object, approved: object,
) -> bool:
    """Allow only the approval-state delta for the exact same candidate."""

    if not isinstance(candidate, dict) or not isinstance(approved, dict):
        return False
    mutable = frozenset({
        "human_release_approval_sha256", "projection_version", "release_eligible",
    })
    if (
        set(candidate) != set(approved)
        or candidate.get("projection_version") != "partner-semantic-candidate-v2"
        or approved.get("projection_version") != "partner-semantic-summary-v3"
        or candidate.get("release_eligible") is not False
        or approved.get("release_eligible") is not True
        or candidate.get("human_release_approval_sha256") is not None
        or re.fullmatch(
            r"[0-9a-f]{64}",
            str(approved.get("human_release_approval_sha256") or ""),
        ) is None
    ):
        return False
    return all(
        candidate[key] == approved[key]
        for key in candidate.keys() - mutable
    )


def render_current_report_bundle(
    release_root: str | Path,
    *,
    semantic_aggregate_path: str | Path | None = None,
    semantic_approval_path: str | Path | None = None,
    semantic_approval_secret: bytes | None = None,
    semantic_authoritative_context: Mapping[str, object] | None = None,
    now: datetime | None = None,
) -> list[dict[str, object]]:
    """Rebuild a local report candidate from the current aggregate contracts."""
    from community_os.partner_report import render_partner_talent_report
    from community_os.partner_report_presentation import (
        load_or_create_partner_report_presentation,
        partner_report_presentation_sha256,
    )
    from community_os.partner_semantic_projection import (
        build_protected_partner_semantic_cohort_candidate_bundle,
        load_partner_semantic_summary,
        load_protected_partner_semantic_candidate_summary,
        semantic_summary_manifest_binding,
    )
    from community_os.pdf_export import export_pdf
    from community_os.real_report import _code_provenance, _reproduction_guide
    from community_os.report_contract import load_report_contract
    from community_os.talent_intelligence_contract import (
        load_talent_intelligence_contract,
    )

    configured_root = Path(release_root)
    if configured_root.is_symlink() or not configured_root.is_dir():
        raise PermissionError("protected release root is unsafe")
    root = configured_root.resolve()
    v1_name = "talent-intelligence-v1.real.aggregate.json"
    v3_name = "talent-report-v3.real.aggregate.json"
    html_name = "talent-brief.real.html"
    pdf_name = "talent-brief.real.pdf"
    manifest_path = root / "talent-report-v3.real.manifest.json"
    guide_name = "reproduce-real-report.md"
    presentation_name = "partner-report-presentation.json"
    presentation_path = root / presentation_name
    existing_targets = tuple(
        root / name
        for name in (
            v1_name, v3_name, html_name, pdf_name, guide_name,
            manifest_path.name,
            presentation_name,
        )
    )
    if any(
        path.is_symlink() or (path.exists() and not path.is_file())
        for path in existing_targets
    ):
        raise PermissionError("protected report target is unsafe")
    withdraw_local_partner_share(root)
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        output_hashes = manifest["output_hashes"]
    except (OSError, KeyError, TypeError, json.JSONDecodeError) as error:
        raise PermissionError("protected release manifest is unreadable") from error
    if not isinstance(manifest, dict) or not isinstance(output_hashes, dict):
        raise PermissionError("protected release manifest is unreadable")
    release_context = manifest.get("release_context")
    if release_context is not None:
        if not isinstance(release_context, dict):
            raise PermissionError("protected release context is unreadable")
        release_context["code_provenance"] = _code_provenance()
    v1 = load_talent_intelligence_contract(root / v1_name)
    v3 = load_report_contract(root / v3_name)
    semantic_path = (
        Path(semantic_aggregate_path) if semantic_aggregate_path is not None
        else root.parent / "rich-semantic-internal.aggregate.json"
    )
    approval_path = (
        Path(semantic_approval_path) if semantic_approval_path is not None
        else root.parent / "semantic-release-approval.json"
    )
    if semantic_approval_path is not None and not approval_path.is_file():
        raise PermissionError("protected semantic release approval is missing")
    semantic_manifest = manifest.get("semantic_enrichment")
    if semantic_aggregate_path is not None or semantic_path.is_file():
        semantic_summary = (
            load_partner_semantic_summary(
                semantic_path,
                approval_path=approval_path,
                now=now or datetime.now(UTC),
                approval_secret=semantic_approval_secret,
            )
            if approval_path.is_file()
            else load_protected_partner_semantic_candidate_summary(semantic_path)
        )
    elif semantic_manifest is not None:
        raise PermissionError("protected semantic enrichment source is missing")
    else:
        semantic_summary = None
    cohort_path = semantic_path.with_name(
        "rich-semantic-internal.cohorts.aggregate.json",
    )
    semantic_cohorts = None
    if cohort_path.is_file():
        if cohort_path.is_symlink() or cohort_path.stat().st_mode & 0o077:
            raise PermissionError("protected semantic cohort bundle is unsafe")
        try:
            protected_cohorts = json.loads(cohort_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise PermissionError(
                "protected semantic cohort bundle is unreadable",
            ) from error
        semantic_cohorts = (
            build_protected_partner_semantic_cohort_candidate_bundle(
                protected_cohorts,
            )
        )
        if (
            semantic_summary is None
            or semantic_cohorts.cohorts[0].summary.aggregate_sha256
            != semantic_summary.aggregate_sha256
        ):
            raise PermissionError(
                "protected semantic cohort bundle does not match approved aggregate",
            )
    semantic_binding = (
        semantic_summary_manifest_binding(semantic_summary)
        if semantic_summary is not None else None
    )
    if semantic_summary is not None:
        presentation = load_or_create_partner_report_presentation(
            presentation_path, semantic_summary=semantic_summary,
        )
    else:
        presentation = None
    partner_share_eligible = (
        semantic_summary is not None
        and semantic_summary.semantic_release_approval_sha256 is not None
    )
    if semantic_manifest is not None and semantic_manifest != semantic_binding:
        if not _is_semantic_binding_promotion(
            semantic_manifest, semantic_binding,
        ):
            raise PermissionError("protected semantic enrichment hash drift")
    semantic_context = None
    if semantic_binding is not None:
        semantic_context = {
            key: semantic_binding[key]
            for key in (
                "event_approval_sha256", "event_definition_sha256", "event_key",
                "population_sha256", "run_sha256", "source_snapshot_sha256",
                "taxonomy_sha256", "taxonomy_version", "total_population",
            )
        }

    expected = (html_name, pdf_name, v1_name, v3_name)
    for name in (v1_name, v3_name):
        path = root / name
        if path.is_symlink() or not path.is_file():
            raise PermissionError("report artifacts are missing: " + name)

    with tempfile.TemporaryDirectory(
        prefix=".report-render-", dir=root.parent,
    ) as directory:
        staging = Path(directory)
        html_staged = staging / html_name
        pdf_staged = staging / pdf_name
        guide_staged = staging / guide_name
        manifest_staged = staging / manifest_path.name
        html_staged.write_text(
            render_partner_talent_report(
                v1, v3, semantic_summary=semantic_summary,
                semantic_cohorts=semantic_cohorts,
                semantic_context=semantic_context,
                presentation=presentation,
            ),
            encoding="utf-8",
        )
        export_pdf(
            html_staged,
            pdf_staged,
            stable_timestamp=v1.metadata.generated_at,
        )
        guide_staged.write_text(
            _reproduction_guide(
                v1.metadata.generated_at,
                semantic_mode=(
                    None if semantic_summary is None
                    else "approved"
                    if semantic_summary.semantic_release_approval_sha256 is not None
                    else "candidate"
                ),
            ),
            encoding="utf-8",
        )
        if not html_staged.is_file() or not pdf_staged.is_file():
            raise PermissionError("report renderer did not produce complete artifacts")

        artifact_paths = {
            html_name: html_staged,
            pdf_name: pdf_staged,
            v1_name: root / v1_name,
            v3_name: root / v3_name,
        }
        _scan_local_partner_share({
            name: artifact_paths[name] for name in _LOCAL_PARTNER_SHARE_NAMES
        })
        artifact_hashes = {
            name: _sha256(path) for name, path in artifact_paths.items()
        }
        if (
            semantic_summary is not None
            and semantic_summary.semantic_release_approval_sha256 is not None
        ):
            bindings = dict(semantic_summary.release_artifact_hashes)
            if semantic_authoritative_context is None:
                raise PermissionError(
                    "approved semantic release requires current operator authority",
                )
            qa_receipt = validate_current_semantic_release_qa(
                root.parent,
                html_path=html_staged,
                pdf_path=pdf_staged,
                authoritative_context=semantic_authoritative_context,
                approval_bound_qa_sha256=str(bindings.get("qa_sha256") or ""),
            )
            if (
                artifact_hashes[html_name] != bindings.get("html_sha256")
                or artifact_hashes[pdf_name] != bindings.get("pdf_sha256")
                or qa_receipt.sha256 != bindings.get("qa_sha256")
            ):
                raise PermissionError(
                    "approved semantic release artifact or QA hash drift",
                )
            from community_os.publication import artifact_set_sha256

            if artifact_set_sha256(tuple(artifact_paths.values())) != bindings.get(
                "report_candidate_sha256",
            ):
                raise PermissionError(
                    "approved semantic release candidate hash drift",
                )

        manifest_hashes = {
            **artifact_hashes,
            guide_name: _sha256(guide_staged),
        }
        manifest["output_hashes"] = {**output_hashes, **manifest_hashes}
        if semantic_summary is None:
            manifest.pop("semantic_enrichment", None)
            manifest.pop("partner_presentation", None)
        else:
            manifest["semantic_enrichment"] = semantic_binding
            manifest["partner_presentation"] = {
                "aggregate_sha256": semantic_summary.aggregate_sha256,
                "presentation_sha256": partner_report_presentation_sha256(
                    presentation,
                ),
                "version": presentation.version,
            }
        manifest_staged.write_text(
            json.dumps(manifest, sort_keys=True, separators=(",", ":")),
            encoding="utf-8",
        )

        replacements = {
            root / html_name: html_staged,
            root / pdf_name: pdf_staged,
            root / guide_name: guide_staged,
            manifest_path: manifest_staged,
        }
        if any(
            target.is_symlink() or (target.exists() and not target.is_file())
            for target in replacements
        ):
            raise PermissionError("protected report target is unsafe")
        snapshots = {
            target: (
                target.exists(),
                target.read_bytes() if target.exists() else b"",
                target.stat().st_mode & 0o777 if target.exists() else 0o600,
            )
            for target in replacements
        }
        try:
            for target, source in replacements.items():
                if target.is_symlink():
                    raise PermissionError("protected report target is an unsafe symlink")
                os.replace(source, target)
                target.chmod(0o600)
            if partner_share_eligible:
                share = materialize_local_partner_share(root)
                expected_share_hashes = {
                    name: artifact_hashes[name]
                    for name in _LOCAL_PARTNER_SHARE_NAMES
                }
                if share["artifact_hashes"] != expected_share_hashes:
                    raise PermissionError("local partner share hash drift")
        except Exception:
            for target, (existed, contents, mode) in snapshots.items():
                if existed:
                    target.write_bytes(contents)
                    target.chmod(mode)
                else:
                    target.unlink(missing_ok=True)
            raise
    return [{
        "artifact_hashes": artifact_hashes,
        "presentation_sha256": (
            partner_report_presentation_sha256(presentation)
            if presentation is not None else None
        ),
        "partner_share_directory": (
            str(root / _LOCAL_PARTNER_SHARE_DIRECTORY)
            if partner_share_eligible else None
        ),
        "state": "complete",
    }]


def _normalized_surface_text(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip().casefold()


_NONRENDERED_HTML_TAGS = frozenset({"script", "style", "template"})
_VOID_HTML_TAGS = frozenset({
    "area", "base", "br", "col", "embed", "hr", "img", "input", "link",
    "meta", "param", "source", "track", "wbr",
})


class _VisibleHTMLTextParser(HTMLParser):
    """Collect text that can contribute to the rendered report surface."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.text: list[str] = []
        self._hidden_stack: list[bool] = []
        self._hidden_depth = 0

    @staticmethod
    def _element_is_hidden(tag: str, attrs: list[tuple[str, str | None]]) -> bool:
        attributes = {
            name.casefold(): "" if value is None else value.casefold()
            for name, value in attrs
        }
        style = attributes.get("style", "")
        return (
            tag in _NONRENDERED_HTML_TAGS
            or "hidden" in attributes
            or "inert" in attributes
            or attributes.get("aria-hidden") == "true"
            or re.search(r"(?:^|;)\s*display\s*:\s*none(?:\s*!important)?\s*(?:;|$)", style)
            is not None
            or re.search(
                r"(?:^|;)\s*visibility\s*:\s*hidden(?:\s*!important)?\s*(?:;|$)",
                style,
            )
            is not None
        )

    def handle_starttag(
        self, tag: str, attrs: list[tuple[str, str | None]],
    ) -> None:
        normalized_tag = tag.casefold()
        hidden = self._hidden_depth > 0 or self._element_is_hidden(
            normalized_tag, attrs,
        )
        if normalized_tag not in _VOID_HTML_TAGS:
            self._hidden_stack.append(hidden)
            if hidden:
                self._hidden_depth += 1

    def handle_endtag(self, tag: str) -> None:
        if not self._hidden_stack:
            return
        if self._hidden_stack.pop():
            self._hidden_depth -= 1

    def handle_startendtag(
        self, tag: str, attrs: list[tuple[str, str | None]],
    ) -> None:
        # A self-closing element has no descendant text and must not alter the
        # visibility stack of its parent.
        return

    def handle_data(self, data: str) -> None:
        if self._hidden_depth == 0:
            self.text.append(data)


class _PDFHeadingParser(HTMLParser):
    """Collect h1/h2 text only from logical PDF pages, not screen-only UI."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.headings: list[str] = []
        self._pdf_depth = 0
        self._tag_stack: list[bool] = []
        self._heading_tag: str | None = None
        self._heading_text: list[str] = []

    def handle_starttag(
        self, tag: str, attrs: list[tuple[str, str | None]],
    ) -> None:
        normalized = tag.casefold()
        starts_page = any(name == "data-pdf-page" for name, _ in attrs)
        inside = self._pdf_depth > 0 or starts_page
        if normalized not in _VOID_HTML_TAGS:
            self._tag_stack.append(starts_page)
            if starts_page:
                self._pdf_depth += 1
        if inside and normalized in {"h1", "h2"} and self._heading_tag is None:
            self._heading_tag = normalized
            self._heading_text = []

    def handle_endtag(self, tag: str) -> None:
        normalized = tag.casefold()
        if normalized == self._heading_tag:
            heading = _normalized_surface_text(" ".join(self._heading_text))
            if heading:
                self.headings.append(heading)
            self._heading_tag = None
            self._heading_text = []
        if self._tag_stack and self._tag_stack.pop():
            self._pdf_depth -= 1

    def handle_data(self, data: str) -> None:
        if self._heading_tag is not None:
            self._heading_text.append(data)


def _pdf_page_headings(html_text: str) -> tuple[str, ...]:
    parser = _PDFHeadingParser()
    parser.feed(html_text)
    parser.close()
    return tuple(dict.fromkeys(parser.headings))


def _normalized_html_surface_text(value: str) -> str:
    parser = _VisibleHTMLTextParser()
    parser.feed(value)
    parser.close()
    return _normalized_surface_text(" ".join(parser.text))


def _release_privacy_minimum(
    aggregate_payloads: Sequence[Mapping[str, object]],
    *, expected_minimum_count: int | None = None,
) -> int:
    """Derive one privacy threshold and optionally bind it to the event input."""

    privacy_records = tuple(payload.get("privacy") for payload in aggregate_payloads)
    if not privacy_records or any(not isinstance(value, Mapping) for value in privacy_records):
        raise PermissionError("aggregate privacy parity is invalid")
    first = dict(privacy_records[0])
    minimum_count = first.get("minimum_count")
    if (
        isinstance(minimum_count, bool)
        or not isinstance(minimum_count, int)
        or minimum_count < 5
    ):
        raise PermissionError("aggregate privacy parity is invalid")
    expected_privacy = {
        "minimum_count": minimum_count,
        "mode": "aggregate_only",
        "pii_included": False,
        "state": "withheld_cells",
    }
    if any(dict(value) != expected_privacy for value in privacy_records):
        raise PermissionError("aggregate privacy parity is invalid")
    if (
        expected_minimum_count is not None
        and minimum_count != expected_minimum_count
    ):
        raise PermissionError("aggregate privacy threshold does not match the event")
    return minimum_count


def _public_headline_counts(
    v1: Mapping[str, object], v3: Mapping[str, object],
) -> dict[str, int | None]:
    try:
        v1_stages = {
            str(item["key"]): item["count"]["value"]
            for item in v1["cohort"]["stages"]
        }
        v3_stages = {
            str(item["key"]): item["count"]["value"]
            for item in v3["attendance_funnel"]["stages"]
        }
        counts = {
            "applied": v1_stages["valid_applicants"],
            "going_accepted": v1_stages["going_accepted"],
            "on_site": v1_stages["on_site"],
        }
    except (KeyError, TypeError, ValueError) as error:
        raise PermissionError("aggregate headline parity is unreadable") from error
    if any(
        value is not None and (isinstance(value, bool) or not isinstance(value, int))
        for value in (*counts.values(), *v3_stages.values())
    ):
        raise PermissionError("aggregate headline parity is unreadable")
    if v3_stages != counts:
        raise PermissionError("aggregate headline parity does not match")
    return counts


_SEMANTIC_REPORT_DIMENSION_LIMITS: dict[str, int | None] = {
    "product_maturity": 0,
    "technical_depth": 0,
    "execution_scope": 0,
    "external_validation": 0,
    "problem_differentiation": 0,
    "technical_methods": 6,
    "demonstrated_capabilities": 6,
    "career_stage": None,
    "founder_state": 5,
    "leadership_state": 5,
    "career_functions": 5,
    "career_delivery": 5,
    "market_domains": 6,
}
_SEMANTIC_REPORT_METRIC_COUNT = 7
_SEMANTIC_REPORT_PUBLIC_GROUP_COUNT = 8


def _semantic_public_group_parity_required(protected_root: str | Path) -> bool:
    """Use legacy public-group claims only when no cohort dashboard exists."""

    cohort_path = (
        Path(protected_root)
        / "rich-semantic-internal.cohorts.aggregate.json"
    )
    if cohort_path.is_symlink():
        raise PermissionError("semantic cohort aggregate is unsafe")
    return not cohort_path.is_file()


def _claim_count_line(value: int, denominator: int) -> str:
    percentage = round(value / denominator * 100) if denominator else 0
    return f"{value} of {denominator} ({percentage}%)"


def _public_funnel_claims(
    headline_counts: Mapping[str, int | None],
) -> list[tuple[str, str]]:
    applied = headline_counts.get("applied")
    accepted = headline_counts.get("going_accepted")
    attendance = headline_counts.get("on_site")
    if (
        isinstance(applied, bool)
        or not isinstance(applied, int)
        or applied < 0
        or isinstance(accepted, bool)
        or not isinstance(accepted, int)
        or accepted < 0
        or (
            attendance is not None
            and (
                isinstance(attendance, bool)
                or not isinstance(attendance, int)
                or attendance < 0
            )
        )
    ):
        raise PermissionError("HTML/PDF text parity claim is invalid")
    claims = [
        ("Applied", f"{applied} people"),
        ("Accepted by organizers", f"{accepted} people"),
        (
            "of applicants",
            f"{round(accepted / applied * 100) if applied else 0}%",
        ),
        (
            "applicants were not in the accepted group",
            str(applied - accepted),
        ),
    ]
    if attendance is None:
        claims.append((
            "Confirmed present at the event", "Attendance count hidden",
        ))
    else:
        claims.extend((
            ("Confirmed present at the event", f"{attendance} people"),
            (
                "accepted participants were confirmed present",
                f"{attendance} of {accepted}",
            ),
            (
                "were not in the reviewed attendance count",
                str(accepted - attendance),
            ),
        ))
    return claims


def _public_semantic_claims(
    semantic_summary: object,
    *,
    include_public_groups: bool = True,
) -> list[tuple[str, str]]:
    claims: list[tuple[str, str]] = []
    metrics = tuple(getattr(semantic_summary, "metrics", ()))
    if len(metrics) != _SEMANTIC_REPORT_METRIC_COUNT:
        raise PermissionError("HTML/PDF text parity claim is invalid")
    for metric in metrics:
        label = str(getattr(metric, "label", ""))
        count = getattr(metric, "count", None)
        denominator = getattr(metric, "denominator", None)
        if count is not None and (
            isinstance(count, bool) or not isinstance(count, int) or count < 0
        ):
            raise PermissionError("HTML/PDF text parity claim is invalid")
        if count is None or count == 0:
            continue
        display = (
            str(count) if denominator is None
            else f"{count} of {denominator}"
        )
        claims.append((label, display))

    public_groups = tuple(getattr(semantic_summary, "public_groups", ()))
    if len(public_groups) != _SEMANTIC_REPORT_PUBLIC_GROUP_COUNT:
        raise PermissionError("HTML/PDF text parity claim is invalid")
    for group in public_groups if include_public_groups else ():
        label = str(getattr(group, "label", ""))
        count = getattr(group, "count", None)
        denominator = getattr(group, "denominator", None)
        state = getattr(group, "state", None)
        if state not in {"reported", "withheld"}:
            raise PermissionError("HTML/PDF text parity claim is invalid")
        if count is not None and (
            isinstance(count, bool) or not isinstance(count, int) or count < 0
        ):
            raise PermissionError("HTML/PDF text parity claim is invalid")
        if state != "reported" or count is None or count == 0:
            continue
        if isinstance(denominator, bool) or not isinstance(denominator, int):
            raise PermissionError("HTML/PDF text parity claim is invalid")
        claims.append((label, _claim_count_line(count, denominator)))

    dimensions = tuple(getattr(semantic_summary, "dimensions", ()))
    if {str(getattr(item, "key", "")) for item in dimensions} != set(
        _SEMANTIC_REPORT_DIMENSION_LIMITS,
    ):
        raise PermissionError("HTML/PDF text parity claim is invalid")
    for dimension in dimensions:
        key = str(getattr(dimension, "key", ""))
        denominator = getattr(dimension, "denominator", None)
        visible = sorted(
            (
                cell for cell in getattr(dimension, "cells", ())
                if getattr(cell, "state", None) == "reported"
                and isinstance(getattr(cell, "count", None), int)
                and not isinstance(getattr(cell, "count", None), bool)
                and getattr(cell, "count") > 0
            ),
            key=lambda cell: (
                -int(getattr(cell, "count")), str(getattr(cell, "label", "")),
            ),
        )
        limit = _SEMANTIC_REPORT_DIMENSION_LIMITS[key]
        if limit is not None:
            visible = visible[:limit]
        if not visible:
            continue
        for cell in visible:
            count = int(getattr(cell, "count"))
            display = (
                _claim_count_line(count, denominator)
                if (
                    isinstance(denominator, int)
                    and not isinstance(denominator, bool)
                )
                else f"{count} people"
            )
            claims.append((str(getattr(cell, "label", "")), display))

    return claims


def _claim_fragment_pattern(value: str) -> str:
    normalized = _normalized_surface_text(value)
    if not normalized:
        raise PermissionError("HTML/PDF text parity claim is invalid")
    return rf"(?<!\w){re.escape(normalized)}(?!\w)"


def _claim_display_pattern(value: str) -> str:
    normalized = _normalized_surface_text(value)
    pattern = _claim_fragment_pattern(value)
    if re.fullmatch(r"[0-9]+ of [0-9]+", normalized):
        pattern += r"(?!\s*\()"
    return pattern


def _surface_has_all_bound_claims(
    text: str, claims: Counter[tuple[str, str]],
) -> bool:
    label_counts: Counter[str] = Counter()
    display_counts: Counter[str] = Counter()
    for (label, display), required in claims.items():
        label_counts[label] += required
        display_counts[display] += required
        label_pattern = _claim_fragment_pattern(label)
        display_pattern = _claim_display_pattern(display)
        spans = {
            (match.start(), match.end())
            for pattern in (
                rf"{label_pattern}.{{0,96}}?{display_pattern}",
                rf"{display_pattern}.{{0,96}}?{label_pattern}",
            )
            for match in re.finditer(pattern, text)
        }
        if len(spans) < required:
            return False
    return all(
        len(tuple(re.finditer(_claim_fragment_pattern(value), text))) >= required
        for value, required in label_counts.items()
    ) and all(
        len(tuple(re.finditer(_claim_display_pattern(value), text))) >= required
        for value, required in display_counts.items()
    )


def _surface_has_all_labeled_claim_groups(
    text: str,
    groups: tuple[tuple[str, Counter[tuple[str, str]]], ...],
) -> bool:
    """Bind each metric/source label to its nearby cohort display claims."""

    combined: Counter[tuple[str, str]] = Counter()
    for label, claims in groups:
        combined.update(claims)
        label_spans = tuple(
            (match.start(), match.end())
            for match in re.finditer(_claim_fragment_pattern(label), text)
        )
        if not label_spans:
            return False
        for (cohort, display), required in claims.items():
            cohort_pattern = _claim_fragment_pattern(cohort)
            display_pattern = _claim_display_pattern(display)
            claim_spans = {
                (match.start(), match.end())
                for pattern in (
                    rf"{cohort_pattern}.{{0,96}}?{display_pattern}",
                    rf"{display_pattern}.{{0,96}}?{cohort_pattern}",
                )
                for match in re.finditer(pattern, text)
            }
            nearby = {
                claim_span
                for claim_span in claim_spans
                if any(
                    claim_span[0] <= label_span[1] + 640
                    and label_span[0] <= claim_span[1] + 640
                    for label_span in label_spans
                )
            }
            if len(nearby) < required:
                return False
    return bool(groups) and _surface_has_all_bound_claims(text, combined)


def _surface_contains_heading(surface: str, heading: str) -> bool:
    """Match rendered headings even when PDF extraction collapses font spans."""

    compact = lambda value: re.sub(r"\s+", "", _normalized_surface_text(value))
    return compact(heading) in compact(surface)


def _assert_partner_surface_claim_parity(
    *, html_text: str, pdf_text: str, headline_counts: Mapping[str, int | None],
    semantic_summary: object | None,
    include_semantic_public_groups: bool = True,
) -> int:
    """Require both surfaces to carry each protected label and its exact display state."""

    claims = _public_funnel_claims(headline_counts)
    if semantic_summary is not None:
        claims.extend(_public_semantic_claims(
            semantic_summary,
            include_public_groups=include_semantic_public_groups,
        ))
    if any(not label or not display for label, display in claims):
        raise PermissionError("HTML/PDF text parity claim is invalid")
    surfaces = (
        _normalized_html_surface_text(html_text),
        _normalized_surface_text(pdf_text),
    )
    required_claims = Counter(claims)
    if any(
        not _surface_has_all_bound_claims(surface, required_claims)
        for surface in surfaces
    ):
        raise PermissionError("HTML/PDF text parity does not match")
    return len(claims)


def _partner_dashboard_state_from_html(html_text: str) -> dict[str, object]:
    """Extract one aggregate-only dashboard payload from a self-contained report."""

    matches = re.findall(
        r'<script id="partner-dashboard-state" type="application/json">(.*?)</script>',
        html_text, flags=re.DOTALL,
    )
    if len(matches) != 1:
        raise PermissionError("partner dashboard state is missing or duplicated")
    try:
        value = json.loads(unescape(matches[0]))
    except (TypeError, json.JSONDecodeError) as error:
        raise PermissionError("partner dashboard state is unreadable") from error
    if not isinstance(value, dict):
        raise PermissionError("partner dashboard state is invalid")
    raw = json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    if (
        "subject_ref" in raw
        or "case:v1:" in raw
        or re.search(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}", raw)
        or re.search(r"(?:file://|/Users/|/private/tmp/)", raw)
    ):
        raise PermissionError("partner dashboard state contains private data")
    return value


def _assert_partner_dashboard_pdf_claims(
    dashboard_state: Mapping[str, object],
    pdf_text: str,
) -> int:
    """Require each unique cohort metric and source-use value in the fixed PDF exhibit."""

    if dashboard_state.get("version") != "partner-dashboard-v2":
        raise PermissionError("partner dashboard PDF cohort claim contract is invalid")
    raw_cohorts = dashboard_state.get("cohorts")
    if not isinstance(raw_cohorts, list) or not raw_cohorts:
        raise PermissionError("partner dashboard PDF cohort claim contract is invalid")
    grouped_claims: dict[
        tuple[str, str], tuple[str, Counter[tuple[str, str]]]
    ] = {}
    for raw_cohort in raw_cohorts:
        if not isinstance(raw_cohort, Mapping):
            raise PermissionError("partner dashboard PDF cohort claim contract is invalid")
        denominator = raw_cohort.get("denominator")
        cohort_label = raw_cohort.get("label")
        metrics = raw_cohort.get("metrics")
        coverage = raw_cohort.get("source_coverage")
        if (
            type(denominator) is not int
            or denominator <= 0
            or not isinstance(cohort_label, str)
            or not cohort_label
            or not isinstance(metrics, list)
            or not isinstance(coverage, list)
        ):
            raise PermissionError("partner dashboard PDF cohort claim contract is invalid")
        metric_claims: set[str] = set()
        for metric in metrics:
            if not isinstance(metric, Mapping):
                raise PermissionError(
                    "partner dashboard PDF cohort claim contract is invalid",
                )
            key = metric.get("key")
            label = metric.get("label")
            count = metric.get("count")
            if (
                not isinstance(key, str)
                or not isinstance(label, str)
                or (count is not None and (type(count) is not int or count < 0))
            ):
                raise PermissionError(
                    "partner dashboard PDF cohort claim contract is invalid",
                )
            display = (
                "Count withheld" if count is None
                else f"{count} of {denominator}"
            )
            if key in metric_claims:
                raise PermissionError(
                    "partner dashboard PDF cohort claim contract is invalid",
                )
            metric_claims.add(key)
            group_key = ("metric", key)
            prior = grouped_claims.get(group_key)
            if prior is None:
                prior = (label, Counter())
                grouped_claims[group_key] = prior
            elif prior[0] != label:
                raise PermissionError(
                    "partner dashboard PDF cohort claim contract is invalid",
                )
            prior[1][(cohort_label, display)] += 1
        for source in coverage:
            if not isinstance(source, Mapping):
                raise PermissionError(
                    "partner dashboard PDF cohort claim contract is invalid",
                )
            key = source.get("key")
            label = source.get("label")
            count = source.get("count")
            if (
                not isinstance(key, str)
                or not isinstance(label, str)
                or (count is not None and (type(count) is not int or count < 0))
            ):
                raise PermissionError(
                    "partner dashboard PDF cohort claim contract is invalid",
                )
            group_key = ("source", key)
            prior = grouped_claims.get(group_key)
            if prior is None:
                prior = (label, Counter())
                grouped_claims[group_key] = prior
            elif prior[0] != label:
                raise PermissionError(
                    "partner dashboard PDF cohort claim contract is invalid",
                )
            display = "Withheld" if count is None else f"{count} of {denominator}"
            prior[1][(cohort_label, display)] += 1
    groups = tuple(grouped_claims.values())
    if not groups or not _surface_has_all_labeled_claim_groups(
        _normalized_surface_text(pdf_text), groups,
    ):
        raise PermissionError("partner dashboard PDF cohort claim parity failed")
    return sum(sum(claims.values()) for _, claims in groups)


def _assert_partner_dashboard_state_parity(
    *, html_path: Path, semantic_summary: object, pdf_text: str,
) -> int:
    """Rebuild the browser state from protected contracts and require exact parity."""

    from community_os.partner_report_presentation import (
        build_partner_dashboard_state,
        load_partner_report_presentation,
    )
    from community_os.partner_semantic_projection import (
        build_protected_partner_semantic_cohort_candidate_bundle,
    )

    cohort_path = (
        html_path.parent.parent / "rich-semantic-internal.cohorts.aggregate.json"
    )
    presentation_path = html_path.parent / "partner-report-presentation.json"
    html_text = html_path.read_text(encoding="utf-8")
    has_dashboard = 'id="partner-dashboard-state"' in html_text
    if not cohort_path.exists() and not has_dashboard:
        return 1
    if not cohort_path.exists() or not has_dashboard:
        raise PermissionError("partner dashboard contract and rendered state diverge")
    for path in (cohort_path, presentation_path):
        if (
            path.is_symlink()
            or not path.is_file()
            or path.stat().st_mode & 0o077
        ):
            raise PermissionError("partner dashboard protected contract is unsafe")
    try:
        cohort_payload = json.loads(cohort_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise PermissionError("partner dashboard cohort contract is unreadable") from error
    if not isinstance(cohort_payload, dict):
        raise PermissionError("partner dashboard cohort contract is invalid")
    cohort_bundle = build_protected_partner_semantic_cohort_candidate_bundle(
        cohort_payload,
    )
    all_summary = cohort_bundle.cohorts[0].summary
    if all_summary.aggregate_sha256 != getattr(semantic_summary, "aggregate_sha256", None):
        raise PermissionError("partner dashboard aggregate binding does not match")
    presentation = load_partner_report_presentation(
        presentation_path, semantic_summary=all_summary,
    )
    expected = build_partner_dashboard_state(
        cohort_bundle, presentation=presentation,
    )
    actual = _partner_dashboard_state_from_html(
        html_text,
    )
    if actual != expected:
        raise PermissionError("partner dashboard state parity does not match")
    cohorts = actual.get("cohorts")
    if (
        not isinstance(cohorts, list)
        or [cohort.get("key") for cohort in cohorts if isinstance(cohort, dict)]
        != ["all", "accepted", "attended"]
        or any(
            type(cohort.get("denominator")) is not int
            or cohort["denominator"] <= 0
            for cohort in cohorts
            if isinstance(cohort, dict)
        )
    ):
        raise PermissionError("partner dashboard cohort contract is invalid")
    _assert_partner_dashboard_pdf_claims(actual, pdf_text)
    return 4


def _semantic_release_artifact_checks(
    *, html_path: Path, pdf_path: Path, aggregate_paths: tuple[Path, Path],
    minimum_group_size: int,
) -> dict[str, dict[str, object]]:
    """Run deterministic privacy, text-parity, and landscape-layout checks."""

    from community_os.publication import _FORBIDDEN_TEXT, _pdf_text

    paths = (html_path, pdf_path, *aggregate_paths)
    for path in paths:
        if path.is_symlink() or not path.is_file():
            raise PermissionError("semantic release QA artifact is missing or unsafe")
        text = (
            _pdf_text(path) if path.suffix == ".pdf"
            else path.read_text(encoding="utf-8")
        )
        if any(pattern.search(text) for pattern in _FORBIDDEN_TEXT):
            raise PermissionError("semantic release QA artifact privacy parity failed")
    try:
        aggregate_payloads = tuple(
            json.loads(path.read_text(encoding="utf-8"))
            for path in aggregate_paths
        )
    except (OSError, json.JSONDecodeError) as error:
        raise PermissionError("semantic release QA aggregate artifact is unreadable") from error
    if any(not isinstance(payload, dict) for payload in aggregate_payloads):
        raise PermissionError("semantic release QA aggregate privacy parity failed")
    try:
        _release_privacy_minimum(
            aggregate_payloads, expected_minimum_count=minimum_group_size,
        )
        headline_counts = _public_headline_counts(*aggregate_payloads)
    except PermissionError as error:
        raise PermissionError(
            "semantic release QA aggregate privacy parity failed",
        ) from error

    semantic_path = html_path.parent.parent / "rich-semantic-internal.aggregate.json"
    if semantic_path.is_symlink() or not semantic_path.is_file():
        raise PermissionError("semantic release QA semantic aggregate is missing or unsafe")
    try:
        semantic_aggregate = json.loads(semantic_path.read_text(encoding="utf-8"))
        if (
            not isinstance(semantic_aggregate, dict)
            or semantic_aggregate.get("minimum_group_size") != minimum_group_size
        ):
            raise PermissionError(
                "semantic release QA semantic privacy threshold does not match",
            )
        from community_os.partner_semantic_projection import (
            build_protected_partner_semantic_candidate_summary,
        )

        semantic_summary = build_protected_partner_semantic_candidate_summary(
            semantic_aggregate,
        )
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise PermissionError("semantic release QA semantic aggregate is unreadable") from error

    public_semantic_summary = semantic_summary
    cohort_path = semantic_path.with_name(
        "rich-semantic-internal.cohorts.aggregate.json",
    )
    if cohort_path.is_file():
        if cohort_path.is_symlink() or cohort_path.stat().st_mode & 0o077:
            raise PermissionError("semantic release QA cohort aggregate is unsafe")
        try:
            from community_os.partner_semantic_projection import (
                build_protected_partner_semantic_cohort_candidate_bundle,
            )

            cohort_payload = json.loads(cohort_path.read_text(encoding="utf-8"))
            if not isinstance(cohort_payload, dict):
                raise PermissionError(
                    "semantic release QA cohort aggregate is invalid",
                )
            cohort_bundle = build_protected_partner_semantic_cohort_candidate_bundle(
                cohort_payload,
            )
            public_semantic_summary = cohort_bundle.cohorts[0].summary
            if (
                public_semantic_summary.aggregate_sha256
                != semantic_summary.aggregate_sha256
            ):
                raise PermissionError(
                    "semantic release QA cohort aggregate binding does not match",
                )
        except (OSError, TypeError, ValueError, json.JSONDecodeError) as error:
            raise PermissionError(
                "semantic release QA cohort aggregate is unreadable",
            ) from error

    html_text = html_path.read_text(encoding="utf-8")
    raw_pdf_text = _pdf_text(pdf_path)
    pdf_text = _normalized_surface_text(raw_pdf_text)
    headings = _pdf_page_headings(html_text)
    if not headings or any(
        not _surface_contains_heading(pdf_text, heading) for heading in headings
    ):
        raise PermissionError("semantic release QA HTML/PDF text parity failed")
    claim_evidence_count = _assert_partner_surface_claim_parity(
        html_text=html_text, pdf_text=raw_pdf_text,
        headline_counts=headline_counts,
        semantic_summary=public_semantic_summary,
        include_semantic_public_groups=(
            _semantic_public_group_parity_required(semantic_path.parent)
        ),
    )
    dashboard_evidence_count = _assert_partner_dashboard_state_parity(
        html_path=html_path,
        semantic_summary=semantic_summary,
        pdf_text=raw_pdf_text,
    )

    try:
        info = subprocess.run(
            ["pdfinfo", str(pdf_path)], check=False, capture_output=True,
            text=True, timeout=30,
        )
    except (OSError, subprocess.SubprocessError, UnicodeError) as error:
        raise PermissionError("semantic release QA PDF layout inspection failed") from error
    pages_match = re.search(r"^Pages:\s+(\d+)\s*$", info.stdout, re.MULTILINE)
    size_match = re.search(
        r"^Page size:\s+([0-9.]+)\s+x\s+([0-9.]+)\s+pts",
        info.stdout, re.MULTILINE,
    )
    if info.returncode != 0 or pages_match is None or size_match is None:
        raise PermissionError("semantic release QA PDF layout inspection failed")
    pages = int(pages_match.group(1))
    width, height = (float(size_match.group(1)), float(size_match.group(2)))
    html_page_sequence = re.findall(r'\bdata-pdf-page="([0-9]+)"', html_text)
    layout_evidence = (
        html_page_sequence == ["1", "2", "3", "4", "5", "6"],
        pages == 6,
        width > height,
        abs(width - 841.89) <= 2.0,
        abs(height - 595.28) <= 2.0,
    )
    if not all(layout_evidence):
        raise PermissionError("semantic release QA PDF layout failed")
    return {
        "artifact_privacy_parity": {
            "passed": True, "evidence_count": len(paths),
            "expected_count": len(paths),
        },
        "dashboard_state_parity": {
            "passed": True,
            "evidence_count": dashboard_evidence_count,
            "expected_count": dashboard_evidence_count,
        },
        "html_pdf_text_parity": {
            "passed": True,
            "evidence_count": len(headings) + claim_evidence_count,
            "expected_count": len(headings) + claim_evidence_count,
        },
        "pdf_layout": {
            "passed": True, "evidence_count": len(layout_evidence),
            "expected_count": len(layout_evidence),
        },
    }


def generate_current_semantic_release_qa(
    state: object,
    *,
    expected_subject_refs: Sequence[str],
    binding_context: Mapping[str, str],
) -> object:
    """Derive and persist the protected QA receipt from current facts and artifacts."""

    from community_os.semantic_metrics import (
        partner_report_taxonomy_positive_claim_count,
        semantic_aggregate_sha256,
    )
    from community_os.semantic_release_qa import (
        build_semantic_release_qa_context,
        build_semantic_release_qa_receipt,
    )

    root = Path(getattr(state, "root"))
    protected = root / "protected"
    release = protected / "release"
    aggregate_path = protected / "rich-semantic-internal.aggregate.json"
    html_path = release / "talent-brief.real.html"
    pdf_path = release / "talent-brief.real.pdf"
    aggregate_paths = (
        release / "talent-intelligence-v1.real.aggregate.json",
        release / "talent-report-v3.real.aggregate.json",
    )
    for path in (aggregate_path, html_path, pdf_path, *aggregate_paths):
        if path.is_symlink() or not path.is_file():
            raise PermissionError("semantic release QA input is missing or unsafe")
    try:
        aggregate = json.loads(aggregate_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise PermissionError("semantic release QA aggregate is unreadable") from error
    if not isinstance(aggregate, dict):
        raise PermissionError("semantic release QA aggregate is invalid")
    generated_at = _timestamp(
        aggregate.get("generated_at"), "semantic release aggregate timestamp",
    )
    rederived = getattr(state, "rich_semantic_reviews").build_population_aggregate(
        expected_subject_refs=tuple(expected_subject_refs),
        binding_context=binding_context,
        generated_at=generated_at,
        minimum_group_size=int(aggregate.get("minimum_group_size", 0)),
    )
    if rederived != aggregate:
        raise PermissionError("semantic release QA aggregate rederivation failed")
    review_evidence = getattr(
        state, "rich_semantic_reviews",
    ).semantic_release_qa_evidence()
    if not isinstance(review_evidence, dict) or set(review_evidence) != {
        "positive_claim_count", "positive_claim_sample_count",
        "positive_claims_sha256",
        "required_review_case_count", "required_review_cases_resolved",
        "review_evidence_sha256",
    }:
        raise PermissionError("semantic release QA review evidence is invalid")
    metrics = aggregate.get("metrics")
    taxonomy_dimensions = aggregate.get("taxonomy_dimensions")
    bindings = aggregate.get("bindings")
    population = aggregate.get("population")
    if (
        not isinstance(metrics, dict)
        or any(type(value) is not int or value < 0 for value in metrics.values())
        or not isinstance(taxonomy_dimensions, dict)
        or (
            sum(metrics.values())
            + partner_report_taxonomy_positive_claim_count(taxonomy_dimensions)
            != review_evidence["positive_claim_count"]
        )
        or not isinstance(bindings, dict)
        or not isinstance(population, dict)
    ):
        raise PermissionError("semantic release QA positive claims do not rederive")
    context = build_semantic_release_qa_context(
        event_approval_sha256=str(bindings["event_approval_sha256"]),
        event_definition_sha256=str(bindings["event_definition_sha256"]),
        event_key=str(bindings["event_key"]),
        source_snapshot_sha256=str(bindings["source_snapshot_sha256"]),
        population=population,
        run_sha256=str(bindings["run_sha256"]),
        taxonomy_version=str(bindings["taxonomy_version"]),
        aggregate_sha256=semantic_aggregate_sha256(aggregate),
        html_candidate_sha256=_sha256(html_path),
        pdf_candidate_sha256=_sha256(pdf_path),
        positive_claim_count=int(review_evidence["positive_claim_count"]),
        required_review_case_count=int(
            review_evidence["required_review_case_count"],
        ),
        review_evidence_sha256=str(review_evidence["review_evidence_sha256"]),
    )
    checks = {
        "aggregate_rederived": {
            "passed": True, "evidence_count": len(metrics),
            "expected_count": len(metrics),
        },
        **_semantic_release_artifact_checks(
            html_path=html_path, pdf_path=pdf_path,
            aggregate_paths=aggregate_paths,
            minimum_group_size=int(aggregate["minimum_group_size"]),
        ),
        "positive_claim_sample_bound_to_final_reviewed_facts": {
            "passed": True,
            "evidence_count": int(
                review_evidence["positive_claim_sample_count"],
            ),
            "expected_count": min(10, int(review_evidence["positive_claim_count"])),
        },
        "required_review_cases_resolved": {
            "passed": True,
            "evidence_count": int(
                review_evidence["required_review_cases_resolved"],
            ),
            "expected_count": int(review_evidence["required_review_case_count"]),
        },
    }
    receipt = build_semantic_release_qa_receipt(context=context, checks=checks)
    destination = protected / "semantic-release-qa.json"
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    temporary.write_text(receipt.canonical_json() + "\n", encoding="utf-8")
    temporary.chmod(0o600)
    os.replace(temporary, destination)
    destination.chmod(0o600)
    return receipt


def regenerate_current_semantic_release_qa_for_approval(
    state: object, *, pseudonym_secret: bytes,
) -> object:
    """Rebuild complete QA from a real operator state immediately before approval."""

    from community_os.release_operations import _load_applications
    from community_os.rich_semantic_review import (
        RichSemanticReviewStore,
        _subject_code,
    )

    store = getattr(state, "rich_semantic_reviews", None)
    root_value = getattr(state, "root", None)
    if (
        not isinstance(store, RichSemanticReviewStore)
        or not isinstance(root_value, (str, Path))
        or not isinstance(pseudonym_secret, bytes)
        or len(pseudonym_secret) < 16
    ):
        raise PermissionError("semantic release QA requires a real operator review state")
    root = Path(root_value)
    aggregate_path = root / "protected" / "rich-semantic-internal.aggregate.json"
    try:
        aggregate = json.loads(aggregate_path.read_text(encoding="utf-8"))
        bindings = aggregate["bindings"]
    except (OSError, KeyError, TypeError, json.JSONDecodeError) as error:
        raise PermissionError("semantic release QA aggregate binding is unreadable") from error
    if not isinstance(bindings, dict):
        raise PermissionError("semantic release QA aggregate binding is invalid")
    cases = tuple(
        case for case in getattr(state, "review_repository").list(
            kind="classification",
        )
        if case.version == "rich_semantic_review_v1"
    )
    case_subject_codes = {case.subject_code for case in cases}
    if not cases or len(case_subject_codes) != len(cases):
        raise PermissionError("semantic release QA review population is invalid")
    subject_by_code: dict[str, str] = {}
    for application in _load_applications(state):
        external_id = str(application.get("external_id") or "").strip()
        if not external_id:
            raise PermissionError("semantic release QA application population is invalid")
        subject_ref = rich_semantic_subject_ref(
            external_id, secret=pseudonym_secret,
        )
        subject_code = _subject_code(subject_ref)
        if subject_code in case_subject_codes:
            if subject_code in subject_by_code:
                raise PermissionError(
                    "semantic release QA application population is duplicated",
                )
            subject_by_code[subject_code] = subject_ref
    if set(subject_by_code) != case_subject_codes:
        raise PermissionError(
            "semantic release QA review population does not match applications",
        )
    return generate_current_semantic_release_qa(
        state,
        expected_subject_refs=tuple(sorted(subject_by_code.values())),
        binding_context={
            key: str(bindings[key])
            for key in (
                "event_approval_sha256", "event_definition_sha256", "event_key",
                "run_sha256", "source_snapshot_sha256", "taxonomy_sha256",
                "taxonomy_version",
            )
        },
    )


def issue_current_semantic_release_approval(
    release_root: str | Path,
    *,
    state: object,
    actor_code: str,
    signing_secret: bytes,
    now: datetime,
    authoritative_context: Mapping[str, object],
    lifetime: timedelta = timedelta(days=1),
) -> dict[str, object]:
    """Seal the exact reviewed local candidate from an authenticated request."""

    from community_os.partner_semantic_projection import (
        build_protected_partner_semantic_candidate_summary,
        semantic_summary_manifest_binding,
    )
    from community_os.publication import artifact_set_sha256
    from community_os.semantic_release_approval import (
        build_semantic_release_candidate,
        issue_semantic_release_approval,
    )

    if (
        not isinstance(now, datetime)
        or now.tzinfo is None
        or now.utcoffset() is None
        or not isinstance(lifetime, timedelta)
        or lifetime <= timedelta(0)
        or lifetime > timedelta(days=7)
    ):
        raise ValueError("semantic release approval time window is invalid")
    root = Path(release_root)
    protected = root.parent
    if Path(getattr(state, "root", "")).resolve() != protected.parent.resolve():
        raise PermissionError("semantic release approval operator root does not match")
    aggregate_path = protected / "rich-semantic-internal.aggregate.json"
    qa_path = protected / "semantic-release-qa.json"
    manifest_path = root / "talent-report-v3.real.manifest.json"
    public_paths = tuple(
        root / name
        for name in (
            "talent-brief.real.html",
            "talent-brief.real.pdf",
            "talent-intelligence-v1.real.aggregate.json",
            "talent-report-v3.real.aggregate.json",
        )
    )
    required = (
        aggregate_path, protected / "semantic-release-context.json",
        manifest_path, *public_paths,
    )
    if any(path.is_symlink() or not path.is_file() for path in required):
        raise PermissionError(
            "semantic release approval requires a complete safe candidate and QA receipt",
        )
    try:
        aggregate = json.loads(aggregate_path.read_text(encoding="utf-8"))
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise PermissionError("semantic release candidate is unreadable") from error
    if not isinstance(aggregate, dict) or not isinstance(manifest, dict):
        raise PermissionError("semantic release candidate is invalid")
    summary = build_protected_partner_semantic_candidate_summary(aggregate)
    if manifest.get("semantic_enrichment") != semantic_summary_manifest_binding(summary):
        raise PermissionError("semantic release candidate manifest binding is stale")
    from community_os.partner_semantic_projection import (
        validate_partner_semantic_release_context,
    )

    context_path = protected / "semantic-release-context.json"
    try:
        stored_context = json.loads(context_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise PermissionError("semantic release context is unreadable") from error
    validate_partner_semantic_release_context(summary, stored_context)
    observed_authority = {
        key: stored_context[key]
        for key in _AUTHORITATIVE_SEMANTIC_CONTEXT_KEYS
    }
    if observed_authority != dict(authoritative_context):
        raise PermissionError(
            "semantic release context does not match current operator authority",
        )
    qa_receipt = regenerate_current_semantic_release_qa_for_approval(
        state, pseudonym_secret=signing_secret,
    )
    candidate = build_semantic_release_candidate(
        aggregate,
        qa_sha256=qa_receipt.sha256,
        report_candidate_sha256=artifact_set_sha256(public_paths),
        html_sha256=_sha256(public_paths[0]),
        pdf_sha256=_sha256(public_paths[1]),
    )
    approval = issue_semantic_release_approval(
        candidate,
        actor_code=actor_code,
        approved_at=now,
        expires_at=now + lifetime,
        signing_secret=signing_secret,
    )
    approval_path = protected / "semantic-release-approval.json"
    temporary = approval_path.with_suffix(approval_path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(approval, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        + "\n",
        encoding="utf-8",
    )
    temporary.chmod(0o600)
    os.replace(temporary, approval_path)
    approval_path.chmod(0o600)
    return {
        "approval_sha256": hashlib.sha256(
            json.dumps(
                approval, ensure_ascii=True, sort_keys=True,
                separators=(",", ":"), allow_nan=False,
            ).encode("utf-8"),
        ).hexdigest(),
        "expires_at": (now + lifetime).astimezone(UTC).isoformat().replace(
            "+00:00", "Z",
        ),
        "state": "complete",
    }


def issue_current_publication_approval(
    release_root: str | Path,
    *,
    state: object,
    actor_code: str,
    approval_bundle: str | Path,
    now: datetime,
    semantic_approval_secret: bytes,
) -> dict[str, object]:
    """Bind authenticated final approval to the exact current HTML/PDF bytes."""

    if (
        not isinstance(now, datetime)
        or now.tzinfo is None
        or now.utcoffset() is None
    ):
        raise ValueError("publication approval requires a timezone-aware time")
    if not isinstance(actor_code, str) or not re.fullmatch(
        r"[a-z][a-z0-9_]{2,63}", actor_code,
    ):
        raise ValueError("publication approval actor must be machine-readable")
    root = Path(release_root)
    operator_root = Path(getattr(state, "root", ""))
    expected_root = operator_root / "protected" / "release"
    if (
        root.is_symlink()
        or not root.is_dir()
        or root.resolve() != expected_root.resolve()
    ):
        raise PermissionError("publication approval operator root does not match")
    bundle_path = Path(approval_bundle)
    if bundle_path.is_symlink() or not bundle_path.is_file():
        raise PermissionError("controlled release approval bundle is unsafe")
    bundle = _load_bundle(bundle_path)
    snapshot = getattr(state, "snapshot")()
    event_approval = snapshot.get("event_approval")
    event_approval_sha256 = (
        event_approval.get("sha256")
        if isinstance(event_approval, dict) else None
    )
    if not isinstance(event_approval_sha256, str) or not re.fullmatch(
        r"[0-9a-f]{64}", event_approval_sha256,
    ):
        raise PermissionError("current event approval hash is unavailable")

    semantic_aggregate = operator_root / "protected" / "rich-semantic-internal.aggregate.json"
    semantic_authority = None
    if semantic_aggregate.is_file():
        authority = getattr(state, "semantic_release_authoritative_context", None)
        if not callable(authority):
            raise PermissionError("semantic release authority is unavailable")
        semantic_authority = authority()
    _verified_release_artifacts(
        root,
        now=now,
        semantic_approval_secret=semantic_approval_secret,
        semantic_authoritative_context=semantic_authority,
    )

    html = root / _LOCAL_PARTNER_SHARE_NAMES[0]
    pdf = root / _LOCAL_PARTNER_SHARE_NAMES[1]
    if any(path.is_symlink() or not path.is_file() for path in (html, pdf)):
        raise PermissionError("publication approval requires complete safe artifacts")
    from community_os.publication import artifact_set_sha256

    approval = {
        "actor_code": actor_code,
        "approved_at": now.astimezone(UTC).isoformat().replace("+00:00", "Z"),
        "artifact_set_sha256": artifact_set_sha256((html, pdf)),
        "event_approval_sha256": event_approval_sha256,
        "report_sha256": _sha256(html),
    }
    updated = {**bundle, "publication_approval": approval}
    _replace_controlled_release_bundle(
        bundle_path,
        (
            json.dumps(
                updated, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
                allow_nan=False,
            ) + "\n"
        ).encode("utf-8"),
    )
    return {**approval, "state": "complete"}


_AUTHORITATIVE_SEMANTIC_CONTEXT_KEYS = frozenset({
    "event_approval_sha256", "event_definition_sha256", "event_key",
    "source_snapshot_sha256", "taxonomy_sha256", "taxonomy_version",
    "total_population",
})


def validate_current_semantic_release_qa(
    protected_root: str | Path,
    *,
    html_path: str | Path,
    pdf_path: str | Path,
    authoritative_context: Mapping[str, object],
    approval_bound_qa_sha256: str,
):
    """Revalidate the structured QA receipt against current release authority."""

    from community_os.partner_semantic_projection import (
        build_protected_partner_semantic_candidate_summary,
        validate_partner_semantic_release_context,
    )
    from community_os.semantic_metrics import semantic_aggregate_sha256
    from community_os.semantic_release_qa import (
        build_semantic_release_qa_context,
        load_semantic_release_qa_receipt,
        load_semantic_release_qa_review_evidence,
    )

    if (
        not isinstance(authoritative_context, Mapping)
        or set(authoritative_context) != _AUTHORITATIVE_SEMANTIC_CONTEXT_KEYS
    ):
        raise PermissionError("semantic release authoritative context is invalid")
    protected = Path(protected_root)
    aggregate_path = protected / "rich-semantic-internal.aggregate.json"
    context_path = protected / "semantic-release-context.json"
    qa_path = protected / "semantic-release-qa.json"
    candidate_paths = (Path(html_path), Path(pdf_path))
    for path in (aggregate_path, context_path, qa_path, *candidate_paths):
        if path.is_symlink() or not path.is_file():
            raise PermissionError("semantic release QA input is missing or unsafe")
    if context_path.stat().st_mode & 0o777 != 0o600:
        raise PermissionError("semantic release context must use mode 0600")
    try:
        aggregate = json.loads(aggregate_path.read_text(encoding="utf-8"))
        stored_context = json.loads(context_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise PermissionError("semantic release context is unreadable") from error
    if not isinstance(aggregate, dict) or not isinstance(stored_context, dict):
        raise PermissionError("semantic release context is invalid")
    summary = build_protected_partner_semantic_candidate_summary(aggregate)
    validate_partner_semantic_release_context(summary, stored_context)
    observed_authority = {
        key: stored_context[key]
        for key in _AUTHORITATIVE_SEMANTIC_CONTEXT_KEYS
    }
    if observed_authority != dict(authoritative_context):
        raise PermissionError(
            "semantic release context does not match current operator authority",
        )
    bindings = aggregate.get("bindings")
    population = aggregate.get("population")
    if not isinstance(bindings, dict) or not isinstance(population, dict):
        raise PermissionError("semantic release aggregate context is invalid")
    if not isinstance(approval_bound_qa_sha256, str) or not re.fullmatch(
        r"[0-9a-f]{64}", approval_bound_qa_sha256,
    ):
        raise PermissionError("semantic release QA requires approved receipt binding")
    observed_review_evidence = load_semantic_release_qa_review_evidence(qa_path)
    expected_qa_context = build_semantic_release_qa_context(
        event_approval_sha256=str(bindings["event_approval_sha256"]),
        event_definition_sha256=str(bindings["event_definition_sha256"]),
        event_key=str(bindings["event_key"]),
        source_snapshot_sha256=str(bindings["source_snapshot_sha256"]),
        population=population,
        run_sha256=str(bindings["run_sha256"]),
        taxonomy_version=str(bindings["taxonomy_version"]),
        aggregate_sha256=semantic_aggregate_sha256(aggregate),
        html_candidate_sha256=_sha256(candidate_paths[0]),
        pdf_candidate_sha256=_sha256(candidate_paths[1]),
        positive_claim_count=observed_review_evidence["positive_claim_count"],
        required_review_case_count=observed_review_evidence[
            "required_review_case_count"
        ],
        review_evidence_sha256=observed_review_evidence[
            "review_evidence_sha256"
        ],
    )
    receipt = load_semantic_release_qa_receipt(
        qa_path, expected_context=expected_qa_context,
    )
    if not hmac.compare_digest(
        receipt.sha256, approval_bound_qa_sha256,
    ):
        raise PermissionError("semantic release approved QA hash drift")
    return receipt


def _verified_release_artifacts(
    release_root: Path, *, now: datetime, semantic_approval_secret: bytes,
    semantic_authoritative_context: Mapping[str, object] | None,
    minimum_group_size: int | None = None,
) -> dict[str, int | None]:
    """Bind every public surface to the protected build manifest and headline parity."""
    names = (
        "talent-brief.real.html", "talent-brief.real.pdf",
        "talent-intelligence-v1.real.aggregate.json",
        "talent-report-v3.real.aggregate.json",
    )
    manifest_path = release_root / "talent-report-v3.real.manifest.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        output_hashes = manifest["output_hashes"]
        aggregates = manifest["aggregates"]
        v1 = json.loads(
            (release_root / "talent-intelligence-v1.real.aggregate.json").read_text(
                encoding="utf-8"
            )
        )
        v3 = json.loads(
            (release_root / "talent-report-v3.real.aggregate.json").read_text(
                encoding="utf-8"
            )
        )
    except (OSError, KeyError, TypeError, json.JSONDecodeError) as error:
        raise PermissionError("protected release manifest or aggregates are unreadable") from error
    if not isinstance(output_hashes, dict) or any(
        not (release_root / name).is_file()
        or not hmac.compare_digest(str(output_hashes.get(name, "")), _sha256(release_root / name))
        for name in names
    ):
        raise PermissionError("protected release artifact hash drift")
    privacy_minimum = _release_privacy_minimum(
        (v1, v3), expected_minimum_count=minimum_group_size,
    )
    semantic_path = release_root.parent / "rich-semantic-internal.aggregate.json"
    semantic_manifest = manifest.get("semantic_enrichment")
    semantic_summary = None
    if not semantic_path.is_file() or semantic_manifest is None:
        raise PermissionError(
            "approved semantic enrichment is required for partner release",
        )
    if semantic_path.is_file():
        if semantic_authoritative_context is None:
            raise PermissionError(
                "semantic release authority is required for semantic artifacts",
            )
        from community_os.partner_semantic_projection import (
            load_partner_semantic_summary,
            semantic_summary_manifest_binding,
        )

        try:
            semantic_aggregate = json.loads(semantic_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise PermissionError("protected semantic enrichment is unreadable") from error
        if (
            not isinstance(semantic_aggregate, dict)
            or semantic_aggregate.get("minimum_group_size") != privacy_minimum
        ):
            raise PermissionError(
                "protected semantic enrichment privacy threshold does not match",
            )

        approval_path = release_root.parent / "semantic-release-approval.json"
        semantic_summary = load_partner_semantic_summary(
            semantic_path, approval_path=approval_path, now=now,
            approval_secret=semantic_approval_secret,
        )
        expected_semantic = semantic_summary_manifest_binding(semantic_summary)
        if semantic_manifest != expected_semantic:
            raise PermissionError("protected semantic enrichment hash drift")
        bindings = dict(semantic_summary.release_artifact_hashes)
        if (
            _sha256(release_root / "talent-brief.real.html")
            != bindings.get("html_sha256")
            or _sha256(release_root / "talent-brief.real.pdf")
            != bindings.get("pdf_sha256")
        ):
            raise PermissionError("protected semantic release artifact hash drift")
        qa_receipt = validate_current_semantic_release_qa(
            release_root.parent,
            html_path=release_root / "talent-brief.real.html",
            pdf_path=release_root / "talent-brief.real.pdf",
            authoritative_context=semantic_authoritative_context,
            approval_bound_qa_sha256=str(bindings.get("qa_sha256") or ""),
        )
        if qa_receipt.sha256 != bindings.get("qa_sha256"):
            raise PermissionError("protected semantic release QA hash drift")
        from community_os.publication import artifact_set_sha256

        semantic_public_paths = tuple(
            release_root / name for name in names
        )
        if (
            artifact_set_sha256(semantic_public_paths)
            != bindings.get("report_candidate_sha256")
        ):
            raise PermissionError("protected semantic release candidate hash drift")
    elif semantic_manifest is not None:
        raise PermissionError("protected semantic enrichment source is missing")
    counts = _public_headline_counts(v1, v3)
    try:
        protected_counts = {
            key: int(aggregates[key]) for key in ("applied", "going_accepted", "on_site")
        }
    except (KeyError, TypeError, ValueError) as error:
        raise PermissionError("protected aggregate headline parity is unreadable") from error
    if any(counts[key] != protected_counts[key] for key in ("applied", "going_accepted")):
        raise PermissionError("aggregate headline parity does not match")
    onsite_remainder = protected_counts["going_accepted"] - protected_counts["on_site"]
    if counts["on_site"] is None:
        if not 0 < onsite_remainder < privacy_minimum:
            raise PermissionError("on-site count is withheld without a below-threshold complement")
    elif counts["on_site"] != protected_counts["on_site"] or 0 < onsite_remainder < privacy_minimum:
        raise PermissionError("public on-site count exposes a below-threshold complement")
    from community_os.publication import _pdf_text

    html_text = (release_root / "talent-brief.real.html").read_text(encoding="utf-8")
    pdf_text = _pdf_text(release_root / "talent-brief.real.pdf")
    _assert_partner_surface_claim_parity(
        html_text=html_text, pdf_text=pdf_text,
        headline_counts=counts, semantic_summary=semantic_summary,
        include_semantic_public_groups=(
            _semantic_public_group_parity_required(release_root.parent)
        ),
    )
    labels = {
        "applied": "applied", "going_accepted": "accepted by organizers",
        "on_site": "confirmed present at the event",
    }
    for text in (html_text, pdf_text):
        normalized = re.sub(r"\s+", " ", text).casefold()
        for key, label in labels.items():
            value = counts[key]
            display = "attendance count hidden" if value is None else str(value)
            forward = re.search(rf"{re.escape(label)}.{{0,320}}\b{display}\b", normalized)
            backward = re.search(rf"\b{display}\b.{{0,320}}{re.escape(label)}", normalized)
            if forward is None and backward is None:
                raise PermissionError("HTML/PDF headline parity does not match")
            if value is None:
                protected_value = str(protected_counts[key])
                leaked_forward = re.search(
                    rf"{re.escape(label)}.{{0,320}}\b{protected_value}\b", normalized
                )
                leaked_backward = re.search(
                    rf"\b{protected_value}\b.{{0,320}}{re.escape(label)}", normalized
                )
                if leaked_forward is not None or leaked_backward is not None:
                    raise PermissionError("HTML/PDF exposes a protected headline count")
    return counts


def _authoritative_release_reviews(state: object) -> tuple[object, ...]:
    """Project only current review paths into the publication decision."""

    from community_os.privacy_operations import ReviewRecord

    repository = getattr(state, "review_repository")
    cases = tuple(repository.list())
    authoritative_classification = tuple(
        repository.authoritative_classification_cases()
    )
    authoritative_codes = {
        case.case_code for case in authoritative_classification
    }
    selected = tuple(
        case for case in cases
        if case.kind != "classification" or case.case_code in authoritative_codes
    )
    return tuple(
        ReviewRecord(
            "review_" + hashlib.sha256(
                case.case_code.encode("utf-8"),
            ).hexdigest()[:20],
            case.status == "resolved",
        )
        for case in selected
    )


def _release_evidence(
    state: object,
    bundle: Mapping[str, object],
    release_root: Path,
    *,
    now: datetime,
    definition: EventDefinition,
    semantic_approval_secret: bytes,
):
    from community_os.privacy_operations import (
        DataAsset, DataClass, ExclusionRegistry, PrivacyParityRecord,
        PublicationApproval, ReleaseEvidence, RightsState, UseApproval,
    )

    privacy = bundle["privacy_operations"]
    assert isinstance(privacy, dict)
    approval_record = privacy["approval"]
    rights_record = privacy["rights"]
    allowed_uses = privacy["allowed_uses"]
    assert isinstance(approval_record, dict)
    assert isinstance(rights_record, dict)
    assert isinstance(allowed_uses, dict)
    owner = str(privacy["accountable_owner"])
    retention = _timestamp(privacy["retention_deadline"], "privacy retention deadline")
    notice_sent = _timestamp(privacy["notice_sent_at"], "privacy notice timestamp")
    approved_at = _timestamp(approval_record["approved_at"], "privacy processing approval")
    expires_at = _timestamp(approval_record["expires_at"], "privacy processing approval expiry")
    if not approved_at <= now < expires_at:
        raise PermissionError("privacy processing approval is not currently valid")

    snapshot = getattr(state, "snapshot")()
    slots = snapshot["source_slots"]
    if not isinstance(slots, dict):
        raise PermissionError("privacy inventory requires validated source slots")
    inventory: list[DataAsset] = []

    def add_asset(
        *, asset_id: str, source: str, pseudonym: str, version_hash: str,
        purpose: str, data_class: DataClass, storage_scope: str,
        resource_ref: str, deadline: datetime = retention,
    ) -> None:
        uses = allowed_uses[source]
        assert isinstance(uses, list)
        inventory.append(DataAsset(
            asset_id=asset_id, version="v_" + version_hash[:16], pseudonym=pseudonym,
            source=source, purpose=purpose, accountable_owner=owner,
            retention_deadline=deadline, allowed_uses=frozenset(uses),
            data_class=data_class, storage_scope=storage_scope,
            resource_ref=resource_ref,
        ))

    for source_definition in definition.sources:
        source = source_definition.role
        slot = slots.get(source)
        if not isinstance(slot, dict):
            if source_definition.required:
                raise PermissionError(f"privacy inventory source is missing: {source}")
            continue
        add_asset(
            asset_id="source_" + source, source=source,
            pseudonym="psn_source_" + source,
            version_hash=str(slot["sha256"]), purpose="talent_release",
            data_class=DataClass.RAW_SOURCE, storage_scope="protected_uploads",
            resource_ref=str(slot["path"]),
        )

    stage_root = Path(getattr(state, "root")) / "protected" / "stages"
    for source in ("github", "public_pages", "coresignal", "classification"):
        path = stage_root / f"{source}.json"
        if not path.is_file():
            continue
        try:
            envelope = json.loads(path.read_text(encoding="utf-8"))
            deadline = _timestamp(envelope["expires_at"], f"{source} retention deadline")
        except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
            raise PermissionError(f"{source} privacy inventory is unreadable") from error
        add_asset(
            asset_id="stage_" + source, source=source,
            pseudonym="psn_stage_" + source, version_hash=_sha256(path),
            purpose="talent_classification" if source != "classification" else "talent_release",
            data_class=(
                DataClass.CLASSIFICATION if source == "classification"
                else DataClass.RAW_ENRICHMENT
            ),
            storage_scope="protected_stages", resource_ref=f"stages/{source}.json",
            deadline=deadline,
        )

    html = release_root / "talent-brief.real.html"
    if not html.is_file():
        raise PermissionError("partner report is missing before release evaluation")
    _verified_release_artifacts(
        release_root,
        now=now,
        semantic_approval_secret=semantic_approval_secret,
        semantic_authoritative_context=(
            getattr(state, "semantic_release_authoritative_context")()
            if (Path(getattr(state, "root")) / "protected"
                / "rich-semantic-internal.aggregate.json").is_file()
            else None
        ),
        minimum_group_size=definition.privacy.minimum_count,
    )
    html_hash = _sha256(html)
    from community_os.publication import artifact_set_sha256

    public_paths = tuple(
        release_root / name for name in _LOCAL_PARTNER_SHARE_NAMES
    )
    report_hash = artifact_set_sha256(public_paths)
    add_asset(
        asset_id="partner_report", source="partner_report", pseudonym="psn_release",
        version_hash=report_hash, purpose="partner_publication",
        data_class=DataClass.AGGREGATE, storage_scope="protected_release",
        resource_ref="release/talent-brief.real.html",
    )

    registry = ExclusionRegistry()
    for asset in inventory:
        registry.record(RightsState(
            pseudonym=asset.pseudonym,
            notice_version=str(privacy["notice_version"]), notice_sent_at=notice_sent,
            objection_status=str(rights_record["objection_status"]),
            exclusion_status=str(rights_record["exclusion_status"]),
            suppression_status=str(rights_record["suppression_status"]),
            deletion_status=str(rights_record["deletion_status"]),
            reconciled=bool(rights_record["reconciled"]),
        ))
    approvals = tuple(
        UseApproval(
            source=asset.source, purpose=asset.purpose, use=use,
            owner_code=owner, actor_code=str(approval_record["actor_code"]),
            approved_at=approved_at, expires_at=expires_at,
        )
        for asset in inventory for use in sorted(asset.allowed_uses)
    )
    reviews = _authoritative_release_reviews(state)
    publication_record = bundle["publication_approval"]
    publication = None
    if publication_record is not None:
        if not isinstance(publication_record, dict) or set(publication_record) != {
            "actor_code", "approved_at", "artifact_set_sha256",
            "event_approval_sha256", "report_sha256",
        }:
            raise PermissionError("publication approval record is invalid")
        event_approval = getattr(state, "snapshot")().get("event_approval")
        current_event_approval_sha256 = (
            event_approval.get("sha256") if isinstance(event_approval, dict) else None
        )
        approved_event_sha256 = publication_record["event_approval_sha256"]
        if (
            not isinstance(current_event_approval_sha256, str)
            or not re.fullmatch(r"[0-9a-f]{64}", current_event_approval_sha256)
            or not isinstance(approved_event_sha256, str)
            or not re.fullmatch(r"[0-9a-f]{64}", approved_event_sha256)
            or not hmac.compare_digest(
                approved_event_sha256, current_event_approval_sha256,
            )
        ):
            raise PermissionError(
                "publication approval event approval hash does not match",
            )
        if not hmac.compare_digest(str(publication_record["report_sha256"]), html_hash):
            raise PermissionError("publication approval HTML hash does not match")
        publication = PublicationApproval(
            report_hash=str(publication_record["artifact_set_sha256"]),
            actor_code=str(publication_record["actor_code"]),
            approved_at=_timestamp(publication_record["approved_at"], "publication approval"),
        )
    members = frozenset({"psn_release"})
    return ReleaseEvidence(
        inventory=tuple(inventory), registry=registry, approvals=approvals,
        cleanup_report=None,
        parity=PrivacyParityRecord(members, members, members, members),
        reviews=reviews, publication_approval=publication, report_hash=report_hash,
        report_generated_at=_timestamp(bundle["generated_at"], "report generation timestamp"),
    )


def _persist_privacy_operations(
    state: object, evidence: object, privacy: Mapping[str, object], release_state: str,
) -> None:
    path = Path(getattr(state, "root")) / "protected" / "privacy-operations.json"
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.parent.chmod(0o700)
    exclusion_path = path.with_name("subject-exclusions.json")
    try:
        exclusion_evidence = json.loads(exclusion_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise PermissionError("subject exclusion evidence is missing") from error
    if not isinstance(exclusion_evidence, dict) or set(exclusion_evidence) != {
        "action", "excluded_count", "exclusion_set_sha256", "reason_code",
        "schema_version",
    }:
        raise PermissionError("subject exclusion evidence is invalid")
    inventory = getattr(evidence, "inventory")
    payload = {
        "accountable_owner": privacy["accountable_owner"],
        "audit_event_count": len(getattr(state, "snapshot")()["audit_events"]),
        "inventory": [{
            "allowed_uses": sorted(item.allowed_uses),
            "asset_id": item.asset_id, "data_class": item.data_class.value,
            "purpose": item.purpose, "retention_deadline": item.retention_deadline.isoformat(),
            "resource_ref": item.resource_ref, "source": item.source,
            "storage_scope": item.storage_scope,
            "version": item.version,
        } for item in inventory],
        "notice_sent_at": privacy["notice_sent_at"],
        "notice_version": privacy["notice_version"],
        "release_state": release_state,
        "rights": privacy["rights"],
        "schema_version": "privacy-operations-v1",
        "subject_exclusions": exclusion_evidence,
    }
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(
        json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    temporary.chmod(0o600)
    temporary.replace(path)


def _persist_privacy_plan(
    state: object, privacy: Mapping[str, object],
    stage_deadlines: Mapping[str, datetime],
    *, exclusion_plan: object | None = None,
    definition: EventDefinition,
    disabled_optional_stages: Sequence[str] = (),
) -> None:
    configured_roles = {source.role for source in definition.sources}
    purposes = {
        **{source: "talent_release" for source in configured_roles},
        "github": "talent_classification", "public_pages": "talent_classification",
        "coresignal": "talent_classification", "classification": "talent_release",
        "partner_report": "partner_publication",
    }
    uses = privacy["allowed_uses"]
    assert isinstance(uses, dict)
    path = Path(getattr(state, "root")) / "protected" / "privacy-operations.json"
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    slots = getattr(state, "snapshot")().get("source_slots", {})
    if not isinstance(slots, dict):
        raise PermissionError("privacy plan source inventory is invalid")
    disabled = frozenset(disabled_optional_stages)
    if not disabled <= {"public_pages"}:
        raise PermissionError("privacy plan optional-stage policy is invalid")

    def retention_deadline(source: str) -> object:
        deadline = stage_deadlines.get(source)
        return deadline.isoformat() if deadline is not None else privacy["retention_deadline"]

    def inventory_record(source: str) -> dict[str, object]:
        if source in disabled:
            return {
                "accountable_owner": privacy["accountable_owner"],
                "allowed_uses": [],
                "data_class": "disabled",
                "purpose": "not_processed",
                "resource_ref": None,
                "retention_deadline": None,
                "source": source,
                "state": "disabled",
                "storage_scope": "none",
            }
        if source in configured_roles:
            slot = slots.get(source)
            if not isinstance(slot, dict) or not str(slot.get("path") or ""):
                raise PermissionError(f"privacy plan source is missing: {source}")
            data_class = "raw_source"
            storage_scope = "protected_uploads"
            resource_ref = str(slot["path"])
        elif source in {"github", "public_pages", "coresignal"}:
            data_class = "raw_enrichment"
            storage_scope = "protected_stages"
            resource_ref = f"stages/{source}.json"
        elif source == "classification":
            data_class = "classification"
            storage_scope = "protected_stages"
            resource_ref = "stages/classification.json"
        else:
            data_class = "aggregate"
            storage_scope = "protected_release"
            resource_ref = "release/talent-brief.real.html"
        return {
            "accountable_owner": privacy["accountable_owner"],
            "allowed_uses": uses[source], "data_class": data_class,
            "purpose": purposes[source], "resource_ref": resource_ref,
            "retention_deadline": retention_deadline(source), "source": source,
            "storage_scope": storage_scope,
        }

    inventory: list[dict[str, object]] = []
    for source in sorted(uses):
        if source in configured_roles and source not in slots:
            if definition.source(source).required:
                raise PermissionError(f"privacy plan source is missing: {source}")
            continue
        inventory.append(inventory_record(source))
    payload = {
        "accountable_owner": privacy["accountable_owner"],
        "inventory": inventory,
        "notice_sent_at": privacy["notice_sent_at"],
        "notice_version": privacy["notice_version"],
        "release_state": "Blocked", "rights": privacy["rights"],
        "schema_version": "privacy-operations-plan-v1",
    }
    if exclusion_plan is not None:
        payload["subject_exclusions"] = getattr(exclusion_plan, "audit_record")
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(
        json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    temporary.chmod(0o600)
    temporary.replace(path)


def _persist_subject_exclusion_plan(state: object, plan: object) -> None:
    """Persist only deterministic exclusion evidence and invalidate stale derivatives."""

    root = Path(getattr(state, "root"))
    protected = root / "protected"
    path = protected / "subject-exclusions.json"
    previous_hash = None
    if path.is_file():
        try:
            previous = json.loads(path.read_text(encoding="utf-8"))
            previous_hash = previous.get("exclusion_set_sha256")
        except (OSError, AttributeError, json.JSONDecodeError):
            previous_hash = "invalid"
    current_hash = str(getattr(plan, "exclusion_set_sha256"))
    derivative_roots = (
        protected / "stages", protected / "cache", protected / "release",
        root / "public-staging", root / "deployment-staging",
    )
    stale_derivatives_exist = any(
        target.is_file() or target.is_symlink()
        for derivative_root in derivative_roots if derivative_root.exists()
        for target in derivative_root.rglob("*")
    ) or any(
        (protected / name).is_file() or (protected / name).is_symlink()
        for name in (
            "enrichment-manifest.json", "review-bindings.json",
            "review-bindings.json.tmp",
            "review-cases.json", "reviewed-override.json",
        )
    )
    plan_changed = previous_hash is not None and not hmac.compare_digest(
        str(previous_hash), current_hash,
    )
    if plan_changed or (previous_hash is None and stale_derivatives_exist):
        getattr(state, "invalidate_for_subject_exclusions")(
            current_hash, excluded_count=int(getattr(plan, "excluded_count")),
        )
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    payload = {
        **getattr(plan, "audit_record"),
        "schema_version": "subject-exclusion-plan-v1",
    }
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(
        json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    temporary.chmod(0o600)
    temporary.replace(path)


def run_scheduled_privacy_cleanup(
    root: str | Path,
    *,
    clock: Callable[[], datetime] = _now,
    event_definition: EventDefinition,
) -> dict[str, object]:
    """Delete expired enrichment payloads without requiring release approval.

    This entry point is suitable for a private scheduler. Malformed raw
    enrichment envelopes are deleted fail-safe because their retention cannot
    be proven.
    """
    from community_os.release_operator import protected_mutation_lock

    with protected_mutation_lock(root):
        return _run_scheduled_privacy_cleanup_unlocked(
            root, clock=clock, event_definition=event_definition,
        )


def _withdraw_public_staging(root: str | Path) -> None:
    def withdraw(directory: Path, names: tuple[str, ...]) -> None:
        if directory.is_symlink():
            directory.unlink()
            return
        for name in names:
            path = directory / name
            if path.is_file() or path.is_symlink():
                path.unlink()
        try:
            directory.rmdir()
        except (FileNotFoundError, OSError):
            pass

    root_path = Path(root)
    withdraw(root_path / "public-staging", (
        "publication-manifest.json", "index.html", "partner-talent-brief.pdf",
        "talent-brief.real.html", "talent-brief.real.pdf",
        "talent-intelligence-v1.real.aggregate.json",
        "talent-report-v3.real.aggregate.json",
    ))
    withdraw(root_path / "deployment-staging", (
        "vercel.json", "index.html", "partner-talent-brief.pdf",
        "publication-manifest.json",
    ))
    analytics_audit = root_path / "protected" / "analytics-publication.json"
    if analytics_audit.is_file() or analytics_audit.is_symlink():
        analytics_audit.unlink()


def _raw_source_expiry_plan(
    protected: Path,
    *,
    now: datetime,
    allowed_sources: frozenset[str],
    expected_source_refs: Mapping[str, str],
) -> tuple[tuple[str, Path], ...]:
    privacy_path = protected / "privacy-operations.json"
    if not privacy_path.is_file():
        if expected_source_refs:
            raise PermissionError("raw source privacy inventory is missing")
        return ()
    try:
        privacy_payload = json.loads(
            privacy_path.read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite,
        )
        if not isinstance(privacy_payload, dict):
            raise PermissionError("privacy inventory is invalid")
        inventory = privacy_payload.get("inventory", [])
    except (OSError, json.JSONDecodeError) as error:
        raise PermissionError("privacy inventory is unreadable") from error
    if not isinstance(inventory, list):
        raise PermissionError("privacy inventory is invalid")
    uploads_root = (protected / "uploads").resolve()
    plan: list[tuple[str, Path]] = []
    seen_sources: set[str] = set()
    seen_targets: set[Path] = set()
    for item in inventory:
        if not isinstance(item, dict):
            raise PermissionError("raw source privacy inventory is invalid")
        source_value = item.get("source")
        if not isinstance(source_value, str):
            raise PermissionError("raw source privacy inventory is invalid")
        if source_value not in allowed_sources:
            if item.get("data_class") == "raw_source":
                raise PermissionError("raw source privacy inventory is invalid")
            continue
        if source_value in seen_sources:
            raise PermissionError("raw source privacy inventory is invalid")
        source = source_value
        seen_sources.add(source)
        if item.get("data_class") != "raw_source":
            raise PermissionError("raw source privacy inventory is invalid")
        try:
            deadline = _timestamp(
                item["retention_deadline"], "raw source retention deadline",
            )
            resource_ref_value = item["resource_ref"]
        except (KeyError, TypeError, PermissionError) as error:
            raise PermissionError("raw source privacy inventory is invalid") from error
        if not isinstance(resource_ref_value, str) or not resource_ref_value:
            raise PermissionError("raw source privacy inventory is invalid")
        resource_ref = resource_ref_value
        if item.get("storage_scope") != "protected_uploads":
            raise PermissionError("raw source storage scope is invalid")
        target = (uploads_root / resource_ref).resolve()
        try:
            target.relative_to(uploads_root)
        except ValueError as error:
            raise PermissionError("raw source resource reference escapes protected storage") from error
        if target in seen_targets:
            raise PermissionError("raw source privacy inventory is invalid")
        seen_targets.add(target)
        expected_ref = expected_source_refs.get(source)
        if expected_ref is not None and not hmac.compare_digest(
            resource_ref, expected_ref,
        ):
            raise PermissionError("raw source privacy inventory is invalid")
        if deadline <= now:
            plan.append((source, target))
    if not set(expected_source_refs).issubset(seen_sources):
        raise PermissionError("raw source privacy inventory is invalid")
    return tuple(plan)


def _append_privacy_cleanup_audit(
    protected: Path, event: Mapping[str, object],
) -> None:
    protected.mkdir(parents=True, exist_ok=True, mode=0o700)
    protected.chmod(0o700)
    audit = protected / "privacy-cleanup-audit.jsonl"
    with audit.open("a", encoding="utf-8") as stream:
        stream.write(
            json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n"
        )
    audit.chmod(0o600)


def _run_scheduled_privacy_cleanup_unlocked(
    root: str | Path,
    *,
    clock: Callable[[], datetime],
    event_definition: EventDefinition,
) -> dict[str, object]:
    protected = Path(root) / "protected"
    now = clock()
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("privacy cleanup clock must be timezone-aware")
    try:
        operator_context = _validated_cleanup_event_binding(
            root, event_definition=event_definition,
        )
        raw_source_plan = _raw_source_expiry_plan(
            protected,
            now=now,
            allowed_sources=frozenset(
                source.role for source in event_definition.sources
            ),
            expected_source_refs=(
                operator_context.source_refs if operator_context is not None else {}
            ),
        )
        return _execute_scheduled_privacy_cleanup_unlocked(
            root, protected=protected, now=now, clock=clock,
            raw_source_plan=raw_source_plan,
            event_definition=event_definition,
            operator_code=(
                operator_context.operator_code
                if operator_context is not None else None
            ),
        )
    except Exception:
        _withdraw_public_staging(root)
        _append_privacy_cleanup_audit(protected, {
            "audit_reason_code": "scheduled_retention_expiry",
            "deletion_progress": "unknown",
            "failure_reason_code": "cleanup_failed",
            "run_at": now.astimezone(UTC).isoformat().replace("+00:00", "Z"),
            "state": "failed",
        })
        raise


@dataclass(frozen=True)
class _CleanupOperatorContext:
    operator_code: str
    source_refs: Mapping[str, str]


def _validated_cleanup_event_binding(
    root: str | Path, *, event_definition: EventDefinition,
) -> _CleanupOperatorContext | None:
    """Validate persisted event state before cleanup mutates protected data."""

    operator_path = Path(root) / "operator-state.json"
    pipeline_path = Path(root) / "pipeline-state.json"
    if not operator_path.exists() and not pipeline_path.exists():
        return None
    if not operator_path.is_file() or not pipeline_path.is_file():
        raise PermissionError("scheduled cleanup operator state is incomplete")
    try:
        operator_payload = json.loads(
            operator_path.read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite,
        )
        operator_code = operator_payload["operator_code"]
        event = operator_payload["event"]
        source_slots = operator_payload["source_slots"]
    except (OSError, KeyError, TypeError, json.JSONDecodeError) as error:
        raise PermissionError("scheduled cleanup operator state is unreadable") from error
    if (
        not isinstance(operator_code, str)
        or not isinstance(event, dict)
        or not isinstance(source_slots, dict)
        or not isinstance(event.get("key"), str)
        or not isinstance(event.get("definition_sha256"), str)
    ):
        raise PermissionError("scheduled cleanup operator code is invalid")
    if (
        not hmac.compare_digest(event["key"], event_definition.event_key)
        or not hmac.compare_digest(
            event["definition_sha256"], event_definition.sha256,
        )
    ):
        raise PermissionError("operator state belongs to a different event")
    allowed_sources = {source.role for source in event_definition.sources}
    if not set(source_slots).issubset(allowed_sources):
        raise PermissionError("scheduled cleanup source slots are invalid")
    source_refs: dict[str, str] = {}
    for role, slot in source_slots.items():
        resource_ref = slot.get("path") if isinstance(slot, dict) else None
        if (
            not isinstance(role, str)
            or not isinstance(resource_ref, str)
            or not resource_ref
            or Path(resource_ref).name != resource_ref
            or resource_ref in source_refs.values()
        ):
            raise PermissionError("scheduled cleanup source slots are invalid")
        source_refs[role] = resource_ref
    return _CleanupOperatorContext(operator_code, source_refs)


def _execute_scheduled_privacy_cleanup_unlocked(
    root: str | Path, *, protected: Path, now: datetime,
    clock: Callable[[], datetime], raw_source_plan: tuple[tuple[str, Path], ...],
    event_definition: EventDefinition, operator_code: str | None,
) -> dict[str, object]:
    derived_files_deleted = 0
    review_bindings_temporary = protected / "review-bindings.json.tmp"
    if review_bindings_temporary.is_file() or review_bindings_temporary.is_symlink():
        review_bindings_temporary.unlink()
        derived_files_deleted += 1
    evidence_vault = ProtectedEvidenceVault(
        protected / "raw-evidence", clock=clock,
    )
    expired_raw_evidence = evidence_vault.purge_expired()
    cache_deleted = 0
    for stage in ("github", "public_pages", "coresignal", "classification"):
        cache_deleted += CanonicalJsonCache(
            protected / "cache" / stage, clock=clock,
        ).delete_expired()
    raw_deleted = 0
    expired_stages: list[str] = []
    stage_root = protected / "stages"
    for stage in ("github", "public_pages", "coresignal", "classification"):
        path = stage_root / f"{stage}.json"
        temporary = path.with_name(path.name + ".tmp")
        if temporary.exists():
            temporary.unlink()
            raw_deleted += 1
        if not path.exists():
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            expiry = _timestamp(payload["expires_at"], f"{stage} retention deadline")
            expired = expiry <= now
        except (OSError, KeyError, TypeError, json.JSONDecodeError, PermissionError):
            expired = True
        if expired:
            path.unlink(missing_ok=True)
            raw_deleted += 1
            expired_stages.append(stage)
    raw_sources_deleted = 0
    expired_sources = [source for source, _target in raw_source_plan]
    for _source, target in raw_source_plan:
        if target.is_file() or target.is_symlink():
            target.unlink()
            raw_sources_deleted += 1
    source_expiry_raw_evidence = (
        evidence_vault.delete_all(reason="source_retention_expired")
        if expired_sources else []
    )
    raw_evidence_deleted = len(expired_raw_evidence) + len(source_expiry_raw_evidence)
    if expired_sources:
        for derived_root in (
            protected / "stages", protected / "cache", protected / "release",
        ):
            if not derived_root.exists():
                continue
            for target in derived_root.rglob("*"):
                if target.is_file() or target.is_symlink():
                    target.unlink()
                    derived_files_deleted += 1
        for name in (
            "enrichment-manifest.json", "review-bindings.json",
            "review-bindings.json.tmp",
            "review-cases.json", "reviewed-override.json",
        ):
            target = protected / name
            if target.is_file() or target.is_symlink():
                target.unlink()
                derived_files_deleted += 1
    if expired_stages or expired_sources or raw_evidence_deleted:
        _withdraw_public_staging(root)
        if operator_code is not None:
            try:
                from community_os.release_operator import ReleaseOperatorState

                operator_state = ReleaseOperatorState(
                    root,
                    operator_code=operator_code,
                    event_definition=event_definition,
                )
                if expired_stages:
                    getattr(operator_state, "invalidate_for_retention_expiry")(
                        expired_stages,
                    )
                if expired_sources:
                    getattr(operator_state, "invalidate_for_source_retention_expiry")(
                        expired_sources,
                    )
                if raw_evidence_deleted:
                    getattr(operator_state, "invalidate_for_retention_expiry")(
                        ("github", "public_pages", "coresignal"),
                    )
            except (OSError, TypeError, ValueError) as error:
                raise PermissionError(
                    "expired enrichment was deleted but derived-state invalidation failed"
                ) from error
    result: dict[str, object] = {
        "audit_reason_code": "scheduled_retention_expiry",
        "cache_entries_deleted": cache_deleted,
        "raw_enrichment_deleted": raw_deleted,
        "temporary_raw_evidence_deleted": raw_evidence_deleted,
        "raw_sources_deleted": raw_sources_deleted,
        "derived_files_deleted": derived_files_deleted,
        "run_at": now.astimezone(UTC).isoformat().replace("+00:00", "Z"),
        "state": "complete",
    }
    _append_privacy_cleanup_audit(protected, result)
    return result


def build_controlled_release_factory(
    runtime: ControlledReleaseRuntime,
) -> Callable[[object], Mapping[str, Operation]]:
    """Return a zero-network lazy factory invoked only after protected uploads exist."""

    def build(
        state: object,
        bundle: dict[str, object],
    ) -> Mapping[str, Operation]:
        try:
            now = runtime.clock()
            if now.tzinfo is None:
                raise ValueError("controlled release clock must be timezone-aware")
            privacy_record = bundle["privacy_operations"]
            assert isinstance(privacy_record, dict)
            definition = runtime.event_definition
            if (
                getattr(state, "event_key", None) != definition.event_key
                or getattr(state, "event_definition_sha256", None) != definition.sha256
            ):
                raise PermissionError(
                    "operator state and controlled release event definition do not match",
                )
            _validate_privacy_operations(
                privacy_record,
                definition=definition,
            )
            if getattr(state, "operator_code") != privacy_record["accountable_owner"]:
                raise PermissionError("operator and privacy accountable owner do not match")
            snapshot = getattr(state, "snapshot")()
            slots = snapshot.get("source_slots", {})
            configured_roles = {source.role for source in definition.sources}
            if not isinstance(slots, dict) or not set(slots) <= configured_roles:
                raise PermissionError("protected source roles do not match the event definition")
            observed_source_hashes: dict[str, str | None] = {}
            for source in definition.sources:
                slot = slots.get(source.role)
                if slot is None:
                    observed_source_hashes[source.role] = None
                    continue
                if (
                    not isinstance(slot, dict)
                    or not isinstance(slot.get("sha256"), str)
                    or not re.fullmatch(r"[0-9a-f]{64}", slot["sha256"])
                ):
                    raise PermissionError("protected source hash is invalid")
                observed_source_hashes[source.role] = str(slot["sha256"])
            approval_record = privacy_record["approval"]
            assert isinstance(approval_record, dict)
            event_approval = validate_event_approval_record(
                bundle["event_approval"],
                definition=definition,
                source_hashes=observed_source_hashes,
                excluded_subject_refs=tuple(privacy_record["excluded_subject_refs"]),
            )
            if event_approval.actor_code != approval_record["actor_code"]:
                raise PermissionError("event and privacy approval actors do not match")
            privacy_approved_at = _timestamp(
                approval_record["approved_at"], "privacy processing approval",
            )
            privacy_expires_at = _timestamp(
                approval_record["expires_at"],
                "privacy processing approval expiry",
            )
            if not privacy_approved_at <= now < privacy_expires_at:
                raise PermissionError("privacy processing approval is not currently valid")
            if not privacy_approved_at <= event_approval.approved_at <= now:
                raise PermissionError("event approval is not currently valid")
            getattr(state, "record_event_approval")(event_approval)
            if _timestamp(privacy_record["retention_deadline"], "privacy retention deadline") <= now:
                raise PermissionError("privacy source retention has expired")
            from community_os.enrichment.state import pseudonymous_id
            from community_os.privacy_operations import build_subject_exclusion_plan
            from community_os.release_operations import _load_applications

            excluded_subject_refs = tuple(privacy_record["excluded_subject_refs"])
            excluded_application_ids: frozenset[str] = frozenset()
            excluded_subject_refs_by_application_id: dict[str, str] = {}
            excluded_emails: frozenset[str] = frozenset()
            if excluded_subject_refs:
                application_rows = tuple(dict(item) for item in _load_applications(state))
                subject_to_application: dict[str, Mapping[str, object]] = {}
                for application in application_rows:
                    external_id = str(application.get("external_id") or "").strip()
                    if not external_id:
                        raise PermissionError("application identifiers are required for exclusions")
                    subject = pseudonymous_id(
                        external_id, secret=runtime.pseudonym_secret, key_version="v1",
                    )
                    if subject in subject_to_application:
                        raise PermissionError("application pseudonyms are duplicated")
                    subject_to_application[subject] = application
                exclusion_plan = build_subject_exclusion_plan(
                    excluded_subject_refs=excluded_subject_refs,
                    known_subject_refs=tuple(subject_to_application),
                )
                excluded_subject_set = set(excluded_subject_refs)
                excluded_application_ids = frozenset(
                    str(application["external_id"])
                    for subject, application in subject_to_application.items()
                    if subject in excluded_subject_set
                )
                excluded_subject_refs_by_application_id = {
                    str(application["external_id"]): subject
                    for subject, application in subject_to_application.items()
                    if subject in excluded_subject_set
                }
                excluded_emails = frozenset(
                    str(application.get("email") or "").strip().casefold()
                    for subject, application in subject_to_application.items()
                    if subject in excluded_subject_set
                    and str(application.get("email") or "").strip()
                )
            else:
                exclusion_plan = build_subject_exclusion_plan(
                    excluded_subject_refs=(), known_subject_refs=(),
                )
            _persist_subject_exclusion_plan(state, exclusion_plan)
            public_records = bundle["public_sources"]
            assert isinstance(public_records, dict)
            gates: dict[str, object] = {}
            for stage in ("github", "public_pages"):
                record = public_records[stage]
                if record is None:
                    if stage != "public_pages":
                        raise PermissionError(
                            "GitHub public-source approval is required",
                        )
                    continue
                gate = PublicSourceGate.from_record(record)
                if (
                    gate.accountable_owner != privacy_record["accountable_owner"]
                    or gate.notice_version != privacy_record["notice_version"]
                    or gate.notice_sent_at != privacy_record["notice_sent_at"]
                ):
                    raise PermissionError(f"{stage} authorization conflicts with privacy operations")
                gate.authorization_hash(stage, now=now)
                gates[stage] = gate
            if bundle["coresignal"] is not None:
                gate = CoresignalGate.from_record(bundle["coresignal"])
                if (
                    gate.notice_version == privacy_record["notice_version"]
                    or _timestamp(gate.notice_sent_at, "Coresignal notice") <= _timestamp(
                        privacy_record["notice_sent_at"], "privacy notice",
                    )
                ):
                    raise PermissionError(
                        "a distinct Coresignal transparency notice is required"
                    )
                gate.authorization_hash("coresignal", now=now)
                gates["coresignal"] = gate
            processor = None
            if bundle["semantic_processor"] is not None:
                processor = ProcessorApproval.from_record(bundle["semantic_processor"])
                processor.authorize(now=now)
                if processor.provider != "openai_responses":
                    raise PermissionError("semantic processor provider is not supported")
                if runtime.openai_api_key and processor.region == "global":
                    if (
                        runtime.openai_model != "gpt-5.6-sol"
                        or runtime.openai_reasoning_effort not in {"low", "medium"}
                    ):
                        raise PermissionError(
                            "global rich semantic production requires gpt-5.6-sol with low or medium reasoning",
                        )
                    rates = (
                        runtime.openai_input_cost_per_million_usd_micros,
                        runtime.openai_output_cost_per_million_usd_micros,
                    )
                    if any(rate is None or rate <= 0 for rate in rates):
                        raise PermissionError(
                            "global rich semantic production requires explicit positive Sol pricing inputs",
                        )
        except (AssertionError, PermissionError, TypeError, ValueError) as error:
            getattr(state, "block_for_invalid_approval")(
                reason_code="approval_record_invalid",
            )
            if isinstance(error, PermissionError):
                raise
            raise PermissionError(str(error)) from error

        disabled_optional_stages = _bundle_disabled_optional_stages(bundle)
        retention_days: dict[str, int] = {}
        for stage in ("github", "public_pages"):
            gate = gates.get(stage)
            if gate is None:
                getattr(state, "revoke_stage_authorization")(
                    stage, reason_code="authorization_revoked",
                )
                continue
            _record_gate(state, stage, gate, now=now)
            retention_days[stage] = gate.retention_days
        if "coresignal" in gates:
            gate = gates["coresignal"]
            if runtime.coresignal_token:
                _record_gate(state, "coresignal", gate, now=now)
                retention_days["coresignal"] = gate.retention_days
            else:
                getattr(state, "revoke_stage_authorization")(
                    "coresignal", reason_code="provider_token_missing",
                )
        else:
            getattr(state, "revoke_stage_authorization")(
                "coresignal", reason_code="authorization_revoked",
            )
        retention_days["classification"] = 30
        if processor is not None and runtime.openai_api_key:
            current = getattr(state, "pipeline").stage("classification")
            expected = processor.authorization_hash(now=now)
            if current.status is not StageStatus.LOCKED and (
                current.authorization_hash is None
                or not hmac.compare_digest(current.authorization_hash, expected)
            ):
                getattr(state, "revoke_stage_authorization")(
                    "classification", reason_code="authorization_replaced",
                )
                current = getattr(state, "pipeline").stage("classification")
            if current.status is StageStatus.LOCKED:
                getattr(state, "record_semantic_processor_authorization")(
                    processor, now=now,
                )
        else:
            getattr(state, "revoke_stage_authorization")(
                "classification", reason_code="authorization_revoked",
            )

        stage_deadlines = {
            stage: now + timedelta(days=days)
            for stage, days in retention_days.items()
        }
        stage_root = Path(getattr(state, "root")) / "protected" / "stages"
        for stage in retention_days:
            stage_path = stage_root / f"{stage}.json"
            if not stage_path.is_file():
                continue
            try:
                stage_payload = json.loads(stage_path.read_text(encoding="utf-8"))
                stage_deadlines[stage] = _timestamp(
                    stage_payload["expires_at"], f"{stage} retention deadline",
                )
            except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
                raise PermissionError(f"{stage} retention envelope is unreadable") from error
        _persist_privacy_plan(
            state, privacy_record, stage_deadlines, exclusion_plan=exclusion_plan,
            definition=definition,
            disabled_optional_stages=disabled_optional_stages,
        )

        def persist_retention_deadline(stage: str, deadline: datetime) -> None:
            if stage not in retention_days:
                raise ValueError("retention stage is not configured")
            stage_deadlines[stage] = deadline
            _persist_privacy_plan(
                state, privacy_record, stage_deadlines, exclusion_plan=exclusion_plan,
                definition=definition,
                disabled_optional_stages=disabled_optional_stages,
            )

        protected = Path(getattr(state, "root")) / "protected"
        evidence_vault = ProtectedEvidenceVault(
            protected / "raw-evidence", clock=runtime.clock,
        )
        caches = {
            stage: CanonicalJsonCache(protected / "cache" / stage, clock=runtime.clock)
            for stage in ("github", "public_pages", "coresignal", "classification")
        }

        def github_factory(verifier: Callable[[object], bool]) -> GitHubAdapter:
            token = resolve_github_token(
                runtime.github_token, runtime.github_token_supplier,
            )
            options: dict[str, object] = {}
            if rich_semantic_enabled:
                github_applications = tuple(
                    dict(item) for item in filtered_application_loader(state)
                )
                options.update({
                    "collect_rich_evidence": True,
                    "identity_literals": _rich_identity_corpus(
                        github_applications,
                        filtered_reconciliation_loader(state),
                    ),
                    "subject_identity_literals": (
                        _application_subject_identity_literals(
                            github_applications,
                            pseudonym_secret=runtime.pseudonym_secret,
                        )
                    ),
                })
            return GitHubAdapter(
                transport=runtime.transport_factory(), cache=caches["github"],
                pseudonym_secret=runtime.pseudonym_secret, clock=runtime.clock,
                sleeper=runtime.sleeper, source_verifier=verifier,
                token=token, evidence_vault=evidence_vault,
                **options,
            )

        def public_page_factory(verifier: Callable[[object], bool]) -> PublicPageAdapter:
            return PublicPageAdapter(
                transport=runtime.transport_factory(), cache=caches["public_pages"],
                pseudonym_secret=runtime.pseudonym_secret, clock=runtime.clock,
                source_verifier=verifier, evidence_vault=evidence_vault,
            )

        def disabled_public_pages() -> Sequence[Mapping[str, object]]:
            raise PermissionError(
                "public-page enrichment is disabled by the approval bundle",
            )

        def coresignal_factory(verifier: Callable[[object], bool]) -> CoresignalAdapter:
            if not runtime.coresignal_token:
                raise PermissionError("Coresignal token is missing from the managed runtime secret")
            return CoresignalAdapter(
                transport=runtime.transport_factory(), cache=caches["coresignal"],
                pseudonym_secret=runtime.pseudonym_secret, clock=runtime.clock,
                api_token=runtime.coresignal_token, source_verifier=verifier,
                sleeper=runtime.sleeper, evidence_vault=evidence_vault,
            )

        rich_semantic_enabled = bool(
            processor is not None
            and runtime.openai_api_key
            and processor.region == "global"
        )
        semantic_classifier = None
        if processor is not None and runtime.openai_api_key and not rich_semantic_enabled:
            semantic_classifier = SemanticClassifier(
                provider=OpenAIResponsesProvider(
                    api_key=runtime.openai_api_key, model=runtime.openai_model,
                    transport=_openai_transport(region=processor.region),
                    sleeper=runtime.sleeper,
                ),
                cache=caches["classification"], clock=runtime.clock,
                approval=processor, model=runtime.openai_model,
                prompt_version="talent-structured-v1",
                taxonomy_version="talent-taxonomy-v1", classifier_version="semantic-v1",
            )

        release_root = protected / "release"
        override_path = protected / "reviewed-override.json"

        def filtered_application_loader(target_state: object) -> tuple[Mapping[str, object], ...]:
            from community_os.release_operations import _load_applications

            return tuple(
                item for item in _load_applications(target_state)
                if str(item.get("external_id") or "").strip() not in excluded_application_ids
            )

        def filtered_reconciliation_loader(target_state: object) -> ReconciliationInputs:
            from community_os.release_operations import _load_reconciliation_inputs

            inputs = _load_reconciliation_inputs(target_state)
            if not excluded_application_ids:
                return inputs
            preference_records = tuple(
                item for item in inputs.preference_records
                if str(getattr(item, "email", "")).strip().casefold() not in excluded_emails
            )
            submission_records = tuple(
                item for item in inputs.submission_records
                if str(getattr(item, "email", "")).strip().casefold() not in excluded_emails
            )
            preferences: dict[str, dict[str, object]] = {}
            for record in preference_records:
                item = preferences.setdefault(
                    str(getattr(record, "team_name", "")),
                    {
                        "track": str(getattr(record, "track", "")),
                        "emails": set(), "source_refs": [],
                    },
                )
                item["emails"].add(str(getattr(record, "email", "")).casefold())
                item["source_refs"].append(str(getattr(record, "external_id", "")))
            projects: dict[str, dict[str, object]] = {}
            for record in submission_records:
                item = projects.setdefault(
                    str(getattr(record, "team_name", "")),
                    {
                        "track": str(getattr(record, "track", "")),
                        "emails": set(), "source_refs": [],
                        "repository_present": False, "demo_present": False,
                    },
                )
                item["emails"].add(str(getattr(record, "email", "")).casefold())
                item["source_refs"].append(str(getattr(record, "external_id", "")))
                item["repository_present"] = bool(
                    item["repository_present"]
                    or getattr(record, "repository_present", False)
                )
                item["demo_present"] = bool(
                    item["demo_present"] or getattr(record, "demo_present", False)
                )
            return ReconciliationInputs(
                applications=tuple(
                    item for item in inputs.applications
                    if str(item.get("external_id") or "").strip() not in excluded_application_ids
                ),
                preference_records=preference_records,
                submission_records=submission_records,
                preferences=preferences,
                projects=projects,
            )

        def privacy_cleanup() -> list[dict[str, object]]:
            expired_raw = evidence_vault.purge_expired()
            if expired_raw:
                getattr(state, "invalidate_for_retention_expiry")(
                    ("github", "public_pages", "coresignal"),
                )
            result = _run_scheduled_privacy_cleanup_unlocked(
                getattr(state, "root"),
                clock=runtime.clock,
                event_definition=definition,
            )
            result["temporary_raw_evidence_deleted"] = len(expired_raw)
            getattr(state, "record_privacy_status")("retention_cleanup", "complete")
            return [result]

        def aggregate() -> list[dict[str, object]]:
            from community_os.real_report import _private_json_write, build_real_release
            from community_os.partner_semantic_projection import (
                build_protected_partner_semantic_candidate_summary,
            )
            from community_os.semantic_metrics import semantic_taxonomy_sha256
            from community_os.release_operations import (
                derive_semantic_application_cohort_membership,
            )

            withdraw_local_partner_share(release_root)

            population_rows = tuple(
                dict(item) for item in filtered_application_loader(state)
            )
            external_ids = tuple(
                str(item.get("external_id") or "").strip()
                for item in population_rows
            )
            if (
                any(not value for value in external_ids)
                or len(external_ids) != len(set(external_ids))
            ):
                raise PermissionError(
                    "rich semantic authoritative application population is invalid",
                )
            expected_subject_refs = tuple(sorted(
                rich_semantic_subject_ref(
                    external_id, secret=runtime.pseudonym_secret,
                )
                for external_id in external_ids
            ))
            membership_by_external_id = (
                derive_semantic_application_cohort_membership(
                    state,
                    population_rows,
                    attendance_loader=None,
                )
            )
            membership_totals = {
                key: sum(row[key] for row in membership_by_external_id.values())
                for key in ("applied", "accepted", "present")
            }
            reviewed_values = getattr(state, "snapshot")().get(
                "reviewed_values", {},
            )
            if not isinstance(reviewed_values, dict):
                raise PermissionError("reviewed cohort values are invalid")
            expected_totals = {
                "accepted": reviewed_values.get("going_accepted", {}).get(
                    "reviewed_value",
                ) if isinstance(reviewed_values.get("going_accepted"), dict) else None,
                "present": reviewed_values.get("on_site_builders", {}).get(
                    "reviewed_value",
                ) if isinstance(reviewed_values.get("on_site_builders"), dict) else None,
            }
            if (
                membership_totals["applied"] != len(population_rows)
                or any(
                    type(expected_totals[key]) is not int
                    or membership_totals[key] > expected_totals[key]
                    for key in ("accepted", "present")
                )
                or expected_totals["present"] > expected_totals["accepted"]
            ):
                raise PermissionError(
                    "exact semantic cohort membership does not reconcile to reviewed counts",
                )
            reviewed_cohort_totals = {
                "all": len(population_rows),
                "accepted": expected_totals["accepted"],
                "attended": expected_totals["present"],
            }
            membership_by_subject = {
                rich_semantic_subject_ref(
                    external_id,
                    secret=runtime.pseudonym_secret,
                ): {
                    key: "member" if row[key] else "not_member"
                    for key in ("applied", "accepted", "present")
                }
                for external_id, row in membership_by_external_id.items()
            }
            source_snapshot_sha256 = getattr(state, "source_snapshot_sha256")()
            review_case_hashes = sorted(
                case.case_hash
                for case in getattr(state, "review_repository").list(
                    kind="classification",
                )
                if case.version == "rich_semantic_review_v1"
            )
            run_sha256 = hashlib.sha256(json.dumps(
                {
                    "event_approval_sha256": event_approval.sha256,
                    "review_case_hashes": review_case_hashes,
                    "source_snapshot_sha256": source_snapshot_sha256,
                    "subject_refs_sha256": hashlib.sha256(
                        "\n".join(expected_subject_refs).encode("ascii"),
                    ).hexdigest(),
                },
                ensure_ascii=True, sort_keys=True, separators=(",", ":"),
            ).encode("utf-8")).hexdigest()
            aggregate_time = runtime.clock()
            if aggregate_time.tzinfo is None or aggregate_time.utcoffset() is None:
                raise ValueError("rich semantic aggregate clock must be timezone-aware")
            semantic_binding_context = {
                "event_approval_sha256": event_approval.sha256,
                "event_definition_sha256": definition.sha256,
                "event_key": definition.event_key,
                "run_sha256": run_sha256,
                "source_snapshot_sha256": source_snapshot_sha256,
                "taxonomy_sha256": semantic_taxonomy_sha256(
                    definition.semantic.taxonomy_version,
                ),
                "taxonomy_version": definition.semantic.taxonomy_version,
            }
            semantic_aggregate = persist_internal_rich_semantic_aggregate(
                state,
                expected_subject_refs=expected_subject_refs,
                binding_context=semantic_binding_context,
                generated_at=aggregate_time,
                minimum_group_size=definition.privacy.minimum_count,
                membership_by_subject=membership_by_subject,
                reviewed_cohort_totals=reviewed_cohort_totals,
            )
            semantic_summary = (
                build_protected_partner_semantic_candidate_summary(semantic_aggregate)
                if semantic_aggregate is not None else None
            )
            semantic_context = None
            if semantic_summary is not None:
                semantic_context = {
                    **semantic_binding_context,
                    "population_sha256": semantic_summary.population_sha256,
                    "total_population": semantic_summary.total_population,
                }
                _private_json_write(
                    protected / "semantic-release-context.json",
                    semantic_context,
                )
            else:
                (protected / "semantic-release-context.json").unlink(missing_ok=True)
            generated_at = str(bundle["generated_at"])
            override = build_reviewed_override(state, generated_at=generated_at)
            projection = _authoritative_person_projection(
                state,
                semantic_aggregate=semantic_aggregate,
                pseudonym_secret=runtime.pseudonym_secret,
                application_loader=filtered_application_loader,
            )
            _private_json_write(override_path, override)
            snapshot = getattr(state, "snapshot")()
            slots = snapshot["source_slots"]
            uploads = Path(getattr(state, "protected_uploads"))
            coverage: dict[str, int] = {}
            for stage in ("github", "public_pages", "coresignal"):
                stage_path = protected / "stages" / f"{stage}.json"
                if not stage_path.is_file():
                    continue
                stage_payload = json.loads(stage_path.read_text(encoding="utf-8"))
                records = stage_payload.get("records") if isinstance(stage_payload, dict) else None
                if not isinstance(records, list):
                    raise ValueError(f"protected {stage} coverage is invalid")
                coverage[stage] = _observed_record_count(records, stage=stage)
            deletion = finalize_reviewed_evidence(
                vault=evidence_vault, caches=tuple(caches.values()),
                projection=projection or {}, semantic_projection=semantic_aggregate,
            )
            outputs = build_real_release(
                applications_path=uploads / str(slots["applications"]["path"]),
                attendance_path=uploads / str(slots["attendance"]["path"]),
                preferences_path=uploads / str(slots["preferences"]["path"]),
                submissions_path=uploads / str(slots["submissions"]["path"]),
                override_path=override_path, output_root=release_root,
                generated_at=generated_at, export_pdf=True,
                classification_projection=projection,
                enrichment_coverage=coverage,
                excluded_application_ids=excluded_application_ids,
                exclusion_set_sha256=exclusion_plan.exclusion_set_sha256,
                event_definition=definition,
                event_approval=event_approval,
                pseudonym_secret=runtime.pseudonym_secret,
                excluded_subject_refs_by_application_id=(
                    excluded_subject_refs_by_application_id
                ),
                semantic_summary=semantic_summary,
                semantic_context=semantic_context,
            )
            share_candidate_hashes = _scan_local_partner_share({
                name: release_root / name
                for name in _LOCAL_PARTNER_SHARE_NAMES
            })
            return [{
                "artifact_count": len(outputs),
                "evidence_projection_sha256": deletion["projection_sha256"],
                "manifest_hash": _sha256(outputs["manifest"]),
                "partner_share_privacy_scan_sha256": hashlib.sha256(
                    json.dumps(
                        share_candidate_hashes,
                        sort_keys=True, separators=(",", ":"),
                    ).encode("utf-8"),
                ).hexdigest(),
                "raw_evidence_deleted": deletion["raw_evidence_deleted"],
                "state": "complete",
            }]

        def report() -> list[dict[str, object]]:
            result = render_current_report_bundle(
                release_root,
                semantic_approval_secret=runtime.pseudonym_secret,
                semantic_authoritative_context=(
                    getattr(state, "semantic_release_authoritative_context")()
                ),
            )
            aggregate_path = protected / "rich-semantic-internal.aggregate.json"
            if aggregate_path.is_file():
                try:
                    current_aggregate = json.loads(
                        aggregate_path.read_text(encoding="utf-8"),
                    )
                    current_bindings = current_aggregate["bindings"]
                except (OSError, KeyError, TypeError, json.JSONDecodeError) as error:
                    raise PermissionError(
                        "semantic release QA aggregate binding is unreadable",
                    ) from error
                if not isinstance(current_bindings, dict):
                    raise PermissionError(
                        "semantic release QA aggregate binding is invalid",
                    )
                population_rows = tuple(
                    dict(item) for item in filtered_application_loader(state)
                )
                expected_subject_refs = tuple(sorted(
                    rich_semantic_subject_ref(
                        str(item.get("external_id") or "").strip(),
                        secret=runtime.pseudonym_secret,
                    )
                    for item in population_rows
                ))
                qa_receipt = generate_current_semantic_release_qa(
                    state,
                    expected_subject_refs=expected_subject_refs,
                    binding_context={
                        key: str(current_bindings[key])
                        for key in (
                            "event_approval_sha256", "event_definition_sha256",
                            "event_key", "run_sha256", "source_snapshot_sha256",
                            "taxonomy_sha256", "taxonomy_version",
                        )
                    },
                )
                result[0]["qa_sha256"] = getattr(qa_receipt, "sha256")
            return result

        def publish() -> Sequence[Mapping[str, object]]:
            from community_os.privacy_operations import ReleaseState
            from community_os.publication import stage_publication

            evidence = _release_evidence(
                state, bundle, release_root, now=now, definition=definition,
                semantic_approval_secret=runtime.pseudonym_secret,
            )
            release_state = getattr(state, "update_release_state")(evidence, now=now)
            privacy_record = bundle["privacy_operations"]
            assert isinstance(privacy_record, dict)
            _persist_privacy_operations(state, evidence, privacy_record, release_state)
            if release_state != ReleaseState.SAFE_TO_PUBLISH.value:
                raise PermissionError(f"controlled publication state is {release_state}")
            local_share = materialize_local_partner_share(release_root)
            manifest = stage_publication(
                Path(str(local_share["directory"])),
                Path(getattr(state, "root")) / "public-staging",
                allowlist=(
                    "talent-brief.real.html", "talent-brief.real.pdf",
                ),
                evidence=evidence, now=now,
            )
            publication_manifest = (
                Path(getattr(state, "root"))
                / "public-staging"
                / "publication-manifest.json"
            )
            return [{
                "artifact_count": len(manifest["artifact_hashes"]),
                "manifest_hash": hashlib.sha256(
                    publication_manifest.read_bytes(),
                ).hexdigest(),
                "release_state": release_state,
            }]

        base_classification = build_local_classification_service(
            state, pseudonym_secret=runtime.pseudonym_secret,
            semantic_classifier=semantic_classifier,
            evidence_vault=evidence_vault,
            application_loader=filtered_application_loader,
        )
        classification = base_classification
        classification_canary = None
        career_evidence_loader = None
        if runtime.coresignal_career_evaluation_root is not None:
            career_store = CoresignalCareerEvaluationStore(
                runtime.coresignal_career_evaluation_root,
                release_root=release_root,
                clock=runtime.clock,
            )
            career_evidence_loader = career_store.load_internal_semantic_evidence
        if rich_semantic_enabled:
            def rich_semantic_provider_factory(
                corpus: tuple[str, ...],
            ) -> OpenAIRichSemanticAssessmentProvider:
                return _build_rich_semantic_provider(runtime, corpus)

            rich_service_options = {
                "state": state,
                "base_classification": base_classification,
                "pseudonym_secret": runtime.pseudonym_secret,
                "provider_factory": rich_semantic_provider_factory,
                "cache": caches["classification"],
                "clock": runtime.clock,
                "application_loader": filtered_application_loader,
                "reconciliation_loader": filtered_reconciliation_loader,
                "career_evidence_loader": career_evidence_loader,
                "run_model": runtime.openai_model,
                "run_reasoning_effort": runtime.openai_reasoning_effort,
                "run_max_concurrency": 72,
                "input_cost_per_million_usd_micros": (
                    runtime.openai_input_cost_per_million_usd_micros
                ),
                "output_cost_per_million_usd_micros": (
                    runtime.openai_output_cost_per_million_usd_micros
                ),
            }
            classification_canary = build_rich_semantic_proposal_service(
                **rich_service_options, run_mode="canary",
            )
            classification = build_rich_semantic_proposal_service(
                **rich_service_options, run_mode="full",
            )

        services: dict[str, Operation] = {
            "privacy_cleanup": privacy_cleanup,
            "reconcile": build_reconcile_service(
                state, pseudonym_secret=runtime.pseudonym_secret,
                source_loader=filtered_reconciliation_loader,
            ),
            "github": build_adapter_service(
                state, stage="github", field="github",
                pseudonym_secret=runtime.pseudonym_secret,
                adapter_factory=github_factory,
                application_loader=filtered_application_loader,
            ),
            "public_pages": (
                build_adapter_service(
                    state, stage="public_pages", field="portfolio",
                    pseudonym_secret=runtime.pseudonym_secret,
                    adapter_factory=public_page_factory,
                    application_loader=filtered_application_loader,
                )
                if "public_pages" in gates else disabled_public_pages
            ),
            "coresignal": build_adapter_service(
                state, stage="coresignal", field="linkedin",
                pseudonym_secret=runtime.pseudonym_secret,
                adapter_factory=coresignal_factory,
                application_loader=filtered_application_loader,
            ),
            "classification": classification,
            "aggregate": aggregate, "report": report, "publish": publish,
        }
        registry = ProductionOperationRegistry.from_operator_state(
            state, services=services, caches=tuple(caches.values()),
            clock=runtime.clock, retention_days=retention_days,
            retention_invalidator=lambda stages: getattr(
                state, "invalidate_for_retention_expiry"
            )(stages),
            retention_persister=persist_retention_deadline,
        )
        callbacks = registry.callbacks()
        if classification_canary is not None:
            callbacks["classification_canary"] = registry.nonpersisting_callback(
                "classification", classification_canary,
            )
        callbacks["withdraw_publication"] = lambda: getattr(
            state, "invalidate_for_provider_result"
        )("coresignal")
        return callbacks

    return _ControlledReleaseOperationFactory(runtime.approval_bundle, build)
