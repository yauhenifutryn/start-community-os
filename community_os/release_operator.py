"""Protected release operator for raw exports, reviews, stages, preview, and exports."""

from __future__ import annotations

from contextlib import contextmanager
import copy
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from html import escape
import hashlib
import hmac
import fcntl
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import secrets
import stat
import threading
from typing import Callable, Iterable, Mapping, Sequence
from urllib.parse import parse_qs, urlparse
import webbrowser

from community_os.enrichment.evidence_vault import ProtectedEvidenceVault
from community_os.enrichment.state import PipelineState, StageStatus
from community_os.enrichment.release_pipeline import ReleasePipeline, canonical_hash
from community_os.event_definition import EventDefinition, EventSource
from community_os.release_operations import (
    ReviewCase, ReviewDecision, ReviewRepository, _review_case_source_hashes,
)
from community_os.rich_semantic_review import RichSemanticReviewStore


_CODE = re.compile(r"^[a-z][a-z0-9_]{1,63}$")
_AUTHENTICATED_OPERATOR_CODE = re.compile(r"^colleague_[0-9a-f]{32}$")
_RICH_SOURCE_FAMILIES = ("application", "career", "devpost", "projects")
_OPTIONAL_ENRICHMENT_STAGES = frozenset({"public_pages"})
_RICH_GITHUB_IMPORT_TRANSACTION_NAME = ".rich-github-import-transaction.json"
_CLASSIFICATION_CANARY_SAFE_ERROR = (
    "semantic canary is unavailable; full enrichment remains blocked"
)
_PRIVATE_SEMANTIC_SOURCE_BINDING_VERSION = (
    "rich-semantic-application-source-binding-v1"
)
_PRIVATE_STANDOUT_DECISION_VERSION = "private-standout-evidence-decision-v1"
_PRIVATE_STANDOUT_HMAC_DOMAIN = b"start-community-os:private-standout-evidence:v1\0"
_PRIVATE_HIGHLIGHT_NEUTRAL_CONNECTORS = frozenset({
    "a", "across", "after", "an", "and", "are", "as", "at", "before", "by",
    "for", "from", "had", "has", "have", "in", "into", "is", "of", "on",
    "or", "over", "that", "the", "their", "these", "this", "those", "through",
    "to", "under", "was", "were", "while", "with", "without",
})
_PRIVATE_HIGHLIGHT_NEUTRAL_CONTENT = frozenset({
    "ai", "api", "apis", "app", "application", "applications", "apps", "audit",
    "audits", "automation", "backend", "career", "careers", "cloud", "code",
    "customer", "customers", "data", "database", "databases", "decision",
    "decisions", "delivery", "deliveries", "deployment", "deployments", "education",
    "evidence", "feature", "features", "finance", "financial", "frontend",
    "function", "functions", "hardware", "health", "healthcare", "implementation",
    "implementations", "infrastructure", "integration", "integrations", "interface",
    "interfaces", "job", "jobs", "logistics", "mechanism", "mechanisms", "ml",
    "mobile", "model", "models", "operation", "operations", "pipeline", "pipelines",
    "platform", "platforms", "process", "processes", "product", "products", "project",
    "projects", "prototype", "prototypes", "receipt", "receipts", "record", "records",
    "release", "releases", "responsibilities", "responsibility", "retail", "retries",
    "retry", "role", "roles", "school", "schools", "security", "service", "services",
    "software", "source", "sources", "system", "systems", "team", "teams", "test",
    "testing", "tests", "tool", "tools", "user", "users", "web", "workflow",
    "workflows",
})
_PRIVATE_HIGHLIGHT_NEUTRAL_ACTIONS = frozenset({
    "automated", "automates", "built", "created", "creates", "delivered", "delivers",
    "deployed", "deploys", "designed", "designs", "developed", "develops", "handled",
    "handles", "implemented", "implements", "included", "includes", "integrated",
    "integrates", "launched", "led", "maintained", "maintains", "operated", "operates",
    "processed", "processes", "provided", "provides", "ran", "recorded", "records",
    "released", "retries", "retried", "runs", "served", "serves", "shipped", "spans",
    "supported", "supports", "tested", "used", "uses", "working",
})
_PRIVATE_HIGHLIGHT_NEUTRAL_DESCRIPTORS = frozenset({
    "active", "current", "deployed", "durable", "end", "explicit", "external", "full",
    "internal", "operational", "previous", "production", "repeated", "reviewed", "stack",
    "structured", "technical",
})
_PRIVATE_HIGHLIGHT_NEUTRAL_STARTS = frozenset({
    "a", "an", "application", "built", "career", "created", "delivered", "deployed",
    "designed", "developed", "evidence", "implemented", "integrated", "launched", "led",
    "operated", "product", "project", "released", "repeated", "reviewed", "service",
    "shipped", "system", "team", "tested", "the", "this", "tool", "workflow",
})
_PRIVATE_HIGHLIGHT_NEUTRAL_VOCABULARY = frozenset().union(
    _PRIVATE_HIGHLIGHT_NEUTRAL_CONNECTORS,
    _PRIVATE_HIGHLIGHT_NEUTRAL_CONTENT,
    _PRIVATE_HIGHLIGHT_NEUTRAL_ACTIONS,
    _PRIVATE_HIGHLIGHT_NEUTRAL_DESCRIPTORS,
)


def _neutral_private_highlight_summary(value: object) -> str | None:
    """Keep neutral evidence prose and reject praise or recommendations."""

    if not isinstance(value, str):
        return None
    normalized = " ".join(value.split())
    if (
        not normalized
        or len(normalized) > 500
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 ,.;:()'-]*", normalized) is None
    ):
        return None
    words = tuple(re.findall(r"[a-z]+|[0-9]+", normalized.casefold()))
    word_set = frozenset(word for word in words if not word.isdigit())
    if (
        len(words) < 4
        or words[0] not in _PRIVATE_HIGHLIGHT_NEUTRAL_STARTS
        or not word_set <= _PRIVATE_HIGHLIGHT_NEUTRAL_VOCABULARY
        or not word_set.intersection(_PRIVATE_HIGHLIGHT_NEUTRAL_CONTENT)
        or not word_set.intersection(_PRIVATE_HIGHLIGHT_NEUTRAL_ACTIONS)
    ):
        return None
    return normalized


def _neutral_private_standout_rationale(value: object) -> str | None:
    """Keep a short neutral rationale while excluding identifier-like numbers."""

    normalized = _neutral_private_highlight_summary(value)
    if (
        normalized is None
        or len(normalized) > 280
        or any(len(token) > 4 for token in re.findall(r"[0-9]+", normalized))
    ):
        return None
    return normalized


def _normalized_disabled_optional_stages(value: object) -> tuple[str, ...]:
    if value is None:
        return ()
    if (
        not isinstance(value, (list, tuple))
        or isinstance(value, (str, bytes))
        or any(not isinstance(item, str) for item in value)
    ):
        raise PermissionError("disabled optional stage policy is invalid")
    stages = tuple(value)
    if (
        len(stages) != len(set(stages))
        or not set(stages) <= _OPTIONAL_ENRICHMENT_STAGES
    ):
        raise PermissionError("disabled optional stage policy is invalid")
    return tuple(sorted(stages))


def _content_free_classification_canary_result(value: object) -> dict[str, object]:
    """Validate the bounded receipt while discarding all provider-owned content."""

    if (
        not isinstance(value, (list, tuple))
        or len(value) != 1
        or not isinstance(value[0], Mapping)
    ):
        raise PermissionError(_CLASSIFICATION_CANARY_SAFE_ERROR)
    receipt = value[0]
    if (
        receipt.get("state") != "complete"
        or type(receipt.get("canary_subject_count")) is not int
        or receipt.get("canary_subject_count") != 5
        or type(receipt.get("interrupted_subject_count")) is not int
        or receipt.get("interrupted_subject_count") != 0
    ):
        raise PermissionError(_CLASSIFICATION_CANARY_SAFE_ERROR)
    return {
        "canary_subject_count": 5,
        "full_enrichment": "blocked_pending_canary_review",
        "interrupted_subject_count": 0,
        "state": "complete",
    }


@contextmanager
def protected_mutation_lock(root: str | Path):
    """Serialize operator and scheduled privacy mutations across processes."""
    directory = Path(root)
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    lock_path = directory / ".operator-mutation.lock"
    with lock_path.open("a+", encoding="utf-8") as stream:
        lock_path.chmod(0o600)
        fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            yield
        finally:
            fcntl.flock(stream.fileno(), fcntl.LOCK_UN)


class ReleaseSourceSlot(StrEnum):
    APPLICATIONS = "applications"
    ATTENDANCE = "attendance"
    PREFERENCES = "preferences"
    SUBMISSIONS = "submissions"


def _event_binding(definition: EventDefinition) -> dict[str, object]:
    """Persist only non-personal event controls needed to bind operator state."""

    return {
        "definition_sha256": definition.sha256,
        "key": definition.event_key,
        "name": definition.event_name,
        "privacy_policy_profile": definition.privacy.policy_profile,
        "sources": [
            {
                "adapter_id": source.adapter_id,
                "media_type": source.media_type,
                "required": source.required,
                "role": source.role,
                "sheets": list(source.sheets),
            }
            for source in definition.sources
        ],
        "taxonomy_version": definition.semantic.taxonomy_version,
        "metric_registry_version": definition.semantic.metric_registry_version,
    }


def _source_role(value: str | ReleaseSourceSlot) -> str:
    role = value.value if isinstance(value, ReleaseSourceSlot) else value
    if not isinstance(role, str) or not _CODE.fullmatch(role):
        raise ValueError("source role must be machine-readable")
    return role


def _source_label(role: str) -> str:
    return {
        "applications": "Applications",
        "attendance": "Attendance",
        "preferences": "Track preferences",
        "submissions": "Submissions",
        "teams": "Teams",
    }.get(role, role.replace("_", " ").title())


def _media_extension(media_type: str) -> str:
    try:
        return {
            "application/json": ".json",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": ".xlsx",
            "text/csv": ".csv",
        }[media_type]
    except KeyError as error:
        raise ValueError(f"operator upload media type is unsupported: {media_type}") from error


@dataclass(frozen=True)
class OperatorAccessPolicy:
    """Trust only identity asserted by an authenticated proxy with a shared secret."""

    allowed_emails: frozenset[str]
    proxy_secret: str
    release_owner_emails: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        normalized = frozenset(value.strip().casefold() for value in self.allowed_emails)
        if not normalized or any("@" not in value for value in normalized):
            raise ValueError("operator colleague allowlist is required")
        if len(self.proxy_secret) < 12:
            raise ValueError("operator proxy secret is too short")
        owners = frozenset(
            value.strip().casefold() for value in self.release_owner_emails
        )
        if not owners <= normalized:
            raise ValueError("operator release owners must be allowlisted colleagues")
        object.__setattr__(self, "allowed_emails", normalized)
        object.__setattr__(self, "release_owner_emails", owners)

    def authorize(self, headers: Mapping[str, str]) -> bool:
        email = str(headers.get("X-Operator-Email") or "").strip().casefold()
        provided = str(headers.get("X-Operator-Proxy-Secret") or "")
        return email in self.allowed_emails and hmac.compare_digest(provided, self.proxy_secret)

    def pseudonymous_actor(self, headers: Mapping[str, str], *, secret: bytes) -> str:
        """Derive a stable code for an authenticated colleague without storing email."""

        if not self.authorize(headers):
            raise PermissionError("operator authentication is required")
        if len(secret) < 16:
            raise ValueError("operator pseudonym secret must contain at least 16 bytes")
        email = str(headers.get("X-Operator-Email") or "").strip().casefold()
        digest = hmac.new(
            secret, f"operator-colleague:{email}".encode("utf-8"), hashlib.sha256,
        ).hexdigest()[:32]
        return f"colleague_{digest}"

    def authorize_release_owner(self, headers: Mapping[str, str]) -> bool:
        """Require both proxy authentication and an explicit release-owner role."""

        email = str(headers.get("X-Operator-Email") or "").strip().casefold()
        return self.authorize(headers) and email in self.release_owner_emails


class _ReleaseBoundRichSemanticReviewStore(RichSemanticReviewStore):
    """Revoke release derivatives before accepting review-gated semantic work."""

    def __init__(
        self, root: str | Path, *, release_root: str | Path,
        review_repository: ReviewRepository, clock: Callable[[], datetime],
        transient_cache_root: str | Path,
        approval_verifier: Callable[[str], bool],
        current_application_sha256: Callable[[], str | None],
        on_pending_proposal: Callable[[], None],
        review_context_hashes: Mapping[str, str],
        decision_signing_secret: bytes | None = None,
    ) -> None:
        if not callable(current_application_sha256):
            raise TypeError("current application source hash provider is required")
        self._on_pending_proposal = on_pending_proposal
        self._current_application_sha256 = current_application_sha256
        super().__init__(
            root, release_root=release_root,
            review_repository=review_repository, clock=clock,
            transient_cache_root=transient_cache_root,
            approval_verifier=approval_verifier,
            review_context_hashes=review_context_hashes,
            decision_signing_secret=decision_signing_secret,
        )
        self.application_source_bindings = (
            self.root / "application-source-bindings"
        )
        self.application_source_bindings.mkdir(
            parents=True, exist_ok=True, mode=0o700,
        )
        self.application_source_bindings.chmod(0o700)

    def _binding_path(self, case_code: str) -> Path:
        if not _CODE.fullmatch(case_code):
            raise ValueError("semantic review case code is invalid")
        return self.application_source_bindings / f"{case_code}.json"

    def _application_source_binding_hmac(
        self, material: Mapping[str, object],
    ) -> str | None:
        """Authenticate binding material with the in-memory review authority."""

        secret = self._decision_signing_secret
        if not isinstance(secret, bytes) or len(secret) < 16:
            return None
        try:
            encoded = json.dumps(
                material, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
        except (TypeError, ValueError):
            return None
        message = (
            b"release-operator:application-source-binding\0" + encoded
        )
        return hmac.new(secret, message, hashlib.sha256).hexdigest()

    def application_source_matches(
        self, case: ReviewCase, current_sha256: str,
    ) -> bool:
        """Require an exact protected application snapshot for private names."""

        if (
            not isinstance(case, ReviewCase)
            or not re.fullmatch(r"[0-9a-f]{64}", current_sha256)
        ):
            return False
        path = self._binding_path(case.case_code)
        directory_descriptor: int | None = None
        file_descriptor: int | None = None
        try:
            if self.application_source_bindings.is_symlink() or path.is_symlink():
                return False
            directory_descriptor = os.open(
                self.application_source_bindings,
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0),
            )
            if not stat.S_ISDIR(os.fstat(directory_descriptor).st_mode):
                return False
            file_descriptor = os.open(
                path.name,
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NONBLOCK", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=directory_descriptor,
            )
            before = os.fstat(file_descriptor)
            if (
                not stat.S_ISREG(before.st_mode)
                or stat.S_IMODE(before.st_mode) != 0o600
                or before.st_nlink != 1
                or not 1 <= before.st_size <= 4_096
            ):
                return False
            chunks: list[bytes] = []
            byte_count = 0
            while byte_count <= 4_096:
                chunk = os.read(file_descriptor, 4_097 - byte_count)
                if not chunk:
                    break
                chunks.append(chunk)
                byte_count += len(chunk)
            after = os.fstat(file_descriptor)
            if (
                byte_count != before.st_size
                or byte_count > 4_096
                or after.st_size != before.st_size
                or after.st_mode != before.st_mode
                or after.st_nlink != before.st_nlink
            ):
                return False
            raw_payload = b"".join(chunks)
            payload = json.loads(raw_payload.decode("utf-8"))
            canonical_payload = (
                json.dumps(
                    payload, ensure_ascii=True, sort_keys=True,
                    separators=(",", ":"), allow_nan=False,
                ) + "\n"
            ).encode("utf-8")
            if not hmac.compare_digest(raw_payload, canonical_payload):
                return False
        except (
            OSError, TypeError, UnicodeDecodeError, ValueError,
            json.JSONDecodeError,
        ):
            return False
        finally:
            if file_descriptor is not None:
                os.close(file_descriptor)
            if directory_descriptor is not None:
                os.close(directory_descriptor)
        if not isinstance(payload, dict) or set(payload) != {
            "application_sha256", "binding_hmac", "binding_version",
            "case_code", "case_hash", "subject_code",
        }:
            return False
        binding_hmac = payload.get("binding_hmac")
        material = {
            key: value for key, value in payload.items()
            if key != "binding_hmac"
        }
        expected_hmac = self._application_source_binding_hmac(material)
        if (
            not isinstance(binding_hmac, str)
            or not re.fullmatch(r"[0-9a-f]{64}", binding_hmac)
            or expected_hmac is None
            or not hmac.compare_digest(binding_hmac, expected_hmac)
        ):
            return False
        return (
            payload.get("binding_version")
            == _PRIVATE_SEMANTIC_SOURCE_BINDING_VERSION
            and hmac.compare_digest(str(payload.get("case_code")), case.case_code)
            and hmac.compare_digest(str(payload.get("case_hash")), case.case_hash)
            and hmac.compare_digest(
                str(payload.get("subject_code")), case.subject_code,
            )
            and hmac.compare_digest(
                str(payload.get("application_sha256")), current_sha256,
            )
        )

    def submit(
        self, value: object, *, known_identity_literals: Iterable[str] | None = None,
    ) -> ReviewCase:
        source_sha256 = self._current_application_sha256()
        self._on_pending_proposal()
        case = super().submit(
            value, known_identity_literals=known_identity_literals,
        )
        current_sha256 = self._current_application_sha256()
        path = self._binding_path(case.case_code)
        if (
            not isinstance(source_sha256, str)
            or not re.fullmatch(r"[0-9a-f]{64}", source_sha256)
            or not isinstance(current_sha256, str)
            or not hmac.compare_digest(source_sha256, current_sha256)
        ):
            path.unlink(missing_ok=True)
            return case
        material = {
            "application_sha256": source_sha256,
            "binding_version": _PRIVATE_SEMANTIC_SOURCE_BINDING_VERSION,
            "case_code": case.case_code,
            "case_hash": case.case_hash,
            "subject_code": case.subject_code,
        }
        binding_hmac = self._application_source_binding_hmac(material)
        if binding_hmac is None:
            path.unlink(missing_ok=True)
            return case
        self._write(path, {**material, "binding_hmac": binding_hmac})
        return case


def append_operator_access_audit(
    root: str | Path, *, action: str, actor_code: str,
    subject_code: str, reason_code: str,
    event_key: str | None = None,
    event_definition_sha256: str | None = None,
) -> None:
    """Append one code-only access event under a process-safe file lock."""

    if not all(_CODE.fullmatch(value) for value in (action, actor_code, subject_code, reason_code)):
        raise ValueError("operator access audit fields must be machine-readable codes")
    if event_key is None or event_definition_sha256 is None:
        try:
            state = json.loads(
                (Path(root) / "operator-state.json").read_text(encoding="utf-8"),
            )
            event = state["event"]
            event_key = event["key"]
            event_definition_sha256 = event["definition_sha256"]
        except (OSError, json.JSONDecodeError, KeyError, TypeError) as error:
            raise ValueError("operator access audit requires an event binding") from error
    if (
        not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", event_key)
        or not re.fullmatch(r"[0-9a-f]{64}", event_definition_sha256)
    ):
        raise ValueError("operator access audit event binding is invalid")
    protected = Path(root) / "protected"
    protected.mkdir(parents=True, exist_ok=True, mode=0o700)
    protected.chmod(0o700)
    path = protected / "operator-access-audit.jsonl"
    event = {
        "action": action, "actor_code": actor_code, "reason_code": reason_code,
        "event_definition_sha256": event_definition_sha256,
        "event_key": event_key, "subject_code": subject_code,
        "timestamp": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
    }
    with path.open("a", encoding="utf-8") as stream:
        path.chmod(0o600)
        fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
        try:
            stream.write(json.dumps(event, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        finally:
            fcntl.flock(stream.fileno(), fcntl.LOCK_UN)


class ReleaseOperatorState:
    VERSION = "release-operator-v2"
    LEGACY_VERSION = "release-operator-v1"

    def __init__(
        self,
        root: str | Path,
        *,
        operator_code: str,
        event_definition: EventDefinition,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not _CODE.fullmatch(operator_code):
            raise ValueError("operator_code must be machine-readable")
        if not isinstance(event_definition, EventDefinition):
            raise ValueError("operator event definition is required")
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.root.chmod(0o700)
        self.protected_uploads = self.root / "protected" / "uploads"
        self.protected_uploads.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.protected_uploads.chmod(0o700)
        self.operator_code = operator_code
        self._active_actor_code = operator_code
        self._clock = clock or (lambda: datetime.now(UTC))
        self._disabled_optional_stages: tuple[str, ...] = ()
        self._optional_stage_policy_bound = False
        self._semantic_approval_secret: bytes | None = None
        self._event_definition = event_definition
        self.path = self.root / "operator-state.json"
        self.pipeline_path = self.root / "pipeline-state.json"
        self.review_repository = ReviewRepository(
            self.root / "protected" / "review-cases.json"
        )
        existing_state = self.path.exists()
        if existing_state:
            self._data = self._load(event_definition=self._event_definition)
            self.pipeline = PipelineState.load(self.pipeline_path)
        else:
            definition = self._event_definition
            self._data = {
                "audit_events": [],
                "classification_reviews": {}, "corrections": {}, "identity_reviews": {},
                "event": _event_binding(definition),
                "event_approval": None,
                "event_summary": {
                    "accepted": None, "applied": None, "present": None,
                    "source_snapshot_sha256": None, "tracks": [],
                },
                "operational_facts": {}, "reviewed_values": {},
                "operator_code": operator_code, "release_state": "Blocked",
                "private_semantic_decisions": {},
                "privacy_operations": {
                    "accountable_owner": operator_code, "deletions": "unreconciled",
                    "exclusions": "unreconciled", "notice": "missing",
                    "objections": "unreconciled",
                    "retention_cleanup": "pending", "suppressions": "unreconciled",
                },
                "source_slots": {}, "state_version": self.VERSION, "team_reviews": {},
            }
            self.pipeline = PipelineState.create(self.pipeline_path, {
                "reconcile": StageStatus.ALLOWED,
                "github": StageStatus.LOCKED,
                "public_pages": StageStatus.LOCKED,
                "coresignal": StageStatus.LOCKED,
                "classification": StageStatus.LOCKED,
                "aggregate": StageStatus.ALLOWED,
                "report": StageStatus.ALLOWED,
                "publish": StageStatus.ALLOWED,
                "analytics": StageStatus.ALLOWED,
            })
            self._persist()
        if existing_state:
            self._recover_operator_transactions_nonblocking(
                repair_non_gated_locks=True,
            )
        self._reset_rich_semantic_review_store()

    def configure_semantic_release_authority(self, secret: bytes) -> None:
        """Attach the in-memory approval verifier without persisting the secret."""

        if not isinstance(secret, bytes) or len(secret) < 16:
            raise ValueError("semantic release approval secret must contain at least 16 bytes")
        self._semantic_approval_secret = secret
        self.rich_semantic_reviews.configure_decision_authority(secret)

    def _verified_application_source(
        self,
    ) -> tuple[bytes, int, str] | None:
        """Read the exact validated application snapshot or fail closed."""

        slots = self._data.get("source_slots")
        slot = slots.get("applications") if isinstance(slots, dict) else None
        if not isinstance(slot, dict):
            return None
        filename = slot.get("path")
        expected_sha256 = slot.get("sha256")
        row_count = slot.get("row_count")
        if (
            slot.get("state") != "validated"
            or not isinstance(filename, str)
            or Path(filename).name != filename
            or not isinstance(expected_sha256, str)
            or not re.fullmatch(r"[0-9a-f]{64}", expected_sha256)
            or type(row_count) is not int
            or row_count < 1
        ):
            return None
        source_path = self.protected_uploads / filename
        try:
            if (
                self.protected_uploads.is_symlink()
                or source_path.is_symlink()
                or not source_path.is_file()
                or source_path.stat().st_size > 25 * 1024 * 1024
                or source_path.parent.resolve() != self.protected_uploads.resolve()
            ):
                return None
            source_bytes = source_path.read_bytes()
            if not hmac.compare_digest(
                hashlib.sha256(source_bytes).hexdigest(), expected_sha256,
            ):
                return None
            return source_bytes, row_count, expected_sha256
        except (OSError, PermissionError, TypeError, ValueError):
            return None

    def _current_application_sha256(self) -> str | None:
        source = self._verified_application_source()
        return source[2] if source is not None else None

    def _standout_evidence_hmac(
        self, material: Mapping[str, object],
    ) -> str | None:
        secret = self._semantic_approval_secret
        if not isinstance(secret, bytes) or len(secret) < 16:
            return None
        try:
            encoded = json.dumps(
                material, ensure_ascii=True, sort_keys=True,
                separators=(",", ":"), allow_nan=False,
            ).encode("utf-8")
        except (TypeError, ValueError):
            return None
        return hmac.new(
            secret, _PRIVATE_STANDOUT_HMAC_DOMAIN + encoded, hashlib.sha256,
        ).hexdigest()

    def _validated_standout_evidence(
        self, value: object, *, case: ReviewCase,
        record: Mapping[str, object], current_application_sha256: str,
    ) -> dict[str, object] | None:
        if not isinstance(value, Mapping) or set(value) != {
            "action", "actor_code", "application_sha256", "case_code",
            "case_hash", "decided_at", "decision_hmac", "decision_version",
            "evidence_refs", "fact_sha256", "rationale",
        }:
            return None
        fact = record.get("fact")
        receipt = record.get("audit_receipt")
        if not isinstance(fact, Mapping) or not isinstance(receipt, Mapping):
            return None
        provenance = fact.get("provenance")
        if not isinstance(provenance, Mapping):
            return None
        current_references = provenance.get("evidence_refs")
        if (
            not isinstance(current_references, list)
            or not current_references
            or any(not isinstance(item, str) for item in current_references)
        ):
            return None
        references = value.get("evidence_refs")
        rationale = _neutral_private_standout_rationale(value.get("rationale"))
        decision_hmac = value.get("decision_hmac")
        material = {
            key: item for key, item in value.items() if key != "decision_hmac"
        }
        expected_hmac = self._standout_evidence_hmac(material)
        try:
            decided_at = datetime.fromisoformat(
                str(value.get("decided_at")).replace("Z", "+00:00"),
            )
        except ValueError:
            return None
        if (
            value.get("decision_version") != _PRIVATE_STANDOUT_DECISION_VERSION
            or value.get("action") != "standout_evidence"
            or not isinstance(value.get("actor_code"), str)
            or not _AUTHENTICATED_OPERATOR_CODE.fullmatch(str(value["actor_code"]))
            or value.get("case_code") != case.case_code
            or value.get("case_hash") != case.case_hash
            or value.get("application_sha256") != current_application_sha256
            or value.get("fact_sha256") != receipt.get("fact_sha256")
            or references != sorted(set(current_references))
            or rationale is None
            or rationale != value.get("rationale")
            or decided_at.tzinfo is None
            or not isinstance(decision_hmac, str)
            or not re.fullmatch(r"[0-9a-f]{64}", decision_hmac)
            or expected_hmac is None
            or not hmac.compare_digest(decision_hmac, expected_hmac)
        ):
            return None
        return dict(value)

    def record_standout_evidence(
        self, case_code: str, case_hash: str, rationale: str,
    ) -> None:
        """Record a private operator judgment bound to finalized evidence."""

        if not _AUTHENTICATED_OPERATOR_CODE.fullmatch(self._active_actor_code):
            raise PermissionError(
                "standout evidence requires an authenticated operator",
            )
        cases = [
            item for item in self.review_repository.list(kind="classification")
            if item.case_code == case_code
        ]
        if (
            len(cases) != 1
            or cases[0].version != "rich_semantic_review_v1"
            or cases[0].status != "resolved"
            or not isinstance(case_hash, str)
            or not hmac.compare_digest(cases[0].case_hash, case_hash)
            or case_code not in self.rich_semantic_reviews.finalized_case_codes()
        ):
            raise PermissionError("standout evidence requires a finalized current case")
        case = cases[0]
        current_application_sha256 = self._current_application_sha256()
        if (
            not isinstance(current_application_sha256, str)
            or not self.rich_semantic_reviews.application_source_matches(
                case, current_application_sha256,
            )
        ):
            raise PermissionError("standout evidence application binding is stale")
        normalized_rationale = _neutral_private_standout_rationale(rationale)
        if normalized_rationale is None:
            raise ValueError("standout evidence rationale must be bounded neutral evidence prose")
        identity = self._private_semantic_identity_index()
        if identity is None or not isinstance(identity.get("by_subject_code"), dict):
            raise PermissionError("standout evidence identity binding is unavailable")
        names = tuple(identity["by_subject_code"].values())
        current_name = identity["by_subject_code"].get(case.subject_code)
        if not isinstance(current_name, str) or not current_name:
            raise PermissionError("standout evidence identity binding is unavailable")
        if any(
            isinstance(name, str)
            and name.casefold() in normalized_rationale.casefold()
            for name in names
        ):
            raise ValueError("standout evidence rationale must not contain an applicant name")
        reviewed_path = self.rich_semantic_reviews.reviewed / f"{case_code}.json"
        record = self.rich_semantic_reviews._load_reviewed_record(reviewed_path)
        fact = record.get("fact")
        receipt = record.get("audit_receipt")
        if not isinstance(fact, Mapping) or not isinstance(receipt, Mapping):
            raise PermissionError("standout evidence reviewed record is invalid")
        provenance = fact.get("provenance")
        references = (
            provenance.get("evidence_refs")
            if isinstance(provenance, Mapping) else None
        )
        fact_sha256 = receipt.get("fact_sha256")
        if (
            not isinstance(references, list)
            or not references
            or any(not isinstance(item, str) for item in references)
            or not isinstance(fact_sha256, str)
            or not re.fullmatch(r"[0-9a-f]{64}", fact_sha256)
        ):
            raise PermissionError("standout evidence requires existing evidence references")
        material = {
            "action": "standout_evidence",
            "actor_code": self._active_actor_code,
            "application_sha256": current_application_sha256,
            "case_code": case.case_code,
            "case_hash": case.case_hash,
            "decided_at": self._clock().astimezone(UTC).isoformat().replace(
                "+00:00", "Z",
            ),
            "decision_version": _PRIVATE_STANDOUT_DECISION_VERSION,
            "evidence_refs": sorted(set(references)),
            "fact_sha256": fact_sha256,
            "rationale": normalized_rationale,
        }
        decision_hmac = self._standout_evidence_hmac(material)
        if decision_hmac is None:
            raise PermissionError("standout evidence signing authority is unavailable")
        decisions = self._data.get("private_semantic_decisions")
        if not isinstance(decisions, dict):
            raise PermissionError("private semantic decision state is invalid")
        decisions[case.case_code] = {**material, "decision_hmac": decision_hmac}
        self._audit(
            "standout_evidence_recorded", case.case_code,
            "operator_evidence_decision",
        )
        self._persist()

    def _private_semantic_identity_index(
        self,
    ) -> dict[str, object] | None:
        """Bind current application names to semantic subjects only in memory."""

        secret = self._semantic_approval_secret
        source = self._verified_application_source()
        if not isinstance(secret, bytes) or len(secret) < 16 or source is None:
            return None
        source_bytes, row_count, source_sha256 = source
        try:
            from community_os.release_operations import (
                _application_rows_from_bytes,
                rich_semantic_subject_ref,
            )

            applications = _application_rows_from_bytes(
                source_bytes, event_definition=self.event_definition,
            )
            if len(applications) != row_count:
                return None
            by_subject_code: dict[str, str] = {}
            by_subject_ref: dict[str, str] = {}
            seen_external_ids: set[str] = set()
            for application in applications:
                external_id = str(application.get("external_id") or "").strip()
                name = " ".join(str(application.get("name") or "").split())
                if (
                    not external_id
                    or external_id in seen_external_ids
                    or len(name) > 200
                ):
                    return None
                seen_external_ids.add(external_id)
                if not name:
                    continue
                subject_ref = rich_semantic_subject_ref(
                    external_id, secret=secret,
                )
                subject_code = "semantic_" + hashlib.sha256(
                    subject_ref.encode("ascii"),
                ).hexdigest()[:24]
                if (
                    subject_ref in by_subject_ref
                    or subject_code in by_subject_code
                ):
                    return None
                by_subject_ref[subject_ref] = name
                by_subject_code[subject_code] = name
            return {
                "by_subject_code": by_subject_code,
                "by_subject_ref": by_subject_ref,
                "source_sha256": source_sha256,
            }
        except (OSError, PermissionError, TypeError, ValueError):
            return None

    def _private_semantic_operator_view(self) -> dict[str, object]:
        """Return detached name-bound review views without persisting identity links."""

        identity = self._private_semantic_identity_index()
        if identity is None:
            return {"highlights": [], "open_names": {}}
        by_subject_code = identity["by_subject_code"]
        by_subject_ref = identity["by_subject_ref"]
        current_source_sha256 = identity["source_sha256"]
        if (
            not isinstance(by_subject_code, dict)
            or not isinstance(by_subject_ref, dict)
            or not isinstance(current_source_sha256, str)
        ):
            return {"highlights": [], "open_names": {}}
        cases = tuple(
            case for case in self.review_repository.list(kind="classification")
            if case.version == "rich_semantic_review_v1"
        )
        open_names = {
            case.case_code: by_subject_code[case.subject_code]
            for case in cases
            if (
                case.status == "open"
                and case.subject_code in by_subject_code
                and self.rich_semantic_reviews.application_source_matches(
                    case, current_source_sha256,
                )
            )
        }
        finalized = self.rich_semantic_reviews.finalized_case_codes()
        from community_os.enrichment.semantic_taxonomy import (
            CAREER_FIELDS,
            PROJECT_FIELDS,
        )

        non_highlight_values = {
            "unknown", "none", "none_observed", "insufficient",
            "derivative", "ordinary", "no_founder_evidence",
        }
        stored_decisions = self._data.get("private_semantic_decisions")
        if not isinstance(stored_decisions, dict):
            stored_decisions = {}
        highlights: list[dict[str, object]] = []
        for case in cases:
            if (
                case.status != "resolved"
                or case.case_code not in finalized
                or not self.rich_semantic_reviews.application_source_matches(
                    case, current_source_sha256,
                )
            ):
                continue
            reviewed_path = (
                self.rich_semantic_reviews.reviewed / f"{case.case_code}.json"
            )
            if reviewed_path.is_symlink() or not reviewed_path.is_file():
                continue
            try:
                record = self.rich_semantic_reviews._load_reviewed_record(
                    reviewed_path,
                )
                fact = record["fact"]
                if not isinstance(fact, Mapping):
                    continue
                subject_ref = fact.get("subject_ref")
                if not isinstance(subject_ref, str):
                    continue
                name = by_subject_ref.get(subject_ref)
                expected_subject_code = "semantic_" + hashlib.sha256(
                    subject_ref.encode("ascii"),
                ).hexdigest()[:24]
                if name is None or not hmac.compare_digest(
                    case.subject_code, expected_subject_code,
                ):
                    continue
                narrative = fact.get("reviewed_narrative")
                taxonomy = fact.get("semantic_taxonomy")
                if not isinstance(narrative, Mapping) or not isinstance(taxonomy, Mapping):
                    continue
                summaries: dict[str, str] = {}
                for scope in ("project", "career"):
                    item = narrative.get(scope)
                    if not isinstance(item, Mapping):
                        continue
                    references = item.get("evidence_refs")
                    text = item.get("text")
                    neutral_text = _neutral_private_highlight_summary(text)
                    if (
                        item.get("state") == "reviewed"
                        and neutral_text is not None
                        and isinstance(references, list)
                        and bool(references)
                    ):
                        summaries[scope] = neutral_text
                evidence_by_dimension = taxonomy.get("evidence_by_dimension")
                if not isinstance(evidence_by_dimension, Mapping):
                    continue
                dimensions: list[dict[str, object]] = []
                for scope, fields in (
                    ("project", PROJECT_FIELDS), ("career", CAREER_FIELDS),
                ):
                    values = taxonomy.get(scope)
                    if not isinstance(values, Mapping):
                        continue
                    for field in fields:
                        references = evidence_by_dimension.get(field)
                        value = values.get(field)
                        if not isinstance(references, list) or not references:
                            continue
                        if isinstance(value, list):
                            shown = [
                                item for item in value
                                if isinstance(item, str)
                                and item not in non_highlight_values
                            ]
                            if not shown:
                                continue
                            display_value: object = shown
                        elif (
                            isinstance(value, str)
                            and value not in non_highlight_values
                        ):
                            display_value = value
                        else:
                            continue
                        dimensions.append({
                            "evidence_count": len(references),
                            "field": field,
                            "scope": scope,
                            "value": display_value,
                        })
                if not summaries and not dimensions:
                    continue
                standout = self._validated_standout_evidence(
                    stored_decisions.get(case.case_code),
                    case=case,
                    record=record,
                    current_application_sha256=current_source_sha256,
                )
                highlights.append({
                    "case_code": case.case_code,
                    "case_hash": case.case_hash,
                    "dimensions": dimensions,
                    "name": name,
                    "standout": standout,
                    "summaries": summaries,
                })
            except (OSError, PermissionError, TypeError, ValueError):
                continue
        return {"highlights": highlights, "open_names": open_names}

    def configure_optional_stage_policy(
        self, disabled_stages: Sequence[str] | None,
    ) -> None:
        """Bind non-secret, event-scoped optional-stage policy for this runtime."""

        if disabled_stages is None:
            self._disabled_optional_stages = ()
            self._optional_stage_policy_bound = False
            return
        self._disabled_optional_stages = _normalized_disabled_optional_stages(
            disabled_stages,
        )
        self._optional_stage_policy_bound = True

    @property
    def disabled_optional_stages(self) -> tuple[str, ...]:
        return self._disabled_optional_stages

    @property
    def optional_stage_policy_bound(self) -> bool:
        return self._optional_stage_policy_bound

    def _reset_rich_semantic_review_store(self) -> None:
        # Reload from the authoritative file so a rights-driven deletion cannot
        # leave removed review cases alive in the in-memory repository.
        self.review_repository = ReviewRepository(
            self.root / "protected" / "review-cases.json"
        )
        self.rich_semantic_reviews = _ReleaseBoundRichSemanticReviewStore(
            self.root / "protected" / "rich-semantic-review",
            release_root=self.root / "protected" / "release",
            review_repository=self.review_repository,
            transient_cache_root=(
                self.root / "protected" / "rich-semantic-review" / "cache"
            ),
            clock=self._clock,
            approval_verifier=self._rich_semantic_approval_is_current,
            current_application_sha256=self._current_application_sha256,
            decision_signing_secret=self._semantic_approval_secret,
            review_context_hashes=_review_case_source_hashes(self, {}),
            on_pending_proposal=lambda: self._invalidate_release(
                ("aggregate", "report", "publish", "analytics"),
                reason_code="rich_semantic_proposal_pending",
            ),
        )

    def _rich_semantic_approval_is_current(self, digest: str) -> bool:
        stage = self.pipeline.stage("classification")
        current = stage.authorization_hash
        return (
            stage.status is not StageStatus.LOCKED
            and isinstance(current, str)
            and hmac.compare_digest(current, digest)
        )

    @property
    def source_slots(self) -> tuple[str, ...]:
        return tuple(str(item["role"]) for item in self._data["event"]["sources"])

    @property
    def required_source_slots(self) -> tuple[str, ...]:
        return tuple(
            str(item["role"])
            for item in self._data["event"]["sources"]
            if item["required"] is True
        )

    @property
    def event_key(self) -> str:
        return str(self._data["event"]["key"])

    @property
    def event_definition_sha256(self) -> str:
        return str(self._data["event"]["definition_sha256"])

    @property
    def event_approval_sha256(self) -> str | None:
        approval = self._data.get("event_approval")
        if approval is None:
            return None
        digest = approval.get("sha256") if isinstance(approval, dict) else None
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise PermissionError("operator event approval binding is invalid")
        return digest

    @property
    def event_definition(self) -> EventDefinition:
        """Return the immutable configuration that governs this operator runtime."""

        return self._event_definition

    def _load(self, *, event_definition: EventDefinition) -> dict[str, object]:
        value = json.loads(self.path.read_text(encoding="utf-8"))
        version = value.get("state_version")
        if value.get("operator_code") != self.operator_code:
            raise ValueError("operator state version or owner does not match")
        if version == self.LEGACY_VERSION:
            raise PermissionError(
                "legacy operator state requires explicit offline migration",
            )
        elif version != self.VERSION:
            raise ValueError("operator state version or owner does not match")
        event = value.get("event")
        if not isinstance(event, dict):
            raise ValueError("operator state event binding is missing")
        required_event_keys = {
            "definition_sha256", "key", "metric_registry_version", "name",
            "privacy_policy_profile", "sources", "taxonomy_version",
        }
        if set(event) != required_event_keys:
            raise ValueError("operator state event binding is malformed")
        if (
            not isinstance(event.get("key"), str)
            or not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", event["key"])
            or not isinstance(event.get("name"), str)
            or not event["name"].strip()
            or not isinstance(event.get("definition_sha256"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", event["definition_sha256"])
            or not isinstance(event.get("sources"), list)
            or not event["sources"]
        ):
            raise ValueError("operator state event binding is malformed")
        roles: list[str] = []
        for source in event["sources"]:
            if not isinstance(source, dict) or set(source) != {
                "adapter_id", "media_type", "required", "role", "sheets",
            }:
                raise ValueError("operator state source binding is malformed")
            role = source.get("role")
            if (
                not isinstance(role, str)
                or not _CODE.fullmatch(role)
                or not isinstance(source.get("required"), bool)
                or not isinstance(source.get("adapter_id"), str)
                or not isinstance(source.get("media_type"), str)
                or not isinstance(source.get("sheets"), list)
                or any(not isinstance(sheet, str) for sheet in source["sheets"])
            ):
                raise ValueError("operator state source binding is malformed")
            _media_extension(str(source["media_type"]))
            roles.append(role)
        if len(roles) != len(set(roles)):
            raise ValueError("operator state source roles are duplicated")
        expected_binding = _event_binding(event_definition)
        if not hmac.compare_digest(
            canonical_hash(event), canonical_hash(expected_binding),
        ):
            raise PermissionError("operator state belongs to a different event")
        value.setdefault("privacy_operations", {
            "accountable_owner": self.operator_code, "deletions": "unreconciled",
            "exclusions": "unreconciled", "notice": "missing",
            "objections": "unreconciled",
            "retention_cleanup": "pending", "suppressions": "unreconciled",
        })
        value["privacy_operations"].setdefault("exclusions", "unreconciled")
        value.setdefault("audit_events", [])
        value.setdefault("event_summary", {
            "accepted": None, "applied": None, "present": None,
            "source_snapshot_sha256": None, "tracks": [],
        })
        value.setdefault("operational_facts", {})
        value.setdefault("private_semantic_decisions", {})
        value.setdefault("reviewed_values", {})
        value.setdefault("event_approval", None)
        return value

    def refresh(self, *, mutation_lock_held: bool = False) -> None:
        """Make external cleanup or operator mutations authoritative in memory."""

        if mutation_lock_held:
            self._recover_operator_transactions_locked(
                repair_non_gated_locks=False,
            )
            return
        recovered = self._recover_operator_transactions_nonblocking(
            repair_non_gated_locks=False,
        )
        if not recovered:
            self._reload_authoritative_state()

    def refresh_import_authority(self) -> None:
        """Reload importer authority without rewriting a live running stage."""

        self._reload_authoritative_state()
        has_upload_transaction = any(
            self._upload_transaction_path(slot).exists()
            for slot in self.source_slots
        )
        has_github_transaction = self._rich_github_import_transaction_path().exists()
        if has_upload_transaction or has_github_transaction:
            self.pipeline.recover_interrupted()
            self._recover_incomplete_upload_transactions()
            self._recover_incomplete_rich_github_import_locked()

    def _recover_operator_transactions_nonblocking(
        self, *, repair_non_gated_locks: bool,
    ) -> bool:
        """Recover only after nonblocking ownership of the shared mutation lock."""

        try:
            with protected_mutation_lock(self.root):
                self._recover_operator_transactions_locked(
                    repair_non_gated_locks=repair_non_gated_locks,
                )
        except BlockingIOError:
            return False
        return True

    def _recover_operator_transactions_locked(
        self, *, repair_non_gated_locks: bool,
    ) -> None:
        """Recover interrupted transactions while the caller owns the lock."""

        self._reload_authoritative_state()
        self.pipeline.recover_interrupted()
        if repair_non_gated_locks:
            for stage in ("aggregate", "report", "publish", "analytics"):
                if self.pipeline.stage(stage).status is StageStatus.LOCKED:
                    self.pipeline.unlock(stage)
        self._recover_incomplete_upload_transactions()
        self._recover_incomplete_rich_github_import_locked()

    def _reload_authoritative_state(self) -> None:
        """Reload validated operator, pipeline, and review state from disk."""

        self._data = self._load(event_definition=self._event_definition)
        self.pipeline.refresh()
        self.review_repository = ReviewRepository(self.review_repository.path)
        self._reset_rich_semantic_review_store()

    def _source_config(self, role: str | ReleaseSourceSlot) -> dict[str, object]:
        value = _source_role(role)
        matches = [
            item for item in self._data["event"]["sources"]
            if item["role"] == value
        ]
        if len(matches) != 1:
            raise ValueError(f"source role is not configured for this event: {value}")
        return matches[0]

    def source_snapshot_sha256(self) -> str:
        """Hash every configured source role, including explicit missing optionals."""

        slots = self._data["source_slots"]
        return canonical_hash({
            role: (
                str(slots[role]["sha256"])
                if isinstance(slots.get(role), dict)
                and isinstance(slots[role].get("sha256"), str)
                else None
            )
            for role in self.source_slots
        })

    def semantic_release_authoritative_context(self) -> dict[str, object]:
        """Re-derive the live event/source authority used by final semantic release."""

        from community_os.semantic_metrics import semantic_taxonomy_sha256

        approval_sha256 = self.event_approval_sha256
        source_sha256 = self.source_snapshot_sha256()
        summary = self._data.get("event_summary")
        taxonomy_version = self._data["event"].get("taxonomy_version")
        if (
            approval_sha256 is None
            or not isinstance(summary, dict)
            or summary.get("source_snapshot_sha256") != source_sha256
            or type(summary.get("applied")) is not int
            or summary["applied"] <= 0
            or not isinstance(taxonomy_version, str)
        ):
            raise PermissionError(
                "semantic release authority is not current for this event",
            )
        return {
            "event_approval_sha256": approval_sha256,
            "event_definition_sha256": self.event_definition_sha256,
            "event_key": self.event_key,
            "source_snapshot_sha256": source_sha256,
            "taxonomy_sha256": semantic_taxonomy_sha256(taxonomy_version),
            "taxonomy_version": taxonomy_version,
            "total_population": summary["applied"],
        }

    def _upload_transaction_path(self, slot: str | ReleaseSourceSlot) -> Path:
        role = _source_role(slot)
        return self.protected_uploads / f".{role}.upload-transaction.json"

    def _rich_github_import_transaction_path(self) -> Path:
        return self.root / "protected" / _RICH_GITHUB_IMPORT_TRANSACTION_NAME

    def _recover_incomplete_upload_transactions(self) -> None:
        """Fail closed after process death during a source-file/state transaction."""
        for slot in self.source_slots:
            marker = self._upload_transaction_path(slot)
            if not marker.is_file():
                continue
            suffix = _media_extension(str(self._source_config(slot)["media_type"]))
            for path in (
                self.protected_uploads / f"{slot}{suffix}",
                self.protected_uploads / f"{slot}{suffix}.pending",
            ):
                path.unlink(missing_ok=True)
            self._data["source_slots"].pop(slot, None)
            self._invalidate_release(
                tuple(self.pipeline.to_dict()["stages"]),
                reason_code="upload_transaction_interrupted",
            )
            self._audit(
                "upload_recovered", slot,
                "upload_transaction_interrupted",
            )
            self._persist()
            marker.unlink(missing_ok=True)

    def _recover_incomplete_rich_github_import_locked(self) -> None:
        """Fail closed for an interrupted import while owning the mutation lock."""

        marker = self._rich_github_import_transaction_path()
        try:
            marker.lstat()
        except FileNotFoundError:
            return
        self._invalidate_release(
            ("github", "classification", "aggregate", "report", "publish", "analytics"),
            reason_code="rich_github_import_interrupted",
        )
        self._audit(
            "rich_github_import_recovered", "github_import",
            "rich_github_import_interrupted",
        )
        self._persist()
        marker.unlink()
        directory_descriptor = os.open(
            marker.parent,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)

    @staticmethod
    def _open_import_protected_directory(
        root_descriptor: int, *, expected_root_identity: tuple[int, int],
    ) -> int:
        root_metadata = os.fstat(root_descriptor)
        if (
            not stat.S_ISDIR(root_metadata.st_mode)
            or stat.S_IMODE(root_metadata.st_mode) != 0o700
            or (root_metadata.st_dev, root_metadata.st_ino) != expected_root_identity
        ):
            raise PermissionError("operator destination root changed during protected import")
        flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            descriptor = os.open("protected", flags, dir_fd=root_descriptor)
        except OSError as error:
            raise PermissionError(
                "operator protected directory changed during protected import",
            ) from error
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            os.close(descriptor)
            raise PermissionError(
                "operator protected directory changed during protected import",
            )
        return descriptor

    def _write_rich_github_import_transaction_marker(
        self, root_descriptor: int, *, expected_root_identity: tuple[int, int],
    ) -> None:
        directory_descriptor = self._open_import_protected_directory(
            root_descriptor, expected_root_identity=expected_root_identity,
        )
        marker_descriptor: int | None = None
        marker_created = False
        try:
            flags = (
                os.O_WRONLY | os.O_CREAT | os.O_EXCL
                | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
            )
            marker_descriptor = os.open(
                _RICH_GITHUB_IMPORT_TRANSACTION_NAME, flags, 0o600,
                dir_fd=directory_descriptor,
            )
            marker_created = True
            os.fchmod(marker_descriptor, 0o600)
            payload = (
                json.dumps({
                    "stage": "github", "state": "installing",
                    "version": "rich-github-import-transaction-v1",
                }, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
                + "\n"
            ).encode("utf-8")
            view = memoryview(payload)
            written = 0
            while written < len(view):
                count = os.write(marker_descriptor, view[written:])
                if count <= 0:
                    raise OSError("GitHub import transaction marker write made no progress")
                written += count
            os.fsync(marker_descriptor)
            os.fsync(directory_descriptor)
        except BaseException:
            if marker_descriptor is not None:
                os.close(marker_descriptor)
                marker_descriptor = None
            if marker_created:
                try:
                    os.unlink(
                        _RICH_GITHUB_IMPORT_TRANSACTION_NAME,
                        dir_fd=directory_descriptor,
                    )
                    os.fsync(directory_descriptor)
                except FileNotFoundError:
                    pass
            raise
        finally:
            if marker_descriptor is not None:
                os.close(marker_descriptor)
            os.close(directory_descriptor)

    def _clear_rich_github_import_transaction_marker(
        self, root_descriptor: int, *, expected_root_identity: tuple[int, int],
    ) -> None:
        directory_descriptor = self._open_import_protected_directory(
            root_descriptor, expected_root_identity=expected_root_identity,
        )
        try:
            os.unlink(
                _RICH_GITHUB_IMPORT_TRANSACTION_NAME,
                dir_fd=directory_descriptor,
            )
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)

    def _audit(self, action: str, subject_code: str, reason_code: str) -> None:
        if not all(_CODE.fullmatch(value) for value in (action, subject_code, reason_code)):
            raise ValueError("operator audit fields must be machine-readable codes")
        self._data["audit_events"].append({
            "action": action,
            "actor_code": self._active_actor_code,
            "event_definition_sha256": self.event_definition_sha256,
            "event_key": self.event_key,
            "reason_code": reason_code,
            "subject_code": subject_code,
            "timestamp": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        })

    @contextmanager
    def acting_as(self, actor_code: str):
        """Attribute serialized request mutations to a pseudonymous colleague."""

        if not _CODE.fullmatch(actor_code):
            raise ValueError("request actor code must be machine-readable")
        previous = self._active_actor_code
        self._active_actor_code = actor_code
        try:
            yield
        finally:
            self._active_actor_code = previous

    def _persist(self) -> None:
        temporary = self.path.with_suffix(".tmp")
        temporary.write_text(
            json.dumps(self._data, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        temporary.chmod(0o600)
        temporary.replace(self.path)

    def _invalidate_release(self, stages: Sequence[str], *, reason_code: str) -> None:
        self.pipeline.invalidate(list(stages))
        self._data["release_state"] = "Blocked"
        protected = self.root / "protected"
        from community_os.controlled_release import withdraw_local_partner_share

        withdraw_local_partner_share(protected / "release")
        for name in (
            "semantic-release-approval.json",
            "semantic-release-approval.json.tmp",
            "semantic-release-qa.json",
            "semantic-release-qa.json.tmp",
            "analytics-publication.json",
        ):
            (protected / name).unlink(missing_ok=True)
        public_staging = self.root / "public-staging"
        for name in (
            "publication-manifest.json", "index.html", "talent-brief.real.html",
            "talent-brief.real.pdf",
            "partner-talent-brief.pdf",
            "talent-intelligence-v1.real.aggregate.json",
            "talent-report-v3.real.aggregate.json",
        ):
            (public_staging / name).unlink(missing_ok=True)
        deployment_staging = self.root / "deployment-staging"
        for name in (
            "vercel.json", "index.html", "partner-talent-brief.pdf",
            "publication-manifest.json",
        ):
            (deployment_staging / name).unlink(missing_ok=True)
        try:
            deployment_staging.rmdir()
        except (FileNotFoundError, OSError):
            pass
        self._audit("release_invalidated", "partner_release", reason_code)
        self._persist()

    def install_imported_github_stage(
        self,
        *,
        installer: Callable[[], None],
        source_guard: Callable[[], None],
        destination_root_descriptor: int,
        expected_root_identity: tuple[int, int],
        output_hash: str,
        record_count: int,
    ) -> None:
        """Install validated GitHub evidence without leaving stale release results ready."""

        if not callable(installer):
            raise TypeError("GitHub stage installer must be callable")
        if not callable(source_guard):
            raise TypeError("GitHub stage source guard must be callable")
        if (
            isinstance(destination_root_descriptor, bool)
            or not isinstance(destination_root_descriptor, int)
            or destination_root_descriptor < 0
        ):
            raise ValueError("GitHub import destination descriptor is invalid")
        if not isinstance(output_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", output_hash):
            raise ValueError("GitHub stage output hash is invalid")
        if (
            isinstance(record_count, bool)
            or not isinstance(record_count, int)
            or record_count < 0
        ):
            raise ValueError("GitHub stage record count is invalid")
        if (
            not isinstance(expected_root_identity, tuple)
            or len(expected_root_identity) != 2
            or any(
                isinstance(value, bool) or not isinstance(value, int) or value < 0
                for value in expected_root_identity
            )
        ):
            raise ValueError("GitHub import destination identity is invalid")
        if self.pipeline.stage("github").status is not StageStatus.COMPLETE:
            raise PermissionError("current GitHub stage must be complete before replacement")

        from community_os.release_operations import _assert_private_root_binding

        def assert_destination_root() -> None:
            _assert_private_root_binding(
                self.root,
                expected_identity=expected_root_identity,
                label="operator destination root",
            )

        downstream = (
            "classification", "aggregate", "report", "publish", "analytics",
        )
        assert_destination_root()
        source_guard()
        assert_destination_root()
        running = tuple(
            stage for stage in downstream
            if self.pipeline.stage(stage).status is StageStatus.RUNNING
        )
        if running:
            raise RuntimeError(
                "cannot import rich GitHub evidence while downstream stage is running: "
                + ",".join(running),
            )

        transaction_started = False
        try:
            self._write_rich_github_import_transaction_marker(
                destination_root_descriptor,
                expected_root_identity=expected_root_identity,
            )
            transaction_started = True
            assert_destination_root()
            self._invalidate_release(
                ("github", *downstream),
                reason_code="rich_github_stage_import",
            )
            assert_destination_root()
            self.pipeline.start("github")
            assert_destination_root()
            installer()
            assert_destination_root()
            self.pipeline.complete("github", {
                "output_hash": output_hash,
                "record_count": record_count,
            })
            assert_destination_root()
            source_guard()
            assert_destination_root()
            self._clear_rich_github_import_transaction_marker(
                destination_root_descriptor,
                expected_root_identity=expected_root_identity,
            )
            transaction_started = False
        except BaseException:
            if not transaction_started:
                raise
            assert_destination_root()
            self.pipeline.invalidate(list(downstream))
            github_status = self.pipeline.stage("github").status
            if github_status is StageStatus.COMPLETE:
                self.pipeline.invalidate(["github"])
                github_status = self.pipeline.stage("github").status
            if github_status is StageStatus.ALLOWED:
                self.pipeline.start("github")
                github_status = self.pipeline.stage("github").status
            if github_status is StageStatus.RUNNING:
                self.pipeline.fail("github", "rich_github_import_failed")
            raise

    def verify_current_source_files(self) -> None:
        """Verify protected source bytes still match every recorded slot hash."""

        slots = self._data.get("source_slots")
        if not isinstance(slots, dict):
            raise PermissionError("validated source state is invalid")
        for role, raw in sorted(slots.items()):
            if not isinstance(raw, dict):
                raise PermissionError("validated source state is invalid")
            filename = raw.get("path")
            expected = raw.get("sha256")
            if (
                not isinstance(filename, str)
                or Path(filename).name != filename
                or not isinstance(expected, str)
                or not re.fullmatch(r"[0-9a-f]{64}", expected)
            ):
                raise PermissionError("validated source state is invalid")
            path = self.protected_uploads / filename
            if path.is_symlink() or not path.is_file():
                raise PermissionError(f"source file is missing or unsafe: {role}")
            observed = hashlib.sha256(path.read_bytes()).hexdigest()
            if not hmac.compare_digest(observed, expected):
                raise PermissionError(f"source file hash drift: {role}")

    def record_source(
        self,
        slot: str | ReleaseSourceSlot,
        *,
        sha256: str,
        row_count: int,
        filename: str,
    ) -> Path:
        if not re.fullmatch(r"[0-9a-f]{64}", sha256) or row_count < 1:
            raise ValueError("validated source hash and row count are required")
        role = _source_role(slot)
        source = self._source_config(role)
        expected_suffix = _media_extension(str(source["media_type"]))
        if Path(filename).suffix.casefold() != expected_suffix:
            raise ValueError(f"{role} requires {expected_suffix}")
        destination = self.protected_uploads / f"{role}{expected_suffix}"
        previous = self._data["source_slots"].get(role)
        if not isinstance(previous, dict) or previous.get("sha256") != sha256:
            self._invalidate_release(
                tuple(self.pipeline.to_dict()["stages"]), reason_code="source_changed",
            )
        self._data["source_slots"][role] = {
            "path": destination.name, "row_count": row_count, "sha256": sha256,
            "state": "validated",
        }
        self._persist()
        return destination

    def store_upload(
        self,
        slot: str | ReleaseSourceSlot,
        body: bytes,
        *,
        filename: str,
    ) -> dict[str, object]:
        if not body or len(body) > 25 * 1024 * 1024:
            raise ValueError("upload must be between 1 byte and 25 MiB")
        role = _source_role(slot)
        source = self._source_config(role)
        suffix = Path(filename).suffix.casefold()
        expected = _media_extension(str(source["media_type"]))
        if suffix != expected:
            raise ValueError(f"{role} requires {expected}")
        pending = self.protected_uploads / f"{role}{suffix}.pending"
        transaction_marker = self._upload_transaction_path(role)
        pending.write_bytes(body)
        pending.chmod(0o600)
        try:
            row_count = _validate_configured_release_source(
                role=role,
                source=self._event_definition.source(role),
                path=pending,
            )
            digest = hashlib.sha256(body).hexdigest()
            destination = self.protected_uploads / f"{role}{suffix}"
            public_staging = self.root / "public-staging"
            deployment_staging = self.root / "deployment-staging"
            transaction_paths = {destination, self.path, self.pipeline_path}
            for staged_root in (public_staging, deployment_staging):
                if staged_root.is_dir():
                    transaction_paths.update(
                        path for path in staged_root.iterdir()
                        if path.is_file() or path.is_symlink()
                    )
            snapshots = {
                path: (
                    path.read_bytes(), path.stat().st_mode & 0o777
                ) if path.is_file() else None
                for path in transaction_paths
            }
            data_snapshot = copy.deepcopy(self._data)
            with transaction_marker.open("w", encoding="utf-8") as stream:
                transaction_marker.chmod(0o600)
                stream.write(json.dumps({
                    "slot": role, "state": "installing",
                    "version": "upload-transaction-v1",
                }, sort_keys=True, separators=(",", ":")) + "\n")
                stream.flush()
                os.fsync(stream.fileno())
            pending.replace(destination)
            destination.chmod(0o600)
            try:
                self.record_source(
                    role, sha256=digest, row_count=row_count, filename=filename,
                )
            except Exception:
                try:
                    for path, snapshot in snapshots.items():
                        if snapshot is None:
                            path.unlink(missing_ok=True)
                            continue
                        contents, mode = snapshot
                        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                        path.write_bytes(contents)
                        path.chmod(mode)
                    for state_path in (self.path, self.pipeline_path):
                        state_path.with_name(state_path.name + ".tmp").unlink(missing_ok=True)
                    self._data = data_snapshot
                    self.pipeline = PipelineState.load(self.pipeline_path)
                except Exception as rollback_error:
                    raise RuntimeError("upload transaction rollback failed") from rollback_error
                transaction_marker.unlink(missing_ok=True)
                raise
            transaction_marker.unlink(missing_ok=True)
            return {"row_count": row_count, "sha256": digest, "state": "validated"}
        except Exception:
            pending.unlink(missing_ok=True)
            raise

    def apply_correction(self, field: str, value: int, *, reason_code: str) -> None:
        if not _CODE.fullmatch(field) or not _CODE.fullmatch(reason_code) or isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError("correction must use code fields and a nonnegative integer")
        previous = self._data["corrections"].get(field)
        current = {"reason_code": reason_code, "value": value}
        if previous != current:
            self._invalidate_release(
                ("aggregate", "report", "publish", "analytics"),
                reason_code="correction_changed",
            )
        self._data["corrections"][field] = current
        self._audit("correction_applied", field, reason_code)
        self._persist()

    def record_reviewed_value(
        self,
        field: str,
        *,
        source_value: int,
        reviewed_value: int,
        reason_code: str,
    ) -> None:
        """Distinguish a confirmed source value from an actual correction."""

        if (
            not _CODE.fullmatch(field)
            or not _CODE.fullmatch(reason_code)
            or any(
                isinstance(value, bool) or not isinstance(value, int) or value < 0
                for value in (source_value, reviewed_value)
            )
        ):
            raise ValueError("reviewed value must use code fields and nonnegative integers")
        decision = "approved" if source_value == reviewed_value else "corrected"
        record = {
            "decision": decision,
            "reason_code": reason_code,
            "reviewed_value": reviewed_value,
            "source_snapshot_sha256": self.source_snapshot_sha256(),
            "source_value": source_value,
        }
        if self._data["reviewed_values"].get(field) != record:
            self._invalidate_release(
                ("aggregate", "report", "publish", "analytics"),
                reason_code="reviewed_value_changed",
            )
        self._data["reviewed_values"][field] = record
        if decision == "corrected":
            self._data["corrections"][field] = {
                "reason_code": reason_code,
                "value": reviewed_value,
            }
        else:
            self._data["corrections"].pop(field, None)
        self._audit(f"source_value_{decision}", field, reason_code)
        self._persist()

    def record_event_approval(self, approval: object) -> None:
        """Bind provider gates and every derivative to one exact event approval."""

        event_key = getattr(approval, "event_key", None)
        definition_sha256 = getattr(approval, "event_definition_sha256", None)
        approval_sha256 = getattr(approval, "sha256", None)
        actor_code = getattr(approval, "actor_code", None)
        approved_at = getattr(approval, "approved_at", None)
        if (
            event_key != self.event_key
            or definition_sha256 != self.event_definition_sha256
            or not isinstance(approval_sha256, str)
            or not re.fullmatch(r"[0-9a-f]{64}", approval_sha256)
            or not isinstance(actor_code, str)
            or not _CODE.fullmatch(actor_code)
            or not isinstance(approved_at, datetime)
            or approved_at.tzinfo is None
            or approved_at.utcoffset() is None
        ):
            raise PermissionError("event approval does not match operator state")
        record = {
            "actor_code": actor_code,
            "approved_at": approved_at.isoformat(),
            "sha256": approval_sha256,
        }
        if self._data.get("event_approval") == record:
            return
        for stage in ("github", "public_pages", "coresignal", "classification"):
            self.pipeline.lock(stage)
        protected = self.root / "protected"
        for derivative_root in (protected / "rich-semantic-review",):
            if derivative_root.exists():
                for target in derivative_root.rglob("*"):
                    if target.is_file() or target.is_symlink():
                        target.unlink()
        for name in (
            "review-bindings.json", "review-bindings.json.tmp",
            "review-cases.json", "reviewed-override.json",
            "rich-semantic-internal.aggregate.json",
        ):
            target = protected / name
            if target.is_file() or target.is_symlink():
                target.unlink()
        self._data["event_approval"] = record
        for review_key in (
            "classification_reviews", "identity_reviews", "team_reviews",
        ):
            self._data[review_key] = {}
        self._reset_rich_semantic_review_store()
        self._invalidate_release(
            tuple(self.pipeline.to_dict()["stages"]),
            reason_code="event_approval_changed",
        )
        self._audit("event_approval_recorded", "event_approval", "approval_bound")
        self._persist()

    def record_operational_fact(
        self,
        key: str,
        *,
        value: int,
        unit: str,
        funnel_stage: bool,
        reason_code: str,
    ) -> None:
        """Record a reviewed aggregate fact that is explicitly outside the funnel."""

        if (
            not _CODE.fullmatch(key)
            or not _CODE.fullmatch(unit)
            or not _CODE.fullmatch(reason_code)
            or isinstance(value, bool)
            or not isinstance(value, int)
            or value < 0
            or funnel_stage is not False
        ):
            raise ValueError("operational fact must be nonnegative and outside the funnel")
        record = {
            "funnel_stage": False,
            "reason_code": reason_code,
            "source_snapshot_sha256": self.source_snapshot_sha256(),
            "unit": unit,
            "value": value,
        }
        if self._data["operational_facts"].get(key) != record:
            self._invalidate_release(
                ("aggregate", "report", "publish", "analytics"),
                reason_code="operational_fact_changed",
            )
        self._data["operational_facts"][key] = record
        self._audit("operational_fact_recorded", key, reason_code)
        self._persist()

    def record_event_summary(
        self,
        *,
        applied: int,
        accepted: int,
        present: int,
        tracks: Sequence[str],
        reason_code: str,
    ) -> None:
        """Record reviewed aggregate event context without embedding person data."""

        counts = (applied, accepted, present)
        if (
            any(isinstance(value, bool) or not isinstance(value, int) or value < 0 for value in counts)
            or not applied >= accepted >= present
            or not _CODE.fullmatch(reason_code)
        ):
            raise ValueError("event summary counts or reason are invalid")
        values: list[str] = []
        for track in tracks:
            if (
                not isinstance(track, str)
                or not track.strip()
                or track != track.strip()
                or len(track) > 80
                or any(ord(character) < 32 for character in track)
            ):
                raise ValueError("event summary track is invalid")
            values.append(track)
        if len(values) != len(set(values)):
            raise ValueError("event summary tracks contain duplicates")
        current = {
            "accepted": accepted,
            "applied": applied,
            "present": present,
            "source_snapshot_sha256": self.source_snapshot_sha256(),
            "tracks": values,
        }
        if self._data["event_summary"] != current:
            self._invalidate_release(
                ("aggregate", "report", "publish", "analytics"),
                reason_code="event_summary_changed",
            )
        self._data["event_summary"] = current
        self._audit("event_summary_recorded", "event_summary", reason_code)
        self._persist()

    def replace_review_cases(self, cases: Sequence[ReviewCase]) -> None:
        self.review_repository.replace(cases)

    def decide_identity(
        self, case_code: str, case_hash: str, decision: str,
        *, selected_code: str | None = None,
    ) -> None:
        self.review_repository.decide(
            ReviewDecision(
                case_code=case_code, case_hash=case_hash, action=decision,
                selected_code=selected_code,
            ),
            actor_code=self._active_actor_code, decided_at=datetime.now(UTC),
        )
        self._invalidate_release(
            ("github", "public_pages", "coresignal", "classification", "aggregate", "report", "publish", "analytics"),
            reason_code="identity_review_changed",
        )
        self._data["identity_reviews"][case_code] = decision
        self._audit("identity_reviewed", case_code, decision)
        self._persist()

    def decide_team(self, case_code: str, case_hash: str, project_code: str) -> None:
        self.review_repository.decide(
            ReviewDecision(
                case_code=case_code, case_hash=case_hash, action="link",
                selected_code=project_code,
            ),
            actor_code=self._active_actor_code, decided_at=datetime.now(UTC),
        )
        self._invalidate_release(
            ("github", "public_pages", "coresignal", "classification", "aggregate", "report", "publish", "analytics"),
            reason_code="team_review_changed",
        )
        self._data["team_reviews"][case_code] = project_code
        self._audit("team_reviewed", case_code, "project_linked")
        self._persist()

    def review_classification(
        self, case_code: str, case_hash: str, decision: str,
        *, corrected_output: Mapping[str, object] | None = None,
    ) -> None:
        matches = [
            item for item in self.review_repository.list(kind="classification")
            if item.case_code == case_code
        ]
        if len(matches) != 1 or not hmac.compare_digest(matches[0].case_hash, case_hash):
            raise PermissionError("classification review case is stale")
        decided_at = datetime.now(UTC)
        if matches[0].version == "rich_semantic_review_v1":
            self.rich_semantic_reviews.decide(
                case_code, action=decision, actor_code=self._active_actor_code,
                decided_at=decided_at,
                corrected_assessment=(
                    dict(corrected_output) if corrected_output is not None else None
                ),
            )
        else:
            self.review_repository.decide(
                ReviewDecision(
                    case_code=case_code, case_hash=case_hash, action=decision,
                    corrected_output=corrected_output,
                ),
                actor_code=self._active_actor_code, decided_at=decided_at,
            )
        self._invalidate_release(
            ("aggregate", "report", "publish", "analytics"),
            reason_code="classification_review_changed",
        )
        self._data["classification_reviews"][case_code] = decision
        self._audit("classification_reviewed", case_code, decision)
        self._persist()

    def record_privacy_status(self, field: str, status: str) -> None:
        if field not in {
            "notice", "objections", "exclusions", "suppressions", "deletions",
            "retention_cleanup",
        }:
            raise ValueError("privacy operations field is invalid")
        if status not in {"missing", "pending", "recorded", "reconciled", "complete", "unreconciled"}:
            raise ValueError("privacy operations status is invalid")
        if self._data["privacy_operations"].get(field) != status:
            self._invalidate_release(
                ("github", "public_pages", "coresignal", "classification", "aggregate", "report", "publish", "analytics"),
                reason_code="privacy_state_changed",
            )
        self._data["privacy_operations"][field] = status
        self._audit("privacy_status_recorded", field, status)
        self._persist()

    def _record_authorization_privacy_state(self, stage: str) -> None:
        self._data["privacy_operations"].update({
            "notice": "recorded", "objections": "reconciled",
            "exclusions": "reconciled", "suppressions": "reconciled",
            "deletions": "reconciled",
        })
        self._audit("authorization_recorded", stage, "gate_recorded")
        self._persist()

    def record_public_source_authorization(
        self, stage: str, authorization: object, *, now: datetime,
    ) -> None:
        if stage not in {"github", "public_pages"}:
            raise ValueError("public-source authorization stage is invalid")
        self.pipeline.unlock(stage, authorization, now=now)
        self._invalidate_release(
            ("classification", "aggregate", "report", "publish", "analytics"),
            reason_code="authorization_changed",
        )
        self._record_authorization_privacy_state(stage)

    def record_coresignal_authorization(
        self, authorization: object, *, now: datetime,
    ) -> None:
        self.pipeline.unlock("coresignal", authorization, now=now)
        self._invalidate_release(
            ("classification", "aggregate", "report", "publish", "analytics"),
            reason_code="authorization_changed",
        )
        self._record_authorization_privacy_state("coresignal")

    def record_semantic_processor_authorization(
        self, authorization: object, *, now: datetime,
    ) -> None:
        self.pipeline.unlock("classification", authorization, now=now)
        self._invalidate_release(
            ("aggregate", "report", "publish", "analytics"),
            reason_code="authorization_changed",
        )
        self._record_authorization_privacy_state("classification")

    def revoke_stage_authorization(self, stage: str, *, reason_code: str) -> None:
        if stage not in {"github", "public_pages", "coresignal", "classification"}:
            raise ValueError("authorization revocation stage is invalid")
        if not _CODE.fullmatch(reason_code):
            raise ValueError("authorization revocation reason is invalid")
        was_locked = self.pipeline.stage(stage).status is StageStatus.LOCKED
        self.pipeline.lock(stage)
        removed = 0
        payload = self.root / "protected" / "stages" / f"{stage}.json"
        for item in (payload, payload.with_name(payload.name + ".tmp")):
            if item.exists():
                item.unlink()
                removed += 1
        cache_root = self.root / "protected" / "cache" / stage
        if cache_root.is_dir():
            for pattern in ("*.json", "*.tmp"):
                for item in cache_root.glob(pattern):
                    item.unlink(missing_ok=True)
                    removed += 1
        vault = ProtectedEvidenceVault(
            self.root / "protected" / "raw-evidence",
            clock=lambda: datetime.now(UTC),
        )
        if stage == "classification":
            removed += len(vault.delete_all(reason="authorization_revoked"))
        else:
            removed += len(vault.delete_source(stage, reason="authorization_revoked"))
        if was_locked and removed == 0:
            return
        self._invalidate_release(
            ("classification", "aggregate", "report", "publish", "analytics"),
            reason_code=reason_code,
        )
        self._audit("authorization_revoked", stage, reason_code)
        self._persist()

    def block_for_invalid_approval(self, *, reason_code: str) -> None:
        if not _CODE.fullmatch(reason_code):
            raise ValueError("approval block reason is invalid")
        for stage in ("github", "public_pages", "coresignal", "classification"):
            self.revoke_stage_authorization(stage, reason_code=reason_code)
        self._invalidate_release(
            tuple(self.pipeline.to_dict()["stages"]), reason_code=reason_code,
        )

    def invalidate_for_provider_result(self, stage: str) -> list[dict[str, object]]:
        if stage != "coresignal":
            raise ValueError("provider-result invalidation stage is invalid")
        self._invalidate_release(
            ("classification", "aggregate", "report", "publish", "analytics"),
            reason_code="provider_result_changed",
        )
        return [{"stage": stage, "state": "invalidated"}]

    def invalidate_for_subject_exclusions(
        self, exclusion_set_sha256: str, *, excluded_count: int,
    ) -> None:
        """Withdraw every derived surface without persisting subject identifiers."""
        if (
            not re.fullmatch(r"[0-9a-f]{64}", exclusion_set_sha256)
            or isinstance(excluded_count, bool)
            or not isinstance(excluded_count, int)
            or excluded_count < 0
        ):
            raise ValueError("subject exclusion evidence is invalid")
        protected = self.root / "protected"
        ProtectedEvidenceVault(
            protected / "raw-evidence", clock=lambda: datetime.now(UTC),
        ).delete_all(reason="subject_exclusion")
        for derivative_root in (
            protected / "stages", protected / "cache", protected / "release",
            protected / "rich-semantic-review",
        ):
            if not derivative_root.exists():
                continue
            for target in derivative_root.rglob("*"):
                if target.is_file() or target.is_symlink():
                    target.unlink()
        for name in (
            "enrichment-manifest.json", "review-bindings.json",
            "review-bindings.json.tmp",
            "review-cases.json", "reviewed-override.json",
            "rich-semantic-internal.aggregate.json",
        ):
            target = protected / name
            if target.is_file() or target.is_symlink():
                target.unlink()
        # Exclusions arrive as a set hash, not person identifiers. With no safe
        # subject-level binding available here, discard every semantic review
        # result and require a filtered rerun rather than risk retaining one
        # excluded participant in an aggregate.
        self._reset_rich_semantic_review_store()
        self._invalidate_release(
            tuple(self.pipeline.to_dict()["stages"]),
            reason_code="subject_exclusions_changed",
        )
        self._audit(
            "subject_exclusions_changed",
            "exclusions_" + exclusion_set_sha256[:16],
            f"rights_request_{excluded_count}",
        )
        self._persist()

    def invalidate_for_retention_expiry(self, stages: Sequence[str]) -> None:
        values = tuple(dict.fromkeys(stages))
        if not values or any(
            stage not in {"github", "public_pages", "coresignal", "classification"}
            for stage in values
        ):
            raise ValueError("retention invalidation stages are invalid")
        derived = ("aggregate", "report", "publish", "analytics")
        if "classification" not in values:
            derived = ("classification", *derived)
        self._invalidate_release(
            (*values, *derived),
            reason_code="enrichment_retention_expired",
        )

    def invalidate_for_source_retention_expiry(self, sources: Sequence[str]) -> None:
        values = tuple(dict.fromkeys(sources))
        allowed = set(self.source_slots)
        if not values or any(source not in allowed for source in values):
            raise ValueError("source retention invalidation values are invalid")
        for source in values:
            self._data["source_slots"].pop(source, None)
        self._invalidate_release(
            tuple(self.pipeline.to_dict()["stages"]),
            reason_code="source_retention_expired",
        )
        for source in values:
            self._audit(
                "source_retention_expired", "source_" + source,
                "scheduled_retention_expiry",
            )
        self._persist()

    def update_release_state(self, evidence: object, *, now: object) -> str:
        from community_os.privacy_operations import evaluate_release
        value = evaluate_release(evidence, now=now).value
        self._data["release_state"] = value
        self._audit("release_state_evaluated", "partner_release", value.casefold().replace(" ", "_"))
        self._persist()
        return value

    def snapshot(self) -> dict[str, object]:
        stages = {
            key: {"attempts": value["attempts"], "status": value["status"]}
            for key, value in self.pipeline.to_dict()["stages"].items()
        }
        privacy_inventory: list[dict[str, object]] = []
        privacy_exclusions: dict[str, object] = {
            "excluded_count": 0, "exclusion_set_sha256": None,
            "state": "pending",
        }
        privacy_path = self.root / "protected" / "privacy-operations.json"
        if privacy_path.is_file():
            try:
                privacy_payload = json.loads(privacy_path.read_text(encoding="utf-8"))
                value = privacy_payload.get("inventory", [])
                if isinstance(value, list) and all(isinstance(item, dict) for item in value):
                    privacy_inventory = value
                exclusions = privacy_payload.get("subject_exclusions")
                if isinstance(exclusions, dict):
                    count = exclusions.get("excluded_count")
                    digest = exclusions.get("exclusion_set_sha256")
                    if (
                        isinstance(count, int) and not isinstance(count, bool)
                        and count >= 0 and isinstance(digest, str)
                        and re.fullmatch(r"[0-9a-f]{64}", digest)
                    ):
                        privacy_exclusions = {
                            "excluded_count": count,
                            "exclusion_set_sha256": digest,
                            "state": (
                                "clear" if count == 0 else (
                                    "propagated"
                                    if privacy_payload.get("schema_version")
                                    == "privacy-operations-v1"
                                    else "registered"
                                )
                            ),
                        }
            except (OSError, json.JSONDecodeError):
                privacy_inventory = []
        payload = json.loads(json.dumps(self._data))
        event = payload["event"]
        event["source_total"] = len(event["sources"])
        summary = payload["event_summary"]
        summary_is_current = hmac.compare_digest(
            str(summary.get("source_snapshot_sha256") or ""),
            self.source_snapshot_sha256(),
        )
        event_counts = {
            key: summary.get(key) if summary_is_current else None
            for key in ("applied", "accepted", "present")
        }
        event_tracks = list(summary.get("tracks", [])) if summary_is_current else []
        return {
            **payload,
            "event_counts": event_counts,
            "event_tracks": event_tracks,
            "privacy_exclusions": privacy_exclusions,
            "privacy_inventory": privacy_inventory,
            "review_cases": [item.to_dict() for item in self.review_repository.list()],
            "rich_semantic_status": self._rich_semantic_status(),
            "stages": stages,
        }

    def _rich_semantic_status(self) -> dict[str, object]:
        """Project private rich-review state into bounded aggregate-only status."""

        cases = tuple(
            item for item in self.review_repository.list(kind="classification")
            if item.version == "rich_semantic_review_v1"
        )
        pending = sum(item.status == "open" for item in cases)
        finalized_case_codes = self.rich_semantic_reviews.finalized_case_codes()
        reviewed = sum(
            item.status == "resolved" and item.case_code in finalized_case_codes
            for item in cases
        )
        projection_incomplete = sum(
            item.status == "resolved" and item.case_code not in finalized_case_codes
            for item in cases
        )
        aggregate_ready = False
        aggregate_summary: dict[str, object] | None = None
        aggregate_path = self.root / "protected" / "rich-semantic-internal.aggregate.json"
        if reviewed and not aggregate_path.is_symlink() and aggregate_path.is_file():
            try:
                stored_aggregate = json.loads(aggregate_path.read_text(encoding="utf-8"))
                if not isinstance(stored_aggregate, dict):
                    raise ValueError("rich semantic aggregate is invalid")
                from community_os.semantic_release_approval import (
                    validate_protected_semantic_aggregate,
                )
                from community_os.semantic_metrics import semantic_taxonomy_sha256

                validated = validate_protected_semantic_aggregate(stored_aggregate)
                bindings = validated["bindings"]
                population = validated["population"]
                assert isinstance(bindings, dict)
                assert isinstance(population, dict)
                expected_event_approval = self.rich_semantic_reviews.review_context_hashes[
                    "event_approval"
                ]
                aggregate_ready = (
                    aggregate_path.stat().st_mode & 0o777 == 0o600
                    and bindings["event_key"] == self.event_key
                    and hmac.compare_digest(
                        str(bindings["event_definition_sha256"]),
                        self.event_definition_sha256,
                    )
                    and hmac.compare_digest(
                        str(bindings["event_approval_sha256"]),
                        expected_event_approval,
                    )
                    and hmac.compare_digest(
                        str(bindings["source_snapshot_sha256"]),
                        self.source_snapshot_sha256(),
                    )
                    and bindings["taxonomy_version"]
                    == self.event_definition.semantic.taxonomy_version
                    and hmac.compare_digest(
                        str(bindings["taxonomy_sha256"]),
                        semantic_taxonomy_sha256(
                            self.event_definition.semantic.taxonomy_version,
                        ),
                    )
                )
                if aggregate_ready:
                    aggregate_summary = {
                        "metrics": validated["metrics"],
                        "minimum_group_size": validated["minimum_group_size"],
                        "population": population,
                    }
            except (
                AssertionError, OSError, TypeError, ValueError, PermissionError,
                json.JSONDecodeError,
            ):
                aggregate_ready = False
        coverage = self.rich_semantic_reviews.source_coverage_counts()
        if pending:
            noun = "proposal" if pending == 1 else "proposals"
            next_action = f"Review {pending} pending rich semantic {noun}."
        elif projection_incomplete:
            next_action = (
                f"Recover {projection_incomplete} interrupted rich semantic projection"
                + ("." if projection_incomplete == 1 else "s.")
            )
        elif aggregate_ready:
            next_action = (
                "Internal-only rich semantic aggregate is ready; "
                "human review remains required before release."
            )
        elif reviewed:
            next_action = "Build the internal-only rich semantic aggregate."
        else:
            next_action = "Run mandatory GitHub + application semantic enrichment."
        return {
            "aggregate_summary": aggregate_summary,
            "next_action": next_action,
            "pending": pending,
            "projection_incomplete": projection_incomplete,
            "reviewed": reviewed,
            "source_coverage": coverage,
        }


def run_approved_release(
    pipeline: ReleasePipeline,
    operations: Mapping[str, Callable[[], Sequence[Mapping[str, object]]]],
    *, include_coresignal: bool,
    semantic_review_store: RichSemanticReviewStore | None = None,
) -> dict[str, dict[str, object]]:
    """Run the controlled action and persist its current state even on failure."""

    try:
        return _run_approved_release(
            pipeline, operations, include_coresignal=include_coresignal,
            semantic_review_store=semantic_review_store,
        )
    finally:
        pipeline.write_manifest()


def _adopt_approved_semantic_aggregate(
    pipeline: ReleasePipeline,
    *,
    root: str | Path,
    semantic_approval_sha256: str,
) -> dict[str, object]:
    """Record a locally verified reviewed aggregate without rerunning a provider."""

    if not isinstance(semantic_approval_sha256, str) or not re.fullmatch(
        r"[0-9a-f]{64}", semantic_approval_sha256,
    ):
        raise ValueError("semantic approval hash is invalid")
    protected = Path(root) / "protected"
    paths = tuple(
        protected / name
        for name in (
            "rich-semantic-internal.aggregate.json",
            "rich-semantic-internal.cohorts.aggregate.json",
        )
    )
    if any(
        path.is_symlink()
        or not path.is_file()
        or (path.stat().st_mode & 0o777) != 0o600
        for path in paths
    ):
        raise PermissionError(
            "approved semantic aggregate files are missing or unsafe",
        )
    record = {
        "adoption_version": "approved-reviewed-semantic-aggregate-v1",
        "aggregate_sha256": hashlib.sha256(paths[0].read_bytes()).hexdigest(),
        "cohort_aggregate_sha256": hashlib.sha256(paths[1].read_bytes()).hexdigest(),
        "semantic_approval_sha256": semantic_approval_sha256,
    }
    result = {
        "output_hash": canonical_hash([record]),
        "record_count": 1,
    }
    stage = pipeline.state.stage("aggregate")
    if stage.status is StageStatus.COMPLETE:
        if stage.result != result:
            pipeline.state.invalidate(("aggregate", "report", "publish", "analytics"))
            stage = pipeline.state.stage("aggregate")
        else:
            return dict(result)
    if stage.status is StageStatus.FAILED:
        pipeline.state.resume("aggregate")
    elif stage.status is StageStatus.ALLOWED:
        pipeline.state.start("aggregate")
    else:
        raise PermissionError(
            "reviewed semantic aggregate cannot be adopted from its current stage",
        )
    pipeline.state.complete("aggregate", result)
    return result


def _fresh_report_records(
    operation: Callable[[], Sequence[Mapping[str, object]]],
    *,
    required_artifacts: Sequence[str | Path],
) -> tuple[dict[str, object], ...]:
    """Run one local report operation and prove every required file was replaced."""

    artifacts = tuple(Path(item) for item in required_artifacts)
    if not artifacts or len(set(artifacts)) != len(artifacts):
        raise ValueError("required report artifacts must be unique and non-empty")

    def artifact_signature(path: Path) -> tuple[int, int, int] | None:
        if path.is_symlink() or not path.is_file():
            return None
        stat = path.stat()
        return stat.st_ino, stat.st_mtime_ns, stat.st_ctime_ns

    before = {path: artifact_signature(path) for path in artifacts}
    records = tuple(dict(item) for item in operation())
    stale = [
        path.name for path in artifacts
        if artifact_signature(path) is None
        or artifact_signature(path) == before[path]
    ]
    if stale:
        raise PermissionError(
            "report operation did not freshly regenerate: " + ",".join(stale)
        )
    return records


def _regenerate_semantic_report_candidate(
    operation: Callable[[], Sequence[Mapping[str, object]]],
    *,
    required_artifacts: Sequence[str | Path],
) -> dict[str, object]:
    """Refresh the approval-neutral local candidate before binding its hashes."""

    records = _fresh_report_records(
        operation,
        required_artifacts=required_artifacts,
    )
    return {
        "output_hash": canonical_hash(records),
        "record_count": len(records),
    }


def run_local_report_render(
    pipeline: ReleasePipeline,
    operation: Callable[[], Sequence[Mapping[str, object]]],
    *,
    required_artifacts: Sequence[str | Path],
) -> dict[str, object]:
    """Regenerate local HTML/PDF from current aggregates without publishing."""
    if pipeline.state.stage("aggregate").status is not StageStatus.COMPLETE:
        raise PermissionError("current aggregates are required before report generation")
    report = pipeline.state.stage("report")
    if report.status is StageStatus.RUNNING:
        raise PermissionError("report generation is already running")

    def verified_operation() -> Sequence[Mapping[str, object]]:
        return _fresh_report_records(
            operation,
            required_artifacts=required_artifacts,
        )

    if report.status is StageStatus.COMPLETE:
        pipeline.state.invalidate(("report", "publish", "analytics"))
    return pipeline.run("report", verified_operation)


def _run_approved_release(
    pipeline: ReleasePipeline,
    operations: Mapping[str, Callable[[], Sequence[Mapping[str, object]]]],
    *, include_coresignal: bool,
    semantic_review_store: RichSemanticReviewStore | None,
) -> dict[str, dict[str, object]]:
    """Run the one controlled action after every external approval has been recorded."""
    if include_coresignal:
        raise PermissionError(
            "Coresignal evaluation cannot enter the release pipeline"
        )
    if pipeline.config.get("optional_stage_policy_bound") is not True:
        raise PermissionError("optional-stage approval policy was not bound")
    disabled_optional_stages = _normalized_disabled_optional_stages(
        pipeline.config.get("disabled_optional_stages", []),
    )
    for stage in disabled_optional_stages:
        if pipeline.state.stage(stage).status is not StageStatus.LOCKED:
            raise PermissionError(
                f"disabled optional stage {stage} must remain locked",
            )
    order = ["reconcile", "github"]
    if "public_pages" not in disabled_optional_stages:
        order.append("public_pages")
    # Analytics is intentionally absent. It requires a separate, explicit action
    # after exact publication staging and before any deployment.
    order.extend(("classification", "aggregate", "report", "publish"))
    required = ["privacy_cleanup", *order]
    missing = [stage for stage in required if stage not in operations]
    if missing:
        raise PermissionError("controlled release operations are not configured: " + ",".join(missing))
    if (
        "classification_canary" in operations
        and pipeline.state.stage("classification").status is not StageStatus.COMPLETE
    ):
        if semantic_review_store is None:
            raise PermissionError(
                "semantic canary review state is unavailable; full enrichment is blocked"
            )
        canary_cases = tuple(
            case
            for case in semantic_review_store.review_repository.list(
                kind="classification",
            )
            if case.version == "rich_semantic_review_v1"
        )
        expected_case_codes = frozenset(case.case_code for case in canary_cases)
        if (
            len(canary_cases) != 5
            or any(case.status != "resolved" for case in canary_cases)
            or semantic_review_store.finalized_case_codes() != expected_case_codes
        ):
            raise PermissionError(
                "semantic canary review remains open; full enrichment is blocked"
            )
    cleanup_records = [dict(item) for item in operations["privacy_cleanup"]()]
    results: dict[str, dict[str, object]] = {
        "privacy_cleanup": {
            "output_hash": canonical_hash(cleanup_records),
            "record_count": len(cleanup_records),
        },
    }
    for stage in order:
        current = pipeline.state.stage(stage)
        if current.status is StageStatus.LOCKED:
            raise PermissionError(
                f"{stage} remains locked because a required approval or prerequisite is missing"
            )
        results[stage] = pipeline.run(stage, operations[stage])
    return results


def _mapping_expected_headers(source: EventSource) -> tuple[str, ...]:
    """Load the exact header contract already hash-bound by the event definition."""

    from community_os.source_contract import load_registered_source_contract

    return load_registered_source_contract(source).mapping.expected_headers


def _validate_registered_headers(
    *, role: str, actual: Sequence[str], expected: Sequence[str],
) -> None:
    actual_values = list(actual)
    expected_values = set(expected)
    actual_set = set(actual_values)
    unexpected = sorted(actual_set - expected_values)
    missing = sorted(expected_values - actual_set)
    duplicates = sorted({
        header for header in actual_values if actual_values.count(header) > 1
    })
    if not (unexpected or missing or duplicates):
        return
    details: list[str] = []
    if unexpected:
        details.append("unexpected headers: " + ", ".join(unexpected))
    if missing:
        details.append("missing headers: " + ", ".join(missing))
    if duplicates:
        details.append("duplicate headers: " + ", ".join(duplicates))
    raise ValueError(f"{role} schema drift: {'; '.join(details)}")


def _validate_configured_release_source(
    *, role: str, source: EventSource, path: Path,
) -> int:
    """Validate one protected upload according to its event-bound media contract."""

    if source.role != role:
        raise ValueError("event source role does not match the upload role")
    media_type = source.media_type
    expected_headers = _mapping_expected_headers(source)
    if media_type in {
        "text/csv",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    }:
        from community_os.operator_pipeline import read_registered_source_data

        return len(read_registered_source_data(path, source).records)
    if media_type == "application/json":
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError(f"{role} upload is not valid JSON") from error
        if isinstance(value, list):
            count = len(value)
        elif isinstance(value, dict) and isinstance(value.get("records"), list):
            count = len(value["records"])
        else:
            raise ValueError(f"{role} JSON must be a list or a records object")
        records = value if isinstance(value, list) else value["records"]
        if count < 1 or any(not isinstance(item, dict) for item in records):
            raise ValueError(f"{role} JSON contains no valid record objects")
        for number, record in enumerate(records, start=1):
            _validate_registered_headers(
                role=f"{role} JSON record {number}",
                actual=tuple(record),
                expected=expected_headers,
            )
        return count
    raise ValueError(f"{role} media type is unsupported")


def apply_partner_presentation_edits(
    presentation: object,
    edits: object,
    *,
    semantic_summary: object,
) -> object:
    """Apply only bounded copy fields while retaining all server-owned bindings."""

    from dataclasses import replace

    from community_os.partner_report_presentation import (
        PartnerReportPresentation,
        validate_partner_report_presentation,
    )
    from community_os.partner_semantic_projection import PartnerSemanticSummary

    expected = {"cover_title", "cover_dek"}
    if (
        not isinstance(presentation, PartnerReportPresentation)
        or not isinstance(semantic_summary, PartnerSemanticSummary)
        or not isinstance(edits, dict)
        or set(edits) != expected
        or any(not isinstance(edits[key], str) for key in expected)
    ):
        raise PermissionError("partner presentation edit request is invalid")
    updated = replace(
        presentation,
        cover_title=edits["cover_title"],
        cover_dek=edits["cover_dek"],
    )
    return validate_partner_report_presentation(
        updated, semantic_summary=semantic_summary,
    )


def render_partner_presentation_editor(presentation: object) -> str:
    """Render bounded copy controls without exposing evidence or hash bindings."""

    from community_os.partner_report_presentation import (
        PartnerReportPresentation,
        partner_report_presentation_copy_options,
    )

    if not isinstance(presentation, PartnerReportPresentation):
        raise PermissionError("partner presentation is invalid")
    copy_options = partner_report_presentation_copy_options()

    def select_field(*, name: str, label: str, selected: str) -> str:
        options = "".join(
            '<option value="' + escape(value, quote=True) + '"'
            + (' selected' if value == selected else '')
            + '>' + escape(value) + '</option>'
            for value in copy_options[name]
        )
        return (
            '<label>' + escape(label) + '<select name="'
            + escape(name, quote=True) + '" required>' + options
            + '</select></label>'
        )

    return (
        '<form class="partner-presentation-editor" '
        'data-partner-presentation-form>'
        '<div><strong>Polish partner report copy</strong>'
        '<small>Choose from reviewed framing. Metrics, evidence references, section '
        'targets, and release bindings stay server-owned.</small></div>'
        + select_field(
            name="cover_title", label="Cover title",
            selected=presentation.cover_title,
        )
        + select_field(
            name="cover_dek", label="Cover introduction",
            selected=presentation.cover_dek,
        )
        + '<button type="submit">Save copy and invalidate stale report</button>'
        '</form>'
    )


def _current_partner_presentation(
    state: ReleaseOperatorState,
) -> tuple[object, object, Path]:
    """Load the current protected candidate and its editable presentation."""

    from community_os.partner_report_presentation import (
        load_or_create_partner_report_presentation,
    )
    from community_os.partner_semantic_projection import (
        load_protected_partner_semantic_candidate_summary,
    )

    status = state._rich_semantic_status()
    if not isinstance(status.get("aggregate_summary"), dict):
        raise PermissionError(
            "partner presentation requires the current reviewed aggregate",
        )
    semantic_summary = load_protected_partner_semantic_candidate_summary(
        state.root / "protected" / "rich-semantic-internal.aggregate.json",
    )
    if (
        semantic_summary.event_key != state.event_key
        or semantic_summary.event_definition_sha256
        != state.event_definition_sha256
    ):
        raise PermissionError(
            "partner presentation requires the current reviewed aggregate",
        )
    path = (
        state.root / "protected" / "release"
        / "partner-report-presentation.json"
    )
    presentation = load_or_create_partner_report_presentation(
        path, semantic_summary=semantic_summary,
    )
    return semantic_summary, presentation, path


def persist_partner_presentation_edits(
    state: ReleaseOperatorState, edits: object,
) -> dict[str, object]:
    """Persist bounded copy and revoke only report-derived release state."""

    from community_os.partner_report_presentation import (
        partner_report_presentation_sha256,
        write_partner_report_presentation,
    )

    semantic_summary, presentation, path = _current_partner_presentation(state)
    updated = apply_partner_presentation_edits(
        presentation, edits, semantic_summary=semantic_summary,
    )
    write_partner_report_presentation(
        path, updated, semantic_summary=semantic_summary,
    )
    state._invalidate_release(
        ("report", "publish", "analytics"),
        reason_code="partner_presentation_changed",
    )
    return {
        "ok": True,
        "presentation_sha256": partner_report_presentation_sha256(updated),
    }


def render_event_setup_page(*, csrf: str, operator_code: str) -> str:
    """Render the first-run setup surface without exposing server-owned mappings."""

    if not isinstance(csrf, str) or not csrf:
        raise ValueError("event setup CSRF token is required")
    if not _CODE.fullmatch(operator_code):
        raise ValueError("operator_code must be machine-readable")
    return f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="operator-csrf" content="{escape(csrf)}"><title>Create event · START Community OS</title>
<style>
:root{{color-scheme:light;--ink:oklch(25% .025 265);--muted:oklch(48% .025 265);--paper:oklch(98% .008 90);--surface:oklch(95% .012 90);--rule:oklch(83% .018 265);--accent:oklch(42% .12 20);--danger:oklch(48% .16 25)}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--paper);color:var(--ink);font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",system-ui,sans-serif}}main{{width:min(920px,calc(100% - 32px));margin:48px auto 72px}}header{{max-width:68ch;margin-bottom:36px}}.eyebrow{{color:var(--accent);font-size:.78rem;font-weight:800;letter-spacing:.08em;text-transform:uppercase}}h1{{font-size:2.15rem;line-height:1.08;margin:8px 0 14px}}p{{color:var(--muted)}}form{{display:grid;gap:30px}}fieldset{{margin:0;padding:0;border:0}}legend{{font-size:1.25rem;font-weight:800;margin-bottom:14px}}.grid{{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:18px}}label{{display:grid;gap:7px;font-weight:700}}label.wide{{grid-column:1/-1}}input,select{{width:100%;min-height:44px;padding:10px 12px;border:1px solid var(--rule);border-radius:7px;background:oklch(99% .004 90);color:var(--ink);font:inherit}}input:focus-visible,select:focus-visible,button:focus-visible{{outline:3px solid color-mix(in oklch,var(--accent) 32%,transparent);outline-offset:2px;border-color:var(--accent)}}small{{color:var(--muted);font-weight:500}}.owner{{display:flex;justify-content:space-between;gap:20px;padding:14px 0;border-top:1px solid var(--rule);border-bottom:1px solid var(--rule)}}.owner strong{{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}}button{{justify-self:start;min-height:46px;padding:11px 18px;border:1px solid var(--accent);border-radius:7px;background:var(--accent);color:var(--paper);font:inherit;font-weight:800;cursor:pointer}}button:hover{{filter:brightness(.94)}}button:disabled{{cursor:wait;opacity:.58}}#status{{min-height:24px;margin:0;color:var(--muted)}}#status[data-state="error"]{{color:var(--danger)}}#status[data-state="done"]{{color:oklch(42% .1 145);font-weight:700}}@media(max-width:640px){{main{{margin-top:28px}}.grid{{grid-template-columns:1fr}}}}
</style></head><body><main>
<header><span class="eyebrow">First-run setup</span><h1>Create a supported hackathon event</h1><p>Enter event details and workbook sheet names. Source adapters, mappings, privacy rules, and report structure remain registered on the server.</p></header>
<form id="event-setup-form">
<fieldset><legend>Event</legend><div class="grid">
<label>Event key<input name="event-key" required maxlength="96" pattern="[a-z0-9]+(?:-[a-z0-9]+)*" placeholder="start-warsaw-autumn-2027"><small>Lowercase words separated by hyphens.</small></label>
<label>Event name<input name="event-name" required maxlength="160" placeholder="START Warsaw Autumn Hackathon"></label>
<label>Starts on<input name="starts-on" type="date" required></label><label>Ends on<input name="ends-on" type="date" required></label>
<label class="wide">Timezone<input name="timezone" required maxlength="64" value="Europe/Warsaw"><small>Use an IANA timezone such as Europe/Warsaw.</small></label>
</div></fieldset>
<fieldset><legend>Source and report profiles</legend><div class="grid">
<label>Source profile<select name="source-profile"><option value="start-hackathon-v1">START hackathon exports</option></select></label>
<label>Report profile<select name="report-profile"><option value="start-partner-talent-v1">Partner talent brief</option></select></label>
<label>Track preference sheets<input name="preference-sheets" required maxlength="512" placeholder="Responses 2027"><small>Separate multiple sheet names with commas.</small></label>
<label>Submission sheets<input name="submission-sheets" required maxlength="512" placeholder="health tech, developer tools"><small>Separate multiple sheet names with commas.</small></label>
</div></fieldset>
<div class="owner"><span>Accountable operator</span><strong>{escape(operator_code)}</strong></div>
<button type="submit">Create protected event</button><p id="status" role="status" aria-live="polite"></p>
</form></main><script>
(() => {{
  const form = document.getElementById('event-setup-form');
  const status = document.getElementById('status');
  const csrf = document.querySelector('meta[name="operator-csrf"]').content;
  const sheets = value => value.split(',').map(item => item.trim()).filter(Boolean);
  form.addEventListener('submit', async event => {{
    event.preventDefault();
    const button = form.querySelector('button[type="submit"]');
    button.disabled = true; status.dataset.state = ''; status.textContent = 'Creating the protected event definition…';
    const values = new FormData(form);
    const payload = {{
      version: 'event-setup-v1',
      event: {{key: values.get('event-key'), name: values.get('event-name'), starts_on: values.get('starts-on'), ends_on: values.get('ends-on'), timezone: values.get('timezone')}},
      source_profile: values.get('source-profile'),
      selected_sheets: {{preferences: sheets(values.get('preference-sheets')), submissions: sheets(values.get('submission-sheets'))}},
      report_profile: values.get('report-profile')
    }};
    try {{
      const response = await fetch('/event-setup', {{method:'POST',headers:{{'Content-Type':'application/json','X-Operator-CSRF':csrf}},body:JSON.stringify(payload)}});
      const result = await response.json();
      if (!response.ok) throw new Error(result.error || 'Setup failed');
      status.dataset.state = 'done'; status.textContent = 'Event created. Restart this command to open uploads and enrichment.';
    }} catch (error) {{
      status.dataset.state = 'error'; status.textContent = error.message; button.disabled = false;
    }}
  }});
}})();
</script></body></html>'''


def run_event_setup_operator(
    *, root: str | Path, access_policy: OperatorAccessPolicy,
    operator_code: str, pseudonym_secret: bytes,
    port: int = 8766, open_browser: bool = False,
    host: str = "127.0.0.1",
) -> None:
    """Serve one authenticated setup flow, then stop after atomic creation."""

    if len(pseudonym_secret) < 16:
        raise ValueError("operator pseudonym secret must contain at least 16 bytes")
    if not _CODE.fullmatch(operator_code):
        raise ValueError("operator_code must be machine-readable")
    if host not in {"127.0.0.1", "0.0.0.0"}:
        raise ValueError(
            "operator host must be loopback or all interfaces behind the authenticated proxy",
        )
    setup_root = Path(root)
    setup_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    setup_root.chmod(0o700)
    destination = setup_root / "event-definition.json"
    if destination.exists():
        raise FileExistsError("event definition already exists")
    csrf = secrets.token_urlsafe(32)
    mutation_lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        def _reply(
            self, status: int, body: bytes,
            content_type: str = "application/json",
        ) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type + "; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; "
                "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
            )
            self.end_headers()
            self.wfile.write(body)

        def _authorized(self) -> bool:
            if access_policy.authorize(self.headers):
                return True
            self._reply(403, b'{"error":"forbidden"}')
            return False

        def do_GET(self) -> None:
            parsed = urlparse(self.path)
            if parsed.path == "/health":
                self._reply(200, b'{"status":"setup_required"}')
                return
            if not self._authorized():
                return
            if parsed.path != "/":
                self._reply(404, b'{"error":"not_found"}')
                return
            page = render_event_setup_page(
                csrf=csrf, operator_code=operator_code,
            )
            self._reply(200, page.encode("utf-8"), "text/html")

        def do_POST(self) -> None:
            if not self._authorized():
                return
            if not hmac.compare_digest(
                self.headers.get("X-Operator-CSRF", ""), csrf,
            ):
                self._reply(403, b'{"error":"csrf_failed"}')
                return
            parsed = urlparse(self.path)
            if parsed.path != "/event-setup":
                self._reply(404, b'{"error":"not_found"}')
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                self._reply(400, b'{"error":"invalid_content_length"}')
                return
            if length < 2 or length > 32 * 1024:
                self._reply(413, b'{"error":"setup_payload_too_large"}')
                return
            if not mutation_lock.acquire(blocking=False):
                self._reply(409, b'{"error":"operator_mutation_in_progress"}')
                return
            try:
                try:
                    from community_os.event_setup import write_event_definition

                    if destination.exists():
                        self._reply(
                            409, b'{"error":"event_definition_already_exists"}',
                        )
                        return
                    payload = json.loads(self.rfile.read(length))
                    if not isinstance(payload, dict):
                        raise ValueError("event setup must be an object")
                    definition = write_event_definition(destination, payload)
                    result = {
                        "event_key": definition.event_key,
                        "ok": True,
                        "restart_required": True,
                    }
                    self._reply(
                        200,
                        json.dumps(result, separators=(",", ":")).encode("utf-8"),
                    )
                    threading.Thread(
                        target=server.shutdown, daemon=True,
                    ).start()
                except (
                    json.JSONDecodeError, OSError, TypeError, ValueError,
                ) as error:
                    self._reply(
                        400,
                        json.dumps(
                            {"error": str(error)}, separators=(",", ":"),
                        ).encode("utf-8"),
                    )
            finally:
                mutation_lock.release()

        def log_message(self, format: str, *args: object) -> None:
            print(f"release_operator_setup {self.command} {urlparse(self.path).path}")

    server = ThreadingHTTPServer((host, port), Handler)
    url = f"http://127.0.0.1:{server.server_port}/"
    print(url, flush=True)
    if open_browser:
        webbrowser.open(url)
    try:
        server.serve_forever()
    finally:
        server.server_close()


def render_release_operator_page(state: ReleaseOperatorState) -> str:
    snapshot = state.snapshot()
    authoritative_classification_codes = {
        case.case_code
        for case in state.review_repository.authoritative_classification_cases()
    }
    review_cases = tuple(
        case for case in snapshot["review_cases"]
        if (
            case["kind"] != "classification"
            or case["case_code"] in authoritative_classification_codes
        )
    )
    private_semantic_view = state._private_semantic_operator_view()
    private_open_names = private_semantic_view["open_names"]
    private_reviewed_highlights = private_semantic_view["highlights"]
    if (
        not isinstance(private_open_names, dict)
        or not isinstance(private_reviewed_highlights, list)
    ):
        raise PermissionError("private semantic operator view is invalid")
    event = snapshot["event"]
    disabled_optional_stages = set(state.disabled_optional_stages)
    optional_stage_policy_bound = state.optional_stage_policy_bound
    sources = tuple(event["sources"])
    labels = {str(source["role"]): _source_label(str(source["role"])) for source in sources}

    def upload_card(role: str) -> str:
        source = next(item for item in sources if item["role"] == role)
        record = snapshot["source_slots"].get(role, {})
        if isinstance(record, dict) and record.get("state") == "validated":
            detail = (
                f'Validated schema · {record.get("row_count", "?")} rows · '
                f'SHA-256 {str(record.get("sha256", ""))[:12]}…'
            )
        else:
            detail = "Waiting for protected export"
        accept = _media_extension(str(source["media_type"]))
        requirement = "" if source["required"] else " · optional"
        return (
            f'<label class="drop" data-drop="{role}"><span>{escape(labels[role])}</span>'
            f'<input type="file" data-source="{role}" accept="{accept}">'
            f'<small>{escape(detail + requirement)}</small></label>'
        )

    uploads = "".join(upload_card(role) for role in state.source_slots)
    required_stage_order = tuple(
        stage for stage in (
            "reconcile", "github", "public_pages", "classification",
            "aggregate", "report", "publish", "analytics",
        )
        if stage not in disabled_optional_stages
        and (stage != "public_pages" or optional_stage_policy_bound)
    )
    stage_display_names = {
        "github": "GitHub",
        "public_pages": "Public Pages",
        "publish": "Create share bundle",
    }
    stage_descriptions = {
        "reconcile": "Validate sources, corrections, identities, and team links.",
        "github": (
            "Required for release. Mandatory semantic inputs: application + GitHub projects. "
            "The separate protected GitHub semantic assessment must be reviewed before "
            "aggregate use."
        ),
        "public_pages": (
            "Required for release. Read only applicant-supplied, allowlisted public pages."
        ),
        "classification": (
            "Required for release. Classify minimum-necessary structured evidence, "
            "then queue uncertainty."
        ),
        "aggregate": "Apply suppression and minimum-cell privacy controls.",
        "report": "Generate matched aggregate-only HTML and PDF evidence surfaces.",
        "publish": "Create the verified local partner bundle inside the share boundary.",
        "analytics": "Enable privacy-limited measurement only after sharing approval.",
    }
    if not optional_stage_policy_bound:
        public_pages_policy_note = (
            '<aside class="optional-boundary" data-optional-provider="public_pages">'
            '<strong>Public-page policy awaits approval validation</strong>'
            '<span>No public-page operation can run until approval bundle is validated. '
            'GitHub + application evidence remains mandatory.</span></aside>'
        )
    elif "public_pages" in disabled_optional_stages:
        public_pages_policy_note = (
            '<aside class="optional-boundary" data-optional-provider="public_pages">'
            '<strong>Public-page enrichment is off for this event</strong>'
            '<span>GitHub + application evidence remains mandatory. No public-page '
            'transport is created or called, and missing public pages do not affect '
            'a participant assessment.</span></aside>'
        )
    else:
        public_pages_policy_note = ""
    stage_status_labels = {
        "allowed": "Ready to run", "locked": "Waiting for approval",
        "failed": "Needs attention", "complete": "Done", "running": "Running",
    }
    stages = "".join(
        f'''<li data-stage="{escape(key)}"><span class="stage-index">{index:02d}</span><div class="stage-copy"><strong>{escape(stage_display_names.get(key, key.replace('_', ' ').title()))}</strong><span>{escape(stage_descriptions[key])}</span></div><span class="state state-{escape(item['status'])}">{escape(stage_status_labels.get(item['status'], item['status'].replace('_', ' ').title()))}</span><small>{item['attempts']} attempts</small></li>'''
        for index, key in enumerate(required_stage_order, start=1)
        if (item := snapshot["stages"].get(key)) is not None
    )
    privacy_status = "".join(
        f'<li><strong>{escape(key.replace("_", " ").title())}</strong><span class="state">{escape(str(value))}</span></li>'
        for key, value in snapshot["privacy_operations"].items()
    )
    exclusion_state = snapshot["privacy_exclusions"]
    exclusion_hash = exclusion_state.get("exclusion_set_sha256")
    privacy_status += (
        '<li><strong>Subject opt-outs</strong><span class="state">'
        + escape(
            f'{exclusion_state["state"]}: {exclusion_state["excluded_count"]}'
            + (f' · {str(exclusion_hash)[:12]}' if exclusion_hash else "")
        )
        + "</span></li>"
    )
    privacy_inventory = "".join(
        "<tr>"
        f'<th scope="row">{escape(str(item.get("source", "unknown")))}</th>'
        f'<td>{escape(str(item.get("purpose", "pending")))}</td>'
        f'<td>{escape(str(item.get("accountable_owner", snapshot["privacy_operations"].get("accountable_owner", "pending"))))}</td>'
        f'<td>{escape(str(item.get("retention_deadline", "pending")))}</td>'
        f'<td>{escape(", ".join(str(value) for value in item.get("allowed_uses", [])))}</td>'
        "</tr>"
        for item in snapshot["privacy_inventory"]
    ) or '<tr><td colspan="5">Inventory becomes available after the approval bundle is validated.</td></tr>'
    def display_code(value: object) -> str:
        if isinstance(value, list):
            return ", ".join(display_code(item) for item in value) or "None observed"
        return str(value).replace("_", " ").title()

    def render_semantic_review_packet(packet: Mapping[str, object]) -> str:
        proposal = packet["proposal"]
        coverage = packet["source_coverage"]
        evidence_items = packet["evidence_items"]
        if (
            not isinstance(proposal, Mapping)
            or not isinstance(coverage, Mapping)
            or not isinstance(evidence_items, list)
        ):
            raise PermissionError("rich semantic review packet is invalid")
        classification = proposal["classification"]
        taxonomy = proposal["semantic_taxonomy"]
        if not isinstance(classification, Mapping) or not isinstance(taxonomy, Mapping):
            raise PermissionError("rich semantic review packet is invalid")
        classification_rows = "".join(
            f'<div><dt>{escape(display_code(key))}</dt>'
            f'<dd>{escape(display_code(value))}</dd></div>'
            for key, value in classification.items()
        ) + (
            '<div><dt>Confidence</dt><dd>'
            + escape(display_code(proposal["confidence"]))
            + "</dd></div>"
        )
        taxonomy_rows: list[str] = []
        for group in ("project", "career"):
            dimensions = taxonomy.get(group)
            if not isinstance(dimensions, Mapping):
                raise PermissionError("rich semantic review taxonomy is invalid")
            taxonomy_rows.extend(
                "<tr>"
                f'<th scope="row">{escape(display_code(key))}</th>'
                f'<td>{escape(display_code(value))}</td>'
                f'<td>{escape(display_code(group))}</td>'
                "</tr>"
                for key, value in dimensions.items()
            )
        coverage_items: list[str] = []
        for family in _RICH_SOURCE_FAMILIES:
            counts = coverage.get(family)
            if not isinstance(counts, Mapping):
                raise PermissionError("rich semantic review coverage is invalid")
            coverage_items.append(
                "<li>"
                + escape(display_code(family))
                + f': {escape(str(counts.get("available")))} available, '
                + f'{escape(str(counts.get("shown")))} shown</li>'
            )
        reason_chips = "".join(
            f'<span>{escape(display_code(reason))}</span>'
            for reason in proposal["reason_codes"]
        )
        evidence_markup: list[str] = []
        for item in evidence_items:
            if not isinstance(item, Mapping):
                raise PermissionError("rich semantic review evidence is invalid")
            signals = item["signals"]
            excerpts = item["excerpts"]
            references = item["references"]
            if (
                not isinstance(signals, Mapping)
                or not isinstance(excerpts, list)
                or not isinstance(references, list)
            ):
                raise PermissionError("rich semantic review evidence is invalid")
            signal_items = "".join(
                f'<li>{escape(display_code(key))}: {escape(display_code(value))}</li>'
                for key, value in signals.items()
            ) or "<li>No additional structural signal.</li>"
            excerpt_items = "".join(
                '<blockquote><small>'
                + escape(display_code(excerpt["excerpt_kind"]))
                + "</small><p>"
                + escape(str(excerpt["text"]))
                + "</p></blockquote>"
                for excerpt in excerpts
                if isinstance(excerpt, Mapping)
            ) or "<p>No safe prose excerpt was available for this evidence item.</p>"
            reference_text = ", ".join(str(value) for value in references)
            evidence_markup.append(
                '<article class="semantic-evidence-item"><h5>'
                + escape(display_code(item["source_family"]))
                + " evidence " + escape(str(item["item_index"]))
                + "</h5><ul class=\"semantic-signals\">" + signal_items
                + "</ul>" + excerpt_items
                + '<small class="semantic-refs">Evidence references: '
                + escape(reference_text) + "</small></article>"
            )
        return (
            '<article class="semantic-review-packet" '
            f'data-private-review-packet="{escape(str(packet["packet_version"]))}">'
            '<header><small>Evidence-bound private review</small>'
            '<h4>Proposed semantic judgment</h4></header>'
            f'<dl class="semantic-classification">{classification_rows}</dl>'
            '<p class="semantic-summary"><strong>Project summary:</strong> '
            + escape(str(proposal["project_summary"]))
            + '</p><p class="semantic-summary"><strong>Career summary:</strong> '
            + escape(str(proposal["career_summary"]))
            + '</p><p class="semantic-rationale"><strong>Rationale:</strong> '
            + escape(str(proposal["rationale"])) + "</p>"
            + '<div class="semantic-reasons"><strong>Reason codes</strong>'
            + reason_chips + "</div>"
            + '<ul class="semantic-coverage">' + "".join(coverage_items) + "</ul>"
            + '<div class="table-scroll semantic-taxonomy"><table><thead><tr>'
            + '<th>Taxonomy dimension</th><th>Proposed value</th><th>Scope</th>'
            + '</tr></thead><tbody>' + "".join(taxonomy_rows)
            + "</tbody></table></div>"
            + '<div class="semantic-evidence-grid">' + "".join(evidence_markup)
            + "</div></article>"
        )

    review_groups: dict[str, list[str]] = {"identity": [], "team": [], "classification": []}
    for case in review_cases:
        if case["status"] != "open":
            continue
        kind = str(case["kind"])
        common = (
            f'data-review-kind="{escape(kind)}" data-case-code="{escape(str(case["case_code"]))}" '
            f'data-case-hash="{escape(str(case["case_hash"]))}"'
        )
        reasons = ", ".join(str(value).replace("_", " ") for value in case["reason_codes"])
        actions: list[str] = []
        review_packet = ""
        correction_control = (
            f'<textarea data-corrected-output="{escape(str(case["case_code"]))}" '
            'aria-label="Corrected structured classification JSON" '
            'placeholder="{&quot;professional_identity&quot;:{...}}"></textarea>'
        )
        if kind == "identity":
            actions.extend(
                f'<button {common} data-review-action="approve" data-selected-code="{escape(str(candidate))}">Approve {escape(str(candidate))}</button>'
                for candidate in case["candidate_codes"]
            )
            actions.extend((
                f'<button {common} data-review-action="keep_separate">Keep separate</button>',
                f'<button {common} data-review-action="quarantine">Quarantine</button>',
            ))
        elif kind == "team":
            actions.extend(
                f'<button {common} data-review-action="link" data-selected-code="{escape(str(candidate))}">Link {escape(str(candidate))}</button>'
                for candidate in case["candidate_codes"]
            )
        else:
            if case["version"] == "rich_semantic_review_v1":
                packet = state.rich_semantic_reviews.load_review_packet(
                    str(case["case_code"]),
                )
                private_name = private_open_names.get(str(case["case_code"]))
                name_markup = (
                    '<p class="private-subject-name"><strong>Applicant</strong>'
                    f'<span>{escape(private_name)}</span></p>'
                    if isinstance(private_name, str) and private_name else ""
                )
                review_packet = name_markup + render_semantic_review_packet(packet)
                proposal = packet["proposal"]
                if not isinstance(proposal, Mapping) or not isinstance(
                    proposal.get("classification"), Mapping,
                ):
                    raise PermissionError("rich semantic review packet is invalid")
                classification = proposal["classification"]
                correction_template = {
                    **classification,
                    "career_summary": proposal["career_summary"],
                    "cross_source_confidence": proposal["confidence"],
                    "evidence_refs": proposal["evidence_refs"],
                    "project_summary": proposal["project_summary"],
                    "rationale": proposal["rationale"],
                    "reason_codes": proposal["reason_codes"],
                    "review_state": "human_review_required",
                    "semantic_taxonomy": proposal["semantic_taxonomy"],
                }
                correction_control = (
                    f'<textarea data-corrected-output="{escape(str(case["case_code"]))}" '
                    'aria-label="Corrected rich semantic assessment JSON">'
                    + escape(json.dumps(
                        correction_template, ensure_ascii=True, indent=2,
                        sort_keys=True,
                    ))
                    + "</textarea>"
                )
            actions.extend((
                f'<button {common} data-review-action="approved">Approve</button>',
                correction_control,
                f'<button {common} data-review-action="corrected">Apply JSON correction</button>',
                f'<button {common} data-review-action="rejected">Reject</button>',
            ))
        review_groups[kind].append(
            '<li><strong>' + escape(str(case["case_code"])) + '</strong>'
            f'<span>{escape(reasons)}</span>{review_packet}'
            f'<div class="review-actions">{"".join(actions)}</div></li>'
        )
    review_lists = {
        key: ('<ul class="review-list">' + "".join(values) + '</ul>')
        if values else '<p class="empty-review">No open cases.</p>'
        for key, values in review_groups.items()
    }
    semantic_review_count = len(review_groups["classification"])
    semantic_review_queue = (
        '<details class="operator-ledger semantic-review-queue" '
        'data-review-queue="classification"><summary>Semantic review queue · '
        + str(semantic_review_count)
        + ' open</summary><div class="ledger-body"><p>Approve, correct, or reject '
        'uncertain classifications.</p>'
        + review_lists["classification"]
        + '</div></details>'
    )
    release_steps = "".join(
        f'<span class="{"active" if value == snapshot["release_state"] else ""}" '
        f'aria-current="{"step" if value == snapshot["release_state"] else "false"}">{label}</span>'
        for value, label in (
            ("Blocked", "Blocked"),
            ("Needs review", "Needs review"),
            ("Safe to publish", "Approved for sharing"),
        )
    )
    source_count = len(snapshot["source_slots"])
    source_total = int(event["source_total"])
    source_columns = min(max(source_total, 1), 4)
    counts = snapshot["event_counts"]
    if isinstance(counts.get("accepted"), int) and isinstance(counts.get("present"), int):
        event_count_text = f'{counts["accepted"]} accepted / {counts["present"]} present'
    else:
        event_count_text = "Reviewed event counts are not recorded yet"
    event_tracks = snapshot["event_tracks"]
    tracks_text = (
        "Tracks: " + ", ".join(str(value) for value in event_tracks)
        if event_tracks else "Tracks are not recorded yet"
    )
    rich_status = snapshot["rich_semantic_status"]
    rich_coverage = rich_status["source_coverage"]
    aggregate_summary = rich_status.get("aggregate_summary")
    semantic_results = ""
    partner_presentation_editor = ""
    if isinstance(aggregate_summary, dict):
        metrics = aggregate_summary.get("metrics")
        minimum_group_size = aggregate_summary.get("minimum_group_size")
        population = aggregate_summary.get("population")
        if isinstance(metrics, dict) and isinstance(population, dict):
            assessed_count = population.get("assessed_count")
            unknown_count = population.get("unknown_count")
            rows: list[str] = []
            for key, count in metrics.items():
                label = str(key).replace("_", " ").title()
                rows.append(
                    "<tr>"
                    f'<th scope="row">{escape(label)}</th>'
                    f'<td>{escape(str(count))}</td>'
                    "</tr>"
                )
            semantic_results = (
                '<div id="semantic-results" class="semantic-results">'
                '<h3>Internal semantic findings</h3>'
                '<p>Agent-assisted internal review. Not approved for partner release. '
                f'Public projection later applies the minimum group size of {escape(str(minimum_group_size))} and complementary suppression.</p>'
                '<dl class="semantic-meta"><div><dt>Reviewed facts</dt>'
                f'<dd>{escape(str(assessed_count))}</dd></div>'
                '<div><dt>Unknown or unresolved</dt>'
                f'<dd>{escape(str(unknown_count))}</dd></div></dl>'
                '<div class="table-scroll"><table><thead><tr><th>Registered metric</th>'
                '<th>Internal count</th></tr></thead>'
                f'<tbody>{"".join(rows)}</tbody></table></div></div>'
            )
        _, presentation, _ = _current_partner_presentation(state)
        partner_presentation_editor = render_partner_presentation_editor(
            presentation,
        )
    private_highlights = ""
    if private_reviewed_highlights:
        highlight_cards: list[str] = []
        for highlight in private_reviewed_highlights:
            if not isinstance(highlight, Mapping):
                raise PermissionError("private semantic highlight is invalid")
            name = highlight.get("name")
            case_code = highlight.get("case_code")
            case_hash = highlight.get("case_hash")
            summaries = highlight.get("summaries")
            dimensions = highlight.get("dimensions")
            standout = highlight.get("standout")
            if (
                not isinstance(name, str) or not name
                or not isinstance(case_code, str) or not _CODE.fullmatch(case_code)
                or not isinstance(case_hash, str)
                or not re.fullmatch(r"[0-9a-f]{64}", case_hash)
                or not isinstance(summaries, Mapping)
                or not isinstance(dimensions, list)
                or (standout is not None and not isinstance(standout, Mapping))
            ):
                raise PermissionError("private semantic highlight is invalid")
            standout_markup = ""
            if isinstance(standout, Mapping):
                rationale = standout.get("rationale")
                if not isinstance(rationale, str) or not rationale:
                    raise PermissionError("private standout evidence is invalid")
                standout_markup = (
                    '<aside class="private-standout-evidence">'
                    '<strong>Standout evidence for human follow-up</strong>'
                    '<p>' + escape(rationale) + "</p></aside>"
                )
            existing_rationale = (
                str(standout.get("rationale"))
                if isinstance(standout, Mapping) else ""
            )
            standout_control = (
                '<div class="private-standout-control" '
                f'data-standout-case-code="{escape(case_code)}" '
                f'data-standout-case-hash="{escape(case_hash)}">'
                '<label>Neutral evidence rationale<textarea '
                'aria-label="Neutral standout-evidence rationale" '
                'data-standout-rationale maxlength="280">'
                + escape(existing_rationale)
                + '</textarea></label><button type="button" '
                'data-standout-action="record">Record private follow-up cue</button>'
                '<small>Private operator judgment only. No ranking, recommendation, '
                'or partner-specific fit claim.</small></div>'
            )
            summary_markup = "".join(
                '<p class="private-highlight-summary"><strong>'
                + escape(display_code(scope))
                + " summary</strong><span>"
                + escape(str(summaries[scope]))
                + "</span></p>"
                for scope in ("project", "career")
                if scope in summaries
            )
            dimension_markup: list[str] = []
            for dimension in dimensions:
                if not isinstance(dimension, Mapping):
                    raise PermissionError("private semantic highlight is invalid")
                evidence_count = dimension.get("evidence_count")
                if type(evidence_count) is not int or evidence_count < 1:
                    raise PermissionError("private semantic highlight is invalid")
                dimension_markup.append(
                    "<div><dt>"
                    + escape(display_code(dimension.get("field")))
                    + "</dt><dd>"
                    + escape(display_code(dimension.get("value")))
                    + "</dd><small>"
                    + escape(display_code(dimension.get("scope")))
                    + " · "
                    + escape(str(evidence_count))
                    + (" evidence reference" if evidence_count == 1 else " evidence references")
                    + "</small></div>"
                )
            highlight_cards.append(
                '<article class="private-highlight-card"><h4>'
                + escape(name)
                + "</h4>"
                + standout_markup
                + summary_markup
                + '<dl class="private-highlight-dimensions">'
                + "".join(dimension_markup)
                + "</dl>"
                + standout_control
                + "</article>"
            )
        private_highlights = (
            '<div class="private-reviewed-highlights" '
            'data-private-reviewed-highlights="v1">'
            '<h3>Reviewed semantic highlights</h3>'
            '<p>Private, human-reviewed evidence summaries only. These are not '
            'partner-fit recommendations, rankings, or automatic praise.</p>'
            '<div class="private-highlight-grid">'
            + "".join(highlight_cards)
            + "</div></div>"
        )
    open_review_count = sum(
        1 for case in review_cases if case["status"] == "open"
    )
    locked_stage_names = [
        stage_display_names.get(key, key.replace("_", " ").title())
        for key in required_stage_order
        if snapshot["stages"].get(key, {}).get("status") == "locked"
    ]
    blockers: list[str] = []
    missing_sources = [
        labels[str(source["role"])] for source in sources
        if source["required"] is True
        and source["role"] not in snapshot["source_slots"]
    ]
    if missing_sources:
        blockers.append("Protected exports missing: " + ", ".join(missing_sources) + ".")
    if open_review_count:
        blockers.append(f"{open_review_count} review case(s) still need a recorded decision.")
    if locked_stage_names:
        blockers.append("Approval-gated stages remain locked: " + ", ".join(locked_stage_names) + ".")
    incomplete_privacy = [
        key.replace("_", " ") for key, value in snapshot["privacy_operations"].items()
        if key != "accountable_owner"
        and value not in {"complete", "clear", "recorded", "reconciled", "none"}
    ]
    if incomplete_privacy:
        blockers.append("Privacy Operations requires reconciliation: " + ", ".join(incomplete_privacy) + ".")
    if exclusion_state["excluded_count"] and exclusion_state["state"] != "propagated":
        blockers.append(
            "Subject opt-outs are registered but remain pending across regenerated outputs."
        )
    if not blockers:
        blockers.append("No machine-detected sharing blocker. Complete the final parity review before creating the share bundle.")
    blocker_list = "".join(f"<li>{escape(value)}</li>" for value in blockers)
    preview_ready = release_export_ready(
        state, "html", allow_candidate_preview=True,
    )
    preview_link = (
        '<a class="export" href="/preview" target="_blank" rel="noopener">Preview partner report</a>'
        if preview_ready else
        '<a class="export unavailable" target="_blank" aria-disabled="true">Preview partner report'
        '<small>Generate a current preview first</small></a>'
    )
    def export_link(artifact: str, label: str) -> str:
        return (
            f'<a class="export" href="/export?artifact={artifact}" download>'
            f'Export {label}</a>'
            if release_export_ready(state, artifact) else
            f'<span class="export unavailable" aria-disabled="true">Export {label}'
            '<small>Not ready</small></span>'
        )

    share_export_links = "".join(
        export_link(artifact, label)
        for artifact, label in (
            ("vercel_config", "Vercel security configuration"),
            ("site_html", "partner HTML"),
            ("site_pdf", "partner PDF"),
            ("site_manifest", "publication manifest"),
        )
    )
    internal_export_links = "".join(
        export_link(artifact, label)
        for artifact, label in (
            ("aggregates", "aggregates"),
            ("manifest", "pipeline manifest"),
            ("qa", "QA report"),
        )
    )
    report_render_ready = (
        snapshot["stages"].get("aggregate", {}).get("status") == "complete"
    )
    report_render_control = (
        '<div class="report-build"><div><strong>Generate the partner bundle</strong>'
        '<small>Uses current reviewed aggregates only. Does not enrich or share.</small></div>'
        '<button data-render-report'
        + ("" if report_render_ready else " disabled")
        + '>Generate current HTML and PDF</button></div>'
    )
    semantic_approval_path = (
        state.root / "protected" / "semantic-release-approval.json"
    )
    semantic_qa_path = state.root / "protected" / "semantic-release-qa.json"
    semantic_release_sealed = semantic_approval_path.is_file() and all(
        release_export_ready(state, artifact)
        for artifact in ("html", "pdf", "aggregates")
    )
    if semantic_release_sealed:
        semantic_approval_control = (
            '<div class="report-build"><div><strong>Semantic release sealed</strong>'
            '<small>The signed approval and exact artifact hashes are present. '
            'Exports remain available only while every binding verifies.</small></div></div>'
        )
    elif (
        semantic_approval_path.is_file()
        and isinstance(aggregate_summary, dict)
        and semantic_qa_path.is_file()
    ):
        semantic_approval_control = (
            '<div class="report-build"><div><strong>Semantic approval is stale</strong>'
            '<small>The prior seal no longer verifies against the current files or bindings. '
            'Re-run exact-candidate approval.</small></div>'
            '<button data-approve-semantic>Re-approve exact candidate</button></div>'
        )
    elif isinstance(aggregate_summary, dict) and semantic_qa_path.is_file():
        semantic_approval_control = (
            '<div class="report-build"><div><strong>Final semantic release approval</strong>'
            '<small>Release-owner only. Seals the exact candidate, QA receipt, HTML, PDF, '
            'aggregates, population, taxonomy, and run.</small></div>'
            '<button data-approve-semantic>Approve and seal exact candidate</button></div>'
        )
    elif isinstance(aggregate_summary, dict):
        semantic_approval_control = (
            '<div class="report-build"><div><strong>Final semantic release approval</strong>'
            '<small>Release-owner only. Generates and verifies the protected semantic QA '
            'receipt, then seals the exact candidate and artifact hashes.</small>'
            '</div><button data-approve-semantic>Generate QA and approve exact candidate'
            '</button></div>'
        )
    else:
        semantic_approval_control = (
            '<p class="approval-pending">Approval becomes available after current '
            'aggregate QA is generated.</p>'
        )
    publication_staging_ready = _verified_public_staging(state)
    deployment_staging_ready = _verified_deployment_staging(state)
    if publication_staging_ready:
        publication_approval_control = (
            '<div class="report-build"><div><strong>Partner share sealed</strong>'
            '<small>The exact approved partner HTML, PDF, and hash manifest are staged. '
            'Deployment remains a separate action.</small></div></div>'
        )
    elif semantic_release_sealed:
        publication_approval_control = (
            '<div class="report-build"><div><strong>Final publication approval</strong>'
            '<small>Release-owner only. Binds the current event approval, HTML, PDF, '
            'and artifact-set hashes, then runs only the local publication stage.</small>'
            '</div><button data-approve-publication>Approve and stage partner share'
            '</button></div>'
        )
    else:
        publication_approval_control = (
            '<p class="approval-pending">Publication approval becomes available after '
            'the reviewed semantic candidate is sealed.</p>'
        )
    if deployment_staging_ready:
        analytics_control = (
            '<div class="report-build"><div><strong>Analytics bundle sealed</strong>'
            '<small>The separate Vercel-ready bundle is hash-bound, uses the EU endpoint, '
            'and contains only the approved aggregate interaction events. It remains '
            'local until a separate deployment action.</small></div></div>'
        )
    elif publication_staging_ready:
        analytics_control = (
            '<form class="report-build" data-analytics-form><div>'
            '<strong>Prepare privacy-minimized PostHog EU analytics</strong>'
            '<small>Creates a separate local deployment bundle with report opens, PDF '
            'downloads, cohort changes, metric selections, and overlap-region selections only. '
            'No participant data, stable viewer profile, autocapture, or session replay. '
            'This action does not publish or deploy.</small></div>'
            '<label>PostHog public project key '
            '<input name="public_key" required autocomplete="off" '
            'pattern="phc_[A-Za-z0-9_-]{4,128}"></label>'
            '<small>The local process must provide POSTHOG_PERSONAL_API_KEY and '
            'POSTHOG_PROJECT_ID. This action verifies the live project setting and '
            'public-key binding before any bundle is created.</small>'
            '<button type="submit">Prepare analytics bundle</button></form>'
        )
    else:
        analytics_control = (
            '<p class="approval-pending">Analytics preparation becomes available after '
            'the exact partner share is staged.</p>'
        )
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Talent Pipeline Operator</title><link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Crect width='32' height='32' fill='%2300002c'/%3E%3C/svg%3E">
<style>:root{{--navy:#00002c;--burgundy:#80011f;--paper:#f7f7f4;--surface:#fff;--ink:#171729;--rule:#d9d9df;--muted:#626274;--ok:#176d45;--warn:#8a4b00;--soft:#efeff3}}*{{box-sizing:border-box}}html{{scroll-behavior:smooth}}body{{margin:0;background:var(--paper);color:var(--ink);font:15px/1.55 Avenir,"Avenir Next",system-ui,sans-serif}}header{{padding:30px max(24px,5vw) 34px;color:white;background:var(--navy);border-bottom:5px solid var(--burgundy)}}header .eyebrow{{margin:0 0 18px;color:#c9c9d4;font-size:.72rem;font-weight:800;letter-spacing:.13em;text-transform:uppercase}}header h1{{max-width:18ch;margin:0;font-size:clamp(2.25rem,5vw,4.6rem);line-height:.94;letter-spacing:-.045em;text-wrap:balance}}header p{{max-width:72ch;margin:18px 0 0;color:#d6d6df}}.command-nav{{display:flex;gap:18px;overflow:auto;padding:12px max(24px,5vw);border-bottom:1px solid var(--rule);background:var(--surface);font-size:.78rem;font-weight:800;text-transform:uppercase;letter-spacing:.04em}}.command-nav a{{color:var(--navy);text-decoration:none;white-space:nowrap}}main{{max-width:1500px;margin:auto;padding:0 max(24px,5vw) 64px}}section{{padding:38px 0;border-bottom:1px solid var(--rule)}}h2{{margin:0 0 8px;color:var(--navy);font-size:clamp(1.55rem,3vw,2.35rem);line-height:1.05;letter-spacing:-.03em}}h3{{color:var(--navy)}}section>p{{max-width:78ch;color:var(--muted)}}.overview-grid{{display:grid;grid-template-columns:minmax(0,1.45fr) minmax(300px,.8fr);gap:28px;margin-top:24px}}.summary-grid{{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:1px;padding:1px;background:var(--rule)}}.summary-card{{min-height:128px;padding:20px;background:var(--surface)}}.summary-card small{{display:block;color:var(--muted);font-weight:800;text-transform:uppercase;letter-spacing:.08em}}.summary-card strong{{display:block;margin-top:22px;color:var(--navy);font-size:1.8rem;line-height:1}}.action-card{{padding:24px;color:white;background:var(--navy)}}.action-card h3{{margin-top:0;color:white;font-size:1.35rem}}.action-card p{{color:#cfcfda}}.blockers{{margin:18px 0 0;padding-left:20px;list-style:disc}}.blockers li{{margin:8px 0}}.release{{display:flex;gap:0;margin-top:18px;border:1px solid var(--rule);background:var(--surface)}}.release span{{flex:1;padding:10px 12px;color:var(--muted);text-align:center;font-size:.77rem;font-weight:800;text-transform:uppercase}}.release .active{{color:white;background:var(--burgundy)}}.uploads{{display:grid;grid-template-columns:repeat({source_columns},minmax(0,1fr));gap:1px;margin-top:22px;padding:1px;background:var(--rule)}}.drop{{min-height:160px;padding:24px;background:var(--surface);display:grid;align-content:center;cursor:pointer}}.drop.dragging{{background:#fff1f4}}.drop span{{color:var(--navy);font-size:1.22rem;font-weight:800}}.drop small{{color:var(--muted)}}.drop input{{margin:16px 0}}.workflow{{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:28px;margin-top:22px}}.queue{{padding:20px;border:1px solid var(--rule);background:var(--surface)}}.queue h3{{margin-top:0}}form label{{display:grid;gap:5px;margin:12px 0;color:var(--muted);font-size:.78rem;font-weight:800;text-transform:uppercase;letter-spacing:.04em}}form input,textarea{{width:100%;padding:10px;border:1px solid var(--rule);background:white;color:var(--ink)}}ul{{padding:0;list-style:none}}.review-list li{{padding:14px 0;border-top:1px solid var(--rule)}}.review-list span{{display:block;color:var(--muted)}}.review-list textarea{{min-height:120px;margin:8px 0;font:12px/1.4 ui-monospace,monospace}}.privacy-grid{{display:grid;grid-template-columns:minmax(240px,.55fr) minmax(0,1.45fr);gap:28px;margin-top:22px}}.privacy-status li{{display:flex;justify-content:space-between;gap:16px;padding:10px 0;border-bottom:1px solid var(--rule)}}.table-scroll{{overflow:auto;border:1px solid var(--rule);background:var(--surface)}}table{{width:100%;border-collapse:collapse;min-width:760px}}th,td{{padding:12px;text-align:left;border-bottom:1px solid var(--rule);vertical-align:top}}thead th{{color:var(--muted);font-size:.72rem;text-transform:uppercase;letter-spacing:.05em}}.stages{{margin:22px 0;border-top:1px solid var(--rule)}}.stages li{{display:grid;grid-template-columns:42px minmax(260px,1fr) auto auto minmax(170px,auto);gap:14px;align-items:center;padding:17px 0;border-bottom:1px solid var(--rule)}}.stage-index{{color:var(--muted);font:700 .74rem ui-monospace,monospace}}.stage-copy strong,.stage-copy span{{display:block}}.stage-copy span{{max-width:62ch;color:var(--muted);font-size:.86rem}}.stage-actions{{display:flex;gap:6px;justify-content:flex-end}}button,a.export{{padding:9px 12px;border:1px solid var(--rule);color:var(--navy);background:white;font-weight:800;text-decoration:none;cursor:pointer}}button:not(:disabled):hover,a.export:hover{{border-color:var(--navy)}}button:disabled{{cursor:not-allowed;opacity:.48}}button:focus-visible,a:focus-visible,input:focus-visible,textarea:focus-visible{{outline:3px solid #d8a7b4;outline-offset:3px}}.state{{display:inline-flex;align-items:center;width:max-content;padding:5px 8px;color:var(--muted);background:var(--soft);font-size:.66rem;font-weight:800;text-transform:uppercase;letter-spacing:.04em}}.state-complete,.state-allowed{{color:var(--ok);background:#e5f2eb}}.state-locked,.state-failed{{color:var(--burgundy);background:#fdecef}}.state-running{{color:var(--warn);background:#fff2df}}.run-bar{{display:flex;align-items:center;justify-content:space-between;gap:20px;margin-top:22px;padding:18px;border:1px solid var(--rule);background:var(--surface)}}.run-bar label{{color:var(--muted)}}.run-bar button{{color:white;background:var(--burgundy);border-color:var(--burgundy)}}.exports{{display:flex;flex-wrap:wrap;gap:8px;margin-top:18px}}#status{{position:sticky;bottom:18px;width:max-content;max-width:100%;margin:22px 0 0 auto;padding:10px 14px;color:white;background:var(--navy)}}#status:empty{{display:none}}@media(max-width:950px){{.overview-grid,.privacy-grid{{grid-template-columns:1fr}}.stages li{{grid-template-columns:34px 1fr auto}}.stages li>small{{grid-column:2}}.stage-actions{{grid-column:2/-1;justify-content:flex-start}}}}@media(max-width:700px){{.uploads,.workflow,.summary-grid{{grid-template-columns:1fr}}.release{{display:grid;grid-template-columns:1fr}}.stages li{{grid-template-columns:28px 1fr}}.stages li>.state{{grid-column:2}}.run-bar{{align-items:flex-start;flex-direction:column}}}}</style></head><body>
<style>
body{{overflow-wrap:anywhere}}.skip{{position:fixed;left:-999px;top:12px;z-index:30;padding:11px 14px;color:var(--navy);background:white}}.skip:focus{{left:12px}}.command-nav{{display:grid;grid-template-columns:repeat(6,minmax(0,1fr));gap:0;overflow:visible;padding:0;font-size:.82rem;text-transform:none;letter-spacing:0}}.workflow-nav-link{{min-height:44px;padding:12px max(12px,2.5vw);color:var(--navy);text-decoration:none;border-right:1px solid var(--rule)}}section{{scroll-margin-top:58px}}.phase-label{{margin:0 0 7px;color:var(--burgundy);font-size:.72rem;font-weight:800}}.stages li{{grid-template-columns:42px minmax(260px,1fr) auto auto}}button,a.export,span.export{{display:inline-flex;align-items:center;min-height:44px}}button:disabled,.unavailable{{cursor:not-allowed;opacity:.58}}.export small{{display:block;margin-left:8px;color:var(--muted);font-weight:500}}.state{{max-width:100%;font-size:.72rem;text-transform:none;letter-spacing:0}}.optional-boundary{{margin-top:22px;padding:18px;border:1px solid var(--rule);background:var(--surface)}}.optional-boundary strong,.optional-boundary span{{display:block}}.optional-boundary span{{max-width:78ch;margin-top:6px;color:var(--muted)}}.operator-ledger{{margin:22px 0;border:1px solid var(--rule);background:var(--surface)}}.operator-ledger>summary{{min-height:52px;padding:14px 18px;color:var(--navy);font-weight:800;cursor:pointer}}.operator-ledger>summary:focus-visible{{outline:3px solid #d8a7b4;outline-offset:3px}}.ledger-body{{padding:0 18px 18px;border-top:1px solid var(--rule)}}.report-build{{display:flex;align-items:center;justify-content:space-between;gap:20px;margin:20px 0;padding:18px;border:1px solid var(--rule);background:var(--surface)}}.report-build strong,.report-build small{{display:block}}.report-build small{{margin-top:4px;color:var(--muted)}}.report-build button{{color:white;background:var(--burgundy);border-color:var(--burgundy)}}
.semantic-results{{margin-top:26px;padding:24px 0;border-top:1px solid var(--rule);border-bottom:1px solid var(--rule)}}.semantic-results h3{{margin:0 0 6px;font-size:1.35rem}}.semantic-results p{{max-width:78ch;color:var(--muted)}}.semantic-meta{{display:flex;gap:24px;margin:18px 0}}.semantic-meta div{{display:flex;align-items:baseline;gap:10px}}.semantic-meta dt{{color:var(--muted);font-size:.75rem;font-weight:800;text-transform:uppercase;letter-spacing:.06em}}.semantic-meta dd{{margin:0;color:var(--navy);font-size:1.7rem;font-weight:800}}.partner-presentation-editor{{display:grid;gap:14px;min-width:0;margin:22px 0;padding:22px;border:1px solid var(--rule);background:var(--surface)}}.partner-presentation-editor>div:first-child strong,.partner-presentation-editor>div:first-child small{{display:block}}.partner-presentation-editor>div:first-child small{{max-width:74ch;margin-top:4px;color:var(--muted)}}.partner-presentation-editor textarea{{min-height:76px;resize:vertical}}.partner-presentation-editor select{{width:100%;min-width:0;max-width:100%}}.partner-presentation-editor button{{justify-self:start;color:white;background:var(--burgundy);border-color:var(--burgundy)}}
.private-subject-name{{display:flex;align-items:baseline;gap:10px;margin:12px 0 0;padding:9px 11px;color:var(--ink);background:white;border-left:3px solid var(--burgundy)}}.private-subject-name strong{{color:var(--muted);font-size:.7rem;text-transform:uppercase;letter-spacing:.05em}}.private-subject-name span{{color:var(--navy)!important;font-size:1rem;font-weight:800}}.private-reviewed-highlights{{margin:26px 0;padding:24px;border:1px solid var(--rule);background:var(--surface)}}.private-reviewed-highlights>h3{{margin:0}}.private-reviewed-highlights>p{{max-width:78ch;color:var(--muted)}}.private-highlight-grid{{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px;margin-top:18px}}.private-highlight-card{{padding:18px;border:1px solid var(--rule);background:var(--paper)}}.private-highlight-card h4{{margin:0 0 12px;color:var(--navy);font-size:1.2rem}}.private-standout-evidence{{margin:12px 0;padding:12px;border-left:4px solid var(--burgundy);background:#fff1f4}}.private-standout-evidence strong{{color:var(--burgundy)}}.private-standout-evidence p{{margin:4px 0 0}}.private-standout-control{{display:grid;gap:8px;margin-top:16px;padding-top:14px;border-top:1px solid var(--rule)}}.private-standout-control label{{margin:0}}.private-standout-control textarea{{min-height:74px}}.private-standout-control small{{color:var(--muted)}}.private-highlight-summary{{display:grid;gap:3px;margin:10px 0}}.private-highlight-summary strong{{color:var(--muted);font-size:.7rem;text-transform:uppercase;letter-spacing:.05em}}.private-highlight-summary span{{color:var(--ink)!important}}.private-highlight-dimensions{{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:1px;margin:16px 0 0;padding:1px;background:var(--rule)}}.private-highlight-dimensions div{{padding:10px;background:white}}.private-highlight-dimensions dt{{color:var(--muted);font-size:.68rem;font-weight:800;text-transform:uppercase;letter-spacing:.04em}}.private-highlight-dimensions dd{{margin:3px 0;color:var(--navy);font-weight:800}}.private-highlight-dimensions small{{color:var(--muted)}}.semantic-review-packet{{margin:16px 0;padding:18px;border:1px solid var(--rule);background:var(--paper)}}.semantic-review-packet>header{{padding:0;color:var(--ink);background:transparent;border:0}}.semantic-review-packet>header small{{color:var(--burgundy);font-size:.7rem;font-weight:800;text-transform:uppercase;letter-spacing:.06em}}.semantic-review-packet h4{{margin:3px 0 14px;color:var(--navy);font-size:1.25rem}}.semantic-classification{{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:1px;margin:0 0 16px;padding:1px;background:var(--rule)}}.semantic-classification div{{padding:10px;background:white}}.semantic-classification dt{{color:var(--muted);font-size:.68rem;font-weight:800;text-transform:uppercase;letter-spacing:.04em}}.semantic-classification dd{{margin:4px 0 0;color:var(--navy);font-weight:800}}.semantic-summary,.semantic-rationale{{margin:8px 0;color:var(--ink)!important}}.semantic-reasons{{display:flex;flex-wrap:wrap;gap:6px;margin:14px 0}}.semantic-reasons strong{{width:100%;font-size:.75rem;text-transform:uppercase;letter-spacing:.04em}}.semantic-reasons span{{display:inline-flex!important;padding:4px 7px;color:var(--navy)!important;background:var(--soft);font-size:.72rem;font-weight:800}}.semantic-coverage{{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:4px 14px;margin:14px 0;color:var(--muted);font-size:.8rem}}.semantic-taxonomy table{{min-width:680px}}.semantic-evidence-grid{{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px;margin-top:14px}}.semantic-evidence-item{{min-width:0;padding:12px;border:1px solid var(--rule);background:white}}.semantic-evidence-item h5{{margin:0 0 8px;color:var(--navy)}}.semantic-signals{{display:flex;flex-wrap:wrap;gap:4px;margin:0 0 10px}}.semantic-signals li{{padding:3px 6px;border:0;background:var(--soft);font-size:.7rem}}.semantic-evidence-item blockquote{{margin:8px 0;padding:8px 10px;border-left:3px solid var(--burgundy);background:var(--paper)}}.semantic-evidence-item blockquote small{{color:var(--muted);font-weight:800;text-transform:uppercase}}.semantic-evidence-item blockquote p{{margin:4px 0 0}}.semantic-refs{{display:block;margin-top:8px;color:var(--muted);font:11px/1.4 ui-monospace,monospace}}.review-actions{{display:flex;flex-wrap:wrap;gap:6px;margin-top:12px}}
@media(max-width:950px){{.stages li{{grid-template-columns:34px minmax(0,1fr) auto}}.stages li>small{{grid-column:2}}.semantic-evidence-grid{{grid-template-columns:1fr}}}}@media(max-width:700px){{.stages li{{grid-template-columns:28px minmax(0,1fr)}}.stages li>.state,.stages li>small{{grid-column:2}}.report-build{{align-items:flex-start;flex-direction:column}}.semantic-classification,.semantic-coverage{{grid-template-columns:1fr}}}}@media(max-width:420px){{header{{padding:24px 18px}}main{{padding:0 18px 48px}}.command-nav{{grid-template-columns:repeat(2,minmax(0,1fr))}}.workflow-nav-link{{padding:11px 10px}}.drop{{min-height:132px;padding:18px}}.privacy-status li{{align-items:flex-start;flex-direction:column}}.release span{{text-align:left}}.report-build button{{width:100%;justify-content:center}}}}@media (prefers-reduced-motion:reduce){{html{{scroll-behavior:auto}}*,*::before,*::after{{animation:none!important;transition:none!important}}}}
</style><style>.analytics-confirmation{{display:flex;align-items:flex-start;gap:9px;max-width:36ch;text-transform:none;letter-spacing:0}}.analytics-confirmation input{{width:auto;margin-top:3px}}</style><a class="skip" href="#operator-main">Skip to release workflow</a>
<header><p class="eyebrow">{escape(str(event['name']))} · Authenticated release operator</p><h1>Talent pipeline release desk</h1><p>Raw participant data stays in protected server storage. This surface is the <code>release-operator</code>: it requires authenticated proxy identity, colleague allowlisting, and an attributable audit trail. The legacy operator command is unauthenticated and must never receive protected participant data.</p></header>
<nav class="command-nav" aria-label="Release actions"><a class="workflow-nav-link" data-top-level-action="upload" href="#sources">1. Upload</a><a class="workflow-nav-link" data-top-level-action="review" href="#reviews">2. Review</a><a class="workflow-nav-link" data-top-level-action="run" href="#pipeline">3. Run</a><a class="workflow-nav-link" data-top-level-action="preview" href="#preview">4. Preview</a><a class="workflow-nav-link" data-top-level-action="approve" href="#approve">5. Approve</a><a class="workflow-nav-link" data-top-level-action="export" href="#export">6. Export</a></nav><main id="operator-main">
<section id="overview"><h2>Release overview</h2><p>One release desk for source integrity, privacy rights, enrichment authorization, review, and sharing. {escape(event_count_text)}. {escape(tracks_text)}.</p><div class="overview-grid"><div><div class="summary-grid"><div class="summary-card" data-summary="sources"><small>Sources validated</small><strong>{source_count} / {source_total}</strong></div><div class="summary-card" data-summary="reviews"><small>Open reviews</small><strong>{open_review_count}</strong></div><div class="summary-card"><small>Rich proposals pending</small><strong>{rich_status['pending']}</strong></div><div class="summary-card"><small>Rich proposals reviewed</small><strong>{rich_status['reviewed']}</strong></div><div class="summary-card"><small>Mandatory stages locked</small><strong>{len(locked_stage_names)}</strong></div><div class="summary-card"><small>Release decision</small><strong>Current state: {escape(str(snapshot['release_state']))}</strong></div></div><div class="release" aria-label="Release sequence">{release_steps}</div></div><aside class="action-card"><h3>Action required</h3><p>What blocks sharing</p><ul class="blockers">{blocker_list}</ul></aside></div></section>
<section id="sources"><p class="phase-label">1. Upload source files</p><h2>Upload {source_total} protected exports</h2><p>Schema &amp; hash validation runs server-side before a source becomes available. Files never enter the partner share bundle.</p><div class="uploads">{uploads}</div></section>
<section id="reviews"><p class="phase-label">2. Review</p><h2>Reviewed source values &amp; resolution queues</h2><p>Every source confirmation or consequential override requires a structured reason and an attributable operator decision.</p><div class="workflow"><div class="queue"><h3>Reviewed source values</h3><p>Confirm an observed value or record an attributable correction. Equal values are approvals, not corrections.</p><form data-correction-form><label>Field code <input name="field" required pattern="[a-z][a-z0-9_]{{1,63}}"></label><label>Observed source value <input name="source_value" required type="number" min="0" step="1"></label><label>Reviewed value <input name="reviewed_value" required type="number" min="0" step="1"></label><label>Reason code <input name="reason_code" required pattern="[a-z][a-z0-9_]{{1,63}}"></label><button type="submit">Record reviewed value</button></form></div><div class="queue"><h3>Identity resolution</h3><p>Approve, keep separate, or quarantine ambiguous records.</p>{review_lists['identity']}</div><div class="queue"><h3>Team linking</h3><p>Resolve unmatched preference teams and submitted projects.</p>{review_lists['team']}</div><div class="queue"><h3>Semantic review</h3><p>{semantic_review_count} open classification review(s). Open the queue only when reviewing evidence.</p>{semantic_review_queue}</div></div><details class="operator-ledger" data-ledger="qa"><summary>QA evidence ledger</summary><div class="ledger-body"><aside class="optional-boundary" data-rich-semantic-status><strong>Mandatory semantic inputs: application + GitHub projects</strong><span>Aggregate source coverage only. Application evidence: {rich_coverage['application']} · GitHub project evidence: {rich_coverage['projects']} · Devpost evidence: {rich_coverage['devpost']} · Career evidence: {rich_coverage['career']}.</span><span><strong>Next action:</strong> {escape(str(rich_status['next_action']))}</span></aside>{semantic_results}{private_highlights}</div></details></section>
<section id="privacy"><details class="operator-ledger" data-ledger="privacy"><summary>Privacy and retention ledger</summary><div class="ledger-body"><h2>Privacy Operations</h2><p>Source, purpose, accountable owner, retention deadline, allowed uses, notice, objections, suppression, deletion, and opt-out propagation are enforced before release.</p><div class="privacy-grid"><ul class="privacy-status">{privacy_status}</ul><div class="table-scroll"><table><thead><tr><th>Source</th><th>Purpose</th><th>Accountable owner</th><th>Retention deadline</th><th>Allowed uses</th></tr></thead><tbody>{privacy_inventory}</tbody></table></div></div></div></details></section>
<section id="pipeline"><p class="phase-label">3. Run</p><h2>Run approved pipeline</h2><p>The single controlled action runs only mandatory stages whose prerequisites and approvals are current. It continues from a failed stage without rerunning completed work.</p><details class="operator-ledger" data-ledger="provider"><summary>Provider controls and stage ledger</summary><div class="ledger-body"><h3>Pipeline sequence</h3><div class="report-build" data-classification-canary><div><strong>Five-person semantic canary</strong><small>The service prioritizes accepted and present participants, then remaining applicants. Full enrichment remains blocked until the five proposals are reviewed.</small></div><button data-run-canary>Run five-person semantic canary</button></div><ol class="stages">{stages}</ol>{public_pages_policy_note}<aside class="optional-boundary" data-optional-provider="coresignal"><strong>Optional internal-only Coresignal evaluation</strong><span>Optional career-only Coresignal overlay. It is never a release prerequisite and is not covered by the participant notice; retained records never enter partner output, and reviewed aggregate semantic facts require exact release approval under the same privacy gates. Its locked provider-stage record remains fail-closed.</span></aside></div></details><div class="run-bar"><span>Run required source, semantic, privacy, aggregate, and report stages.</span><button data-run-approved>Run approved release</button></div></section>
<section id="exports"><div id="preview"><p class="phase-label">4. Preview</p><h2>Preview partner report</h2><p>Preview the reviewed partner experience before creating the evidence-parity share bundle.</p>{partner_presentation_editor}{report_render_control}<p>{preview_link}</p></div><div id="approve"><p class="phase-label">5. Approve</p><h2>Approve the exact candidate</h2>{semantic_approval_control}{publication_approval_control}{analytics_control}</div><div id="export"><p class="phase-label">6. Export</p><h2>Export verified files</h2><div class="export-boundary" data-export-scope="partner-share"><h3>Partner share files</h3><p>Only the staged Vercel configuration, HTML, partner PDF, and exact hash manifest belong in the deployable partner share.</p><div class="exports">{share_export_links}</div></div><details class="operator-ledger internal-evidence" data-ledger="internal"><summary>Internal operator evidence</summary><div class="ledger-body"><p><strong>Never forward this internal evidence.</strong> It exists only for protected QA and reproducibility.</p><div class="exports">{internal_export_links}</div></div></details></div></section>
<div id="status" role="status" aria-live="polite"></div></main><script>
const status=document.querySelector('#status');
const operatorMain=document.querySelector('#operator-main');
function setBusy(busy){{operatorMain.setAttribute('aria-busy',String(busy));document.querySelectorAll('button,input[type=file]').forEach(control=>control.disabled=busy)}}
document.querySelectorAll('[data-drop]').forEach(zone=>{{zone.addEventListener('dragover',event=>{{event.preventDefault();zone.classList.add('dragging')}});zone.addEventListener('dragleave',()=>zone.classList.remove('dragging'));zone.addEventListener('drop',event=>{{event.preventDefault();zone.classList.remove('dragging');const file=event.dataTransfer.files[0];if(file)upload(zone.dataset.drop,file)}})}});
document.querySelectorAll('[data-source]').forEach(input=>input.addEventListener('change',()=>input.files[0]&&upload(input.dataset.source,input.files[0])));
async function upload(slot,file){{let response;setBusy(true);status.textContent='Validating '+slot+'…';try{{response=await fetch('/upload?slot='+encodeURIComponent(slot),{{method:'POST',headers:{{'Content-Type':'application/octet-stream','X-Operator-CSRF':'__OPERATOR_CSRF__','X-Filename':file.name}},body:file}});status.textContent=await response.text();if(response.ok)location.reload()}}catch(error){{status.textContent='Upload could not be completed. Check the private operator connection and try again.'}}finally{{if(!response?.ok)setBusy(false)}}}}
async function postJson(path,payload,message){{let response;setBusy(true);status.textContent=message;try{{response=await fetch(path,{{method:'POST',headers:{{'Content-Type':'application/json','X-Operator-CSRF':'__OPERATOR_CSRF__'}},body:JSON.stringify(payload)}});status.textContent=await response.text();if(response.ok)location.reload()}}catch(error){{status.textContent='The protected action could not be completed. Check the private operator connection and try again.'}}finally{{if(!response?.ok)setBusy(false)}}}}
document.querySelector('[data-correction-form]').addEventListener('submit',event=>{{event.preventDefault();const data=new FormData(event.currentTarget);postJson('/correction',{{field:data.get('field'),source_value:Number(data.get('source_value')),reviewed_value:Number(data.get('reviewed_value')),reason_code:data.get('reason_code')}},'Recording reviewed source value…')}});
document.querySelector('[data-partner-presentation-form]')?.addEventListener('submit',event=>{{event.preventDefault();const data=new FormData(event.currentTarget);postJson('/partner-presentation',{{cover_title:data.get('cover_title'),cover_dek:data.get('cover_dek')}},'Saving report copy and invalidating stale output…')}});
document.querySelectorAll('[data-review-kind]').forEach(button=>button.addEventListener('click',()=>{{const payload={{case:button.dataset.caseCode,case_hash:button.dataset.caseHash,decision:button.dataset.reviewAction}};if(button.dataset.selectedCode)payload.selected_code=button.dataset.selectedCode;if(button.dataset.reviewAction==='corrected'){{const field=[...document.querySelectorAll('[data-corrected-output]')].find(item=>item.dataset.correctedOutput===button.dataset.caseCode);try{{payload.corrected_output=JSON.parse(field?.value||'')}}catch(error){{status.textContent='Correction must be valid structured JSON.';return}}}}const path={{identity:'/identity-review',team:'/team-review',classification:'/classification-review'}}[button.dataset.reviewKind];postJson(path,payload,'Recording review decision…')}}));
document.querySelectorAll('[data-standout-action]').forEach(button=>button.addEventListener('click',()=>{{const control=button.closest('[data-standout-case-code]');const rationale=control?.querySelector('[data-standout-rationale]')?.value||'';postJson('/standout-evidence',{{case:control?.dataset.standoutCaseCode,case_hash:control?.dataset.standoutCaseHash,rationale}},'Recording private follow-up cue…')}}));
document.querySelector('[data-run-canary]').addEventListener('click',()=>postJson('/classification-canary',{{}},'Running five-person semantic canary…'));
document.querySelector('[data-run-approved]').addEventListener('click',()=>postJson('/run-approved',{{}},'Running approved release…'));
document.querySelector('[data-render-report]').addEventListener('click',()=>postJson('/render-report',{{}},'Generating current HTML and PDF…'));
document.querySelector('[data-approve-semantic]')?.addEventListener('click',()=>postJson('/approve-semantic-release',{{}},'Sealing the exact reviewed semantic candidate…'));
document.querySelector('[data-approve-publication]')?.addEventListener('click',()=>postJson('/approve-publication',{{}},'Binding exact hashes and staging the partner share…'));
document.querySelector('[data-analytics-form]')?.addEventListener('submit',event=>{{event.preventDefault();const data=new FormData(event.currentTarget);postJson('/prepare-analytics',{{public_key:data.get('public_key')}},'Verifying PostHog privacy settings and preparing the analytics bundle…')}});
</script></body></html>'''


_EXPORTS = {
    "vercel_config": ("deployment-staging/vercel.json", "application/json"),
    "site_html": ("deployment-staging/index.html", "text/html"),
    "site_pdf": ("deployment-staging/partner-talent-brief.pdf", "application/pdf"),
    "site_manifest": ("deployment-staging/publication-manifest.json", "application/json"),
    "html": ("protected/release/talent-brief.real.html", "text/html"),
    "pdf": ("protected/release/talent-brief.real.pdf", "application/pdf"),
    "aggregates": ("protected/release/talent-intelligence-v1.real.aggregate.json", "application/json"),
    "manifest": ("protected/enrichment-manifest.json", "application/json"),
    "qa": ("protected/release/talent-brief.internal-qa.md", "text/markdown"),
}


_DEPLOYMENT_EXPORTS = frozenset({
    "vercel_config", "site_html", "site_pdf", "site_manifest",
})


def _verified_public_staging(state: ReleaseOperatorState) -> bool:
    public = state.root / "public-staging"
    expected = {
        "index.html", "partner-talent-brief.pdf", "publication-manifest.json",
    }
    if (
        public.is_symlink()
        or not public.is_dir()
        or {path.name for path in public.iterdir()} != expected
    ):
        return False
    paths = {name: public / name for name in expected}
    if any(path.is_symlink() or not path.is_file() for path in paths.values()):
        return False
    try:
        manifest = json.loads(
            paths["publication-manifest.json"].read_text(encoding="utf-8"),
        )
    except (OSError, json.JSONDecodeError):
        return False
    if not isinstance(manifest, dict) or set(manifest) != {
        "analytics_enabled", "artifact_hashes", "artifact_set_sha256",
        "entrypoint", "manifest_version", "pdf", "privacy_state",
        "public_transform_version", "release_state",
    }:
        return False
    hashes = manifest.get("artifact_hashes")
    if not isinstance(hashes, dict) or set(hashes) != {
        "index.html", "partner-talent-brief.pdf",
    }:
        return False
    protected_release = state.root / "protected" / "release"
    source_paths = tuple(
        protected_release / name
        for name in ("talent-brief.real.html", "talent-brief.real.pdf")
    )
    if any(path.is_symlink() or not path.is_file() for path in source_paths):
        return False
    from community_os.publication import artifact_set_sha256, _public_html_bytes

    try:
        source_hashes = {
            "index.html": hashlib.sha256(
                _public_html_bytes(source_paths[0].read_bytes()),
            ).hexdigest(),
            "partner-talent-brief.pdf": hashlib.sha256(
                source_paths[1].read_bytes(),
            ).hexdigest(),
        }
    except (OSError, ValueError):
        return False
    from community_os.enrichment.release_pipeline import canonical_hash

    manifest_sha256 = hashlib.sha256(
        paths["publication-manifest.json"].read_bytes(),
    ).hexdigest()
    publish_result = state.pipeline.stage("publish").result
    expected_publish_output = canonical_hash([{
        "artifact_count": 2,
        "manifest_hash": manifest_sha256,
        "release_state": "Safe to publish",
    }])

    return (
        manifest.get("analytics_enabled") is False
        and isinstance(manifest.get("artifact_set_sha256"), str)
        and hmac.compare_digest(
            str(manifest["artifact_set_sha256"]),
            artifact_set_sha256(source_paths),
        )
        and manifest.get("entrypoint") == "index.html"
        and manifest.get("manifest_version") == "partner-static-bundle-v1"
        and manifest.get("pdf") == "partner-talent-brief.pdf"
        and manifest.get("privacy_state") == "aggregate_only"
        and manifest.get("public_transform_version") == "neutral-public-artifact-names-v1"
        and manifest.get("release_state") == "Safe to publish"
        and isinstance(publish_result, dict)
        and publish_result.get("record_count") == 1
        and isinstance(publish_result.get("output_hash"), str)
        and hmac.compare_digest(
            str(publish_result["output_hash"]), expected_publish_output,
        )
        and all(
            isinstance(hashes[name], str)
            and hmac.compare_digest(hashes[name], source_hashes[name])
            and hmac.compare_digest(
                hashes[name], hashlib.sha256(paths[name].read_bytes()).hexdigest(),
            )
            for name in hashes
        )
    )


def _analytics_publication_record(root: Path, manifest: Mapping[str, object]) -> dict[str, object]:
    manifest_path = root / "publication-manifest.json"
    return {
        "analytics_policy_version": manifest.get("analytics_policy_version"),
        "artifact_count": 3,
        "manifest_hash": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
        "release_state": manifest.get("release_state"),
    }


def _verified_vercel_config(config: object) -> bool:
    """Validate the exact static security wrapper without trusting free-form config."""

    if not isinstance(config, dict) or set(config) != {"$schema", "framework", "headers"}:
        return False
    rules = config.get("headers")
    if (
        config.get("$schema") != "https://openapi.vercel.sh/vercel.json"
        or config.get("framework") is not None
        or not isinstance(rules, list)
        or len(rules) != 1
        or not isinstance(rules[0], dict)
        or set(rules[0]) != {"source", "headers"}
        or rules[0].get("source") != "/(.*)"
    ):
        return False
    items = rules[0].get("headers")
    if not isinstance(items, list) or any(
        not isinstance(item, dict) or set(item) != {"key", "value"}
        for item in items
    ):
        return False
    headers = {
        str(item["key"]): item["value"]
        for item in items
    }
    if len(headers) != len(items) or set(headers) != {
        "Content-Security-Policy", "Permissions-Policy", "Referrer-Policy",
        "X-Content-Type-Options", "X-Frame-Options", "X-Robots-Tag",
    }:
        return False
    csp = headers["Content-Security-Policy"]
    return (
        isinstance(csp, str)
        and "script-src 'unsafe-inline'" not in csp
        and "connect-src https://eu.i.posthog.com" in csp
        and headers["Referrer-Policy"] == "no-referrer"
        and headers["Permissions-Policy"] == (
            "camera=(), geolocation=(), microphone=(), payment=(), usb=()"
        )
        and headers["X-Content-Type-Options"] == "nosniff"
        and headers["X-Frame-Options"] == "DENY"
        and headers["X-Robots-Tag"] == "noindex, nofollow, noarchive"
    )


def _verified_deployment_staging(state: ReleaseOperatorState) -> bool:
    """Verify the final analytics-enabled bundle against its staged source and stage receipt."""

    if not _verified_public_staging(state):
        return False
    deployment = state.root / "deployment-staging"
    expected = {
        "vercel.json", "index.html", "partner-talent-brief.pdf",
        "publication-manifest.json",
    }
    if (
        deployment.is_symlink()
        or not deployment.is_dir()
        or {path.name for path in deployment.iterdir()} != expected
    ):
        return False
    paths = {name: deployment / name for name in expected}
    if any(path.is_symlink() or not path.is_file() for path in paths.values()):
        return False
    try:
        from community_os.postpublication_analytics import (
            load_posthog_privacy_verification,
        )

        manifest = json.loads(
            paths["publication-manifest.json"].read_text(encoding="utf-8"),
        )
        source_manifest_path = state.root / "public-staging" / "publication-manifest.json"
        source_index_path = state.root / "public-staging" / "index.html"
        vercel_config = json.loads(paths["vercel.json"].read_text(encoding="utf-8"))
        privacy_verification = load_posthog_privacy_verification(
            state.root / "protected" / "posthog-project-privacy.json",
        )
    except (OSError, TypeError, UnicodeDecodeError, ValueError, json.JSONDecodeError):
        return False
    if not isinstance(manifest, dict) or set(manifest) != {
        "analytics_enabled", "analytics_policy_version", "artifact_hashes",
        "artifact_set_sha256", "entrypoint", "manifest_version", "pdf",
        "posthog_privacy_receipt_sha256",
        "privacy_state", "public_transform_version", "release_state",
        "source_index_sha256", "source_manifest_sha256",
    }:
        return False
    hashes = manifest.get("artifact_hashes")
    if not isinstance(hashes, dict) or set(hashes) != {
        "vercel.json", "index.html", "partner-talent-brief.pdf",
    }:
        return False
    analytics_result = state.pipeline.stage("analytics").result
    try:
        expected_result = {
            "output_hash": canonical_hash([
                _analytics_publication_record(deployment, manifest),
            ]),
            "record_count": 1,
        }
    except OSError:
        return False
    return (
        manifest.get("analytics_enabled") is True
        and manifest.get("analytics_policy_version") == "posthog-minimal-v2"
        and manifest.get("entrypoint") == "index.html"
        and manifest.get("manifest_version") == "partner-static-bundle-v2"
        and manifest.get("pdf") == "partner-talent-brief.pdf"
        and re.fullmatch(
            r"[a-f0-9]{64}",
            str(manifest.get("posthog_privacy_receipt_sha256")),
        ) is not None
        and hmac.compare_digest(
            str(manifest.get("posthog_privacy_receipt_sha256")),
            privacy_verification.sha256,
        )
        and manifest.get("privacy_state") == "aggregate_only"
        and manifest.get("public_transform_version") == "neutral-public-artifact-names-v1"
        and manifest.get("release_state") == "Safe to publish"
        and hmac.compare_digest(
            str(manifest.get("source_index_sha256")),
            hashlib.sha256(source_index_path.read_bytes()).hexdigest(),
        )
        and hmac.compare_digest(
            str(manifest.get("source_manifest_sha256")),
            hashlib.sha256(source_manifest_path.read_bytes()).hexdigest(),
        )
        and _verified_vercel_config(vercel_config)
        and all(
            isinstance(hashes.get(name), str)
            and hmac.compare_digest(
                str(hashes[name]), hashlib.sha256(paths[name].read_bytes()).hexdigest(),
            )
            for name in hashes
        )
        and analytics_result == expected_result
    )


def release_export_ready(
    state: ReleaseOperatorState,
    artifact: str,
    *,
    allow_candidate_preview: bool = False,
) -> bool:
    """Expose protected previews only while their producing stage is current."""
    spec = _EXPORTS.get(artifact)
    if spec is None:
        return False
    rich_status = state._rich_semantic_status()
    if rich_status["pending"] or rich_status["projection_incomplete"]:
        return False
    stage = (
        "analytics" if artifact in _DEPLOYMENT_EXPORTS
        else "aggregate" if artifact == "aggregates"
        else "report"
    )
    if state.pipeline.stage(stage).status is not StageStatus.COMPLETE:
        return False
    path = state.root / spec[0]
    if not path.is_file():
        return False
    if artifact == "aggregates":
        companion = state.root / "protected" / "release" / "talent-report-v3.real.aggregate.json"
        if not companion.is_file():
            return False
    semantic_path = (
        state.root / "protected" / "rich-semantic-internal.aggregate.json"
    )
    if semantic_path.is_file() and not allow_candidate_preview:
        if rich_status.get("aggregate_summary") is None:
            return False
        secret = state._semantic_approval_secret
        approval_path = state.root / "protected" / "semantic-release-approval.json"
        release_root = state.root / "protected" / "release"
        manifest_path = release_root / "talent-report-v3.real.manifest.json"
        if secret is None or not approval_path.is_file() or not manifest_path.is_file():
            return False
        try:
            from community_os.partner_semantic_projection import (
                load_partner_semantic_summary,
                semantic_summary_manifest_binding,
            )
            from community_os.publication import artifact_set_sha256
            from community_os.controlled_release import (
                validate_current_semantic_release_qa,
            )

            summary = load_partner_semantic_summary(
                semantic_path,
                approval_path=approval_path,
                now=datetime.now(UTC),
                approval_secret=secret,
            )
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            if manifest.get("semantic_enrichment") != semantic_summary_manifest_binding(
                summary,
            ):
                return False
            bindings = dict(summary.release_artifact_hashes)
            public_paths = tuple(
                release_root / name
                for name in (
                    "talent-brief.real.html",
                    "talent-brief.real.pdf",
                    "talent-intelligence-v1.real.aggregate.json",
                    "talent-report-v3.real.aggregate.json",
                )
            )
            if any(item.is_symlink() or not item.is_file() for item in public_paths):
                return False
            qa_receipt = validate_current_semantic_release_qa(
                state.root / "protected",
                html_path=public_paths[0],
                pdf_path=public_paths[1],
                authoritative_context=state.semantic_release_authoritative_context(),
                approval_bound_qa_sha256=str(bindings.get("qa_sha256") or ""),
            )
            if (
                hashlib.sha256(public_paths[0].read_bytes()).hexdigest()
                != bindings.get("html_sha256")
                or hashlib.sha256(public_paths[1].read_bytes()).hexdigest()
                != bindings.get("pdf_sha256")
                or qa_receipt.sha256 != bindings.get("qa_sha256")
                or artifact_set_sha256(public_paths)
                != bindings.get("report_candidate_sha256")
            ):
                return False
        except (
            OSError, PermissionError, TypeError, ValueError, json.JSONDecodeError,
        ):
            return False
    if artifact in _DEPLOYMENT_EXPORTS:
        return _verified_deployment_staging(state)
    if artifact != "manifest":
        return True
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    current = state.pipeline.to_dict()["stages"]
    expected_stages = {
        key: {
            "attempts": value["attempts"], "result": value["result"],
            "status": value["status"],
        }
        for key, value in sorted(current.items())
    }
    slots = state.snapshot()["source_slots"]
    expected_sources = {
        key: str(value["sha256"]) for key, value in sorted(slots.items())
    }
    exclusion_hash = state.snapshot()["privacy_exclusions"].get(
        "exclusion_set_sha256",
    )
    if isinstance(exclusion_hash, str) and re.fullmatch(r"[0-9a-f]{64}", exclusion_hash):
        expected_sources["subject_exclusions"] = exclusion_hash
    return (
        payload.get("stages") == expected_stages
        and payload.get("source_hashes") == expected_sources
    )


def run_release_operator(
    *, root: str | Path, access_policy: OperatorAccessPolicy,
    operator_code: str, pseudonym_secret: bytes,
    event_definition: EventDefinition,
    port: int = 8766, open_browser: bool = False,
    host: str = "127.0.0.1",
    approval_bundle: str | Path | None = None,
    stage_operations: Mapping[str, Callable[[], Sequence[Mapping[str, object]]]] | None = None,
    stage_operation_factory: Callable[[ReleaseOperatorState], Mapping[str, Callable[[], Sequence[Mapping[str, object]]]]] | None = None,
) -> None:
    """Serve the protected operator behind an authenticated identity proxy."""
    if len(pseudonym_secret) < 16:
        raise ValueError("operator pseudonym secret must contain at least 16 bytes")
    optional_stage_policy = getattr(
        stage_operation_factory, "disabled_optional_stages", None,
    )
    state = ReleaseOperatorState(
        root,
        operator_code=operator_code,
        event_definition=event_definition,
    )
    state.configure_optional_stage_policy(optional_stage_policy)
    disabled_optional_stages = state.disabled_optional_stages
    state.configure_semantic_release_authority(pseudonym_secret)
    approval_bundle_path = (
        Path(approval_bundle)
        if approval_bundle is not None
        else state.root / "protected" / "controlled-release-approval.json"
    )
    operations = dict(stage_operations or {})
    csrf = secrets.token_urlsafe(32)
    pipeline = ReleasePipeline(
        state.pipeline, manifest_path=state.root / "protected" / "enrichment-manifest.json",
        config={
            "event_definition_sha256": state.event_definition_sha256,
            "event_key": state.event_key,
            "operator_version": state.VERSION,
            "owner_code": operator_code,
            "disabled_optional_stages": list(disabled_optional_stages),
            "optional_stage_policy_bound": state.optional_stage_policy_bound,
        },
        prerequisites={
            "github": ("reconcile",),
            "public_pages": ("reconcile",),
            "coresignal": ("reconcile",),
            "classification": (
                ("github",)
                if "public_pages" in disabled_optional_stages
                else ("github", "public_pages")
            ),
            "aggregate": ("classification",),
            "report": ("aggregate",),
            "publish": ("report",),
            "analytics": ("publish",),
        },
    )

    def apply_optional_stage_policy(value: object) -> None:
        if value is None:
            raise PermissionError("optional-stage approval policy was not bound")
        disabled = _normalized_disabled_optional_stages(value)
        state.configure_optional_stage_policy(disabled)
        pipeline.config["disabled_optional_stages"] = list(disabled)
        pipeline.config["optional_stage_policy_bound"] = True
        pipeline.prerequisites["classification"] = (
            ("github",)
            if "public_pages" in disabled else ("github", "public_pages")
        )
        pipeline.config["stage_prerequisites"] = {
            key: list(pipeline.prerequisites[key])
            for key in sorted(pipeline.prerequisites)
        }

    def sync_pipeline_sources() -> None:
        nonlocal operations
        state.verify_current_source_files()
        slots = state.snapshot()["source_slots"]
        missing = sorted(
            role for role in state.required_source_slots if role not in slots
        )
        if missing:
            raise PermissionError("validated protected sources are missing: " + ",".join(missing))
        pipeline.source_hashes = {
            key: str(value["sha256"])
            for key, value in sorted(slots.items())
        }
        if stage_operation_factory is not None:
            operations = dict(stage_operation_factory(state))
            apply_optional_stage_policy(
                getattr(stage_operation_factory, "disabled_optional_stages", None),
            )
            exclusion_hash = state.snapshot()["privacy_exclusions"].get(
                "exclusion_set_sha256",
            )
            if isinstance(exclusion_hash, str) and re.fullmatch(
                r"[0-9a-f]{64}", exclusion_hash,
            ):
                pipeline.source_hashes["subject_exclusions"] = exclusion_hash

    mutation_lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        def _reply(self, status: int, body: bytes, content_type: str = "application/json") -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type + "; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'unsafe-inline'; script-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'")
            self.end_headers()
            self.wfile.write(body)

        def _authorized_actor(self) -> str | None:
            if access_policy.authorize(self.headers):
                return access_policy.pseudonymous_actor(
                    self.headers, secret=pseudonym_secret,
                )
            self._reply(403, b'{"error":"forbidden"}')
            return None

        def do_GET(self) -> None:
            path = urlparse(self.path)
            if path.path == "/health":
                self._reply(200, b'{"status":"ok"}')
                return
            actor_code = self._authorized_actor()
            if actor_code is None:
                return
            if not mutation_lock.acquire(blocking=False):
                self._reply(409, b'{"error":"operator_mutation_in_progress"}')
                return
            try:
                try:
                    with protected_mutation_lock(state.root):
                        state.refresh(mutation_lock_held=True)
                        self._do_authorized_GET(path, actor_code)
                except BlockingIOError:
                    self._reply(409, b'{"error":"operator_mutation_in_progress"}')
            finally:
                mutation_lock.release()

        def _do_authorized_GET(self, path: object, actor_code: str) -> None:
            if path.path == "/":
                append_operator_access_audit(
                    state.root, action="operator_viewed", actor_code=actor_code,
                    subject_code="operator_dashboard", reason_code="authenticated_request",
                )
                page = render_release_operator_page(state).replace(
                    "<head>", f'<head><meta name="operator-csrf" content="{csrf}">', 1,
                ).replace("__OPERATOR_CSRF__", csrf)
                self._reply(200, page.encode(), "text/html")
                return
            if path.path == "/preview":
                if not release_export_ready(
                    state, "html", allow_candidate_preview=True,
                ):
                    self._reply(409, b'{"error":"preview_is_stale_or_blocked"}')
                    return
                target = state.root / _EXPORTS["html"][0]
                if not target.exists():
                    self._reply(404, b'{"error":"preview_not_generated"}')
                    return
                append_operator_access_audit(
                    state.root, action="artifact_previewed", actor_code=actor_code,
                    subject_code="html", reason_code="authenticated_request",
                )
                self._reply(200, target.read_bytes(), "text/html")
                return
            if path.path == "/export":
                artifact = parse_qs(path.query).get("artifact", [""])[0]
                spec = _EXPORTS.get(artifact)
                if spec is None:
                    self._reply(404, b'{"error":"unknown_artifact"}')
                    return
                if not release_export_ready(state, artifact):
                    self._reply(409, b'{"error":"artifact_is_stale_or_blocked"}')
                    return
                if artifact == "aggregates":
                    aggregate_root = state.root / "protected" / "release"
                    sources = {
                        "talent_intelligence_v1": aggregate_root / "talent-intelligence-v1.real.aggregate.json",
                        "talent_report_v3": aggregate_root / "talent-report-v3.real.aggregate.json",
                    }
                    if any(not value.is_file() for value in sources.values()):
                        self._reply(404, b'{"error":"artifact_not_generated"}')
                        return
                    append_operator_access_audit(
                        state.root, action="artifact_exported", actor_code=actor_code,
                        subject_code="aggregates", reason_code="authenticated_request",
                    )
                    payload = {
                        key: json.loads(value.read_text(encoding="utf-8"))
                        for key, value in sources.items()
                    }
                    self._reply(
                        200, json.dumps(payload, separators=(",", ":")).encode(),
                        "application/json",
                    )
                    return
                target = state.root / spec[0]
                if not target.exists():
                    self._reply(404, b'{"error":"artifact_not_generated"}')
                    return
                append_operator_access_audit(
                    state.root, action="artifact_exported", actor_code=actor_code,
                    subject_code=artifact, reason_code="authenticated_request",
                )
                self._reply(200, target.read_bytes(), spec[1])
                return
            self._reply(404, b'{"error":"not_found"}')

        def do_POST(self) -> None:
            if not mutation_lock.acquire(blocking=False):
                self._reply(409, b'{"error":"operator_mutation_in_progress"}')
                return
            try:
                try:
                    with protected_mutation_lock(state.root):
                        state.refresh(mutation_lock_held=True)
                        self._do_POST()
                except BlockingIOError:
                    self._reply(409, b'{"error":"operator_mutation_in_progress"}')
            finally:
                mutation_lock.release()

        def _do_POST(self) -> None:
            actor_code = self._authorized_actor()
            if actor_code is None:
                return
            if not hmac.compare_digest(self.headers.get("X-Operator-CSRF", ""), csrf):
                self._reply(403, b'{"error":"csrf_failed"}')
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                self._reply(400, b'{"error":"invalid_content_length"}')
                return
            if length < 0 or length > 25 * 1024 * 1024:
                self._reply(413, b'{"error":"upload_too_large"}')
                return
            parsed = urlparse(self.path)
            try:
                body = self.rfile.read(length)
                with state.acting_as(actor_code):
                    if parsed.path == "/upload":
                        slot = _source_role(
                            parse_qs(parsed.query).get("slot", [""])[0],
                        )
                        state._source_config(slot)
                        append_operator_access_audit(
                            state.root, action="source_upload_requested", actor_code=actor_code,
                            subject_code=slot, reason_code="operator_requested",
                        )
                        response = state.store_upload(slot, body, filename=self.headers.get("X-Filename", ""))
                    elif parsed.path == "/stage":
                        sync_pipeline_sources()
                        request = json.loads(body)
                        stage = str(request["stage"])
                        if stage in {
                            "github", "public_pages", "coresignal", "publish",
                        }:
                            raise PermissionError(
                                "network enrichment and publication run only through "
                                "their controlled release actions",
                            )
                        operation = operations.get(stage)
                        if operation is None:
                            raise PermissionError("stage operation is not configured")
                        append_operator_access_audit(
                            state.root, action="stage_requested", actor_code=actor_code,
                            subject_code=stage, reason_code="operator_requested",
                        )
                        try:
                            response = pipeline.run(stage, operation)
                        finally:
                            pipeline.write_manifest()
                        append_operator_access_audit(
                            state.root, action="stage_completed", actor_code=actor_code,
                            subject_code=stage, reason_code="operation_completed",
                        )
                    elif parsed.path == "/classification-canary":
                        try:
                            sync_pipeline_sources()
                            operation = operations.get("classification_canary")
                            if operation is None:
                                raise PermissionError(
                                    _CLASSIFICATION_CANARY_SAFE_ERROR,
                                )
                            append_operator_access_audit(
                                state.root,
                                action="classification_canary_requested",
                                actor_code=actor_code,
                                subject_code="classification_canary",
                                reason_code="operator_requested",
                            )
                            response = _content_free_classification_canary_result(
                                operation(),
                            )
                            append_operator_access_audit(
                                state.root,
                                action="classification_canary_completed",
                                actor_code=actor_code,
                                subject_code="classification_canary",
                                reason_code="operation_completed",
                            )
                        except Exception:
                            raise PermissionError(
                                _CLASSIFICATION_CANARY_SAFE_ERROR,
                            ) from None
                    elif parsed.path == "/run-approved":
                        sync_pipeline_sources()
                        request = json.loads(body or b"{}")
                        append_operator_access_audit(
                            state.root, action="release_requested", actor_code=actor_code,
                            subject_code="partner_release", reason_code="operator_requested",
                        )
                        response = run_approved_release(
                            pipeline, operations,
                            include_coresignal=request.get("include_coresignal") is True,
                            semantic_review_store=state.rich_semantic_reviews,
                        )
                        append_operator_access_audit(
                            state.root, action="release_completed", actor_code=actor_code,
                            subject_code="partner_release", reason_code="operation_completed",
                        )
                    elif parsed.path == "/render-report":
                        sync_pipeline_sources()
                        operation = operations.get("report")
                        if operation is None:
                            raise PermissionError("report operation is not configured")
                        append_operator_access_audit(
                            state.root, action="report_render_requested", actor_code=actor_code,
                            subject_code="html_pdf", reason_code="operator_requested",
                        )
                        try:
                            response = run_local_report_render(
                                pipeline,
                                operation,
                                required_artifacts=(
                                    state.root / _EXPORTS["html"][0],
                                    state.root / _EXPORTS["pdf"][0],
                                ),
                            )
                        finally:
                            pipeline.write_manifest()
                        append_operator_access_audit(
                            state.root, action="report_render_completed", actor_code=actor_code,
                            subject_code="html_pdf", reason_code="operation_completed",
                        )
                    elif parsed.path == "/attest-semantic-reviews":
                        if not access_policy.authorize_release_owner(self.headers):
                            raise PermissionError(
                                "authenticated release-owner role is required",
                            )
                        request = json.loads(body)
                        if not isinstance(request, dict) or set(request) != {
                            "review_set_sha256",
                        }:
                            raise ValueError(
                                "semantic review attestation request is invalid",
                            )
                        expected_review_set_sha256 = str(
                            request["review_set_sha256"],
                        )
                        state._invalidate_release(
                            ("aggregate", "report", "publish", "analytics"),
                            reason_code="semantic_human_attestation_changed",
                        )
                        state._audit(
                            "semantic_human_review_attestation_requested",
                            "rich_semantic_review_set",
                            "authenticated_release_owner",
                        )
                        state._persist()
                        response = (
                            state.rich_semantic_reviews
                            .attest_required_human_reviews(
                                expected_review_set_sha256=(
                                    expected_review_set_sha256
                                ),
                                actor_code=actor_code,
                                attested_at=state._clock(),
                            )
                        )
                        state._audit(
                            "semantic_human_review_attestation_completed",
                            "rich_semantic_review_set",
                            "authenticated_release_owner",
                        )
                        state._persist()
                    elif parsed.path == "/approve-semantic-release":
                        sync_pipeline_sources()
                        if not access_policy.authorize_release_owner(self.headers):
                            raise PermissionError(
                                "authenticated release-owner role is required",
                            )
                        operation = operations.get("report")
                        if operation is None:
                            raise PermissionError("report operation is not configured")
                        from community_os.controlled_release import (
                            issue_current_semantic_release_approval,
                        )

                        append_operator_access_audit(
                            state.root,
                            action="semantic_release_approval_requested",
                            actor_code=actor_code,
                            subject_code="partner_release",
                            reason_code="authenticated_owner_requested",
                        )
                        required_report_artifacts = (
                            state.root / _EXPORTS["html"][0],
                            state.root / _EXPORTS["pdf"][0],
                        )
                        candidate_result = _regenerate_semantic_report_candidate(
                            operation,
                            required_artifacts=required_report_artifacts,
                        )
                        approval_result = issue_current_semantic_release_approval(
                            state.root / "protected" / "release",
                            state=state,
                            actor_code=actor_code,
                            signing_secret=pseudonym_secret,
                            now=datetime.now(UTC),
                            authoritative_context=(
                                state.semantic_release_authoritative_context()
                            ),
                        )
                        try:
                            aggregate_result = _adopt_approved_semantic_aggregate(
                                pipeline,
                                root=state.root,
                                semantic_approval_sha256=str(
                                    approval_result["approval_sha256"],
                                ),
                            )
                            report_result = run_local_report_render(
                                pipeline,
                                operation,
                                required_artifacts=required_report_artifacts,
                            )
                            if not all(
                                release_export_ready(state, artifact)
                                for artifact in ("html", "pdf", "aggregates")
                            ):
                                raise PermissionError(
                                    "semantic approval does not match regenerated artifacts",
                                )
                        except Exception:
                            approval_path = (
                                state.root / "protected"
                                / "semantic-release-approval.json"
                            )
                            approval_path.unlink(missing_ok=True)
                            raise
                        finally:
                            pipeline.write_manifest()
                        append_operator_access_audit(
                            state.root,
                            action="semantic_release_approval_completed",
                            actor_code=actor_code,
                            subject_code="partner_release",
                            reason_code="signed_candidate_verified",
                        )
                        response = {
                            "aggregate": aggregate_result,
                            "approval": approval_result,
                            "candidate": candidate_result,
                            "report": report_result,
                        }
                    elif parsed.path == "/approve-publication":
                        sync_pipeline_sources()
                        if not access_policy.authorize_release_owner(self.headers):
                            raise PermissionError(
                                "authenticated release-owner role is required",
                            )
                        from community_os.controlled_release import (
                            _replace_controlled_release_bundle,
                            issue_current_publication_approval,
                        )

                        append_operator_access_audit(
                            state.root,
                            action="publication_approval_requested",
                            actor_code=actor_code,
                            subject_code="partner_share",
                            reason_code="authenticated_owner_requested",
                        )
                        if (
                            approval_bundle_path.is_symlink()
                            or not approval_bundle_path.is_file()
                        ):
                            raise PermissionError(
                                "controlled release approval bundle is unsafe",
                            )
                        original_approval_bundle = approval_bundle_path.read_bytes()
                        approval_result = issue_current_publication_approval(
                            state.root / "protected" / "release",
                            state=state,
                            actor_code=actor_code,
                            approval_bundle=approval_bundle_path,
                            now=datetime.now(UTC),
                            semantic_approval_secret=pseudonym_secret,
                        )
                        try:
                            sync_pipeline_sources()
                            operation = operations.get("publish")
                            if operation is None:
                                raise PermissionError(
                                    "publication operation is not configured",
                                )
                            if pipeline.state.stage("publish").status is StageStatus.COMPLETE:
                                pipeline.state.invalidate(("publish", "analytics"))
                            publication_result = pipeline.run(
                                "publish", operation,
                            )
                        except BaseException:
                            _replace_controlled_release_bundle(
                                approval_bundle_path,
                                original_approval_bundle,
                            )
                            pipeline.state.invalidate(("publish", "analytics"))
                            pipeline.write_manifest()
                            raise
                        pipeline.write_manifest()
                        append_operator_access_audit(
                            state.root,
                            action="publication_approval_completed",
                            actor_code=actor_code,
                            subject_code="partner_share",
                            reason_code="exact_hash_bundle_staged",
                        )
                        response = {
                            "approval": approval_result,
                            "publication": publication_result,
                        }
                    elif parsed.path == "/prepare-analytics":
                        if not access_policy.authorize_release_owner(self.headers):
                            raise PermissionError(
                                "authenticated release-owner role is required",
                            )
                        if not _verified_public_staging(state):
                            raise PermissionError(
                                "exact analytics-free partner staging is required",
                            )
                        request = json.loads(body)
                        public_key = request.get("public_key")
                        if not isinstance(public_key, str):
                            raise ValueError("PostHog public project key is required")
                        personal_api_key = os.environ.get("POSTHOG_PERSONAL_API_KEY")
                        if not isinstance(personal_api_key, str) or not personal_api_key:
                            raise ValueError(
                                "POSTHOG_PERSONAL_API_KEY is required for live privacy verification",
                            )
                        project_id_value = os.environ.get("POSTHOG_PROJECT_ID")
                        try:
                            project_id = int(project_id_value or "")
                        except ValueError as error:
                            raise ValueError(
                                "POSTHOG_PROJECT_ID must be a positive integer",
                            ) from error
                        if project_id < 1:
                            raise ValueError("POSTHOG_PROJECT_ID must be a positive integer")
                        from community_os.postpublication_analytics import (
                            AnalyticsActivationApproval,
                            prepare_analytics_publication_bundle,
                            verify_posthog_project_privacy,
                        )

                        source = state.root / "public-staging"
                        source_index = source / "index.html"
                        source_manifest = source / "publication-manifest.json"
                        requested_at = datetime.now(UTC)
                        privacy_verification = verify_posthog_project_privacy(
                            personal_api_key=personal_api_key,
                            project_id=project_id,
                            public_key=public_key,
                            now=requested_at,
                            artifact_path=(
                                state.root / "protected"
                                / "posthog-project-privacy.json"
                            ),
                        )
                        approval = AnalyticsActivationApproval(
                            approval_code="approval_" + secrets.token_hex(8),
                            actor_code="actor_" + hashlib.sha256(
                                actor_code.encode("ascii"),
                            ).hexdigest()[:16],
                            scope="privacy_limited_posthog",
                            report_sha256=hashlib.sha256(
                                source_index.read_bytes(),
                            ).hexdigest(),
                            publication_manifest_sha256=hashlib.sha256(
                                source_manifest.read_bytes(),
                            ).hexdigest(),
                            posthog_privacy_receipt_sha256=(
                                privacy_verification.sha256
                            ),
                            approved_at=requested_at,
                            expires_at=requested_at + timedelta(minutes=15),
                        )
                        append_operator_access_audit(
                            state.root,
                            action="analytics_publication_requested",
                            actor_code=actor_code,
                            subject_code="partner_share",
                            reason_code="privacy_limited_posthog_requested",
                        )

                        def prepare_analytics() -> Sequence[Mapping[str, object]]:
                            final_manifest = prepare_analytics_publication_bundle(
                                source_directory=source,
                                destination=state.root / "deployment-staging",
                                approval=approval,
                                public_key=public_key,
                                posthog_host="https://eu.i.posthog.com",
                                personal_api_key=personal_api_key,
                                posthog_project_id=project_id,
                                now=requested_at,
                                artifact_path=(
                                    state.root / "protected"
                                    / "analytics-publication.json"
                                ),
                                posthog_privacy_artifact_path=(
                                    state.root / "protected"
                                    / "posthog-project-privacy.json"
                                ),
                            )
                            manifest_path = (
                                state.root / "deployment-staging"
                                / "publication-manifest.json"
                            )
                            return (_analytics_publication_record(
                                manifest_path.parent,
                                final_manifest,
                            ),)

                        if pipeline.state.stage("analytics").status is StageStatus.COMPLETE:
                            pipeline.state.invalidate(("analytics",))
                        try:
                            response = pipeline.run("analytics", prepare_analytics)
                        finally:
                            pipeline.write_manifest()
                        append_operator_access_audit(
                            state.root,
                            action="analytics_publication_completed",
                            actor_code=actor_code,
                            subject_code="partner_share",
                            reason_code="local_bundle_prepared",
                        )
                    elif parsed.path == "/partner-presentation":
                        request = json.loads(body)
                        append_operator_access_audit(
                            state.root,
                            action="partner_presentation_edit_requested",
                            actor_code=actor_code,
                            subject_code="partner_presentation",
                            reason_code="operator_requested",
                        )
                        response = persist_partner_presentation_edits(
                            state, request,
                        )
                    elif parsed.path == "/correction":
                        request = json.loads(body)
                        field = str(request["field"])
                        append_operator_access_audit(
                            state.root, action="source_value_review_requested", actor_code=actor_code,
                            subject_code=field, reason_code="operator_requested",
                        )
                        state.record_reviewed_value(
                            field,
                            source_value=request["source_value"],
                            reviewed_value=request["reviewed_value"],
                            reason_code=str(request["reason_code"]),
                        )
                        response = {"ok": True}
                    elif parsed.path == "/identity-review":
                        request = json.loads(body)
                        case_code = str(request["case"])
                        append_operator_access_audit(state.root, action="review_requested", actor_code=actor_code, subject_code=case_code, reason_code="operator_requested")
                        state.decide_identity(case_code, str(request["case_hash"]), str(request["decision"]), selected_code=request.get("selected_code")); response = {"ok": True}
                    elif parsed.path == "/team-review":
                        request = json.loads(body)
                        case_code = str(request["case"])
                        append_operator_access_audit(state.root, action="review_requested", actor_code=actor_code, subject_code=case_code, reason_code="operator_requested")
                        state.decide_team(case_code, str(request["case_hash"]), str(request["selected_code"])); response = {"ok": True}
                    elif parsed.path == "/classification-review":
                        request = json.loads(body)
                        case_code = str(request["case"])
                        append_operator_access_audit(state.root, action="review_requested", actor_code=actor_code, subject_code=case_code, reason_code="operator_requested")
                        state.review_classification(case_code, str(request["case_hash"]), str(request["decision"]), corrected_output=request.get("corrected_output")); response = {"ok": True}
                    elif parsed.path == "/standout-evidence":
                        request = json.loads(body)
                        case_code = str(request["case"])
                        append_operator_access_audit(
                            state.root,
                            action="standout_evidence_requested",
                            actor_code=actor_code,
                            subject_code=case_code,
                            reason_code="operator_requested",
                        )
                        state.record_standout_evidence(
                            case_code,
                            str(request["case_hash"]),
                            str(request["rationale"]),
                        )
                        response = {"ok": True}
                    else:
                        self._reply(404, b'{"error":"not_found"}')
                        return
                self._reply(200, json.dumps(response, separators=(",", ":")).encode())
            except (ValueError, KeyError, TypeError, PermissionError, json.JSONDecodeError) as error:
                self._reply(400, json.dumps({"error": str(error)}, separators=(",", ":")).encode())

        def log_message(self, format: str, *args: object) -> None:
            print(f"release_operator {self.command} {urlparse(self.path).path}")

    if host not in {"127.0.0.1", "0.0.0.0"}:
        raise ValueError("operator host must be loopback or all interfaces behind the authenticated proxy")
    server = ThreadingHTTPServer((host, port), Handler)
    url = f"http://127.0.0.1:{server.server_port}/"
    print(url, flush=True)
    if open_browser:
        webbrowser.open(url)
    try:
        server.serve_forever()
    finally:
        server.server_close()
