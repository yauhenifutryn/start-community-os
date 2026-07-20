"""Approval-gated protected storage for internal GitHub semantic evaluation."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import tempfile
from typing import Callable, Mapping

from community_os.enrichment.github_assessment import (
    ASSESSMENT_CATEGORIES,
    ASSESSMENT_FIELDS,
    GitHubProjectAssessor,
    MODEL,
    PROJECT_FIELDS,
    PROMPT_VERSION,
    validate_assessment,
)


_HASH = re.compile(r"^[0-9a-f]{64}$")
_PID = re.compile(r"^pid:v1:[0-9a-f]{64}$")
_EVIDENCE = re.compile(r"^evidence:github:[0-9a-f]{64}$")
_TECHNOLOGY_CODES = frozenset({
    "systems", "dotnet", "web_frontend", "dart", "go", "jvm",
    "javascript_typescript", "data_notebook", "php", "python", "ruby",
    "rust", "shell", "swift",
})
_APPROVAL_KEYS = {
    "approval_id", "approved_at", "approved_by", "assessment_fields",
    "cache_identity", "candidate_set_sha256", "canary_size", "distribution",
    "evaluation_version", "expires_at", "github_authorization_sha256",
    "max_provider_attempts", "model", "processing_region",
    "project_vector_fields", "prompt_version", "reasoning_effort",
    "retention_days", "retention_mode", "source_file_sha256", "source_scope",
    "store",
}


def _timestamp(value: object, field: str) -> datetime:
    if not isinstance(value, str):
        raise PermissionError(f"GitHub semantic evaluation {field} is invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise PermissionError(f"GitHub semantic evaluation {field} is invalid") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise PermissionError(f"GitHub semantic evaluation {field} requires a timezone")
    return parsed


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _utc_timestamp(value: datetime) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("GitHub semantic evaluation timestamp requires a timezone")
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


@dataclass(frozen=True)
class GitHubSemanticEvaluationApproval:
    evaluation_version: str
    distribution: str
    source_scope: str
    model: str
    prompt_version: str
    cache_identity: str
    project_vector_fields: list[str]
    assessment_fields: list[str]
    processing_region: str
    retention_mode: str
    store: bool
    reasoning_effort: str
    source_file_sha256: str
    candidate_set_sha256: str
    github_authorization_sha256: str
    approved_by: str
    approval_id: str
    approved_at: str
    expires_at: str
    retention_days: int
    canary_size: int
    max_provider_attempts: int

    @classmethod
    def from_record(cls, value: object) -> "GitHubSemanticEvaluationApproval":
        if not isinstance(value, dict) or set(value) != _APPROVAL_KEYS:
            raise PermissionError("GitHub semantic evaluation approval keys are invalid")
        try:
            return cls(**value)
        except TypeError as error:
            raise PermissionError("GitHub semantic evaluation approval is invalid") from error

    @classmethod
    def load(
        cls, path: str | Path, *, now: datetime,
    ) -> tuple["GitHubSemanticEvaluationApproval", str]:
        approval_path = Path(path)
        if not approval_path.is_file():
            raise PermissionError("GitHub semantic evaluation requires a pre-existing approval")
        try:
            value = json.loads(approval_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise PermissionError("GitHub semantic evaluation approval is unreadable") from error
        approval = cls.from_record(value)
        return approval, approval.authorization_hash(now=now)

    def to_record(self) -> dict[str, object]:
        return {key: getattr(self, key) for key in sorted(_APPROVAL_KEYS)}

    def authorize(self, *, now: datetime) -> None:
        if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
            raise PermissionError("GitHub semantic evaluation authorization time requires a timezone")
        required = {
            "evaluation_version": "github-semantic-evaluation-v1",
            "distribution": "internal_only_pending_human_review",
            "source_scope": "applicant_supplied_public_github",
            "model": MODEL,
            "prompt_version": PROMPT_VERSION,
            "cache_identity": GitHubProjectAssessor.cache_identity,
            "processing_region": "global",
            "retention_mode": "default_abuse_monitoring_30d",
            "store": False,
            "reasoning_effort": "none",
            "approved_by": "release_owner",
        }
        if any(getattr(self, key) != expected for key, expected in required.items()):
            raise PermissionError("GitHub semantic evaluation approval scope is invalid")
        if (
            type(self.project_vector_fields) is not list
            or self.project_vector_fields != sorted(PROJECT_FIELDS)
            or type(self.assessment_fields) is not list
            or self.assessment_fields != sorted(ASSESSMENT_FIELDS)
            or any(
                not isinstance(value, str) or not _HASH.fullmatch(value)
                for value in (
                    self.source_file_sha256, self.candidate_set_sha256,
                    self.github_authorization_sha256,
                )
            )
            or not isinstance(self.approval_id, str)
            or not self.approval_id.strip()
            or type(self.retention_days) is not int
            or not 1 <= self.retention_days <= 7
            or type(self.canary_size) is not int
            or self.canary_size != 5
            or type(self.max_provider_attempts) is not int
            or not 1 <= self.max_provider_attempts <= 597
        ):
            raise PermissionError("GitHub semantic evaluation approval values are invalid")
        approved = _timestamp(self.approved_at, "approval timestamp")
        expires = _timestamp(self.expires_at, "expiry")
        if approved > now or now >= expires or expires <= approved or expires - approved > timedelta(days=7):
            raise PermissionError("GitHub semantic evaluation approval is not currently valid")

    def authorization_hash(self, *, now: datetime) -> str:
        self.authorize(now=now)
        return hashlib.sha256(_canonical(self.to_record())).hexdigest()


class GitHubSemanticEvaluationStore:
    """Isolated, approval-bound results that cannot enter release storage."""

    RECORD_VERSION = "github-semantic-evaluation-result-v1"
    CANARY_VERSION = "github-semantic-evaluation-canary-v1"
    ATTEMPT_VERSION = "github-semantic-evaluation-provider-attempt-v1"
    CLEANUP_VERSION = "github-semantic-evaluation-cleanup-v1"
    _RECORD_KEYS = {
        "approval_sha256", "created_at", "expires_at", "github_result",
        "record_version", "subject_ref", "updated_at",
    }
    _OBSERVED_KEYS = {
        "account_age_days", "evidence_ref", "forks_received",
        "last_public_update", "owned_public_repos_sampled",
        "project_assessment", "public_repos", "recently_active_repos", "state",
        "stars_received", "technology_codes",
    }
    _UNKNOWN_KEYS = {"reason_code", "state"}
    _CANARY_KEYS = {
        "approval_sha256", "canary_file_names", "canary_records_sha256",
        "expires_at", "quality_decision", "receipt_version", "record_count",
        "recorded_at", "reviewed_by",
    }
    _ATTEMPT_KEYS = {
        "approval_sha256", "attempt_number", "attempt_version", "expires_at",
        "started_at",
    }

    def __init__(
        self, root: str | Path, *, release_root: str | Path,
        approval_path: str | Path, clock: Callable[[], datetime],
        source_file_sha256: str, candidate_set_sha256: str,
        github_authorization_sha256: str,
    ) -> None:
        self.root = Path(root).resolve()
        self.release_root = Path(release_root).resolve()
        self.approval_path = Path(approval_path).resolve()
        if self.root.name != "github-semantic-evaluation":
            raise ValueError("GitHub semantic evaluation requires its dedicated storage root")
        if (
            self.root == self.release_root
            or _is_relative_to(self.root, self.release_root)
            or _is_relative_to(self.release_root, self.root)
        ):
            raise ValueError("GitHub semantic evaluation storage must be isolated from release storage")
        if not _is_relative_to(self.approval_path, self.root):
            raise ValueError("GitHub semantic evaluation approval must be inside its protected root")
        self.clock = clock
        self.approval, self.approval_sha256 = GitHubSemanticEvaluationApproval.load(
            self.approval_path, now=self.clock(),
        )
        actual_bindings = {
            "source_file_sha256": source_file_sha256,
            "candidate_set_sha256": candidate_set_sha256,
            "github_authorization_sha256": github_authorization_sha256,
        }
        if any(
            not isinstance(value, str)
            or not _HASH.fullmatch(value)
            or not hmac.compare_digest(value, str(getattr(self.approval, key)))
            for key, value in actual_bindings.items()
        ):
            raise PermissionError("GitHub semantic evaluation approval does not match run inputs")
        self.results = self.root / "results"
        self.attempts = self.root / "provider-attempts"
        self.cache_root = self.root / "cache"
        for directory in (self.root, self.results, self.attempts, self.cache_root):
            directory.mkdir(parents=True, exist_ok=True, mode=0o700)
            directory.chmod(0o700)
        self.approval_path.chmod(0o600)
        self.cleanup_expired()

    def _current_approval(self) -> GitHubSemanticEvaluationApproval:
        approval, approval_sha256 = GitHubSemanticEvaluationApproval.load(
            self.approval_path, now=self.clock(),
        )
        if not hmac.compare_digest(approval_sha256, self.approval_sha256):
            raise PermissionError("GitHub semantic evaluation approval changed after initialization")
        return approval

    @staticmethod
    def _write(path: Path, value: Mapping[str, object]) -> None:
        payload = _canonical(value) + b"\n"
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=path.name + ".", suffix=".tmp", dir=path.parent,
        )
        temporary = Path(temporary_name)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb", closefd=True) as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            temporary.replace(path)
            path.chmod(0o600)
        except BaseException:
            try:
                os.close(descriptor)
            except OSError:
                pass
            temporary.unlink(missing_ok=True)
            raise

    @staticmethod
    def _record_name(subject_ref: str) -> str:
        if not isinstance(subject_ref, str) or not _PID.fullmatch(subject_ref):
            raise ValueError("GitHub semantic evaluation subject must be pseudonymous")
        return hashlib.sha256(subject_ref.encode("utf-8")).hexdigest() + ".json"

    @classmethod
    def _validate_github_result(cls, value: object) -> dict[str, object]:
        if not isinstance(value, dict):
            raise ValueError("GitHub semantic evaluation result must be an object")
        if set(value) == cls._UNKNOWN_KEYS:
            if value != {"reason_code": "profile_not_found", "state": "unknown"}:
                raise ValueError("GitHub semantic evaluation unknown state is invalid")
            return dict(value)
        if set(value) != cls._OBSERVED_KEYS or value.get("state") != "observed":
            raise ValueError("GitHub semantic evaluation result fields are invalid")
        integer_fields = (
            "account_age_days", "forks_received", "owned_public_repos_sampled",
            "public_repos", "recently_active_repos", "stars_received",
        )
        if any(type(value.get(key)) is not int or value[key] < 0 for key in integer_fields):
            raise ValueError("GitHub semantic evaluation numeric signal is invalid")
        if value["recently_active_repos"] > value["owned_public_repos_sampled"]:
            raise ValueError("GitHub semantic evaluation repository counts are inconsistent")
        if not _EVIDENCE.fullmatch(str(value.get("evidence_ref") or "")):
            raise ValueError("GitHub semantic evaluation evidence reference is invalid")
        try:
            if date.fromisoformat(str(value["last_public_update"])) > date.max:
                raise ValueError
        except (TypeError, ValueError) as error:
            raise ValueError("GitHub semantic evaluation update date is invalid") from error
        technologies = value.get("technology_codes")
        if (
            not isinstance(technologies, list)
            or technologies != sorted(set(technologies))
            or any(code not in _TECHNOLOGY_CODES for code in technologies)
        ):
            raise ValueError("GitHub semantic evaluation technology codes are invalid")
        assessment = validate_assessment(value.get("project_assessment"))
        if assessment["review_state"] != "human_review_required":
            raise ValueError("GitHub semantic evaluation must remain human-review gated")
        normalized = dict(value)
        normalized["project_assessment"] = assessment
        return normalized

    def _validate_record(
        self, value: object, *, expected_subject: str | None = None,
    ) -> dict[str, object]:
        if not isinstance(value, dict) or set(value) != self._RECORD_KEYS:
            raise PermissionError("GitHub semantic evaluation record fields are invalid")
        subject = value.get("subject_ref")
        if (
            not isinstance(subject, str)
            or not _PID.fullmatch(subject)
            or (expected_subject is not None and subject != expected_subject)
            or value.get("record_version") != self.RECORD_VERSION
            or value.get("approval_sha256") != self.approval_sha256
        ):
            raise PermissionError("GitHub semantic evaluation record binding is invalid")
        created = _timestamp(value.get("created_at"), "record creation")
        updated = _timestamp(value.get("updated_at"), "record update")
        expires = _timestamp(value.get("expires_at"), "record expiry")
        expected_expiry = min(
            created + timedelta(days=self.approval.retention_days),
            _timestamp(self.approval.expires_at, "approval expiry"),
        )
        if (
            updated < created or updated > expires or expires != expected_expiry
            or expires <= created
        ):
            raise PermissionError("GitHub semantic evaluation record timestamps are invalid")
        try:
            self._validate_github_result(value.get("github_result"))
        except ValueError as error:
            raise PermissionError("GitHub semantic evaluation record projection is invalid") from error
        return dict(value)

    def get(self, subject_ref: str) -> dict[str, object] | None:
        self._current_approval()
        path = self.results / self._record_name(subject_ref)
        if not path.exists():
            return None
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
            record = self._validate_record(value, expected_subject=subject_ref)
            expires = _timestamp(record["expires_at"], "record expiry")
        except (OSError, json.JSONDecodeError, PermissionError) as error:
            raise PermissionError("GitHub semantic evaluation record is unreadable") from error
        if expires <= self.clock():
            self.cleanup_expired()
            return None
        return record

    def put(
        self, *, subject_ref: str, github_result: Mapping[str, object],
    ) -> dict[str, object]:
        approval = self._current_approval()
        normalized_result = self._validate_github_result(dict(github_result))
        path = self.results / self._record_name(subject_ref)
        current_files = sorted(self.results.glob("*.json"))
        if not path.exists() and len(current_files) >= approval.canary_size:
            self._require_canary_receipt()
        now = self.clock()
        created = now
        expiry = min(
            now + timedelta(days=approval.retention_days),
            _timestamp(approval.expires_at, "approval expiry"),
        )
        if path.exists():
            try:
                existing = self._validate_record(
                    json.loads(path.read_text(encoding="utf-8")),
                    expected_subject=subject_ref,
                )
            except (OSError, json.JSONDecodeError, PermissionError) as error:
                raise PermissionError("GitHub semantic evaluation record is unreadable") from error
            created = _timestamp(existing["created_at"], "record creation")
            expiry = _timestamp(existing["expires_at"], "record expiry")
            if expiry <= now:
                self.cleanup_expired()
                raise PermissionError("GitHub semantic evaluation record expired and was deleted")
        record = {
            "approval_sha256": self.approval_sha256,
            "created_at": _utc_timestamp(created),
            "expires_at": _utc_timestamp(expiry),
            "github_result": normalized_result,
            "record_version": self.RECORD_VERSION,
            "subject_ref": subject_ref,
            "updated_at": _utc_timestamp(now),
        }
        self._validate_record(record, expected_subject=subject_ref)
        self._write(path, record)
        return record

    @staticmethod
    def _canary_digest(paths: list[Path]) -> str:
        entries = [hashlib.sha256(path.read_bytes()).hexdigest() for path in paths]
        return hashlib.sha256("\n".join(entries).encode("ascii")).hexdigest()

    def write_canary_receipt(
        self, *, reviewed_by: str, quality_decision: str,
    ) -> dict[str, object]:
        approval = self._current_approval()
        if reviewed_by != "codex_proof_for_me" or quality_decision != "accepted":
            raise PermissionError("GitHub semantic evaluation canary review is invalid")
        paths = sorted(self.results.glob("*.json"))
        if len(paths) != approval.canary_size:
            raise PermissionError("GitHub semantic evaluation canary must contain exactly five records")
        for path in paths:
            try:
                self._validate_record(json.loads(path.read_text(encoding="utf-8")))
            except (OSError, json.JSONDecodeError, PermissionError) as error:
                raise PermissionError("GitHub semantic evaluation canary record is unreadable") from error
        now = self.clock()
        receipt = {
            "approval_sha256": self.approval_sha256,
            "canary_file_names": [path.name for path in paths],
            "canary_records_sha256": self._canary_digest(paths),
            "expires_at": approval.expires_at,
            "quality_decision": quality_decision,
            "receipt_version": self.CANARY_VERSION,
            "record_count": approval.canary_size,
            "recorded_at": _utc_timestamp(now),
            "reviewed_by": reviewed_by,
        }
        self._write(self.root / "canary-receipt.json", receipt)
        return receipt

    def _require_canary_receipt(self) -> None:
        path = self.root / "canary-receipt.json"
        try:
            receipt = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise PermissionError("GitHub semantic evaluation expansion requires a canary receipt") from error
        names = receipt.get("canary_file_names") if isinstance(receipt, dict) else None
        if (
            set(receipt) != self._CANARY_KEYS
            or receipt.get("receipt_version") != self.CANARY_VERSION
            or receipt.get("approval_sha256") != self.approval_sha256
            or receipt.get("record_count") != 5
            or receipt.get("reviewed_by") != "codex_proof_for_me"
            or receipt.get("quality_decision") != "accepted"
            or not isinstance(names, list)
            or len(names) != 5
            or len(set(names)) != 5
            or any(not re.fullmatch(r"[0-9a-f]{64}\.json", str(name)) for name in names)
        ):
            raise PermissionError("GitHub semantic evaluation canary receipt is invalid")
        recorded = _timestamp(receipt.get("recorded_at"), "canary receipt")
        expires = _timestamp(receipt.get("expires_at"), "canary expiry")
        if recorded > self.clock() or expires <= self.clock():
            raise PermissionError("GitHub semantic evaluation canary receipt expired")
        canary_paths = [self.results / str(name) for name in names]
        if any(not item.is_file() for item in canary_paths):
            raise PermissionError("GitHub semantic evaluation canary records changed")
        if not hmac.compare_digest(
            str(receipt.get("canary_records_sha256") or ""),
            self._canary_digest(canary_paths),
        ):
            raise PermissionError("GitHub semantic evaluation canary records changed")

    def assert_expansion_allowed(self) -> None:
        """Fail before provider transport unless the accepted canary is current."""
        self._current_approval()
        self._require_canary_receipt()

    def _validated_attempt_paths(self) -> list[Path]:
        paths = sorted(self.attempts.glob("*.json"))
        for index, path in enumerate(paths, start=1):
            if path.name != f"{index:06d}.json":
                raise PermissionError("GitHub semantic evaluation attempt ledger is discontinuous")
            try:
                value = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as error:
                raise PermissionError("GitHub semantic evaluation attempt ledger is unreadable") from error
            if (
                not isinstance(value, dict)
                or set(value) != self._ATTEMPT_KEYS
                or value.get("attempt_version") != self.ATTEMPT_VERSION
                or value.get("approval_sha256") != self.approval_sha256
                or value.get("attempt_number") != index
            ):
                raise PermissionError("GitHub semantic evaluation attempt ledger is invalid")
            started = _timestamp(value.get("started_at"), "attempt start")
            expires = _timestamp(value.get("expires_at"), "attempt expiry")
            if expires != _timestamp(self.approval.expires_at, "approval expiry") or started >= expires:
                raise PermissionError("GitHub semantic evaluation attempt timestamps are invalid")
        return paths

    def begin_provider_attempt(self) -> int:
        approval = self._current_approval()
        while True:
            paths = self._validated_attempt_paths()
            if len(paths) >= approval.max_provider_attempts:
                raise PermissionError("GitHub semantic evaluation provider attempt ceiling reached")
            number = len(paths) + 1
            path = self.attempts / f"{number:06d}.json"
            now = self.clock()
            value = {
                "approval_sha256": self.approval_sha256,
                "attempt_number": number,
                "attempt_version": self.ATTEMPT_VERSION,
                # The attempt contains no participant data and must survive for
                # the full approval window so cleanup cannot reset the ceiling.
                "expires_at": _utc_timestamp(
                    _timestamp(approval.expires_at, "approval expiry"),
                ),
                "started_at": _utc_timestamp(now),
            }
            try:
                descriptor = os.open(
                    path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600,
                )
            except FileExistsError:
                continue
            try:
                payload = _canonical(value) + b"\n"
                written = 0
                while written < len(payload):
                    count = os.write(descriptor, payload[written:])
                    if count <= 0:
                        raise OSError("GitHub semantic evaluation attempt write was incomplete")
                    written += count
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            path.chmod(0o600)
            return number

    def cleanup_expired(self) -> dict[str, object]:
        now = self.clock()
        deleted: list[str] = []
        for directory in (self.root, self.results, self.attempts):
            for temporary in directory.glob("*.tmp"):
                deleted.append(str(temporary.relative_to(self.root)))
                temporary.unlink(missing_ok=True)
        cache_root = self.cache_root
        if cache_root.exists():
            for temporary in cache_root.rglob("*.tmp"):
                deleted.append(str(temporary.relative_to(self.root)))
                temporary.unlink(missing_ok=True)
        candidates = list(self.results.glob("*.json")) + list(self.attempts.glob("*.json"))
        if cache_root.exists():
            candidates.extend(cache_root.rglob("*.json"))
        canary = self.root / "canary-receipt.json"
        if canary.exists():
            candidates.append(canary)
        for path in candidates:
            remove = False
            try:
                value = json.loads(path.read_text(encoding="utf-8"))
                expiry = _timestamp(value.get("expires_at"), "cleanup expiry")
                remove = expiry <= now
            except (OSError, AttributeError, json.JSONDecodeError, PermissionError) as error:
                if _is_relative_to(path, self.attempts):
                    # A malformed attempt is still a consumed attempt. Deleting it
                    # would reduce the durable cost count and reopen the budget.
                    raise PermissionError(
                        "GitHub semantic evaluation attempt ledger is unreadable"
                    ) from error
                remove = True
            if remove:
                deleted.append(str(path.relative_to(self.root)))
                path.unlink(missing_ok=True)
        receipt = {
            "cleanup_version": self.CLEANUP_VERSION,
            "deleted_assets_sha256": hashlib.sha256(
                "\n".join(sorted(deleted)).encode("utf-8"),
            ).hexdigest(),
            "deleted_at": _utc_timestamp(now),
            "deleted_count": len(deleted),
        }
        self._write(self.root / "cleanup-receipt.json", receipt)
        return receipt


def cleanup_expired_github_evaluation(
    root: str | Path, *, release_root: str | Path, now: datetime,
) -> dict[str, object]:
    """Delete an expired evaluation without requiring a currently valid approval."""
    target = Path(root).resolve()
    release = Path(release_root).resolve()
    if target.name != "github-semantic-evaluation" or (
        target == release
        or _is_relative_to(target, release)
        or _is_relative_to(release, target)
    ):
        raise ValueError("GitHub semantic evaluation cleanup root is invalid")
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("GitHub semantic evaluation cleanup time requires a timezone")
    approval_path = target / "approval.json"
    approval_unreadable = False
    try:
        value = json.loads(approval_path.read_text(encoding="utf-8"))
        approval = GitHubSemanticEvaluationApproval.from_record(value)
        approval.authorize(now=now)
        expiry = _timestamp(approval.expires_at, "approval expiry")
    except (OSError, json.JSONDecodeError, PermissionError):
        # Retention cleanup is allowed to destroy data, never to authorize use.
        # If the controlling approval is unreadable, delete the scoped evaluation
        # data fail-safe rather than allowing corruption to extend retention.
        approval_unreadable = True
        expiry = now
    deleted: list[str] = []
    if approval_unreadable or expiry <= now:
        preserved = {approval_path.resolve(), (target / "cleanup-receipt.json").resolve()}
        for path in sorted(target.rglob("*")):
            if not path.is_file() or path.resolve() in preserved:
                continue
            deleted.append(str(path.relative_to(target)))
            path.unlink(missing_ok=True)
    receipt = {
        "cleanup_version": GitHubSemanticEvaluationStore.CLEANUP_VERSION,
        "deleted_assets_sha256": hashlib.sha256(
            "\n".join(sorted(deleted)).encode("utf-8"),
        ).hexdigest(),
        "deleted_at": _utc_timestamp(now),
        "deleted_count": len(deleted),
    }
    target.mkdir(parents=True, exist_ok=True, mode=0o700)
    target.chmod(0o700)
    GitHubSemanticEvaluationStore._write(target / "cleanup-receipt.json", receipt)
    return receipt


def _aggregate_cell(value: int, *, withheld: bool = False) -> dict[str, object]:
    if withheld:
        return {
            "privacy": "withheld",
            "reason": "complement_below_minimum_group_size",
            "value": None,
        }
    return {"privacy": "published", "reason": None, "value": value}


def _protected_partition(
    values: Mapping[str, int], *, minimum_group_size: int,
) -> dict[str, dict[str, object]]:
    withheld = any(0 < value < minimum_group_size for value in values.values())
    return {
        key: _aggregate_cell(value, withheld=withheld)
        for key, value in values.items()
    }


def build_internal_github_aggregate(
    records: list[Mapping[str, object]], *, minimum_group_size: int = 5,
) -> dict[str, object]:
    """Aggregate pending structural assessments without making release facts."""
    if type(minimum_group_size) is not int or minimum_group_size < 5:
        raise ValueError("GitHub aggregate minimum group size must be at least five")
    evidence = {"insufficient": 0, "limited": 0, "moderate_or_strong": 0}
    maintenance = {"unknown": 0, "inactive": 0, "active_or_sustained": 0}
    external = {"none": 0, "limited": 0, "moderate_or_strong": 0}
    productization = {"none": 0, "limited": 0, "moderate_or_strong": 0}
    confidence = {"low": 0, "medium_or_high": 0}
    categories = {key: 0 for key in sorted(ASSESSMENT_CATEGORIES)}
    observed = 0
    unknown = 0
    for record in records:
        if not isinstance(record, Mapping) or "subject_ref" not in record:
            raise ValueError("GitHub aggregate input is invalid")
        result = GitHubSemanticEvaluationStore._validate_github_result(
            record.get("github_result"),
        )
        if result["state"] == "unknown":
            unknown += 1
            continue
        observed += 1
        assessment = result["project_assessment"]
        assert isinstance(assessment, dict)
        strength = str(assessment["evidence_strength"])
        evidence[
            strength if strength in {"insufficient", "limited"} else "moderate_or_strong"
        ] += 1
        maintenance_value = str(assessment["maintenance"])
        maintenance[
            maintenance_value if maintenance_value in {"unknown", "inactive"}
            else "active_or_sustained"
        ] += 1
        for source_key, target in (
            ("external_validation", external),
            ("productization", productization),
        ):
            value = str(assessment[source_key])
            target[value if value in {"none", "limited"} else "moderate_or_strong"] += 1
        confidence_value = str(assessment["confidence_state"])
        confidence["low" if confidence_value == "low" else "medium_or_high"] += 1
        for category in assessment["categories"]:
            categories[str(category)] += 1
    return {
        "aggregate_version": "github-semantic-internal-aggregate-v1",
        "distribution": "internal_only_pending_human_review",
        "minimum_group_size": minimum_group_size,
        "release_eligible": False,
        "population": {
            "attempted": len(records), "observed": observed,
            "pending_human_review": len(records), "unknown": unknown,
        },
        "dimensions": {
            "evidence_strength": _protected_partition(
                evidence, minimum_group_size=minimum_group_size,
            ),
            "maintenance": _protected_partition(
                maintenance, minimum_group_size=minimum_group_size,
            ),
            "external_validation": _protected_partition(
                external, minimum_group_size=minimum_group_size,
            ),
            "productization": _protected_partition(
                productization, minimum_group_size=minimum_group_size,
            ),
            "confidence": _protected_partition(
                confidence, minimum_group_size=minimum_group_size,
            ),
            "categories": {
                key: _aggregate_cell(value, withheld=0 < value < minimum_group_size)
                for key, value in categories.items()
            },
        },
    }


class GitHubSemanticEvaluationTransport:
    """Reserve a durable approved attempt immediately before each OpenAI request."""

    def __init__(self, *, store: GitHubSemanticEvaluationStore, transport: object) -> None:
        if not callable(getattr(transport, "request", None)):
            raise ValueError("GitHub semantic evaluation transport must expose request")
        self.store = store
        self.transport = transport

    def request(
        self, *, headers: dict[str, str], body: bytes, timeout: float,
        max_bytes: int,
    ) -> object:
        self.store.begin_provider_attempt()
        return getattr(self.transport, "request")(
            headers=headers, body=body, timeout=timeout, max_bytes=max_bytes,
        )
