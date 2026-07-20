"""Isolated, career-only Coresignal evaluation with fail-closed receipts."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
import hashlib
import hmac
from itertools import islice
import json
from pathlib import Path
import re
from urllib.parse import quote, urlencode

from community_os.coresignal_evaluation import (
    EvaluationCandidate,
    preview_evaluation_plan,
)
from community_os.enrichment.coresignal import (
    _CORESIGNAL_ENDPOINT,
    _CORESIGNAL_FIELDS,
    _profile_shorthand,
)
from community_os.enrichment.coresignal_career_evidence import (
    CAREER_FIELDS,
    build_career_evidence,
)
from community_os.enrichment.semantic_evidence import (
    assert_no_known_identity_literals,
    assert_safe_semantic_payload,
    sanitize_professional_text,
)
from community_os.enrichment.transport import Transport


_HASH = re.compile(r"^[0-9a-f]{64}$")
_PID = re.compile(r"^pid:v1:[0-9a-f]{64}$")
_PRIORITIES = ("checked_in", "accepted_not_checked_in", "other")
_FIELDS = tuple(_CORESIGNAL_FIELDS)
_ACTIVE_STATES = frozenset({"current", "historic", "unknown"})
_DURATION_BANDS = frozenset({
    "under_one_year", "one_to_three_years", "over_three_years", "unknown",
})
_SENIORITY_CONTEXTS = frozenset({
    "founder_executive", "leadership", "senior", "early_career",
    "individual_contributor", "unknown",
})
_INDUSTRY_CODES = frozenset({
    "software", "finance", "education", "health", "research", "consulting",
    "manufacturing", "other", "unknown",
})
_ORGANIZATION_SIZE_BANDS = frozenset({
    "solo", "small", "medium", "large", "enterprise", "unknown",
})
_APPROVAL_KEYS = {
    "approval_id", "approved_at", "approved_by", "distribution",
    "evaluation_version", "exclusions_sha256", "expires_at", "fields",
    "notice_status", "priority_order", "projection_version",
    "provider_access_verified", "provider_terms_version", "purpose",
    "retention_days", "sample_limit", "sample_sha256", "source_scope",
}


def _timestamp(value: str, field: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError) as error:
        raise PermissionError(f"Coresignal career evaluation {field} is invalid") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise PermissionError(f"Coresignal career evaluation {field} requires a timezone")
    return parsed


def _utc_timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("Coresignal career evaluation timestamp requires a timezone")
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _canonical(value: Mapping[str, object]) -> bytes:
    return (json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False,
    ) + "\n").encode("utf-8")


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise PermissionError(
                f"Coresignal career evaluation contains duplicate key: {key}"
            )
        result[key] = value
    return result


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


@dataclass(frozen=True)
class CoresignalCareerEvaluationApproval:
    approval_id: str
    approved_at: str
    approved_by: str
    distribution: str
    evaluation_version: str
    exclusions_sha256: str
    expires_at: str
    fields: tuple[str, ...]
    notice_status: str
    priority_order: tuple[str, ...]
    projection_version: str
    provider_access_verified: bool
    provider_terms_version: str
    purpose: str
    retention_days: int
    sample_limit: int
    sample_sha256: str
    source_scope: str

    @classmethod
    def from_record(cls, value: object) -> "CoresignalCareerEvaluationApproval":
        if not isinstance(value, dict) or set(value) != _APPROVAL_KEYS:
            raise PermissionError("Coresignal career evaluation approval keys are invalid")
        fields = value.get("fields")
        priorities = value.get("priority_order")
        if not isinstance(fields, list) or not all(isinstance(item, str) for item in fields):
            raise PermissionError("Coresignal career evaluation fields are invalid")
        if not isinstance(priorities, list) or not all(isinstance(item, str) for item in priorities):
            raise PermissionError("Coresignal career evaluation priorities are invalid")
        normalized = dict(value)
        normalized["fields"] = tuple(fields)
        normalized["priority_order"] = tuple(priorities)
        return cls(**normalized)

    def to_record(self) -> dict[str, object]:
        record: dict[str, object] = {
            key: getattr(self, key) for key in sorted(_APPROVAL_KEYS)
        }
        record["fields"] = list(self.fields)
        record["priority_order"] = list(self.priority_order)
        return record

    def authorize(self, *, now: datetime) -> None:
        if now.tzinfo is None or now.utcoffset() is None:
            raise PermissionError("Coresignal career evaluation authorization time requires a timezone")
        required = {
            "approved_by": "release_owner",
            "distribution": "internal_only",
            "evaluation_version": "coresignal-career-evaluation-v1",
            "notice_status": "not_sent",
            "projection_version": "coresignal-career-evidence-v1",
            "purpose": "internal_career_semantic_evaluation",
            "source_scope": "applicant_supplied_linkedin",
        }
        if any(getattr(self, key) != value for key, value in required.items()):
            raise PermissionError("Coresignal career evaluation approval scope is invalid")
        if self.fields != _FIELDS or self.priority_order != _PRIORITIES:
            raise PermissionError("Coresignal career evaluation approval is not career-only")
        if (
            type(self.provider_access_verified) is not bool
            or not self.provider_access_verified
            or type(self.sample_limit) is not int
            or not 1 <= self.sample_limit <= 100
            or type(self.retention_days) is not int
            or not 1 <= self.retention_days <= 7
            or not _HASH.fullmatch(self.sample_sha256)
            or not _HASH.fullmatch(self.exclusions_sha256)
            or not self.approval_id.strip()
            or not self.provider_terms_version.strip()
        ):
            raise PermissionError("Coresignal career evaluation approval values are invalid")
        approved = _timestamp(self.approved_at, "approval timestamp")
        expires = _timestamp(self.expires_at, "expiry")
        if approved > now or now >= expires or expires - approved > timedelta(days=7):
            raise PermissionError("Coresignal career evaluation approval is not currently valid")

    def authorization_hash(self, *, now: datetime) -> str:
        self.authorize(now=now)
        return hashlib.sha256(_canonical(self.to_record())).hexdigest()


def preview_career_evaluation_plan(
    candidates: Iterable[EvaluationCandidate], *, sample_limit: int,
) -> tuple[tuple[EvaluationCandidate, ...], str, str]:
    """Reuse the established evidence-backed cohort ordering and exact hashes."""
    return preview_evaluation_plan(candidates, sample_limit=sample_limit)


def build_career_evaluation_plan(
    candidates: Iterable[EvaluationCandidate], *,
    approval: CoresignalCareerEvaluationApproval, now: datetime,
) -> tuple[EvaluationCandidate, ...]:
    approval.authorize(now=now)
    plan, sample_hash, exclusions_hash = preview_career_evaluation_plan(
        candidates, sample_limit=approval.sample_limit,
    )
    if (
        not hmac.compare_digest(sample_hash, approval.sample_sha256)
        or not hmac.compare_digest(exclusions_hash, approval.exclusions_sha256)
    ):
        raise PermissionError("Coresignal career evaluation approval does not match the cohort")
    return plan


class CoresignalCareerEvaluationStore:
    """Short-lived career projections kept structurally outside release storage."""

    RECORD_VERSION = "coresignal-career-evaluation-result-v1"
    ATTEMPT_VERSION = "coresignal-career-evaluation-attempt-v1"
    EXHAUSTION_VERSION = "coresignal-career-evaluation-exhaustion-v1"
    CLEANUP_VERSION = "coresignal-career-evaluation-cleanup-v1"
    _RECORD_KEYS = {
        "approval_sha256", "audit_receipt", "career_evidence", "collected_at",
        "distribution", "expires_at", "outcome", "priority", "record_version",
        "release_eligible", "subject_ref", "unknown_state",
    }
    _AUDIT_KEYS = {
        "deletion_state", "payload_sha256", "projected_at", "projection_version",
        "raw_evidence_deleted", "reason_code",
    }
    _ATTEMPT_KEYS = {
        "approval_sha256", "attempt_version", "candidate_sha256", "expires_at",
        "priority", "started_at", "state", "subject_ref",
    }
    _EXHAUSTION_KEYS = {
        "approval_sha256", "exhaustion_version", "expires_at", "observed_at",
        "provider_status", "state",
    }

    def __init__(
        self, root: str | Path, *, release_root: str | Path,
        clock: Callable[[], datetime],
    ) -> None:
        configured_root = Path(root)
        if configured_root.is_symlink():
            raise PermissionError(
                "Coresignal career evaluation storage root cannot be a symlink"
            )
        self.root = configured_root.resolve()
        self.release_root = Path(release_root).resolve()
        if self.root.name != "coresignal-career-evaluation":
            raise ValueError("Coresignal career evaluation requires its dedicated storage root")
        if (
            self.root == self.release_root
            or _is_relative_to(self.root, self.release_root)
            or _is_relative_to(self.release_root, self.root)
        ):
            raise ValueError("Coresignal career evaluation must be isolated from release storage")
        self.clock = clock
        self.results = self.root / "results"
        self.attempts = self.root / "attempts"
        self.exhaustions = self.root / "exhaustions"
        for directory in (self.root, self.results, self.attempts, self.exhaustions):
            if directory.is_symlink():
                raise PermissionError(
                    "Coresignal career evaluation storage directory cannot be a symlink"
                )
            if directory.exists():
                if (
                    not directory.is_dir()
                    or directory.stat().st_mode & 0o777 != 0o700
                ):
                    raise PermissionError(
                        "Coresignal career evaluation storage permissions are unsafe"
                    )
            else:
                directory.mkdir(parents=True, exist_ok=False, mode=0o700)
                directory.chmod(0o700)
        self._assert_no_storage_symlinks()
        self._assert_private_storage_permissions()

    @property
    def _storage_directories(self) -> tuple[Path, ...]:
        return (self.root, self.results, self.attempts, self.exhaustions)

    def _assert_no_storage_symlinks(self) -> None:
        for directory in self._storage_directories:
            if directory.is_symlink() or not directory.is_dir():
                raise PermissionError(
                    "Coresignal career evaluation storage structure is unsafe"
                )
            try:
                entries = tuple(directory.iterdir())
            except OSError as error:
                raise PermissionError(
                    "Coresignal career evaluation storage is unreadable"
                ) from error
            if any(entry.is_symlink() for entry in entries):
                raise PermissionError(
                    "Coresignal career evaluation storage contains a symlink"
                )

    def _assert_private_storage_permissions(self) -> None:
        for directory in self._storage_directories:
            try:
                mode = directory.stat().st_mode & 0o777
            except OSError as error:
                raise PermissionError(
                    "Coresignal career evaluation storage is unreadable"
                ) from error
            if directory.is_symlink() or not directory.is_dir() or mode != 0o700:
                raise PermissionError(
                    "Coresignal career evaluation storage permissions are unsafe"
                )
            for path in directory.glob("*.json"):
                try:
                    file_mode = path.stat().st_mode & 0o777
                except OSError as error:
                    raise PermissionError(
                        "Coresignal career evaluation record is unreadable"
                    ) from error
                if path.is_symlink() or not path.is_file() or file_mode != 0o600:
                    raise PermissionError(
                        "Coresignal career evaluation record permissions are unsafe"
                    )

    def _load_current_approval(self) -> tuple[CoresignalCareerEvaluationApproval, str]:
        path = self.root / "approval.json"
        if path.is_symlink() or not path.is_file():
            raise PermissionError(
                "Coresignal career evaluation approval is missing or unsafe"
            )
        try:
            value = json.loads(
                path.read_text(encoding="utf-8"),
                object_pairs_hook=_reject_duplicate_keys,
            )
            approval = CoresignalCareerEvaluationApproval.from_record(value)
            approval_sha256 = approval.authorization_hash(now=self.clock())
        except PermissionError:
            raise
        except (OSError, TypeError, ValueError, json.JSONDecodeError) as error:
            raise PermissionError(
                "Coresignal career evaluation approval is unreadable"
            ) from error
        return approval, approval_sha256

    @staticmethod
    def _record_name(subject_ref: str) -> str:
        if not _PID.fullmatch(subject_ref):
            raise ValueError("Coresignal career evaluation subject must be pseudonymous")
        return hashlib.sha256(subject_ref.encode("utf-8")).hexdigest() + ".json"

    @staticmethod
    def _candidate_sha256(candidate: EvaluationCandidate) -> str:
        """Bind a pending attempt to the full candidate without storing its URL."""
        return hashlib.sha256(_canonical({
            "linkedin_url": candidate.linkedin_url,
            "priority": candidate.priority,
            "source_record_ref": candidate.source_record_ref,
            "subject_ref": candidate.subject_ref,
        })).hexdigest()

    @staticmethod
    def _write(path: Path, value: Mapping[str, object]) -> None:
        temporary = path.with_name(path.name + ".tmp")
        temporary.write_bytes(_canonical(value))
        temporary.chmod(0o600)
        temporary.replace(path)
        path.chmod(0o600)

    def write_approval(
        self, approval: CoresignalCareerEvaluationApproval, *, now: datetime,
    ) -> str:
        approval_hash = approval.authorization_hash(now=now)
        self._write(self.root / "approval.json", approval.to_record())
        return approval_hash

    @staticmethod
    def _career_projection_has_valid_shape(value: object) -> bool:
        if not isinstance(value, list) or len(value) > 6:
            return False
        if any(not isinstance(item, Mapping) or set(item) != CAREER_FIELDS for item in value):
            return False
        for ordinal, item in enumerate(value, start=1):
            role_code = item.get("role_code")
            title = item.get("title_excerpt")
            description = item.get("description_excerpt")
            references = item.get("evidence_refs")
            if (
                not isinstance(role_code, str)
                or role_code != f"role_{ordinal:02d}"
                or not isinstance(title, str)
                or len(title) > 300
                or not isinstance(description, str)
                or len(description) > 1_500
                or item.get("active_state") not in _ACTIVE_STATES
                or item.get("duration_band") not in _DURATION_BANDS
                or item.get("seniority_context") not in _SENIORITY_CONTEXTS
                or item.get("industry_code") not in _INDUSTRY_CODES
                or item.get("organization_size_band") not in _ORGANIZATION_SIZE_BANDS
                or not isinstance(references, list)
                or references != [
                    reference for present, reference in (
                        (bool(title), f"{role_code}:title"),
                        (bool(description), f"{role_code}:description"),
                    ) if present
                ]
            ):
                return False
        return True

    @classmethod
    def _career_projection_is_valid(cls, value: object) -> bool:
        if not cls._career_projection_has_valid_shape(value):
            return False
        try:
            assert_safe_semantic_payload(
                value, allowed_keys=CAREER_FIELDS, max_total_chars=12_000,
            )
        except (TypeError, ValueError):
            return False
        return True

    def _read_validated_result(
        self, subject_ref: str, *, approval_sha256: str,
        require_safe_text: bool,
    ) -> dict[str, object] | None:
        path = self.results / self._record_name(subject_ref)
        if path.is_symlink():
            raise PermissionError("Coresignal career evaluation result path is unsafe")
        if not path.exists():
            return None
        if not path.is_file() or path.stat().st_mode & 0o777 != 0o600:
            raise PermissionError("Coresignal career evaluation result permissions are unsafe")
        try:
            record = json.loads(
                path.read_text(encoding="utf-8"),
                object_pairs_hook=_reject_duplicate_keys,
            )
            collected = _timestamp(str(record["collected_at"]), "collection timestamp")
            expires = _timestamp(str(record["expires_at"]), "result expiry")
            audit = record.get("audit_receipt")
            projected = _timestamp(
                str(audit["projected_at"]), "projection timestamp",
            )
        except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
            raise PermissionError("Coresignal career evaluation result is unreadable") from error
        outcome = record.get("outcome")
        expected_unknown = {
            "observed": "none",
            "not_found": "provider_not_found",
            "projection_rejected": "provider_payload_rejected",
        }
        expected_deletion = {
            "observed": "deleted_after_projection",
            "not_found": "not_retained_not_found",
            "projection_rejected": "deleted_after_projection_rejection",
        }
        expected_reason = {
            "observed": "none",
            "not_found": "none",
            "projection_rejected": "projection_failed_after_response",
        }
        now = self.clock()
        if now.tzinfo is None or now.utcoffset() is None:
            raise PermissionError(
                "Coresignal career evaluation validation time requires a timezone"
            )
        if (
            not isinstance(record, dict)
            or set(record) != self._RECORD_KEYS
            or record.get("record_version") != self.RECORD_VERSION
            or record.get("subject_ref") != subject_ref
            or record.get("approval_sha256") != approval_sha256
            or not _HASH.fullmatch(str(approval_sha256))
            or record.get("priority") not in _PRIORITIES
            or outcome not in expected_unknown
            or record.get("unknown_state") != expected_unknown.get(outcome)
            or record.get("distribution") != "internal_only"
            or record.get("release_eligible") is not False
            or not (
                self._career_projection_is_valid(record.get("career_evidence"))
                if require_safe_text
                else self._career_projection_has_valid_shape(
                    record.get("career_evidence")
                )
            )
            or not isinstance(audit, dict)
            or set(audit) != self._AUDIT_KEYS
            or not (
                _HASH.fullmatch(str(audit.get("payload_sha256") or ""))
                or (
                    outcome == "projection_rejected"
                    and audit.get("payload_sha256") is None
                )
            )
            or audit.get("projection_version") != "coresignal-career-evidence-v1"
            or audit.get("raw_evidence_deleted") is not True
            or audit.get("deletion_state") != expected_deletion.get(outcome)
            or audit.get("reason_code") != expected_reason.get(outcome)
            or projected != collected
            or collected > now
            or expires <= collected
            or expires - collected > timedelta(days=7)
            or (
                outcome in {"not_found", "projection_rejected"}
                and record["career_evidence"]
            )
        ):
            raise PermissionError("Coresignal career evaluation result failed validation")
        if expires <= now:
            self.cleanup_expired()
            raise PermissionError("Coresignal career evaluation result expired and was deleted")
        return record

    def get(self, subject_ref: str, *, approval_sha256: str) -> dict[str, object] | None:
        return self._read_validated_result(
            subject_ref, approval_sha256=approval_sha256, require_safe_text=True,
        )

    @staticmethod
    def _ordered_subject_refs(subject_refs: Iterable[str]) -> tuple[str, ...]:
        if isinstance(subject_refs, (str, bytes)):
            raise ValueError(
                "Coresignal career coverage subjects must be a bounded iterable"
            )
        try:
            subject_iterator = iter(subject_refs)
        except TypeError as error:
            raise ValueError(
                "Coresignal career coverage subjects must be a bounded iterable"
            ) from error
        requested = tuple(islice(subject_iterator, 100_001))
        if (
            not requested
            or len(requested) > 100_000
            or any(not isinstance(subject, str) or not _PID.fullmatch(subject) for subject in requested)
            or len(requested) != len(set(requested))
        ):
            raise ValueError("Coresignal career coverage subjects are invalid")
        return tuple(sorted(requested))

    def load_internal_semantic_evidence(
        self, subject_refs: Iterable[str], *, identity_literals: Iterable[str],
    ) -> dict[str, list[dict[str, object]]]:
        """Load current sanitized career packets for protected semantic review only."""
        if isinstance(identity_literals, (str, bytes)):
            raise PermissionError(
                "Coresignal career evaluation identity literals are invalid"
            )
        try:
            identity_corpus = tuple(identity_literals)
        except TypeError as error:
            raise PermissionError(
                "Coresignal career evaluation identity literals are invalid"
            ) from error
        if not identity_corpus or any(
            not isinstance(item, str) or not item.strip() for item in identity_corpus
        ):
            raise PermissionError(
                "Coresignal career evaluation identity literals are required"
            )
        try:
            assert_no_known_identity_literals({}, identity_corpus)
        except (TypeError, ValueError) as error:
            raise PermissionError(
                "Coresignal career evaluation identity literals are invalid"
            ) from error
        ordered = self._ordered_subject_refs(subject_refs)

        self._assert_no_storage_symlinks()
        self._assert_private_storage_permissions()
        self.cleanup_expired(subject_refs=ordered)
        self._assert_no_storage_symlinks()
        self._assert_private_storage_permissions()
        _approval, approval_sha256 = self._load_current_approval()

        result: dict[str, list[dict[str, object]]] = {}
        for subject_ref in ordered:
            record = self._read_validated_result(
                subject_ref,
                approval_sha256=approval_sha256,
                require_safe_text=False,
            )
            if (
                record is None
                or record.get("outcome") != "observed"
                or not record.get("career_evidence")
            ):
                continue
            evidence = record["career_evidence"]
            if not self._career_projection_has_valid_shape(evidence):
                raise PermissionError(
                    "Coresignal career evaluation semantic evidence is invalid"
                )
            detached = json.loads(json.dumps(
                evidence, ensure_ascii=True, sort_keys=True,
                separators=(",", ":"), allow_nan=False,
            ))
            if not isinstance(detached, list):
                raise PermissionError(
                    "Coresignal career evaluation semantic evidence is invalid"
                )
            for item in detached:
                title = sanitize_professional_text(
                    item["title_excerpt"], forbidden_literals=identity_corpus,
                    max_chars=300,
                ).strip(" -,:@")
                description = sanitize_professional_text(
                    item["description_excerpt"], forbidden_literals=identity_corpus,
                    max_chars=1_500,
                )
                role_code = item["role_code"]
                item["title_excerpt"] = title
                item["description_excerpt"] = description
                item["evidence_refs"] = [
                    reference for present, reference in (
                        (bool(title), f"{role_code}:title"),
                        (bool(description), f"{role_code}:description"),
                    ) if present
                ]
            try:
                assert_no_known_identity_literals(detached, identity_corpus)
            except (TypeError, ValueError) as error:
                raise PermissionError(
                    "Coresignal career evaluation semantic evidence is unsafe"
                ) from error
            if not self._career_projection_is_valid(detached):
                raise PermissionError(
                    "Coresignal career evaluation semantic evidence is invalid"
                )
            result[subject_ref] = detached
        return result

    def build_coverage_snapshot(
        self, subject_refs: Iterable[str],
    ) -> dict[str, object]:
        """Return detached career packet groups without exposing subject bindings.

        The opaque snapshot hash binds the current approval and exact retained
        packet content. The returned value deliberately omits
        approval metadata, provider metadata, timestamps, and pseudonymous IDs.
        """

        ordered = self._ordered_subject_refs(subject_refs)

        # Reject path substitution before cleanup can follow or silently remove it.
        self._assert_no_storage_symlinks()
        self._assert_private_storage_permissions()
        self.cleanup_expired(subject_refs=ordered)
        self._assert_no_storage_symlinks()
        self._assert_private_storage_permissions()
        _approval, approval_sha256 = self._load_current_approval()

        detached_packets: list[tuple[bytes, list[dict[str, object]]]] = []
        for subject_ref in ordered:
            record = self.get(subject_ref, approval_sha256=approval_sha256)
            if (
                record is None
                or record.get("outcome") != "observed"
                or not record.get("career_evidence")
            ):
                continue
            evidence = record["career_evidence"]
            if not self._career_projection_is_valid(evidence):
                raise PermissionError(
                    "Coresignal career evaluation coverage evidence is invalid"
                )
            detached = json.loads(
                json.dumps(
                    evidence, ensure_ascii=True, sort_keys=True,
                    separators=(",", ":"), allow_nan=False,
                )
            )
            if not isinstance(detached, list):
                raise PermissionError(
                    "Coresignal career evaluation coverage evidence is invalid"
                )
            detached_packets.append((
                _canonical({"career_evidence": detached}),
                detached,
            ))

        detached_packets.sort(key=lambda item: item[0])
        packet_groups = [packet for _canonical_packet, packet in detached_packets]
        snapshot_sha256 = hashlib.sha256(_canonical({
            "approval_sha256": approval_sha256,
            "career_evidence_sha256s": [
                hashlib.sha256(canonical_packet).hexdigest()
                for canonical_packet, _packet in detached_packets
            ],
            "snapshot_version": "career-coverage-snapshot-v1",
        })).hexdigest()
        return {
            "career_evidence": packet_groups,
            "snapshot_sha256": snapshot_sha256,
        }

    def put(
        self, *, candidate: EvaluationCandidate, approval_sha256: str,
        outcome: str, career_evidence: list[dict[str, object]],
        payload_sha256: str, retention_days: int,
    ) -> dict[str, object]:
        if (
            outcome not in {"observed", "not_found", "projection_rejected"}
            or not _HASH.fullmatch(approval_sha256)
            or not _HASH.fullmatch(payload_sha256)
            or type(retention_days) is not int
            or not 1 <= retention_days <= 7
            or not self._career_projection_is_valid(career_evidence)
            or (outcome in {"not_found", "projection_rejected"} and career_evidence)
        ):
            raise ValueError("Coresignal career evaluation projection is invalid")
        return self._put_record(
            candidate=candidate,
            approval_sha256=approval_sha256,
            outcome=outcome,
            career_evidence=career_evidence,
            payload_sha256=payload_sha256,
            retention_days=retention_days,
        )

    def _put_record(
        self, *, candidate: EvaluationCandidate, approval_sha256: str,
        outcome: str, career_evidence: list[dict[str, object]],
        payload_sha256: str | None, retention_days: int,
    ) -> dict[str, object]:
        now = self.clock()
        deletion_state = {
            "observed": "deleted_after_projection",
            "not_found": "not_retained_not_found",
            "projection_rejected": "deleted_after_projection_rejection",
        }[outcome]
        record = {
            "approval_sha256": approval_sha256,
            "audit_receipt": {
                "deletion_state": deletion_state,
                "payload_sha256": payload_sha256,
                "projected_at": _utc_timestamp(now),
                "projection_version": "coresignal-career-evidence-v1",
                "raw_evidence_deleted": True,
                "reason_code": (
                    "projection_failed_after_response"
                    if outcome == "projection_rejected" else "none"
                ),
            },
            "career_evidence": career_evidence,
            "collected_at": _utc_timestamp(now),
            "distribution": "internal_only",
            "expires_at": _utc_timestamp(now + timedelta(days=retention_days)),
            "outcome": outcome,
            "priority": candidate.priority,
            "record_version": self.RECORD_VERSION,
            "release_eligible": False,
            "subject_ref": candidate.subject_ref,
            "unknown_state": {
                "observed": "none",
                "not_found": "provider_not_found",
                "projection_rejected": "provider_payload_rejected",
            }[outcome],
        }
        self._write(self.results / self._record_name(candidate.subject_ref), record)
        return record

    def resolve_pending_projection_rejection(
        self, *, candidate: EvaluationCandidate, approval_sha256: str,
        reason_code: str, retention_days: int,
    ) -> dict[str, object]:
        """Resolve a known received-and-deleted response without provider retry."""
        if reason_code != "projection_failed_after_response":
            raise ValueError("Coresignal career evaluation resolution reason is invalid")
        if (
            not _HASH.fullmatch(approval_sha256)
            or type(retention_days) is not int
            or not 1 <= retention_days <= 7
        ):
            raise ValueError("Coresignal career evaluation resolution is invalid")
        attempt_path = self.attempts / self._record_name(candidate.subject_ref)
        result_path = self.results / self._record_name(candidate.subject_ref)
        if not attempt_path.exists() or result_path.exists():
            raise PermissionError(
                "Coresignal career evaluation has no matching pending attempt"
            )
        try:
            attempt = json.loads(attempt_path.read_text(encoding="utf-8"))
            expires = _timestamp(str(attempt["expires_at"]), "attempt expiry")
        except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
            raise PermissionError(
                "Coresignal career evaluation pending attempt is unreadable"
            ) from error
        if (
            not isinstance(attempt, dict)
            or set(attempt) != self._ATTEMPT_KEYS
            or attempt.get("attempt_version") != self.ATTEMPT_VERSION
            or attempt.get("state") != "pending_or_uncertain"
            or attempt.get("subject_ref") != candidate.subject_ref
            or attempt.get("priority") != candidate.priority
            or attempt.get("approval_sha256") != approval_sha256
            or not hmac.compare_digest(
                str(attempt.get("candidate_sha256") or ""),
                self._candidate_sha256(candidate),
            )
            or expires <= self.clock()
        ):
            raise PermissionError(
                "Coresignal career evaluation pending attempt does not match the resolution"
            )
        record = self._put_record(
            candidate=candidate,
            approval_sha256=approval_sha256,
            outcome="projection_rejected",
            career_evidence=[],
            payload_sha256=None,
            retention_days=retention_days,
        )
        self.clear_attempt(candidate.subject_ref)
        return record

    def begin_attempt(
        self, *, candidate: EvaluationCandidate, approval_sha256: str,
        retention_days: int,
    ) -> None:
        if (
            not _HASH.fullmatch(approval_sha256)
            or type(retention_days) is not int
            or not 1 <= retention_days <= 7
        ):
            raise ValueError("Coresignal career evaluation attempt is invalid")
        path = self.attempts / self._record_name(candidate.subject_ref)
        if path.exists():
            raise PermissionError(
                "Coresignal career evaluation has an uncertain provider attempt; automatic retry is blocked"
            )
        now = self.clock()
        self._write(path, {
            "approval_sha256": approval_sha256,
            "attempt_version": self.ATTEMPT_VERSION,
            "candidate_sha256": self._candidate_sha256(candidate),
            "expires_at": _utc_timestamp(now + timedelta(days=retention_days)),
            "priority": candidate.priority,
            "started_at": _utc_timestamp(now),
            "state": "pending_or_uncertain",
            "subject_ref": candidate.subject_ref,
        })

    def assert_retry_safe(self, subject_ref: str) -> None:
        if (self.attempts / self._record_name(subject_ref)).exists():
            raise PermissionError(
                "Coresignal career evaluation has an uncertain provider attempt; automatic retry is blocked"
            )

    def clear_attempt(self, subject_ref: str) -> None:
        (self.attempts / self._record_name(subject_ref)).unlink(missing_ok=True)

    def record_capacity_exhaustion(
        self, *, approval_sha256: str, approval_expires_at: str,
    ) -> dict[str, object]:
        """Persist an approval-bound terminal receipt for provider HTTP 402."""
        if not _HASH.fullmatch(approval_sha256):
            raise ValueError("Coresignal capacity exhaustion receipt is invalid")
        now = self.clock()
        try:
            expires = _timestamp(approval_expires_at, "exhaustion approval expiry")
        except PermissionError as error:
            raise ValueError("Coresignal capacity exhaustion receipt is invalid") from error
        if expires <= now or expires - now > timedelta(days=7):
            raise ValueError("Coresignal capacity exhaustion receipt is invalid")
        receipt = {
            "approval_sha256": approval_sha256,
            "exhaustion_version": self.EXHAUSTION_VERSION,
            "expires_at": _utc_timestamp(expires),
            "observed_at": _utc_timestamp(now),
            "provider_status": 402,
            "state": "provider_capacity_exhausted",
        }
        self._write(self.exhaustions / f"{approval_sha256}.json", receipt)
        return receipt

    def assert_capacity_available(self, *, approval_sha256: str) -> None:
        """Block transport after capacity exhaustion under the same approval."""
        if not _HASH.fullmatch(approval_sha256):
            raise ValueError("Coresignal capacity approval hash is invalid")
        path = self.exhaustions / f"{approval_sha256}.json"
        if not path.exists():
            return
        try:
            receipt = json.loads(path.read_text(encoding="utf-8"))
            observed = _timestamp(str(receipt["observed_at"]), "exhaustion timestamp")
            expires = _timestamp(str(receipt["expires_at"]), "exhaustion expiry")
        except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
            raise PermissionError(
                "Coresignal capacity exhaustion receipt is unreadable"
            ) from error
        if (
            not isinstance(receipt, dict)
            or set(receipt) != self._EXHAUSTION_KEYS
            or receipt.get("exhaustion_version") != self.EXHAUSTION_VERSION
            or receipt.get("approval_sha256") != approval_sha256
            or receipt.get("provider_status") != 402
            or receipt.get("state") != "provider_capacity_exhausted"
            or expires <= observed
            or expires - observed > timedelta(days=7)
        ):
            raise PermissionError(
                "Coresignal capacity exhaustion receipt failed validation"
            )
        if expires <= self.clock():
            path.unlink(missing_ok=True)
            return
        raise PermissionError(
            "Coresignal provider capacity is exhausted under this approval (status 402)"
        )

    def cleanup_expired(
        self, *, subject_refs: Iterable[str] | None = None,
    ) -> dict[str, object]:
        now = self.clock()
        deleted: list[str] = []
        if subject_refs is None:
            result_candidates = list(self.results.glob("*.json"))
            attempt_candidates = list(self.attempts.glob("*.json"))
        else:
            requested = tuple(subject_refs)
            if any(
                not isinstance(subject, str) or not _PID.fullmatch(subject)
                for subject in requested
            ):
                raise ValueError(
                    "Coresignal career cleanup subjects are invalid"
                )
            result_candidates = [
                path for subject in requested
                if (path := self.results / self._record_name(subject)).exists()
            ]
            attempt_candidates = [
                path for subject in requested
                if (path := self.attempts / self._record_name(subject)).exists()
            ]
        candidates = (
            result_candidates
            + attempt_candidates
            + list(self.exhaustions.glob("*.json"))
        )
        approval = self.root / "approval.json"
        if approval.exists():
            candidates.append(approval)
        for directory in (self.root, self.results, self.attempts, self.exhaustions):
            for temporary in directory.glob("*.tmp"):
                deleted.append(str(temporary.relative_to(self.root)))
                temporary.unlink(missing_ok=True)
        for path in candidates:
            remove = False
            try:
                value = json.loads(path.read_text(encoding="utf-8"))
                remove = _timestamp(str(value["expires_at"]), "cleanup expiry") <= now
            except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError):
                remove = True
            if remove:
                deleted.append(str(path.relative_to(self.root)))
                path.unlink(missing_ok=True)
        receipt = {
            "assets_sha256": hashlib.sha256(
                "\n".join(sorted(deleted)).encode("utf-8")
            ).hexdigest(),
            "cleanup_version": self.CLEANUP_VERSION,
            "deleted_at": _utc_timestamp(now),
            "deleted_count": len(deleted),
        }
        self._write(self.root / "cleanup-receipt.json", receipt)
        return receipt


class _DefinitiveProviderStop(PermissionError):
    """A known non-success response that does not warrant an automatic retry."""


class _ProviderCapacityExhausted(_DefinitiveProviderStop):
    """A terminal capacity response that must bind to the current approval."""


class CoresignalCareerEvaluationRunner:
    """Collect at most once per approved subject and retain only career evidence."""

    def __init__(
        self, *, transport: Transport, store: CoresignalCareerEvaluationStore,
        api_token: str, clock: Callable[[], datetime],
        source_verifier: Callable[[EvaluationCandidate], bool],
        identity_literals_resolver: Callable[[EvaluationCandidate], Iterable[str]],
    ) -> None:
        if (
            not api_token
            or not callable(source_verifier)
            or not callable(identity_literals_resolver)
        ):
            raise ValueError("Coresignal career evaluation runtime dependencies are required")
        self.transport = transport
        self.store = store
        self.api_token = api_token
        self.clock = clock
        self.source_verifier = source_verifier
        self.identity_literals_resolver = identity_literals_resolver

    @staticmethod
    def _identity_literals(value: object) -> tuple[str, ...]:
        if isinstance(value, (str, bytes)):
            raise PermissionError("Coresignal career evaluation identity literals are invalid")
        try:
            literals = tuple(value)  # type: ignore[arg-type]
        except TypeError as error:
            raise PermissionError("Coresignal career evaluation identity literals are invalid") from error
        if not literals or any(
            not isinstance(item, str) or not item.strip() for item in literals
        ):
            raise PermissionError("Coresignal career evaluation identity literals are required")
        return literals

    def _fetch_and_project(
        self, candidate: EvaluationCandidate, *, identity_literals: tuple[str, ...],
    ) -> tuple[str, list[dict[str, object]], str]:
        query = urlencode([("fields", field) for field in _FIELDS])
        url = (
            _CORESIGNAL_ENDPOINT + "/"
            + quote(_profile_shorthand(candidate.linkedin_url), safe="") + "?" + query
        )
        response = self.transport.request(
            "GET", url,
            headers={"apikey": self.api_token, "Accept": "application/json"},
            timeout=10.0, max_bytes=262144,
        )
        payload_sha256 = hashlib.sha256(response.body).hexdigest()
        if response.status == 402:
            raise _ProviderCapacityExhausted(
                "Coresignal career evaluation request stopped with status 402"
            )
        if response.status == 429:
            raise _DefinitiveProviderStop(
                f"Coresignal career evaluation request stopped with status {response.status}"
            )
        if response.status == 404:
            return "not_found", [], payload_sha256
        if response.status != 200:
            raise PermissionError(
                f"Coresignal career evaluation request failed with status {response.status}"
            )
        raw_body = response.body
        try:
            payload = json.loads(raw_body)
            evidence = build_career_evidence(
                payload, identity_literals=identity_literals,
            )
            if not self.store._career_projection_is_valid(evidence):
                raise ValueError("Coresignal career evaluation projection is unsafe")
        except (TypeError, ValueError, json.JSONDecodeError):
            # A 200 response is definitive and may already be billable. Do not
            # retain the rejected payload or convert it into an automatic retry.
            return "projection_rejected", [], payload_sha256
        finally:
            # The raw body is intentionally call-local and is never passed to storage.
            raw_body = b""
        del payload
        return "observed", evidence, payload_sha256

    def evaluate(
        self, candidates: Iterable[EvaluationCandidate], *,
        approval: CoresignalCareerEvaluationApproval,
        max_new_records: int | None = None,
    ) -> dict[str, object]:
        materialized = tuple(candidates)
        if any(self.source_verifier(item) is not True for item in materialized):
            raise PermissionError("Coresignal career evaluation applicant-source evidence was not verified")
        if (
            max_new_records is not None
            and (type(max_new_records) is not int or not 1 <= max_new_records <= 100)
        ):
            raise ValueError("Coresignal career evaluation canary size is invalid")
        plan = build_career_evaluation_plan(
            materialized, approval=approval, now=self.clock(),
        )
        self.store.cleanup_expired()
        if len(plan) > 100:
            raise PermissionError("Coresignal career evaluation provider-attempt ceiling was exceeded")
        identities = {
            item.subject_ref: self._identity_literals(self.identity_literals_resolver(item))
            for item in plan
        }
        approval_sha256 = self.store.write_approval(approval, now=self.clock())
        self.store.assert_capacity_available(approval_sha256=approval_sha256)
        records: list[dict[str, object]] = []
        created = 0
        for item in plan:
            existing = self.store.get(item.subject_ref, approval_sha256=approval_sha256)
            if existing is not None:
                self.store.clear_attempt(item.subject_ref)
                records.append(existing)
                continue
            if max_new_records is not None and created >= max_new_records:
                continue
            if (
                not hmac.compare_digest(
                    approval.authorization_hash(now=self.clock()), approval_sha256,
                )
                or self.source_verifier(item) is not True
            ):
                raise PermissionError("Coresignal career evaluation authorization or provenance expired")
            self.store.assert_retry_safe(item.subject_ref)
            self.store.begin_attempt(
                candidate=item, approval_sha256=approval_sha256,
                retention_days=approval.retention_days,
            )
            try:
                outcome, career_evidence, payload_sha256 = self._fetch_and_project(
                    item, identity_literals=identities[item.subject_ref],
                )
            except _ProviderCapacityExhausted:
                self.store.record_capacity_exhaustion(
                    approval_sha256=approval_sha256,
                    approval_expires_at=approval.expires_at,
                )
                self.store.clear_attempt(item.subject_ref)
                raise
            except _DefinitiveProviderStop:
                self.store.clear_attempt(item.subject_ref)
                raise
            record = self.store.put(
                candidate=item, approval_sha256=approval_sha256,
                outcome=outcome, career_evidence=career_evidence,
                payload_sha256=payload_sha256,
                retention_days=approval.retention_days,
            )
            self.store.clear_attempt(item.subject_ref)
            records.append(record)
            created += 1
        return {
            "attempted": len(records),
            "distribution": "internal_only",
            "evaluation_version": approval.evaluation_version,
            "records": records,
            "release_eligible": False,
        }
