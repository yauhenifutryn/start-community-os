"""Isolated approval and sampling for internal-only Coresignal evaluation."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
import hashlib
import hmac
import json
from pathlib import Path
import re
from typing import Callable, Iterable, Mapping
from urllib.parse import quote, urlencode

from community_os.enrichment.coresignal import (
    _CORESIGNAL_ENDPOINT, _CORESIGNAL_FIELDS, _COMPANY_CATEGORIES,
    _SENIORITY_CATEGORIES, _profile_shorthand, _profile_url,
    normalize_coresignal_payload,
)
from community_os.enrichment.transport import (
    RetryableTransportError, Transport,
)
from community_os.enrichment.state import pseudonymous_id
from community_os.identity import normalize_email


_HASH = re.compile(r"^[0-9a-f]{64}$")
_PID = re.compile(r"^pid:v1:[0-9a-f]{64}$")
_EVIDENCE = re.compile(r"^evidence:coresignal:[0-9a-f]{64}$")
_SOURCE_REF = re.compile(r"^[a-z][a-z0-9_:.-]{2,160}$")
_PRIORITY = {"checked_in": 0, "accepted_not_checked_in": 1, "other": 2}
_APPROVAL_KEYS = {
    "approval_id", "approved_at", "approved_by", "distribution",
    "evaluation_version", "exclusions_sha256", "expires_at", "notice_status",
    "provider_access_verified", "provider_terms_version", "purpose",
    "retention_days", "sample_limit", "sample_sha256", "source_scope",
}


def _timestamp(value: str, field: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (AttributeError, ValueError) as error:
        raise PermissionError(f"Coresignal evaluation {field} is invalid") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise PermissionError(f"Coresignal evaluation {field} requires a timezone")
    return parsed


@dataclass(frozen=True)
class CoresignalEvaluationApproval:
    evaluation_version: str
    notice_status: str
    purpose: str
    distribution: str
    source_scope: str
    sample_sha256: str
    exclusions_sha256: str
    sample_limit: int
    provider_access_verified: bool
    provider_terms_version: str
    approved_by: str
    approval_id: str
    approved_at: str
    expires_at: str
    retention_days: int

    @classmethod
    def from_record(cls, value: object) -> "CoresignalEvaluationApproval":
        if not isinstance(value, dict) or set(value) != _APPROVAL_KEYS:
            raise PermissionError("Coresignal evaluation approval keys are invalid")
        return cls(**value)

    def to_record(self) -> dict[str, object]:
        return {key: getattr(self, key) for key in sorted(_APPROVAL_KEYS)}

    def authorize(self, *, now: datetime) -> None:
        if now.tzinfo is None or now.utcoffset() is None:
            raise PermissionError("Coresignal evaluation authorization time requires a timezone")
        required = {
            "evaluation_version": "coresignal-evaluation-v1",
            "notice_status": "not_sent",
            "purpose": "internal_provider_evaluation",
            "distribution": "internal_only",
            "source_scope": "applicant_supplied_linkedin",
            "approved_by": "release_owner",
        }
        if any(getattr(self, key) != value for key, value in required.items()):
            raise PermissionError("Coresignal evaluation approval scope is invalid")
        if (
            type(self.provider_access_verified) is not bool
            or not self.provider_access_verified
            or type(self.sample_limit) is not int
            or not 1 <= self.sample_limit <= 100
            or type(self.retention_days) is not int
            or not 1 <= self.retention_days <= 7
            or not _HASH.fullmatch(self.sample_sha256)
            or not _HASH.fullmatch(self.exclusions_sha256)
            or not self.provider_terms_version.strip()
            or not self.approval_id.strip()
        ):
            raise PermissionError("Coresignal evaluation approval values are invalid")
        approved = _timestamp(self.approved_at, "approval timestamp")
        expires = _timestamp(self.expires_at, "expiry")
        if approved > now or now >= expires or expires - approved > timedelta(days=7):
            raise PermissionError("Coresignal evaluation approval is not currently valid")

    def authorization_hash(self, *, now: datetime) -> str:
        self.authorize(now=now)
        canonical = json.dumps(
            self.to_record(), ensure_ascii=True, sort_keys=True, separators=(",", ":"),
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class EvaluationCandidate:
    subject_ref: str
    linkedin_url: str
    source_record_ref: str
    priority: str

    def __post_init__(self) -> None:
        if not _PID.fullmatch(self.subject_ref):
            raise ValueError("Coresignal evaluation subject must be pseudonymous")
        if not _SOURCE_REF.fullmatch(self.source_record_ref):
            raise ValueError("Coresignal evaluation source reference is invalid")
        if self.priority not in _PRIORITY:
            raise ValueError("Coresignal evaluation priority is not evidence-backed")
        object.__setattr__(self, "linkedin_url", _profile_url(self.linkedin_url))


def build_event_evaluation_candidates(
    applications: Iterable[Mapping[str, object]],
    attendance: Iterable[Mapping[str, object]], *, pseudonym_secret: bytes,
) -> tuple[EvaluationCandidate, ...]:
    """Join exact attendance evidence to applicant-supplied LinkedIn profiles."""
    if not pseudonym_secret:
        raise ValueError("Coresignal evaluation pseudonym secret is required")
    application_rows = tuple(dict(item) for item in applications)
    by_email: dict[str, dict[str, object]] = {}
    external_ids: set[str] = set()
    for application in application_rows:
        external_id = str(application.get("external_id") or "").strip()
        email = normalize_email(str(application.get("email") or ""))
        if not external_id or not email or external_id in external_ids or email in by_email:
            raise ValueError("Coresignal evaluation applications are missing or duplicated")
        external_ids.add(external_id)
        by_email[email] = application

    attendance_by_email: dict[str, tuple[bool, bool]] = {}
    attendance_seen: set[str] = set()
    for item in attendance:
        email = normalize_email(str(item.get("email") or ""))
        accepted = item.get("accepted")
        checked_in = item.get("checked_in")
        if (
            not email or email in attendance_seen
            or type(accepted) is not bool or type(checked_in) is not bool
            or (checked_in and not accepted)
        ):
            raise ValueError("Coresignal evaluation attendance linkage is invalid")
        attendance_seen.add(email)
        if email not in by_email:
            # Attendance-only guests are outside the applicant population and
            # cannot acquire applicant enrichment merely by appearing on-site.
            continue
        attendance_by_email[email] = (accepted, checked_in)

    candidates: list[EvaluationCandidate] = []
    for application in sorted(
        application_rows, key=lambda item: str(item.get("external_id") or ""),
    ):
        linkedin = str(application.get("linkedin") or "").strip()
        if not linkedin:
            continue
        try:
            linkedin = _profile_url(linkedin)
        except ValueError:
            # Do not repair or infer a personal profile from malformed input.
            continue
        external_id = str(application["external_id"])
        email = normalize_email(str(application["email"]))
        accepted, checked_in = attendance_by_email.get(email, (False, False))
        priority = (
            "checked_in" if checked_in else
            "accepted_not_checked_in" if accepted else "other"
        )
        source_digest = hmac.new(
            pseudonym_secret, external_id.encode("utf-8"), hashlib.sha256,
        ).hexdigest()[:24]
        candidates.append(EvaluationCandidate(
            subject_ref=pseudonymous_id(
                external_id, secret=pseudonym_secret, key_version="v1",
            ),
            linkedin_url=linkedin,
            source_record_ref=f"source:application:{source_digest}",
            priority=priority,
        ))
    return tuple(candidates)


def build_evaluation_plan(
    candidates: Iterable[EvaluationCandidate], *,
    approval: CoresignalEvaluationApproval, now: datetime,
) -> tuple[EvaluationCandidate, ...]:
    """Prioritize evidence-backed cohorts and spend no more than the approved ceiling."""
    approval.authorize(now=now)
    plan, sample_sha256, exclusions_sha256 = preview_evaluation_plan(
        candidates, sample_limit=approval.sample_limit,
    )
    if (
        not hmac.compare_digest(approval.sample_sha256, sample_sha256)
        or not hmac.compare_digest(approval.exclusions_sha256, exclusions_sha256)
    ):
        raise PermissionError("Coresignal evaluation approval does not match the cohort")
    return plan


def _candidate_digest_value(candidate: EvaluationCandidate) -> dict[str, str]:
    return {
        "linkedin_url": candidate.linkedin_url,
        "priority": candidate.priority,
        "source_record_ref": candidate.source_record_ref,
        "subject_ref": candidate.subject_ref,
    }


def preview_evaluation_plan(
    candidates: Iterable[EvaluationCandidate], *, sample_limit: int,
) -> tuple[tuple[EvaluationCandidate, ...], str, str]:
    """Derive the exact plan hashes that the owner approval must bind."""
    if type(sample_limit) is not int or not 1 <= sample_limit <= 100:
        raise ValueError("Coresignal evaluation sample limit is invalid")
    materialized = tuple(candidates)
    ordered = sorted(
        enumerate(materialized), key=lambda item: (_PRIORITY[item[1].priority], item[0]),
    )
    unique: list[EvaluationCandidate] = []
    excluded: list[EvaluationCandidate] = []
    seen: set[str] = set()
    for _index, candidate in ordered:
        key = candidate.linkedin_url.casefold()
        if key in seen or len(unique) == sample_limit:
            excluded.append(candidate)
            continue
        seen.add(key)
        unique.append(candidate)
    sample_sha256 = hashlib.sha256(_canonical_sequence(
        [_candidate_digest_value(candidate) for candidate in unique],
    )).hexdigest()
    exclusions_sha256 = hashlib.sha256(_canonical_sequence(
        [_candidate_digest_value(candidate) for candidate in excluded],
    )).hexdigest()
    return tuple(unique), sample_sha256, exclusions_sha256


def _canonical_sequence(value: list[dict[str, str]]) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False,
    ).encode("utf-8")


def _canonical(value: Mapping[str, object]) -> bytes:
    return (json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False,
    ) + "\n").encode("utf-8")


def _utc_timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("Coresignal evaluation timestamp requires a timezone")
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


class CoresignalEvaluationStore:
    """Protected records that are structurally unreachable from release outputs."""

    RECORD_VERSION = "coresignal-evaluation-result-v1"
    REPORT_VERSION = "coresignal-evaluation-quality-v1"
    ATTEMPT_VERSION = "coresignal-evaluation-attempt-v1"
    CLEANUP_VERSION = "coresignal-evaluation-cleanup-v1"
    _RESULT_KEYS = {
        "approval_sha256", "collected_at", "evidence_ref", "expires_at", "facts",
        "outcome", "priority", "record_version", "subject_ref",
    }
    _FACT_KEYS = {"company_category", "founder_history", "seniority", "title_category"}
    _REPORT_KEYS = {
        "approval_sha256", "attempted", "coverage", "evaluation_version",
        "expires_at", "generated_at", "not_found", "observed", "priority",
        "report_version",
    }

    def __init__(
        self, root: str | Path, *, release_root: str | Path,
        clock: Callable[[], datetime],
    ) -> None:
        self.root = Path(root).resolve()
        self.release_root = Path(release_root).resolve()
        if self.root.name != "coresignal-evaluation":
            raise ValueError("Coresignal evaluation requires its dedicated storage root")
        if (
            self.root == self.release_root
            or _is_relative_to(self.root, self.release_root)
            or _is_relative_to(self.release_root, self.root)
        ):
            raise ValueError("Coresignal evaluation storage must be isolated from release storage")
        self.clock = clock
        self.results = self.root / "results"
        self.attempts = self.root / "attempts"
        for directory in (self.root, self.results, self.attempts):
            directory.mkdir(parents=True, exist_ok=True, mode=0o700)
            directory.chmod(0o700)
        self.cleanup_expired()

    @staticmethod
    def _record_name(subject_ref: str) -> str:
        if not _PID.fullmatch(subject_ref):
            raise ValueError("Coresignal evaluation subject must be pseudonymous")
        return hashlib.sha256(subject_ref.encode("utf-8")).hexdigest() + ".json"

    @staticmethod
    def _write(path: Path, value: Mapping[str, object]) -> None:
        temporary = path.with_name(path.name + ".tmp")
        temporary.write_bytes(_canonical(value))
        temporary.chmod(0o600)
        temporary.replace(path)
        path.chmod(0o600)

    def get(self, subject_ref: str, *, approval_sha256: str) -> dict[str, object] | None:
        path = self.results / self._record_name(subject_ref)
        if not path.exists():
            return None
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
            collected = _timestamp(str(value["collected_at"]), "result collection")
            expiry = _timestamp(str(value["expires_at"]), "result expiry")
        except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
            raise PermissionError("Coresignal evaluation record is unreadable") from error
        facts = value.get("facts")
        if (
            not isinstance(value, dict)
            or set(value) != self._RESULT_KEYS
            or value.get("record_version") != self.RECORD_VERSION
            or value.get("subject_ref") != subject_ref
            or value.get("approval_sha256") != approval_sha256
            or not _HASH.fullmatch(str(value.get("approval_sha256") or ""))
            or not _EVIDENCE.fullmatch(str(value.get("evidence_ref") or ""))
            or value.get("priority") not in _PRIORITY
            or value.get("outcome") not in {"observed", "not_found"}
            or not self._facts_are_valid(facts, outcome=str(value.get("outcome")))
            or expiry <= collected
            or expiry - collected > timedelta(days=7)
        ):
            raise PermissionError("Coresignal evaluation record failed validation")
        if expiry <= self.clock():
            self.cleanup_expired()
            raise PermissionError("Coresignal evaluation record expired and was deleted")
        return value

    @classmethod
    def _facts_are_valid(cls, facts: object, *, outcome: str) -> bool:
        if not isinstance(facts, dict) or set(facts) != cls._FACT_KEYS:
            return False
        if (
            facts.get("company_category") not in _COMPANY_CATEGORIES
            or facts.get("seniority") not in _SENIORITY_CATEGORIES
            or facts.get("title_category") not in {"unknown", "software_engineering"}
            or type(facts.get("founder_history")) is not bool
        ):
            return False
        return outcome != "not_found" or facts == _UNKNOWN_FACTS

    def put(
        self, *, candidate: EvaluationCandidate, approval_sha256: str,
        outcome: str, evidence_ref: str, facts: Mapping[str, object],
        retention_days: int,
    ) -> dict[str, object]:
        if (
            outcome not in {"observed", "not_found"}
            or not self._facts_are_valid(facts, outcome=outcome)
            or not _HASH.fullmatch(approval_sha256)
            or not _EVIDENCE.fullmatch(evidence_ref)
            or type(retention_days) is not int
            or not 1 <= retention_days <= 7
        ):
            raise ValueError("Coresignal evaluation projection is invalid")
        now = self.clock()
        record = {
            "approval_sha256": approval_sha256,
            "collected_at": _utc_timestamp(now),
            "evidence_ref": evidence_ref,
            "expires_at": _utc_timestamp(now + timedelta(days=retention_days)),
            "facts": dict(facts),
            "outcome": outcome,
            "priority": candidate.priority,
            "record_version": self.RECORD_VERSION,
            "subject_ref": candidate.subject_ref,
        }
        self._write(self.results / self._record_name(candidate.subject_ref), record)
        return record

    def write_report(self, report: Mapping[str, object]) -> None:
        coverage = report.get("coverage")
        priority = report.get("priority")
        integer = lambda value: type(value) is int and value >= 0
        try:
            generated = _timestamp(str(report["generated_at"]), "report generation")
            expiry = _timestamp(str(report["expires_at"]), "report expiry")
        except (KeyError, TypeError, ValueError) as error:
            raise ValueError("Coresignal evaluation quality report is invalid") from error
        if (
            set(report) != self._REPORT_KEYS
            or report.get("report_version") != self.REPORT_VERSION
            or report.get("evaluation_version") != "coresignal-evaluation-v1"
            or not _HASH.fullmatch(str(report.get("approval_sha256") or ""))
            or not isinstance(coverage, dict)
            or set(coverage) != {
                "company_category_known", "founder_history", "seniority_known",
                "software_engineering_title",
            }
            or not all(integer(value) for value in coverage.values())
            or not isinstance(priority, dict)
            or set(priority) != set(_PRIORITY)
            or not all(integer(value) for value in priority.values())
            or not all(integer(report.get(key)) for key in ("attempted", "observed", "not_found"))
            or report["attempted"] != sum(priority.values())
            or report["attempted"] != report["observed"] + report["not_found"]
            or any(value > report["observed"] for value in coverage.values())
            or expiry <= generated
            or expiry - generated > timedelta(days=7)
        ):
            raise ValueError("Coresignal evaluation quality report is invalid")
        self._write(self.root / "quality-report.json", report)

    def write_internal_aggregate(
        self, records: Iterable[Mapping[str, object]], *, minimum_group_size: int = 5,
    ) -> dict[str, object]:
        aggregate = build_internal_evaluation_aggregate(
            records, minimum_group_size=minimum_group_size,
        )
        self._write(self.root / "internal-aggregate.json", aggregate)
        return aggregate

    def write_approval(
        self, approval: CoresignalEvaluationApproval, *, now: datetime,
    ) -> str:
        authorization_hash = approval.authorization_hash(now=now)
        self._write(self.root / "approval.json", approval.to_record())
        return authorization_hash

    def begin_attempt(
        self, *, candidate: EvaluationCandidate, approval_sha256: str,
        retention_days: int,
    ) -> None:
        if (
            not _HASH.fullmatch(approval_sha256)
            or type(retention_days) is not int
            or not 1 <= retention_days <= 7
        ):
            raise ValueError("Coresignal evaluation attempt is invalid")
        path = self.attempts / self._record_name(candidate.subject_ref)
        if path.exists():
            raise PermissionError(
                "Coresignal evaluation has an uncertain prior provider attempt; automatic retry is blocked"
            )
        now = self.clock()
        self._write(path, {
            "approval_sha256": approval_sha256,
            "attempt_version": self.ATTEMPT_VERSION,
            "expires_at": _utc_timestamp(now + timedelta(days=retention_days)),
            "priority": candidate.priority,
            "started_at": _utc_timestamp(now),
            "state": "pending_or_uncertain",
            "subject_ref": candidate.subject_ref,
        })

    def clear_attempt(self, subject_ref: str) -> None:
        (self.attempts / self._record_name(subject_ref)).unlink(missing_ok=True)

    def assert_retry_safe(self, subject_ref: str) -> None:
        if (self.attempts / self._record_name(subject_ref)).exists():
            raise PermissionError(
                "Coresignal evaluation has an uncertain prior provider attempt; automatic retry is blocked"
            )

    def cleanup_expired(self) -> dict[str, object]:
        deleted: list[str] = []
        now = self.clock()
        candidates = list(self.results.glob("*.json")) + list(self.attempts.glob("*.json"))
        quality = self.root / "quality-report.json"
        if quality.exists():
            candidates.append(quality)
        approval = self.root / "approval.json"
        if approval.exists():
            candidates.append(approval)
        for directory in (self.root, self.results, self.attempts):
            for temporary in directory.glob("*.tmp"):
                deleted.append(str(temporary.relative_to(self.root)))
                temporary.unlink(missing_ok=True)
        for path in candidates:
            remove = False
            try:
                value = json.loads(path.read_text(encoding="utf-8"))
                expiry = _timestamp(str(value["expires_at"]), "cleanup expiry")
                remove = expiry <= now
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


_UNKNOWN_FACTS: dict[str, object] = {
    "company_category": "unknown",
    "founder_history": False,
    "seniority": "unknown",
    "title_category": "unknown",
}


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
    """Suppress a whole partition when one non-empty complement is below k."""
    withheld = any(0 < value < minimum_group_size for value in values.values())
    return {
        key: _aggregate_cell(value, withheld=withheld)
        for key, value in values.items()
    }


def build_internal_evaluation_aggregate(
    records: Iterable[Mapping[str, object]], *, minimum_group_size: int = 5,
) -> dict[str, object]:
    """Create an identifier-free, group-safe internal diagnostic aggregate."""
    if type(minimum_group_size) is not int or minimum_group_size < 5:
        raise ValueError("Coresignal aggregate minimum group size must be at least five")

    materialized = tuple(dict(record) for record in records)
    cohort_counts = {
        priority: {"attempted": 0, "observed": 0, "not_found": 0}
        for priority in _PRIORITY
    }
    company = {
        "enterprise": 0,
        "academia_research": 0,
        "startup_scaleup": 0,
        "unknown_or_other": 0,
    }
    seniority = {"founder_or_executive": 0, "other_known": 0, "unknown": 0}
    founder = {"observed": 0, "not_observed": 0}
    title = {"software_engineering": 0, "other_or_unknown": 0}

    for record in materialized:
        priority = record.get("priority")
        outcome = record.get("outcome")
        facts = record.get("facts")
        if (
            priority not in _PRIORITY
            or outcome not in {"observed", "not_found"}
            or not CoresignalEvaluationStore._facts_are_valid(facts, outcome=str(outcome))
        ):
            raise ValueError("Coresignal aggregate input is invalid")
        cohort_counts[str(priority)]["attempted"] += 1
        cohort_counts[str(priority)][str(outcome)] += 1
        assert isinstance(facts, dict)

        company_category = str(facts["company_category"])
        company_key = (
            company_category if company_category in company and company_category != "unknown_or_other"
            else "unknown_or_other"
        )
        company[company_key] += 1

        seniority_category = str(facts["seniority"])
        if seniority_category in {"founder", "executive"}:
            seniority["founder_or_executive"] += 1
        elif seniority_category == "unknown":
            seniority["unknown"] += 1
        else:
            seniority["other_known"] += 1

        founder_key = "observed" if facts["founder_history"] is True else "not_observed"
        founder[founder_key] += 1
        title_key = (
            "software_engineering"
            if facts["title_category"] == "software_engineering"
            else "other_or_unknown"
        )
        title[title_key] += 1

    cohorts: dict[str, object] = {}
    for priority, counts in cohort_counts.items():
        outcomes = _protected_partition(
            {"observed": counts["observed"], "not_found": counts["not_found"]},
            minimum_group_size=minimum_group_size,
        )
        cohorts[priority] = {
            "attempted": _aggregate_cell(counts["attempted"]),
            **outcomes,
        }

    observed_total = sum(
        counts["observed"] for counts in cohort_counts.values()
    )
    not_found_total = len(materialized) - observed_total
    return {
        "aggregate_version": "coresignal-internal-aggregate-v1",
        "distribution": "internal_only",
        "notice_status": "not_sent",
        "minimum_group_size": minimum_group_size,
        "population": {
            "attempted": len(materialized),
            "observed": observed_total,
            "not_found": not_found_total,
        },
        "cohorts": cohorts,
        "dimensions": {
            "company_context": _protected_partition(
                company, minimum_group_size=minimum_group_size,
            ),
            "seniority_context": _protected_partition(
                seniority, minimum_group_size=minimum_group_size,
            ),
            "founder_history": _protected_partition(
                founder, minimum_group_size=minimum_group_size,
            ),
            "title_context": _protected_partition(
                title, minimum_group_size=minimum_group_size,
            ),
        },
    }


class _DefinitiveProviderFailure(PermissionError):
    """An explicit response known not to be a successful collect."""


class CoresignalEvaluationRunner:
    """Evaluate a bounded approved sample without retaining provider payloads."""

    VERSION = "coresignal-internal-evaluator-v1"

    def __init__(
        self, *, transport: Transport, store: CoresignalEvaluationStore,
        pseudonym_secret: bytes, api_token: str, clock: Callable[[], datetime],
        source_verifier: Callable[[EvaluationCandidate], bool],
        sleeper: Callable[[float], None] = lambda _seconds: None,
    ) -> None:
        if not pseudonym_secret or not api_token or not callable(source_verifier):
            raise ValueError("Coresignal evaluation secret and token are required")
        self.transport = transport
        self.store = store
        self.secret = pseudonym_secret
        self.api_token = api_token
        self.clock = clock
        self.source_verifier = source_verifier
        self.sleeper = sleeper

    def _evidence_ref(self, candidate: EvaluationCandidate) -> str:
        material = (
            f"{self.VERSION}:{candidate.subject_ref}:{candidate.source_record_ref}:"
            f"{candidate.linkedin_url}"
        ).encode("utf-8")
        return "evidence:coresignal:" + hmac.new(
            self.secret, material, hashlib.sha256,
        ).hexdigest()

    def _fetch(self, candidate: EvaluationCandidate) -> tuple[str, dict[str, object]]:
        query = urlencode([("fields", field) for field in _CORESIGNAL_FIELDS])
        url = (
            _CORESIGNAL_ENDPOINT + "/"
            + quote(_profile_shorthand(candidate.linkedin_url), safe="") + "?" + query
        )

        def request() -> tuple[str, dict[str, object]]:
            response = self.transport.request(
                "GET", url, headers={"apikey": self.api_token, "Accept": "application/json"},
                timeout=10.0, max_bytes=262144,
            )
            if response.status == 429:
                raise _DefinitiveProviderFailure(
                    "Coresignal evaluation request failed with status 429"
                )
            if response.status >= 500:
                raise RetryableTransportError("Coresignal unavailable")
            evidence_ref = self._evidence_ref(candidate)
            if response.status == 404:
                return "not_found", dict(_UNKNOWN_FACTS)
            if response.status == 402:
                raise _DefinitiveProviderFailure(
                    "Coresignal evaluation request failed with status 402"
                )
            if response.status != 200:
                raise _DefinitiveProviderFailure(
                    f"Coresignal evaluation request failed with status {response.status}"
                )
            try:
                payload = json.loads(response.body)
                normalized = normalize_coresignal_payload(payload, evidence_ref=evidence_ref)
            except (TypeError, ValueError, json.JSONDecodeError) as error:
                raise ValueError("Coresignal evaluation response failed schema validation") from error
            facts = {key: normalized[key] for key in CoresignalEvaluationStore._FACT_KEYS}
            return "observed", facts

        # A lost response can still represent a successfully billed collect.
        # Never retry automatically because doing so could spend a second credit
        # and bypass the per-transport approval/provenance check.
        return request()

    def evaluate(
        self, candidates: Iterable[EvaluationCandidate], *,
        approval: CoresignalEvaluationApproval,
        max_new_records: int | None = None,
    ) -> dict[str, object]:
        materialized = tuple(candidates)
        if any(self.source_verifier(candidate) is not True for candidate in materialized):
            raise PermissionError("Coresignal evaluation applicant-source evidence was not verified")
        if (
            max_new_records is not None
            and (type(max_new_records) is not int or not 1 <= max_new_records <= approval.sample_limit)
        ):
            raise ValueError("Coresignal evaluation canary size is invalid")
        authorization_hash = self.store.write_approval(approval, now=self.clock())
        plan = build_evaluation_plan(materialized, approval=approval, now=self.clock())
        records: list[dict[str, object]] = []
        created = 0
        for candidate in plan:
            existing = self.store.get(
                candidate.subject_ref, approval_sha256=authorization_hash,
            )
            if existing is not None:
                self.store.clear_attempt(candidate.subject_ref)
                records.append(existing)
                continue
            if max_new_records is not None and created >= max_new_records:
                continue
            current_hash = approval.authorization_hash(now=self.clock())
            if (
                not hmac.compare_digest(current_hash, authorization_hash)
                or self.source_verifier(candidate) is not True
            ):
                raise PermissionError("Coresignal evaluation authorization or provenance expired")
            self.store.assert_retry_safe(candidate.subject_ref)
            self.store.begin_attempt(
                candidate=candidate, approval_sha256=authorization_hash,
                retention_days=approval.retention_days,
            )
            try:
                outcome, facts = self._fetch(candidate)
            except _DefinitiveProviderFailure:
                self.store.clear_attempt(candidate.subject_ref)
                raise
            record = self.store.put(
                candidate=candidate, approval_sha256=authorization_hash,
                outcome=outcome, evidence_ref=self._evidence_ref(candidate), facts=facts,
                retention_days=approval.retention_days,
            )
            self.store.clear_attempt(candidate.subject_ref)
            records.append(record)
            created += 1

        priority = {name: 0 for name in _PRIORITY}
        coverage = {
            "company_category_known": 0,
            "founder_history": 0,
            "seniority_known": 0,
            "software_engineering_title": 0,
        }
        for record in records:
            priority[str(record["priority"])] += 1
            facts = record["facts"]
            if not isinstance(facts, dict):
                raise PermissionError("Coresignal evaluation facts are invalid")
            coverage["company_category_known"] += facts["company_category"] != "unknown"
            coverage["founder_history"] += facts["founder_history"] is True
            coverage["seniority_known"] += facts["seniority"] != "unknown"
            coverage["software_engineering_title"] += facts["title_category"] == "software_engineering"
        report = {
            "approval_sha256": authorization_hash,
            "attempted": len(records),
            "coverage": coverage,
            "evaluation_version": approval.evaluation_version,
            "expires_at": _utc_timestamp(self.clock() + timedelta(days=approval.retention_days)),
            "generated_at": _utc_timestamp(self.clock()),
            "not_found": sum(record["outcome"] == "not_found" for record in records),
            "observed": sum(record["outcome"] == "observed" for record in records),
            "priority": priority,
            "report_version": self.store.REPORT_VERSION,
        }
        self.store.write_report(report)
        return report
