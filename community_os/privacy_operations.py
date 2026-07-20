"""Machine-enforced privacy operations. This module does not assert legal compliance."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
import hashlib
import hmac
import json
import re


_CODE = re.compile(r"^[a-z][a-z0-9_]{1,63}$")
_PSEUDONYM = re.compile(r"^(?:psn_[a-z0-9_]{1,64}|pid:[A-Za-z0-9._-]{1,32}:[0-9a-f]{64})$")
_RESOURCE = re.compile(r"^(?!/)(?!.*\.\.)(?!.*[@\s])[A-Za-z0-9_./-]{1,240}$")
_SURFACES = frozenset({"classification", "aggregate", "html", "pdf"})
_AUTHENTICATED_PUBLICATION_ACTOR = re.compile(
    r"^(?:release_owner|colleague_[0-9a-f]{32})$",
)


def _code(value: str, field: str) -> str:
    if not isinstance(value, str) or not _CODE.fullmatch(value):
        raise ValueError(f"{field} must be a machine-readable code")
    return value


def _aware(value: datetime, field: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field} must be timezone-aware")
    return value


@dataclass(frozen=True)
class SubjectExclusionPlan:
    """A deterministic, identifier-free record of reviewed subject exclusions."""

    allowed_subject_refs: frozenset[str]
    excluded_count: int
    exclusion_set_sha256: str

    @property
    def audit_record(self) -> dict[str, object]:
        return {
            "action": "subject_exclusions_propagated",
            "excluded_count": self.excluded_count,
            "exclusion_set_sha256": self.exclusion_set_sha256,
            "reason_code": "rights_request",
        }


def build_subject_exclusion_plan(
    *, excluded_subject_refs: Iterable[str], known_subject_refs: Iterable[str],
) -> SubjectExclusionPlan:
    """Validate exact pseudonyms and expose only a count and set hash as evidence."""

    known = tuple(known_subject_refs)
    excluded = tuple(excluded_subject_refs)
    if any(not isinstance(value, str) or not _PSEUDONYM.fullmatch(value) for value in (*known, *excluded)):
        raise ValueError("subject reference is malformed")
    if len(set(known)) != len(known) or len(set(excluded)) != len(excluded):
        raise ValueError("subject reference is duplicated")
    unknown = set(excluded).difference(known)
    if unknown:
        raise ValueError("excluded subject reference is unknown")
    canonical = json.dumps(sorted(excluded), ensure_ascii=True, separators=(",", ":"))
    return SubjectExclusionPlan(
        allowed_subject_refs=frozenset(set(known).difference(excluded)),
        excluded_count=len(excluded),
        exclusion_set_sha256=hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
    )


class DataClass(Enum):
    RAW_ENRICHMENT = "raw_enrichment"
    ENRICHMENT_CACHE = "enrichment_cache"
    RAW_SOURCE = "raw_source"
    CLASSIFICATION = "classification"
    AGGREGATE = "aggregate"


DELETABLE_DATA_CLASSES = frozenset(
    item for item in DataClass
    if item.value.startswith("raw_") or item.value.endswith("_cache")
)


@dataclass(frozen=True)
class UseApproval:
    source: str
    purpose: str
    use: str
    owner_code: str
    actor_code: str
    approved_at: datetime
    expires_at: datetime

    def __post_init__(self) -> None:
        for field in ("source", "purpose", "use", "owner_code", "actor_code"):
            object.__setattr__(self, field, _code(getattr(self, field), field))
        _aware(self.approved_at, "approved_at")
        _aware(self.expires_at, "expires_at")
        if self.expires_at <= self.approved_at:
            raise ValueError("approval expiry must follow approval time")


@dataclass(frozen=True)
class DataAsset:
    asset_id: str
    version: str
    pseudonym: str
    source: str
    purpose: str
    accountable_owner: str
    retention_deadline: datetime
    allowed_uses: frozenset[str]
    data_class: DataClass
    storage_scope: str
    resource_ref: str

    def __post_init__(self) -> None:
        for field in ("asset_id", "version", "source", "purpose", "accountable_owner", "storage_scope"):
            object.__setattr__(self, field, _code(getattr(self, field), field))
        if not _PSEUDONYM.fullmatch(self.pseudonym):
            raise ValueError("pseudonym must be a supported pseudonymous identifier")
        if not _RESOURCE.fullmatch(self.resource_ref):
            raise ValueError("resource_ref must be a protected relative locator")
        _aware(self.retention_deadline, "retention_deadline")
        if not isinstance(self.data_class, DataClass):
            raise ValueError("data_class must be a DataClass")
        if not isinstance(self.allowed_uses, frozenset) or not self.allowed_uses:
            raise ValueError("allowed_uses must be a nonempty frozenset")
        normalized = frozenset(_code(value, "allowed_uses") for value in self.allowed_uses)
        object.__setattr__(self, "allowed_uses", normalized)

    @property
    def source_purpose_code(self) -> str:
        return f"{self.source}:{self.purpose}"

    def may_use(
        self, use: str, now: datetime, *, owner_code: str,
        approval: UseApproval | None, registry: "ExclusionRegistry",
    ) -> bool:
        try:
            requested = _code(use, "use")
            owner = _code(owner_code, "owner_code")
            _aware(now, "now")
        except ValueError:
            return False
        return bool(
            requested in self.allowed_uses
            and owner == self.accountable_owner
            and self.retention_deadline > now
            and not registry.is_excluded(self.pseudonym)
            and approval is not None
            and approval.source == self.source
            and approval.purpose == self.purpose
            and approval.use == requested
            and approval.owner_code == owner
            and approval.approved_at <= now < approval.expires_at
        )


@dataclass(frozen=True)
class RightsState:
    pseudonym: str
    notice_version: str
    notice_sent_at: datetime
    objection_status: str
    exclusion_status: str
    suppression_status: str
    deletion_status: str
    reconciled: bool

    def __post_init__(self) -> None:
        if not _PSEUDONYM.fullmatch(self.pseudonym):
            raise ValueError("pseudonym must be a supported pseudonymous identifier")
        _code(self.notice_version, "notice_version")
        _aware(self.notice_sent_at, "notice_sent_at")
        choices = {
            "objection_status": {"none", "received", "resolved"},
            "exclusion_status": {"included", "excluded"},
            "suppression_status": {"not_requested", "requested", "propagated"},
            "deletion_status": {"not_requested", "requested", "completed"},
        }
        for field, allowed in choices.items():
            if getattr(self, field) not in allowed:
                raise ValueError(f"{field} is invalid")
        if not isinstance(self.reconciled, bool):
            raise ValueError("reconciled must be boolean")


class ExclusionRegistry:
    def __init__(self) -> None:
        self._history: dict[str, list[RightsState]] = {}

    def record(self, state: RightsState) -> None:
        history = self._history.setdefault(state.pseudonym, [])
        if history:
            previous = history[-1]
            ranks = {
                "objection_status": {"none": 0, "received": 1, "resolved": 2},
                "exclusion_status": {"included": 0, "excluded": 1},
                "suppression_status": {"not_requested": 0, "requested": 1, "propagated": 2},
                "deletion_status": {"not_requested": 0, "requested": 1, "completed": 2},
            }
            monotonic = state.notice_sent_at > previous.notice_sent_at and all(
                ranks[field][getattr(state, field)] >= ranks[field][getattr(previous, field)]
                for field in ranks
            )
            if not monotonic:
                raise ValueError("rights state transitions must be monotonic")
        history.append(state)

    def history(self, pseudonym: str) -> tuple[RightsState, ...]:
        return tuple(self._history.get(pseudonym, ()))

    def current(self, pseudonym: str) -> RightsState | None:
        history = self._history.get(pseudonym)
        return history[-1] if history else None

    def is_excluded(self, pseudonym: str) -> bool:
        state = self.current(pseudonym)
        if state is None:
            return True
        return bool(
            not state.reconciled
            or state.objection_status == "received"
            or state.exclusion_status == "excluded"
            or state.suppression_status in {"requested", "propagated"}
            or state.deletion_status in {"requested", "completed"}
        )

    def publishable_members(self, surface: str, pseudonyms: Iterable[str]) -> frozenset[str]:
        if surface not in _SURFACES:
            raise ValueError("surface is not publishable")
        return frozenset(value for value in pseudonyms if not self.is_excluded(value))


@dataclass(frozen=True)
class PseudonymousAuditEvent:
    run_id: str
    asset_id: str
    asset_version: str
    pseudonym: str
    actor_code: str
    reason_code: str
    timestamp: datetime
    action: str
    source_code: str
    purpose_code: str

    def __post_init__(self) -> None:
        for field in (
            "run_id", "asset_id", "asset_version", "actor_code", "reason_code",
            "action", "source_code", "purpose_code",
        ):
            object.__setattr__(self, field, _code(getattr(self, field), field))
        if not _PSEUDONYM.fullmatch(self.pseudonym):
            raise ValueError("pseudonym must be a supported pseudonymous identifier")
        _aware(self.timestamp, "timestamp")


class PseudonymousAuditLog:
    def __init__(self) -> None:
        self._events: list[PseudonymousAuditEvent] = []

    def append(self, event: PseudonymousAuditEvent) -> None:
        self._events.append(event)

    @property
    def events(self) -> tuple[PseudonymousAuditEvent, ...]:
        return tuple(self._events)


@dataclass(frozen=True)
class CleanupReport:
    deleted_count: int
    retained_count: int
    audit_events: tuple[PseudonymousAuditEvent, ...]

    def __post_init__(self) -> None:
        if self.deleted_count < 0 or self.retained_count < 0:
            raise ValueError("cleanup counts cannot be negative")
        if self.deleted_count != len(self.audit_events):
            raise ValueError("cleanup deletion count must match its audit evidence")


def delete_expired_assets(
    assets: Iterable[DataAsset], *, now: datetime,
    deleters: Mapping[str, Callable[[str], None]], run_id: str,
    actor_code: str, reason_code: str,
) -> CleanupReport:
    _aware(now, "now")
    run_id = _code(run_id, "run_id")
    actor_code = _code(actor_code, "actor_code")
    reason_code = _code(reason_code, "reason_code")
    materialized = tuple(assets)
    expired = tuple(
        item for item in materialized
        if item.retention_deadline <= now and item.data_class in DELETABLE_DATA_CLASSES
    )
    missing = sorted({item.storage_scope for item in expired if item.storage_scope not in deleters})
    if missing:
        raise RuntimeError("no deleter configured for storage scope " + ",".join(missing))
    events: list[PseudonymousAuditEvent] = []
    for item in expired:
        deleters[item.storage_scope](item.resource_ref)
        events.append(PseudonymousAuditEvent(
            run_id=run_id, asset_id=item.asset_id, asset_version=item.version,
            pseudonym=item.pseudonym, actor_code=actor_code,
            reason_code=reason_code, timestamp=now, action="asset_deleted",
            source_code=item.source, purpose_code=item.purpose,
        ))
    return CleanupReport(
        deleted_count=len(expired), retained_count=len(materialized) - len(expired),
        audit_events=tuple(events),
    )


@dataclass(frozen=True)
class PrivacyParityRecord:
    classification_members: frozenset[str]
    aggregate_members: frozenset[str]
    html_members: frozenset[str]
    pdf_members: frozenset[str]

    def is_equal(self) -> bool:
        return len({self.classification_members, self.aggregate_members, self.html_members, self.pdf_members}) == 1


@dataclass(frozen=True)
class ReviewRecord:
    review_code: str
    resolved: bool

    def __post_init__(self) -> None:
        _code(self.review_code, "review_code")
        if not isinstance(self.resolved, bool):
            raise ValueError("resolved must be boolean")


@dataclass(frozen=True)
class PublicationApproval:
    report_hash: str
    actor_code: str
    approved_at: datetime

    def __post_init__(self) -> None:
        if not re.fullmatch(r"[0-9a-f]{64}", self.report_hash):
            raise ValueError("report_hash must be SHA-256")
        _code(self.actor_code, "actor_code")
        _aware(self.approved_at, "approved_at")


@dataclass(frozen=True)
class ReleaseEvidence:
    inventory: tuple[DataAsset, ...]
    registry: ExclusionRegistry
    approvals: tuple[UseApproval, ...]
    cleanup_report: CleanupReport | None
    parity: PrivacyParityRecord
    reviews: tuple[ReviewRecord, ...]
    publication_approval: PublicationApproval | None
    report_hash: str
    report_generated_at: datetime

    def __post_init__(self) -> None:
        if not re.fullmatch(r"[0-9a-f]{64}", self.report_hash):
            raise ValueError("release report_hash must be SHA-256")
        _aware(self.report_generated_at, "report_generated_at")


class ReleaseState(Enum):
    BLOCKED = "Blocked"
    NEEDS_REVIEW = "Needs review"
    SAFE_TO_PUBLISH = "Safe to publish"


def evaluate_release(evidence: ReleaseEvidence, *, now: datetime) -> ReleaseState:
    _aware(now, "now")
    approval_index = {
        (item.source, item.purpose, item.use, item.owner_code): item
        for item in evidence.approvals
    }
    asset_keys = {(asset.asset_id, asset.version) for asset in evidence.inventory}
    if len(asset_keys) != len(evidence.inventory):
        return ReleaseState.BLOCKED
    publish_use_authorized = False
    for asset in evidence.inventory:
        if asset.retention_deadline <= now:
            deleted = evidence.cleanup_report and any(
                event.asset_id == asset.asset_id
                and event.asset_version == asset.version
                and event.pseudonym == asset.pseudonym
                and event.action == "asset_deleted"
                for event in evidence.cleanup_report.audit_events
            )
            if not deleted:
                return ReleaseState.BLOCKED
            continue
        if evidence.registry.is_excluded(asset.pseudonym):
            return ReleaseState.BLOCKED
        if not any(
            asset.may_use(
                use, now, owner_code=asset.accountable_owner,
                approval=approval_index.get((asset.source, asset.purpose, use, asset.accountable_owner)),
                registry=evidence.registry,
            )
            for use in asset.allowed_uses
        ):
            return ReleaseState.BLOCKED
        if asset.data_class is DataClass.AGGREGATE and "publish" in asset.allowed_uses:
            publish_use_authorized = publish_use_authorized or asset.may_use(
                "publish", now, owner_code=asset.accountable_owner,
                approval=approval_index.get((asset.source, asset.purpose, "publish", asset.accountable_owner)),
                registry=evidence.registry,
            )
    if not publish_use_authorized:
        return ReleaseState.BLOCKED
    if not evidence.parity.is_equal():
        return ReleaseState.BLOCKED
    members = evidence.parity.aggregate_members
    if evidence.registry.publishable_members("aggregate", members) != members:
        return ReleaseState.BLOCKED
    if any(not item.resolved for item in evidence.reviews):
        return ReleaseState.NEEDS_REVIEW
    approval = evidence.publication_approval
    if approval is None:
        return ReleaseState.NEEDS_REVIEW
    if (
        _AUTHENTICATED_PUBLICATION_ACTOR.fullmatch(approval.actor_code) is None
        or approval.approved_at < evidence.report_generated_at
        or approval.approved_at > now
        or not hmac.compare_digest(approval.report_hash, evidence.report_hash)
    ):
        return ReleaseState.BLOCKED
    return ReleaseState.SAFE_TO_PUBLISH
