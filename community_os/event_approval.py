"""Strict approval binding for one configured event release."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import hashlib
import hmac
import json
from pathlib import Path
import re
from typing import Iterable, Mapping

from community_os.event_definition import EventDefinition


_HASH = re.compile(r"[0-9a-f]{64}")
_ACTOR = re.compile(r"[a-z][a-z0-9_]{2,63}")
_PSEUDONYM = re.compile(r"(?:psn_[a-z0-9_]{1,64}|pid:[A-Za-z0-9._-]{1,32}:[0-9a-f]{64})")
_TOP_LEVEL_KEYS = frozenset({
    "version",
    "event_key",
    "event_definition_sha256",
    "policy_profile",
    "taxonomy_version",
    "metric_registry_version",
    "sources",
    "excluded_subject_refs",
    "actor_code",
    "approved_at",
})
_SOURCE_KEYS = frozenset({"adapter_id", "mapping_sha256", "source_sha256"})


class EventApprovalError(ValueError):
    """An event approval does not match the release it would authorize."""


@dataclass(frozen=True)
class EventSourceApproval:
    role: str
    adapter_id: str
    mapping_sha256: str
    source_sha256: str | None


@dataclass(frozen=True)
class EventApproval:
    version: str
    event_key: str
    event_definition_sha256: str
    policy_profile: str
    taxonomy_version: str
    metric_registry_version: str
    sources: tuple[EventSourceApproval, ...]
    excluded_subject_refs: frozenset[str]
    actor_code: str
    approved_at: datetime
    sha256: str

    def source(self, role: str) -> EventSourceApproval:
        """Return one explicitly bound source role."""

        for source in self.sources:
            if source.role == role:
                return source
        raise EventApprovalError(f"event approval source role is not configured: {role}")


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise EventApprovalError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_nonfinite(value: str) -> None:
    raise EventApprovalError(f"non-finite JSON value is forbidden: {value}")


def _exact_object(
    value: object, *, keys: frozenset[str], label: str,
) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != keys:
        raise EventApprovalError(f"event approval {label} has invalid keys")
    return value


def _hash(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not _HASH.fullmatch(value):
        raise EventApprovalError(f"event approval {label} must be a lowercase SHA-256")
    return value


def _same(actual: object, expected: str, *, label: str) -> str:
    if not isinstance(actual, str) or not hmac.compare_digest(actual, expected):
        raise EventApprovalError(f"event approval {label} does not match")
    return actual


def _source_hashes(
    definition: EventDefinition,
    values: Mapping[str, str | None],
) -> dict[str, str | None]:
    roles = {source.role for source in definition.sources}
    if set(values) != roles:
        raise EventApprovalError("event approval observed source roles do not match")
    result: dict[str, str | None] = {}
    for source in definition.sources:
        digest = values[source.role]
        if digest is None:
            if source.required:
                raise EventApprovalError(
                    f"event approval required source is unavailable: {source.role}"
                )
            result[source.role] = None
        else:
            result[source.role] = _hash(digest, label=f"source hash for {source.role}")
    return result


def _exclusions(values: Iterable[str], *, label: str) -> tuple[str, ...]:
    materialized = tuple(values)
    if any(not isinstance(value, str) or not _PSEUDONYM.fullmatch(value) for value in materialized):
        raise EventApprovalError(f"event approval {label} contains an invalid pseudonym")
    if len(materialized) != len(set(materialized)):
        raise EventApprovalError(f"event approval {label} contains duplicate values")
    return tuple(sorted(materialized))


def validate_event_approval_record(
    payload: object,
    *,
    definition: EventDefinition,
    source_hashes: Mapping[str, str | None],
    excluded_subject_refs: Iterable[str],
) -> EventApproval:
    """Verify one decoded event-approval-v2 against observed release state."""

    raw = _exact_object(payload, keys=_TOP_LEVEL_KEYS, label="keys")
    if raw["version"] != "event-approval-v2":
        raise EventApprovalError("event approval version is unsupported")

    event_key = _same(raw["event_key"], definition.event_key, label="event key")
    definition_sha256 = _hash(
        raw["event_definition_sha256"], label="event definition hash",
    )
    if not hmac.compare_digest(definition_sha256, definition.sha256):
        raise EventApprovalError("event approval event definition does not match")
    policy_profile = _same(
        raw["policy_profile"], definition.privacy.policy_profile, label="policy profile",
    )
    taxonomy_version = _same(
        raw["taxonomy_version"], definition.semantic.taxonomy_version,
        label="taxonomy version",
    )
    metric_registry_version = _same(
        raw["metric_registry_version"], definition.semantic.metric_registry_version,
        label="metrics registry version",
    )

    expected_hashes = _source_hashes(definition, source_hashes)
    source_records = raw["sources"]
    expected_roles = {source.role for source in definition.sources}
    if not isinstance(source_records, dict) or set(source_records) != expected_roles:
        raise EventApprovalError("event approval source roles do not match")
    bound_sources: list[EventSourceApproval] = []
    for source in definition.sources:
        record = _exact_object(
            source_records[source.role], keys=_SOURCE_KEYS,
            label=f"source binding for {source.role}",
        )
        adapter_id = _same(
            record["adapter_id"], source.adapter_id,
            label=f"adapter for {source.role}",
        )
        mapping_sha256 = _hash(
            record["mapping_sha256"], label=f"mapping hash for {source.role}",
        )
        if not hmac.compare_digest(mapping_sha256, source.mapping_sha256):
            raise EventApprovalError(
                f"event approval mapping for {source.role} does not match"
            )
        source_sha256 = record["source_sha256"]
        expected_sha256 = expected_hashes[source.role]
        if source_sha256 is None:
            if source.required:
                raise EventApprovalError(
                    f"event approval required source is unavailable: {source.role}"
                )
            if expected_sha256 is not None:
                raise EventApprovalError(
                    f"event approval source for {source.role} does not match"
                )
        else:
            source_sha256 = _hash(
                source_sha256, label=f"source hash for {source.role}",
            )
            if expected_sha256 is None or not hmac.compare_digest(
                source_sha256, expected_sha256,
            ):
                raise EventApprovalError(
                    f"event approval source for {source.role} does not match"
                )
        bound_sources.append(EventSourceApproval(
            source.role, adapter_id, mapping_sha256, source_sha256,
        ))

    raw_exclusions = raw["excluded_subject_refs"]
    if not isinstance(raw_exclusions, list):
        raise EventApprovalError("event approval exclusion set must be a list")
    approved_exclusions = _exclusions(raw_exclusions, label="exclusion set")
    expected_exclusions = _exclusions(
        excluded_subject_refs, label="expected exclusion set",
    )
    if approved_exclusions != expected_exclusions:
        raise EventApprovalError("event approval exclusion set does not match")

    actor_code = raw["actor_code"]
    if not isinstance(actor_code, str) or not _ACTOR.fullmatch(actor_code):
        raise EventApprovalError("event approval actor code is invalid")
    try:
        approved_at = datetime.fromisoformat(str(raw["approved_at"]).replace("Z", "+00:00"))
    except ValueError as error:
        raise EventApprovalError("event approval timestamp is invalid") from error
    if approved_at.tzinfo is None or approved_at.utcoffset() is None:
        raise EventApprovalError("event approval timestamp requires a timezone")

    canonical = {
        "version": "event-approval-v2",
        "event_key": event_key,
        "event_definition_sha256": definition_sha256,
        "policy_profile": policy_profile,
        "taxonomy_version": taxonomy_version,
        "metric_registry_version": metric_registry_version,
        "sources": {
            source.role: {
                "adapter_id": source.adapter_id,
                "mapping_sha256": source.mapping_sha256,
                "source_sha256": source.source_sha256,
            }
            for source in bound_sources
        },
        "excluded_subject_refs": list(approved_exclusions),
        "actor_code": actor_code,
        "approved_at": approved_at.isoformat(),
    }
    approval_sha256 = hashlib.sha256(json.dumps(
        canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")).hexdigest()
    return EventApproval(
        version="event-approval-v2",
        event_key=event_key,
        event_definition_sha256=definition_sha256,
        policy_profile=policy_profile,
        taxonomy_version=taxonomy_version,
        metric_registry_version=metric_registry_version,
        sources=tuple(bound_sources),
        excluded_subject_refs=frozenset(approved_exclusions),
        actor_code=actor_code,
        approved_at=approved_at,
        sha256=approval_sha256,
    )


def load_event_approval(
    path: str | Path,
    *,
    definition: EventDefinition,
    source_hashes: Mapping[str, str | None],
    excluded_subject_refs: Iterable[str],
) -> EventApproval:
    """Strictly decode and validate one event-approval-v2 file."""

    try:
        payload = json.loads(
            Path(path).read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite,
        )
    except (OSError, json.JSONDecodeError) as error:
        raise EventApprovalError("event approval is missing or unreadable") from error
    return validate_event_approval_record(
        payload,
        definition=definition,
        source_hashes=source_hashes,
        excluded_subject_refs=excluded_subject_refs,
    )
