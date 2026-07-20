"""Strict, immutable configuration for one reusable event release."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
import hashlib
import hmac
import json
from pathlib import Path
import re
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


_REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
_MAPPING_ROOT = (_REPOSITORY_ROOT / "mappings").resolve()
_HASH = re.compile(r"[0-9a-f]{64}")
_KEY = re.compile(r"[a-z][a-z0-9_]*")
_VERSIONED_ID = re.compile(r"[a-z0-9]+(?:[._-][a-z0-9]+)*-v[1-9][0-9]*")
_MEDIA_TYPE = re.compile(r"[a-z0-9][a-z0-9.+-]*/[a-z0-9][a-z0-9.+-]*")

_REPORT_FAMILIES = frozenset({"hackathon-partner-talent-v1"})
_ARTIFACT_PROFILES = frozenset({"partner-brief-five-page-landscape-v1"})
_POLICY_PROFILES = frozenset({"aggregate-partner-v1"})
_STABLE_ID_STRATEGIES = frozenset({"provider_id", "canonical_content_key"})
_FUNNEL_STAGES = ("applied", "accepted", "present")
_REQUIRED_SOURCE_ROLES = frozenset({"applications", "attendance"})


class EventDefinitionError(ValueError):
    """Raised when an event definition is incomplete, ambiguous, or unsafe."""


@dataclass(frozen=True)
class EventPrivacy:
    minimum_count: int
    policy_profile: str


@dataclass(frozen=True)
class EventSemanticVersions:
    taxonomy_version: str
    metric_registry_version: str


@dataclass(frozen=True)
class EventSource:
    role: str
    required: bool
    adapter_id: str
    media_type: str
    mapping_path: Path
    mapping_sha256: str
    mapping_fields: frozenset[str]
    sheets: tuple[str, ...]
    stable_id_strategy: str


@dataclass(frozen=True)
class FunnelStage:
    stage: str
    source_role: str
    field: str | None
    match: str
    accepted_values: tuple[str, ...]


@dataclass(frozen=True)
class EventDefinition:
    version: str
    event_key: str
    event_name: str
    starts_on: date
    ends_on: date
    timezone: str
    event_type: str
    report_family: str
    privacy: EventPrivacy
    sources: tuple[EventSource, ...]
    funnel: tuple[FunnelStage, ...]
    semantic: EventSemanticVersions
    artifact_profile: str
    sha256: str

    def source(self, role: str) -> EventSource:
        """Return one configured source role without exposing a mutable index."""

        for source in self.sources:
            if source.role == role:
                return source
        raise EventDefinitionError(f"event source is not configured: {role}")

    def funnel_stage(self, stage: str) -> FunnelStage:
        """Return one required funnel stage."""

        for item in self.funnel:
            if item.stage == stage:
                return item
        raise EventDefinitionError(f"funnel stage is not configured: {stage}")


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise EventDefinitionError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _reject_nonfinite(value: str) -> None:
    raise EventDefinitionError(f"non-finite JSON value is forbidden: {value}")


def _exact_object(value: object, *, label: str, keys: frozenset[str]) -> dict[str, object]:
    if not isinstance(value, dict):
        raise EventDefinitionError(f"{label} must be an object")
    missing = sorted(keys - value.keys())
    unknown = sorted(value.keys() - keys)
    if missing or unknown:
        details: list[str] = []
        if missing:
            details.append("missing " + ", ".join(missing))
        if unknown:
            details.append("unknown " + ", ".join(unknown))
        raise EventDefinitionError(f"{label} has invalid keys: {'; '.join(details)}")
    return value


def _string(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise EventDefinitionError(f"{label} must be a non-empty trimmed string")
    return value


def _versioned_id(value: object, *, label: str) -> str:
    identifier = _string(value, label=label)
    if not _VERSIONED_ID.fullmatch(identifier):
        raise EventDefinitionError(f"{label} must be a lowercase versioned identifier")
    return identifier


def _event_date(value: object, *, label: str) -> date:
    raw = _string(value, label=label)
    if not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", raw):
        raise EventDefinitionError(f"{label} must use YYYY-MM-DD")
    try:
        return date.fromisoformat(raw)
    except ValueError as error:
        raise EventDefinitionError(f"{label} is not a valid date") from error


def _mapping_path(value: object, *, label: str) -> Path:
    raw = _string(value, label=label)
    relative = Path(raw)
    if (
        relative.is_absolute()
        or relative.suffix != ".json"
        or not relative.parts
        or relative.parts[0] != "mappings"
        or any(part in {"", ".", ".."} for part in relative.parts)
    ):
        raise EventDefinitionError(f"{label} must be a repository-relative mappings/*.json path")
    candidate = _REPOSITORY_ROOT / relative
    if not candidate.is_file():
        raise EventDefinitionError(f"{label} does not exist: {raw}")
    resolved = candidate.resolve()
    if not resolved.is_relative_to(_MAPPING_ROOT):
        raise EventDefinitionError(f"{label} resolves outside the mapping directory")
    return resolved


def _mapping_contract(
    value: object, *, label: str, path: Path,
) -> tuple[str, frozenset[str]]:
    expected = _string(value, label=label)
    if not _HASH.fullmatch(expected):
        raise EventDefinitionError(f"{label} must be a lowercase SHA-256")
    try:
        payload = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite,
        )
    except (OSError, json.JSONDecodeError) as error:
        raise EventDefinitionError(f"{label} mapping is unreadable") from error
    if not isinstance(payload, dict) or not isinstance(payload.get("field_map"), dict):
        raise EventDefinitionError(f"{label} mapping has no field_map")
    field_map = payload["field_map"]
    if not field_map or any(
        not isinstance(key, str)
        or not _KEY.fullmatch(key)
        or not isinstance(source, str)
        or not source.strip()
        for key, source in field_map.items()
    ):
        raise EventDefinitionError(f"{label} mapping field_map is invalid")
    canonical = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")
    actual = hashlib.sha256(canonical).hexdigest()
    if not hmac.compare_digest(expected, actual):
        raise EventDefinitionError(f"{label} does not match {path.relative_to(_REPOSITORY_ROOT)}")
    return expected, frozenset(field_map)


def _sheets(value: object, *, label: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise EventDefinitionError(f"{label} must be a list")
    sheets: list[str] = []
    for index, item in enumerate(value):
        sheet = _string(item, label=f"{label}[{index}]")
        if len(sheet) > 128 or any(character in sheet for character in ("/", "\\")):
            raise EventDefinitionError(f"{label}[{index}] is not a safe sheet selector")
        if any(ord(character) < 32 for character in sheet):
            raise EventDefinitionError(f"{label}[{index}] contains a control character")
        sheets.append(sheet)
    if len(sheets) != len(set(sheets)):
        raise EventDefinitionError(f"{label} contains duplicates")
    return tuple(sheets)


def _load_source(value: object, *, index: int) -> EventSource:
    label = f"sources[{index}]"
    raw = _exact_object(
        value,
        label=label,
        keys=frozenset({
            "role", "required", "adapter_id", "media_type", "mapping_path",
            "mapping_sha256", "sheets", "stable_id_strategy",
        }),
    )
    role = _string(raw["role"], label=f"{label}.role")
    if not _KEY.fullmatch(role):
        raise EventDefinitionError(f"{label}.role must be a lowercase key")
    required = raw["required"]
    if not isinstance(required, bool):
        raise EventDefinitionError(f"{label}.required must be a boolean")
    adapter_id = _versioned_id(raw["adapter_id"], label=f"{label}.adapter_id")
    media_type = _string(raw["media_type"], label=f"{label}.media_type")
    if not _MEDIA_TYPE.fullmatch(media_type):
        raise EventDefinitionError(f"{label}.media_type is invalid")
    mapping_path = _mapping_path(raw["mapping_path"], label=f"{label}.mapping_path")
    mapping_sha256, mapping_fields = _mapping_contract(
        raw["mapping_sha256"], label=f"{label}.mapping_sha256", path=mapping_path,
    )
    stable_id_strategy = _string(
        raw["stable_id_strategy"], label=f"{label}.stable_id_strategy",
    )
    if stable_id_strategy not in _STABLE_ID_STRATEGIES:
        raise EventDefinitionError(
            f"{label}.stable_id_strategy must be provider_id or canonical_content_key",
        )
    return EventSource(
        role=role,
        required=required,
        adapter_id=adapter_id,
        media_type=media_type,
        mapping_path=mapping_path,
        mapping_sha256=mapping_sha256,
        mapping_fields=mapping_fields,
        sheets=_sheets(raw["sheets"], label=f"{label}.sheets"),
        stable_id_strategy=stable_id_strategy,
    )


def _load_funnel(
    value: object, *, sources_by_role: dict[str, EventSource],
) -> tuple[FunnelStage, ...]:
    if not isinstance(value, list):
        raise EventDefinitionError("funnel must be a list")
    stages: list[FunnelStage] = []
    for index, item in enumerate(value):
        label = f"funnel[{index}]"
        raw = _exact_object(
            item,
            label=label,
            keys=frozenset({"stage", "source_role", "field", "match", "accepted_values"}),
        )
        stage = _string(raw["stage"], label=f"{label}.stage")
        source_role = _string(raw["source_role"], label=f"{label}.source_role")
        if source_role not in sources_by_role:
            raise EventDefinitionError(f"{label}.source_role is not configured: {source_role}")
        match = _string(raw["match"], label=f"{label}.match")
        if match not in {"any_row", "value_in", "non_empty"}:
            raise EventDefinitionError(f"{label}.match is unsupported")
        field_value = raw["field"]
        field = None if field_value is None else _string(field_value, label=f"{label}.field")
        values_value = raw["accepted_values"]
        if not isinstance(values_value, list) or not all(
            isinstance(item, str) and item.strip() and item == item.strip()
            for item in values_value
        ):
            raise EventDefinitionError(f"{label}.accepted_values must be a trimmed string list")
        accepted_values = tuple(values_value)
        if len(accepted_values) != len(set(accepted_values)):
            raise EventDefinitionError(f"{label}.accepted_values contains duplicates")
        if match == "any_row" and (field is not None or accepted_values):
            raise EventDefinitionError(f"{label} any_row matching takes no field or values")
        if match == "value_in" and (field is None or not accepted_values):
            raise EventDefinitionError(f"{label} value_in matching requires a field and values")
        if match == "non_empty" and (field is None or accepted_values):
            raise EventDefinitionError(f"{label} non_empty matching requires only a field")
        if field is not None and field not in sources_by_role[source_role].mapping_fields:
            raise EventDefinitionError(
                f"{label}.field is not a canonical mapping field for {source_role}: {field}",
            )
        stages.append(FunnelStage(stage, source_role, field, match, accepted_values))
    if tuple(item.stage for item in stages) != _FUNNEL_STAGES:
        raise EventDefinitionError(
            "funnel stages must appear exactly once in applied, accepted, present order",
        )
    return tuple(stages)


def load_event_definition(path: str | Path) -> EventDefinition:
    """Load one strict event-release-v1 definition and bind it to mapping bytes."""

    definition_path = Path(path)
    try:
        payload = json.loads(
            definition_path.read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite,
        )
    except (OSError, json.JSONDecodeError) as error:
        raise EventDefinitionError(f"cannot load event definition {definition_path}: {error}") from error
    raw = _exact_object(
        payload,
        label="event definition",
        keys=frozenset({
            "version", "event", "report_family", "privacy", "sources", "funnel",
            "semantic", "artifact_profile",
        }),
    )
    if raw["version"] != "event-release-v1":
        raise EventDefinitionError("version must be event-release-v1")

    event = _exact_object(
        raw["event"],
        label="event",
        keys=frozenset({"key", "name", "starts_on", "ends_on", "timezone", "type"}),
    )
    event_key = _string(event["key"], label="event.key")
    if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", event_key):
        raise EventDefinitionError("event.key must be a lowercase slug")
    event_name = _string(event["name"], label="event.name")
    starts_on = _event_date(event["starts_on"], label="event.starts_on")
    ends_on = _event_date(event["ends_on"], label="event.ends_on")
    if ends_on < starts_on:
        raise EventDefinitionError("event.ends_on cannot precede event.starts_on")
    timezone = _string(event["timezone"], label="event.timezone")
    try:
        ZoneInfo(timezone)
    except (ZoneInfoNotFoundError, ValueError) as error:
        raise EventDefinitionError("event.timezone must be an IANA timezone") from error
    if event["type"] != "hackathon":
        raise EventDefinitionError("event.type must be hackathon")

    report_family = _string(raw["report_family"], label="report_family")
    if report_family not in _REPORT_FAMILIES:
        raise EventDefinitionError(f"unsupported report_family: {report_family}")

    privacy_raw = _exact_object(
        raw["privacy"],
        label="privacy",
        keys=frozenset({"minimum_count", "policy_profile"}),
    )
    minimum_count = privacy_raw["minimum_count"]
    if isinstance(minimum_count, bool) or not isinstance(minimum_count, int) or minimum_count < 5:
        raise EventDefinitionError("privacy.minimum_count must be an integer of at least 5")
    policy_profile = _string(privacy_raw["policy_profile"], label="privacy.policy_profile")
    if policy_profile not in _POLICY_PROFILES:
        raise EventDefinitionError(f"unsupported privacy.policy_profile: {policy_profile}")
    privacy = EventPrivacy(minimum_count, policy_profile)

    sources_value = raw["sources"]
    if not isinstance(sources_value, list) or not sources_value:
        raise EventDefinitionError("sources must be a non-empty list")
    sources = tuple(_load_source(item, index=index) for index, item in enumerate(sources_value))
    source_roles = tuple(source.role for source in sources)
    if len(source_roles) != len(set(source_roles)):
        raise EventDefinitionError("sources contains duplicate roles")
    sources_by_role = {source.role: source for source in sources}
    missing_sources = sorted(_REQUIRED_SOURCE_ROLES - sources_by_role.keys())
    if missing_sources:
        raise EventDefinitionError("missing required source roles: " + ", ".join(missing_sources))
    optional_required = sorted(
        role for role in _REQUIRED_SOURCE_ROLES if not sources_by_role[role].required
    )
    if optional_required:
        raise EventDefinitionError(
            "required source roles cannot be optional: " + ", ".join(optional_required),
        )

    funnel = _load_funnel(raw["funnel"], sources_by_role=sources_by_role)

    semantic_raw = _exact_object(
        raw["semantic"],
        label="semantic",
        keys=frozenset({"taxonomy_version", "metric_registry_version"}),
    )
    semantic = EventSemanticVersions(
        taxonomy_version=_versioned_id(
            semantic_raw["taxonomy_version"], label="semantic.taxonomy_version",
        ),
        metric_registry_version=_versioned_id(
            semantic_raw["metric_registry_version"], label="semantic.metric_registry_version",
        ),
    )
    artifact_profile = _string(raw["artifact_profile"], label="artifact_profile")
    if artifact_profile not in _ARTIFACT_PROFILES:
        raise EventDefinitionError(f"unsupported artifact_profile: {artifact_profile}")

    canonical = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")
    return EventDefinition(
        version="event-release-v1",
        event_key=event_key,
        event_name=event_name,
        starts_on=starts_on,
        ends_on=ends_on,
        timezone=timezone,
        event_type="hackathon",
        report_family=report_family,
        privacy=privacy,
        sources=sources,
        funnel=funnel,
        semantic=semantic,
        artifact_profile=artifact_profile,
        sha256=hashlib.sha256(canonical).hexdigest(),
    )
