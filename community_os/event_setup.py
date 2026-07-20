"""Browser-safe setup expansion for supported START hackathon events.

The setup contract intentionally exposes only event metadata, registered profile
identifiers, and workbook sheet selectors. Adapter identifiers, mapping paths,
mapping hashes, and the strict release contract remain server-owned.
"""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass
from datetime import date
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
from typing import NoReturn
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from community_os.event_definition import EventDefinition, load_event_definition


_REPOSITORY_ROOT = Path(__file__).resolve().parent.parent
_MAPPING_ROOT = (_REPOSITORY_ROOT / "mappings").resolve()
_EVENT_KEY = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")
_SETUP_KEYS = frozenset({
    "version", "event", "source_profile", "selected_sheets", "report_profile",
})
_EVENT_KEYS = frozenset({"key", "name", "starts_on", "ends_on", "timezone"})
_WORKBOOK_ROLES = ("preferences", "submissions")


class EventSetupError(ValueError):
    """Raised when browser-supplied setup does not match a registered profile."""


@dataclass(frozen=True)
class _SourceSpec:
    role: str
    required: bool
    adapter_id: str
    media_type: str
    mapping_name: str
    stable_id_strategy: str


_SOURCE_PROFILES: dict[str, tuple[_SourceSpec, ...]] = {
    "start-hackathon-v1": (
        _SourceSpec(
            role="applications",
            required=True,
            adapter_id="luma-csv-v2",
            media_type="text/csv",
            mapping_name="luma-guests-v2.json",
            stable_id_strategy="provider_id",
        ),
        _SourceSpec(
            role="attendance",
            required=True,
            adapter_id="luma-supplement-csv-v1",
            media_type="text/csv",
            mapping_name="luma-supplement-v1.json",
            stable_id_strategy="canonical_content_key",
        ),
        _SourceSpec(
            role="preferences",
            required=True,
            adapter_id="track-preferences-xlsx-v1",
            media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            mapping_name="track-preferences-v1.json",
            stable_id_strategy="provider_id",
        ),
        _SourceSpec(
            role="submissions",
            required=True,
            adapter_id="devpost-final-xlsx-v1",
            media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            mapping_name="devpost-final-v1.json",
            stable_id_strategy="provider_id",
        ),
    ),
}

_REPORT_PROFILES: dict[str, dict[str, object]] = {
    "start-partner-talent-v1": {
        "report_family": "hackathon-partner-talent-v1",
        "privacy": {
            "minimum_count": 5,
            "policy_profile": "aggregate-partner-v1",
        },
        "funnel": [
            {
                "stage": "applied",
                "source_role": "applications",
                "field": None,
                "match": "any_row",
                "accepted_values": [],
            },
            {
                "stage": "accepted",
                "source_role": "attendance",
                "field": "approval_status",
                "match": "value_in",
                "accepted_values": ["approved"],
            },
            {
                "stage": "present",
                "source_role": "attendance",
                "field": "checked_in_at",
                "match": "non_empty",
                "accepted_values": [],
            },
        ],
        "semantic": {
            "taxonomy_version": "semantic-taxonomy-v1",
            "metric_registry_version": "partner-metrics-v1",
        },
        "artifact_profile": "partner-brief-five-page-landscape-v1",
    },
}


def _invalid_keys(
    value: object, *, label: str, expected: frozenset[str],
) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise EventSetupError(f"{label} must be an object")
    keys = set(value)
    missing = sorted(expected - keys)
    unknown = sorted(keys - expected)
    if missing or unknown:
        details: list[str] = []
        if missing:
            details.append("missing " + ", ".join(missing))
        if unknown:
            details.append("unknown " + ", ".join(unknown))
        raise EventSetupError(f"{label} has invalid keys: {'; '.join(details)}")
    if any(not isinstance(key, str) for key in keys):
        raise EventSetupError(f"{label} keys must be strings")
    return value


def _string(value: object, *, label: str, maximum: int = 160) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > maximum
        or any(ord(character) < 32 for character in value)
    ):
        raise EventSetupError(f"{label} must be a bounded trimmed string")
    return value


def _parse_date(value: object, *, label: str) -> date:
    raw = _string(value, label=label, maximum=10)
    if not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", raw):
        raise EventSetupError(f"{label} must use YYYY-MM-DD")
    try:
        return date.fromisoformat(raw)
    except ValueError as error:
        raise EventSetupError(f"{label} is not a valid date") from error


def _event_payload(value: object) -> dict[str, object]:
    event = _invalid_keys(value, label="event", expected=_EVENT_KEYS)
    event_key = _string(event["key"], label="event.key")
    if not _EVENT_KEY.fullmatch(event_key):
        raise EventSetupError("event.key must be a lowercase slug")
    event_name = _string(event["name"], label="event.name")
    starts_on = _parse_date(event["starts_on"], label="event.starts_on")
    ends_on = _parse_date(event["ends_on"], label="event.ends_on")
    if ends_on < starts_on:
        raise EventSetupError("event.ends_on cannot precede event.starts_on")
    timezone = _string(event["timezone"], label="event.timezone")
    try:
        ZoneInfo(timezone)
    except (ZoneInfoNotFoundError, ValueError) as error:
        raise EventSetupError("event.timezone must be an IANA timezone") from error
    return {
        "key": event_key,
        "name": event_name,
        "starts_on": starts_on.isoformat(),
        "ends_on": ends_on.isoformat(),
        "timezone": timezone,
        "type": "hackathon",
    }


def _selected_sheets(value: object) -> dict[str, list[str]]:
    if not isinstance(value, Mapping):
        raise EventSetupError("selected_sheets must be an object")
    expected = frozenset(_WORKBOOK_ROLES)
    unknown = sorted(set(value) - expected)
    if unknown:
        raise EventSetupError(f"unsupported workbook role: {unknown[0]}")
    missing = sorted(expected - set(value))
    if missing:
        raise EventSetupError(f"selected_sheets missing workbook role: {missing[0]}")
    selected = value
    result: dict[str, list[str]] = {}
    for role in _WORKBOOK_ROLES:
        raw_sheets = selected[role]
        if not isinstance(raw_sheets, list) or not raw_sheets:
            raise EventSetupError(f"selected_sheets.{role} must select at least one sheet")
        sheets: list[str] = []
        for index, value in enumerate(raw_sheets):
            try:
                sheet = _string(
                    value,
                    label=f"selected_sheets.{role}[{index}]",
                    maximum=128,
                )
            except EventSetupError as error:
                raise EventSetupError(
                    f"selected_sheets.{role}[{index}] must be a safe sheet name",
                ) from error
            if sheet in {".", ".."} or "/" in sheet or "\\" in sheet:
                raise EventSetupError(
                    f"selected_sheets.{role}[{index}] must be a safe sheet name",
                )
            sheets.append(sheet)
        if len(sheets) != len(set(sheets)):
            raise EventSetupError(f"selected_sheets.{role} contains a duplicate sheet")
        result[role] = sheets
    return result


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise EventSetupError(f"registered mapping contains duplicate key: {key}")
        result[key] = value
    return result


def _reject_nonfinite(value: str) -> NoReturn:
    raise EventSetupError(f"registered mapping contains non-finite value: {value}")


def _mapping_contract(mapping_name: str) -> tuple[str, str]:
    relative = Path("mappings") / mapping_name
    path = (_REPOSITORY_ROOT / relative).resolve()
    if not path.is_relative_to(_MAPPING_ROOT) or not path.is_file():
        raise EventSetupError(f"registered mapping is unavailable: {mapping_name}")
    try:
        payload = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite,
        )
    except (OSError, json.JSONDecodeError) as error:
        raise EventSetupError(f"registered mapping is unreadable: {mapping_name}") from error
    canonical = json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return relative.as_posix(), hashlib.sha256(canonical).hexdigest()


def build_event_definition_payload(setup: Mapping[str, object]) -> dict[str, object]:
    """Expand one browser-safe setup object into a strict event definition."""

    raw = _invalid_keys(setup, label="event setup", expected=_SETUP_KEYS)
    if raw["version"] != "event-setup-v1":
        raise EventSetupError("version must be event-setup-v1")
    source_profile = _string(raw["source_profile"], label="source_profile")
    try:
        source_specs = _SOURCE_PROFILES[source_profile]
    except KeyError as error:
        raise EventSetupError(f"unsupported source profile: {source_profile}") from error
    report_profile = _string(raw["report_profile"], label="report_profile")
    try:
        report = _REPORT_PROFILES[report_profile]
    except KeyError as error:
        raise EventSetupError(f"unsupported report profile: {report_profile}") from error
    selected_sheets = _selected_sheets(raw["selected_sheets"])

    sources: list[dict[str, object]] = []
    for spec in source_specs:
        mapping_path, mapping_sha256 = _mapping_contract(spec.mapping_name)
        sources.append({
            "role": spec.role,
            "required": spec.required,
            "adapter_id": spec.adapter_id,
            "media_type": spec.media_type,
            "mapping_path": mapping_path,
            "mapping_sha256": mapping_sha256,
            "sheets": list(selected_sheets.get(spec.role, ())),
            "stable_id_strategy": spec.stable_id_strategy,
        })

    return {
        "version": "event-release-v1",
        "event": _event_payload(raw["event"]),
        "report_family": report["report_family"],
        "privacy": deepcopy(report["privacy"]),
        "sources": sources,
        "funnel": deepcopy(report["funnel"]),
        "semantic": deepcopy(report["semantic"]),
        "artifact_profile": report["artifact_profile"],
    }


def _serialized_definition(setup: Mapping[str, object]) -> str:
    payload = build_event_definition_payload(setup)
    return json.dumps(
        payload,
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
    ) + "\n"


def write_event_definition(
    path: str | Path, setup: Mapping[str, object],
) -> EventDefinition:
    """Validate and atomically persist a generated definition with mode 0600."""

    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    serialized = _serialized_definition(setup)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.",
        suffix=".tmp",
        dir=destination.parent,
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            descriptor = -1
            stream.write(serialized)
            stream.flush()
            os.fsync(stream.fileno())
        definition = load_event_definition(temporary)
        os.replace(temporary, destination)
        destination.chmod(0o600)
        return definition
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)


__all__ = (
    "EventSetupError",
    "build_event_definition_payload",
    "write_event_definition",
)
