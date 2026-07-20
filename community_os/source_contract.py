"""Runtime validation for hash-bound registered event source contracts."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import json

from community_os.config import SourceMapping, load_mapping
from community_os.event_definition import EventSource


_XLSX = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"


@dataclass(frozen=True, slots=True)
class _AdapterContract:
    roles: frozenset[str]
    media_type: str
    source_types: frozenset[str]
    table_layout: str
    authority: str | None = None


@dataclass(frozen=True, slots=True)
class RegisteredSourceContract:
    """Validated runtime view of one immutable event source binding."""

    source: EventSource
    mapping: SourceMapping
    table_layout: str
    authority: str | None


_ADAPTER_CONTRACTS = {
    "luma-csv-v2": _AdapterContract(
        frozenset({"applications"}), "text/csv",
        frozenset({"luma_guests"}), "single_table",
    ),
    "luma-supplement-csv-v1": _AdapterContract(
        frozenset({"attendance"}), "text/csv",
        frozenset({"luma_supplement"}), "single_table",
        authority="luma_final_status_supplement",
    ),
    "track-preferences-xlsx-v1": _AdapterContract(
        frozenset({"preferences"}), _XLSX,
        frozenset({"track_preferences"}), "header_per_sheet",
    ),
    "devpost-final-xlsx-v1": _AdapterContract(
        frozenset({"submissions"}), _XLSX,
        frozenset({"devpost_final"}), "shared_first_header",
    ),
    "mapped-xlsx-v1": _AdapterContract(
        frozenset({"applications", "attendance"}), _XLSX,
        frozenset({"luma_guests", "luma_supplement"}), "header_per_sheet",
        authority="luma_final_status_supplement",
    ),
    "devpost-registrants-json-v1": _AdapterContract(
        frozenset({"teams"}), "application/json",
        frozenset({"devpost_registrants"}), "json_records",
    ),
    "devpost-projects-json-v1": _AdapterContract(
        frozenset({"submissions"}), "application/json",
        frozenset({"devpost_projects"}), "json_records",
    ),
}
_ROLE_SOURCE_TYPES = {
    "applications": frozenset({"luma_guests"}),
    "attendance": frozenset({"luma_supplement"}),
    "preferences": frozenset({"track_preferences"}),
    "teams": frozenset({"devpost_registrants"}),
    "submissions": frozenset({"devpost_final", "devpost_projects"}),
}


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate mapping key: {key}")
        result[key] = value
    return result


def _reject_nonfinite(value: str) -> None:
    raise ValueError(f"non-finite mapping value is forbidden: {value}")


def load_registered_source_contract(source: EventSource) -> RegisteredSourceContract:
    """Recheck the adapter and canonical mapping hash immediately before use."""

    if not isinstance(source, EventSource):
        raise TypeError("source must be an EventSource")
    adapter = _ADAPTER_CONTRACTS.get(source.adapter_id)
    if adapter is None:
        raise ValueError(f"registered source adapter is unsupported: {source.adapter_id}")
    if source.role not in adapter.roles:
        raise ValueError(f"{source.role} is not supported by {source.adapter_id}")
    if source.media_type != adapter.media_type:
        raise ValueError(f"{source.role} media type does not match its registered adapter")
    if adapter.table_layout in {"header_per_sheet", "shared_first_header"}:
        if not source.sheets:
            raise ValueError(f"{source.role} workbook has no configured sheets")
    elif source.sheets:
        raise ValueError(f"{source.role} source must not configure workbook sheets")

    try:
        payload = json.loads(
            source.mapping_path.read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite,
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"{source.role} mapping is unreadable") from error
    canonical = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")
    if not hmac.compare_digest(
        hashlib.sha256(canonical).hexdigest(), source.mapping_sha256,
    ):
        raise ValueError(f"{source.role} mapping changed after event registration")

    mapping = load_mapping(source.mapping_path)
    if (
        mapping.source_type not in adapter.source_types
        or mapping.source_type not in _ROLE_SOURCE_TYPES[source.role]
    ):
        raise ValueError(f"{source.role} mapping does not match its registered adapter")
    authority = adapter.authority if mapping.metadata.get("requires_explicit_authority") else None
    if mapping.metadata.get("requires_explicit_authority"):
        allowed = mapping.metadata.get("allowed_authorities", [])
        if authority is None or authority not in allowed:
            raise ValueError(f"{source.role} adapter has no registered mapping authority")
    return RegisteredSourceContract(source, mapping, adapter.table_layout, authority)
