"""Load and validate versioned source-mapping configuration."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any


class ConfigurationError(ValueError):
    """Raised when a source mapping is absent or internally inconsistent."""


@dataclass(frozen=True)
class IdentityRequirement:
    """Columns that establish one structural identity role."""

    fields: tuple[str, ...]
    mode: str = "any"

    def is_present(self, row: dict[str, str]) -> bool:
        present = [bool(row.get(field, "").strip()) for field in self.fields]
        return all(present) if self.mode == "all" else any(present)


@dataclass(frozen=True)
class SourceMapping:
    """Validated mapping contract consumed by CSV adapters."""

    source_type: str
    version: str
    expected_headers: tuple[str, ...]
    field_map: dict[str, str]
    source_identity: IdentityRequirement
    applicant_identity: IdentityRequirement
    external_id_field: str
    applicant_identity_field: str
    authoritative_fields: frozenset[str]
    identity_only_fields: frozenset[str]
    metadata: dict[str, Any]


def _identity_requirement(raw: object, label: str) -> IdentityRequirement:
    if not isinstance(raw, dict):
        raise ConfigurationError(f"{label} must be an object")
    fields = raw.get("fields")
    mode = raw.get("mode", "any")
    if not isinstance(fields, list) or not fields or not all(isinstance(v, str) for v in fields):
        raise ConfigurationError(f"{label}.fields must be a non-empty string list")
    if mode not in {"any", "all"}:
        raise ConfigurationError(f"{label}.mode must be 'any' or 'all'")
    return IdentityRequirement(tuple(fields), mode)


def load_mapping(path: str | Path) -> SourceMapping:
    """Read a JSON mapping and reject incomplete contracts before ingestion."""

    mapping_path = Path(path)
    try:
        raw = json.loads(mapping_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ConfigurationError(f"cannot load mapping {mapping_path}: {error}") from error

    required = {
        "source_type",
        "version",
        "expected_headers",
        "field_map",
        "source_identity",
        "applicant_identity",
        "external_id_field",
        "applicant_identity_field",
        "metadata",
    }
    missing = sorted(required - raw.keys())
    if missing:
        raise ConfigurationError(f"mapping {mapping_path} is missing: {', '.join(missing)}")
    headers = raw["expected_headers"]
    field_map = raw["field_map"]
    if not isinstance(headers, list) or not headers or not all(isinstance(v, str) for v in headers):
        raise ConfigurationError("expected_headers must be a non-empty string list")
    if len(headers) != len(set(headers)):
        raise ConfigurationError("expected_headers contains duplicates")
    if not isinstance(field_map, dict) or not all(
        isinstance(key, str) and isinstance(value, str) for key, value in field_map.items()
    ):
        raise ConfigurationError("field_map must map canonical names to CSV headers")
    referenced = set(field_map.values()) | {
        field_map.get(raw["external_id_field"], raw["external_id_field"]),
        field_map.get(
            raw["applicant_identity_field"], raw["applicant_identity_field"],
        ),
    }
    unknown = sorted(referenced - set(headers))
    if unknown:
        raise ConfigurationError(f"mapping references unknown headers: {', '.join(unknown)}")
    if not isinstance(raw["metadata"], dict):
        raise ConfigurationError("metadata must be an object")
    metadata = raw["metadata"]
    authoritative_fields = frozenset(metadata.get("authoritative_fields", []))
    identity_only_fields = frozenset(metadata.get("identity_only_fields", []))
    if metadata.get("requires_explicit_authority"):
        canonical_fields = set(field_map)
        classified_fields = authoritative_fields | identity_only_fields
        overlap = sorted(authoritative_fields & identity_only_fields)
        unknown_classifications = sorted(classified_fields - canonical_fields)
        unclassified = sorted(canonical_fields - classified_fields)
        if overlap:
            raise ConfigurationError(
                f"supplement fields cannot be both authoritative and identity-only: {', '.join(overlap)}"
            )
        if unknown_classifications:
            raise ConfigurationError(
                "supplement classifies unknown fields: " + ", ".join(unknown_classifications)
            )
        if unclassified:
            raise ConfigurationError(
                "supplement has unclassified fields: " + ", ".join(unclassified)
            )
        if not authoritative_fields:
            raise ConfigurationError("supplement requires at least one authoritative field")

    return SourceMapping(
        source_type=raw["source_type"],
        version=raw["version"],
        expected_headers=tuple(headers),
        field_map=dict(field_map),
        source_identity=_identity_requirement(raw["source_identity"], "source_identity"),
        applicant_identity=_identity_requirement(raw["applicant_identity"], "applicant_identity"),
        external_id_field=raw["external_id_field"],
        applicant_identity_field=raw["applicant_identity_field"],
        authoritative_fields=authoritative_fields,
        identity_only_fields=identity_only_fields,
        metadata=dict(metadata),
    )
