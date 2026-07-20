"""Shared strict CSV ingestion machinery."""

from __future__ import annotations

import csv
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING

from community_os.config import ConfigurationError, IdentityRequirement, SourceMapping

if TYPE_CHECKING:
    from collections.abc import Iterable


class SchemaDriftError(ValueError):
    """Raised when export headers no longer match their versioned mapping."""


class RejectionCode(StrEnum):
    MISSING_SOURCE_IDENTITY = "missing_source_identity"
    MISSING_APPLICANT_IDENTITY = "missing_applicant_identity"


class WarningCode(StrEnum):
    REAL_EXPORT_UNVERIFIED = "real_export_unverified"


@dataclass(frozen=True)
class IngestWarning:
    code: WarningCode
    message: str


@dataclass(frozen=True)
class RejectedRow:
    row_number: int
    code: RejectionCode
    source_partition: str | None = None


@dataclass(frozen=True)
class MappedRecord:
    external_record_id: str
    applicant_identity: str
    mapping_version: str
    authority: str | None
    authoritative_fields: frozenset[str]
    identity_only_fields: frozenset[str]
    values: dict[str, str]
    raw: dict[str, str]
    row_number: int = 0
    source_partition: str | None = None

    @property
    def authoritative_values(self) -> dict[str, str]:
        """Return only fields this source is permitted to override canonically."""

        if self.authority is None:
            return {}
        return {
            field: self.values[field]
            for field in self.authoritative_fields
            if field in self.values
        }


@dataclass
class IngestResult:
    mapping: SourceMapping
    records: list[MappedRecord] = field(default_factory=list)
    rejected: list[RejectedRow] = field(default_factory=list)
    warnings: list[IngestWarning] = field(default_factory=list)


class CsvAdapter:
    """Strict versioned adapter that retains raw provenance per accepted row."""

    def __init__(self, mapping: SourceMapping):
        self.mapping = mapping

    def read(self, path: str | Path, *, authority: str | None = None) -> IngestResult:
        self._validate_authority(authority)
        result = IngestResult(mapping=self.mapping, warnings=list(self._warnings()))
        with Path(path).open("r", encoding="utf-8-sig", newline="") as stream:
            reader = csv.DictReader(stream)
            self._validate_headers(reader.fieldnames)
            for row_number, row in enumerate(reader, start=2):
                if None in row:
                    raise SchemaDriftError(f"row {row_number} has more values than headers")
                normalized = {key: (value or "") for key, value in row.items()}
                rejection = self._rejection(normalized, row_number)
                if rejection is not None:
                    result.rejected.append(rejection)
                    continue
                result.records.append(self._map_record(normalized, authority, row_number))
        return result

    def read_table(
        self,
        headers: Iterable[str],
        rows: Iterable[Iterable[str]],
        *,
        authority: str | None = None,
        source_partition: str | None = None,
    ) -> IngestResult:
        """Read an already-decoded table while preserving its workbook partition."""

        self._validate_authority(authority)
        header = list(headers)
        self._validate_headers(header)
        result = IngestResult(mapping=self.mapping, warnings=list(self._warnings()))
        for row_number, values in enumerate(rows, start=2):
            materialized = list(values)
            if not any(materialized):
                continue
            if len(materialized) != len(header):
                raise SchemaDriftError(
                    f"row {row_number} has {len(materialized)} values; expected {len(header)}"
                )
            normalized = dict(zip(header, materialized, strict=True))
            rejection = self._rejection(
                normalized,
                row_number,
                source_partition=source_partition,
            )
            if rejection is not None:
                result.rejected.append(rejection)
                continue
            result.records.append(
                self._map_record(
                    normalized,
                    authority,
                    row_number,
                    source_partition=source_partition,
                )
            )
        return result

    def _validate_headers(self, actual: list[str] | None) -> None:
        expected = set(self.mapping.expected_headers)
        actual_list = actual or []
        actual_set = set(actual_list)
        unexpected = sorted(actual_set - expected)
        missing = sorted(expected - actual_set)
        duplicates = sorted({header for header in actual_list if actual_list.count(header) > 1})
        if unexpected or missing or duplicates:
            parts = []
            if unexpected:
                parts.append(f"unexpected headers: {', '.join(unexpected)}")
            if missing:
                parts.append(f"missing headers: {', '.join(missing)}")
            if duplicates:
                parts.append(f"duplicate headers: {', '.join(duplicates)}")
            raise SchemaDriftError("; ".join(parts))

    def _validate_authority(self, authority: str | None) -> None:
        if self.mapping.metadata.get("requires_explicit_authority") and not authority:
            raise ConfigurationError(
                f"mapping {self.mapping.version} requires explicit supplement authority"
            )
        allowed = self.mapping.metadata.get("allowed_authorities")
        if authority and allowed and authority not in allowed:
            raise ConfigurationError(
                f"authority {authority!r} is not allowed for mapping {self.mapping.version}"
            )

    def _warnings(self) -> Iterable[IngestWarning]:
        if self.mapping.metadata.get("untested_real_export"):
            yield IngestWarning(
                WarningCode.REAL_EXPORT_UNVERIFIED,
                f"{self.mapping.version} is modeled from documentation; verify against a real export",
            )

    def _rejection(
        self,
        row: dict[str, str],
        row_number: int,
        *,
        source_partition: str | None = None,
    ) -> RejectedRow | None:
        def requirement_is_present(requirement: IdentityRequirement) -> bool:
            present = [
                bool(row.get(self.mapping.field_map.get(field, field), "").strip())
                for field in requirement.fields
            ]
            return (
                all(present)
                if requirement.mode == "all" else any(present)
            )

        if not requirement_is_present(self.mapping.source_identity):
            return RejectedRow(
                row_number,
                RejectionCode.MISSING_SOURCE_IDENTITY,
                source_partition,
            )
        if not requirement_is_present(self.mapping.applicant_identity):
            return RejectedRow(
                row_number,
                RejectionCode.MISSING_APPLICANT_IDENTITY,
                source_partition,
            )
        return None

    def _map_record(
        self,
        row: dict[str, str],
        authority: str | None,
        row_number: int,
        *,
        source_partition: str | None = None,
    ) -> MappedRecord:
        values = {
            canonical: row[source].strip()
            for canonical, source in self.mapping.field_map.items()
        }
        external_id_header = self.mapping.field_map.get(
            self.mapping.external_id_field,
            self.mapping.external_id_field,
        )
        applicant_identity_header = self.mapping.field_map.get(
            self.mapping.applicant_identity_field,
            self.mapping.applicant_identity_field,
        )
        return MappedRecord(
            external_record_id=row[external_id_header].strip(),
            applicant_identity=row[applicant_identity_header].strip().lower(),
            mapping_version=self.mapping.version,
            authority=authority,
            authoritative_fields=self.mapping.authoritative_fields,
            identity_only_fields=self.mapping.identity_only_fields,
            values=values,
            raw=dict(row),
            row_number=row_number,
            source_partition=source_partition,
        )


def ingest_csv(
    path: str | Path,
    mapping: SourceMapping,
    *,
    authority: str | None = None,
) -> IngestResult:
    """Dispatch to the source-specific adapter named by the mapping."""

    if mapping.source_type.startswith("luma"):
        from .luma import LumaAdapter

        adapter: CsvAdapter = LumaAdapter(mapping)
    elif mapping.source_type.startswith("devpost"):
        from .devpost import DevpostAdapter

        adapter = DevpostAdapter(mapping)
    elif mapping.source_type.startswith("track_"):
        adapter = CsvAdapter(mapping)
    else:
        raise ConfigurationError(f"unsupported source type: {mapping.source_type}")
    return adapter.read(path, authority=authority)


def ingest_table(
    headers: Iterable[str],
    rows: Iterable[Iterable[str]],
    mapping: SourceMapping,
    *,
    authority: str | None = None,
    source_partition: str | None = None,
) -> IngestResult:
    """Map one decoded table through the same strict source adapter contract."""

    if mapping.source_type.startswith("luma"):
        from .luma import LumaAdapter

        adapter: CsvAdapter = LumaAdapter(mapping)
    elif mapping.source_type.startswith("devpost"):
        from .devpost import DevpostAdapter

        adapter = DevpostAdapter(mapping)
    elif mapping.source_type.startswith("track_"):
        adapter = CsvAdapter(mapping)
    else:
        raise ConfigurationError(f"unsupported source type: {mapping.source_type}")
    return adapter.read_table(
        headers,
        rows,
        authority=authority,
        source_partition=source_partition,
    )
