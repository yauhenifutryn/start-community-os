"""Public source-ingestion adapter contracts."""

from .base import (
    IngestResult,
    IngestWarning,
    MappedRecord,
    RejectedRow,
    RejectionCode,
    SchemaDriftError,
    WarningCode,
    ingest_csv,
)

__all__ = [
    "IngestResult",
    "IngestWarning",
    "MappedRecord",
    "RejectedRow",
    "RejectionCode",
    "SchemaDriftError",
    "WarningCode",
    "ingest_csv",
]
