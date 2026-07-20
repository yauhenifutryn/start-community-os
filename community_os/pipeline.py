"""Transactional file ingestion into the canonical SQLite store."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import sqlite3
from typing import Callable, Mapping

from community_os.config import SourceMapping
from community_os.ingest import ingest_csv
from community_os.ingest.base import MappedRecord
from community_os.normalize import GhostIdentityMatch, NormalizedRecord, normalize_record


@dataclass(frozen=True)
class FileIngestSummary:
    source_file_id: int
    file_sha256: str
    accepted: int
    rejected: int
    skipped: bool = False


def ingest_file(
    connection: sqlite3.Connection, *, event_id: int, path: str | Path,
    mapping: SourceMapping, observed_at: str, authority: str | None = None,
    reingest: bool = False,
    ghost_secrets: Mapping[str, str] | None = None,
    record_writer: Callable[..., NormalizedRecord] = normalize_record,
) -> FileIngestSummary:
    """Ingest one mapped file atomically; explicit reingest appends history."""
    source_path = Path(path)
    digest = hashlib.sha256(source_path.read_bytes()).hexdigest()
    existing = connection.execute(
        """SELECT id FROM source_file
           WHERE event_id=? AND source_type=? AND file_sha256=?""",
        (event_id, mapping.source_type, digest),
    ).fetchone()
    if existing is not None and not reingest:
        return FileIngestSummary(existing[0], digest, 0, 0, True)

    result = ingest_csv(source_path, mapping, authority=authority)
    if not reingest:
        external_ids = [record.external_record_id for record in result.records]
        if external_ids:
            placeholders = ",".join("?" for _ in external_ids)
            corrected = connection.execute(
                f"""SELECT 1 FROM source_record sr JOIN source_file sf ON sf.id=sr.source_file_id
                    WHERE sf.event_id=? AND sf.source_type=? AND sr.external_record_id IN ({placeholders}) LIMIT 1""",
                (event_id, mapping.source_type, *external_ids),
            ).fetchone()
            if corrected:
                raise ValueError("corrected export requires explicit reingest")

    stored_digest = digest
    if existing is not None:
        suffix = connection.execute(
            """SELECT COUNT(*) FROM source_file
               WHERE event_id=? AND source_type=? AND file_sha256 LIKE ?""",
            (event_id, mapping.source_type, f"{digest}:reingest:%"),
        ).fetchone()[0] + 1
        stored_digest = f"{digest}:reingest:{suffix}"

    connection.execute("SAVEPOINT canonical_file_ingest")
    try:
        source_file_id = connection.execute(
            """INSERT INTO source_file(event_id,source_type,file_sha256,mapping_version,observed_at)
               VALUES(?,?,?,?,?)""",
            (event_id, mapping.source_type, stored_digest, mapping.version, observed_at),
        ).lastrowid
        normalized_count = 0
        ghost_rejections = 0
        for record in result.records:
            source_record_id = connection.execute(
                """INSERT INTO source_record(source_file_id,external_record_id,mapping_version,
                       observed_at,raw_payload_json) VALUES(?,?,?,?,?)""",
                (source_file_id, record.external_record_id, mapping.version, observed_at,
                 json.dumps(record.raw, ensure_ascii=False)),
            ).lastrowid
            try:
                record_writer(
                    connection, event_id=event_id, source_type=mapping.source_type,
                    source_record_id=source_record_id, record=record,
                    ghost_secrets=ghost_secrets,
                )
            except GhostIdentityMatch as error:
                connection.execute(
                    "UPDATE source_record SET raw_payload_json=NULL,quarantined=1 WHERE id=?",
                    (source_record_id,),
                )
                connection.execute(
                    """INSERT INTO deletion_log(person_id,source_record_id,action,reason,rows_affected,occurred_at)
                       VALUES(?,?,'ghost_return_blocked','explicit reactivation required',1,?)""",
                    (error.person_id, source_record_id, observed_at),
                )
                ghost_rejections += 1
            else:
                normalized_count += 1
    except Exception:
        connection.execute("ROLLBACK TO canonical_file_ingest")
        connection.execute("RELEASE canonical_file_ingest")
        raise
    else:
        connection.execute("RELEASE canonical_file_ingest")
    return FileIngestSummary(
        source_file_id, digest, normalized_count,
        len(result.rejected) + ghost_rejections,
    )
