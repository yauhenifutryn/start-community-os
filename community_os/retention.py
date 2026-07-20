"""Executable retention, objection, and ghost-record lifecycle rules."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
import hashlib
import hmac
import sqlite3


@dataclass(frozen=True)
class CleanupReport:
    enrichment_payloads_erased: int
    raw_source_payloads_erased: int
    raw_application_answers_erased: int
    applied: bool


def _iso(value: datetime) -> str:
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def cleanup_expired(
    connection: sqlite3.Connection, *, now: datetime | None = None, apply: bool = False,
) -> CleanupReport:
    """Erase expired raw payloads. Direct calls are dry-run unless apply is true."""
    current = now or datetime.now(UTC)
    cutoff = _iso(current - timedelta(days=365))
    enrichment = connection.execute(
        "SELECT COUNT(*) FROM enrichment_snapshot WHERE payload_json IS NOT NULL AND expires_at<=?",
        (_iso(current),),
    ).fetchone()[0]
    raw_sources = connection.execute(
        """SELECT COUNT(*) FROM source_record sr JOIN source_file sf ON sf.id=sr.source_file_id
           WHERE sr.raw_payload_json IS NOT NULL AND sf.observed_at<=?""", (cutoff,)
    ).fetchone()[0]
    raw_answers = connection.execute(
        """SELECT COUNT(*) FROM application a JOIN source_record sr ON sr.id=a.source_record_id
           JOIN source_file sf ON sf.id=sr.source_file_id
           WHERE a.raw_answers_json IS NOT NULL AND sf.observed_at<=?""", (cutoff,)
    ).fetchone()[0]
    if apply:
        connection.execute(
            "UPDATE enrichment_snapshot SET payload_json=NULL WHERE payload_json IS NOT NULL AND expires_at<=?",
            (_iso(current),),
        )
        connection.execute(
            """UPDATE application SET raw_answers_json=NULL WHERE id IN (
               SELECT a.id FROM application a JOIN source_record sr ON sr.id=a.source_record_id
               JOIN source_file sf ON sf.id=sr.source_file_id WHERE sf.observed_at<=?)""", (cutoff,)
        )
        connection.execute(
            """UPDATE source_record SET raw_payload_json=NULL WHERE id IN (
               SELECT sr.id FROM source_record sr JOIN source_file sf ON sf.id=sr.source_file_id
               WHERE sf.observed_at<=?)""", (cutoff,)
        )
        connection.execute(
            """INSERT INTO deletion_log(action,reason,rows_affected,occurred_at,details_json)
               VALUES('retention_cleanup','12-month raw payload policy',?,?,json_object('enrichment',?,'source',?,'answers',?))""",
            (enrichment + raw_sources + raw_answers, _iso(current), enrichment, raw_sources, raw_answers),
        )
        connection.commit()
    return CleanupReport(enrichment, raw_sources, raw_answers, apply)


def ghost_person(
    connection: sqlite3.Connection, person_id: int, *, secret: str,
    key_version: str, now: str,
) -> None:
    """Minimize an inactive person while retaining nonreversible return matching."""
    if not secret:
        raise ValueError("ghost secret is required")
    person = connection.execute("SELECT state FROM person WHERE id=?", (person_id,)).fetchone()
    if person is None:
        raise ValueError("person does not exist")
    if person[0] == "ghost":
        return
    identities = connection.execute(
        """SELECT id,source_record_id,normalized_value FROM person_identity
           WHERE person_id=? AND identity_type='email' AND verified=1 ORDER BY id""", (person_id,)
    ).fetchall()
    if not identities:
        raise ValueError("ghost transition requires at least one verified email identity")
    for identity in identities:
        token = hmac.new(secret.encode(), identity[2].encode(), hashlib.sha256).hexdigest()
        connection.execute(
            """INSERT OR IGNORE INTO hashed_identity(person_id,evidence_identity_id,evidence_source_record_id,
               identity_hmac,key_version,created_at) VALUES(?,?,?,?,?,?)""",
            (person_id, identity[0], identity[1], token, key_version, now),
        )
    linked_ids = [row[0] for row in connection.execute(
        "SELECT DISTINCT source_record_id FROM person_source_record_link WHERE person_id=?", (person_id,)
    )]
    if linked_ids:
        marks = ",".join("?" for _ in linked_ids)
        connection.execute(
            f"DELETE FROM fact_assertion_payload WHERE pii_class!='non_pii' AND assertion_id IN (SELECT id FROM fact_assertion WHERE source_record_id IN ({marks}))",
            linked_ids,
        )
        connection.execute(f"UPDATE source_record SET raw_payload_json=NULL WHERE id IN ({marks})", linked_ids)
    connection.execute("UPDATE application SET raw_answers_json=NULL WHERE person_id=?", (person_id,))
    connection.execute("UPDATE enrichment_snapshot SET payload_json=NULL WHERE person_id=?", (person_id,))
    connection.execute("UPDATE classification SET facts_json=NULL WHERE person_id=?", (person_id,))
    connection.execute("UPDATE intro SET context=NULL WHERE person_id=?", (person_id,))
    connection.execute("DELETE FROM person_identity WHERE person_id=?", (person_id,))
    connection.execute("UPDATE person SET state='ghost',updated_at=? WHERE id=?", (now, person_id))
    connection.execute(
        "INSERT INTO deletion_log(person_id,action,reason,rows_affected,occurred_at) VALUES(?, 'ghost_transition','36-month inactivity',1,?)",
        (person_id, now),
    )
    connection.commit()
