"""SQLite connection and schema initialization helpers."""

from __future__ import annotations

from pathlib import Path
import sqlite3
from typing import Literal


SCHEMA_PATH = Path(__file__).with_name("schema.sql")
CURRENT_SCHEMA_VERSION = 2

_REQUIRED_TABLES = frozenset({
    "aggregate_snapshot",
    "application",
    "classification",
    "consent_assertion",
    "deletion_log",
    "enrichment_snapshot",
    "event",
    "fact_assertion",
    "fact_assertion_payload",
    "hashed_identity",
    "identity_decision",
    "identity_evidence",
    "identity_review",
    "intro",
    "intro_outcome",
    "participation",
    "person",
    "person_identity",
    "publication",
    "publication_cell",
    "source_file",
    "source_record",
    "submission",
    "team",
})

_SOURCE_FILE_COLUMNS = (
    "id",
    "event_id",
    "source_type",
    "file_sha256",
    "mapping_version",
    "observed_at",
    "ingested_at",
)

_CURRENT_SOURCE_FILE_SQL = """CREATE TABLE source_file (
    id INTEGER PRIMARY KEY,
    event_id INTEGER NOT NULL REFERENCES event(id) ON DELETE RESTRICT,
    source_type TEXT NOT NULL,
    file_sha256 TEXT NOT NULL,
    mapping_version TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    ingested_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE (event_id, source_type, file_sha256)
)"""

_SOURCE_FILE_EVENT_TRIGGER_SQL = """CREATE TRIGGER source_file_event_no_reassignment
BEFORE UPDATE OF event_id ON source_file
FOR EACH ROW
WHEN NEW.event_id IS NOT OLD.event_id
BEGIN
    SELECT RAISE(ABORT, 'source file event provenance is immutable');
END"""


class SchemaMigrationError(RuntimeError):
    """The canonical database cannot be upgraded without risking data drift."""


def connect(database: str | Path) -> sqlite3.Connection:
    """Open a canonical-store connection with referential integrity enabled."""
    connection = sqlite3.connect(database)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def _table_names(connection: sqlite3.Connection) -> frozenset[str]:
    return frozenset(
        str(row[0])
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        )
    )


def _unique_indexes(
    connection: sqlite3.Connection, table: str,
) -> frozenset[tuple[str, ...]]:
    indexes = set()
    for row in connection.execute(f"PRAGMA index_list('{table}')"):
        if not row[2] or row[4]:
            continue
        indexes.add(tuple(
            str(column[2])
            for column in connection.execute(f"PRAGMA index_info('{row[1]}')")
        ))
    return frozenset(indexes)


def _foreign_keys(
    connection: sqlite3.Connection, table: str,
) -> frozenset[tuple[str, str, str, str, str]]:
    return frozenset(
        (str(row[3]), str(row[2]), str(row[4]), str(row[5]), str(row[6]))
        for row in connection.execute(f"PRAGMA foreign_key_list('{table}')")
    )


def _schema_kind(
    connection: sqlite3.Connection,
) -> Literal["empty", "legacy_v1", "current", "unknown"]:
    tables = _table_names(connection)
    if not tables:
        return "empty"
    if not _REQUIRED_TABLES.issubset(tables):
        return "unknown"
    columns = tuple(row[1] for row in connection.execute("PRAGMA table_info(source_file)"))
    if columns != _SOURCE_FILE_COLUMNS:
        return "unknown"
    if _foreign_keys(connection, "source_file") != frozenset({
        ("event_id", "event", "id", "NO ACTION", "RESTRICT"),
    }):
        return "unknown"
    if _foreign_keys(connection, "source_record") != frozenset({
        ("source_file_id", "source_file", "id", "NO ACTION", "RESTRICT"),
    }):
        return "unknown"
    event_column = next(
        row for row in connection.execute("PRAGMA table_info(source_file)")
        if row[1] == "event_id"
    )
    unique_indexes = _unique_indexes(connection, "source_file")
    global_digest = ("source_type", "file_sha256")
    event_digest = ("event_id", "source_type", "file_sha256")
    if event_column[3] == 0 and global_digest in unique_indexes and event_digest not in unique_indexes:
        return "legacy_v1"
    if event_column[3] == 1 and event_digest in unique_indexes and global_digest not in unique_indexes:
        return "current"
    return "unknown"


def _source_rows(connection: sqlite3.Connection) -> tuple[tuple[object, ...], ...]:
    return tuple(tuple(row) for row in connection.execute(
        """SELECT id,event_id,source_type,file_sha256,mapping_version,observed_at,ingested_at
           FROM source_file ORDER BY id"""
    ))


def _source_record_references(
    connection: sqlite3.Connection,
) -> tuple[tuple[object, ...], ...]:
    return tuple(tuple(row) for row in connection.execute(
        """SELECT id,source_file_id,external_record_id,mapping_version,observed_at,
                  raw_payload_json,quarantined,created_at
           FROM source_record ORDER BY id"""
    ))


def _assert_current_integrity(connection: sqlite3.Connection) -> None:
    if _schema_kind(connection) != "current":
        raise SchemaMigrationError("canonical source_file schema does not match version 2")
    if connection.execute("PRAGMA foreign_key_check").fetchall():
        raise SchemaMigrationError("canonical database contains foreign-key violations")
    quick_check = connection.execute("PRAGMA quick_check").fetchone()
    if quick_check is None or quick_check[0] != "ok":
        raise SchemaMigrationError("canonical database failed SQLite quick_check")


def _migrate_legacy_v1(connection: sqlite3.Connection) -> None:
    if connection.execute(
        "SELECT 1 FROM source_file WHERE event_id IS NULL LIMIT 1"
    ).fetchone():
        raise SchemaMigrationError("legacy source_file contains null event_id")

    expected_sources = _source_rows(connection)
    expected_records = _source_record_references(connection)
    foreign_keys = int(connection.execute("PRAGMA foreign_keys").fetchone()[0])
    legacy_alter_table = int(
        connection.execute("PRAGMA legacy_alter_table").fetchone()[0]
    )

    try:
        connection.execute("PRAGMA foreign_keys = OFF")
        connection.execute("PRAGMA legacy_alter_table = ON")
        connection.execute("BEGIN IMMEDIATE")
        try:
            connection.execute(
                "ALTER TABLE source_file RENAME TO source_file_legacy_v1"
            )
            connection.execute(_CURRENT_SOURCE_FILE_SQL)
            connection.execute(
                """INSERT INTO source_file(
                       id,event_id,source_type,file_sha256,mapping_version,observed_at,ingested_at
                   )
                   SELECT id,event_id,source_type,file_sha256,mapping_version,observed_at,ingested_at
                   FROM source_file_legacy_v1 ORDER BY id"""
            )
            connection.execute("DROP TABLE source_file_legacy_v1")
            connection.execute(_SOURCE_FILE_EVENT_TRIGGER_SQL)

            if _source_rows(connection) != expected_sources:
                raise SchemaMigrationError("source_file rows drifted during migration")
            if _source_record_references(connection) != expected_records:
                raise SchemaMigrationError("source_record references drifted during migration")
            _assert_current_integrity(connection)
            connection.execute(f"PRAGMA user_version = {CURRENT_SCHEMA_VERSION}")
            connection.commit()
        except BaseException:
            if connection.in_transaction:
                connection.rollback()
            raise
    finally:
        connection.execute(f"PRAGMA legacy_alter_table = {legacy_alter_table}")
        connection.execute(f"PRAGMA foreign_keys = {foreign_keys}")


def _execute_current_schema(connection: sqlite3.Connection) -> None:
    connection.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))


def apply_schema(connection: sqlite3.Connection) -> None:
    """Create or transactionally migrate the canonical schema."""
    if connection.in_transaction:
        raise SchemaMigrationError("schema changes require no active transaction")

    version = int(connection.execute("PRAGMA user_version").fetchone()[0])
    if version > CURRENT_SCHEMA_VERSION:
        raise SchemaMigrationError(
            f"database uses newer schema version {version}; supported version is "
            f"{CURRENT_SCHEMA_VERSION}"
        )

    kind = _schema_kind(connection)
    if kind == "empty":
        if version != 0:
            raise SchemaMigrationError("unrecognized empty database schema version")
        _execute_current_schema(connection)
    elif kind == "legacy_v1":
        if version not in {0, 1}:
            raise SchemaMigrationError("legacy schema has an inconsistent version")
        _migrate_legacy_v1(connection)
        _execute_current_schema(connection)
    elif kind == "current":
        if version not in {0, 1, CURRENT_SCHEMA_VERSION}:
            raise SchemaMigrationError("current schema has an inconsistent version")
        _execute_current_schema(connection)
    else:
        raise SchemaMigrationError("unrecognized canonical database schema")

    final_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
    if final_version != CURRENT_SCHEMA_VERSION:
        raise SchemaMigrationError("canonical schema version was not persisted")
    _assert_current_integrity(connection)


def initialize(database: str | Path) -> sqlite3.Connection:
    """Open a database, apply its schema, and return the ready connection."""
    connection = connect(database)
    try:
        apply_schema(connection)
        return connection
    except BaseException:
        connection.close()
        raise
