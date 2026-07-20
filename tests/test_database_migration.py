"""Transactional migration tests for populated canonical operator databases."""

from __future__ import annotations

from pathlib import Path
import sqlite3
import tempfile
import unittest

from community_os.db import CURRENT_SCHEMA_VERSION, apply_schema, connect, initialize


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "community_os" / "schema.sql"
POPULATED_V1_PATH = ROOT / "tests" / "fixtures" / "db" / "operator-v1-populated.sql"

CURRENT_SOURCE_FILE_SQL = """CREATE TABLE IF NOT EXISTS source_file (
    id INTEGER PRIMARY KEY,
    event_id INTEGER NOT NULL REFERENCES event(id) ON DELETE RESTRICT,
    source_type TEXT NOT NULL,
    file_sha256 TEXT NOT NULL,
    mapping_version TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    ingested_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE (event_id, source_type, file_sha256)
);"""

LEGACY_SOURCE_FILE_SQL = """CREATE TABLE IF NOT EXISTS source_file (
    id INTEGER PRIMARY KEY,
    event_id INTEGER REFERENCES event(id) ON DELETE RESTRICT,
    source_type TEXT NOT NULL,
    file_sha256 TEXT NOT NULL,
    mapping_version TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    ingested_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE (source_type, file_sha256)
);"""

FINGERPRINT_TABLES = (
    "event",
    "person",
    "source_file",
    "source_record",
    "person_identity",
    "identity_evidence",
    "identity_decision",
    "application",
    "participation",
    "fact_assertion",
    "fact_assertion_payload",
)


def _legacy_schema() -> str:
    schema = SCHEMA_PATH.read_text(encoding="utf-8")
    if schema.count(CURRENT_SOURCE_FILE_SQL) != 1:
        raise AssertionError("current source_file DDL drifted from the migration fixture")
    schema = schema.replace(CURRENT_SOURCE_FILE_SQL, LEGACY_SOURCE_FILE_SQL)
    schema = schema.replace(
        f"PRAGMA user_version = {CURRENT_SCHEMA_VERSION};",
        "PRAGMA user_version = 0;",
    )
    return schema


def _build_populated_v1(database: Path) -> None:
    connection = sqlite3.connect(database)
    try:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.executescript(_legacy_schema())
        connection.executescript(POPULATED_V1_PATH.read_text(encoding="utf-8"))
        connection.commit()
        if connection.execute("PRAGMA foreign_key_check").fetchall():
            raise AssertionError("legacy fixture contains foreign-key violations")
    finally:
        connection.close()


def _build_lookalike_v1_without_source_record_foreign_key(database: Path) -> None:
    schema = _legacy_schema()
    expected = (
        "source_file_id INTEGER NOT NULL REFERENCES source_file(id) ON DELETE RESTRICT,"
    )
    if schema.count(expected) != 1:
        raise AssertionError("source_record foreign-key fixture drifted")
    schema = schema.replace(expected, "source_file_id INTEGER NOT NULL,", 1)
    connection = sqlite3.connect(database)
    try:
        connection.executescript(schema)
        connection.executescript(POPULATED_V1_PATH.read_text(encoding="utf-8"))
        connection.commit()
    finally:
        connection.close()


def _data_fingerprint(connection: sqlite3.Connection) -> dict[str, tuple[tuple[object, ...], ...]]:
    result = {}
    for table in FINGERPRINT_TABLES:
        columns = tuple(row[1] for row in connection.execute(f"PRAGMA table_info('{table}')"))
        rows = connection.execute(
            f"SELECT {','.join(columns)} FROM '{table}' ORDER BY rowid"
        ).fetchall()
        result[table] = tuple(tuple(row) for row in rows)
    return result


def _schema_fingerprint(connection: sqlite3.Connection) -> tuple[tuple[object, ...], ...]:
    return tuple(tuple(row) for row in connection.execute(
        """SELECT type,name,tbl_name,sql FROM sqlite_master
           WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name"""
    ))


class DatabaseMigrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.database = Path(self.temporary.name) / "operator-v1.sqlite3"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_initialize_migrates_populated_v1_without_provenance_drift(self) -> None:
        _build_populated_v1(self.database)
        before = sqlite3.connect(self.database)
        try:
            expected_data = _data_fingerprint(before)
        finally:
            before.close()

        connection = initialize(self.database)
        self.addCleanup(connection.close)

        self.assertEqual(
            connection.execute("PRAGMA user_version").fetchone()[0],
            CURRENT_SCHEMA_VERSION,
        )
        self.assertEqual(_data_fingerprint(connection), expected_data)
        self.assertEqual(connection.execute("PRAGMA foreign_key_check").fetchall(), [])
        self.assertEqual(connection.execute("PRAGMA quick_check").fetchone()[0], "ok")
        event_column = next(
            row for row in connection.execute("PRAGMA table_info(source_file)")
            if row[1] == "event_id"
        )
        self.assertEqual(event_column[3], 1)

        connection.execute(
            """INSERT INTO source_file(
                   event_id,source_type,file_sha256,mapping_version,observed_at
               ) VALUES(12,'luma_final',?,'luma_final-v1','2026-08-01T12:00:00Z')""",
            ("a" * 64,),
        )
        with self.assertRaises(sqlite3.IntegrityError):
            connection.execute(
                """INSERT INTO source_file(
                       event_id,source_type,file_sha256,mapping_version,observed_at
                   ) VALUES(11,'luma_final',?,'luma_final-v1','2026-07-11T12:00:00Z')""",
                ("a" * 64,),
            )
        with self.assertRaises(sqlite3.IntegrityError):
            connection.execute(
                """INSERT INTO source_file(
                       event_id,source_type,file_sha256,mapping_version,observed_at
                   ) VALUES(NULL,'luma_final',?,'luma_final-v1','2026-07-11T12:00:00Z')""",
                ("c" * 64,),
            )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "event provenance is immutable"):
            connection.execute("UPDATE source_file SET event_id=12 WHERE id=101")

    def test_migration_is_idempotent(self) -> None:
        _build_populated_v1(self.database)
        first = initialize(self.database)
        expected_data = _data_fingerprint(first)
        expected_schema = _schema_fingerprint(first)
        first.close()

        second = initialize(self.database)
        self.addCleanup(second.close)
        self.assertEqual(_data_fingerprint(second), expected_data)
        self.assertEqual(_schema_fingerprint(second), expected_schema)
        self.assertEqual(
            second.execute("PRAGMA user_version").fetchone()[0],
            CURRENT_SCHEMA_VERSION,
        )

    def test_injected_failure_rolls_back_schema_data_version_and_pragmas(self) -> None:
        _build_populated_v1(self.database)
        connection = connect(self.database)
        self.addCleanup(connection.close)
        expected_data = _data_fingerprint(connection)
        expected_schema = _schema_fingerprint(connection)
        expected_version = connection.execute("PRAGMA user_version").fetchone()[0]
        expected_foreign_keys = connection.execute("PRAGMA foreign_keys").fetchone()[0]
        expected_legacy_alter = connection.execute("PRAGMA legacy_alter_table").fetchone()[0]

        def deny_legacy_drop(action, name, _arg2, _database, _trigger):
            if action == sqlite3.SQLITE_DROP_TABLE and name == "source_file_legacy_v1":
                return sqlite3.SQLITE_DENY
            return sqlite3.SQLITE_OK

        connection.set_authorizer(deny_legacy_drop)
        with self.assertRaises(sqlite3.DatabaseError):
            apply_schema(connection)
        connection.set_authorizer(None)

        self.assertFalse(connection.in_transaction)
        self.assertEqual(_data_fingerprint(connection), expected_data)
        self.assertEqual(_schema_fingerprint(connection), expected_schema)
        self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], expected_version)
        self.assertEqual(
            connection.execute("PRAGMA foreign_keys").fetchone()[0],
            expected_foreign_keys,
        )
        self.assertEqual(
            connection.execute("PRAGMA legacy_alter_table").fetchone()[0],
            expected_legacy_alter,
        )
        self.assertIsNotNone(connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='source_file'"
        ).fetchone())
        self.assertIsNone(connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='source_file_legacy_v1'"
        ).fetchone())

    def test_legacy_null_event_id_is_rejected_without_mutation(self) -> None:
        _build_populated_v1(self.database)
        connection = sqlite3.connect(self.database)
        connection.execute(
            """INSERT INTO source_file(
                   id,event_id,source_type,file_sha256,mapping_version,observed_at,ingested_at
               ) VALUES(103,NULL,'luma_final',?,'luma_final-v1',
                        '2026-07-12T00:00:00Z','2026-07-12T00:01:00Z')""",
            ("c" * 64,),
        )
        connection.commit()
        expected_schema = _schema_fingerprint(connection)
        connection.close()

        with self.assertRaisesRegex(RuntimeError, "null event_id"):
            initialize(self.database)

        unchanged = sqlite3.connect(self.database)
        self.addCleanup(unchanged.close)
        self.assertEqual(_schema_fingerprint(unchanged), expected_schema)
        self.assertEqual(unchanged.execute("PRAGMA user_version").fetchone()[0], 0)

    def test_unknown_and_newer_database_versions_fail_closed(self) -> None:
        unknown = Path(self.temporary.name) / "unknown.sqlite3"
        connection = sqlite3.connect(unknown)
        connection.execute("CREATE TABLE unrelated(id INTEGER PRIMARY KEY)")
        connection.close()
        with self.assertRaisesRegex(RuntimeError, "unrecognized.*schema"):
            initialize(unknown)

        newer = Path(self.temporary.name) / "newer.sqlite3"
        connection = sqlite3.connect(newer)
        connection.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
        connection.execute(f"PRAGMA user_version = {CURRENT_SCHEMA_VERSION + 1}")
        connection.close()
        with self.assertRaisesRegex(RuntimeError, "newer schema version"):
            initialize(newer)

    def test_lookalike_legacy_schema_without_required_foreign_key_fails_closed(self) -> None:
        _build_lookalike_v1_without_source_record_foreign_key(self.database)

        with self.assertRaisesRegex(RuntimeError, "unrecognized.*schema"):
            initialize(self.database)

    def test_apply_schema_rejects_an_active_transaction(self) -> None:
        connection = connect(":memory:")
        self.addCleanup(connection.close)
        connection.execute("BEGIN")

        with self.assertRaisesRegex(RuntimeError, "active transaction"):
            apply_schema(connection)

        self.assertTrue(connection.in_transaction)
        connection.rollback()

    def test_unversioned_current_shape_is_stamped_without_rebuild(self) -> None:
        connection = sqlite3.connect(self.database)
        connection.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
        connection.execute("PRAGMA user_version = 0")
        original_source_sql = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='source_file'"
        ).fetchone()[0]
        connection.close()

        current = initialize(self.database)
        self.addCleanup(current.close)
        self.assertEqual(
            current.execute("PRAGMA user_version").fetchone()[0],
            CURRENT_SCHEMA_VERSION,
        )
        self.assertEqual(
            current.execute(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name='source_file'"
            ).fetchone()[0],
            original_source_sql,
        )


if __name__ == "__main__":
    unittest.main()
