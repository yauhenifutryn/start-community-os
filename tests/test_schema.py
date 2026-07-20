"""Behavioral tests for the canonical SQLite schema."""

from __future__ import annotations

import importlib
from pathlib import Path
import sqlite3
import tempfile
import unittest


REQUIRED_TABLES = {
    "person",
    "person_identity",
    "hashed_identity",
    "identity_evidence",
    "identity_decision",
    "consent_assertion",
    "fact_assertion",
    "fact_assertion_payload",
    "event",
    "source_file",
    "source_record",
    "application",
    "participation",
    "team",
    "submission",
    "enrichment_snapshot",
    "classification",
    "intro",
    "intro_outcome",
    "identity_review",
    "aggregate_snapshot",
    "publication",
    "publication_cell",
    "deletion_log",
}


class CanonicalSchemaTests(unittest.TestCase):
    def setUp(self) -> None:
        self.schema_path = (
            Path(__file__).resolve().parents[1] / "community_os" / "schema.sql"
        )
        self.assertTrue(self.schema_path.exists(), "canonical schema.sql is missing")
        self.connection = sqlite3.connect(":memory:")
        self.connection.execute("PRAGMA foreign_keys = ON")
        self.connection.executescript(self.schema_path.read_text(encoding="utf-8"))

    def tearDown(self) -> None:
        if hasattr(self, "connection"):
            self.connection.close()

    def _seed_provenance(self) -> tuple[int, int, int, int]:
        person_id = self.connection.execute(
            "INSERT INTO person DEFAULT VALUES"
        ).lastrowid
        event_id = self.connection.execute(
            """
            INSERT INTO event (event_key, name, starts_at, event_type)
            VALUES ('event-1', 'Synthetic event', '2026-07-11T10:00:00Z', 'hackathon')
            """
        ).lastrowid
        source_file_id = self.connection.execute(
            """
            INSERT INTO source_file (
                event_id, source_type, file_sha256, mapping_version, observed_at
            ) VALUES (?, 'luma', 'sha256:one', 'luma-v1', '2026-07-11T11:00:00Z')
            """,
            (event_id,),
        ).lastrowid
        source_record_id = self.connection.execute(
            """
            INSERT INTO source_record (
                source_file_id, external_record_id, mapping_version,
                observed_at, raw_payload_json
            ) VALUES (?, 'guest-1', 'luma-v1', '2026-07-11T11:00:00Z', '{}')
            """,
            (source_file_id,),
        ).lastrowid
        return person_id, event_id, source_file_id, source_record_id

    def _add_event(self, suffix: str) -> int:
        return self.connection.execute(
            """
            INSERT INTO event (event_key, name, starts_at, event_type)
            VALUES (?, ?, '2026-07-12T10:00:00Z', 'hackathon')
            """,
            (f"event-{suffix}", f"Synthetic event {suffix}"),
        ).lastrowid

    def _add_source_record(self, event_id: int, suffix: str) -> int:
        source_file_id = self.connection.execute(
            """
            INSERT INTO source_file (
                event_id, source_type, file_sha256, mapping_version, observed_at
            ) VALUES (?, 'luma', ?, 'luma-v1', '2026-07-12T11:00:00Z')
            """,
            (event_id, f"sha256:{suffix}"),
        ).lastrowid
        return self.connection.execute(
            """
            INSERT INTO source_record (
                source_file_id, external_record_id, mapping_version,
                observed_at, raw_payload_json
            ) VALUES (?, ?, 'luma-v1', '2026-07-12T11:00:00Z', '{}')
            """,
            (source_file_id, f"record-{suffix}"),
        ).lastrowid

    def test_creates_every_required_table(self) -> None:
        actual = {
            row[0]
            for row in self.connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        self.assertTrue(REQUIRED_TABLES <= actual, REQUIRED_TABLES - actual)

    def test_connection_helper_enables_foreign_keys_and_schema_is_idempotent(self) -> None:
        db = importlib.import_module("community_os.db")
        with tempfile.TemporaryDirectory() as temporary_directory:
            database_path = Path(temporary_directory) / "canonical.sqlite3"
            connection = db.connect(database_path)
            self.addCleanup(connection.close)

            db.apply_schema(connection)
            db.apply_schema(connection)

            self.assertEqual(
                connection.execute("PRAGMA foreign_keys").fetchone()[0],
                1,
            )
            tables = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                )
            }
            self.assertTrue(REQUIRED_TABLES <= tables)
            self.assertEqual(connection.execute("PRAGMA foreign_key_check").fetchall(), [])

    def test_person_state_is_checked_and_timestamps_are_present(self) -> None:
        row = self.connection.execute(
            """
            INSERT INTO person DEFAULT VALUES
            RETURNING state, created_at, updated_at
            """
        ).fetchone()
        self.assertEqual(row[0], "active")
        self.assertTrue(row[1])
        self.assertTrue(row[2])

        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute("INSERT INTO person (state) VALUES ('deleted')")

    def test_foreign_keys_reject_orphans_and_cover_relational_tables(self) -> None:
        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute(
                """
                INSERT INTO application (
                    person_id, event_id, source_record_id, status, applied_at
                ) VALUES (999, 999, 999, 'applied', '2026-07-11T11:00:00Z')
                """
            )

        expected_targets = {
            "person_identity": {"person", "source_record"},
            "hashed_identity": {"person", "source_record"},
            "consent_assertion": {
                "person",
                "event",
                "source_record",
                "consent_assertion",
            },
            "fact_assertion": {"source_record", "fact_assertion"},
            "fact_assertion_payload": {"fact_assertion"},
            "application": {"person", "event", "source_record"},
            "participation": {
                "person",
                "event",
                "source_record",
                "team",
                "submission",
            },
            "intro": {"person", "event", "source_record"},
            "intro_outcome": {"intro", "source_record"},
            "publication_cell": {"publication"},
        }
        for table, targets in expected_targets.items():
            with self.subTest(table=table):
                actual_targets = {
                    row[2]
                    for row in self.connection.execute(f"PRAGMA foreign_key_list({table})")
                }
                self.assertEqual(actual_targets, targets)

    def test_source_and_identity_uniqueness_constraints(self) -> None:
        person_id, event_id, source_file_id, source_record_id = self._seed_provenance()

        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute(
                """
                INSERT INTO source_record (
                    source_file_id, external_record_id, mapping_version,
                    observed_at, raw_payload_json
                ) VALUES (?, 'guest-1', 'luma-v1', '2026-07-11T11:01:00Z', '{}')
                """,
                (source_file_id,),
            )
        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute(
                """
                INSERT INTO source_file (
                    event_id, source_type, file_sha256, mapping_version, observed_at
                ) VALUES (?, 'luma', 'sha256:one', 'luma-v1', '2026-07-11T11:01:00Z')
                """,
                (event_id,),
            )

        other_event_id = self._add_event("same-source")
        other_source_file_id = self.connection.execute(
            """
            INSERT INTO source_file (
                event_id, source_type, file_sha256, mapping_version, observed_at
            ) VALUES (?, 'luma', 'sha256:one', 'luma-v1', '2026-07-12T11:01:00Z')
            """,
            (other_event_id,),
        ).lastrowid
        self.assertNotEqual(other_source_file_id, source_file_id)

        identity_values = (
            person_id,
            source_record_id,
            "PERSON@example.com",
            "person@example.com",
        )
        self.connection.execute(
            """
            INSERT INTO person_identity (
                person_id, source_record_id, identity_type, display_value,
                normalized_value, verified, applicant_provided, observed_at
            ) VALUES (?, ?, 'email', ?, ?, 1, 1, '2026-07-11T11:00:00Z')
            """,
            identity_values,
        )
        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute(
                """
                INSERT INTO person_identity (
                    person_id, source_record_id, identity_type, display_value,
                    normalized_value, verified, applicant_provided, observed_at
                ) VALUES (?, ?, 'email', ?, ?, 1, 1, '2026-07-11T11:00:00Z')
                """,
                identity_values,
            )

    def test_source_file_requires_event_and_uses_event_scoped_digest_index(self) -> None:
        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute(
                """INSERT INTO source_file(
                       event_id,source_type,file_sha256,mapping_version,observed_at
                   ) VALUES(NULL,'luma','sha256:none','luma-v1','2026-07-11T11:00:00Z')"""
            )

        unique_indexes = []
        for index in self.connection.execute("PRAGMA index_list(source_file)"):
            if index[2]:
                columns = tuple(
                    row[2]
                    for row in self.connection.execute(
                        f"PRAGMA index_info('{index[1]}')"
                    )
                )
                unique_indexes.append(columns)
        self.assertIn(
            ("event_id", "source_type", "file_sha256"),
            unique_indexes,
        )
        self.assertNotIn(("source_type", "file_sha256"), unique_indexes)

    def test_consent_and_fact_assertions_require_source_provenance(self) -> None:
        person_id, event_id, _, source_record_id = self._seed_provenance()

        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute(
                """
                INSERT INTO consent_assertion (
                    person_id, event_id, purpose, recipient_scope, granted,
                    source_text, source_version, observed_at, evidence_source
                ) VALUES (?, ?, 'aggregate_stats', 'partners', 0,
                          'Opted out', 'form-v1', '2026-07-11T11:00:00Z', 'luma')
                """,
                (person_id, event_id),
            )
        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute(
                """
                INSERT INTO fact_assertion (
                    subject_table, subject_id, field_name,
                    mapping_version, authority, observed_at
                ) VALUES ('person', ?, 'name', 'luma-v1',
                          'applicant', '2026-07-11T11:00:00Z')
                """,
                (person_id,),
            )
        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute(
                """
                INSERT INTO fact_assertion (
                    subject_table, subject_id, field_name, source_record_id,
                    mapping_version, authority, observed_at
                ) VALUES ('person', 999, 'name', ?, 'luma-v1',
                          'applicant', '2026-07-11T11:00:00Z')
                """,
                (source_record_id,),
            )

        consent_id = self.connection.execute(
            """
            INSERT INTO consent_assertion (
                person_id, event_id, source_record_id, purpose, recipient_scope,
                granted, source_text, source_version, observed_at,
                withdrawal_time, evidence_source
            ) VALUES (?, ?, ?, 'aggregate_stats', 'partners', 0,
                      'Opted out', 'form-v1', '2026-07-11T11:00:00Z',
                      '2026-07-11T12:00:00Z', 'luma')
            """,
            (person_id, event_id, source_record_id),
        ).lastrowid
        fact_id = self.connection.execute(
            """
            INSERT INTO fact_assertion (
                subject_table, subject_id, field_name, source_record_id,
                mapping_version, authority, observed_at
            ) VALUES ('person', ?, 'name', ?, 'luma-v1',
                      'applicant', '2026-07-11T11:00:00Z')
            """,
            (person_id, source_record_id),
        ).lastrowid

        self.assertIsInstance(consent_id, int)
        self.assertIsInstance(fact_id, int)

    def test_assertions_are_append_only_and_superseded_once(self) -> None:
        person_id, _, _, source_record_id = self._seed_provenance()
        first_id = self.connection.execute(
            """
            INSERT INTO fact_assertion (
                subject_table, subject_id, field_name, source_record_id,
                mapping_version, authority, observed_at
            ) VALUES ('person', ?, 'name', ?, 'luma-v1',
                      'applicant', '2026-07-11T11:00:00Z')
            """,
            (person_id, source_record_id),
        ).lastrowid

        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute(
                "UPDATE fact_assertion SET authority = ? WHERE id = ?",
                ("changed", first_id),
            )
        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute(
                "DELETE FROM fact_assertion WHERE id = ?",
                (first_id,),
            )

        self.connection.execute(
            """
            INSERT INTO fact_assertion (
                subject_table, subject_id, field_name, source_record_id,
                mapping_version, authority, observed_at,
                supersedes_assertion_id
            ) VALUES ('person', ?, 'name', ?, 'luma-v1',
                      'applicant', '2026-07-11T12:00:00Z', ?)
            """,
            (person_id, source_record_id, first_id),
        )
        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute(
                """
                INSERT INTO fact_assertion (
                    subject_table, subject_id, field_name, source_record_id,
                    mapping_version, authority, observed_at,
                    supersedes_assertion_id
                ) VALUES ('person', ?, 'name', ?, 'luma-v1',
                          'applicant', '2026-07-11T13:00:00Z', ?)
                """,
                (person_id, source_record_id, first_id),
            )
        untouched_id = self.connection.execute(
            """
            INSERT INTO fact_assertion (
                subject_table, subject_id, field_name, source_record_id,
                mapping_version, authority, observed_at
            ) VALUES ('person', ?, 'state', ?, 'luma-v1',
                      'system', '2026-07-11T13:30:00Z')
            """,
            (person_id, source_record_id),
        ).lastrowid
        event_id = self.connection.execute(
            "SELECT id FROM event WHERE event_key = 'event-1'"
        ).fetchone()[0]
        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute(
                """
                INSERT INTO fact_assertion (
                    subject_table, subject_id, field_name, source_record_id,
                    mapping_version, authority, observed_at,
                    supersedes_assertion_id
                ) VALUES ('event', ?, 'name', ?, 'luma-v1',
                          'organizer', '2026-07-11T14:00:00Z', ?)
                """,
                (event_id, source_record_id, untouched_id),
            )

    def test_audit_history_tables_are_append_only(self) -> None:
        person_id, event_id, _, source_record_id = self._seed_provenance()
        row_ids = {
            "consent_assertion": self.connection.execute(
                """
                INSERT INTO consent_assertion (
                    person_id, event_id, source_record_id, purpose, recipient_scope,
                    granted, source_text, source_version, observed_at, evidence_source
                ) VALUES (?, ?, ?, 'aggregate_stats', 'partners', 1,
                          'Consent text', 'form-v1', '2026-07-11T11:00:00Z', 'luma')
                """,
                (person_id, event_id, source_record_id),
            ).lastrowid,
            "identity_decision": self.connection.execute(
                """
                INSERT INTO identity_decision (
                    source_record_id, person_id, decision, reviewer, reason, decided_at
                ) VALUES (?, ?, 'linked', 'reviewer', 'Exact email',
                          '2026-07-11T12:00:00Z')
                """,
                (source_record_id, person_id),
            ).lastrowid,
            "classification": self.connection.execute(
                """
                INSERT INTO classification (
                    person_id, event_id, source_record_id, taxonomy_version,
                    occupation, observed_at
                ) VALUES (?, ?, ?, 'taxonomy-v1', 'builder',
                          '2026-07-11T12:00:00Z')
                """,
                (person_id, event_id, source_record_id),
            ).lastrowid,
            "deletion_log": self.connection.execute(
                """
                INSERT INTO deletion_log (
                    person_id, source_record_id, action, reason, occurred_at
                ) VALUES (?, ?, 'redact', 'retention', '2026-07-11T12:00:00Z')
                """,
                (person_id, source_record_id),
            ).lastrowid,
        }

        for table, row_id in row_ids.items():
            with self.subTest(table=table, operation="update"):
                with self.assertRaises(sqlite3.IntegrityError):
                    self.connection.execute(
                        f"UPDATE {table} SET created_at = created_at WHERE id = ?",
                        (row_id,),
                    )
            with self.subTest(table=table, operation="delete"):
                with self.assertRaises(sqlite3.IntegrityError):
                    self.connection.execute(f"DELETE FROM {table} WHERE id = ?", (row_id,))

    def test_hashed_identity_requires_a_verified_email_and_supports_key_rotation(self) -> None:
        person_id, _, _, source_record_id = self._seed_provenance()
        verified_email_id = self.connection.execute(
            """
            INSERT INTO person_identity (
                person_id, source_record_id, identity_type, display_value,
                normalized_value, verified, applicant_provided, observed_at
            ) VALUES (?, ?, 'email', 'person@example.com', 'person@example.com',
                      1, 1, '2026-07-11T11:00:00Z')
            """,
            (person_id, source_record_id),
        ).lastrowid
        unverified_email_id = self.connection.execute(
            """
            INSERT INTO person_identity (
                person_id, source_record_id, identity_type, display_value,
                normalized_value, verified, applicant_provided, observed_at
            ) VALUES (?, ?, 'email', 'other@example.com', 'other@example.com',
                      0, 1, '2026-07-11T11:00:00Z')
            """,
            (person_id, source_record_id),
        ).lastrowid

        self.connection.execute(
            """
            INSERT INTO hashed_identity (
                person_id, evidence_identity_id, evidence_source_record_id,
                identity_hmac, key_version, created_at
            ) VALUES (?, ?, ?, 'hmac-v1', 'ghost-key-v1', '2026-07-11T12:00:00Z')
            """,
            (person_id, verified_email_id, source_record_id),
        )
        self.connection.execute(
            """
            INSERT INTO hashed_identity (
                person_id, evidence_identity_id, evidence_source_record_id,
                identity_hmac, key_version, created_at
            ) VALUES (?, ?, ?, 'hmac-v2', 'ghost-key-v2', '2026-07-11T12:00:00Z')
            """,
            (person_id, verified_email_id, source_record_id),
        )
        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute(
                """
                INSERT INTO hashed_identity (
                    person_id, evidence_identity_id, evidence_source_record_id,
                    identity_hmac, key_version, created_at
                ) VALUES (?, ?, ?, 'duplicate', 'ghost-key-v1',
                          '2026-07-11T12:00:00Z')
                """,
                (person_id, verified_email_id, source_record_id),
            )
        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute(
                """
                INSERT INTO hashed_identity (
                    person_id, evidence_identity_id, evidence_source_record_id,
                    identity_hmac, key_version, created_at
                ) VALUES (?, ?, ?, 'unverified', 'ghost-key-v1',
                          '2026-07-11T12:00:00Z')
                """,
                (person_id, unverified_email_id, source_record_id),
            )

    def test_intro_outcomes_are_event_scoped_and_append_only(self) -> None:
        person_id, event_id, _, source_record_id = self._seed_provenance()
        intro_id = self.connection.execute(
            """
            INSERT INTO intro (
                person_id, event_id, source_record_id, partner, context, introduced_at
            ) VALUES (?, ?, ?, 'Partner', 'Demo day', '2026-07-11T12:00:00Z')
            """,
            (person_id, event_id, source_record_id),
        ).lastrowid
        outcome_id = self.connection.execute(
            """
            INSERT INTO intro_outcome (
                intro_id, source_record_id, outcome, observed_at
            ) VALUES (?, ?, 'interview', '2026-07-12T12:00:00Z')
            """,
            (intro_id, source_record_id),
        ).lastrowid
        self.connection.execute(
            """
            INSERT INTO intro_outcome (
                intro_id, source_record_id, outcome, observed_at
            ) VALUES (?, ?, 'hire', '2026-07-20T12:00:00Z')
            """,
            (intro_id, source_record_id),
        )

        intro_columns = {
            row[1] for row in self.connection.execute("PRAGMA table_info(intro)")
        }
        self.assertNotIn("outcome", intro_columns)
        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute(
                "UPDATE intro_outcome SET outcome = 'none' WHERE id = ?",
                (outcome_id,),
            )
        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute(
                "DELETE FROM intro_outcome WHERE id = ?",
                (outcome_id,),
            )
        other_event_id = self._add_event("intro-outcome")
        other_source_record_id = self._add_source_record(
            other_event_id, "intro-outcome"
        )
        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute(
                """
                INSERT INTO intro_outcome (
                    intro_id, source_record_id, outcome, observed_at
                ) VALUES (?, ?, 'investment', '2026-07-21T12:00:00Z')
                """,
                (intro_id, other_source_record_id),
            )

    def test_foreign_key_check_remains_clean_for_linked_records(self) -> None:
        self._seed_provenance()
        self.assertEqual(self.connection.execute("PRAGMA foreign_key_check").fetchall(), [])

    def test_fact_values_are_erasable_without_deleting_append_only_metadata(self) -> None:
        tables = {
            row[0]
            for row in self.connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        self.assertIn("fact_assertion_payload", tables)
        fact_columns = {
            row[1] for row in self.connection.execute("PRAGMA table_info(fact_assertion)")
        }
        payload_columns = {
            row[1]
            for row in self.connection.execute(
                "PRAGMA table_info(fact_assertion_payload)"
            )
        }
        self.assertNotIn("canonical_value_json", fact_columns)
        self.assertTrue(
            {"assertion_id", "canonical_value_json", "pii_class"} <= payload_columns
        )

    def test_ghost_transition_requires_erasing_direct_fact_payloads(self) -> None:
        tables = {
            row[0]
            for row in self.connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        self.assertIn("fact_assertion_payload", tables)
        person_id, _, _, source_record_id = self._seed_provenance()
        assertion_id = self.connection.execute(
            """
            INSERT INTO fact_assertion (
                subject_table, subject_id, field_name, source_record_id,
                mapping_version, authority, observed_at
            ) VALUES ('person', ?, 'name', ?, 'luma-v1', 'applicant',
                      '2026-07-11T11:00:00Z')
            """,
            (person_id, source_record_id),
        ).lastrowid
        self.connection.execute(
            """
            INSERT INTO fact_assertion_payload (
                assertion_id, canonical_value_json, pii_class
            ) VALUES (?, '"Person"', 'direct')
            """,
            (assertion_id,),
        )

        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute(
                "UPDATE person SET state = 'ghost' WHERE id = ?",
                (person_id,),
            )

        self.connection.execute(
            "DELETE FROM fact_assertion_payload WHERE assertion_id = ?",
            (assertion_id,),
        )
        self.connection.execute(
            "UPDATE source_record SET raw_payload_json = NULL WHERE id = ?",
            (source_record_id,),
        )
        self.connection.execute(
            "UPDATE person SET state = 'ghost' WHERE id = ?",
            (person_id,),
        )

        self.assertEqual(
            self.connection.execute(
                "SELECT state FROM person WHERE id = ?", (person_id,)
            ).fetchone()[0],
            "ghost",
        )
        self.assertEqual(
            self.connection.execute(
                "SELECT count(*) FROM fact_assertion WHERE id = ?", (assertion_id,)
            ).fetchone()[0],
            1,
        )

    def test_hashed_identity_is_immutable_and_outlives_direct_email_identity(self) -> None:
        person_id, _, _, source_record_id = self._seed_provenance()
        columns = {
            row[1] for row in self.connection.execute("PRAGMA table_info(hashed_identity)")
        }
        self.assertIn("evidence_source_record_id", columns)
        self.assertNotIn("person_identity_id", columns)

        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute(
                """
                INSERT INTO hashed_identity (
                    person_id, evidence_identity_id, evidence_source_record_id,
                    identity_hmac, key_version, created_at
                ) VALUES (?, 999, ?, 'hmac-before-evidence', 'ghost-key-v1',
                          '2026-07-11T12:00:00Z')
                """,
                (person_id, source_record_id),
            )
        email_identity_id = self.connection.execute(
            """
            INSERT INTO person_identity (
                person_id, source_record_id, identity_type, display_value,
                normalized_value, verified, applicant_provided, observed_at
            ) VALUES (?, ?, 'email', 'person@example.com', 'person@example.com',
                      1, 1, '2026-07-11T11:00:00Z')
            """,
            (person_id, source_record_id),
        ).lastrowid
        hashed_identity_id = self.connection.execute(
            """
            INSERT INTO hashed_identity (
                person_id, evidence_identity_id, evidence_source_record_id,
                identity_hmac, key_version, created_at
            ) VALUES (?, ?, ?, 'hmac-after-evidence', 'ghost-key-v1',
                      '2026-07-11T12:00:00Z')
            """,
            (person_id, email_identity_id, source_record_id),
        ).lastrowid

        self.connection.execute(
            "DELETE FROM person_identity WHERE id = ?", (email_identity_id,)
        )
        replacement_identity_id = self.connection.execute(
            """
            INSERT INTO person_identity (
                person_id, source_record_id, identity_type, display_value,
                normalized_value, verified, applicant_provided, observed_at
            ) VALUES (?, ?, 'email', 'replacement@example.com',
                      'replacement@example.com', 1, 1, '2026-07-12T11:00:00Z')
            """,
            (person_id, source_record_id),
        ).lastrowid
        self.assertNotEqual(replacement_identity_id, email_identity_id)
        self.assertEqual(
            self.connection.execute(
                "SELECT identity_hmac FROM hashed_identity WHERE id = ?",
                (hashed_identity_id,),
            ).fetchone()[0],
            "hmac-after-evidence",
        )
        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute(
                "UPDATE hashed_identity SET identity_hmac = 'changed' WHERE id = ?",
                (hashed_identity_id,),
            )
        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute(
                "DELETE FROM hashed_identity WHERE id = ?", (hashed_identity_id,)
            )

    def test_consent_supersession_cannot_cross_identity_or_scope(self) -> None:
        person_id, event_id, _, source_record_id = self._seed_provenance()
        other_person_id = self.connection.execute(
            "INSERT INTO person DEFAULT VALUES"
        ).lastrowid
        other_event_id = self._add_event("consent-other")
        other_source_record_id = self._add_source_record(
            other_event_id, "consent-other"
        )

        cases = (
            {
                "label": "person",
                "old": (person_id, event_id, source_record_id, "purpose-person", "partners"),
                "new": (
                    other_person_id,
                    event_id,
                    source_record_id,
                    "purpose-person",
                    "partners",
                ),
            },
            {
                "label": "event",
                "old": (person_id, event_id, source_record_id, "purpose-event", "partners"),
                "new": (
                    person_id,
                    other_event_id,
                    other_source_record_id,
                    "purpose-event",
                    "partners",
                ),
            },
            {
                "label": "purpose",
                "old": (person_id, event_id, source_record_id, "purpose-old", "partners"),
                "new": (person_id, event_id, source_record_id, "purpose-new", "partners"),
            },
            {
                "label": "recipient_scope",
                "old": (person_id, event_id, source_record_id, "purpose-scope", "partners"),
                "new": (person_id, event_id, source_record_id, "purpose-scope", "internal"),
            },
        )

        for case in cases:
            predecessor_id = self.connection.execute(
                """
                INSERT INTO consent_assertion (
                    person_id, event_id, source_record_id, purpose, recipient_scope,
                    granted, source_text, source_version, observed_at, evidence_source
                ) VALUES (?, ?, ?, ?, ?, 1, 'Consent', 'form-v1',
                          '2026-07-11T11:00:00Z', 'luma')
                """,
                case["old"],
            ).lastrowid
            with self.subTest(mismatch=case["label"]):
                with self.assertRaises(sqlite3.IntegrityError):
                    self.connection.execute(
                        """
                        INSERT INTO consent_assertion (
                            person_id, event_id, source_record_id, purpose,
                            recipient_scope, granted, source_text, source_version,
                            observed_at, evidence_source, supersedes_assertion_id
                        ) VALUES (?, ?, ?, ?, ?, 0, 'Withdrawal', 'form-v2',
                                  '2026-07-12T11:00:00Z', 'luma', ?)
                        """,
                        (*case["new"], predecessor_id),
                    )

    def test_event_scoped_writes_reject_cross_event_source_records(self) -> None:
        person_id, event_id, _, source_record_id = self._seed_provenance()
        other_event_id = self._add_event("coherence-source")

        invalid_inserts = (
            (
                "consent_assertion",
                """
                INSERT INTO consent_assertion (
                    person_id, event_id, source_record_id, purpose, recipient_scope,
                    granted, source_text, source_version, observed_at, evidence_source
                ) VALUES (?, ?, ?, 'stats', 'partners', 1, 'Consent', 'v1',
                          '2026-07-12T11:00:00Z', 'luma')
                """,
            ),
            (
                "application",
                """
                INSERT INTO application (
                    person_id, event_id, source_record_id, status, applied_at
                ) VALUES (?, ?, ?, 'applied', '2026-07-12T11:00:00Z')
                """,
            ),
            (
                "team",
                """
                INSERT INTO team (event_id, source_record_id, canonical_name)
                VALUES (?, ?, 'Wrong event team')
                """,
            ),
            (
                "classification",
                """
                INSERT INTO classification (
                    person_id, event_id, source_record_id, taxonomy_version, observed_at
                ) VALUES (?, ?, ?, 'taxonomy-v1', '2026-07-12T11:00:00Z')
                """,
            ),
            (
                "intro",
                """
                INSERT INTO intro (
                    person_id, event_id, source_record_id, partner, introduced_at
                ) VALUES (?, ?, ?, 'Partner', '2026-07-12T11:00:00Z')
                """,
            ),
        )

        for index, (table, sql) in enumerate(invalid_inserts):
            wrong_source_record_id = self._add_source_record(
                other_event_id, f"coherence-{table}-{index}"
            )
            params = (
                (event_id, wrong_source_record_id)
                if table == "team"
                else (person_id, event_id, wrong_source_record_id)
            )
            with self.subTest(table=table):
                with self.assertRaises(sqlite3.IntegrityError):
                    self.connection.execute(sql, params)

        wrong_submission_source = self._add_source_record(
            other_event_id, "coherence-submission-source"
        )
        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute(
                """
                INSERT INTO submission (event_id, source_record_id, title)
                VALUES (?, ?, 'Wrong source event')
                """,
                (event_id, wrong_submission_source),
            )

        wrong_participation_source = self._add_source_record(
            other_event_id, "coherence-participation-source"
        )
        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute(
                """
                INSERT INTO participation (
                    person_id, event_id, source_record_id, checked_in
                ) VALUES (?, ?, ?, 1)
                """,
                (person_id, event_id, wrong_participation_source),
            )

    def test_team_and_submission_links_reject_cross_event_entities(self) -> None:
        person_id, event_id, _, _ = self._seed_provenance()
        other_event_id = self._add_event("coherence-links")
        other_team_source = self._add_source_record(other_event_id, "other-team")
        other_team_id = self.connection.execute(
            """
            INSERT INTO team (event_id, source_record_id, canonical_name)
            VALUES (?, ?, 'Other team')
            """,
            (other_event_id, other_team_source),
        ).lastrowid
        other_submission_source = self._add_source_record(
            other_event_id, "other-submission"
        )
        other_submission_id = self.connection.execute(
            """
            INSERT INTO submission (event_id, team_id, source_record_id, title)
            VALUES (?, ?, ?, 'Other submission')
            """,
            (other_event_id, other_team_id, other_submission_source),
        ).lastrowid

        local_submission_source = self._add_source_record(event_id, "local-submission")
        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute(
                """
                INSERT INTO submission (event_id, team_id, source_record_id, title)
                VALUES (?, ?, ?, 'Cross-event team')
                """,
                (event_id, other_team_id, local_submission_source),
            )

        for label, team_id, submission_id in (
            ("team", other_team_id, None),
            ("submission", None, other_submission_id),
        ):
            local_participation_source = self._add_source_record(
                event_id, f"local-participation-{label}"
            )
            with self.subTest(link=label):
                with self.assertRaises(sqlite3.IntegrityError):
                    self.connection.execute(
                        """
                        INSERT INTO participation (
                            person_id, event_id, source_record_id, checked_in,
                            team_id, submission_id
                        ) VALUES (?, ?, ?, 1, ?, ?)
                        """,
                        (
                            person_id,
                            event_id,
                            local_participation_source,
                            team_id,
                            submission_id,
                        ),
                    )

    def test_source_provenance_event_links_cannot_be_reassigned(self) -> None:
        _, event_id, source_file_id, source_record_id = self._seed_provenance()
        other_event_id = self._add_event("provenance-reassignment")
        other_source_record_id = self._add_source_record(
            other_event_id, "provenance-reassignment"
        )
        other_source_file_id = self.connection.execute(
            "SELECT source_file_id FROM source_record WHERE id = ?",
            (other_source_record_id,),
        ).fetchone()[0]

        with self.subTest(provenance="source_file_event"):
            with self.assertRaises(sqlite3.IntegrityError):
                self.connection.execute(
                    "UPDATE source_file SET event_id = ? WHERE id = ?",
                    (other_event_id, source_file_id),
                )
        with self.subTest(provenance="source_record_file"):
            with self.assertRaises(sqlite3.IntegrityError):
                self.connection.execute(
                    "UPDATE source_record SET source_file_id = ? WHERE id = ?",
                    (other_source_file_id, source_record_id),
                )
        self.assertEqual(
            self.connection.execute(
                "SELECT event_id FROM source_file WHERE id = ?", (source_file_id,)
            ).fetchone()[0],
            event_id,
        )

    def test_fact_assertion_source_matches_event_scoped_subject(self) -> None:
        person_id, event_id, _, source_record_id = self._seed_provenance()
        application_id = self.connection.execute(
            """
            INSERT INTO application (
                person_id, event_id, source_record_id, status, applied_at
            ) VALUES (?, ?, ?, 'applied', '2026-07-11T11:00:00Z')
            """,
            (person_id, event_id, source_record_id),
        ).lastrowid
        other_event_id = self._add_event("fact-source")
        other_source_record_id = self._add_source_record(other_event_id, "fact-source")

        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute(
                """
                INSERT INTO fact_assertion (
                    subject_table, subject_id, field_name, source_record_id,
                    mapping_version, authority, observed_at
                ) VALUES ('application', ?, 'status', ?, 'luma-v1',
                          'platform', '2026-07-12T11:00:00Z')
                """,
                (application_id, other_source_record_id),
            )

    def test_ghost_transition_requires_all_person_linked_pii_erased(self) -> None:
        person_id, event_id, _, source_record_id = self._seed_provenance()
        identity_id = self.connection.execute(
            """
            INSERT INTO person_identity (
                person_id, source_record_id, identity_type, display_value,
                normalized_value, verified, applicant_provided, observed_at
            ) VALUES (?, ?, 'email', 'person@example.com', 'person@example.com',
                      1, 1, '2026-07-11T11:00:00Z')
            """,
            (person_id, source_record_id),
        ).lastrowid
        evidence_id = self.connection.execute(
            """
            INSERT INTO identity_evidence (
                source_record_id, person_id, person_identity_id, evidence_type,
                normalized_value, applicant_provided, mapping_version, observed_at
            ) VALUES (?, ?, ?, 'exact_email', 'person@example.com', 1,
                      'luma-v1', '2026-07-11T11:00:00Z')
            """,
            (source_record_id, person_id, identity_id),
        ).lastrowid
        application_id = self.connection.execute(
            """
            INSERT INTO application (
                person_id, event_id, source_record_id, status,
                raw_answers_json, applied_at
            ) VALUES (?, ?, ?, 'applied', '{"bio":"private"}',
                      '2026-07-11T11:00:00Z')
            """,
            (person_id, event_id, source_record_id),
        ).lastrowid
        enrichment_id = self.connection.execute(
            """
            INSERT INTO enrichment_snapshot (
                person_id, source_record_id, source_type, payload_json,
                fetched_at, expires_at
            ) VALUES (?, ?, 'github', '{"login":"private"}',
                      '2026-07-11T11:00:00Z', '2027-07-11T11:00:00Z')
            """,
            (person_id, source_record_id),
        ).lastrowid
        classification_id = self.connection.execute(
            """
            INSERT INTO classification (
                person_id, event_id, source_record_id, taxonomy_version,
                facts_json, observed_at
            ) VALUES (?, ?, ?, 'taxonomy-v1', '["private fact"]',
                      '2026-07-11T11:00:00Z')
            """,
            (person_id, event_id, source_record_id),
        ).lastrowid
        intro_id = self.connection.execute(
            """
            INSERT INTO intro (
                person_id, event_id, source_record_id, partner, context, introduced_at
            ) VALUES (?, ?, ?, 'Partner', 'Private context',
                      '2026-07-11T11:00:00Z')
            """,
            (person_id, event_id, source_record_id),
        ).lastrowid
        review_id = self.connection.execute(
            """
            INSERT INTO identity_review (
                source_record_id, provisional_person_id, reason_code,
                evidence_json
            ) VALUES (?, ?, 'possible_match', '{"email":"private"}')
            """,
            (source_record_id, person_id),
        ).lastrowid

        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute(
                "UPDATE person SET state = 'ghost' WHERE id = ?", (person_id,)
            )

        self.connection.execute(
            """
            UPDATE identity_evidence
            SET normalized_value = NULL, person_identity_id = NULL
            WHERE id = ?
            """,
            (evidence_id,),
        )
        self.connection.execute("DELETE FROM person_identity WHERE id = ?", (identity_id,))
        self.connection.execute(
            "UPDATE source_record SET raw_payload_json = NULL WHERE id = ?",
            (source_record_id,),
        )
        self.connection.execute(
            "UPDATE application SET raw_answers_json = NULL WHERE id = ?",
            (application_id,),
        )
        self.connection.execute(
            "UPDATE enrichment_snapshot SET payload_json = NULL WHERE id = ?",
            (enrichment_id,),
        )
        self.connection.execute(
            "UPDATE classification SET facts_json = NULL WHERE id = ?",
            (classification_id,),
        )
        self.connection.execute("UPDATE intro SET context = NULL WHERE id = ?", (intro_id,))
        self.connection.execute(
            "UPDATE identity_review SET evidence_json = NULL WHERE id = ?", (review_id,)
        )
        self.connection.execute(
            "UPDATE person SET state = 'ghost' WHERE id = ?", (person_id,)
        )
        self.assertEqual(
            self.connection.execute(
                "SELECT state FROM person WHERE id = ?", (person_id,)
            ).fetchone()[0],
            "ghost",
        )

    def test_ghost_cannot_regain_person_linked_pii(self) -> None:
        person_id, event_id, _, source_record_id = self._seed_provenance()
        self.connection.execute(
            "UPDATE source_record SET raw_payload_json = NULL WHERE id = ?",
            (source_record_id,),
        )
        self.connection.execute(
            "UPDATE person SET state = 'ghost' WHERE id = ?", (person_id,)
        )

        invalid_writes = (
            (
                "person_identity",
                """
                INSERT INTO person_identity (
                    person_id, source_record_id, identity_type, display_value,
                    normalized_value, verified, applicant_provided, observed_at
                ) VALUES (?, ?, 'email', 'ghost@example.com', 'ghost@example.com',
                          1, 1, '2026-07-12T11:00:00Z')
                """,
                (person_id, source_record_id),
            ),
            (
                "application_raw_answers",
                """
                INSERT INTO application (
                    person_id, event_id, source_record_id, status,
                    raw_answers_json, applied_at
                ) VALUES (?, ?, ?, 'applied', '{"private":true}',
                          '2026-07-12T11:00:00Z')
                """,
                (person_id, event_id, source_record_id),
            ),
            (
                "enrichment_payload",
                """
                INSERT INTO enrichment_snapshot (
                    person_id, source_record_id, source_type, payload_json,
                    fetched_at, expires_at
                ) VALUES (?, ?, 'github', '{"private":true}',
                          '2026-07-12T11:00:00Z', '2027-07-12T11:00:00Z')
                """,
                (person_id, source_record_id),
            ),
            (
                "classification_facts",
                """
                INSERT INTO classification (
                    person_id, event_id, source_record_id, taxonomy_version,
                    facts_json, observed_at
                ) VALUES (?, ?, ?, 'taxonomy-v1', '["private"]',
                          '2026-07-12T11:00:00Z')
                """,
                (person_id, event_id, source_record_id),
            ),
            (
                "intro_context",
                """
                INSERT INTO intro (
                    person_id, event_id, source_record_id, partner,
                    context, introduced_at
                ) VALUES (?, ?, ?, 'Partner', 'Private context',
                          '2026-07-12T11:00:00Z')
                """,
                (person_id, event_id, source_record_id),
            ),
        )
        for label, sql, params in invalid_writes:
            with self.subTest(write=label):
                with self.assertRaises(sqlite3.IntegrityError):
                    self.connection.execute(sql, params)

        assertion_id = self.connection.execute(
            """
            INSERT INTO fact_assertion (
                subject_table, subject_id, field_name, source_record_id,
                mapping_version, authority, observed_at
            ) VALUES ('person', ?, 'name', ?, 'luma-v1', 'applicant',
                      '2026-07-12T11:00:00Z')
            """,
            (person_id, source_record_id),
        ).lastrowid
        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute(
                """
                INSERT INTO fact_assertion_payload (
                    assertion_id, canonical_value_json, pii_class
                ) VALUES (?, '"Private"', 'direct')
                """,
                (assertion_id,),
            )

        raw_source_record_id = self._add_source_record(event_id, "ghost-raw-link")
        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute(
                """
                INSERT INTO participation (
                    person_id, event_id, source_record_id, checked_in
                ) VALUES (?, ?, ?, 1)
                """,
                (person_id, event_id, raw_source_record_id),
            )

    def test_fact_payload_requires_valid_json_is_immutable_but_erasable(self) -> None:
        person_id, _, _, source_record_id = self._seed_provenance()
        invalid_assertion_id = self.connection.execute(
            """
            INSERT INTO fact_assertion (
                subject_table, subject_id, field_name, source_record_id,
                mapping_version, authority, observed_at
            ) VALUES ('person', ?, 'name', ?, 'luma-v1', 'applicant',
                      '2026-07-11T11:00:00Z')
            """,
            (person_id, source_record_id),
        ).lastrowid
        with self.subTest(rule="valid_json"):
            with self.assertRaises(sqlite3.IntegrityError):
                self.connection.execute(
                    """
                    INSERT INTO fact_assertion_payload (
                        assertion_id, canonical_value_json, pii_class
                    ) VALUES (?, 'not-json', 'non_pii')
                    """,
                    (invalid_assertion_id,),
                )
        self.connection.execute(
            "DELETE FROM fact_assertion_payload WHERE assertion_id = ?",
            (invalid_assertion_id,),
        )

        valid_assertion_id = self.connection.execute(
            """
            INSERT INTO fact_assertion (
                subject_table, subject_id, field_name, source_record_id,
                mapping_version, authority, observed_at
            ) VALUES ('person', ?, 'state', ?, 'luma-v1', 'system',
                      '2026-07-11T11:00:00Z')
            """,
            (person_id, source_record_id),
        ).lastrowid
        self.connection.execute(
            """
            INSERT INTO fact_assertion_payload (
                assertion_id, canonical_value_json, pii_class
            ) VALUES (?, '"active"', 'non_pii')
            """,
            (valid_assertion_id,),
        )
        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute(
                """
                UPDATE fact_assertion_payload
                SET canonical_value_json = '"changed"'
                WHERE assertion_id = ?
                """,
                (valid_assertion_id,),
            )
        self.connection.execute(
            "DELETE FROM fact_assertion_payload WHERE assertion_id = ?",
            (valid_assertion_id,),
        )
        self.assertEqual(
            self.connection.execute(
                "SELECT count(*) FROM fact_assertion WHERE id = ?",
                (valid_assertion_id,),
            ).fetchone()[0],
            1,
        )

    def test_ghost_cannot_link_a_person_record_to_raw_source_payloads(self) -> None:
        person_id, event_id, _, erased_source_record_id = self._seed_provenance()
        self.connection.execute(
            "UPDATE source_record SET raw_payload_json = NULL WHERE id = ?",
            (erased_source_record_id,),
        )
        self.connection.execute(
            "UPDATE person SET state = 'ghost' WHERE id = ?", (person_id,)
        )
        raw_sources = {
            label: self._add_source_record(event_id, f"ghost-link-{label}")
            for label in (
                "consent",
                "evidence",
                "decision",
                "review",
                "fact",
            )
        }
        invalid_links = (
            (
                "consent",
                """
                INSERT INTO consent_assertion (
                    person_id, event_id, source_record_id, purpose,
                    recipient_scope, granted, source_text, source_version,
                    observed_at, evidence_source
                ) VALUES (?, ?, ?, 'stats', 'partners', 0, 'Withdrawal',
                          'v1', '2026-07-12T11:00:00Z', 'luma')
                """,
                (person_id, event_id, raw_sources["consent"]),
            ),
            (
                "identity_evidence",
                """
                INSERT INTO identity_evidence (
                    source_record_id, person_id, evidence_type,
                    mapping_version, observed_at
                ) VALUES (?, ?, 'manual', 'luma-v1', '2026-07-12T11:00:00Z')
                """,
                (raw_sources["evidence"], person_id),
            ),
            (
                "identity_decision",
                """
                INSERT INTO identity_decision (
                    source_record_id, person_id, decision, reviewer,
                    reason, decided_at
                ) VALUES (?, ?, 'linked', 'reviewer', 'manual',
                          '2026-07-12T11:00:00Z')
                """,
                (raw_sources["decision"], person_id),
            ),
            (
                "identity_review",
                """
                INSERT INTO identity_review (
                    source_record_id, provisional_person_id, reason_code,
                    evidence_json
                ) VALUES (?, ?, 'manual', NULL)
                """,
                (raw_sources["review"], person_id),
            ),
            (
                "fact_assertion",
                """
                INSERT INTO fact_assertion (
                    subject_table, subject_id, field_name, source_record_id,
                    mapping_version, authority, observed_at
                ) VALUES ('person', ?, 'state', ?, 'luma-v1', 'system',
                          '2026-07-12T11:00:00Z')
                """,
                (person_id, raw_sources["fact"]),
            ),
        )
        for label, sql, params in invalid_links:
            with self.subTest(raw_link=label):
                with self.assertRaises(sqlite3.IntegrityError):
                    self.connection.execute(sql, params)

        with self.subTest(write="identity_evidence_direct_value"):
            with self.assertRaises(sqlite3.IntegrityError):
                self.connection.execute(
                    """
                    INSERT INTO identity_evidence (
                        source_record_id, person_id, evidence_type, normalized_value,
                        mapping_version, observed_at
                    ) VALUES (?, ?, 'manual', 'direct@example.com', 'luma-v1',
                              '2026-07-12T11:00:00Z')
                    """,
                    (erased_source_record_id, person_id),
                )

        review_id = self.connection.execute(
            """
            INSERT INTO identity_review (
                source_record_id, provisional_person_id, reason_code, evidence_json
            ) VALUES (?, ?, 'manual', NULL)
            """,
            (erased_source_record_id, person_id),
        ).lastrowid
        with self.subTest(write="identity_review_evidence_update"):
            with self.assertRaises(sqlite3.IntegrityError):
                self.connection.execute(
                    "UPDATE identity_review SET evidence_json = '{}' WHERE id = ?",
                    (review_id,),
                )

    def test_publication_event_must_match_aggregate_event(self) -> None:
        _, event_id, _, _ = self._seed_provenance()
        other_event_id = self._add_event("publication-mismatch")
        aggregate_id = self.connection.execute(
            """
            INSERT INTO aggregate_snapshot (event_id, config_hash, payload_json)
            VALUES (?, 'config-one', '{}')
            """,
            (event_id,),
        ).lastrowid
        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute(
                """
                INSERT INTO publication (
                    event_id, aggregate_snapshot_id, partner_key,
                    report_hash, published_at
                ) VALUES (?, ?, 'partner', 'report-mismatch',
                          '2026-07-12T11:00:00Z')
                """,
                (other_event_id, aggregate_id),
            )

    def test_identity_evidence_owner_must_match_identity_and_refs_are_immutable(self) -> None:
        person_id, _, _, source_record_id = self._seed_provenance()
        other_person_id = self.connection.execute(
            "INSERT INTO person DEFAULT VALUES"
        ).lastrowid
        identity_id = self.connection.execute(
            """
            INSERT INTO person_identity (
                person_id, source_record_id, identity_type, display_value,
                normalized_value, verified, applicant_provided, observed_at
            ) VALUES (?, ?, 'email', 'owner@example.com', 'owner@example.com',
                      1, 1, '2026-07-11T11:00:00Z')
            """,
            (person_id, source_record_id),
        ).lastrowid
        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute(
                """
                INSERT INTO identity_evidence (
                    source_record_id, person_id, person_identity_id,
                    evidence_type, mapping_version, observed_at
                ) VALUES (?, ?, ?, 'exact_email', 'luma-v1',
                          '2026-07-11T11:00:00Z')
                """,
                (source_record_id, other_person_id, identity_id),
            )

        evidence_id = self.connection.execute(
            """
            INSERT INTO identity_evidence (
                source_record_id, person_id, person_identity_id,
                evidence_type, mapping_version, observed_at
            ) VALUES (?, ?, ?, 'exact_email', 'luma-v1',
                      '2026-07-11T11:00:00Z')
            """,
            (source_record_id, person_id, identity_id),
        ).lastrowid
        other_source_record_id = self._add_source_record(
            self._add_event("identity-evidence-owner"), "identity-evidence-owner"
        )
        for column, value in (
            ("person_id", other_person_id),
            ("source_record_id", other_source_record_id),
        ):
            self.connection.execute("SAVEPOINT ownership_probe")
            with self.subTest(immutable=column):
                with self.assertRaises(sqlite3.IntegrityError):
                    self.connection.execute(
                        f"UPDATE identity_evidence SET {column} = ? WHERE id = ?",
                        (value, evidence_id),
                    )
            self.connection.execute("ROLLBACK TO ownership_probe")
            self.connection.execute("RELEASE ownership_probe")

    def test_event_scoped_parent_references_are_immutable(self) -> None:
        person_id, event_id, _, source_record_id = self._seed_provenance()
        other_person_id = self.connection.execute(
            "INSERT INTO person DEFAULT VALUES"
        ).lastrowid
        other_event_id = self._add_event("immutable-parent")

        team_source = self._add_source_record(event_id, "immutable-team")
        team_id = self.connection.execute(
            "INSERT INTO team (event_id, source_record_id) VALUES (?, ?)",
            (event_id, team_source),
        ).lastrowid
        other_team_source = self._add_source_record(
            other_event_id, "immutable-other-team"
        )
        other_team_id = self.connection.execute(
            "INSERT INTO team (event_id, source_record_id) VALUES (?, ?)",
            (other_event_id, other_team_source),
        ).lastrowid
        submission_source = self._add_source_record(
            event_id, "immutable-submission"
        )
        submission_id = self.connection.execute(
            """
            INSERT INTO submission (event_id, team_id, source_record_id)
            VALUES (?, ?, ?)
            """,
            (event_id, team_id, submission_source),
        ).lastrowid
        other_submission_source = self._add_source_record(
            other_event_id, "immutable-other-submission"
        )
        other_submission_id = self.connection.execute(
            """
            INSERT INTO submission (event_id, team_id, source_record_id)
            VALUES (?, ?, ?)
            """,
            (other_event_id, other_team_id, other_submission_source),
        ).lastrowid
        application_id = self.connection.execute(
            """
            INSERT INTO application (
                person_id, event_id, source_record_id, status, applied_at
            ) VALUES (?, ?, ?, 'applied', '2026-07-11T11:00:00Z')
            """,
            (person_id, event_id, source_record_id),
        ).lastrowid
        participation_source = self._add_source_record(
            event_id, "immutable-participation"
        )
        participation_id = self.connection.execute(
            """
            INSERT INTO participation (
                person_id, event_id, source_record_id, team_id, submission_id
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (person_id, event_id, participation_source, team_id, submission_id),
        ).lastrowid
        intro_source = self._add_source_record(event_id, "immutable-intro")
        intro_id = self.connection.execute(
            """
            INSERT INTO intro (
                person_id, event_id, source_record_id, partner, introduced_at
            ) VALUES (?, ?, ?, 'Partner', '2026-07-11T11:00:00Z')
            """,
            (person_id, event_id, intro_source),
        ).lastrowid
        aggregate_id = self.connection.execute(
            """
            INSERT INTO aggregate_snapshot (event_id, config_hash, payload_json)
            VALUES (?, 'immutable-config-one', '{}')
            """,
            (event_id,),
        ).lastrowid
        other_aggregate_id = self.connection.execute(
            """
            INSERT INTO aggregate_snapshot (event_id, config_hash, payload_json)
            VALUES (?, 'immutable-config-two', '{}')
            """,
            (other_event_id,),
        ).lastrowid
        publication_id = self.connection.execute(
            """
            INSERT INTO publication (
                event_id, aggregate_snapshot_id, partner_key,
                report_hash, published_at
            ) VALUES (?, ?, 'partner', 'immutable-report',
                      '2026-07-12T11:00:00Z')
            """,
            (event_id, aggregate_id),
        ).lastrowid

        target_sources = {
            name: self._add_source_record(other_event_id, f"immutable-target-{name}")
            for name in ("team", "submission", "application", "participation", "intro")
        }
        updates = (
            (
                "team",
                "UPDATE team SET event_id = ?, source_record_id = ? WHERE id = ?",
                (other_event_id, target_sources["team"], team_id),
            ),
            (
                "submission",
                """
                UPDATE submission
                SET event_id = ?, team_id = ?, source_record_id = ?
                WHERE id = ?
                """,
                (
                    other_event_id,
                    other_team_id,
                    target_sources["submission"],
                    submission_id,
                ),
            ),
            (
                "application_person",
                "UPDATE application SET person_id = ? WHERE id = ?",
                (other_person_id, application_id),
            ),
            (
                "application_event",
                """
                UPDATE application SET event_id = ?, source_record_id = ? WHERE id = ?
                """,
                (other_event_id, target_sources["application"], application_id),
            ),
            (
                "participation_person",
                "UPDATE participation SET person_id = ? WHERE id = ?",
                (other_person_id, participation_id),
            ),
            (
                "participation_event_links",
                """
                UPDATE participation
                SET event_id = ?, source_record_id = ?, team_id = ?, submission_id = ?
                WHERE id = ?
                """,
                (
                    other_event_id,
                    target_sources["participation"],
                    other_team_id,
                    other_submission_id,
                    participation_id,
                ),
            ),
            (
                "intro_person",
                "UPDATE intro SET person_id = ? WHERE id = ?",
                (other_person_id, intro_id),
            ),
            (
                "intro_event",
                "UPDATE intro SET event_id = ?, source_record_id = ? WHERE id = ?",
                (other_event_id, target_sources["intro"], intro_id),
            ),
            (
                "aggregate_event",
                "UPDATE aggregate_snapshot SET event_id = ? WHERE id = ?",
                (other_event_id, aggregate_id),
            ),
            (
                "publication_refs",
                """
                UPDATE publication SET event_id = ?, aggregate_snapshot_id = ?
                WHERE id = ?
                """,
                (other_event_id, other_aggregate_id, publication_id),
            ),
        )
        for label, sql, params in updates:
            self.connection.execute("SAVEPOINT reparent_probe")
            with self.subTest(reparent=label):
                with self.assertRaises(sqlite3.IntegrityError):
                    self.connection.execute(sql, params)
            self.connection.execute("ROLLBACK TO reparent_probe")
            self.connection.execute("RELEASE reparent_probe")


if __name__ == "__main__":
    unittest.main()
