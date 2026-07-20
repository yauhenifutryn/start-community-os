"""Transactional and replay behavior for the canonical ingestion pipeline."""

from __future__ import annotations

import csv
from pathlib import Path
import sqlite3
import tempfile
import unittest

from community_os.config import load_mapping
from community_os.pipeline import ingest_file


ROOT = Path(__file__).resolve().parents[1]


class PipelineIngestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.connection = sqlite3.connect(":memory:")
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys = ON")
        self.connection.executescript(
            (ROOT / "community_os" / "schema.sql").read_text(encoding="utf-8")
        )
        self.event_id = self.connection.execute(
            """INSERT INTO event(event_key,name,starts_at,event_type)
               VALUES('event-1','Synthetic event','2026-07-10T08:00:00Z','hackathon')"""
        ).lastrowid
        self.mapping = load_mapping(ROOT / "mappings" / "luma-guests-v2.json")
        self.fixture = ROOT / "tests" / "fixtures" / "luma_guests_synthetic.csv"

    def tearDown(self) -> None:
        self.connection.close()

    def _add_event(self, suffix: str) -> int:
        return int(self.connection.execute(
            """INSERT INTO event(event_key,name,starts_at,event_type)
               VALUES(?,?,?,'hackathon')""",
            (
                f"event-{suffix}",
                f"Synthetic event {suffix}",
                "2026-07-12T08:00:00Z",
            ),
        ).lastrowid)

    def test_repeated_file_hash_is_idempotent(self) -> None:
        first = ingest_file(
            self.connection,
            event_id=self.event_id,
            path=self.fixture,
            mapping=self.mapping,
            observed_at="2026-07-11T10:00:00Z",
        )
        second = ingest_file(
            self.connection,
            event_id=self.event_id,
            path=self.fixture,
            mapping=self.mapping,
            observed_at="2026-07-11T10:05:00Z",
        )

        self.assertFalse(first.skipped)
        self.assertTrue(second.skipped)
        self.assertEqual(second.source_file_id, first.source_file_id)
        self.assertEqual(self.connection.execute("SELECT COUNT(*) FROM source_file").fetchone()[0], 1)
        self.assertEqual(self.connection.execute("SELECT COUNT(*) FROM source_record").fetchone()[0], 1)
        self.assertEqual(self.connection.execute("SELECT COUNT(*) FROM application").fetchone()[0], 1)

    def test_identical_file_hash_is_ingested_independently_for_each_event(self) -> None:
        other_event_id = self._add_event("2")

        first = ingest_file(
            self.connection,
            event_id=self.event_id,
            path=self.fixture,
            mapping=self.mapping,
            observed_at="2026-07-11T10:00:00Z",
        )
        second = ingest_file(
            self.connection,
            event_id=other_event_id,
            path=self.fixture,
            mapping=self.mapping,
            observed_at="2026-07-12T10:00:00Z",
        )

        self.assertFalse(first.skipped)
        self.assertFalse(second.skipped)
        self.assertNotEqual(second.source_file_id, first.source_file_id)
        rows = self.connection.execute(
            """SELECT event_id,file_sha256 FROM source_file
               WHERE source_type=? ORDER BY event_id""",
            (self.mapping.source_type,),
        ).fetchall()
        self.assertEqual(
            [(row["event_id"], row["file_sha256"]) for row in rows],
            [(self.event_id, first.file_sha256), (other_event_id, first.file_sha256)],
        )

    def test_reingest_suffix_sequence_is_independent_for_each_event(self) -> None:
        other_event_id = self._add_event("2")
        for event_id, observed_at in (
            (self.event_id, "2026-07-11T10:00:00Z"),
            (other_event_id, "2026-07-12T10:00:00Z"),
        ):
            ingest_file(
                self.connection,
                event_id=event_id,
                path=self.fixture,
                mapping=self.mapping,
                observed_at=observed_at,
            )
            ingest_file(
                self.connection,
                event_id=event_id,
                path=self.fixture,
                mapping=self.mapping,
                observed_at=observed_at,
                reingest=True,
            )

        rows = self.connection.execute(
            """SELECT event_id,file_sha256 FROM source_file
               WHERE source_type=? ORDER BY event_id,id""",
            (self.mapping.source_type,),
        ).fetchall()
        self.assertEqual(
            [(row["event_id"], row["file_sha256"]) for row in rows],
            [
                (self.event_id, rows[0]["file_sha256"]),
                (self.event_id, f"{rows[0]['file_sha256']}:reingest:1"),
                (other_event_id, rows[0]["file_sha256"]),
                (other_event_id, f"{rows[0]['file_sha256']}:reingest:1"),
            ],
        )

    def test_same_file_requires_explicit_reingest_and_supersedes_without_history_rewrite(self) -> None:
        first = ingest_file(
            self.connection,
            event_id=self.event_id,
            path=self.fixture,
            mapping=self.mapping,
            observed_at="2026-07-11T10:00:00Z",
        )
        replay = ingest_file(
            self.connection,
            event_id=self.event_id,
            path=self.fixture,
            mapping=self.mapping,
            observed_at="2026-07-11T11:00:00Z",
            reingest=True,
        )

        self.assertFalse(replay.skipped)
        self.assertNotEqual(replay.source_file_id, first.source_file_id)
        self.assertEqual(self.connection.execute("SELECT COUNT(*) FROM source_file").fetchone()[0], 2)
        statuses = self.connection.execute(
            """SELECT fa.id,fa.source_record_id,fa.supersedes_assertion_id,
                      p.canonical_value_json
               FROM fact_assertion fa JOIN fact_assertion_payload p ON p.assertion_id=fa.id
               WHERE fa.subject_table='application' AND fa.field_name='status'
               ORDER BY fa.id"""
        ).fetchall()
        self.assertEqual(len(statuses), 2)
        self.assertEqual(statuses[1]["supersedes_assertion_id"], statuses[0]["id"])
        self.assertNotEqual(statuses[1]["source_record_id"], statuses[0]["source_record_id"])
        self.assertEqual(self.connection.execute("SELECT COUNT(*) FROM person").fetchone()[0], 1)

    def test_corrected_export_new_hash_supersedes_current_assertion(self) -> None:
        first = ingest_file(
            self.connection,
            event_id=self.event_id,
            path=self.fixture,
            mapping=self.mapping,
            observed_at="2026-07-11T10:00:00Z",
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            corrected = Path(temporary_directory) / "corrected.csv"
            text = self.fixture.read_text(encoding="utf-8-sig")
            corrected.write_text(text.replace(",approved,", ",declined,"), encoding="utf-8")
            second = ingest_file(
                self.connection,
                event_id=self.event_id,
                path=corrected,
                mapping=self.mapping,
                observed_at="2026-07-11T12:00:00Z",
                reingest=True,
            )

        self.assertNotEqual(second.file_sha256, first.file_sha256)
        self.assertEqual(self.connection.execute("SELECT COUNT(*) FROM person").fetchone()[0], 1)
        current = self.connection.execute(
            """SELECT p.canonical_value_json
               FROM fact_assertion fa JOIN fact_assertion_payload p ON p.assertion_id=fa.id
               WHERE fa.subject_table='application' AND fa.field_name='status'
                 AND NOT EXISTS (
                     SELECT 1 FROM fact_assertion newer
                     WHERE newer.supersedes_assertion_id=fa.id
                 )"""
        ).fetchone()[0]
        self.assertEqual(current, '"declined"')

    def test_any_record_failure_rolls_back_the_whole_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            two_rows = Path(temporary_directory) / "two.csv"
            with self.fixture.open("r", encoding="utf-8-sig", newline="") as stream:
                reader = csv.DictReader(stream)
                accepted = next(row for row in reader if row["guest_id"] == "gst_synthetic_001")
                fieldnames = reader.fieldnames
            duplicate = {**accepted, "guest_id": "gst_synthetic_003", "email": "ada2@example.org"}
            with two_rows.open("w", encoding="utf-8", newline="") as stream:
                writer = csv.DictWriter(stream, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows([accepted, duplicate])

            calls = 0

            def fail_second(*args, **kwargs):
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise RuntimeError("synthetic canonical write failure")
                from community_os.normalize import normalize_record

                return normalize_record(*args, **kwargs)

            with self.assertRaisesRegex(RuntimeError, "synthetic canonical write failure"):
                ingest_file(
                    self.connection,
                    event_id=self.event_id,
                    path=two_rows,
                    mapping=self.mapping,
                    observed_at="2026-07-11T10:00:00Z",
                    record_writer=fail_second,
                )

        for table in ("source_file", "source_record", "person", "application", "fact_assertion"):
            with self.subTest(table=table):
                self.assertEqual(self.connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0], 0)


if __name__ == "__main__":
    unittest.main()
