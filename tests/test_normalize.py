"""Behavioral tests for source-linked canonical normalization."""

from __future__ import annotations

import json
from pathlib import Path
import sqlite3
import unittest

from community_os.config import load_mapping
from community_os.ingest import ingest_csv
from community_os.normalize import normalize_record


ROOT = Path(__file__).resolve().parents[1]


class NormalizationTests(unittest.TestCase):
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

    def tearDown(self) -> None:
        self.connection.close()

    def _mapped_record(self, mapping_name: str, fixture_name: str, **kwargs):
        mapping = load_mapping(ROOT / "mappings" / mapping_name)
        result = ingest_csv(ROOT / "tests" / "fixtures" / fixture_name, mapping, **kwargs)
        return mapping, result.records[0]

    def _source_record(self, mapping, record, suffix: str = "one") -> int:
        source_file_id = self.connection.execute(
            """INSERT INTO source_file(
                   event_id,source_type,file_sha256,mapping_version,observed_at
               ) VALUES(?,?,?,?,?)""",
            (
                self.event_id,
                mapping.source_type,
                f"sha256:{suffix}",
                mapping.version,
                "2026-07-11T10:00:00Z",
            ),
        ).lastrowid
        return self.connection.execute(
            """INSERT INTO source_record(
                   source_file_id,external_record_id,mapping_version,observed_at,raw_payload_json
               ) VALUES(?,?,?,?,?)""",
            (
                source_file_id,
                record.external_record_id,
                mapping.version,
                "2026-07-11T10:00:00Z",
                json.dumps(record.raw),
            ),
        ).lastrowid

    def test_luma_application_participation_and_consents_are_source_assertions(self) -> None:
        mapping, record = self._mapped_record(
            "luma-guests-v2.json", "luma_guests_synthetic.csv"
        )
        source_record_id = self._source_record(mapping, record)

        normalized = normalize_record(
            self.connection,
            event_id=self.event_id,
            source_type=mapping.source_type,
            source_record_id=source_record_id,
            record=record,
        )

        application = self.connection.execute(
            "SELECT status FROM application WHERE id=?", (normalized.application_id,)
        ).fetchone()
        participation = self.connection.execute(
            "SELECT checked_in,checked_in_at FROM participation WHERE id=?",
            (normalized.participation_id,),
        ).fetchone()
        self.assertEqual(application["status"], "accepted")
        self.assertEqual(tuple(participation), (1, "2026-07-10T09:00:00Z"))

        assertions = self.connection.execute(
            """SELECT fa.subject_table,fa.field_name,fa.source_record_id,
                      fa.mapping_version,fa.authority,p.canonical_value_json
               FROM fact_assertion fa
               JOIN fact_assertion_payload p ON p.assertion_id=fa.id
               WHERE fa.source_record_id=?""",
            (source_record_id,),
        ).fetchall()
        keyed = {(row["subject_table"], row["field_name"]): row for row in assertions}
        self.assertEqual(
            json.loads(keyed[("application", "status")]["canonical_value_json"]),
            "accepted",
        )
        self.assertEqual(
            json.loads(keyed[("participation", "checked_in")]["canonical_value_json"]),
            True,
        )
        self.assertTrue(all(row["mapping_version"] == mapping.version for row in assertions))
        self.assertTrue(all(row["authority"] == mapping.source_type for row in assertions))

        consents = self.connection.execute(
            """SELECT purpose,recipient_scope,granted,source_record_id,source_version
               FROM consent_assertion WHERE person_id=? ORDER BY purpose""",
            (normalized.person_id,),
        ).fetchall()
        self.assertEqual(len(consents), 5)
        partner = next(row for row in consents if row["purpose"] == "partner_recruitment")
        self.assertEqual(
            (partner["recipient_scope"], partner["granted"], partner["source_record_id"]),
            ("case_partners", 1, source_record_id),
        )
        self.assertTrue(all(row["source_version"] == mapping.version for row in consents))

    def test_team_name_links_participation_without_inferred_team_size(self) -> None:
        mapping, record = self._mapped_record(
            "luma-guests-v2.json", "luma_guests_synthetic.csv"
        )
        source_record_id = self._source_record(mapping, record)
        normalized = normalize_record(
            self.connection,
            event_id=self.event_id,
            source_type=mapping.source_type,
            source_record_id=source_record_id,
            record=record,
        )

        row = self.connection.execute(
            """SELECT t.canonical_name,p.team_id FROM participation p
               JOIN team t ON t.id=p.team_id WHERE p.id=?""",
            (normalized.participation_id,),
        ).fetchone()
        self.assertEqual(tuple(row), ("Team Synthetic", normalized.team_id))
        self.assertIsNone(
            self.connection.execute(
                "SELECT 1 FROM fact_assertion WHERE field_name='team_size'"
            ).fetchone()
        )

    def test_late_question_distinguishes_not_present_empty_and_answered(self) -> None:
        v1_mapping, v1_record = self._mapped_record(
            "luma-guests-v1.json", "luma_guests_v1_synthetic.csv"
        )
        v1_source = self._source_record(v1_mapping, v1_record, "v1")
        v1 = normalize_record(
            self.connection,
            event_id=self.event_id,
            source_type=v1_mapping.source_type,
            source_record_id=v1_source,
            record=v1_record,
        )
        v1_answers = json.loads(
            self.connection.execute(
                "SELECT raw_answers_json FROM application WHERE id=?", (v1.application_id,)
            ).fetchone()[0]
        )
        self.assertEqual(v1_answers["impressive_thing"], {"state": "question_not_present"})

        v2_mapping, v2_record = self._mapped_record(
            "luma-guests-v2.json", "luma_guests_synthetic.csv"
        )
        empty_record = type(v2_record)(
            external_record_id="gst-empty",
            applicant_identity="empty@example.org",
            mapping_version=v2_record.mapping_version,
            authority=v2_record.authority,
            authoritative_fields=v2_record.authoritative_fields,
            identity_only_fields=v2_record.identity_only_fields,
            values={
                **v2_record.values,
                "email": "empty@example.org",
                "github": "",
                "linkedin": "",
                "impressive_thing": "",
            },
            raw={**v2_record.raw, "guest_id": "gst-empty", "email": "empty@example.org"},
        )
        empty_source = self._source_record(v2_mapping, empty_record, "empty")
        empty = normalize_record(
            self.connection,
            event_id=self.event_id,
            source_type=v2_mapping.source_type,
            source_record_id=empty_source,
            record=empty_record,
        )
        empty_answers = json.loads(
            self.connection.execute(
                "SELECT raw_answers_json FROM application WHERE id=?", (empty.application_id,)
            ).fetchone()[0]
        )
        self.assertEqual(empty_answers["impressive_thing"], {"state": "empty"})

        answered_source = self._source_record(v2_mapping, v2_record, "answered")
        answered = normalize_record(
            self.connection,
            event_id=self.event_id,
            source_type=v2_mapping.source_type,
            source_record_id=answered_source,
            record=v2_record,
        )
        answered_answers = json.loads(
            self.connection.execute(
                "SELECT raw_answers_json FROM application WHERE id=?", (answered.application_id,)
            ).fetchone()[0]
        )
        self.assertEqual(answered_answers["impressive_thing"]["state"], "answered")

    def test_supplement_overrides_only_with_authority_and_retains_both_assertions(self) -> None:
        primary_mapping, primary_record = self._mapped_record(
            "luma-guests-v1.json", "luma_guests_v1_synthetic.csv"
        )
        primary_source = self._source_record(primary_mapping, primary_record, "primary")
        first = normalize_record(
            self.connection,
            event_id=self.event_id,
            source_type=primary_mapping.source_type,
            source_record_id=primary_source,
            record=primary_record,
        )
        supplement_mapping, supplement_record = self._mapped_record(
            "luma-supplement-v1.json",
            "luma_supplement_synthetic.csv",
            authority="luma_final_status_supplement",
        )
        supplement_source = self._source_record(
            supplement_mapping, supplement_record, "supplement"
        )
        updated = normalize_record(
            self.connection,
            event_id=self.event_id,
            source_type=supplement_mapping.source_type,
            source_record_id=supplement_source,
            record=supplement_record,
        )

        self.assertEqual((updated.person_id, updated.application_id), (first.person_id, first.application_id))
        self.assertEqual(
            self.connection.execute(
                "SELECT status FROM application WHERE id=?", (first.application_id,)
            ).fetchone()[0],
            "accepted",
        )
        history = self.connection.execute(
            """SELECT fa.id,fa.source_record_id,fa.authority,fa.supersedes_assertion_id,
                      p.canonical_value_json
               FROM fact_assertion fa
               JOIN fact_assertion_payload p ON p.assertion_id=fa.id
               WHERE fa.subject_table='application' AND fa.subject_id=?
                 AND fa.field_name='status' ORDER BY fa.id""",
            (first.application_id,),
        ).fetchall()
        self.assertEqual([json.loads(row["canonical_value_json"]) for row in history], ["applied", "accepted"])
        self.assertEqual(history[1]["supersedes_assertion_id"], history[0]["id"])
        self.assertEqual(history[1]["source_record_id"], supplement_source)
        self.assertEqual(history[1]["authority"], "luma_final_status_supplement")


if __name__ == "__main__":
    unittest.main()
