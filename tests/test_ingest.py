"""Contract tests for config-driven CSV source adapters."""

from __future__ import annotations

from pathlib import Path
import json
import tempfile
import unittest

from community_os.config import ConfigurationError, load_mapping
from community_os.ingest import RejectionCode, SchemaDriftError, WarningCode, ingest_csv


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"
MAPPINGS = ROOT / "mappings"


class SourceAdapterTests(unittest.TestCase):
    def test_luma_v2_handles_bom_quoted_newline_and_rejects_artifacts(self) -> None:
        result = ingest_csv(
            FIXTURES / "luma_guests_synthetic.csv",
            load_mapping(MAPPINGS / "luma-guests-v2.json"),
        )

        self.assertEqual(len(result.records), 1)
        record = result.records[0]
        self.assertEqual(record.external_record_id, "gst_synthetic_001")
        self.assertEqual(record.applicant_identity, "ada@example.org")
        self.assertEqual(
            record.values["relevant_experience"],
            "Built an accessibility tool\nwith a volunteer team.",
        )
        self.assertEqual(record.values["impressive_thing"], "Shipped it to 20 schools")
        self.assertEqual(len(result.rejected), 2)
        self.assertEqual(
            {item.code for item in result.rejected},
            {RejectionCode.MISSING_SOURCE_IDENTITY, RejectionCode.MISSING_APPLICANT_IDENTITY},
        )

    def test_luma_v1_models_schema_before_late_question(self) -> None:
        result = ingest_csv(
            FIXTURES / "luma_guests_v1_synthetic.csv",
            load_mapping(MAPPINGS / "luma-guests-v1.json"),
        )

        self.assertEqual(len(result.records), 1)
        self.assertNotIn("impressive_thing", result.records[0].values)
        self.assertEqual(result.records[0].mapping_version, "luma-guests-v1")

    def test_schema_drift_fails_loudly(self) -> None:
        original = (FIXTURES / "luma_guests_v1_synthetic.csv").read_text(encoding="utf-8")
        drifted = original.replace("ticket_name", "ticket_label", 1)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "drift.csv"
            path.write_text(drifted, encoding="utf-8")
            with self.assertRaisesRegex(SchemaDriftError, "ticket_label.*ticket_name"):
                ingest_csv(path, load_mapping(MAPPINGS / "luma-guests-v1.json"))

    def test_supplement_requires_explicit_authority(self) -> None:
        mapping = load_mapping(MAPPINGS / "luma-supplement-v1.json")
        with self.assertRaisesRegex(ConfigurationError, "authority"):
            ingest_csv(FIXTURES / "luma_supplement_synthetic.csv", mapping)

        result = ingest_csv(
            FIXTURES / "luma_supplement_synthetic.csv",
            mapping,
            authority="luma_final_status_supplement",
        )
        self.assertEqual(result.records[0].authority, "luma_final_status_supplement")
        self.assertEqual(result.records[0].external_record_id, "ada@example.org")
        self.assertEqual(result.records[0].values["approval_status"], "approved")

    def test_supplement_enforces_field_level_authority(self) -> None:
        result = ingest_csv(
            FIXTURES / "luma_supplement_synthetic.csv",
            load_mapping(MAPPINGS / "luma-supplement-v1.json"),
            authority="luma_final_status_supplement",
        )
        record = result.records[0]

        self.assertEqual(
            record.authoritative_fields,
            frozenset({"approval_status", "checked_in_at", "team_mode", "team_name"}),
        )
        self.assertEqual(
            record.identity_only_fields,
            frozenset({"name", "first_name", "last_name", "email"}),
        )
        self.assertEqual(
            set(record.authoritative_values),
            {"approval_status", "checked_in_at", "team_mode", "team_name"},
        )
        self.assertNotIn("email", record.authoritative_values)
        self.assertNotIn("name", record.authoritative_values)

    def test_supplement_mapping_rejects_unclassified_fields(self) -> None:
        raw = json.loads(
            (MAPPINGS / "luma-supplement-v1.json").read_text(encoding="utf-8")
        )
        raw["metadata"]["identity_only_fields"].remove("email")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "unsafe-supplement.json"
            path.write_text(json.dumps(raw), encoding="utf-8")
            with self.assertRaisesRegex(ConfigurationError, "unclassified.*email"):
                load_mapping(path)

    def test_devpost_adapters_always_warn_that_real_export_is_unverified(self) -> None:
        cases = (
            ("devpost_registrants_synthetic.csv", "devpost-registrants-v1.unverified.json"),
            ("devpost_projects_synthetic.csv", "devpost-projects-v1.unverified.json"),
        )
        for fixture, mapping_name in cases:
            with self.subTest(mapping=mapping_name):
                result = ingest_csv(
                    FIXTURES / fixture,
                    load_mapping(MAPPINGS / mapping_name),
                )
                self.assertEqual(len(result.records), 1)
                self.assertIn(WarningCode.REAL_EXPORT_UNVERIFIED, {w.code for w in result.warnings})
                self.assertTrue(result.mapping.metadata["untested_real_export"])


if __name__ == "__main__":
    unittest.main()
