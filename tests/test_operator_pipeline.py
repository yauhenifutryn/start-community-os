from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
import tempfile
import unittest

from community_os.operator_pipeline import (
    OperatorError,
    SourceSlot,
    build_report_payload,
    preflight_csv,
    preflight_xlsx,
    records_from_source,
    split_people,
    validate_distinct_inputs,
    write_outputs,
)
from community_os.report_contract import load_report_contract


class OperatorPipelineTests(unittest.TestCase):
    def test_multi_person_cells_accept_observed_pipe_delimiter(self) -> None:
        self.assertEqual(split_people("Ada | Bob | Cyd"), ["Ada", "Bob", "Cyd"])

    def test_luma_preflight_accepts_bom_and_rejects_malformed_rows(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            valid = Path(directory) / "anything.csv"
            valid.write_text(
                "\ufeffname,first_name,last_name,email,approval_status,checked_in_at,"
                "Are you applying solo or with a team? Each team member has to register separately.,"
                "Team name (if applying with a team)\nAda,Ada,L,a@example.org,approved,,solo,\n",
                encoding="utf-8",
            )
            result = preflight_csv(valid, SourceSlot.LUMA)
            self.assertEqual(result.row_count, 1)
            self.assertEqual(result.source, "luma")
            records = records_from_source(valid, SourceSlot.LUMA)
            self.assertEqual((records[0].email, records[0].name), ("a@example.org", "Ada"))

            malformed = Path(directory) / "bad.csv"
            malformed.write_bytes(b"name,email\nAda,not-closed\x00")
            with self.assertRaises(OperatorError):
                preflight_csv(malformed, SourceSlot.LUMA)

    def test_duplicate_inputs_are_blocked_by_hash_not_filename(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            first = Path(directory) / "a"
            second = Path(directory) / "b"
            first.write_bytes(b"same")
            second.write_bytes(b"same")
            with self.assertRaisesRegex(OperatorError, "duplicate input"):
                validate_distinct_inputs({SourceSlot.LUMA: first, SourceSlot.TRACK: second})

    def test_xlsx_slot_rejects_non_zip_signature(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fake = Path(directory) / "fake.xlsx"
            fake.write_bytes(b"not an xlsx")
            with self.assertRaisesRegex(OperatorError, "XLSX"):
                preflight_xlsx(fake, SourceSlot.TRACK)

    def test_configured_devpost_sheet_names_drive_record_parsing(self) -> None:
        from community_os.operator_pipeline import DEVPOST_HEADERS
        from tests.test_mapped_workbook_ingest import _write_workbook

        row = {header: "" for header in DEVPOST_HEADERS}
        row.update({
            "Project Title": "Portable parser",
            '"Try it out" Links': "https://example.test/repository",
            "Submitter First Name": "Ada",
            "Submitter Last Name": "Lovelace",
            "Submitter Email": "ada@example.test",
            "Track": "Main challenge",
        })
        values = [row[header] for header in DEVPOST_HEADERS]
        second = dict(row)
        second.update({
            "Project Title": "Second portable parser",
            "Submitter Email": "grace@example.test",
        })
        second_values = [second[header] for header in DEVPOST_HEADERS]

        with tempfile.TemporaryDirectory() as directory:
            workbook = Path(directory) / "submissions.xlsx"
            _write_workbook(workbook, {
                "Final builds": [list(DEVPOST_HEADERS), values],
                "Wildcard finalists": [second_values],
                "Ignored archive": [["not", "part", "of", "the", "run"]],
            })

            records = records_from_source(
                workbook,
                SourceSlot.DEVPOST,
                selected_sheets=("Final builds", "Wildcard finalists"),
            )

        self.assertEqual(
            {(record.email, record.team_name) for record in records},
            {
                ("ada@example.test", "Portable parser"),
                ("grace@example.test", "Second portable parser"),
            },
        )

    def test_current_registered_parser_matches_legacy_final_records(self) -> None:
        from community_os.event_definition import load_event_definition
        from community_os.operator_pipeline import DEVPOST_HEADERS
        from tests.test_mapped_workbook_ingest import _write_workbook

        definition = load_event_definition(
            Path(__file__).resolve().parents[1]
            / "config/events/openai-hackathon-2026.json"
        )
        row = {header: "" for header in DEVPOST_HEADERS}
        row.update({
            "Project Title": "Portable parser",
            "Submission Url": "https://devpost.com/software/portable-parser",
            '"Try it out" Links': "https://github.com/example/portable-parser",
            "Video Demo Link": "https://example.test/demo",
            "Submitter First Name": "Ada",
            "Submitter Last Name": "Lovelace",
            "Submitter Email": "ada@example.test",
            "Track": "Main challenge",
        })
        first_values = [row[header] for header in DEVPOST_HEADERS]
        second = dict(row)
        second.update({
            "Project Title": "Second portable parser",
            "Submission Url": "https://devpost.com/software/portable-parser-two",
            "Submitter Email": "grace@example.test",
        })
        second_values = [second[header] for header in DEVPOST_HEADERS]

        with tempfile.TemporaryDirectory() as directory:
            workbook = Path(directory) / "submissions.xlsx"
            _write_workbook(workbook, {
                "solidgate": [list(DEVPOST_HEADERS), first_values],
                "boski": [second_values],
            })
            legacy = records_from_source(workbook, SourceSlot.DEVPOST)
            registered = records_from_source(
                workbook,
                SourceSlot.DEVPOST,
                source=definition.source("submissions"),
            )

        self.assertEqual(registered, legacy)
        self.assertEqual(
            [record.external_id for record in registered],
            [
                "devpost-solidgate-01-member-1",
                "devpost-boski-01-member-1",
            ],
        )

    def test_source_bound_parser_rejects_registered_mapping_drift(self) -> None:
        from community_os.event_definition import load_event_definition
        from community_os.operator_pipeline import DEVPOST_HEADERS
        from tests.test_mapped_workbook_ingest import _write_workbook

        definition = load_event_definition(
            Path(__file__).resolve().parents[1]
            / "config/events/openai-hackathon-2026.json"
        )
        row = {header: "" for header in DEVPOST_HEADERS}
        row.update({
            "Project Title": "Mapping drift",
            "Submission Url": "https://devpost.com/software/mapping-drift",
            "Submitter Email": "ada@example.test",
        })

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            workbook = root / "submissions.xlsx"
            _write_workbook(workbook, {
                "solidgate": [
                    list(DEVPOST_HEADERS),
                    [row[header] for header in DEVPOST_HEADERS],
                ],
                "boski": [],
            })
            source = definition.source("submissions")
            changed_mapping = root / "devpost-final-v1.json"
            payload = json.loads(source.mapping_path.read_text(encoding="utf-8"))
            payload["metadata"]["schema_note"] = "changed after registration"
            changed_mapping.write_text(json.dumps(payload), encoding="utf-8")

            with self.assertRaisesRegex(
                ValueError, "mapping changed after event registration",
            ):
                records_from_source(
                    workbook,
                    SourceSlot.DEVPOST,
                    source=replace(source, mapping_path=changed_mapping),
                )

    def test_open_review_blocks_review_ready_aggregate(self) -> None:
        facts = {
            "approved": 10, "checked_in": 8, "submitted_people": 5,
            "teams_by_track": {"boski": {"submitted": 5, "not_submitted": 0}},
            "projects_by_track_domain": {"boski": {"unclassified": 5}},
            "composition": {"solo": 5, "team": 5},
            "artifact_counts": {"repository": (5, 5)},
        }
        with self.assertRaisesRegex(OperatorError, "identity review"):
            build_report_payload(facts, open_review_count=1, generated_at="2026-07-12T00:00:00Z")

    def test_outputs_load_frozen_contract_and_manifest_contains_no_pii(self) -> None:
        facts = {
            "approved": 10, "checked_in": 10, "submitted_people": 5,
            "teams_by_track": {"boski": {"submitted": 5, "not_submitted": 0}},
            "projects_by_track_domain": {"boski": {"unclassified": 5}},
            "composition": {"solo": 5, "team": 5},
            "artifact_counts": {"repository": (5, 5)},
        }
        payload = build_report_payload(facts, open_review_count=0, generated_at="2026-07-12T00:00:00Z")
        with tempfile.TemporaryDirectory() as directory:
            report_path, manifest_path = write_outputs(
                Path(directory), payload,
                source_hashes={"luma": "a" * 64, "track": "b" * 64, "devpost": "c" * 64},
                counts={"approved": 10}, warnings=[], generated_at="2026-07-12T00:00:00Z",
            )
            loaded = load_report_contract(report_path)
            self.assertEqual(loaded.metadata.contract_version, "talent-report-v3")
            manifest = manifest_path.read_text(encoding="utf-8")
            self.assertNotIn("@", manifest)
            self.assertNotIn("/Users/", manifest)
            self.assertEqual(json.loads(manifest)["open_review_count"], 0)


if __name__ == "__main__":
    unittest.main()
