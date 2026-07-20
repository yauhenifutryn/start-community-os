"""Tests for the browser-safe event setup contract."""

from __future__ import annotations

import json
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

from community_os.event_definition import load_event_definition
from community_os.event_setup import (
    EventSetupError,
    build_event_definition_payload,
    write_event_definition,
)


ROOT = Path(__file__).resolve().parents[1]
CURRENT_DEFINITION = ROOT / "config/events/openai-hackathon-2026.json"


def current_setup() -> dict[str, object]:
    return {
        "version": "event-setup-v1",
        "event": {
            "key": "openai-hackathon-2026",
            "name": "OpenAI Hackathon",
            "starts_on": "2026-07-11",
            "ends_on": "2026-07-11",
            "timezone": "Europe/Warsaw",
        },
        "source_profile": "start-hackathon-v1",
        "selected_sheets": {
            "preferences": ["Submissions"],
            "submissions": ["solidgate", "boski"],
        },
        "report_profile": "start-partner-talent-v1",
    }


class EventSetupTests(unittest.TestCase):
    def test_supported_start_setup_expands_to_current_strict_definition(self) -> None:
        generated = build_event_definition_payload(current_setup())
        expected = json.loads(CURRENT_DEFINITION.read_text(encoding="utf-8"))

        self.assertEqual(generated, expected)

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "event.json"
            definition = write_event_definition(path, current_setup())
            self.assertEqual(definition.sha256, load_event_definition(path).sha256)
            self.assertEqual(
                json.loads(path.read_text(encoding="utf-8")),
                expected,
            )

    def test_event_metadata_and_safe_workbook_sheets_are_event_specific(self) -> None:
        setup = current_setup()
        setup["event"] = {
            "key": "start-warsaw-autumn-2027",
            "name": "START Warsaw Autumn Hackathon",
            "starts_on": "2027-10-02",
            "ends_on": "2027-10-03",
            "timezone": "Europe/Warsaw",
        }
        setup["selected_sheets"] = {
            "preferences": ["Responses 2027"],
            "submissions": ["health tech", "developer tools"],
        }

        first = build_event_definition_payload(setup)
        second = build_event_definition_payload(setup)

        self.assertEqual(first, second)
        self.assertEqual(first["event"]["type"], "hackathon")
        self.assertEqual(first["sources"][2]["sheets"], ["Responses 2027"])
        self.assertEqual(
            first["sources"][3]["sheets"],
            ["health tech", "developer tools"],
        )
        self.assertEqual(
            first["sources"][0]["mapping_sha256"],
            "be9d41ca6f05f925b330ca1ddf2816de2aceb9b6957b39bdb4f62777c3430a5e",
        )

    def test_generated_payload_cannot_mutate_the_registered_profile(self) -> None:
        generated = build_event_definition_payload(current_setup())
        generated["funnel"][1]["accepted_values"].append("attacker-controlled")

        regenerated = build_event_definition_payload(current_setup())

        self.assertEqual(
            regenerated["funnel"][1]["accepted_values"],
            ["approved"],
        )

    def test_browser_contract_rejects_server_owned_paths_hashes_and_adapters(self) -> None:
        attacks = (
            ("mapping_path", "mappings/attacker.json"),
            ("mapping_sha256", "f" * 64),
            ("source_sha256", "f" * 64),
            ("adapter_id", "attacker-v1"),
            ("artifact_profile", "attacker-v1"),
        )
        for key, value in attacks:
            with self.subTest(key=key):
                setup = current_setup()
                setup[key] = value
                with self.assertRaisesRegex(EventSetupError, f"unknown {key}"):
                    build_event_definition_payload(setup)

    def test_unknown_setup_version_source_and_report_profiles_fail_plainly(self) -> None:
        cases = (
            ("version", "event-setup-v2", "version must be event-setup-v1"),
            ("source_profile", "custom-csv-v1", "unsupported source profile: custom-csv-v1"),
            ("report_profile", "custom-report-v1", "unsupported report profile: custom-report-v1"),
        )
        for key, value, message in cases:
            with self.subTest(key=key):
                setup = current_setup()
                setup[key] = value
                with self.assertRaisesRegex(EventSetupError, message):
                    build_event_definition_payload(setup)

    def test_selected_sheets_are_bounded_safe_and_only_for_workbook_roles(self) -> None:
        cases = (
            ({"applications": ["Sheet 1"], "submissions": ["demo"]}, "unsupported workbook role"),
            ({"preferences": [], "submissions": ["demo"]}, "must select at least one sheet"),
            ({"preferences": ["Submissions"], "submissions": ["../private"]}, "safe sheet name"),
            ({"preferences": ["Submissions"], "submissions": ["demo", "demo"]}, "duplicate"),
            ({"preferences": ["Submissions\nHidden"], "submissions": ["demo"]}, "safe sheet name"),
        )
        for selected_sheets, message in cases:
            with self.subTest(selected_sheets=selected_sheets):
                setup = current_setup()
                setup["selected_sheets"] = selected_sheets
                with self.assertRaisesRegex(EventSetupError, message):
                    build_event_definition_payload(setup)

    def test_event_definition_is_atomically_persisted_with_mode_0600(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            destination = root / "protected" / "event-definition.json"
            definition = write_event_definition(destination, current_setup())

            self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o600)
            self.assertEqual(load_event_definition(destination).sha256, definition.sha256)
            self.assertEqual(list(destination.parent.glob(".*.tmp")), [])

            previous = destination.read_bytes()
            setup = current_setup()
            setup["event"] = {
                **setup["event"],
                "key": "replacement-event-2027",
                "name": "Replacement Event",
            }
            with patch(
                "community_os.event_setup.os.replace",
                side_effect=OSError("simulated interrupted install"),
            ):
                with self.assertRaisesRegex(OSError, "interrupted install"):
                    write_event_definition(destination, setup)

            self.assertEqual(destination.read_bytes(), previous)
            self.assertEqual(list(destination.parent.glob(".*.tmp")), [])
            self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o600)


if __name__ == "__main__":
    unittest.main()
