from __future__ import annotations

from dataclasses import FrozenInstanceError
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

import community_os
from community_os.event_definition import (
    EventDefinitionError,
    load_event_definition,
)


ROOT = Path(__file__).resolve().parents[1]
CURRENT_EVENT = ROOT / "config/events/openai-hackathon-2026.json"
SECOND_EVENT = ROOT / "tests/fixtures/events/second-hackathon.synthetic.json"


class EventDefinitionTests(unittest.TestCase):
    def payload(self) -> dict[str, object]:
        return json.loads(SECOND_EVENT.read_text(encoding="utf-8"))

    def write_payload(self, payload: dict[str, object], *, indent: int | None = 2) -> Path:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = Path(directory.name) / "event.json"
        path.write_text(json.dumps(payload, indent=indent), encoding="utf-8")
        return path

    def test_current_and_differently_shaped_events_load_as_immutable_contracts(self) -> None:
        current = load_event_definition(CURRENT_EVENT)
        second = load_event_definition(SECOND_EVENT)

        self.assertEqual(current.version, "event-release-v1")
        self.assertEqual(current.event_key, "openai-hackathon-2026")
        self.assertEqual(current.event_name, "OpenAI Hackathon")
        self.assertEqual(current.timezone, "Europe/Warsaw")
        self.assertEqual(current.report_family, "hackathon-partner-talent-v1")
        self.assertEqual(current.privacy.minimum_count, 5)
        self.assertEqual(current.privacy.policy_profile, "aggregate-partner-v1")
        self.assertEqual(current.semantic.taxonomy_version, "semantic-taxonomy-v1")
        self.assertEqual(current.semantic.metric_registry_version, "partner-metrics-v1")
        self.assertEqual(current.artifact_profile, "partner-brief-five-page-landscape-v1")
        self.assertRegex(current.sha256, r"^[0-9a-f]{64}$")
        self.assertEqual(second.event_key, "second-hackathon-synthetic")
        self.assertEqual(second.privacy.minimum_count, 7)
        self.assertEqual(second.source("applications").sheets, ("Applications 2027",))
        self.assertEqual(second.funnel_stage("accepted").accepted_values, ("accepted", "confirmed"))

        with self.assertRaises(FrozenInstanceError):
            current.event_key = "changed"  # type: ignore[misc]

        self.assertIs(community_os.load_event_definition, load_event_definition)

    def test_source_contract_binds_adapter_mapping_sheet_and_stable_id_strategy(self) -> None:
        current = load_event_definition(CURRENT_EVENT)
        second = load_event_definition(SECOND_EVENT)
        source = current.source("applications")

        self.assertEqual(source.adapter_id, "luma-csv-v2")
        self.assertEqual(source.mapping_path, ROOT / "mappings/luma-guests-v2.json")
        self.assertRegex(source.mapping_sha256, r"^[0-9a-f]{64}$")
        self.assertEqual(source.sheets, ())
        self.assertEqual(source.stable_id_strategy, "provider_id")
        self.assertEqual(
            tuple(item.role for item in current.sources),
            ("applications", "attendance", "preferences", "submissions"),
        )
        self.assertEqual(
            current.source("submissions").sheets,
            ("solidgate", "boski"),
        )
        self.assertNotEqual(
            source.mapping_path,
            second.source("applications").mapping_path,
            "the second event must exercise a distinct source mapping",
        )

    def test_funnel_maps_required_population_stages_and_source_values(self) -> None:
        definition = load_event_definition(CURRENT_EVENT)

        self.assertEqual(tuple(stage.stage for stage in definition.funnel), ("applied", "accepted", "present"))
        self.assertEqual(definition.funnel_stage("applied").match, "any_row")
        self.assertEqual(definition.funnel_stage("accepted").field, "approval_status")
        self.assertEqual(definition.funnel_stage("accepted").accepted_values, ("approved",))
        self.assertEqual(definition.funnel_stage("present").match, "non_empty")

    def test_funnel_fields_must_exist_in_the_selected_source_mapping(self) -> None:
        payload = self.payload()
        funnel = [dict(item) for item in payload["funnel"]]  # type: ignore[union-attr]
        funnel[1]["field"] = "not_a_canonical_mapping_field"
        payload["funnel"] = funnel

        with self.assertRaisesRegex(EventDefinitionError, "mapping field"):
            load_event_definition(self.write_payload(payload))

    def test_mapping_hashes_bind_canonical_json_not_formatting_bytes(self) -> None:
        source = load_event_definition(CURRENT_EVENT).source("applications")
        payload = json.loads(source.mapping_path.read_text(encoding="utf-8"))
        canonical = json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        ).encode("utf-8")

        self.assertEqual(source.mapping_sha256, hashlib.sha256(canonical).hexdigest())
        self.assertNotEqual(source.mapping_sha256, hashlib.sha256(source.mapping_path.read_bytes()).hexdigest())

    def test_sha256_is_canonical_across_json_formatting_and_key_order(self) -> None:
        payload = self.payload()
        reordered = dict(reversed(tuple(payload.items())))
        compact = self.write_payload(payload, indent=None)
        pretty_reordered = self.write_payload(reordered, indent=4)

        self.assertEqual(
            load_event_definition(compact).sha256,
            load_event_definition(pretty_reordered).sha256,
        )

    def test_unknown_or_missing_keys_are_rejected_at_every_contract_boundary(self) -> None:
        cases: list[tuple[str, dict[str, object]]] = []

        unknown_root = self.payload()
        unknown_root["unexpected"] = True
        cases.append(("unknown root", unknown_root))

        missing_root = self.payload()
        del missing_root["semantic"]
        cases.append(("missing root", missing_root))

        unknown_event = self.payload()
        event = dict(unknown_event["event"])  # type: ignore[arg-type]
        event["venue"] = "Krakow"
        unknown_event["event"] = event
        cases.append(("unknown event", unknown_event))

        unknown_source = self.payload()
        sources = [dict(item) for item in unknown_source["sources"]]  # type: ignore[union-attr]
        sources[0]["source_sha256"] = "a" * 64
        unknown_source["sources"] = sources
        cases.append(("source hashes belong in protected approval", unknown_source))

        for label, payload in cases:
            with self.subTest(label=label):
                with self.assertRaises(EventDefinitionError):
                    load_event_definition(self.write_payload(payload))

    def test_duplicate_roles_and_missing_required_sources_are_rejected(self) -> None:
        duplicate = self.payload()
        duplicate_sources = [dict(item) for item in duplicate["sources"]]  # type: ignore[union-attr]
        duplicate_sources[1]["role"] = "applications"
        duplicate["sources"] = duplicate_sources

        missing = self.payload()
        missing["sources"] = [
            item for item in missing["sources"]  # type: ignore[union-attr]
            if item["role"] != "attendance"
        ]

        optional_required = self.payload()
        optional_sources = [dict(item) for item in optional_required["sources"]]  # type: ignore[union-attr]
        optional_sources[0]["required"] = False
        optional_required["sources"] = optional_sources

        for label, payload in (
            ("duplicate role", duplicate),
            ("missing attendance", missing),
            ("applications must be required", optional_required),
        ):
            with self.subTest(label=label):
                with self.assertRaises(EventDefinitionError):
                    load_event_definition(self.write_payload(payload))

    def test_mapping_paths_and_hashes_fail_closed(self) -> None:
        for field, value in (
            ("mapping_path", "../private/mapping.json"),
            ("mapping_path", "/tmp/mapping.json"),
            ("mapping_path", "config/not-a-mapping.json"),
            ("mapping_sha256", "not-a-sha256"),
            ("mapping_sha256", "A" * 64),
            ("mapping_sha256", "0" * 64),
        ):
            payload = self.payload()
            sources = [dict(item) for item in payload["sources"]]  # type: ignore[union-attr]
            sources[0][field] = value
            payload["sources"] = sources
            with self.subTest(field=field, value=value):
                with self.assertRaises(EventDefinitionError):
                    load_event_definition(self.write_payload(payload))

    def test_adapter_sheet_and_stable_id_fields_are_validated(self) -> None:
        for field, value in (
            ("adapter_id", "../adapter"),
            ("adapter_id", "unversioned-adapter"),
            ("sheets", [""]),
            ("sheets", ["../People"]),
            ("sheets", ["People", "People"]),
            ("stable_id_strategy", "row_index"),
            ("stable_id_strategy", "email"),
        ):
            payload = self.payload()
            sources = [dict(item) for item in payload["sources"]]  # type: ignore[union-attr]
            sources[0][field] = value
            payload["sources"] = sources
            with self.subTest(field=field, value=value):
                with self.assertRaises(EventDefinitionError):
                    load_event_definition(self.write_payload(payload))

    def test_report_and_artifact_profiles_are_allowlisted(self) -> None:
        for field, value in (
            ("report_family", "invented-report-v9"),
            ("artifact_profile", "browser-print-default"),
        ):
            payload = self.payload()
            payload[field] = value
            with self.subTest(field=field):
                with self.assertRaises(EventDefinitionError):
                    load_event_definition(self.write_payload(payload))

    def test_funnel_rejects_missing_or_unbound_stages_and_invalid_match_values(self) -> None:
        missing_stage = self.payload()
        missing_stage["funnel"] = missing_stage["funnel"][:-1]  # type: ignore[index]

        unknown_source = self.payload()
        unknown_funnel = [dict(item) for item in unknown_source["funnel"]]  # type: ignore[union-attr]
        unknown_funnel[1]["source_role"] = "not-configured"
        unknown_source["funnel"] = unknown_funnel

        invalid_value_match = self.payload()
        invalid_funnel = [dict(item) for item in invalid_value_match["funnel"]]  # type: ignore[union-attr]
        invalid_funnel[1]["accepted_values"] = []
        invalid_value_match["funnel"] = invalid_funnel

        for label, payload in (
            ("missing stage", missing_stage),
            ("unbound source", unknown_source),
            ("value match without values", invalid_value_match),
        ):
            with self.subTest(label=label):
                with self.assertRaises(EventDefinitionError):
                    load_event_definition(self.write_payload(payload))


if __name__ == "__main__":
    unittest.main()
