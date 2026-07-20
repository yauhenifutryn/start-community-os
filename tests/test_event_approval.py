"""Strict hash binding for reusable event release approvals."""

from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from community_os.event_approval import EventApprovalError, load_event_approval
from community_os.event_definition import load_event_definition


ROOT = Path(__file__).resolve().parents[1]
CURRENT_EVENT = ROOT / "config" / "events" / "openai-hackathon-2026.json"
SECOND_EVENT = ROOT / "tests" / "fixtures" / "events" / "second-hackathon.synthetic.json"


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _approval_record(definition, source_hashes, excluded=()):
    return {
        "version": "event-approval-v2",
        "event_key": definition.event_key,
        "event_definition_sha256": definition.sha256,
        "policy_profile": definition.privacy.policy_profile,
        "taxonomy_version": definition.semantic.taxonomy_version,
        "metric_registry_version": definition.semantic.metric_registry_version,
        "sources": {
            source.role: {
                "adapter_id": source.adapter_id,
                "mapping_sha256": source.mapping_sha256,
                "source_sha256": source_hashes[source.role],
            }
            for source in definition.sources
        },
        "excluded_subject_refs": list(excluded),
        "actor_code": "release_owner",
        "approved_at": "2026-07-15T20:00:00+02:00",
    }


class EventApprovalTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.path = Path(self.temporary.name) / "event-approval.json"
        self.definition = load_event_definition(CURRENT_EVENT)
        self.source_hashes = {
            source.role: _digest(source.role)
            for source in self.definition.sources
        }
        self.record = _approval_record(self.definition, self.source_hashes)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _load(self, record=None, *, excluded=(), source_hashes=None):
        self.path.write_text(
            json.dumps(self.record if record is None else record),
            encoding="utf-8",
        )
        return load_event_approval(
            self.path,
            definition=self.definition,
            source_hashes=self.source_hashes if source_hashes is None else source_hashes,
            excluded_subject_refs=excluded,
        )

    def test_loads_immutable_event_bound_approval(self) -> None:
        approval = self._load()

        self.assertEqual(approval.version, "event-approval-v2")
        self.assertEqual(approval.event_key, self.definition.event_key)
        self.assertEqual(approval.event_definition_sha256, self.definition.sha256)
        self.assertEqual(approval.actor_code, "release_owner")
        self.assertRegex(approval.sha256, r"^[0-9a-f]{64}$")
        self.assertEqual(
            tuple(source.role for source in approval.sources),
            tuple(source.role for source in self.definition.sources),
        )
        with self.assertRaises(AttributeError):
            approval.event_key = "changed"

    def test_canonical_hash_is_independent_of_json_formatting_and_key_order(self) -> None:
        compact = self._load().sha256
        reordered = {key: self.record[key] for key in reversed(tuple(self.record))}
        self.path.write_text(json.dumps(reordered, indent=4), encoding="utf-8")

        formatted = load_event_approval(
            self.path,
            definition=self.definition,
            source_hashes=self.source_hashes,
            excluded_subject_refs=(),
        ).sha256

        self.assertEqual(formatted, compact)

    def test_rejects_each_definition_and_observation_mismatch(self) -> None:
        mutations = {
            "event": ("event_key", "wrong-event"),
            "definition": ("event_definition_sha256", "f" * 64),
            "policy": ("policy_profile", "other-policy-v1"),
            "taxonomy": ("taxonomy_version", "other-taxonomy-v1"),
            "metrics": ("metric_registry_version", "other-metrics-v1"),
        }
        for label, (field, value) in mutations.items():
            record = deepcopy(self.record)
            record[field] = value
            with self.subTest(binding=label):
                with self.assertRaisesRegex(EventApprovalError, label):
                    self._load(record)

        for label, field, value in (
            ("adapter", "adapter_id", "other-adapter-v1"),
            ("mapping", "mapping_sha256", "e" * 64),
            ("source", "source_sha256", "d" * 64),
        ):
            record = deepcopy(self.record)
            record["sources"]["applications"][field] = value
            with self.subTest(binding=label):
                with self.assertRaisesRegex(EventApprovalError, label):
                    self._load(record)

        observed = dict(self.source_hashes)
        observed["applications"] = "c" * 64
        with self.assertRaisesRegex(EventApprovalError, "source"):
            self._load(source_hashes=observed)

    def test_exclusion_set_is_sorted_unique_and_exactly_bound(self) -> None:
        excluded = ("psn_second", "psn_first")
        record = _approval_record(self.definition, self.source_hashes, reversed(excluded))
        approval = self._load(record, excluded=excluded)
        self.assertEqual(approval.excluded_subject_refs, frozenset(excluded))

        with self.assertRaisesRegex(EventApprovalError, "exclusion"):
            self._load(record, excluded=("psn_other",))

        duplicate = deepcopy(record)
        duplicate["excluded_subject_refs"] = ["psn_first", "psn_first"]
        with self.assertRaisesRegex(EventApprovalError, "duplicate"):
            self._load(duplicate, excluded=("psn_first",))

    def test_optional_source_unavailability_is_explicit_not_omitted(self) -> None:
        definition = load_event_definition(SECOND_EVENT)
        source_hashes = {
            source.role: (
                None if not source.required else _digest(source.role)
            )
            for source in definition.sources
        }
        record = _approval_record(definition, source_hashes)
        self.path.write_text(json.dumps(record), encoding="utf-8")

        approval = load_event_approval(
            self.path,
            definition=definition,
            source_hashes=source_hashes,
            excluded_subject_refs=(),
        )
        self.assertIsNone(approval.source("teams").source_sha256)

        omitted = deepcopy(record)
        del omitted["sources"]["teams"]
        self.path.write_text(json.dumps(omitted), encoding="utf-8")
        with self.assertRaisesRegex(EventApprovalError, "source roles"):
            load_event_approval(
                self.path,
                definition=definition,
                source_hashes=source_hashes,
                excluded_subject_refs=(),
            )

        required_missing = deepcopy(record)
        required_missing["sources"]["applications"]["source_sha256"] = None
        self.path.write_text(json.dumps(required_missing), encoding="utf-8")
        with self.assertRaisesRegex(EventApprovalError, "required source"):
            load_event_approval(
                self.path,
                definition=definition,
                source_hashes={**source_hashes, "applications": None},
                excluded_subject_refs=(),
            )

    def test_rejects_unknown_keys_roles_and_malformed_metadata(self) -> None:
        cases = []
        unknown = deepcopy(self.record)
        unknown["unexpected"] = True
        cases.append(("keys", unknown))
        role = deepcopy(self.record)
        role["sources"]["unexpected"] = role["sources"].pop("applications")
        cases.append(("source roles", role))
        nested = deepcopy(self.record)
        nested["sources"]["applications"]["path"] = "/private/source.csv"
        cases.append(("source binding", nested))
        actor = deepcopy(self.record)
        actor["actor_code"] = "Release Owner"
        cases.append(("actor", actor))
        timestamp = deepcopy(self.record)
        timestamp["approved_at"] = "2026-07-15T20:00:00"
        cases.append(("timezone", timestamp))

        for label, record in cases:
            with self.subTest(case=label):
                with self.assertRaisesRegex(EventApprovalError, label):
                    self._load(record)


if __name__ == "__main__":
    unittest.main()
