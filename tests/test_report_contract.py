"""Executable privacy and shape contract for talent report v3."""

from __future__ import annotations

from dataclasses import FrozenInstanceError
import json
from pathlib import Path
import tempfile
import unittest


def _cell(value: int | None, *, reason: str | None = None) -> dict[str, object]:
    return {
        "value": value,
        "privacy": "published" if value is not None else "withheld",
        "reason": reason,
    }


def _valid_payload() -> dict[str, object]:
    return {
        "metadata": {
            "contract_version": "talent-report-v3",
            "title": "START Warsaw Talent Data Room",
            "event_key": "openai-hackathon-2026",
            "event_name": "OpenAI Hackathon",
            "event_date": "2026-07-11",
            "generated_at": "2026-07-12T18:00:00Z",
            "synthetic": True,
            "publication_state": "review_ready",
        },
        "privacy": {
            "mode": "aggregate_only",
            "minimum_count": 5,
            "pii_included": False,
            "state": "withheld_cells",
        },
        "attendance_funnel": {
            "unit": "people",
            "stages": [
                {"key": "approved", "label": "Approved", "order": 1, "count": _cell(80)},
                {"key": "checked_in", "label": "Checked in", "order": 2, "count": _cell(70)},
                {"key": "submitted", "label": "Submitted", "order": 3, "count": _cell(55)},
            ],
        },
        "journey": {
            "unit": "people",
            "nodes": [
                {"key": "approved", "label": "Approved", "order": 1, "count": _cell(80), "unit": "people"},
                {"key": "checked_in", "label": "Checked in", "order": 2, "count": _cell(70), "unit": "people"},
            ],
            "links": [
                {"source": "approved", "target": "checked_in", "count": _cell(70), "unit": "people"},
            ],
        },
        "team_submission_matrix": {
            "unit": "teams",
            "row_keys": ["boski", "solidgate"],
            "column_keys": ["submitted", "not_submitted"],
            "cells": [
                {"row": "boski", "column": "submitted", "count": _cell(10)},
                {"row": "boski", "column": "not_submitted", "count": _cell(0)},
                {"row": "solidgate", "column": "submitted", "count": _cell(10)},
                {"row": "solidgate", "column": "not_submitted", "count": _cell(None, reason="Below publication threshold")},
            ],
        },
        "builder_signal_intersections": {
            "unit": "people",
            "signal_keys": ["github", "portfolio", "prior_project"],
            "intersections": [
                {"signals": ["github"], "count": _cell(15)},
                {"signals": ["github", "portfolio"], "count": _cell(8)},
                {"signals": ["portfolio", "prior_project"], "count": _cell(None, reason="Below publication threshold")},
            ],
        },
        "track_domain_heatmap": {
            "unit": "projects",
            "track_keys": ["boski", "solidgate"],
            "domain_keys": ["ai_apps", "fintech"],
            "cells": [
                {"track": "boski", "domain": "ai_apps", "count": _cell(5)},
                {"track": "boski", "domain": "fintech", "count": _cell(0)},
                {"track": "solidgate", "domain": "ai_apps", "count": _cell(None, reason="Below publication threshold")},
                {"track": "solidgate", "domain": "fintech", "count": _cell(5)},
            ],
        },
        "composition": {
            "unit": "people",
            "categories": [
                {"key": "team", "label": "Joined with a team", "count": _cell(55)},
                {"key": "solo", "label": "Joined solo", "count": _cell(25)},
            ],
        },
        "artifact_completeness": {
            "unit": "projects",
            "items": [
                {"key": "demo", "label": "Demo link", "status": "complete", "present": _cell(20), "eligible": _cell(20)},
                {"key": "repository", "label": "Repository", "status": "partial", "present": _cell(15), "eligible": _cell(20)},
            ],
        },
        "readiness": [
            {"component": "identity_review", "state": "ready", "required": True, "note": "All blocking reviews resolved"},
            {"component": "coresignal", "state": "off", "required": False, "note": "Not enabled"},
        ],
        "source_notes": [
            {"source": "devpost", "state": "validated", "note": "Two track sheets validated"},
            {"source": "luma", "state": "validated", "note": "Final approval and check-in export"},
            {"source": "track_preferences", "state": "validated", "note": "Final preference export"},
        ],
    }


class TalentReportContractTests(unittest.TestCase):
    def _load(self, payload: dict[str, object]):
        from community_os.report_contract import load_report_contract

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "contract.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            return load_report_contract(path)

    def test_loads_frozen_aggregate_only_contract(self) -> None:
        report = self._load(_valid_payload())

        self.assertEqual(report.metadata.contract_version, "talent-report-v3")
        self.assertEqual(report.privacy.minimum_count, 5)
        self.assertEqual(report.attendance_funnel.stages[1].key, "checked_in")
        self.assertIsInstance(report.readiness, tuple)
        self.assertIsInstance(report.journey.links, tuple)
        with self.assertRaises(FrozenInstanceError):
            report.metadata.title = "Changed"

    def test_rejects_stable_pseudonymous_identifier_in_public_text(self) -> None:
        identifiers = (
            "pid:rotation_2026:" + "a" * 64,
            "person_" + "b" * 24,
            "source:application:" + "c" * 24,
            "approval_7f4ab218",
            "pid:v1:" + "d" * 64 + "_x",
        )
        for identifier in identifiers:
            payload = _valid_payload()
            payload["metadata"]["title"] = identifier  # type: ignore[index]
            with self.subTest(identifier=identifier), self.assertRaisesRegex(
                ValueError, "PII-like",
            ):
                self._load(payload)

    def test_checked_in_synthetic_contract_is_valid(self) -> None:
        from community_os.report_contract import load_report_contract

        path = Path(__file__).resolve().parents[1] / "config/contracts/talent-report-v3.synthetic.json"
        report = load_report_contract(path)

        self.assertTrue(report.metadata.synthetic)
        self.assertEqual(report.metadata.publication_state, "review_ready")
        self.assertEqual(report.privacy.mode, "aggregate_only")

    def test_rejects_unknown_keys_at_every_level(self) -> None:
        payload = _valid_payload()
        payload["metadata"]["unexpected"] = "not allowed"  # type: ignore[index]

        with self.assertRaisesRegex(ValueError, "metadata.*unexpected"):
            self._load(payload)

    def test_rejects_disclosive_count_and_invalid_withholding(self) -> None:
        payload = _valid_payload()
        payload["composition"]["categories"][0]["count"] = _cell(4)  # type: ignore[index]
        with self.assertRaisesRegex(ValueError, "below minimum_count"):
            self._load(payload)

        payload = _valid_payload()
        payload["composition"]["categories"][0]["count"] = _cell(None)  # type: ignore[index]
        with self.assertRaisesRegex(ValueError, "withheld.*reason"):
            self._load(payload)

    def test_rejects_single_withheld_exact_journey_complement(self) -> None:
        payload = _valid_payload()
        payload["journey"] = {
            "unit": "people",
            "nodes": [
                {"key": "applied", "label": "Applied", "order": 1, "count": _cell(20), "unit": "people"},
                {"key": "accepted", "label": "Accepted", "order": 2, "count": _cell(18), "unit": "people"},
                {"key": "not_accepted", "label": "Not accepted", "order": 3, "count": _cell(None, reason="Below publication threshold"), "unit": "people"},
            ],
            "links": [
                {"source": "applied", "target": "accepted", "count": _cell(18), "unit": "people"},
                {"source": "applied", "target": "not_accepted", "count": _cell(None, reason="Below publication threshold"), "unit": "people"},
            ],
        }

        with self.assertRaisesRegex(ValueError, "withheld exact complement"):
            self._load(payload)

        payload["journey"]["links"] = [  # type: ignore[index]
            {"source": "applied", "target": "accepted", "count": _cell(18), "unit": "people"},
        ]
        with self.assertRaisesRegex(ValueError, "withheld exact complement"):
            self._load(payload)

        payload = _valid_payload()
        payload["metadata"]["synthetic"] = False  # type: ignore[index]
        payload["journey"] = {
            "unit": "people",
            "nodes": [
                {"key": "applied", "label": "Applied", "order": 1, "count": _cell(20), "unit": "people"},
                {"key": "going_accepted", "label": "Going / accepted", "order": 2, "count": _cell(15), "unit": "people"},
                {"key": "declined", "label": "Not accepted", "order": 3, "count": _cell(None, reason="Below publication threshold"), "unit": "people"},
                {"key": "on_site", "label": "On site", "order": 4, "count": _cell(15), "unit": "people"},
            ],
            "links": [
                {"source": "applied", "target": "going_accepted", "count": _cell(15), "unit": "people"},
                {"source": "going_accepted", "target": "on_site", "count": _cell(15), "unit": "people"},
            ],
        }
        with self.assertRaisesRegex(ValueError, "real journey topology"):
            self._load(payload)

        payload = _valid_payload()
        payload["journey"] = {
            "unit": "people",
            "nodes": [
                {"key": "applied", "label": "Applied", "order": 1, "count": _cell(20), "unit": "people"},
                {"key": "accepted", "label": "Accepted", "order": 2, "count": _cell(13), "unit": "people"},
                {"key": "other_outcome", "label": "Other outcome", "order": 3, "count": _cell(5), "unit": "people"},
                {"key": "not_accepted", "label": "Not accepted", "order": 4, "count": _cell(None, reason="Below publication threshold"), "unit": "people"},
            ],
            "links": [
                {"source": "applied", "target": "accepted", "count": _cell(13), "unit": "people"},
                {"source": "applied", "target": "other_outcome", "count": _cell(5), "unit": "people"},
                {"source": "applied", "target": "not_accepted", "count": _cell(None, reason="Below publication threshold"), "unit": "people"},
            ],
        }

        with self.assertRaisesRegex(ValueError, "withheld exact complement"):
            self._load(payload)

    def test_rejects_privacy_floor_below_five(self) -> None:
        payload = _valid_payload()
        payload["privacy"]["minimum_count"] = 4  # type: ignore[index]

        with self.assertRaisesRegex(ValueError, "minimum_count.*at least 5"):
            self._load(payload)

    def test_rejects_journey_unit_mismatch_and_unknown_nodes(self) -> None:
        payload = _valid_payload()
        payload["journey"]["links"][0]["unit"] = "teams"  # type: ignore[index]
        with self.assertRaisesRegex(ValueError, "journey.*unit"):
            self._load(payload)

        payload = _valid_payload()
        payload["journey"]["links"][0]["target"] = "missing"  # type: ignore[index]
        with self.assertRaisesRegex(ValueError, "unknown node"):
            self._load(payload)

    def test_rejects_journey_links_that_overcount_or_flow_backward(self) -> None:
        payload = _valid_payload()
        payload["journey"]["nodes"].extend([  # type: ignore[index]
            {"key": "team_path", "label": "Team", "order": 3, "count": _cell(50), "unit": "people"},
            {"key": "solo_path", "label": "Solo", "order": 4, "count": _cell(25), "unit": "people"},
        ])
        payload["journey"]["links"].extend([  # type: ignore[index]
            {"source": "checked_in", "target": "team_path", "count": _cell(50), "unit": "people"},
            {"source": "checked_in", "target": "solo_path", "count": _cell(25), "unit": "people"},
        ])
        with self.assertRaisesRegex(ValueError, "outgoing links exceed"):
            self._load(payload)

        payload = _valid_payload()
        payload["journey"]["links"][0]["source"] = "checked_in"  # type: ignore[index]
        payload["journey"]["links"][0]["target"] = "approved"  # type: ignore[index]
        with self.assertRaisesRegex(ValueError, "forward in stage order"):
            self._load(payload)

    def test_rejects_below_threshold_nested_funnel_dropoff(self) -> None:
        payload = _valid_payload()
        payload["attendance_funnel"]["stages"] = [  # type: ignore[index]
            {"key": "approved", "label": "Approved", "order": 1, "count": _cell(82)},
            {"key": "checked_in", "label": "Checked in", "order": 2, "count": _cell(78)},
        ]

        with self.assertRaisesRegex(ValueError, "below-threshold stage dropoff"):
            self._load(payload)

    def test_rejects_below_threshold_artifact_complement(self) -> None:
        payload = _valid_payload()
        payload["artifact_completeness"]["items"][1] = {  # type: ignore[index]
            "key": "repository", "label": "Repository", "status": "partial",
            "present": _cell(19), "eligible": _cell(20),
        }

        with self.assertRaisesRegex(ValueError, "below-threshold artifact complement"):
            self._load(payload)

    def test_rejects_non_rectangular_matrices(self) -> None:
        payload = _valid_payload()
        payload["team_submission_matrix"]["cells"].pop()  # type: ignore[index]

        with self.assertRaisesRegex(ValueError, "team_submission_matrix.*complete rectangle"):
            self._load(payload)

    def test_rejects_pii_like_content_and_partner_outcomes(self) -> None:
        payload = _valid_payload()
        payload["source_notes"][0]["note"] = "Contact person@example.com"  # type: ignore[index]
        with self.assertRaisesRegex(ValueError, "PII-like"):
            self._load(payload)

        payload = _valid_payload()
        payload["partner_outcomes"] = []
        with self.assertRaisesRegex(ValueError, "partner_outcomes"):
            self._load(payload)

    def test_published_contract_requires_all_required_readiness_gates(self) -> None:
        payload = _valid_payload()
        payload["metadata"]["publication_state"] = "published"  # type: ignore[index]
        payload["readiness"][0]["state"] = "blocked"  # type: ignore[index]

        with self.assertRaisesRegex(ValueError, "published.*required readiness"):
            self._load(payload)

    def test_unordered_sections_are_canonicalized_deterministically(self) -> None:
        first = _valid_payload()
        second = _valid_payload()
        for key, child in (
            ("readiness", second),
            ("source_notes", second),
        ):
            child[key].reverse()  # type: ignore[index]
        second["composition"]["categories"].reverse()  # type: ignore[index]
        second["team_submission_matrix"]["cells"].reverse()  # type: ignore[index]

        self.assertEqual(self._load(first), self._load(second))


if __name__ == "__main__":
    unittest.main()
