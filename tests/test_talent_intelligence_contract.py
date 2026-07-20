from __future__ import annotations

from dataclasses import FrozenInstanceError
import json
from pathlib import Path
import tempfile
import unittest


def published(value: int) -> dict[str, object]:
    return {"value": value, "privacy": "published", "reason": None}


def valid_payload() -> dict[str, object]:
    return {
        "metadata": {
            "contract_version": "talent-intelligence-v1",
            "title": "Synthetic talent intelligence",
            "event_key": "synthetic-event",
            "event_name": "Synthetic Event",
            "event_date": "2026-07-11",
            "generated_at": "2026-07-12T20:00:00Z",
            "synthetic": True,
            "publication_state": "review_ready",
        },
        "privacy": {
            "mode": "aggregate_only",
            "minimum_count": 5,
            "pii_included": False,
            "state": "safe",
        },
        "cohort": {
            "unit": "people",
            "denominator": published(20),
            "stages": [
                {"key": "valid_applicants", "label": "Valid applicants", "order": 1, "count": published(20)},
                {"key": "eligible", "label": "Eligible", "order": 2, "count": published(15)},
                {"key": "accepted", "label": "Accepted", "order": 3, "count": published(10)},
                {"key": "checked_in", "label": "Checked in", "order": 4, "count": published(5)},
                {"key": "submitted", "label": "Submitted", "order": 5, "count": published(5)},
            ],
        },
        "selection_outcomes": {
            "unit": "people",
            "denominator_key": "valid_applicants",
            "categories": [
                {"key": "accepted", "label": "Accepted", "reason_state": "observed", "count": published(10)},
                {"key": "not_accepted_reason_unknown", "label": "Not accepted, reason unknown", "reason_state": "unknown", "count": published(10)},
            ],
        },
        "dimensions": [
            {
                "key": "seniority",
                "label": "Seniority",
                "mode": "exclusive",
                "denominator_key": "valid_applicants",
                "known_count": published(20),
                "items": [
                    {
                        "key": "senior",
                        "label": "Senior",
                        "count": published(8),
                        "definition": "Six or more years of relevant experience",
                        "evidence_sources": ["application"],
                    },
                    {
                        "key": "other_or_unknown",
                        "label": "Other or unknown",
                        "count": published(12),
                        "definition": "Other levels or insufficient evidence",
                        "evidence_sources": ["application"],
                    },
                ],
            },
            {
                "key": "builder_evidence",
                "label": "Builder evidence",
                "mode": "overlapping",
                "denominator_key": "valid_applicants",
                "known_count": published(15),
                "items": [
                    {
                        "key": "shipped_product",
                        "label": "Shipped product",
                        "count": published(10),
                        "definition": "Evidence of a product shipped beyond a concept",
                        "evidence_sources": ["application", "devpost"],
                    },
                    {
                        "key": "active_github",
                        "label": "Active public GitHub",
                        "count": published(6),
                        "definition": "Recent public repository activity",
                        "evidence_sources": ["github"],
                    },
                ],
            },
        ],
        "intersections": [
            {
                "key": "senior_builders",
                "label": "Senior builders",
                "count": published(6),
                "component_keys": ["seniority.senior", "builder_evidence.shipped_product"],
                "evidence_sources": ["application", "devpost"],
            }
        ],
        "qualitative_themes": [
            {
                "key": "production_shipping",
                "label": "Production shipping",
                "statement": "A material segment reports shipping software beyond prototypes",
                "count": published(10),
                "confidence": "medium",
                "review_state": "synthetic",
                "evidence_sources": ["application", "devpost"],
            }
        ],
        "evidence_coverage": [
            {
                "source": "application",
                "label": "Application evidence",
                "eligible": published(20),
                "covered": published(20),
                "state": "ready",
                "note": "Structured and free-text application fields",
            },
            {
                "source": "coresignal",
                "label": "Professional-profile enrichment",
                "eligible": published(20),
                "covered": published(0),
                "state": "off",
                "note": "Live enrichment remains disabled pending notice confirmation",
            },
        ],
        "readiness": [
            {"component": "synthetic_contract", "state": "ready", "required": True, "note": "Fixture reconciled"},
            {"component": "real_classification", "state": "pending", "required": False, "note": "Real semantic review not run"},
        ],
        "feature_gates": [
            {"feature": "gated_talent_appendix", "state": "disabled", "required": True, "note": "Legal and access controls not approved"}
        ],
        "source_notes": [
            {"source": "luma", "state": "schema_reference", "note": "Applicant and attendance fields shape this synthetic contract"},
            {"source": "devpost", "state": "schema_reference", "note": "Project and team fields shape this synthetic contract"},
        ],
    }


class TalentIntelligenceContractTests(unittest.TestCase):
    def load(self, payload: dict[str, object]):
        from community_os.talent_intelligence_contract import load_talent_intelligence_contract

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "contract.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            return load_talent_intelligence_contract(path)

    def test_loads_canonical_frozen_contract(self) -> None:
        report = self.load(valid_payload())
        self.assertEqual(report.metadata.contract_version, "talent-intelligence-v1")
        self.assertEqual(report.cohort.denominator.value, 20)
        self.assertEqual(tuple(item.key for item in report.dimensions), ("builder_evidence", "seniority"))
        with self.assertRaises(FrozenInstanceError):
            report.metadata.title = "Changed"  # type: ignore[misc]

    def test_rejects_stable_pseudonymous_identifier_in_public_text(self) -> None:
        identifiers = (
            "pid:rotation_2026:" + "a" * 64,
            "class_" + "b" * 24,
            "evidence:application:" + "c" * 64,
            "actor_23b1c7e9",
            "x_pid:v1:" + "d" * 64,
        )
        for identifier in identifiers:
            payload = valid_payload()
            payload["metadata"]["title"] = identifier  # type: ignore[index]
            with self.subTest(identifier=identifier), self.assertRaisesRegex(
                ValueError, "PII-like",
            ):
                self.load(payload)

    def test_rejects_selection_outcomes_that_do_not_reconcile(self) -> None:
        payload = valid_payload()
        payload["selection_outcomes"]["categories"][1]["count"] = published(5)  # type: ignore[index]
        with self.assertRaisesRegex(ValueError, "selection outcomes must reconcile"):
            self.load(payload)

    def test_rejects_single_withheld_exact_selection_complement(self) -> None:
        payload = valid_payload()
        payload["privacy"]["state"] = "withheld_cells"  # type: ignore[index]
        payload["selection_outcomes"]["categories"] = [  # type: ignore[index]
            {"key": "accepted", "label": "Accepted", "reason_state": "observed", "count": published(18)},
            {
                "key": "not_accepted_reason_unknown",
                "label": "Not accepted, reason unknown",
                "reason_state": "unknown",
                "count": {"value": None, "privacy": "withheld", "reason": "Below publication threshold"},
            },
        ]

        with self.assertRaisesRegex(ValueError, "withheld exact complement"):
            self.load(payload)

        payload = valid_payload()
        payload["privacy"]["state"] = "withheld_cells"  # type: ignore[index]
        payload["selection_outcomes"]["categories"] = [  # type: ignore[index]
            {"key": "accepted", "label": "Accepted", "reason_state": "observed", "count": published(18)},
            {"key": "other", "label": "Other", "reason_state": "unknown", "count": {"value": None, "privacy": "withheld", "reason": "Below publication threshold"}},
            {"key": "not_accepted", "label": "Not accepted", "reason_state": "unknown", "count": {"value": None, "privacy": "withheld", "reason": "Below publication threshold"}},
        ]

        with self.assertRaisesRegex(ValueError, "withheld selection remainder"):
            self.load(payload)

    def test_rejects_exclusive_dimension_that_does_not_reconcile(self) -> None:
        payload = valid_payload()
        payload["dimensions"][0]["items"][1]["count"] = published(6)  # type: ignore[index]
        with self.assertRaisesRegex(ValueError, "exclusive dimension seniority"):
            self.load(payload)

    def test_rejects_single_withheld_exclusive_cell_revealed_by_subtraction(self) -> None:
        payload = valid_payload()
        payload["privacy"]["state"] = "withheld_cells"  # type: ignore[index]
        dimension = payload["dimensions"][0]  # type: ignore[index]
        dimension["known_count"] = published(10)
        dimension["items"][0]["count"] = published(9)
        dimension["items"][1]["count"] = {
            "value": None,
            "privacy": "withheld",
            "reason": "Below publication threshold",
        }
        with self.assertRaisesRegex(ValueError, "complementary suppression"):
            self.load(payload)

    def test_rejects_intersection_larger_than_component(self) -> None:
        payload = valid_payload()
        payload["intersections"][0]["count"] = published(9)  # type: ignore[index]
        with self.assertRaisesRegex(ValueError, "exceeds component"):
            self.load(payload)

    def test_rejects_personal_or_link_like_content(self) -> None:
        payload = valid_payload()
        payload["qualitative_themes"][0]["statement"] = "Contact alex@example.test"  # type: ignore[index]
        with self.assertRaisesRegex(ValueError, "PII-like"):
            self.load(payload)

    def test_rejects_enabled_gated_appendix(self) -> None:
        payload = valid_payload()
        payload["feature_gates"][0]["state"] = "enabled"  # type: ignore[index]
        with self.assertRaisesRegex(ValueError, "gated_talent_appendix must remain disabled"):
            self.load(payload)

    def test_rejects_safe_privacy_state_when_a_count_is_withheld(self) -> None:
        payload = valid_payload()
        payload["dimensions"][1]["items"][1]["count"] = {  # type: ignore[index]
            "value": None,
            "privacy": "withheld",
            "reason": "Below publication threshold",
        }
        with self.assertRaisesRegex(ValueError, "privacy.state safe contradicts withheld counts"):
            self.load(payload)

    def test_rejects_withheld_privacy_state_when_no_count_is_withheld(self) -> None:
        payload = valid_payload()
        payload["privacy"]["state"] = "withheld_cells"  # type: ignore[index]
        with self.assertRaisesRegex(ValueError, "privacy.state withheld_cells requires"):
            self.load(payload)

    def test_rejects_below_threshold_nested_cohort_dropoff(self) -> None:
        payload = valid_payload()
        payload["cohort"]["stages"] = [  # type: ignore[index]
            {"key": "valid_applicants", "label": "Applied", "order": 1, "count": published(286)},
            {"key": "going_accepted", "label": "Going / accepted", "order": 2, "count": published(82)},
            {"key": "on_site", "label": "On site", "order": 3, "count": published(78)},
        ]
        payload["cohort"]["denominator"] = published(286)  # type: ignore[index]
        payload["selection_outcomes"]["categories"] = [  # type: ignore[index]
            {"key": "going_accepted", "label": "Going / accepted", "reason_state": "operator_reviewed", "count": published(82)},
            {"key": "not_accepted_reason_unknown", "label": "Not accepted", "reason_state": "unknown", "count": published(204)},
        ]

        with self.assertRaisesRegex(ValueError, "below-threshold stage dropoff"):
            self.load(payload)

    def test_rejects_below_threshold_coverage_complement(self) -> None:
        payload = valid_payload()
        payload["evidence_coverage"].append({  # type: ignore[index]
            "source": "submission", "label": "Submitted-team membership",
            "eligible": published(78), "covered": published(76),
            "state": "partial", "note": "Aggregate linkage coverage",
        })

        with self.assertRaisesRegex(ValueError, "below-threshold coverage complement"):
            self.load(payload)

    def test_rich_synthetic_fixture_covers_both_audiences_and_unknown_states(self) -> None:
        from community_os.talent_intelligence_contract import load_talent_intelligence_contract

        repo = Path(__file__).resolve().parents[1]
        report = load_talent_intelligence_contract(
            repo / "config/contracts/talent-intelligence-v1.synthetic.json"
        )
        self.assertTrue(report.metadata.synthetic)
        self.assertEqual(report.cohort.denominator.value, 286)
        self.assertEqual(
            {dimension.key for dimension in report.dimensions},
            {
                "builder_evidence", "capabilities", "domains", "employer_pedigree",
                "functional_role", "professional_identity", "seniority",
                "cross_dimension_signals",
            },
        )
        self.assertGreaterEqual(len(report.intersections), 5)
        self.assertGreaterEqual(len(report.qualitative_themes), 4)
        unknown_outcome = next(
            item for item in report.selection_outcomes.categories
            if item.key == "not_accepted_reason_unknown"
        )
        self.assertEqual(unknown_outcome.reason_state, "unknown")
        coresignal = next(item for item in report.evidence_coverage if item.source == "coresignal")
        self.assertEqual((coresignal.state, coresignal.covered.value), ("off", 0))
        appendix = next(item for item in report.feature_gates if item.feature == "gated_talent_appendix")
        self.assertEqual(appendix.state, "disabled")


if __name__ == "__main__":
    unittest.main()
