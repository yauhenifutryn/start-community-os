from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime
import unittest


NOW = datetime(2026, 7, 15, 12, tzinfo=UTC)


def population_facts() -> tuple[dict[str, object], ...]:
    from community_os.semantic_metrics import (
        metric_registry_sha256, population_snapshot_sha256,
        semantic_taxonomy_sha256,
    )

    bindings = {
        "event_approval_sha256": "e" * 64,
        "event_definition_sha256": "a" * 64,
        "event_key": "start-warsaw-2026-07",
        "metric_registry_version": "partner-metrics-v1",
        "metric_registry_sha256": metric_registry_sha256(),
        "population_key": "all_applicants",
        "population_sha256": "0" * 64,
        "run_sha256": "b" * 64,
        "source_snapshot_sha256": "c" * 64,
        "taxonomy_version": "talent-taxonomy-v1",
        "taxonomy_sha256": semantic_taxonomy_sha256("talent-taxonomy-v1"),
    }
    facts: list[dict[str, object]] = []
    for index in range(286):
        state = (
            "assessed" if index < 195
            else "no_evidence" if index < 282
            else "rejected"
        )
        assessed = state == "assessed"
        facts.append({
            "assessment_state": state,
            "bindings": dict(bindings),
            "cohort_membership": {
                "accepted": "member" if index < 83 else "not_member",
                "applied": "member",
                "present": "member" if index < 78 else "not_member",
                "submitted": "unknown",
            },
            "confidence": "medium" if assessed else "unknown",
            "evidence_refs": (
                [f"project_{index % 6 + 1:02d}:readme"] if assessed else []
            ),
            "evidence_scopes": {
                "application": "observed" if assessed else "not_provided",
                "career_context": "observed" if index < 12 else "not_provided",
                "event_submission": "observed" if index < 63 else "not_provided",
                "public_projects": "observed" if index < 169 else "not_provided",
            },
            "fact_version": "population-semantic-fact-v1",
            "population_key": "all_applicants",
            "reason_codes": [
                "corroborated_across_sources" if assessed
                else "no_semantic_evidence" if state == "no_evidence"
                else "semantic_review_rejected"
            ],
            "review_states": {
                "agent": "reviewed" if assessed else "not_reviewed",
                "human": "not_required" if state != "rejected" else "rejected",
                "model": "complete" if assessed else "not_run",
                "system": "valid",
            },
            "semantic_dimensions": ({
                "builder_level": "substantial" if index < 21 else "exploratory",
                "execution_scope": "primary_builder" if index < 22 else "contributor",
                "external_validation": "meaningful" if index < 6 else "none",
                "originality": "differentiated" if index < 62 else "ordinary",
                "product_maturity": "working_product" if index < 21 else "prototype",
                "technical_depth": (
                    "advanced" if index < 19 else "moderate" if index < 133 else "basic"
                ),
            } if assessed else {
                key: None for key in (
                    "builder_level", "execution_scope", "external_validation",
                    "originality", "product_maturity", "technical_depth",
                )
            }),
            "subject_ref": f"case:v1:{index:064x}",
        })
    population_hash = population_snapshot_sha256(facts)
    for fact in facts:
        fact["bindings"]["population_sha256"] = population_hash
    return tuple(facts)


class SemanticMetricTests(unittest.TestCase):
    def test_cohort_aggregate_bundle_is_ordered_and_uses_exact_membership(self) -> None:
        import community_os.semantic_metrics as semantic_metrics

        self.assertTrue(
            hasattr(semantic_metrics, "build_semantic_cohort_aggregate_bundle"),
            "cohort aggregate bundle builder is missing",
        )
        build_semantic_cohort_aggregate_bundle = (
            semantic_metrics.build_semantic_cohort_aggregate_bundle
        )

        facts = population_facts()
        bundle = build_semantic_cohort_aggregate_bundle(
            facts,
            generated_at=NOW,
            expected_subject_refs=sorted(
                str(fact["subject_ref"]) for fact in facts
            ),
        )

        self.assertEqual(tuple(bundle), ("all", "accepted", "attended"))
        self.assertEqual(
            {
                key: aggregate["population"]["total_count"]
                for key, aggregate in bundle.items()
            },
            {"all": 286, "accepted": 83, "attended": 78},
        )
        self.assertEqual(
            [bundle[key]["bindings"]["population_key"] for key in bundle],
            ["all_applicants", "accepted_participants", "confirmed_attendees"],
        )
        self.assertEqual(
            {
                bundle[key]["bindings"]["event_definition_sha256"]
                for key in bundle
            },
            {facts[0]["bindings"]["event_definition_sha256"]},
        )
        self.assertNotIn("case:v1", str(bundle))

    def test_cohort_aggregate_bundle_rejects_incomplete_or_impossible_membership(self) -> None:
        import community_os.semantic_metrics as semantic_metrics

        self.assertTrue(
            hasattr(semantic_metrics, "build_semantic_cohort_aggregate_bundle"),
            "cohort aggregate bundle builder is missing",
        )
        build_semantic_cohort_aggregate_bundle = (
            semantic_metrics.build_semantic_cohort_aggregate_bundle
        )

        expected = sorted(
            str(fact["subject_ref"]) for fact in population_facts()
        )

        incomplete = list(population_facts())
        incomplete[0]["cohort_membership"]["accepted"] = "unknown"
        with self.assertRaisesRegex(ValueError, "complete.*membership"):
            build_semantic_cohort_aggregate_bundle(
                incomplete, generated_at=NOW, expected_subject_refs=expected,
            )

        accepted_without_application = list(population_facts())
        accepted_without_application[0]["cohort_membership"]["applied"] = (
            "not_member"
        )
        with self.assertRaisesRegex(ValueError, "accepted.*applied"):
            build_semantic_cohort_aggregate_bundle(
                accepted_without_application,
                generated_at=NOW,
                expected_subject_refs=expected,
            )

        present_without_acceptance = list(population_facts())
        present_without_acceptance[0]["cohort_membership"]["accepted"] = (
            "not_member"
        )
        with self.assertRaisesRegex(ValueError, "present.*accepted"):
            build_semantic_cohort_aggregate_bundle(
                present_without_acceptance,
                generated_at=NOW,
                expected_subject_refs=expected,
            )

    def test_reviewed_cohort_totals_add_only_unattributed_unknowns_not_positive_claims(self) -> None:
        from community_os.semantic_metrics import (
            build_semantic_cohort_aggregate_bundle,
        )

        facts = list(population_facts())
        for index, fact in enumerate(facts):
            membership = fact["cohort_membership"]
            membership["accepted"] = "member" if index < 82 else "not_member"
            membership["present"] = "member" if index < 72 else "not_member"
        from community_os.semantic_metrics import population_snapshot_sha256
        population_hash = population_snapshot_sha256(facts)
        for fact in facts:
            fact["bindings"]["population_sha256"] = population_hash
        expected = sorted(str(fact["subject_ref"]) for fact in facts)

        bundle = build_semantic_cohort_aggregate_bundle(
            facts,
            generated_at=NOW,
            expected_subject_refs=expected,
            reviewed_cohort_totals={
                "all": 286,
                "accepted": 83,
                "attended": 78,
            },
        )

        self.assertEqual(
            {
                key: aggregate["population"]["total_count"]
                for key, aggregate in bundle.items()
            },
            {"all": 286, "accepted": 82, "attended": 72},
        )
        self.assertEqual(
            {
                key: aggregate["unattributed_membership_unknown_count"]
                for key, aggregate in bundle.items()
            },
            {"all": 0, "accepted": 1, "attended": 6},
        )
        self.assertEqual(bundle["accepted"]["population"]["unknown_count"], 0)
        self.assertEqual(bundle["attended"]["population"]["unknown_count"], 0)
        self.assertEqual(
            bundle["accepted"]["population"]["state_counts"]["no_evidence"],
            0,
        )
        self.assertEqual(
            bundle["attended"]["population"]["state_counts"]["no_evidence"],
            0,
        )
        self.assertEqual(
            bundle["accepted"]["metrics"]["advanced_technical_evidence"],
            19,
        )
        self.assertEqual(
            bundle["attended"]["metrics"]["advanced_technical_evidence"],
            19,
        )
        with self.assertRaisesRegex(ValueError, "reviewed cohort total"):
            build_semantic_cohort_aggregate_bundle(
                facts,
                generated_at=NOW,
                expected_subject_refs=expected,
                reviewed_cohort_totals={
                    "all": 286, "accepted": 81, "attended": 78,
                },
            )

    def test_linkage_padding_preserves_semantic_no_evidence_and_conflict_states(self) -> None:
        from community_os.semantic_metrics import (
            build_semantic_cohort_aggregate_bundle,
            population_snapshot_sha256,
        )

        facts = list(population_facts())
        dimension_keys = (
            "builder_level", "execution_scope", "external_validation",
            "originality", "product_maturity", "technical_depth",
        )
        for index, fact in enumerate(facts):
            membership = fact["cohort_membership"]
            membership["accepted"] = "member" if index < 82 else "not_member"
            membership["present"] = "member" if index < 72 else "not_member"
            if index < 14:
                fact.update({
                    "assessment_state": "no_evidence",
                    "confidence": "unknown",
                    "evidence_refs": [],
                    "evidence_scopes": {
                        key: "not_provided" for key in fact["evidence_scopes"]
                    },
                    "reason_codes": ["no_semantic_evidence"],
                    "review_states": {
                        "agent": "not_reviewed", "human": "not_required",
                        "model": "not_run", "system": "valid",
                    },
                    "semantic_dimensions": {key: None for key in dimension_keys},
                })
            elif index < 18:
                fact.update({
                    "assessment_state": "conflict",
                    "confidence": "unknown",
                    "evidence_refs": [],
                    "evidence_scopes": {
                        key: "conflict" for key in fact["evidence_scopes"]
                    },
                    "reason_codes": ["semantic_evidence_conflict"],
                    "review_states": {
                        "agent": "not_reviewed", "human": "not_required",
                        "model": "not_run", "system": "valid",
                    },
                    "semantic_dimensions": {key: None for key in dimension_keys},
                })
            else:
                fact.update({
                    "assessment_state": "assessed",
                    "confidence": "medium",
                    "evidence_refs": ["application_01:experience"],
                    "evidence_scopes": {
                        "application": "observed",
                        "career_context": "not_provided",
                        "event_submission": "not_provided",
                        "public_projects": "not_provided",
                    },
                    "reason_codes": ["corroborated_across_sources"],
                    "review_states": {
                        "agent": "reviewed", "human": "not_required",
                        "model": "complete", "system": "valid",
                    },
                    "semantic_dimensions": {
                        "builder_level": "exploratory",
                        "execution_scope": "contributor",
                        "external_validation": "none",
                        "originality": "ordinary",
                        "product_maturity": "prototype",
                        "technical_depth": "basic",
                    },
                })
        population_hash = population_snapshot_sha256(facts)
        for fact in facts:
            fact["bindings"]["population_sha256"] = population_hash

        bundle = build_semantic_cohort_aggregate_bundle(
            facts,
            generated_at=NOW,
            expected_subject_refs=sorted(
                str(fact["subject_ref"]) for fact in facts
            ),
            reviewed_cohort_totals={
                "all": 286, "accepted": 83, "attended": 78,
            },
        )

        all_states = bundle["all"]["population"]["state_counts"]
        self.assertEqual(all_states["no_evidence"], 14)
        self.assertEqual(all_states["conflict"], 4)
        self.assertEqual(
            bundle["accepted"]["population"]["state_counts"]["no_evidence"],
            14,
        )
        self.assertEqual(
            bundle["attended"]["population"]["state_counts"]["conflict"],
            4,
        )

    def test_partner_taxonomy_registry_matches_only_reported_public_codes(self) -> None:
        from community_os.semantic_metrics import (
            partner_report_taxonomy_claim_keys,
            partner_report_taxonomy_codes,
            partner_report_taxonomy_positive_claim_count,
            partner_report_taxonomy_schema_sha256,
            semantic_taxonomy_positive_claim_count,
        )
        from tests.test_partner_semantic_projection import semantic_aggregate

        registry = partner_report_taxonomy_codes()
        self.assertEqual(
            set(registry),
            {
                "career_delivery", "career_functions", "career_stage",
                "demonstrated_capabilities", "execution_scope",
                "external_validation", "founder_state", "leadership_state",
                "market_domains", "problem_differentiation",
                "product_maturity", "technical_depth", "technical_methods",
            },
        )
        self.assertNotIn("ordinary", registry["problem_differentiation"])
        self.assertNotIn("none_observed", registry["external_validation"])
        original_hash = partner_report_taxonomy_schema_sha256()
        self.assertRegex(original_hash, r"^[0-9a-f]{64}$")
        registry["career_stage"] = ("executive",)
        self.assertEqual(partner_report_taxonomy_schema_sha256(), original_hash)
        claims = partner_report_taxonomy_claim_keys({
            "project": {
                "product_maturity": "working_product",
                "technical_depth": "advanced",
                "execution_scope": "substantial_contributor",
                "external_validation": "none_observed",
                "problem_differentiation": "ordinary",
                "market_domains": ["education_learning"],
                "technical_methods": ["applied_ai_ml"],
                "demonstrated_capabilities": ["product_engineering"],
            },
            "career": {
                "career_stage": "unknown",
                "founder_state": "no_founder_evidence",
                "leadership_state": "unknown",
                "career_functions": [],
                "career_delivery": [],
            },
        })
        self.assertEqual(
            claims,
            (
                "taxonomy:demonstrated_capabilities:product_engineering",
                "taxonomy:execution_scope:substantial_contributor",
                "taxonomy:market_domains:education_learning",
                "taxonomy:product_maturity:working_product",
                "taxonomy:technical_depth:advanced",
                "taxonomy:technical_methods:applied_ai_ml",
            ),
        )
        aggregate = semantic_aggregate()
        taxonomy = aggregate["taxonomy_dimensions"]
        self.assertEqual(
            partner_report_taxonomy_positive_claim_count(taxonomy), 2519,
        )
        self.assertEqual(semantic_taxonomy_positive_claim_count(taxonomy), 2950)

    def test_taxonomy_hash_binds_version_enums_and_controlled_reasons(self) -> None:
        from community_os.enrichment.semantic_taxonomy import TAXONOMY_SHA256
        from community_os.semantic_metrics import (
            semantic_taxonomy_sha256,
            validate_semantic_facts,
        )

        current = semantic_taxonomy_sha256("semantic-taxonomy-v1")
        self.assertEqual(current, TAXONOMY_SHA256)
        self.assertRegex(current, r"^[0-9a-f]{64}$")
        self.assertEqual(current, semantic_taxonomy_sha256("semantic-taxonomy-v1"))
        self.assertNotEqual(current, semantic_taxonomy_sha256("semantic-taxonomy-v2"))

        forged = list(population_facts())
        for fact in forged:
            fact["bindings"]["taxonomy_sha256"] = "f" * 64
        with self.assertRaisesRegex(ValueError, "binding mismatch"):
            validate_semantic_facts(forged)

    def test_registry_calculates_strict_metrics_from_person_level_facts(self) -> None:
        from community_os.semantic_metrics import build_semantic_aggregate, metric

        facts = population_facts()

        self.assertEqual(metric("advanced_technical_evidence", facts), 19)
        self.assertEqual(metric("primary_execution", facts), 22)
        self.assertEqual(metric("meaningful_validation", facts), 6)
        self.assertEqual(metric("serious_product_builder", facts), 21)
        aggregate = build_semantic_aggregate(
            facts,
            generated_at=NOW,
            expected_subject_refs=sorted(str(fact["subject_ref"]) for fact in facts),
        )
        self.assertEqual(aggregate["population"], {
            "assessed_count": 195,
            "eligible_count": 286,
            "excluded_count": 0,
            "population_key": "all_applicants",
            "snapshot_sha256": facts[0]["bindings"]["population_sha256"],
            "state_counts": {
                "assessed": 195,
                "conflict": 0,
                "excluded": 0,
                "no_evidence": 87,
                "provider_unavailable": 0,
                "rejected": 4,
            },
            "total_count": 286,
            "unknown_count": 91,
        })
        self.assertEqual(aggregate["metrics"]["advanced_technical_evidence"], 19)
        self.assertEqual(aggregate["metrics"]["primary_execution"], 22)
        self.assertEqual(aggregate["metrics"]["meaningful_validation"], 6)
        self.assertEqual(aggregate["metrics"]["serious_product_builder"], 21)
        self.assertEqual(aggregate["source_coverage"], {
            "application": 195,
            "career_context": 12,
            "event_submission": 63,
            "public_projects": 169,
        })
        self.assertTrue(aggregate["internal_only"])
        self.assertFalse(aggregate["release_eligible"])

    def test_registry_predicate_boundaries_are_exact(self) -> None:
        from community_os.semantic_metrics import metric

        facts = list(population_facts())
        facts[19]["semantic_dimensions"]["technical_depth"] = "exceptional"
        facts[6]["semantic_dimensions"]["external_validation"] = "strong"
        facts[21]["semantic_dimensions"]["builder_level"] = "substantial"
        facts[22]["semantic_dimensions"]["builder_level"] = "standout"

        self.assertEqual(metric("substantive_technical_evidence", facts), 133)
        self.assertEqual(metric("advanced_technical_evidence", facts), 20)
        self.assertEqual(metric("meaningful_validation", facts), 7)
        self.assertEqual(metric("primary_execution", facts), 22)
        self.assertEqual(metric("serious_product_builder", facts), 21)
        self.assertEqual(metric("standout_builder", facts), 1)
        self.assertEqual(metric("differentiated_problem", facts), 62)

        facts[21]["semantic_dimensions"]["product_maturity"] = "working_product"
        facts[22]["semantic_dimensions"]["product_maturity"] = "production_evidence"
        self.assertEqual(metric("serious_product_builder", facts), 23)

    def test_only_uncertain_assessed_facts_require_case_level_human_review(self) -> None:
        from community_os.semantic_metrics import validate_semantic_facts

        facts = list(population_facts())
        batch_reviewed = deepcopy(facts)
        batch_reviewed[0]["confidence"] = "high"
        batch_reviewed[0]["review_states"]["human"] = "not_required"
        validate_semantic_facts(batch_reviewed)

        uncertain = deepcopy(facts)
        uncertain[0]["confidence"] = "low"
        uncertain[0]["review_states"]["human"] = "not_required"
        with self.assertRaisesRegex(ValueError, "uncertain"):
            validate_semantic_facts(uncertain)

        uncertain[0]["review_states"]["human"] = "corrected"
        validate_semantic_facts(uncertain)

    def test_population_validation_fails_on_subject_or_binding_drift(self) -> None:
        from community_os.semantic_metrics import (
            build_semantic_aggregate,
            population_snapshot_sha256,
            validate_semantic_facts,
        )

        facts = list(population_facts())
        expected = sorted(str(fact["subject_ref"]) for fact in facts)
        validate_semantic_facts(facts, expected_subject_refs=expected)

        duplicate = deepcopy(facts)
        duplicate[-1]["subject_ref"] = duplicate[0]["subject_ref"]
        with self.assertRaisesRegex(ValueError, "duplicate"):
            validate_semantic_facts(duplicate)

        missing = facts[:-1]
        with self.assertRaisesRegex(ValueError, "reconcile"):
            validate_semantic_facts(missing, expected_subject_refs=expected)

        mixed = deepcopy(facts)
        mixed[-1]["bindings"]["run_sha256"] = "f" * 64
        with self.assertRaisesRegex(ValueError, "mixed bindings"):
            validate_semantic_facts(mixed)

        prose = deepcopy(facts)
        prose[0]["reason_codes"] = ["this_person_seems_impressive"]
        with self.assertRaisesRegex(ValueError, "reason codes"):
            validate_semantic_facts(prose)

        truncated = deepcopy(facts[:10])
        truncated_hash = population_snapshot_sha256(truncated)
        for fact in truncated:
            fact["bindings"]["population_sha256"] = truncated_hash
        with self.assertRaisesRegex(ValueError, "reconcile"):
            build_semantic_aggregate(
                truncated,
                generated_at=NOW,
                expected_subject_refs=expected,
            )

    def test_every_population_member_has_one_explicit_nonnegative_state(self) -> None:
        from community_os.semantic_metrics import (
            build_semantic_aggregate, metric_registry_sha256,
            population_snapshot_sha256, semantic_taxonomy_sha256,
            validate_semantic_facts,
        )

        states = (
            "assessed", "no_evidence", "provider_unavailable",
            "excluded", "conflict", "rejected",
        )
        reason_by_state = {
            "assessed": "insufficient_evidence",
            "no_evidence": "no_semantic_evidence",
            "provider_unavailable": "semantic_provider_unavailable",
            "excluded": "subject_excluded",
            "conflict": "semantic_evidence_conflict",
            "rejected": "semantic_review_rejected",
        }
        facts: list[dict[str, object]] = []
        for index, state in enumerate(states):
            assessed = state == "assessed"
            facts.append({
                "assessment_state": state,
                "bindings": {
                    "event_approval_sha256": "e" * 64,
                    "event_definition_sha256": "a" * 64,
                    "event_key": "start-warsaw-2026-07",
                    "metric_registry_version": "partner-metrics-v1",
                    "metric_registry_sha256": metric_registry_sha256(),
                    "population_key": "all_applicants",
                    "population_sha256": "0" * 64,
                    "run_sha256": "b" * 64,
                    "source_snapshot_sha256": "c" * 64,
                    "taxonomy_version": "talent-taxonomy-v1",
                    "taxonomy_sha256": semantic_taxonomy_sha256(
                        "talent-taxonomy-v1",
                    ),
                },
                "cohort_membership": {
                    "accepted": "unknown", "applied": "member",
                    "present": "unknown", "submitted": "unknown",
                },
                "confidence": "low" if assessed else "unknown",
                "evidence_refs": ["application_01:experience"] if assessed else [],
                "evidence_scopes": {
                    key: (
                        "observed" if assessed and key == "application"
                        else "excluded" if state == "excluded"
                        else "provider_unavailable" if state == "provider_unavailable"
                        else "not_provided"
                    )
                    for key in (
                        "application", "career_context", "event_submission",
                        "public_projects",
                    )
                },
                "fact_version": "population-semantic-fact-v1",
                "population_key": "all_applicants",
                "reason_codes": [reason_by_state[state]],
                "review_states": {
                    "agent": "reviewed" if assessed else "not_reviewed",
                    "human": (
                        "approved" if assessed else "rejected" if state == "rejected"
                        else "not_required"
                    ),
                    "model": "complete" if assessed else "not_run",
                    "system": "valid",
                },
                "semantic_dimensions": ({
                    "builder_level": "exploratory",
                    "execution_scope": "contributor",
                    "external_validation": "none",
                    "originality": "ordinary",
                    "product_maturity": "prototype",
                    "technical_depth": "basic",
                } if assessed else {
                    key: None for key in (
                        "builder_level", "execution_scope", "external_validation",
                        "originality", "product_maturity", "technical_depth",
                    )
                }),
                "subject_ref": f"case:v1:{index + 1:064x}",
            })
        population_hash = population_snapshot_sha256(facts)
        for fact in facts:
            fact["bindings"]["population_sha256"] = population_hash

        validated = validate_semantic_facts(facts)
        aggregate = build_semantic_aggregate(
            validated,
            generated_at=NOW,
            expected_subject_refs=sorted(
                str(fact["subject_ref"]) for fact in validated
            ),
        )

        self.assertEqual(len(validated), 6)
        self.assertEqual(aggregate["population"]["eligible_count"], 5)
        self.assertEqual(aggregate["population"]["assessed_count"], 1)
        self.assertEqual(aggregate["population"]["unknown_count"], 4)
        self.assertEqual(aggregate["population"]["excluded_count"], 1)
        tampered = [dict(item) for item in facts]
        tampered[0] = {**tampered[0], "rationale": "unrestricted prose"}
        with self.assertRaisesRegex(ValueError, "keys"):
            validate_semantic_facts(tampered)


if __name__ == "__main__":
    unittest.main()
