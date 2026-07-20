from __future__ import annotations

from dataclasses import asdict, replace
from datetime import UTC, datetime, timedelta
import hashlib
import json
import unittest


NOW = datetime(2026, 7, 15, 12, tzinfo=UTC)
APPROVAL_SECRET = b"semantic-projection-test-secret-v1"


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def legacy_semantic_aggregate() -> dict[str, object]:
    def dimension(cells: dict[str, int | None]) -> dict[str, object]:
        return {
            "cells": {
                key: {
                    "count": value,
                    "state": "reported" if value is not None else "withheld",
                }
                for key, value in cells.items()
            },
            "denominator": 195,
            "unknown_cell": {"count": None, "state": "withheld"},
        }

    return {
        "aggregate_version": "rich-semantic-internal-aggregate-v4",
        "dimensions": {
            "builder_level": dimension({
                "exploratory": None, "insufficient": None,
                "standout": None, "substantial": None,
            }),
            "cross_source_confidence": dimension({
                "high": 24, "low": 51, "medium": 120,
            }),
            "execution_scope": dimension({
                "contributor": 13, "end_to_end_builder": 5,
                "primary_builder": 17, "substantial_contributor": 21,
                "unknown": 139,
            }),
            "external_validation": dimension({
                "early_signal": 31, "meaningful": 6,
                "none": 158, "strong": None,
            }),
            "impressive_band": dimension({
                "impressive": 21, "not_impressive": 134, "unknown": 40,
            }),
            "originality": dimension({
                "ambitious": 5, "derivative": 12, "differentiated": 57,
                "ordinary": 77, "unknown": 44,
            }),
            "product_maturity": dimension({
                "concept": None, "production_evidence": None,
                "prototype": None, "unknown": None, "working_product": None,
            }),
            "technical_depth": dimension({
                "advanced": 19, "basic": 31, "exceptional": None,
                "moderate": 114, "unknown": 31,
            }),
        },
        "generated_at": "2026-07-15T11:00:00Z",
        "internal_only": True,
        "minimum_group_size": 5,
        "release_eligible": False,
        "reviewed_denominator": 195,
        "source_coverage": {
            "application": 193,
            "career": 12,
            "devpost": 63,
            "projects": 169,
        },
    }


def population_aggregate() -> dict[str, object]:
    from community_os.enrichment.semantic_taxonomy import TAXONOMY_VERSION
    from community_os.semantic_metrics import (
        metric_registry_sha256,
        semantic_taxonomy_sha256,
    )
    from tests.test_semantic_release_approval import _taxonomy_dimensions

    population_hash = _digest("population")
    return {
        "aggregate_version": "population-semantic-aggregate-v2",
        "bindings": {
            "event_approval_sha256": _digest("event-approval"),
            "event_definition_sha256": _digest("event-definition"),
            "event_key": "openai-hackathon-2026",
            "metric_registry_sha256": metric_registry_sha256(),
            "metric_registry_version": "partner-metrics-v1",
            "population_key": "all_applicants",
            "population_sha256": population_hash,
            "run_sha256": _digest("run"),
            "source_snapshot_sha256": _digest("source"),
            "taxonomy_sha256": semantic_taxonomy_sha256(TAXONOMY_VERSION),
            "taxonomy_version": TAXONOMY_VERSION,
        },
        "generated_at": "2026-07-15T11:00:00Z",
        "internal_only": True,
        "metrics": {
            "advanced_technical_evidence": 19,
            "differentiated_problem": 62,
            "meaningful_validation": 6,
            "primary_execution": 22,
            "serious_product_builder": 21,
            "standout_builder": 5,
            "substantive_technical_evidence": 133,
        },
        "minimum_group_size": 5,
        "population": {
            "assessed_count": 195,
            "eligible_count": 286,
            "excluded_count": 0,
            "population_key": "all_applicants",
            "snapshot_sha256": population_hash,
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
        },
        "release_eligible": False,
        "source_coverage": {
            "application": 193,
            "career_context": 12,
            "event_submission": 63,
            "public_projects": 169,
        },
        "taxonomy_dimensions": _taxonomy_dimensions(
            eligible_count=286, assessed_count=195,
        ),
    }


def semantic_aggregate() -> dict[str, object]:
    """Compatibility fixture for protected candidate-render integration tests."""

    return population_aggregate()


def _rebase_taxonomy_to_population(aggregate: dict[str, object]) -> None:
    from tests.test_semantic_release_approval import _taxonomy_dimensions

    population = aggregate["population"]
    assert isinstance(population, dict)
    aggregate["taxonomy_dimensions"] = _taxonomy_dimensions(
        eligible_count=int(population["eligible_count"]),
        assessed_count=int(population["assessed_count"]),
    )


def approved_release(*, aggregate: dict[str, object] | None = None):
    from community_os.semantic_release_approval import (
        build_semantic_release_candidate,
        issue_semantic_release_approval,
        validate_semantic_release_approval_record,
    )

    candidate = build_semantic_release_candidate(
        population_aggregate() if aggregate is None else aggregate,
        qa_sha256=_digest("qa"),
        report_candidate_sha256=_digest("candidate"),
        html_sha256=_digest("html"),
        pdf_sha256=_digest("pdf"),
    )
    record = issue_semantic_release_approval(
        candidate,
        actor_code="colleague_0123456789abcdef0123456789abcdef",
        approved_at=NOW,
        expires_at=NOW + timedelta(days=1),
        signing_secret=APPROVAL_SECRET,
    )
    return validate_semantic_release_approval_record(
        record, candidate=candidate, now=NOW,
        signing_secret=APPROVAL_SECRET,
    )


class PartnerSemanticProjectionTests(unittest.TestCase):
    def test_cohort_candidate_is_ordered_sealed_and_privacy_safe_per_cohort(self) -> None:
        import tempfile

        import community_os.partner_semantic_projection as semantic_projection
        from tests.test_rich_semantic_review import (
            RichSemanticReviewTests,
            assessment,
            population_context,
            proposal,
        )

        self.assertTrue(
            hasattr(
                semantic_projection,
                "build_protected_partner_semantic_cohort_candidate_bundle",
            ),
            "partner cohort candidate builder is missing",
        )
        build_protected_partner_semantic_cohort_candidate_bundle = (
            semantic_projection
            .build_protected_partner_semantic_cohort_candidate_bundle
        )
        validate_partner_semantic_cohort_bundle = (
            semantic_projection.validate_partner_semantic_cohort_bundle
        )

        advanced_ordinals = {1, 2, 3, 4, 6, 11, 12, 13, 14, 15}
        with tempfile.TemporaryDirectory() as directory:
            helper = RichSemanticReviewTests()
            store, _ = helper.create_store(directory)
            expected: list[str] = []
            for ordinal in range(1, 16):
                candidate = (
                    proposal(ordinal)
                    if ordinal in advanced_ordinals
                    else proposal(ordinal, assessment=assessment(
                        technical_depth="moderate",
                    ))
                )
                expected.append(str(candidate["subject_ref"]))
                case = store.submit(candidate)
                store.decide(
                    case.case_code, action="approved",
                    actor_code="release_owner", decided_at=NOW,
                )
            membership = {
                subject: {
                    "applied": "member",
                    "accepted": "member" if ordinal <= 10 else "not_member",
                    "present": "member" if ordinal <= 5 else "not_member",
                }
                for ordinal, subject in enumerate(expected, start=1)
            }
            protected = store.build_population_aggregate(
                expected_subject_refs=expected,
                binding_context=population_context(),
                generated_at=NOW,
                minimum_group_size=5,
                membership_by_subject=membership,
                reviewed_cohort_totals={
                    "all": 15, "accepted": 11, "attended": 6,
                },
            )
            protected["all"]["source_coverage"]["application"] = 8
            protected["accepted"]["source_coverage"]["application"] = 5
            protected["attended"]["source_coverage"]["application"] = 5

        bundle = build_protected_partner_semantic_cohort_candidate_bundle(
            protected,
        )
        validated = validate_partner_semantic_cohort_bundle(bundle)

        self.assertIs(validated, bundle)
        self.assertEqual(
            tuple(cohort.key for cohort in bundle.cohorts),
            ("all", "accepted", "attended"),
        )
        self.assertEqual(
            tuple(cohort.denominator for cohort in bundle.cohorts),
            (15, 11, 6),
        )
        self.assertTrue(
            hasattr(
                bundle.cohorts[0],
                "unattributed_membership_unknown_count",
            ),
            "cohort linkage-unknown metadata is missing",
        )
        self.assertEqual(
            tuple(
                cohort.unattributed_membership_unknown_count
                for cohort in bundle.cohorts
            ),
            (0, 1, 1),
        )
        advanced = {
            cohort.key: next(
                metric for metric in cohort.summary.metrics
                if metric.key == "advanced_technical_evidence"
            )
            for cohort in bundle.cohorts
        }
        self.assertEqual(
            (advanced["all"].count, advanced["all"].state),
            (10, "reported"),
        )
        self.assertEqual(
            (advanced["accepted"].count, advanced["accepted"].state),
            (None, "withheld"),
        )
        self.assertEqual(
            (advanced["attended"].count, advanced["attended"].state),
            (None, "withheld"),
        )
        by_cohort = {cohort.key: cohort.summary for cohort in bundle.cohorts}
        self.assertIsNone(dict(by_cohort["all"].source_coverage)["application"])
        self.assertIsNone(
            dict(by_cohort["accepted"].source_coverage)["application"],
        )
        public_groups = {
            cohort_key: {group.key: group for group in summary.public_groups}
            for cohort_key, summary in by_cohort.items()
        }
        for cohort_key in ("accepted", "attended"):
            public_group = public_groups[cohort_key][
                "advanced_or_exceptional_technical"
            ]
            self.assertIsNone(public_group.count)
            self.assertEqual(public_group.state, "withheld")
            technical_depth = next(
                dimension for dimension in by_cohort[cohort_key].dimensions
                if dimension.key == "technical_depth"
            )
            self.assertTrue(
                all(cell.state == "withheld" for cell in technical_depth.cells),
            )
            self.assertEqual(technical_depth.unknown_state, "withheld")
        self.assertEqual(
            by_cohort["accepted"].whole_person_unresolved_count,
            0,
        )
        self.assertEqual(
            by_cohort["attended"].whole_person_unresolved_count,
            0,
        )
        self.assertNotIn("case:v1", json.dumps(asdict(bundle), sort_keys=True))

        forged = replace(
            bundle,
            cohorts=(
                replace(bundle.cohorts[0], denominator=999),
                *bundle.cohorts[1:],
            ),
        )
        with self.assertRaisesRegex(PermissionError, "cohort bundle"):
            validate_partner_semantic_cohort_bundle(forged)

    def test_public_semantic_group_registry_is_fixed_and_versioned(self) -> None:
        from community_os.semantic_metrics import public_semantic_group_registry

        registry = public_semantic_group_registry()

        self.assertEqual(
            registry["registry_version"],
            "partner-public-semantic-groups-v1",
        )
        self.assertEqual(
            set(registry["groups"]),
            {
                "advanced_or_exceptional_technical",
                "differentiated_or_ambitious_problem",
                "early_or_greater_validation",
                "meaningful_or_strong_validation",
                "moderate_or_stronger_technical",
                "prototype_or_beyond",
                "substantial_or_greater_execution",
                "working_or_production",
            },
        )
        self.assertEqual(
            registry["groups"]["working_or_production"]["values"],
            ["production_evidence", "working_product"],
        )
        self.assertEqual(
            registry["groups"]["moderate_or_stronger_technical"]["dimension"],
            "technical_depth",
        )

    def test_projects_fixed_public_semantic_group_unions(self) -> None:
        from community_os.partner_semantic_projection import (
            build_partner_semantic_summary,
        )

        summary = build_partner_semantic_summary(
            approved_release(), now=NOW, approval_secret=APPROVAL_SECRET,
        )

        self.assertEqual(
            summary.public_group_registry_version,
            "partner-public-semantic-groups-v1",
        )
        self.assertEqual(
            {group.key: group.count for group in summary.public_groups},
            {
                "advanced_or_exceptional_technical": 19,
                "differentiated_or_ambitious_problem": 62,
                "early_or_greater_validation": 37,
                "meaningful_or_strong_validation": 6,
                "moderate_or_stronger_technical": 133,
                "prototype_or_beyond": 69,
                "substantial_or_greater_execution": 43,
                "working_or_production": 21,
            },
        )

    def test_whole_person_unresolved_is_separate_from_dimension_unknowns(self) -> None:
        from community_os.partner_semantic_projection import (
            build_partner_semantic_summary,
        )

        summary = build_partner_semantic_summary(
            approved_release(), now=NOW, approval_secret=APPROVAL_SECRET,
        )
        by_key = {dimension.key: dimension for dimension in summary.dimensions}

        self.assertEqual(summary.whole_person_unresolved_count, 91)
        self.assertIsNone(summary.unknown_count)
        self.assertEqual(by_key["technical_depth"].unknown_count, 91)

    def test_synthetic_headline_metrics_reconcile_with_taxonomy_dimensions(self) -> None:
        aggregate = population_aggregate()
        metrics = aggregate["metrics"]
        dimensions = aggregate["taxonomy_dimensions"]
        assert isinstance(metrics, dict)
        assert isinstance(dimensions, dict)

        expected_sums = {
            "advanced_technical_evidence": (
                "technical_depth", ("advanced", "exceptional"),
            ),
            "differentiated_problem": (
                "problem_differentiation", ("differentiated", "ambitious"),
            ),
            "meaningful_validation": (
                "external_validation", ("meaningful", "strong"),
            ),
            "primary_execution": (
                "execution_scope", ("primary_builder", "end_to_end_builder"),
            ),
            "serious_product_builder": (
                "product_maturity", ("working_product", "production_evidence"),
            ),
            "substantive_technical_evidence": (
                "technical_depth", ("moderate", "advanced", "exceptional"),
            ),
        }
        for metric_key, (dimension_key, cell_keys) in expected_sums.items():
            dimension = dimensions[dimension_key]
            assert isinstance(dimension, dict)
            cells = dimension["cells"]
            assert isinstance(cells, dict)
            self.assertEqual(
                metrics[metric_key],
                sum(int(cells[key]) for key in cell_keys),
                metric_key,
            )

    def test_manifest_binding_rejects_a_forged_summary_with_private_text(self) -> None:
        from community_os.partner_semantic_projection import (
            build_protected_partner_semantic_candidate_summary,
            semantic_summary_manifest_binding,
        )

        summary = build_protected_partner_semantic_candidate_summary(
            population_aggregate(),
        )
        forged = replace(
            summary,
            metrics=(
                replace(
                    summary.metrics[0],
                    label="Private Person private@example.org",
                    note="https://github.com/private/person",
                ),
                *summary.metrics[1:],
            ),
        )

        with self.assertRaisesRegex(PermissionError, "summary"):
            semantic_summary_manifest_binding(forged)

    def test_summary_retains_exact_event_source_and_taxonomy_bindings(self) -> None:
        from community_os.partner_semantic_projection import (
            build_protected_partner_semantic_candidate_summary,
            semantic_summary_manifest_binding,
        )

        aggregate = population_aggregate()
        summary = build_protected_partner_semantic_candidate_summary(aggregate)
        bindings = aggregate["bindings"]
        assert isinstance(bindings, dict)

        self.assertEqual(summary.event_key, bindings["event_key"])
        self.assertEqual(
            summary.event_definition_sha256,
            bindings["event_definition_sha256"],
        )
        self.assertEqual(
            summary.event_approval_sha256,
            bindings["event_approval_sha256"],
        )
        self.assertEqual(
            summary.source_snapshot_sha256,
            bindings["source_snapshot_sha256"],
        )
        self.assertEqual(summary.population_sha256, bindings["population_sha256"])
        self.assertEqual(summary.taxonomy_sha256, bindings["taxonomy_sha256"])
        self.assertEqual(summary.taxonomy_version, bindings["taxonomy_version"])
        self.assertEqual(summary.run_sha256, bindings["run_sha256"])
        self.assertEqual(
            semantic_summary_manifest_binding(summary)["source_snapshot_sha256"],
            bindings["source_snapshot_sha256"],
        )

    def test_partner_taxonomy_uses_deliberate_public_labels(self) -> None:
        from community_os.partner_semantic_projection import (
            build_protected_partner_semantic_candidate_summary,
        )

        summary = build_protected_partner_semantic_candidate_summary(
            population_aggregate(),
        )
        labels = {
            cell.key: cell.label
            for dimension in summary.dimensions
            for cell in dimension.cells
        }

        self.assertEqual(labels["applied_ai_ml"], "Applied AI / ML")
        self.assertEqual(
            labels["infrastructure_devops"], "Infrastructure / DevOps",
        )
        self.assertEqual(
            labels["healthcare_life_sciences"],
            "Healthcare and life sciences",
        )

    def test_projects_only_fixed_human_approved_partner_metrics(self) -> None:
        from community_os.partner_semantic_projection import (
            build_partner_semantic_summary,
        )

        summary = build_partner_semantic_summary(
            approved_release(), now=NOW, approval_secret=APPROVAL_SECRET,
        )

        self.assertEqual(summary.reviewed_denominator, 195)
        self.assertEqual(summary.eligible_denominator, 286)
        self.assertEqual(
            {metric.key: metric.count for metric in summary.metrics},
            population_aggregate()["metrics"],
        )
        self.assertEqual(
            dict(summary.source_coverage),
            {
                "application": 193,
                "public_projects": 169,
                "event_submission": 63,
                "career_context": 12,
            },
        )
        serialized = json.dumps(asdict(summary), sort_keys=True)
        for forbidden in (
            "not_impressive", "ordinary", "derivative", "subject_ref",
            "evidence_refs", "github.com", "linkedin.com",
        ):
            self.assertNotIn(forbidden, serialized)

    def test_projects_full_controlled_taxonomy_as_privacy_safe_distributions(self) -> None:
        from community_os.partner_semantic_projection import (
            build_partner_semantic_summary,
        )
        from community_os.semantic_metrics import (
            semantic_taxonomy_dimension_registry,
        )

        summary = build_partner_semantic_summary(
            approved_release(), now=NOW, approval_secret=APPROVAL_SECRET,
        )
        registry = semantic_taxonomy_dimension_registry()
        by_key = {dimension.key: dimension for dimension in summary.dimensions}
        self.assertEqual(set(by_key), set(registry))

        technical_depth = by_key["technical_depth"]
        self.assertEqual(technical_depth.mode, "exclusive")
        self.assertEqual(technical_depth.denominator, 286)
        self.assertEqual(technical_depth.unknown_count, 91)
        self.assertEqual(
            {cell.key: cell.count for cell in technical_depth.cells},
            {"moderate": 114, "advanced": 14, "exceptional": 5},
        )

        career_delivery = by_key["career_delivery"]
        self.assertEqual(career_delivery.mode, "overlapping")
        self.assertEqual(career_delivery.unknown_count, 91)
        self.assertTrue(all(cell.state == "reported" for cell in career_delivery.cells))

    def test_taxonomy_projection_withholds_small_exclusive_and_overlapping_cells(self) -> None:
        from community_os.partner_semantic_projection import (
            build_partner_semantic_summary,
        )

        aggregate = population_aggregate()
        taxonomy = aggregate["taxonomy_dimensions"]
        assert isinstance(taxonomy, dict)
        technical = taxonomy["technical_depth"]
        assert isinstance(technical, dict)
        technical_cells = technical["cells"]
        assert isinstance(technical_cells, dict)
        technical_cells["basic"] += 10
        technical_cells["advanced"] = 4
        domains = taxonomy["market_domains"]
        assert isinstance(domains, dict)
        domain_cells = domains["cells"]
        assert isinstance(domain_cells, dict)
        domain_cells["commerce_consumer"] = 4

        summary = build_partner_semantic_summary(
            approved_release(aggregate=aggregate), now=NOW,
            approval_secret=APPROVAL_SECRET,
        )
        by_key = {dimension.key: dimension for dimension in summary.dimensions}
        self.assertTrue(
            all(cell.state == "withheld" for cell in by_key["technical_depth"].cells),
        )
        self.assertEqual(by_key["technical_depth"].unknown_state, "withheld")
        domains_by_key = {
            cell.key: cell for cell in by_key["market_domains"].cells
        }
        self.assertIsNone(domains_by_key["commerce_consumer"].count)
        self.assertEqual(domains_by_key["commerce_consumer"].state, "withheld")
        self.assertEqual(domains_by_key["climate_energy"].state, "reported")

    def test_omitted_exclusive_residual_cannot_be_reconstructed(self) -> None:
        from community_os.partner_semantic_projection import (
            build_partner_semantic_summary,
        )

        aggregate = population_aggregate()
        taxonomy = aggregate["taxonomy_dimensions"]
        assert isinstance(taxonomy, dict)
        validation = taxonomy["external_validation"]
        assert isinstance(validation, dict)
        cells = validation["cells"]
        assert isinstance(cells, dict)
        cells["none_observed"] = 4
        cells["early_signal"] = 185

        summary = build_partner_semantic_summary(
            approved_release(aggregate=aggregate), now=NOW,
            approval_secret=APPROVAL_SECRET,
        )
        by_key = {dimension.key: dimension for dimension in summary.dimensions}
        public_validation = by_key["external_validation"]
        public_groups = {group.key: group for group in summary.public_groups}

        self.assertTrue(
            all(cell.state == "withheld" for cell in public_validation.cells),
        )
        self.assertEqual(public_validation.unknown_state, "withheld")
        self.assertEqual(
            public_groups["early_or_greater_validation"].state,
            "withheld",
        )
        self.assertIsNone(
            public_groups["early_or_greater_validation"].count,
        )

    def test_public_group_with_small_full_population_complement_is_withheld(self) -> None:
        from community_os.partner_semantic_projection import (
            build_protected_partner_semantic_candidate_summary,
        )

        aggregate = population_aggregate()
        taxonomy = aggregate["taxonomy_dimensions"]
        assert isinstance(taxonomy, dict)
        product = taxonomy["product_maturity"]
        assert isinstance(product, dict)
        cells = product["cells"]
        assert isinstance(cells, dict)
        product["unknown_count"] = 3
        cells.update({
            "concept": 0,
            "prototype": 200,
            "working_product": 78,
            "production_evidence": 5,
            "unknown": 3,
        })

        summary = build_protected_partner_semantic_candidate_summary(aggregate)
        public_groups = {group.key: group for group in summary.public_groups}

        prototype_or_beyond = public_groups["prototype_or_beyond"]
        self.assertEqual(prototype_or_beyond.denominator, 286)
        self.assertEqual(prototype_or_beyond.state, "withheld")
        self.assertIsNone(prototype_or_beyond.count)

    def test_projection_rejects_raw_or_legacy_internal_aggregates(self) -> None:
        from community_os.partner_semantic_projection import (
            build_partner_semantic_summary,
        )

        for aggregate in (population_aggregate(), legacy_semantic_aggregate()):
            with self.subTest(version=aggregate["aggregate_version"]):
                with self.assertRaisesRegex(PermissionError, "human approval"):
                    build_partner_semantic_summary(
                        aggregate, now=NOW, approval_secret=APPROVAL_SECRET,
                    )

    def test_legacy_v3_and_v4_are_available_only_as_named_diagnostics(self) -> None:
        from community_os.partner_semantic_projection import (
            build_legacy_diagnostic_semantic_summary,
        )

        v4 = build_legacy_diagnostic_semantic_summary(legacy_semantic_aggregate())
        self.assertEqual(v4.projection_version, "partner-semantic-diagnostic-v1")
        self.assertEqual(v4.reviewed_denominator, 195)
        self.assertEqual(dict(v4.source_coverage)["career"], 12)

        v3_aggregate = legacy_semantic_aggregate()
        v3_aggregate["aggregate_version"] = "rich-semantic-internal-aggregate-v3"
        v3_aggregate["event_counts"] = {"accepted": 999, "present": 999}
        v3_aggregate.pop("source_coverage")
        v3 = build_legacy_diagnostic_semantic_summary(v3_aggregate)
        self.assertEqual(v3.source_coverage, ())
        self.assertNotIn("999", json.dumps(asdict(v3), sort_keys=True))

    def test_partner_projection_suppresses_small_positive_or_complementary_cells(self) -> None:
        from community_os.partner_semantic_projection import (
            build_partner_semantic_summary,
        )

        aggregate = population_aggregate()
        aggregate["metrics"]["standout_builder"] = 4
        population = aggregate["population"]
        assert isinstance(population, dict)
        population["assessed_count"] = 286
        population["unknown_count"] = 0
        states = population["state_counts"]
        assert isinstance(states, dict)
        states["assessed"] = 286
        states["no_evidence"] = 0
        states["rejected"] = 0
        aggregate["metrics"]["substantive_technical_evidence"] = 283
        summary = build_partner_semantic_summary(
            approved_release(aggregate=aggregate), now=NOW,
            approval_secret=APPROVAL_SECRET,
        )
        by_key = {metric.key: metric for metric in summary.metrics}
        self.assertIsNone(by_key["standout_builder"].count)
        self.assertEqual(by_key["standout_builder"].state, "withheld")
        self.assertIsNone(by_key["substantive_technical_evidence"].count)
        self.assertEqual(
            by_key["substantive_technical_evidence"].state, "withheld",
        )

        aggregate = population_aggregate()
        aggregate["metrics"]["advanced_technical_evidence"] = 10
        aggregate["metrics"]["substantive_technical_evidence"] = 12
        summary = build_partner_semantic_summary(
            approved_release(aggregate=aggregate), now=NOW,
            approval_secret=APPROVAL_SECRET,
        )
        by_key = {metric.key: metric for metric in summary.metrics}
        self.assertEqual(by_key["advanced_technical_evidence"].count, 10)
        self.assertIsNone(by_key["substantive_technical_evidence"].count)

    def test_partner_projection_suppresses_small_unassessed_complement(self) -> None:
        from community_os.partner_semantic_projection import (
            build_partner_semantic_summary,
        )

        aggregate = population_aggregate()
        population = aggregate["population"]
        assert isinstance(population, dict)
        population["assessed_count"] = 283
        population["unknown_count"] = 3
        states = population["state_counts"]
        assert isinstance(states, dict)
        states["assessed"] = 283
        states["no_evidence"] = 3
        states["rejected"] = 0
        summary = build_partner_semantic_summary(
            approved_release(aggregate=aggregate), now=NOW,
            approval_secret=APPROVAL_SECRET,
        )
        self.assertIsNone(summary.reviewed_denominator)
        self.assertEqual(summary.total_population, 286)
        self.assertIsNone(summary.unknown_count)
        self.assertIsNone(summary.whole_person_unresolved_count)

    def test_small_excluded_group_never_leaks_through_metric_denominators(self) -> None:
        from community_os.partner_semantic_projection import (
            build_partner_semantic_summary,
        )

        aggregate = population_aggregate()
        population = aggregate["population"]
        assert isinstance(population, dict)
        population["eligible_count"] = 282
        population["excluded_count"] = 4
        population["assessed_count"] = 195
        population["unknown_count"] = 87
        states = population["state_counts"]
        assert isinstance(states, dict)
        states["assessed"] = 195
        states["no_evidence"] = 83
        states["rejected"] = 4
        states["excluded"] = 4
        coverage = aggregate["source_coverage"]
        assert isinstance(coverage, dict)
        coverage["application"] = 193
        _rebase_taxonomy_to_population(aggregate)
        summary = build_partner_semantic_summary(
            approved_release(aggregate=aggregate), now=NOW,
            approval_secret=APPROVAL_SECRET,
        )

        self.assertIsNone(summary.eligible_denominator)
        self.assertIsNone(summary.excluded_count)
        self.assertTrue(all(metric.denominator is None for metric in summary.metrics))

    def test_nested_assessment_metric_and_source_complements_are_suppressed(self) -> None:
        from community_os.partner_semantic_projection import (
            build_partner_semantic_summary,
        )

        aggregate = population_aggregate()
        population = aggregate["population"]
        assert isinstance(population, dict)
        population["assessed_count"] = 190
        population["unknown_count"] = 96
        states = population["state_counts"]
        assert isinstance(states, dict)
        states["assessed"] = 190
        states["no_evidence"] = 92
        states["rejected"] = 4
        aggregate["metrics"]["serious_product_builder"] = 188
        summary = build_partner_semantic_summary(
            approved_release(aggregate=aggregate), now=NOW,
            approval_secret=APPROVAL_SECRET,
        )
        by_key = {metric.key: metric for metric in summary.metrics}
        self.assertEqual(summary.reviewed_denominator, 190)
        self.assertIsNone(by_key["serious_product_builder"].count)

        aggregate = population_aggregate()
        population = aggregate["population"]
        assert isinstance(population, dict)
        population["eligible_count"] = 281
        population["excluded_count"] = 5
        population["assessed_count"] = 195
        population["unknown_count"] = 86
        states = population["state_counts"]
        assert isinstance(states, dict)
        states["assessed"] = 195
        states["no_evidence"] = 82
        states["rejected"] = 4
        states["excluded"] = 5
        coverage = aggregate["source_coverage"]
        assert isinstance(coverage, dict)
        coverage["application"] = 280
        _rebase_taxonomy_to_population(aggregate)
        summary = build_partner_semantic_summary(
            approved_release(aggregate=aggregate), now=NOW,
            approval_secret=APPROVAL_SECRET,
        )
        self.assertEqual(summary.eligible_denominator, 281)
        self.assertIsNone(dict(summary.source_coverage)["application"])


if __name__ == "__main__":
    unittest.main()
