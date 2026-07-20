from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime, timedelta
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


NOW = datetime(2026, 7, 15, 12, tzinfo=UTC)
APPROVAL_SECRET = b"semantic-approval-test-secret-v1"
ACTOR_CODE = "colleague_0123456789abcdef0123456789abcdef"


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _taxonomy_dimensions(
    *, eligible_count: int, assessed_count: int,
) -> dict[str, object]:
    from community_os.semantic_metrics import semantic_taxonomy_dimension_registry

    unknown_count = eligible_count - assessed_count
    dimensions: dict[str, object] = {}
    for field, spec in semantic_taxonomy_dimension_registry().items():
        values = list(spec["values"])
        cells = {str(value): 0 for value in values}
        if spec["mode"] == "exclusive":
            cells["unknown"] = unknown_count
            observed_code = next(value for value in values if value != "unknown")
            cells[str(observed_code)] = assessed_count
        else:
            cells[str(values[0])] = assessed_count
        dimensions[field] = {
            "cells": cells,
            "denominator": eligible_count,
            "mode": spec["mode"],
            "unknown_count": unknown_count,
        }
    fixed_exclusive = {
        "product_maturity": {
            "concept": assessed_count - 69,
            "prototype": 48,
            "working_product": 16,
            "production_evidence": 5,
        },
        "technical_depth": {
            "basic": assessed_count - 133,
            "moderate": 114,
            "advanced": 14,
            "exceptional": 5,
        },
        "problem_differentiation": {
            "derivative": 12,
            "ordinary": assessed_count - 74,
            "differentiated": 57,
            "ambitious": 5,
        },
        "execution_scope": {
            "contributor": assessed_count - 43,
            "substantial_contributor": 21,
            "primary_builder": 17,
            "end_to_end_builder": 5,
        },
        "external_validation": {
            "none_observed": assessed_count - 37,
            "early_signal": 31,
            "meaningful": 6,
            "strong": 0,
        },
        "career_stage": {
            "early_career": 43,
            "mid_career": 70,
            "senior": 57,
            "executive": assessed_count - 170,
        },
        "founder_state": {
            "no_founder_evidence": assessed_count - 60,
            "former_founder": 20,
            "current_founder": 40,
        },
        "leadership_state": {
            "individual_contributor": assessed_count - 85,
            "team_lead": 50,
            "organizational_leader": 25,
            "executive_leader": 10,
        },
    }
    for field, observed_cells in fixed_exclusive.items():
        dimension = dimensions[field]
        assert isinstance(dimension, dict)
        cells = dimension["cells"]
        assert isinstance(cells, dict)
        cells.update(observed_cells)
    fixed_overlapping = {
        "market_domains": {
            "climate_energy": 27,
            "financial_services": 68,
            "developer_infrastructure": 54,
            "enterprise_operations": 47,
            "healthcare_life_sciences": 36,
            "commerce_consumer": 31,
        },
        "technical_methods": {
            "applied_ai_ml": 105,
            "web_full_stack": 81,
            "cloud_infrastructure": 62,
            "data_engineering": 49,
            "automation_orchestration": 44,
            "mobile_native": 18,
        },
        "demonstrated_capabilities": {
            "backend_engineering": 98,
            "data_ai_engineering": 91,
            "product_engineering": 79,
            "frontend_engineering": 63,
            "infrastructure_devops": 45,
            "product_design": 24,
        },
        "career_functions": {
            "commercial": 24,
            "software_engineering": 129,
            "data_ai": 88,
            "product": 56,
            "research": 34,
            "operations": 21,
        },
        "career_delivery": {
            "customer_delivery": 58,
            "shipped_products": 89,
            "scaled_systems": 46,
            "founded_venture": 35,
            "led_teams": 33,
            "open_source_maintenance": 27,
            "research_to_practice": 21,
        },
    }
    for field, observed_cells in fixed_overlapping.items():
        dimension = dimensions[field]
        assert isinstance(dimension, dict)
        cells = dimension["cells"]
        assert isinstance(cells, dict)
        cells.update(observed_cells)
    return dimensions


def _internal_aggregate() -> dict[str, object]:
    from community_os.semantic_metrics import (
        metric_registry_sha256,
        semantic_taxonomy_sha256,
    )
    from community_os.enrichment.semantic_taxonomy import TAXONOMY_VERSION

    return {
        "aggregate_version": "population-semantic-aggregate-v2",
        "bindings": {
            "event_approval_sha256": _digest("event-approval"),
            "event_definition_sha256": _digest("event-definition"),
            "event_key": "start-warsaw-2026-07",
            "metric_registry_sha256": metric_registry_sha256(),
            "metric_registry_version": "partner-metrics-v1",
            "population_key": "all_applicants",
            "population_sha256": _digest("population"),
            "run_sha256": _digest("run"),
            "source_snapshot_sha256": _digest("source-snapshot"),
            "taxonomy_sha256": semantic_taxonomy_sha256(TAXONOMY_VERSION),
            "taxonomy_version": TAXONOMY_VERSION,
        },
        "generated_at": "2026-07-15T12:00:00Z",
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
            "assessed_count": 180,
            "eligible_count": 191,
            "excluded_count": 4,
            "population_key": "all_applicants",
            "snapshot_sha256": _digest("population"),
            "state_counts": {
                "assessed": 180,
                "conflict": 2,
                "excluded": 4,
                "no_evidence": 5,
                "provider_unavailable": 3,
                "rejected": 1,
            },
            "total_count": 195,
            "unknown_count": 11,
        },
        "release_eligible": False,
        "source_coverage": {
            "application": 191,
            "career_context": 12,
            "event_submission": 63,
            "public_projects": 169,
        },
        "taxonomy_dimensions": _taxonomy_dimensions(
            eligible_count=191, assessed_count=180,
        ),
    }


def _candidate(aggregate: dict[str, object] | None = None):
    from community_os.semantic_release_approval import (
        build_semantic_release_candidate,
    )

    return build_semantic_release_candidate(
        _internal_aggregate() if aggregate is None else aggregate,
        qa_sha256=_digest("release-qa"),
        report_candidate_sha256=_digest("report-candidate"),
        html_sha256=_digest("partner-html"),
        pdf_sha256=_digest("partner-pdf"),
    )


def _approval_record(
    candidate, *, approved_at: datetime = NOW,
    expires_at: datetime | None = None,
):
    from community_os.semantic_release_approval import (
        issue_semantic_release_approval,
    )

    return issue_semantic_release_approval(
        candidate,
        actor_code=ACTOR_CODE,
        approved_at=approved_at,
        expires_at=expires_at or approved_at + timedelta(days=1),
        signing_secret=APPROVAL_SECRET,
    )


class SemanticReleaseApprovalTests(unittest.TestCase):
    def test_self_declared_human_or_public_owner_literal_without_seal_is_rejected(self) -> None:
        from community_os.semantic_release_approval import (
            SemanticReleaseApprovalError,
            validate_semantic_release_approval_record,
        )

        candidate = _candidate()
        record = _approval_record(candidate)
        record["actor_code"] = "release_owner"

        with self.assertRaisesRegex(
            SemanticReleaseApprovalError, "authentic|seal",
        ):
            validate_semantic_release_approval_record(
                record, candidate=candidate, now=NOW,
                signing_secret=APPROVAL_SECRET,
            )

    def test_human_approval_binds_exact_candidate_and_unlocks_projection(self) -> None:
        from community_os.partner_semantic_projection import (
            build_partner_semantic_summary,
        )
        from community_os.semantic_release_approval import (
            validate_semantic_release_approval_record,
        )

        aggregate = _internal_aggregate()
        candidate = _candidate(aggregate)
        expected_binding_keys = {
            "aggregate_sha256",
            "event_approval_sha256",
            "event_definition_sha256",
            "event_key",
            "html_sha256",
            "metric_registry_sha256",
            "metric_registry_version",
            "pdf_sha256",
            "population",
            "population_key",
            "population_sha256",
            "qa_sha256",
            "report_candidate_sha256",
            "run_sha256",
            "source_snapshot_sha256",
            "taxonomy_sha256",
            "taxonomy_version",
        }
        approval_bindings = candidate.approval_bindings()
        self.assertEqual(set(approval_bindings), expected_binding_keys)
        expected_aggregate_sha256 = hashlib.sha256(json.dumps(
            aggregate, ensure_ascii=True, sort_keys=True,
            separators=(",", ":"), allow_nan=False,
        ).encode("utf-8")).hexdigest()
        self.assertEqual(
            approval_bindings["aggregate_sha256"], expected_aggregate_sha256,
        )
        self.assertEqual(approval_bindings["population"], aggregate["population"])
        self.assertEqual(
            approval_bindings["event_approval_sha256"],
            aggregate["bindings"]["event_approval_sha256"],
        )

        approved = validate_semantic_release_approval_record(
            _approval_record(candidate), candidate=candidate, now=NOW,
            signing_secret=APPROVAL_SECRET,
        )
        self.assertEqual(approved.version, "semantic-release-approval-v3")
        self.assertEqual(approved.actor_type, "human")
        self.assertRegex(approved.sha256, r"^[0-9a-f]{64}$")

        summary = build_partner_semantic_summary(
            approved, now=NOW, approval_secret=APPROVAL_SECRET,
        )
        self.assertEqual(
            {metric.key: metric.count for metric in summary.metrics},
            _internal_aggregate()["metrics"],
        )

    def test_rejects_nonhuman_nonapproved_or_shape_drifted_record(self) -> None:
        from community_os.semantic_release_approval import (
            SemanticReleaseApprovalError,
            validate_semantic_release_approval_record,
        )

        candidate = _candidate()
        cases = (
            ("actor_type", "service", "authentic"),
            ("decision", "rejected", "authentic"),
            ("actor_code", "model output", "authentic"),
        )
        for field, value, message in cases:
            record = _approval_record(candidate)
            record[field] = value
            with self.subTest(field=field):
                with self.assertRaisesRegex(SemanticReleaseApprovalError, message):
                    validate_semantic_release_approval_record(
                        record, candidate=candidate, now=NOW,
                        signing_secret=APPROVAL_SECRET,
                    )

        extra = _approval_record(candidate)
        extra["review_note"] = "unrestricted prose is not part of approval"
        with self.assertRaisesRegex(SemanticReleaseApprovalError, "keys"):
            validate_semantic_release_approval_record(
                extra, candidate=candidate, now=NOW,
                signing_secret=APPROVAL_SECRET,
            )

    def test_approval_expiry_is_current_timezone_aware_and_at_most_seven_days(self) -> None:
        from community_os.semantic_release_approval import (
            SemanticReleaseApprovalError,
            validate_semantic_release_approval_record,
        )

        candidate = _candidate()
        exactly_seven_days = _approval_record(
            candidate, expires_at=NOW + timedelta(days=7),
        )
        validate_semantic_release_approval_record(
            exactly_seven_days, candidate=candidate, now=NOW,
            signing_secret=APPROVAL_SECRET,
        )

        cases = (
            ("too_long", NOW, NOW + timedelta(days=7, seconds=1)),
            ("expired", NOW, NOW),
            ("backwards", NOW, NOW - timedelta(seconds=1)),
            ("naive", NOW.replace(tzinfo=None), NOW + timedelta(days=1)),
            ("future", NOW + timedelta(seconds=1), NOW + timedelta(days=1)),
        )
        for label, approved_at, expires_at in cases:
            with self.subTest(case=label):
                with self.assertRaisesRegex(
                    SemanticReleaseApprovalError, "expir|timestamp|timezone",
                ):
                    record = _approval_record(
                        candidate, approved_at=approved_at, expires_at=expires_at,
                    )
                    validate_semantic_release_approval_record(
                        record, candidate=candidate, now=NOW,
                        signing_secret=APPROVAL_SECRET,
                    )

    def test_candidate_rejects_inconsistent_population_arithmetic(self) -> None:
        from community_os.semantic_release_approval import (
            SemanticReleaseApprovalError,
        )

        mutations = {
            "eligible": ("eligible_count", 190),
            "assessed": ("assessed_count", 179),
            "unknown": ("unknown_count", 10),
            "excluded": ("excluded_count", 3),
            "total": ("total_count", 194),
        }
        for label, (field, value) in mutations.items():
            aggregate = _internal_aggregate()
            population = aggregate["population"]
            assert isinstance(population, dict)
            population[field] = value
            with self.subTest(arithmetic=label):
                with self.assertRaisesRegex(
                    SemanticReleaseApprovalError, "population",
                ):
                    _candidate(aggregate)

        aggregate = _internal_aggregate()
        population = aggregate["population"]
        assert isinstance(population, dict)
        state_counts = population["state_counts"]
        assert isinstance(state_counts, dict)
        state_counts["no_evidence"] = 4
        with self.assertRaisesRegex(SemanticReleaseApprovalError, "population"):
            _candidate(aggregate)

    def test_candidate_metrics_and_coverage_cannot_include_unassessed_or_excluded_people(self) -> None:
        from community_os.semantic_release_approval import (
            SemanticReleaseApprovalError,
        )

        aggregate = _internal_aggregate()
        population = aggregate["population"]
        assert isinstance(population, dict)
        population["assessed_count"] = 1
        population["unknown_count"] = 190
        states = population["state_counts"]
        assert isinstance(states, dict)
        states["assessed"] = 1
        states["no_evidence"] = 184
        with self.assertRaisesRegex(
            SemanticReleaseApprovalError, "assessed population",
        ):
            _candidate(aggregate)

    def test_candidate_requires_exact_reconciled_taxonomy_dimensions(self) -> None:
        from community_os.semantic_release_approval import (
            SemanticReleaseApprovalError,
        )

        aggregate = _internal_aggregate()
        taxonomy = aggregate["taxonomy_dimensions"]
        assert isinstance(taxonomy, dict)
        taxonomy.pop("technical_methods")
        with self.assertRaisesRegex(
            SemanticReleaseApprovalError, "taxonomy dimension",
        ):
            _candidate(aggregate)

        aggregate = _internal_aggregate()
        taxonomy = aggregate["taxonomy_dimensions"]
        assert isinstance(taxonomy, dict)
        technical_depth = taxonomy["technical_depth"]
        assert isinstance(technical_depth, dict)
        technical_depth["denominator"] = 190
        with self.assertRaisesRegex(
            SemanticReleaseApprovalError, "taxonomy dimension",
        ):
            _candidate(aggregate)

        aggregate = _internal_aggregate()
        taxonomy = aggregate["taxonomy_dimensions"]
        assert isinstance(taxonomy, dict)
        technical_depth = taxonomy["technical_depth"]
        assert isinstance(technical_depth, dict)
        cells = technical_depth["cells"]
        assert isinstance(cells, dict)
        cells["advanced"] = 181
        with self.assertRaisesRegex(
            SemanticReleaseApprovalError, "taxonomy dimension",
        ):
            _candidate(aggregate)

        aggregate = _internal_aggregate()
        coverage = aggregate["source_coverage"]
        assert isinstance(coverage, dict)
        coverage["application"] = 192
        with self.assertRaisesRegex(
            SemanticReleaseApprovalError, "eligible population",
        ):
            _candidate(aggregate)

    def test_rejects_every_bound_hash_or_population_metadata_drift(self) -> None:
        from community_os.semantic_release_approval import (
            SemanticReleaseApprovalError,
            validate_semantic_release_approval_record,
        )

        candidate = _candidate()
        hash_bindings = (
            "aggregate_sha256",
            "event_approval_sha256",
            "event_definition_sha256",
            "html_sha256",
            "metric_registry_sha256",
            "pdf_sha256",
            "population_sha256",
            "qa_sha256",
            "report_candidate_sha256",
            "run_sha256",
            "source_snapshot_sha256",
            "taxonomy_sha256",
        )
        for key in hash_bindings:
            record = _approval_record(candidate)
            record["bindings"][key] = _digest(f"drift-{key}")
            with self.subTest(binding=key):
                with self.assertRaisesRegex(
                    SemanticReleaseApprovalError, "match|binding",
                ):
                    validate_semantic_release_approval_record(
                        record, candidate=candidate, now=NOW,
                        signing_secret=APPROVAL_SECRET,
                    )

        for key in (
            "event_key", "taxonomy_version", "metric_registry_version",
            "population_key",
        ):
            record = _approval_record(candidate)
            record["bindings"][key] = f"drift-{key}"
            with self.subTest(binding=key):
                with self.assertRaisesRegex(
                    SemanticReleaseApprovalError, "match|binding",
                ):
                    validate_semantic_release_approval_record(
                        record, candidate=candidate, now=NOW,
                        signing_secret=APPROVAL_SECRET,
                    )

        record = _approval_record(candidate)
        population = record["bindings"]["population"]
        assert isinstance(population, dict)
        population["unknown_count"] = 12
        with self.assertRaisesRegex(SemanticReleaseApprovalError, "match|binding"):
            validate_semantic_release_approval_record(
                record, candidate=candidate, now=NOW,
                signing_secret=APPROVAL_SECRET,
            )

    def test_raw_internal_aggregate_and_unapproved_candidate_cannot_project(self) -> None:
        from community_os.partner_semantic_projection import (
            build_partner_semantic_summary,
        )

        with self.assertRaisesRegex(PermissionError, "human approval"):
            build_partner_semantic_summary(
                _internal_aggregate(), now=NOW, approval_secret=APPROVAL_SECRET,
            )
        with self.assertRaisesRegex(PermissionError, "human approval"):
            build_partner_semantic_summary(
                _candidate(), now=NOW, approval_secret=APPROVAL_SECRET,
            )

    def test_approved_wrapper_detects_record_or_aggregate_mutation(self) -> None:
        from community_os.partner_semantic_projection import (
            build_partner_semantic_summary,
        )
        from community_os.semantic_release_approval import (
            validate_semantic_release_approval_record,
        )

        candidate = _candidate()
        approved = validate_semantic_release_approval_record(
            _approval_record(candidate), candidate=candidate, now=NOW,
            signing_secret=APPROVAL_SECRET,
        )
        approval = approved.approval
        assert isinstance(approval, dict)
        approval_bindings = approval["bindings"]
        assert isinstance(approval_bindings, dict)
        approval_bindings["qa_sha256"] = _digest("mutated-qa")
        with self.assertRaisesRegex(PermissionError, "approval record"):
            build_partner_semantic_summary(
                approved, now=NOW, approval_secret=APPROVAL_SECRET,
            )

        candidate = _candidate()
        approved = validate_semantic_release_approval_record(
            _approval_record(candidate), candidate=candidate, now=NOW,
            signing_secret=APPROVAL_SECRET,
        )
        aggregate = approved.candidate.aggregate
        assert isinstance(aggregate, dict)
        metrics = aggregate["metrics"]
        assert isinstance(metrics, dict)
        metrics["primary_execution"] = 23
        with self.assertRaisesRegex(PermissionError, "binding drifted"):
            build_partner_semantic_summary(
                approved, now=NOW, approval_secret=APPROVAL_SECRET,
            )

    def test_projection_uses_detached_revalidated_artifact_bindings(self) -> None:
        import community_os.partner_semantic_projection as projection_module
        from community_os.partner_semantic_projection import (
            build_partner_semantic_summary,
        )
        from community_os.semantic_release_approval import (
            validate_semantic_release_approval_record,
        )

        candidate = _candidate()
        approved = validate_semantic_release_approval_record(
            _approval_record(candidate), candidate=candidate, now=NOW,
            signing_secret=APPROVAL_SECRET,
        )
        approved_html_sha256 = str(candidate.approval_bindings()["html_sha256"])
        post_validation_mutation = _digest("post-validation-html-mutation")
        original_project = projection_module._project_population_aggregate

        def mutate_after_binding_validation(*args, **kwargs):
            approval = approved.approval
            assert isinstance(approval, dict)
            bindings = approval["bindings"]
            assert isinstance(bindings, dict)
            bindings["html_sha256"] = post_validation_mutation
            return original_project(*args, **kwargs)

        with patch.object(
            projection_module,
            "_project_population_aggregate",
            side_effect=mutate_after_binding_validation,
        ):
            summary = build_partner_semantic_summary(
                approved, now=NOW, approval_secret=APPROVAL_SECRET,
            )

        projected_hashes = dict(summary.release_artifact_hashes)
        self.assertEqual(projected_hashes["html_sha256"], approved_html_sha256)
        self.assertNotEqual(
            projected_hashes["html_sha256"], post_validation_mutation,
        )

    def test_public_approved_wrapper_constructor_cannot_bypass_record_validation(self) -> None:
        from community_os.partner_semantic_projection import (
            build_partner_semantic_summary,
        )
        from community_os.semantic_release_approval import ApprovedSemanticRelease

        candidate = _candidate()
        forged_record = {"bindings": candidate.approval_bindings()}
        forged_hash = hashlib.sha256(json.dumps(
            forged_record, ensure_ascii=True, sort_keys=True,
            separators=(",", ":"), allow_nan=False,
        ).encode("utf-8")).hexdigest()
        forged = ApprovedSemanticRelease(
            candidate=candidate,
            approval=forged_record,
            sha256=forged_hash,
            version="forged",
            actor_type="service",
        )
        with self.assertRaisesRegex(PermissionError, "approval record"):
            build_partner_semantic_summary(
                forged, now=NOW, approval_secret=APPROVAL_SECRET,
            )

    def test_loader_rejects_duplicate_nonfinite_and_symlinked_approval(self) -> None:
        from community_os.semantic_release_approval import (
            SemanticReleaseApprovalError,
            load_semantic_release_approval,
        )

        candidate = _candidate()
        record = _approval_record(candidate)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            approval_path = root / "approval.json"
            duplicate = json.dumps(record)[:-1] + ',"version":"semantic-release-approval-v3"}'
            approval_path.write_text(duplicate, encoding="utf-8")
            with self.assertRaisesRegex(SemanticReleaseApprovalError, "duplicate"):
                load_semantic_release_approval(
                    approval_path, candidate=candidate, now=NOW,
                    signing_secret=APPROVAL_SECRET,
                )

            nonfinite = deepcopy(record)
            population = nonfinite["bindings"]["population"]
            assert isinstance(population, dict)
            population["unknown_count"] = float("nan")
            approval_path.write_text(json.dumps(nonfinite), encoding="utf-8")
            with self.assertRaisesRegex(SemanticReleaseApprovalError, "non-finite"):
                load_semantic_release_approval(
                    approval_path, candidate=candidate, now=NOW,
                    signing_secret=APPROVAL_SECRET,
                )

            target = root / "real-approval.json"
            target.write_text(json.dumps(record), encoding="utf-8")
            symlink = root / "approval-link.json"
            symlink.symlink_to(target)
            with self.assertRaisesRegex(SemanticReleaseApprovalError, "unsafe"):
                load_semantic_release_approval(
                    symlink, candidate=candidate, now=NOW,
                    signing_secret=APPROVAL_SECRET,
                )

    def test_loader_derives_candidate_only_from_approval_bound_hashes(self) -> None:
        from community_os.semantic_release_approval import (
            load_approved_semantic_release,
        )

        aggregate = _internal_aggregate()
        candidate = _candidate(aggregate)
        record = _approval_record(candidate)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            aggregate_path = root / "aggregate.json"
            approval_path = root / "approval.json"
            aggregate_path.write_text(json.dumps(aggregate), encoding="utf-8")
            approval_path.write_text(json.dumps(record), encoding="utf-8")

            approved = load_approved_semantic_release(
                aggregate_path, approval_path, now=NOW,
                signing_secret=APPROVAL_SECRET,
            )
            self.assertEqual(approved.sha256, hashlib.sha256(json.dumps(
                record, ensure_ascii=True, sort_keys=True,
                separators=(",", ":"), allow_nan=False,
            ).encode("utf-8")).hexdigest())

            tampered = deepcopy(aggregate)
            tampered["metrics"]["primary_execution"] = 23
            aggregate_path.write_text(json.dumps(tampered), encoding="utf-8")
            with self.assertRaisesRegex(
                PermissionError, "binding does not match",
            ):
                load_approved_semantic_release(
                    aggregate_path, approval_path, now=NOW,
                    signing_secret=APPROVAL_SECRET,
                )


if __name__ == "__main__":
    unittest.main()
