from __future__ import annotations

from hashlib import sha256
import json
import unittest

from community_os.enrichment.semantic_taxonomy import (
    BUILDER_TIER_DERIVATION_VERSION,
    MAX_EVIDENCE_REFS_PER_DIMENSION,
    SemanticTaxonomyFact,
    TAXONOMY_SHA256,
    TAXONOMY_VERSION,
    build_semantic_taxonomy_fact,
    derive_builder_tier,
    empty_semantic_taxonomy,
    semantic_taxonomy_contract,
    semantic_taxonomy_claim_keys,
    validate_semantic_taxonomy_fact,
)


PROJECT_FIELDS = (
    "product_maturity",
    "technical_depth",
    "execution_scope",
    "external_validation",
    "problem_differentiation",
    "market_domains",
    "technical_methods",
    "demonstrated_capabilities",
)
CAREER_FIELDS = (
    "career_stage",
    "founder_state",
    "leadership_state",
    "career_functions",
    "career_delivery",
)


def unknown_project() -> dict[str, object]:
    return {
        "product_maturity": "unknown",
        "technical_depth": "unknown",
        "execution_scope": "unknown",
        "external_validation": "unknown",
        "problem_differentiation": "unknown",
        "market_domains": [],
        "technical_methods": [],
        "demonstrated_capabilities": [],
    }


def unknown_career() -> dict[str, object]:
    return {
        "career_stage": "unknown",
        "founder_state": "unknown",
        "leadership_state": "unknown",
        "career_functions": [],
        "career_delivery": [],
    }


def empty_evidence() -> dict[str, list[str]]:
    return {field: [] for field in (*PROJECT_FIELDS, *CAREER_FIELDS)}


def substantial_project() -> dict[str, object]:
    return {
        "product_maturity": "working_product",
        "technical_depth": "advanced",
        "execution_scope": "primary_builder",
        "external_validation": "meaningful",
        "problem_differentiation": "differentiated",
        "market_domains": ["education_learning"],
        "technical_methods": ["applied_ai_ml", "web_full_stack"],
        "demonstrated_capabilities": [
            "backend_engineering",
            "product_engineering",
        ],
    }


def substantial_project_evidence() -> dict[str, list[str]]:
    result = empty_evidence()
    result.update({
        "product_maturity": ["project_01:deployment"],
        "technical_depth": ["project_01:readme"],
        "execution_scope": ["project_01:ownership"],
        "external_validation": ["application_01:achievement"],
        "problem_differentiation": ["devpost_01:project"],
        "market_domains": ["project_01:description"],
        "technical_methods": ["project_01:readme"],
        "demonstrated_capabilities": ["project_01:readme"],
    })
    return result


def career_context() -> dict[str, object]:
    return {
        "career_stage": "senior",
        "founder_state": "current_founder",
        "leadership_state": "organizational_leader",
        "career_functions": ["product", "software_engineering"],
        "career_delivery": ["founded_venture", "led_teams", "shipped_products"],
    }


def career_evidence() -> dict[str, list[str]]:
    result = empty_evidence()
    result.update({
        "career_stage": ["role_01:title"],
        "founder_state": ["role_01:title"],
        "leadership_state": ["role_01:description"],
        "career_functions": ["application_01:experience", "role_01:title"],
        "career_delivery": ["application_01:achievement", "role_01:description"],
    })
    return result


class SemanticTaxonomyContractTests(unittest.TestCase):
    def test_empty_taxonomy_is_a_valid_insufficient_fact(self) -> None:
        taxonomy = empty_semantic_taxonomy()

        fact = validate_semantic_taxonomy_fact(taxonomy)

        self.assertEqual(fact.builder_tier, "insufficient")
        self.assertEqual(fact.project, unknown_project())
        self.assertEqual(fact.career, unknown_career())
        self.assertEqual(fact.evidence_by_dimension, empty_evidence())
        self.assertEqual(semantic_taxonomy_claim_keys(taxonomy), ())

    def test_claim_keys_cover_each_supported_controlled_value(self) -> None:
        evidence_by_dimension = substantial_project_evidence()
        career_refs = career_evidence()
        evidence_by_dimension.update({
            field: career_refs[field] for field in CAREER_FIELDS
        })
        taxonomy = {
            "version": TAXONOMY_VERSION,
            "project": substantial_project(),
            "career": career_context(),
            "evidence_by_dimension": evidence_by_dimension,
        }

        claims = semantic_taxonomy_claim_keys(taxonomy)

        self.assertIn("technical_depth:advanced", claims)
        self.assertIn("technical_methods:applied_ai_ml", claims)
        self.assertIn("career_stage:senior", claims)
        self.assertIn("career_delivery:led_teams", claims)
        self.assertNotIn("external_validation:none_observed", claims)

    def test_contract_exports_canonical_version_and_hash(self) -> None:
        contract = semantic_taxonomy_contract()
        canonical = json.dumps(
            contract,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")

        self.assertEqual(contract["version"], TAXONOMY_VERSION)
        self.assertEqual(TAXONOMY_VERSION, "semantic-taxonomy-v1")
        self.assertEqual(BUILDER_TIER_DERIVATION_VERSION, "builder-tier-v2")
        self.assertEqual(TAXONOMY_SHA256, sha256(canonical).hexdigest())
        self.assertEqual(
            contract["builder_tier_derivation"]["input_dimensions"],
            list(PROJECT_FIELDS[:5]),
        )
        self.assertNotIn(
            "career_stage",
            contract["builder_tier_derivation"]["input_dimensions"],
        )

    def test_prototype_never_derives_a_substantial_builder_tier(self) -> None:
        project = substantial_project()
        project["product_maturity"] = "prototype"

        self.assertEqual(derive_builder_tier(project), "exploratory")

    def test_builds_exact_semantic_fact_and_derives_builder_tier(self) -> None:
        fact = build_semantic_taxonomy_fact(
            project=substantial_project(),
            career=unknown_career(),
            evidence_by_dimension=substantial_project_evidence(),
        )

        self.assertEqual(fact.project, substantial_project())
        self.assertEqual(fact.career, unknown_career())
        self.assertEqual(fact.builder_tier, "standout")
        self.assertEqual(
            set(fact.to_record()),
            {"version", "project", "career", "evidence_by_dimension", "builder_tier"},
        )
        self.assertEqual(fact.sha256, sha256(fact.canonical_bytes()).hexdigest())

    def test_validator_never_accepts_builder_tier_as_model_claim(self) -> None:
        raw = {
            "version": TAXONOMY_VERSION,
            "project": {**unknown_project(), "builder_tier": "standout"},
            "career": unknown_career(),
            "evidence_by_dimension": empty_evidence(),
        }
        with self.assertRaises(ValueError):
            validate_semantic_taxonomy_fact(raw)

    def test_fact_type_cannot_be_constructed_with_a_caller_claimed_tier(self) -> None:
        raw = {
            "version": TAXONOMY_VERSION,
            "project": unknown_project(),
            "career": unknown_career(),
            "evidence_by_dimension": empty_evidence(),
        }
        canonical = json.dumps(
            raw,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )

        with self.assertRaises(TypeError):
            SemanticTaxonomyFact(canonical, builder_tier="standout")

        raw["project"] = unknown_project()
        raw["builder_tier"] = "standout"
        with self.assertRaises(ValueError):
            validate_semantic_taxonomy_fact(raw)

    def test_generic_words_cannot_directly_create_semantic_categories(self) -> None:
        for field, generic_word in (
            ("market_domains", "care"),
            ("technical_methods", "model"),
            ("demonstrated_capabilities", "automation"),
        ):
            project = unknown_project()
            project[field] = [generic_word]
            evidence = empty_evidence()
            evidence[field] = ["project_01:description"]
            with self.subTest(field=field, generic_word=generic_word):
                with self.assertRaises(ValueError):
                    build_semantic_taxonomy_fact(
                        project=project,
                        career=unknown_career(),
                        evidence_by_dimension=evidence,
                    )

        career = unknown_career()
        career["career_stage"] = "student"
        evidence = empty_evidence()
        evidence["career_stage"] = ["application_01:experience"]
        with self.assertRaises(ValueError):
            build_semantic_taxonomy_fact(
                project=unknown_project(),
                career=career,
                evidence_by_dimension=evidence,
            )

        with self.assertRaises(ValueError):
            build_semantic_taxonomy_fact(
                project={**unknown_project(), "source_text": "care student model automation"},
                career=unknown_career(),
                evidence_by_dimension=empty_evidence(),
            )

    def test_career_only_changes_do_not_change_project_builder_tier(self) -> None:
        baseline = build_semantic_taxonomy_fact(
            project=substantial_project(),
            career=unknown_career(),
            evidence_by_dimension=substantial_project_evidence(),
        )
        enriched_refs = substantial_project_evidence()
        complete_career_evidence = career_evidence()
        enriched_refs.update({
            field: complete_career_evidence[field]
            for field in CAREER_FIELDS
        })
        enriched = build_semantic_taxonomy_fact(
            project=substantial_project(),
            career=career_context(),
            evidence_by_dimension=enriched_refs,
        )

        self.assertEqual(baseline.builder_tier, enriched.builder_tier)
        self.assertEqual(
            derive_builder_tier(baseline.project),
            derive_builder_tier(enriched.project),
        )
        self.assertEqual(baseline.project, enriched.project)

    def test_project_dimensions_reject_role_evidence(self) -> None:
        evidence = substantial_project_evidence()
        evidence["technical_depth"] = ["role_01:description"]

        with self.assertRaises(ValueError):
            build_semantic_taxonomy_fact(
                project=substantial_project(),
                career=unknown_career(),
                evidence_by_dimension=evidence,
            )

    def test_career_dimensions_accept_only_role_or_application_evidence(self) -> None:
        evidence = career_evidence()
        for disallowed_ref in ("project_01:description", "devpost_01:project"):
            evidence["career_stage"] = [disallowed_ref]
            with self.subTest(disallowed_ref=disallowed_ref):
                with self.assertRaises(ValueError):
                    build_semantic_taxonomy_fact(
                        project=unknown_project(),
                        career=career_context(),
                        evidence_by_dimension=evidence,
                    )

        evidence["career_stage"] = ["application_01:experience"]
        fact = build_semantic_taxonomy_fact(
            project=unknown_project(),
            career=career_context(),
            evidence_by_dimension=evidence,
        )
        self.assertEqual(
            fact.evidence_by_dimension["career_stage"],
            ["application_01:experience"],
        )

    def test_evidence_suffix_must_exist_for_its_source_type(self) -> None:
        cases = (
            ("technical_depth", "project_01:title"),
            ("technical_depth", "application_01:readme"),
            ("technical_depth", "devpost_01:release"),
            ("career_stage", "role_01:deployment"),
        )
        for field, impossible_ref in cases:
            project = unknown_project()
            career = unknown_career()
            evidence = empty_evidence()
            if field in PROJECT_FIELDS:
                project[field] = "advanced"
            else:
                career[field] = "senior"
            evidence[field] = [impossible_ref]
            with self.subTest(field=field, impossible_ref=impossible_ref):
                with self.assertRaises(ValueError):
                    build_semantic_taxonomy_fact(
                        project=project,
                        career=career,
                        evidence_by_dimension=evidence,
                    )

    def test_non_unknown_values_require_field_specific_evidence(self) -> None:
        evidence = substantial_project_evidence()
        evidence["external_validation"] = []

        with self.assertRaises(ValueError):
            build_semantic_taxonomy_fact(
                project=substantial_project(),
                career=unknown_career(),
                evidence_by_dimension=evidence,
            )

    def test_explicit_negative_states_allow_zero_refs_without_raising_tier(self) -> None:
        project = unknown_project()
        project["external_validation"] = "none_observed"
        career = unknown_career()
        career["founder_state"] = "no_founder_evidence"

        fact = build_semantic_taxonomy_fact(
            project=project,
            career=career,
            evidence_by_dimension=empty_evidence(),
        )

        self.assertEqual(fact.builder_tier, "insufficient")
        self.assertEqual(
            semantic_taxonomy_contract()["evidence"]["unreferenced_negative_values"],
            {
                "external_validation": "none_observed",
                "founder_state": "no_founder_evidence",
            },
        )

    def test_positive_external_validation_still_requires_field_specific_refs(self) -> None:
        project = unknown_project()
        project["external_validation"] = "early_signal"

        with self.assertRaises(ValueError):
            build_semantic_taxonomy_fact(
                project=project,
                career=unknown_career(),
                evidence_by_dimension=empty_evidence(),
            )

    def test_unknown_and_empty_values_forbid_evidence(self) -> None:
        for field in PROJECT_FIELDS:
            evidence = empty_evidence()
            evidence[field] = ["application_01:experience"]
            with self.subTest(field=field):
                with self.assertRaises(ValueError):
                    build_semantic_taxonomy_fact(
                        project=unknown_project(),
                        career=unknown_career(),
                        evidence_by_dimension=evidence,
                    )

    def test_evidence_map_has_exact_keys_sorted_unique_refs_and_a_bound(self) -> None:
        bad_maps: list[dict[str, list[str]]] = []
        missing = empty_evidence()
        del missing["technical_depth"]
        bad_maps.append(missing)
        extra = empty_evidence()
        extra["summary"] = []
        bad_maps.append(extra)
        duplicate = empty_evidence()
        duplicate["technical_depth"] = ["project_01:readme", "project_01:readme"]
        bad_maps.append(duplicate)
        unsorted = empty_evidence()
        unsorted["technical_depth"] = [
            "project_02:readme",
            "project_01:readme",
        ]
        bad_maps.append(unsorted)
        excessive = empty_evidence()
        excessive["technical_depth"] = [
            f"project_{index:02d}:readme"
            for index in range(1, MAX_EVIDENCE_REFS_PER_DIMENSION + 2)
        ]
        bad_maps.append(excessive)

        project = unknown_project()
        project["technical_depth"] = "advanced"
        for evidence in bad_maps:
            with self.subTest(evidence=evidence):
                with self.assertRaises(ValueError):
                    build_semantic_taxonomy_fact(
                        project=project,
                        career=unknown_career(),
                        evidence_by_dimension=evidence,
                    )

    def test_controlled_lists_are_sorted_unique_and_bounded(self) -> None:
        for values in (
            ["web_full_stack", "applied_ai_ml"],
            ["applied_ai_ml", "applied_ai_ml"],
            [
                "applied_ai_ml",
                "automation_orchestration",
                "blockchain_web3",
                "cloud_infrastructure",
                "computer_vision",
                "cybersecurity",
                "data_engineering",
                "distributed_systems",
                "hardware_iot",
            ],
        ):
            project = unknown_project()
            project["technical_methods"] = values
            evidence = empty_evidence()
            evidence["technical_methods"] = ["project_01:readme"]
            with self.subTest(values=values):
                with self.assertRaises(ValueError):
                    build_semantic_taxonomy_fact(
                        project=project,
                        career=unknown_career(),
                        evidence_by_dimension=evidence,
                    )

    def test_exact_keys_forbid_prose_fields(self) -> None:
        invalid_project = {**unknown_project(), "project_summary": "A good product."}
        invalid_career = {**unknown_career(), "career_summary": "A senior founder."}
        for project, career in (
            (invalid_project, unknown_career()),
            (unknown_project(), invalid_career),
        ):
            with self.subTest(project=project, career=career):
                with self.assertRaises(ValueError):
                    build_semantic_taxonomy_fact(
                        project=project,
                        career=career,
                        evidence_by_dimension=empty_evidence(),
                    )

    def test_fact_serialization_is_canonical_across_mapping_order(self) -> None:
        first = build_semantic_taxonomy_fact(
            project=substantial_project(),
            career=unknown_career(),
            evidence_by_dimension=substantial_project_evidence(),
        )
        raw = {
            "evidence_by_dimension": dict(
                reversed(list(substantial_project_evidence().items()))
            ),
            "career": dict(reversed(list(unknown_career().items()))),
            "project": dict(reversed(list(substantial_project().items()))),
            "version": TAXONOMY_VERSION,
        }
        second = validate_semantic_taxonomy_fact(raw)

        self.assertEqual(first.canonical_bytes(), second.canonical_bytes())
        self.assertEqual(first.sha256, second.sha256)


if __name__ == "__main__":
    unittest.main()
