"""Protected, hash-bound model evaluation for rich semantic assessments."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import tempfile

from community_os.enrichment.openai_rich_semantic_assessment import (
    OpenAIRichSemanticAssessmentProvider,
    RICH_SEMANTIC_MAX_OUTPUT_TOKENS,
    RICH_SEMANTIC_MAX_REQUEST_BYTES,
    RetryableRichSemanticOutputError,
    rich_semantic_schema_sha256,
)
from community_os.enrichment.rich_semantic_assessment import (
    ASSESSMENT_ENUMS,
    MODEL_ALLOWLIST,
    PROMPT_VERSION,
    SEMANTIC_NORMALIZATION_CODES,
    SEMANTIC_NORMALIZATION_VERSION,
    REASON_CODES,
    REASONING_ALLOWLIST,
    validate_profile_evidence,
    validate_rich_semantic_assessment,
)
from community_os.enrichment.semantic_taxonomy import (
    ALL_DIMENSIONS,
    CAREER_FIELDS,
    PROJECT_FIELDS,
    TAXONOMY_SHA256,
    TAXONOMY_VERSION,
    validate_semantic_taxonomy_fact,
)
from community_os.enrichment.transport import RetryableTransportError
from community_os.semantic_metrics import (
    matching_metric_keys,
    metric_registry_sha256,
    partner_report_taxonomy_claim_keys,
    partner_report_taxonomy_schema_sha256,
)


_HASH = re.compile(r"^[0-9a-f]{64}$")
_CASE = re.compile(r"^case:v1:[0-9a-f]{64}$")
_ENDPOINTS = frozenset({
    "https://api.openai.com/v1/responses",
    "https://eu.api.openai.com/v1/responses",
})
_LABEL_FIELDS = frozenset({
    "builder_level", "cross_source_confidence", "reason_codes",
    "semantic_taxonomy", "source_families_by_dimension",
})
_LABEL_TAXONOMY_FIELDS = frozenset({"career", "project"})
_LABEL_FIELD_ORDER = (
    "builder_level",
    "cross_source_confidence",
    "reason_codes",
    *(f"project.{field}" for field in PROJECT_FIELDS),
    *(f"career.{field}" for field in CAREER_FIELDS),
    *(f"sources.{field}" for field in ALL_DIMENSIONS),
)
_REPORT_SCALAR_FIELDS = (
    "builder_level",
    "project.product_maturity",
    "project.technical_depth",
    "project.execution_scope",
    "project.external_validation",
    "project.problem_differentiation",
)
_RECOMMENDATION_POLICY_VERSION = "rich-semantic-proposal-quality-gate-v4"
_REPORT_VERSION = "rich-semantic-evaluation-report-v9"
_EVALUATION_SCHEMA_VERSION = "rich-semantic-evaluation-schema-v5"
_CONSERVATIVE_FLOOR_ALLOWANCE_BASIS_POINTS = 1_000
_SOURCE_FAMILIES = frozenset({"application", "career", "devpost", "projects"})
_SOURCE_PREFIX_TO_FAMILY = {
    "application": "application",
    "devpost": "devpost",
    "project": "projects",
    "role": "career",
}
_FAILED_ATTEMPT_CODES = frozenset({
    "output_token_limit", "semantic_output_invalid",
    "semantic_output_invalid_json", "semantic_output_invalid_normalization",
    "semantic_output_invalid_validation",
})
_SAMPLE_FIELDS = frozenset({"case_ref", "evidence", "label"})
_MODEL_FIELDS = frozenset({
    "endpoint", "input_cost_per_million_usd_micros", "model",
    "max_output_tokens", "max_request_bytes",
    "model_version", "normalization_version",
    "output_cost_per_million_usd_micros",
    "reasoning_effort", "store",
})
_APPROVAL_FIELDS = frozenset({
    "agreement_threshold_basis_points", "approval_id", "approved_at",
    "approved_by", "case_refs_sha256", "distribution",
    "evaluation_version", "expires_at", "labels_sha256",
    "max_attempts_per_case", "max_provider_attempts", "models",
    "prompt_version", "retention_days", "sample_sha256", "schema_sha256",
    "source_scope",
})


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _token_cost(tokens: int, rate: int) -> int:
    numerator = tokens * rate
    return (numerator + 999_999) // 1_000_000


def recommendation_policy_sha256() -> str:
    """Return the deterministic identity of the local model-selection policy."""

    return _sha256({
        "agreement_threshold_source": "approval.agreement_threshold_basis_points",
        "diagnostic_only_fields": [
            "cross_source_confidence", "reason_codes",
            "source_families_by_dimension", "joint_agreement_basis_points",
            "impressive_false_positive_count",
            "partner_metric_false_positive_count",
            "partner_taxonomy_false_positive_count",
        ],
        "hard_requirements": [
            "full_mandatory_human_review_coverage",
            "nonzero_partner_metric_gold_positive_support",
            "nonzero_partner_taxonomy_gold_positive_support",
            "impressive_gold_positive_and_negative_class_support",
            "impressive_agreement_at_threshold",
            "report_scalar_macro_at_threshold",
            "report_scalar_minimum_at_threshold_minus_1000_basis_points",
            "partner_metric_precision_at_threshold",
            "partner_metric_recall_at_threshold",
            "partner_taxonomy_precision_at_threshold",
            "partner_taxonomy_recall_at_threshold_minus_1000_basis_points",
            "zero_provider_failures",
        ],
        "metric_registry_sha256": metric_registry_sha256(),
        "partner_report_taxonomy_schema_sha256": (
            partner_report_taxonomy_schema_sha256()
        ),
        "policy_version": _RECOMMENDATION_POLICY_VERSION,
        "ranking": "quality_then_expected_human_escalation_then_cost",
        "review_contract": (
            "all_model_outputs_are_proposals_and_must_be_human_reviewed_"
            "before_any_positive_highlight_can_release"
        ),
        "support_contract": (
            "undefined_precision_recall_and_one_class_agreement_are_"
            "diagnostic_only_and_never_support_recommendation"
        ),
        "weakest_scalar_and_taxonomy_recall_allowance_basis_points": (
            _CONSERVATIVE_FLOOR_ALLOWANCE_BASIS_POINTS
        ),
        "report_scalar_fields": list(_REPORT_SCALAR_FIELDS),
        "report_version": _REPORT_VERSION,
    })


def _is_impressive(builder_level: object, product_maturity: object) -> bool:
    return (
        builder_level in {"substantial", "standout"}
        and product_maturity in {"working_product", "production_evidence"}
    )


def _predicted_gold_label(assessment: Mapping[str, object]) -> dict[str, object]:
    taxonomy = assessment["semantic_taxonomy"]
    source_families = {
        dimension: sorted({
            _SOURCE_PREFIX_TO_FAMILY[str(reference).split("_", 1)[0]]
            for reference in taxonomy["evidence_by_dimension"][dimension]
        })
        for dimension in ALL_DIMENSIONS
    }
    return {
        "builder_level": assessment["builder_level"],
        "cross_source_confidence": assessment["cross_source_confidence"],
        "reason_codes": sorted(assessment["reason_codes"]),
        "semantic_taxonomy": {
            "project": dict(taxonomy["project"]),
            "career": dict(taxonomy["career"]),
        },
        "source_families_by_dimension": source_families,
    }


def _flatten_label(label: Mapping[str, object]) -> dict[str, object]:
    taxonomy = label["semantic_taxonomy"]
    project = taxonomy["project"]
    career = taxonomy["career"]
    sources = label["source_families_by_dimension"]
    return {
        "builder_level": label["builder_level"],
        "cross_source_confidence": label["cross_source_confidence"],
        "reason_codes": list(label["reason_codes"]),
        **{f"project.{field}": project[field] for field in PROJECT_FIELDS},
        **{f"career.{field}": career[field] for field in CAREER_FIELDS},
        **{f"sources.{field}": sources[field] for field in ALL_DIMENSIONS},
    }


def _gold_field_matches(
    expected: Mapping[str, object], predicted: Mapping[str, object],
) -> dict[str, bool]:
    expected_fields = _flatten_label(expected)
    predicted_fields = _flatten_label(predicted)
    return {
        field: predicted_fields[field] == expected_fields[field]
        for field in _LABEL_FIELD_ORDER
    }


def _partner_metric_keys(label: Mapping[str, object]) -> frozenset[str]:
    project = label["semantic_taxonomy"]["project"]
    return frozenset(matching_metric_keys({
        "builder_level": label["builder_level"],
        "execution_scope": project["execution_scope"],
        "external_validation": (
            "none"
            if project["external_validation"] == "none_observed"
            else project["external_validation"]
        ),
        "originality": project["problem_differentiation"],
        "product_maturity": project["product_maturity"],
        "technical_depth": project["technical_depth"],
    }))


def _partner_taxonomy_keys(label: Mapping[str, object]) -> frozenset[str]:
    return frozenset(
        partner_report_taxonomy_claim_keys(label["semantic_taxonomy"])
    )


def _score_model_results(
    *, sample: Sequence[Mapping[str, object]],
    results: Sequence[Mapping[str, object]],
    failed_attempts: Sequence[Mapping[str, object]],
    failed_attempt_count: int, model: str, model_version: str,
) -> dict[str, object]:
    if len(results) != len(sample) or failed_attempt_count < 0:
        raise PermissionError("rich semantic evaluation results are incomplete")
    field_matches = {field: 0 for field in _LABEL_FIELD_ORDER}
    disagreements: list[dict[str, object]] = []
    impressive_matches = 0
    impressive_expected_positives = 0
    impressive_expected_negatives = 0
    impressive_false_positives = 0
    impressive_false_negatives = 0
    partner_metric_false_positives = 0
    partner_metric_false_negatives = 0
    partner_metric_expected_positives = 0
    partner_metric_predicted_positives = 0
    partner_metric_true_positives = 0
    partner_metric_error_cases = 0
    partner_taxonomy_expected_positives = 0
    partner_taxonomy_predicted_positives = 0
    partner_taxonomy_true_positives = 0
    partner_taxonomy_false_positives = 0
    partner_taxonomy_false_negatives = 0
    partner_taxonomy_error_cases = 0
    material_public_error_cases = 0
    correction_cases = 0
    expected_human_escalation_cases = 0
    mandatory_review_cases = 0
    input_tokens = sum(int(item["input_tokens"]) for item in failed_attempts)
    output_tokens = sum(int(item["output_tokens"]) for item in failed_attempts)
    cost = sum(int(item["cost_usd_micros"]) for item in failed_attempts)
    for sample_case, result in zip(sample, results, strict=True):
        assessment = result["assessment"]
        if assessment.get("review_state") != "human_review_required":
            raise PermissionError(
                "rich semantic evaluation result requires human review"
            )
        mandatory_review_cases += 1
        expected = sample_case["label"]
        predicted = _predicted_gold_label(assessment)
        matches = _gold_field_matches(expected, predicted)
        for field, matched in matches.items():
            field_matches[field] += int(matched)
        expected_project = expected["semantic_taxonomy"]["project"]
        predicted_project = predicted["semantic_taxonomy"]["project"]
        expected_impressive = _is_impressive(
            expected["builder_level"], expected_project["product_maturity"],
        )
        predicted_impressive = _is_impressive(
            predicted["builder_level"], predicted_project["product_maturity"],
        )
        impressive_expected_positives += int(expected_impressive)
        impressive_expected_negatives += int(not expected_impressive)
        impressive_matches += int(expected_impressive == predicted_impressive)
        impressive_false_positives += int(
            predicted_impressive and not expected_impressive
        )
        impressive_false_negatives += int(
            expected_impressive and not predicted_impressive
        )
        expected_metric_keys = _partner_metric_keys(expected)
        predicted_metric_keys = _partner_metric_keys(predicted)
        expected_taxonomy_keys = _partner_taxonomy_keys(expected)
        predicted_taxonomy_keys = _partner_taxonomy_keys(predicted)
        partner_metric_expected_positives += len(expected_metric_keys)
        partner_metric_predicted_positives += len(predicted_metric_keys)
        partner_metric_true_positives += len(
            expected_metric_keys & predicted_metric_keys
        )
        partner_metric_error_cases += int(
            expected_metric_keys != predicted_metric_keys
        )
        partner_metric_false_positives += len(
            predicted_metric_keys - expected_metric_keys
        )
        partner_metric_false_negatives += len(
            expected_metric_keys - predicted_metric_keys
        )
        partner_taxonomy_expected_positives += len(expected_taxonomy_keys)
        partner_taxonomy_predicted_positives += len(predicted_taxonomy_keys)
        partner_taxonomy_true_positives += len(
            expected_taxonomy_keys & predicted_taxonomy_keys
        )
        partner_taxonomy_false_positives += len(
            predicted_taxonomy_keys - expected_taxonomy_keys
        )
        partner_taxonomy_false_negatives += len(
            expected_taxonomy_keys - predicted_taxonomy_keys
        )
        partner_taxonomy_error_cases += int(
            expected_taxonomy_keys != predicted_taxonomy_keys
        )
        material_public_error = (
            expected_impressive != predicted_impressive
            or any(not matches[field] for field in _REPORT_SCALAR_FIELDS)
            or expected_metric_keys != predicted_metric_keys
            or expected_taxonomy_keys != predicted_taxonomy_keys
        )
        correction_required = not all(matches.values())
        expected_human_escalation = (
            correction_required
            or predicted["cross_source_confidence"] == "low"
        )
        material_public_error_cases += int(material_public_error)
        correction_cases += int(correction_required)
        expected_human_escalation_cases += int(expected_human_escalation)
        input_tokens += int(result["input_tokens"])
        output_tokens += int(result["output_tokens"])
        cost += int(result["cost_usd_micros"])
        if correction_required:
            disagreements.append({
                "case_ref": sample_case["case_ref"],
                "expected_label": dict(expected),
                "field_matches": matches,
                "predicted_label": predicted,
            })
    denominator = len(sample)
    field_agreement = {
        field: count * 10_000 // denominator
        for field, count in field_matches.items()
    }
    report_scalar_agreements = [
        field_agreement[field] for field in _REPORT_SCALAR_FIELDS
    ]
    partner_metric_precision = (
        10_000
        if partner_metric_predicted_positives == 0
        else partner_metric_true_positives * 10_000
        // partner_metric_predicted_positives
    )
    partner_metric_recall = (
        10_000
        if partner_metric_expected_positives == 0
        else partner_metric_true_positives * 10_000
        // partner_metric_expected_positives
    )
    partner_taxonomy_precision = (
        10_000
        if partner_taxonomy_predicted_positives == 0
        else partner_taxonomy_true_positives * 10_000
        // partner_taxonomy_predicted_positives
    )
    partner_taxonomy_recall = (
        10_000
        if partner_taxonomy_expected_positives == 0
        else partner_taxonomy_true_positives * 10_000
        // partner_taxonomy_expected_positives
    )
    return {
        "builder_agreement_basis_points": field_agreement["builder_level"],
        "correction_case_basis_points": (
            correction_cases * 10_000 // denominator
        ),
        "correction_case_count": correction_cases,
        "cost_usd_micros": cost,
        "disagreements": disagreements,
        "evaluation_case_count": denominator,
        "failed_attempt_count": failed_attempt_count,
        "field_agreement_basis_points": field_agreement,
        "input_tokens": input_tokens,
        "impressive_agreement_basis_points": (
            impressive_matches * 10_000 // denominator
        ),
        "impressive_expected_negative_count": impressive_expected_negatives,
        "impressive_expected_positive_count": impressive_expected_positives,
        "impressive_false_negative_count": impressive_false_negatives,
        "impressive_false_positive_count": impressive_false_positives,
        "joint_agreement_basis_points": (
            (denominator - len(disagreements)) * 10_000 // denominator
        ),
        "expected_human_escalation_case_basis_points": (
            expected_human_escalation_cases * 10_000 // denominator
        ),
        "expected_human_escalation_case_count": (
            expected_human_escalation_cases
        ),
        "mandatory_review_case_count": mandatory_review_cases,
        "mandatory_review_coverage_basis_points": (
            mandatory_review_cases * 10_000 // denominator
        ),
        "material_public_error_case_basis_points": (
            material_public_error_cases * 10_000 // denominator
        ),
        "material_public_error_case_count": material_public_error_cases,
        "maturity_agreement_basis_points": field_agreement[
            "project.product_maturity"
        ],
        "model": model,
        "model_version": model_version,
        "output_tokens": output_tokens,
        "partner_metric_false_negative_count": partner_metric_false_negatives,
        "partner_metric_false_positive_count": partner_metric_false_positives,
        "partner_metric_error_case_basis_points": (
            partner_metric_error_cases * 10_000 // denominator
        ),
        "partner_metric_error_case_count": partner_metric_error_cases,
        "partner_metric_expected_positive_count": (
            partner_metric_expected_positives
        ),
        "partner_metric_precision_basis_points": partner_metric_precision,
        "partner_metric_predicted_positive_count": (
            partner_metric_predicted_positives
        ),
        "partner_metric_recall_basis_points": partner_metric_recall,
        "partner_metric_true_positive_count": partner_metric_true_positives,
        "partner_taxonomy_error_case_basis_points": (
            partner_taxonomy_error_cases * 10_000 // denominator
        ),
        "partner_taxonomy_error_case_count": partner_taxonomy_error_cases,
        "partner_taxonomy_expected_positive_count": (
            partner_taxonomy_expected_positives
        ),
        "partner_taxonomy_false_negative_count": (
            partner_taxonomy_false_negatives
        ),
        "partner_taxonomy_false_positive_count": (
            partner_taxonomy_false_positives
        ),
        "partner_taxonomy_precision_basis_points": (
            partner_taxonomy_precision
        ),
        "partner_taxonomy_predicted_positive_count": (
            partner_taxonomy_predicted_positives
        ),
        "partner_taxonomy_recall_basis_points": partner_taxonomy_recall,
        "partner_taxonomy_true_positive_count": (
            partner_taxonomy_true_positives
        ),
        "report_scalar_agreement_basis_points": (
            sum(report_scalar_agreements) // len(report_scalar_agreements)
        ),
        "report_scalar_minimum_basis_points": min(
            report_scalar_agreements
        ),
    }


def _select_recommended_model(
    model_reports: Sequence[Mapping[str, object]], *, threshold: int,
) -> tuple[str | None, str]:
    conservative_floor = max(
        0, threshold - _CONSERVATIVE_FLOOR_ALLOWANCE_BASIS_POINTS,
    )
    fully_reviewed = [
        item for item in model_reports
        if item["mandatory_review_coverage_basis_points"] == 10_000
    ]
    taxonomy_supported = [
        item for item in fully_reviewed
        if item["partner_taxonomy_expected_positive_count"] > 0
    ]
    metric_supported = [
        item for item in taxonomy_supported
        if item["partner_metric_expected_positive_count"] > 0
    ]
    impressive_class_supported = [
        item for item in metric_supported
        if item["impressive_expected_positive_count"] > 0
        and item["impressive_expected_negative_count"] > 0
    ]
    impressive_eligible = [
        item for item in metric_supported
        if item["impressive_agreement_basis_points"] >= threshold
    ]
    report_scalar_macro_eligible = [
        item for item in impressive_eligible
        if item["report_scalar_agreement_basis_points"] >= threshold
    ]
    report_scalar_minimum_eligible = [
        item for item in report_scalar_macro_eligible
        if item["report_scalar_minimum_basis_points"] >= conservative_floor
    ]
    partner_precision_eligible = [
        item for item in report_scalar_minimum_eligible
        if item["partner_metric_precision_basis_points"] >= threshold
    ]
    partner_recall_eligible = [
        item for item in partner_precision_eligible
        if item["partner_metric_recall_basis_points"] >= threshold
    ]
    partner_taxonomy_precision_eligible = [
        item for item in partner_recall_eligible
        if item["partner_taxonomy_precision_basis_points"] >= threshold
    ]
    partner_taxonomy_recall_eligible = [
        item for item in partner_taxonomy_precision_eligible
        if item["partner_taxonomy_recall_basis_points"] >= conservative_floor
    ]
    zero_failure_eligible = [
        item for item in partner_taxonomy_recall_eligible
        if item["failed_attempt_count"] == 0
    ]
    diverse_eligible = [
        item for item in zero_failure_eligible
        if item in impressive_class_supported
    ]
    if not diverse_eligible:
        if not fully_reviewed:
            return None, "no_model_met_mandatory_review_coverage"
        if not taxonomy_supported:
            return None, "no_model_met_partner_taxonomy_gold_support_requirement"
        if not metric_supported:
            return None, "no_model_met_partner_metric_gold_support_requirement"
        if not impressive_eligible:
            return None, "no_model_met_impressive_agreement_threshold"
        if not report_scalar_macro_eligible:
            return None, "no_model_met_report_scalar_agreement_threshold"
        if not report_scalar_minimum_eligible:
            return None, "no_model_met_report_scalar_minimum_floor"
        if not partner_precision_eligible:
            return None, "no_model_met_partner_metric_precision_threshold"
        if not partner_recall_eligible:
            return None, "no_model_met_partner_metric_recall_threshold"
        if not partner_taxonomy_precision_eligible:
            return None, "no_model_met_partner_taxonomy_precision_threshold"
        if not partner_taxonomy_recall_eligible:
            return None, "no_model_met_partner_taxonomy_recall_floor"
        if not zero_failure_eligible:
            return None, "no_model_met_zero_failure_requirement"
        return None, "no_model_met_impressive_gold_class_diversity_requirement"

    def rank_key(
        item: Mapping[str, object],
    ) -> tuple[int, int, int, int, int, int, int, int, int]:
        return (
            -int(item["report_scalar_agreement_basis_points"]),
            -int(item["report_scalar_minimum_basis_points"]),
            -int(item["partner_metric_precision_basis_points"]),
            -int(item["partner_metric_recall_basis_points"]),
            -int(item["partner_taxonomy_precision_basis_points"]),
            -int(item["partner_taxonomy_recall_basis_points"]),
            -int(item["impressive_agreement_basis_points"]),
            int(item["expected_human_escalation_case_basis_points"]),
            int(item["cost_usd_micros"]),
        )

    ranked = sorted(
        diverse_eligible,
        key=lambda item: (*rank_key(item), str(item["model"])),
    )
    if len(ranked) > 1 and rank_key(ranked[0]) == rank_key(ranked[1]):
        return None, "models_tied_on_quality_escalation_and_cost"
    return (
        str(ranked[0]["model"]),
        "proposal_quality_thresholds_met_mandatory_human_review_"
        "before_release_ranked_by_quality_then_escalation_then_cost",
    )


def _timestamp(value: object, field: str) -> datetime:
    if not isinstance(value, str):
        raise PermissionError(f"rich semantic evaluation {field} is invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise PermissionError(f"rich semantic evaluation {field} is invalid") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise PermissionError(f"rich semantic evaluation {field} requires a timezone")
    return parsed.astimezone(UTC)


def _utc_timestamp(value: datetime) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("rich semantic evaluation timestamp requires a timezone")
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def evaluation_schema_sha256() -> str:
    """Return the deterministic semantic output-contract identity."""
    return _sha256({
        "evaluation_schema_version": _EVALUATION_SCHEMA_VERSION,
        "flattened_label_fields": list(_LABEL_FIELD_ORDER),
        "label_fields": sorted(_LABEL_FIELDS),
        "metric_registry_sha256": metric_registry_sha256(),
        "provider_schema_sha256": rich_semantic_schema_sha256(),
        "source_families": sorted(_SOURCE_FAMILIES),
        "taxonomy_sha256": TAXONOMY_SHA256,
        "taxonomy_version": TAXONOMY_VERSION,
    })


def _references_by_source_family(
    evidence: Mapping[str, object],
) -> dict[str, list[str]]:
    references = {family: [] for family in _SOURCE_FAMILIES}
    for source in ("projects", "application", "devpost", "career"):
        for item in evidence[source]:
            for reference in item["evidence_refs"]:
                family = _SOURCE_PREFIX_TO_FAMILY[
                    str(reference).split("_", 1)[0]
                ]
                references[family].append(str(reference))
    return {
        family: sorted(set(items))
        for family, items in references.items()
    }


def _normalize_gold_label(
    label: Mapping[str, object], *, evidence: Mapping[str, object],
) -> dict[str, object]:
    taxonomy = label.get("semantic_taxonomy")
    sources = label.get("source_families_by_dimension")
    reasons = label.get("reason_codes")
    confidence = label.get("cross_source_confidence")
    if (
        not isinstance(taxonomy, Mapping)
        or set(taxonomy) != _LABEL_TAXONOMY_FIELDS
        or not isinstance(sources, Mapping)
        or set(sources) != set(ALL_DIMENSIONS)
        or label.get("builder_level") not in ASSESSMENT_ENUMS["builder_level"]
        or confidence not in ASSESSMENT_ENUMS["cross_source_confidence"]
        or not isinstance(reasons, list)
        or not reasons
        or reasons != sorted(set(reasons))
        or any(reason not in REASON_CODES for reason in reasons)
    ):
        raise ValueError("rich semantic evaluation label is outside the rubric")

    references_by_family = _references_by_source_family(evidence)
    dimension_references: dict[str, list[str]] = {}
    normalized_sources: dict[str, list[str]] = {}
    for dimension in ALL_DIMENSIONS:
        families = sources[dimension]
        if (
            not isinstance(families, list)
            or any(not isinstance(family, str) for family in families)
            or families != sorted(set(families))
            or any(family not in _SOURCE_FAMILIES for family in families)
            or any(not references_by_family[family] for family in families)
        ):
            raise ValueError(
                f"rich semantic taxonomy sources for {dimension} are invalid"
            )
        normalized_sources[dimension] = list(families)
        dimension_references[dimension] = sorted(
            references_by_family[family][0] for family in families
        )

    semantic_fact = validate_semantic_taxonomy_fact({
        "version": TAXONOMY_VERSION,
        "project": taxonomy.get("project"),
        "career": taxonomy.get("career"),
        "evidence_by_dimension": dimension_references,
    })
    if semantic_fact.builder_tier != label["builder_level"]:
        raise ValueError("rich semantic gold label is incoherent")

    delivery_references = {
        reference
        for application in evidence["application"]
        for reference in application["evidence_refs"]
        if reference.rsplit(":", 1)[-1] in {"achievement", "experience"}
    }
    if semantic_fact.project["execution_scope"] != "unknown" and (
        "application" not in normalized_sources["execution_scope"]
        or not delivery_references
    ):
        raise ValueError("rich semantic gold label is incoherent")

    all_source_families = {
        family for families in normalized_sources.values() for family in families
    }
    if (
        confidence == "high" and len(all_source_families) < 2
    ) or (
        "corroborated_across_sources" in reasons
        and (confidence != "high" or len(all_source_families) < 2)
    ):
        raise ValueError("rich semantic gold label is incoherent")

    return {
        "builder_level": label["builder_level"],
        "cross_source_confidence": confidence,
        "reason_codes": list(reasons),
        "semantic_taxonomy": {
            "project": semantic_fact.project,
            "career": semantic_fact.career,
        },
        "source_families_by_dimension": normalized_sources,
    }


def _normalize_labeled_sample(value: object) -> list[dict[str, object]]:
    if (
        isinstance(value, (str, bytes)) or not isinstance(value, Sequence)
        or not 1 <= len(value) <= 100
    ):
        raise ValueError("rich semantic labeled sample must contain one to one hundred cases")
    normalized: list[dict[str, object]] = []
    case_refs: list[str] = []
    for item in value:
        if not isinstance(item, dict) or set(item) != _SAMPLE_FIELDS:
            raise ValueError("rich semantic labeled case fields are invalid")
        case_ref = item.get("case_ref")
        label = item.get("label")
        if not isinstance(case_ref, str) or not _CASE.fullmatch(case_ref):
            raise ValueError("rich semantic labeled case must be pseudonymous")
        if not isinstance(label, dict) or set(label) != _LABEL_FIELDS:
            raise ValueError("rich semantic evaluation label fields are invalid")
        normalized_evidence = validate_profile_evidence(item.get("evidence"))
        normalized_label = _normalize_gold_label(
            label, evidence=normalized_evidence,
        )
        normalized.append({
            "case_ref": case_ref,
            "evidence": normalized_evidence,
            "label": normalized_label,
        })
        case_refs.append(case_ref)
    if case_refs != sorted(case_refs) or len(case_refs) != len(set(case_refs)):
        raise ValueError("rich semantic labeled cases must be unique and sorted")
    return normalized


def labeled_sample_hashes(value: object) -> dict[str, str]:
    """Hash the exact cases, labels, and case set independently."""
    sample = _normalize_labeled_sample(value)
    return {
        "sample_sha256": _sha256(sample),
        "case_refs_sha256": _sha256([item["case_ref"] for item in sample]),
        "labels_sha256": _sha256([
            {"case_ref": item["case_ref"], "label": item["label"]}
            for item in sample
        ]),
    }


def _normalize_model_bindings(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list) or not 1 <= len(value) <= 2:
        raise PermissionError("rich semantic evaluation approval models are invalid")
    normalized: list[dict[str, object]] = []
    for item in value:
        if not isinstance(item, dict) or set(item) != _MODEL_FIELDS:
            raise PermissionError("rich semantic evaluation approval model binding is invalid")
        model = item.get("model")
        version = item.get("model_version")
        if (
            model not in MODEL_ALLOWLIST
            or version != model
            or item.get("endpoint") not in _ENDPOINTS
            or item.get("reasoning_effort") not in REASONING_ALLOWLIST
            or item.get("store") is not False
            or item.get("max_output_tokens") != RICH_SEMANTIC_MAX_OUTPUT_TOKENS
            or item.get("max_request_bytes") != RICH_SEMANTIC_MAX_REQUEST_BYTES
            or item.get("normalization_version") != SEMANTIC_NORMALIZATION_VERSION
        ):
            raise PermissionError("rich semantic evaluation approval model posture is invalid")
        for field in (
            "input_cost_per_million_usd_micros",
            "output_cost_per_million_usd_micros",
        ):
            if type(item.get(field)) is not int or item[field] < 0:
                raise PermissionError("rich semantic evaluation approval price binding is invalid")
        normalized.append(dict(item))
    models = [str(item["model"]) for item in normalized]
    if (
        models != sorted(models)
        or len(models) != len(set(models))
        or any(model not in MODEL_ALLOWLIST for model in models)
    ):
        raise PermissionError("rich semantic evaluation approval model set is invalid")
    return normalized


@dataclass(frozen=True)
class RichSemanticEvaluationApproval:
    agreement_threshold_basis_points: int
    approval_id: str
    approved_at: str
    approved_by: str
    case_refs_sha256: str
    distribution: str
    evaluation_version: str
    expires_at: str
    labels_sha256: str
    max_attempts_per_case: int
    max_provider_attempts: int
    models: list[dict[str, object]]
    prompt_version: str
    retention_days: int
    sample_sha256: str
    schema_sha256: str
    source_scope: str

    @classmethod
    def from_record(cls, value: object) -> "RichSemanticEvaluationApproval":
        if not isinstance(value, dict) or set(value) != _APPROVAL_FIELDS:
            raise PermissionError("rich semantic evaluation approval keys are invalid")
        try:
            return cls(**value)
        except TypeError as error:
            raise PermissionError("rich semantic evaluation approval is invalid") from error

    @classmethod
    def load(
        cls, path: str | Path, *, now: datetime,
    ) -> tuple["RichSemanticEvaluationApproval", str]:
        approval_path = Path(path)
        if not approval_path.is_file():
            raise PermissionError("rich semantic evaluation requires a pre-existing approval")
        try:
            raw = json.loads(approval_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise PermissionError("rich semantic evaluation approval is unreadable") from error
        approval = cls.from_record(raw)
        approval.authorize(now=now)
        return approval, _sha256(approval.to_record())

    def to_record(self) -> dict[str, object]:
        return {key: getattr(self, key) for key in sorted(_APPROVAL_FIELDS)}

    def authorize(self, *, now: datetime) -> None:
        if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
            raise PermissionError("rich semantic evaluation authorization time requires a timezone")
        required = {
            "evaluation_version": "rich-semantic-model-evaluation-v5",
            "distribution": "internal_only_pending_human_review",
            "source_scope": "pseudonymous_rich_semantic_labeled_sample",
            "prompt_version": PROMPT_VERSION,
            "schema_sha256": evaluation_schema_sha256(),
            "approved_by": "release_owner",
        }
        if any(getattr(self, key) != expected for key, expected in required.items()):
            raise PermissionError("rich semantic evaluation approval scope is invalid")
        hashes = (self.sample_sha256, self.case_refs_sha256, self.labels_sha256)
        if (
            any(not isinstance(value, str) or not _HASH.fullmatch(value) for value in hashes)
            or not isinstance(self.approval_id, str) or not self.approval_id.strip()
            or type(self.agreement_threshold_basis_points) is not int
            or not 5_000 <= self.agreement_threshold_basis_points <= 10_000
            or type(self.max_attempts_per_case) is not int
            or not 1 <= self.max_attempts_per_case <= 3
            or type(self.max_provider_attempts) is not int
            or not 2 <= self.max_provider_attempts <= 600
            or type(self.retention_days) is not int
            or not 1 <= self.retention_days <= 7
        ):
            raise PermissionError("rich semantic evaluation approval values are invalid")
        _normalize_model_bindings(self.models)
        approved = _timestamp(self.approved_at, "approval timestamp")
        expires = _timestamp(self.expires_at, "approval expiry")
        current = now.astimezone(UTC)
        if approved > current or current >= expires or expires <= approved:
            raise PermissionError("rich semantic evaluation approval is not currently valid")
        if expires - approved > timedelta(days=7):
            raise PermissionError("rich semantic evaluation approval window is too long")

    def model_binding(self, model: str) -> dict[str, object]:
        for binding in _normalize_model_bindings(self.models):
            if binding["model"] == model:
                return binding
        raise PermissionError("rich semantic evaluation model is not approved")


class RetryableEvaluationError(RuntimeError):
    """A bounded provider failure that may consume one approved retry."""


class RichSemanticEvaluationStore:
    """Isolated evaluation state that cannot enter release storage."""

    RECORD_VERSION = "rich-semantic-evaluation-result-v1"
    ATTEMPT_VERSION = "rich-semantic-evaluation-attempt-v1"
    ATTEMPT_STATE_VERSION = "rich-semantic-evaluation-attempt-state-v1"
    FAILED_ATTEMPT_VERSION = "rich-semantic-evaluation-failed-attempt-v1"
    REPORT_VERSION = _REPORT_VERSION
    CLEANUP_VERSION = "rich-semantic-evaluation-cleanup-v1"
    _ATTEMPT_FIELDS = frozenset({
        "approval_sha256", "attempt_number", "attempt_version", "case_ref",
        "expires_at", "model", "model_version", "started_at",
    })
    _ATTEMPT_STATE_FIELDS = frozenset({
        "approval_sha256", "attempt_state_version", "expires_at",
        "high_watermark", "reservations",
    })
    _RESULT_FIELDS = frozenset({
        "approval_sha256", "case_ref", "created_at", "expires_at", "model",
        "model_version", "record_version", "release_eligible", "review_state",
        "value",
    })
    _FAILED_ATTEMPT_FIELDS = frozenset({
        "approval_sha256", "attempt_number", "case_ref", "cost_usd_micros",
        "created_at", "expires_at", "failure_code", "input_tokens", "model",
        "model_version", "output_tokens", "receipt_version", "release_eligible",
    })
    _REPORT_MODEL_FIELDS = frozenset({
        "builder_agreement_basis_points", "correction_case_basis_points",
        "correction_case_count", "cost_usd_micros", "disagreements",
        "evaluation_case_count",
        "expected_human_escalation_case_basis_points",
        "expected_human_escalation_case_count",
        "failed_attempt_count", "field_agreement_basis_points",
        "impressive_agreement_basis_points",
        "impressive_expected_negative_count",
        "impressive_expected_positive_count", "impressive_false_negative_count",
        "impressive_false_positive_count", "input_tokens",
        "joint_agreement_basis_points",
        "mandatory_review_case_count",
        "mandatory_review_coverage_basis_points",
        "material_public_error_case_basis_points",
        "material_public_error_case_count",
        "maturity_agreement_basis_points", "model", "model_version",
        "output_tokens", "partner_metric_error_case_basis_points",
        "partner_metric_error_case_count",
        "partner_metric_expected_positive_count",
        "partner_metric_false_negative_count",
        "partner_metric_false_positive_count",
        "partner_metric_precision_basis_points",
        "partner_metric_predicted_positive_count",
        "partner_metric_recall_basis_points",
        "partner_metric_true_positive_count",
        "partner_taxonomy_error_case_basis_points",
        "partner_taxonomy_error_case_count",
        "partner_taxonomy_expected_positive_count",
        "partner_taxonomy_false_negative_count",
        "partner_taxonomy_false_positive_count",
        "partner_taxonomy_precision_basis_points",
        "partner_taxonomy_predicted_positive_count",
        "partner_taxonomy_recall_basis_points",
        "partner_taxonomy_true_positive_count",
        "report_scalar_agreement_basis_points",
        "report_scalar_minimum_basis_points",
    })
    _DISAGREEMENT_FIELDS = frozenset({
        "case_ref", "expected_label", "field_matches", "predicted_label",
    })

    def __init__(
        self, root: str | Path, *, release_root: str | Path,
        approval_path: str | Path, labeled_sample: object,
        clock: Callable[[], datetime],
    ) -> None:
        self.root = Path(root).resolve()
        self.release_root = Path(release_root).resolve()
        self.approval_path = Path(approval_path).resolve()
        if self.root.name != "rich-semantic-evaluation":
            raise ValueError("rich semantic evaluation requires its dedicated storage root")
        if (
            self.root == self.release_root
            or _is_relative_to(self.root, self.release_root)
            or _is_relative_to(self.release_root, self.root)
        ):
            raise ValueError("rich semantic evaluation must be isolated from release storage")
        if not _is_relative_to(self.approval_path, self.root):
            raise ValueError("rich semantic evaluation approval must be inside its root")
        self.clock = clock
        self.sample = _normalize_labeled_sample(labeled_sample)
        self.sample_by_ref = {str(item["case_ref"]): item for item in self.sample}
        self.approval, self.approval_sha256 = RichSemanticEvaluationApproval.load(
            self.approval_path, now=self.clock(),
        )
        actual = labeled_sample_hashes(self.sample)
        if any(
            not hmac.compare_digest(actual[key], str(getattr(self.approval, key)))
            for key in ("sample_sha256", "case_refs_sha256", "labels_sha256")
        ):
            raise PermissionError("rich semantic evaluation approval does not match labeled sample")
        self.results = self.root / "results"
        self.attempts = self.root / "provider-attempts"
        self.failed_attempts = self.root / "failed-attempts"
        self.attempt_state = self.root / "attempt-state.json"
        for directory in (
            self.root, self.results, self.attempts, self.failed_attempts,
        ):
            directory.mkdir(parents=True, exist_ok=True, mode=0o700)
            directory.chmod(0o700)
        self.approval_path.chmod(0o600)
        self._load_attempt_state()
        self.cleanup_expired()

    @staticmethod
    def _write(path: Path, value: Mapping[str, object]) -> None:
        payload = _canonical(value) + b"\n"
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=path.name + ".", suffix=".tmp", dir=path.parent,
        )
        temporary = Path(temporary_name)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb", closefd=True) as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            temporary.replace(path)
            path.chmod(0o600)
        except BaseException:
            try:
                os.close(descriptor)
            except OSError:
                pass
            temporary.unlink(missing_ok=True)
            raise

    def _current_approval(self) -> RichSemanticEvaluationApproval:
        approval, digest = RichSemanticEvaluationApproval.load(
            self.approval_path, now=self.clock(),
        )
        if not hmac.compare_digest(digest, self.approval_sha256):
            raise PermissionError("rich semantic evaluation approval changed after initialization")
        return approval

    @staticmethod
    def _result_name(model: str, case_ref: str) -> str:
        return hashlib.sha256(f"{model}\0{case_ref}".encode("utf-8")).hexdigest() + ".json"

    def _load_attempt_state(self) -> dict[str, object]:
        approval_expiry = _timestamp(self.approval.expires_at, "approval expiry")
        if not self.attempt_state.exists():
            prior_assets = (
                any(self.attempts.glob("*.json"))
                or any(self.results.glob("*.json"))
                or any(self.failed_attempts.glob("*.json"))
                or (self.root / "evaluation-report.json").exists()
                or (self.root / "cleanup-receipt.json").exists()
            )
            if prior_assets:
                raise PermissionError(
                    "rich semantic evaluation attempt state is missing"
                )
            self._write(self.attempt_state, {
                "approval_sha256": self.approval_sha256,
                "attempt_state_version": self.ATTEMPT_STATE_VERSION,
                "expires_at": _utc_timestamp(approval_expiry),
                "high_watermark": 0,
                "reservations": [],
            })
        if (
            self.attempt_state.is_symlink()
            or not self.attempt_state.is_file()
            or self.attempt_state.stat().st_mode & 0o777 != 0o600
        ):
            raise PermissionError("rich semantic evaluation attempt state is unsafe")
        try:
            state = json.loads(self.attempt_state.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise PermissionError(
                "rich semantic evaluation attempt state is unreadable"
            ) from error
        reservations = state.get("reservations") if isinstance(state, dict) else None
        high_watermark = state.get("high_watermark") if isinstance(state, dict) else None
        if (
            not isinstance(state, dict)
            or set(state) != self._ATTEMPT_STATE_FIELDS
            or state.get("approval_sha256") != self.approval_sha256
            or state.get("attempt_state_version") != self.ATTEMPT_STATE_VERSION
            or _timestamp(state.get("expires_at"), "attempt state expiry")
            != approval_expiry
            or type(high_watermark) is not int
            or not isinstance(reservations, list)
            or high_watermark != len(reservations)
            or high_watermark > self.approval.max_provider_attempts
        ):
            raise PermissionError("rich semantic evaluation attempt state is invalid")
        approved_at = _timestamp(self.approval.approved_at, "approval timestamp")
        per_case_counts: dict[tuple[str, str], int] = {}
        for number, reservation in enumerate(reservations, start=1):
            if (
                not isinstance(reservation, dict)
                or set(reservation) != self._ATTEMPT_FIELDS
                or reservation.get("approval_sha256") != self.approval_sha256
                or reservation.get("attempt_number") != number
                or reservation.get("attempt_version") != self.ATTEMPT_VERSION
                or reservation.get("case_ref") not in self.sample_by_ref
                or _timestamp(reservation.get("expires_at"), "attempt expiry")
                != approval_expiry
            ):
                raise PermissionError(
                    "rich semantic evaluation attempt state reservation is invalid"
                )
            binding = self.approval.model_binding(str(reservation.get("model")))
            started_at = _timestamp(reservation.get("started_at"), "attempt start")
            if (
                reservation.get("model_version") != binding["model_version"]
                or not approved_at <= started_at < approval_expiry
            ):
                raise PermissionError(
                    "rich semantic evaluation attempt state reservation is invalid"
                )
            key = (str(reservation["model"]), str(reservation["case_ref"]))
            per_case_counts[key] = per_case_counts.get(key, 0) + 1
            if per_case_counts[key] > self.approval.max_attempts_per_case:
                raise PermissionError(
                    "rich semantic evaluation attempt state exceeds retry ceiling"
                )
        return state

    def _validated_attempt_paths(self) -> list[Path]:
        state = self._load_attempt_state()
        reservations = state["reservations"]
        expected_names = {
            f"{int(reservation['attempt_number']):06d}.json"
            for reservation in reservations
        }
        actual_paths = {path.name: path for path in self.attempts.glob("*.json")}
        if set(actual_paths) - expected_names:
            raise PermissionError("rich semantic evaluation attempt ledger is discontinuous")
        paths: list[Path] = []
        for reservation in reservations:
            path = self.attempts / f"{int(reservation['attempt_number']):06d}.json"
            if not path.exists():
                self._write(path, reservation)
            try:
                value = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as error:
                raise PermissionError("rich semantic evaluation attempt ledger is unreadable") from error
            if (
                path.is_symlink()
                or path.stat().st_mode & 0o777 != 0o600
                or value != reservation
            ):
                raise PermissionError("rich semantic evaluation attempt ledger is invalid")
            paths.append(path)
        return paths

    def begin_provider_attempt(self, *, model: str, case_ref: str) -> int:
        approval = self._current_approval()
        binding = approval.model_binding(model)
        if case_ref not in self.sample_by_ref:
            raise PermissionError("rich semantic evaluation attempt case is not approved")
        paths = self._validated_attempt_paths()
        if len(paths) >= approval.max_provider_attempts:
            raise PermissionError("rich semantic evaluation provider attempt ceiling reached")
        matching_attempts = sum(
            1
            for existing in paths
            if (
                (value := json.loads(existing.read_text(encoding="utf-8")))["model"]
                == model
                and value["case_ref"] == case_ref
            )
        )
        if matching_attempts >= approval.max_attempts_per_case:
            raise PermissionError("rich semantic evaluation model-case retry ceiling reached")
        state = self._load_attempt_state()
        number = int(state["high_watermark"]) + 1
        reservation = {
            "approval_sha256": self.approval_sha256,
            "attempt_number": number,
            "attempt_version": self.ATTEMPT_VERSION,
            "case_ref": case_ref,
            "expires_at": _utc_timestamp(
                _timestamp(approval.expires_at, "approval expiry"),
            ),
            "model": model,
            "model_version": binding["model_version"],
            "started_at": _utc_timestamp(self.clock()),
        }
        reservations = [*state["reservations"], reservation]
        self._write(self.attempt_state, {
            **state,
            "high_watermark": number,
            "reservations": reservations,
        })
        # The state is durable before the per-attempt file. If interrupted here,
        # validation reconstructs the missing reservation and keeps it billable.
        self._validated_attempt_paths()
        return number

    def _validated_failed_attempt_receipts(
        self, *, model: str | None = None,
    ) -> list[dict[str, object]]:
        self._current_approval()
        attempts = {
            int(value["attempt_number"]): value
            for path in self._validated_attempt_paths()
            for value in [json.loads(path.read_text(encoding="utf-8"))]
        }
        approval_expiry = _timestamp(
            self.approval.expires_at, "approval expiry",
        )
        records: list[dict[str, object]] = []
        for path in sorted(self.failed_attempts.glob("*.json")):
            try:
                value = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as error:
                raise PermissionError(
                    "rich semantic evaluation failed-attempt receipt is unreadable"
                ) from error
            attempt_number = value.get("attempt_number") if isinstance(value, dict) else None
            attempt = attempts.get(attempt_number) if type(attempt_number) is int else None
            receipt_model = value.get("model") if isinstance(value, dict) else None
            if not isinstance(receipt_model, str):
                raise PermissionError(
                    "rich semantic evaluation failed-attempt receipt is invalid"
                )
            binding = self.approval.model_binding(receipt_model)
            input_tokens = value.get("input_tokens")
            output_tokens = value.get("output_tokens")
            if (
                set(value) != self._FAILED_ATTEMPT_FIELDS
                or attempt is None
                or path.name != f"{attempt_number:06d}.json"
                or value.get("approval_sha256") != self.approval_sha256
                or value.get("receipt_version") != self.FAILED_ATTEMPT_VERSION
                or value.get("release_eligible") is not False
                or value.get("failure_code") not in _FAILED_ATTEMPT_CODES
                or value.get("case_ref") != attempt["case_ref"]
                or receipt_model != attempt["model"]
                or value.get("model_version") != attempt["model_version"]
                or value.get("model_version") != binding["model_version"]
                or type(input_tokens) is not int or input_tokens < 0
                or type(output_tokens) is not int or output_tokens < 0
            ):
                raise PermissionError(
                    "rich semantic evaluation failed-attempt receipt is invalid"
                )
            created = _timestamp(value.get("created_at"), "failed-attempt creation")
            expires = _timestamp(value.get("expires_at"), "failed-attempt expiry")
            expected_cost = _token_cost(
                input_tokens,
                int(binding["input_cost_per_million_usd_micros"]),
            ) + _token_cost(
                output_tokens,
                int(binding["output_cost_per_million_usd_micros"]),
            )
            if (
                created < _timestamp(attempt["started_at"], "attempt start")
                or created >= expires
                or expires != approval_expiry
                or value.get("cost_usd_micros") != expected_cost
            ):
                raise PermissionError(
                    "rich semantic evaluation failed-attempt receipt binding is invalid"
                )
            if model is None or receipt_model == model:
                records.append(value)
        return records

    def put_failed_attempt(
        self, *, model: str, case_ref: str, attempt_number: int,
        failure_code: object, model_version: object, usage: object,
    ) -> dict[str, object]:
        approval = self._current_approval()
        binding = approval.model_binding(model)
        if (
            type(attempt_number) is not int
            or failure_code not in _FAILED_ATTEMPT_CODES
            or model_version != binding["model_version"]
            or not isinstance(usage, Mapping)
            or set(usage) != {"input_tokens", "output_tokens"}
            or any(type(usage[field]) is not int or usage[field] < 0 for field in usage)
        ):
            raise PermissionError(
                "rich semantic evaluation failed-attempt metadata is invalid"
            )
        attempts = self._validated_attempt_paths()
        if not 1 <= attempt_number <= len(attempts):
            raise PermissionError(
                "rich semantic evaluation failed-attempt has no reserved attempt"
            )
        attempt = json.loads(attempts[attempt_number - 1].read_text(encoding="utf-8"))
        if attempt["model"] != model or attempt["case_ref"] != case_ref:
            raise PermissionError(
                "rich semantic evaluation failed-attempt binding is invalid"
            )
        path = self.failed_attempts / f"{attempt_number:06d}.json"
        if path.exists():
            raise PermissionError(
                "rich semantic evaluation failed-attempt was already recorded"
            )
        input_tokens = int(usage["input_tokens"])
        output_tokens = int(usage["output_tokens"])
        record = {
            "approval_sha256": self.approval_sha256,
            "attempt_number": attempt_number,
            "case_ref": case_ref,
            "cost_usd_micros": _token_cost(
                input_tokens,
                int(binding["input_cost_per_million_usd_micros"]),
            ) + _token_cost(
                output_tokens,
                int(binding["output_cost_per_million_usd_micros"]),
            ),
            "created_at": _utc_timestamp(self.clock()),
            "expires_at": _utc_timestamp(
                _timestamp(approval.expires_at, "approval expiry"),
            ),
            "failure_code": failure_code,
            "input_tokens": input_tokens,
            "model": model,
            "model_version": model_version,
            "output_tokens": output_tokens,
            "receipt_version": self.FAILED_ATTEMPT_VERSION,
            "release_eligible": False,
        }
        self._write(path, record)
        self._validated_failed_attempt_receipts(model=model)
        return record

    def put_result(
        self, *, model: str, case_ref: str, value: Mapping[str, object],
    ) -> dict[str, object]:
        approval = self._current_approval()
        binding = approval.model_binding(model)
        sample_case = self.sample_by_ref.get(case_ref)
        if sample_case is None or set(value) != {
            "assessment", "input_tokens", "output_tokens", "cost_usd_micros",
        }:
            raise PermissionError("rich semantic evaluation result is not approved")
        assessment = validate_rich_semantic_assessment(
            value.get("assessment"), evidence=sample_case["evidence"],
        )
        for field in ("input_tokens", "output_tokens", "cost_usd_micros"):
            if type(value.get(field)) is not int or value[field] < 0:
                raise PermissionError("rich semantic evaluation usage is invalid")
        matching_attempt = False
        for path in self._validated_attempt_paths():
            attempt = json.loads(path.read_text(encoding="utf-8"))
            if attempt["model"] == model and attempt["case_ref"] == case_ref:
                matching_attempt = True
                break
        if not matching_attempt:
            raise PermissionError("rich semantic evaluation result requires a reserved attempt")
        expected_cost = _token_cost(
            int(value["input_tokens"]),
            int(binding["input_cost_per_million_usd_micros"]),
        ) + _token_cost(
            int(value["output_tokens"]),
            int(binding["output_cost_per_million_usd_micros"]),
        )
        if value["cost_usd_micros"] != expected_cost:
            raise PermissionError("rich semantic evaluation result cost is not bound to usage")
        now = self.clock()
        expires = min(
            now + timedelta(days=approval.retention_days),
            _timestamp(approval.expires_at, "approval expiry"),
        )
        record = {
            "approval_sha256": self.approval_sha256,
            "case_ref": case_ref,
            "created_at": _utc_timestamp(now),
            "expires_at": _utc_timestamp(expires),
            "model": model,
            "model_version": binding["model_version"],
            "record_version": self.RECORD_VERSION,
            "release_eligible": False,
            "review_state": "human_review_required",
            "value": {**dict(value), "assessment": assessment},
        }
        self._write(self.results / self._result_name(model, case_ref), record)
        return record

    def get_result(self, *, model: str, case_ref: str) -> dict[str, object] | None:
        """Load a live, fully revalidated result so interrupted evaluations resume."""
        approval = self._current_approval()
        binding = approval.model_binding(model)
        sample_case = self.sample_by_ref.get(case_ref)
        if sample_case is None:
            raise PermissionError("rich semantic evaluation result is not approved")
        path = self.results / self._result_name(model, case_ref)
        if not path.exists():
            return None
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
            created = _timestamp(record.get("created_at"), "result creation")
            expires = _timestamp(record.get("expires_at"), "result expiry")
        except (OSError, AttributeError, json.JSONDecodeError, PermissionError) as error:
            raise PermissionError("rich semantic evaluation result is unreadable") from error
        value = record.get("value") if isinstance(record, dict) else None
        if (
            set(record) != self._RESULT_FIELDS
            or record.get("approval_sha256") != self.approval_sha256
            or record.get("case_ref") != case_ref
            or record.get("model") != model
            or record.get("model_version") != binding["model_version"]
            or record.get("record_version") != self.RECORD_VERSION
            or record.get("release_eligible") is not False
            or record.get("review_state") != "human_review_required"
            or not isinstance(value, dict)
            or set(value) != {
                "assessment", "input_tokens", "output_tokens", "cost_usd_micros",
            }
            or expires <= created
            or expires > _timestamp(approval.expires_at, "approval expiry")
        ):
            raise PermissionError("rich semantic evaluation result failed validation")
        assessment = validate_rich_semantic_assessment(
            value.get("assessment"), evidence=sample_case["evidence"],
        )
        for field in ("input_tokens", "output_tokens", "cost_usd_micros"):
            if type(value.get(field)) is not int or value[field] < 0:
                raise PermissionError("rich semantic evaluation result usage is invalid")
        expected_cost = _token_cost(
            int(value["input_tokens"]),
            int(binding["input_cost_per_million_usd_micros"]),
        ) + _token_cost(
            int(value["output_tokens"]),
            int(binding["output_cost_per_million_usd_micros"]),
        )
        if value["cost_usd_micros"] != expected_cost:
            raise PermissionError("rich semantic evaluation result cost is invalid")
        if expires <= self.clock():
            self.cleanup_expired()
            return None
        return {**value, "assessment": assessment}

    def _model_report(self, model: str) -> dict[str, object]:
        binding = self.approval.model_binding(model)
        results: list[dict[str, object]] = []
        for sample_case in self.sample:
            result = self.get_result(
                model=model, case_ref=str(sample_case["case_ref"]),
            )
            if result is None:
                raise PermissionError(
                    "rich semantic evaluation results are incomplete"
                )
            results.append(result)
        provider_attempt_count = sum(
            1
            for path in self._validated_attempt_paths()
            if json.loads(path.read_text(encoding="utf-8"))["model"] == model
        )
        failed_attempt_count = provider_attempt_count - len(results)
        return _score_model_results(
            sample=self.sample,
            results=results,
            failed_attempts=self._validated_failed_attempt_receipts(model=model),
            failed_attempt_count=failed_attempt_count,
            model=model,
            model_version=str(binding["model_version"]),
        )

    def provider_attempt_count(self, *, model: str, case_ref: str) -> int:
        if case_ref not in self.sample_by_ref:
            raise PermissionError("rich semantic evaluation attempt case is not approved")
        return sum(
            1
            for path in self._validated_attempt_paths()
            if (
                (attempt := json.loads(path.read_text(encoding="utf-8")))["model"]
                == model
                and attempt["case_ref"] == case_ref
            )
        )

    def write_report(self, report: Mapping[str, object]) -> dict[str, object]:
        approval = self._current_approval()
        required = {
            "agreement_threshold_basis_points", "approval_sha256", "created_at",
            "expires_at", "models", "partner_report_taxonomy_schema_sha256",
            "recommended_model", "recommendation_policy_sha256",
            "release_eligible", "report_version", "review_state",
            "sample_sha256", "selection_reason",
        }
        base_required = required - {"created_at", "expires_at"}
        report_fields = frozenset(report)
        if report_fields not in {frozenset(required), frozenset(base_required)}:
            raise PermissionError("rich semantic evaluation report is invalid")
        now = self.clock()
        expected_created = _utc_timestamp(now)
        expected_expires = _utc_timestamp(min(
            now + timedelta(days=approval.retention_days),
            _timestamp(approval.expires_at, "approval expiry"),
        ))
        if report_fields == frozenset(required):
            if (
                report.get("created_at") != expected_created
                or report.get("expires_at") != expected_expires
            ):
                raise PermissionError(
                    "rich semantic evaluation report window is inconsistent"
                )
            materialized = dict(report)
        else:
            materialized = {
                **dict(report),
                "created_at": expected_created,
                "expires_at": expected_expires,
            }
        report = materialized
        if (
            report.get("agreement_threshold_basis_points")
            != approval.agreement_threshold_basis_points
        ):
            raise PermissionError(
                "rich semantic evaluation report threshold is inconsistent"
            )
        if (
            report.get("recommendation_policy_sha256")
            != recommendation_policy_sha256()
            or report.get("partner_report_taxonomy_schema_sha256")
            != partner_report_taxonomy_schema_sha256()
        ):
            raise PermissionError(
                "rich semantic evaluation recommendation policy is inconsistent"
            )
        if (
            report.get("approval_sha256") != self.approval_sha256
            or report.get("sample_sha256") != self.approval.sample_sha256
            or report.get("report_version") != self.REPORT_VERSION
            or report.get("review_state") != "human_review_required"
            or report.get("release_eligible") is not False
            or report.get("recommended_model") not in {None, *MODEL_ALLOWLIST}
        ):
            raise PermissionError("rich semantic evaluation report is invalid")
        models = report.get("models")
        approved_models = [str(item["model"]) for item in self.approval.models]
        if (
            not isinstance(models, list) or len(models) != len(approved_models)
            or [item.get("model") if isinstance(item, dict) else None for item in models]
            != approved_models
        ):
            raise PermissionError("rich semantic evaluation report model rows are invalid")
        for model, row in zip(approved_models, models, strict=True):
            if not isinstance(row, dict) or set(row) != self._REPORT_MODEL_FIELDS:
                raise PermissionError("rich semantic evaluation report model rows are invalid")
            expected = self._model_report(model)
            if not hmac.compare_digest(_sha256(row), _sha256(expected)):
                raise PermissionError("rich semantic evaluation report agreement is inconsistent")
        recommended, selection_reason = _select_recommended_model(
            models,
            threshold=approval.agreement_threshold_basis_points,
        )
        if (
            report.get("recommended_model") != recommended
            or report.get("selection_reason") != selection_reason
        ):
            raise PermissionError("rich semantic evaluation report selection is inconsistent")
        self._write(self.root / "evaluation-report.json", report)
        return dict(report)

    def cleanup_expired(self) -> dict[str, object]:
        now = self.clock()
        deleted: list[str] = []
        for directory in (
            self.root, self.results, self.attempts, self.failed_attempts,
        ):
            for temporary in directory.glob("*.tmp"):
                deleted.append(str(temporary.relative_to(self.root)))
                temporary.unlink(missing_ok=True)
        candidates = list(self.results.glob("*.json"))
        report = self.root / "evaluation-report.json"
        if report.exists():
            candidates.append(report)
        for path in candidates:
            try:
                value = json.loads(path.read_text(encoding="utf-8"))
                expired = _timestamp(value.get("expires_at"), "asset expiry") <= now
            except (OSError, AttributeError, json.JSONDecodeError, PermissionError):
                expired = True
            if expired:
                deleted.append(str(path.relative_to(self.root)))
                path.unlink(missing_ok=True)
        for path in self._validated_attempt_paths():
            value = json.loads(path.read_text(encoding="utf-8"))
            if _timestamp(value["expires_at"], "attempt expiry") <= now:
                deleted.append(str(path.relative_to(self.root)))
                path.unlink(missing_ok=True)
        for value in self._validated_failed_attempt_receipts():
            if _timestamp(value["expires_at"], "failed-attempt expiry") <= now:
                path = self.failed_attempts / f"{value['attempt_number']:06d}.json"
                deleted.append(str(path.relative_to(self.root)))
                path.unlink(missing_ok=True)
        receipt = {
            "cleanup_version": self.CLEANUP_VERSION,
            "deleted_assets_sha256": hashlib.sha256(
                "\n".join(sorted(deleted)).encode("utf-8"),
            ).hexdigest(),
            "deleted_at": _utc_timestamp(now),
            "deleted_count": len(deleted),
        }
        self._write(self.root / "cleanup-receipt.json", receipt)
        return receipt


def cleanup_expired_rich_semantic_evaluation(
    root: str | Path, *, release_root: str | Path, now: datetime,
) -> dict[str, object]:
    """Delete expired isolated assets without requiring a currently valid approval."""
    target = Path(root).resolve()
    release = Path(release_root).resolve()
    if target.name != "rich-semantic-evaluation" or (
        target == release
        or _is_relative_to(target, release)
        or _is_relative_to(release, target)
    ):
        raise ValueError("rich semantic evaluation cleanup root is invalid")
    if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("rich semantic evaluation cleanup time requires a timezone")
    target.mkdir(parents=True, exist_ok=True, mode=0o700)
    target.chmod(0o700)
    approval_path = target / "approval.json"
    delete_all = False
    try:
        raw = json.loads(approval_path.read_text(encoding="utf-8"))
        approval = RichSemanticEvaluationApproval.from_record(raw)
        approved = _timestamp(approval.approved_at, "approval timestamp")
        approval.authorize(now=approved)
        delete_all = _timestamp(approval.expires_at, "approval expiry") <= now
    except (OSError, json.JSONDecodeError, PermissionError):
        # The isolated scope is known from the root even when its controlling
        # approval is corrupt. Retaining participant-derived assets is less safe.
        delete_all = True

    deleted: list[str] = []
    directories = (
        target, target / "results", target / "provider-attempts",
        target / "failed-attempts",
    )
    for directory in directories:
        if not directory.exists():
            continue
        for temporary in directory.glob("*.tmp"):
            deleted.append(str(temporary.relative_to(target)))
            temporary.unlink(missing_ok=True)
    candidates: list[Path] = []
    for directory in directories[1:]:
        if directory.exists():
            candidates.extend(directory.glob("*.json"))
    report = target / "evaluation-report.json"
    if report.exists():
        candidates.append(report)
    attempt_state = target / "attempt-state.json"
    if attempt_state.exists():
        candidates.append(attempt_state)
    for path in candidates:
        remove = delete_all
        if not remove:
            try:
                value = json.loads(path.read_text(encoding="utf-8"))
                remove = _timestamp(value.get("expires_at"), "asset expiry") <= now
            except (OSError, AttributeError, json.JSONDecodeError, PermissionError):
                if _is_relative_to(path, target / "provider-attempts"):
                    raise PermissionError(
                        "rich semantic evaluation attempt ledger is unreadable"
                    )
                remove = True
        if remove:
            deleted.append(str(path.relative_to(target)))
            path.unlink(missing_ok=True)
    receipt = {
        "cleanup_version": RichSemanticEvaluationStore.CLEANUP_VERSION,
        "deleted_assets_sha256": hashlib.sha256(
            "\n".join(sorted(deleted)).encode("utf-8"),
        ).hexdigest(),
        "deleted_at": _utc_timestamp(now),
        "deleted_count": len(deleted),
    }
    RichSemanticEvaluationStore._write(target / "cleanup-receipt.json", receipt)
    return receipt


class RichSemanticEvaluator:
    """Evaluate the exact labeled sample against both approved model bindings."""

    def __init__(self, store: RichSemanticEvaluationStore) -> None:
        self.store = store

    @staticmethod
    def _cost(tokens: int, rate: int) -> int:
        return _token_cost(tokens, rate)

    def _run_case(
        self, *, model: str, sample_case: Mapping[str, object],
        runner: OpenAIRichSemanticAssessmentProvider,
    ) -> dict[str, object]:
        binding = self.store.approval.model_binding(model)
        case_ref = str(sample_case["case_ref"])
        existing = self.store.get_result(model=model, case_ref=case_ref)
        if existing is not None:
            return existing
        last_error: RuntimeError | None = None
        used_attempts = self.store.provider_attempt_count(
            model=model, case_ref=case_ref,
        )
        remaining_attempts = self.store.approval.max_attempts_per_case - used_attempts
        for _attempt in range(remaining_attempts):
            attempt_number = self.store.begin_provider_attempt(
                model=model, case_ref=case_ref,
            )
            try:
                output = runner.assess_with_metadata(
                    dict(sample_case["evidence"]), max_transport_attempts=1,
                )
            except RetryableRichSemanticOutputError as error:
                if error.usage is not None:
                    self.store.put_failed_attempt(
                        model=model,
                        case_ref=case_ref,
                        attempt_number=attempt_number,
                        failure_code=error.failure_code,
                        model_version=error.model_version,
                        usage=error.usage,
                    )
                last_error = error
                continue
            except (
                RetryableEvaluationError,
                RetryableTransportError,
            ) as error:
                last_error = error
                continue
            if not isinstance(output, dict) or set(output) != {
                "assessment", "model_version", "normalizations", "usage",
            }:
                raise PermissionError("rich semantic evaluation runner output is invalid")
            normalizations = output.get("normalizations")
            if (
                not isinstance(normalizations, list)
                or normalizations != list(dict.fromkeys(normalizations))
                or any(
                    not isinstance(item, str)
                    or item not in SEMANTIC_NORMALIZATION_CODES
                    for item in normalizations
                )
            ):
                raise PermissionError(
                    "rich semantic evaluation normalizations are invalid"
                )
            if output.get("model_version") != binding["model_version"]:
                raise PermissionError("rich semantic evaluation model version is not approved")
            usage = output.get("usage")
            if not isinstance(usage, dict) or set(usage) != {"input_tokens", "output_tokens"}:
                raise PermissionError("rich semantic evaluation usage is invalid")
            input_tokens = usage.get("input_tokens")
            output_tokens = usage.get("output_tokens")
            if (
                type(input_tokens) is not int or input_tokens < 0
                or type(output_tokens) is not int or output_tokens < 0
            ):
                raise PermissionError("rich semantic evaluation token accounting is invalid")
            assessment = validate_rich_semantic_assessment(
                output.get("assessment"), evidence=sample_case["evidence"],
            )
            cost = self._cost(
                input_tokens, int(binding["input_cost_per_million_usd_micros"]),
            ) + self._cost(
                output_tokens, int(binding["output_cost_per_million_usd_micros"]),
            )
            value = {
                "assessment": assessment,
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
                "cost_usd_micros": cost,
            }
            self.store.put_result(model=model, case_ref=case_ref, value=value)
            return value
        raise RuntimeError("rich semantic evaluation retry budget was exhausted") from last_error

    def evaluate(
        self, *, labeled_sample: object,
        runners: Mapping[str, OpenAIRichSemanticAssessmentProvider],
    ) -> dict[str, object]:
        sample = _normalize_labeled_sample(labeled_sample)
        hashes = labeled_sample_hashes(sample)
        if not hmac.compare_digest(hashes["sample_sha256"], self.store.approval.sample_sha256):
            raise PermissionError("rich semantic evaluation sample changed before evaluation")
        approved_models = [str(item["model"]) for item in self.store.approval.models]
        if not isinstance(runners, Mapping) or set(runners) != set(approved_models):
            raise PermissionError("rich semantic evaluation requires every approved model runner")
        for model in approved_models:
            runner = runners[model]
            if not isinstance(runner, OpenAIRichSemanticAssessmentProvider):
                raise PermissionError(
                    "rich semantic evaluation requires a concrete OpenAI provider"
                )
            endpoint = str(self.store.approval.model_binding(model)["endpoint"])
            expected_binding: dict[str, object] = {
                **self.store.approval.model_binding(model),
                "prompt_version": self.store.approval.prompt_version,
                "region": "eu" if endpoint.startswith("https://eu.") else "global",
                "schema_sha256": rich_semantic_schema_sha256(),
            }
            runtime_binding = runner.evaluation_binding.to_record()
            expected_binding = {
                key: value for key, value in expected_binding.items()
                if key not in {
                    "input_cost_per_million_usd_micros",
                    "output_cost_per_million_usd_micros",
                }
            }
            if (
                not callable(runner) or not isinstance(runtime_binding, dict)
                or not hmac.compare_digest(
                    _sha256(runtime_binding), _sha256(expected_binding),
                )
            ):
                raise PermissionError(
                    "rich semantic evaluation runtime binding does not match approval"
                )
        model_reports: list[dict[str, object]] = []
        for model in approved_models:
            runner = runners[model]
            for sample_case in sample:
                self._run_case(
                    model=model, sample_case=sample_case, runner=runner,
                )
            model_reports.append(self.store._model_report(model))
        threshold = self.store.approval.agreement_threshold_basis_points
        recommended, reason = _select_recommended_model(
            model_reports, threshold=threshold,
        )
        report = {
            "agreement_threshold_basis_points": threshold,
            "approval_sha256": self.store.approval_sha256,
            "models": model_reports,
            "partner_report_taxonomy_schema_sha256": (
                partner_report_taxonomy_schema_sha256()
            ),
            "recommended_model": recommended,
            "recommendation_policy_sha256": recommendation_policy_sha256(),
            "release_eligible": False,
            "report_version": self.store.REPORT_VERSION,
            "review_state": "human_review_required",
            "sample_sha256": self.store.approval.sample_sha256,
            "selection_reason": reason,
        }
        return self.store.write_report(report)
