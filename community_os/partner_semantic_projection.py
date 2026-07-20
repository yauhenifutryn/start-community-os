"""Project protected rich-semantic aggregates into a fixed partner-safe schema."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, replace
from datetime import datetime
import hashlib
import hmac
import json
from pathlib import Path
import re
import secrets

from community_os.enrichment.rich_semantic_assessment import ASSESSMENT_ENUMS
from community_os.semantic_metrics import (
    partner_report_taxonomy_codes,
    public_semantic_group_privacy_relations,
    public_semantic_group_registry,
    semantic_taxonomy_dimension_registry,
    semantic_taxonomy_sha256,
)


_BASE_DIMENSIONS = frozenset({
    "builder_level", "product_maturity", "technical_depth", "execution_scope",
    "external_validation", "originality",
})
_DIMENSIONS = _BASE_DIMENSIONS | {"cross_source_confidence", "impressive_band"}
_CELL_KEYS = {
    **{key: frozenset(values) for key, values in ASSESSMENT_ENUMS.items()},
    "cross_source_confidence": frozenset({"low", "medium", "high"}),
    "impressive_band": frozenset({"impressive", "not_impressive", "unknown"}),
}
_V3_KEYS = frozenset({
    "aggregate_version", "dimensions", "event_counts", "generated_at",
    "internal_only", "minimum_group_size", "release_eligible",
    "reviewed_denominator",
})
_V4_KEYS = frozenset({
    "aggregate_version", "dimensions", "generated_at", "internal_only",
    "minimum_group_size", "release_eligible", "reviewed_denominator",
    "source_coverage",
})
_SOURCE_KEYS = ("application", "projects", "devpost", "career")
_POPULATION_SOURCE_KEYS = (
    "application", "public_projects", "event_submission", "career_context",
)
_RELEASE_CONTEXT_KEYS = frozenset({
    "event_approval_sha256", "event_definition_sha256", "event_key",
    "population_sha256", "run_sha256", "source_snapshot_sha256",
    "taxonomy_sha256", "taxonomy_version", "total_population",
})
_SUMMARY_INTEGRITY_KEY = secrets.token_bytes(32)
_CANDIDATE_PROJECTION_VERSION = "partner-semantic-candidate-v2"
_APPROVED_PROJECTION_VERSION = "partner-semantic-summary-v3"
_COHORT_CANDIDATE_PROJECTION_VERSION = "partner-semantic-cohort-candidate-v1"
_UNATTRIBUTED_MEMBERSHIP_KEY = "unattributed_membership_unknown_count"
_COHORT_SPECS = (
    ("all", "All applicants", "all_applicants"),
    ("accepted", "Accepted participants", "accepted_participants"),
    ("attended", "Confirmed attendees", "confirmed_attendees"),
)

_PARTNER_TAXONOMY_CODES = partner_report_taxonomy_codes()
_PARTNER_TAXONOMY_ORDER = tuple(_PARTNER_TAXONOMY_CODES)
_PUBLIC_GROUP_REGISTRY = public_semantic_group_registry()
_PUBLIC_GROUP_REGISTRY_VERSION = str(_PUBLIC_GROUP_REGISTRY["registry_version"])
_PUBLIC_GROUP_SPECS = _PUBLIC_GROUP_REGISTRY["groups"]
assert isinstance(_PUBLIC_GROUP_SPECS, dict)
_PUBLIC_GROUP_ORDER = tuple(_PUBLIC_GROUP_SPECS)
_PARTNER_TAXONOMY_NOTES = {
    "product_maturity": "Positive product maturity supported by evidence-bound project assessment.",
    "technical_depth": "Substantive technical depth supported by descriptions, READMEs, releases, or demos.",
    "execution_scope": "The strongest attributable contribution scope supported by available evidence.",
    "external_validation": "Observed adoption, users, traction, or credible external recognition.",
    "problem_differentiation": "Projects whose framing goes beyond a routine implementation pattern.",
    "market_domains": "Market contexts explicitly supported by the available evidence; people may span several.",
    "technical_methods": "Technical approaches visible in the evidence-bound work; people may use several.",
    "demonstrated_capabilities": "Capabilities demonstrated by concrete work, not self-declared skill lists.",
    "career_stage": "Career context inferred from evidence-bound role and delivery signals when available.",
    "founder_state": "Current or prior founding evidence visible in the available career context.",
    "leadership_state": "Leadership scope supported by responsibility and delivery evidence.",
    "career_functions": "Functions supported by available career evidence; people may span several.",
    "career_delivery": "Career delivery signals supported by concrete outcomes; people may show several.",
}

_PUBLIC_LABEL_OVERRIDES = {
    "applied_ai_ml": "Applied AI / ML",
    "blockchain_web3": "Blockchain / Web3",
    "data_ai": "Data and AI",
    "data_ai_engineering": "Data and AI engineering",
    "go_to_market": "Go-to-market",
    "hardware_iot": "Hardware / IoT",
    "healthcare_life_sciences": "Healthcare and life sciences",
    "infrastructure_devops": "Infrastructure / DevOps",
    "mobile_native": "Native mobile",
    "open_source_maintenance": "Open-source maintenance",
    "web_full_stack": "Full-stack web",
}


def _public_label(code: str) -> str:
    return _PUBLIC_LABEL_OVERRIDES.get(
        code, code.replace("_", " ").capitalize(),
    )


@dataclass(frozen=True)
class PartnerSemanticMetric:
    key: str
    count: int | None
    denominator: int | None
    label: str
    note: str
    state: str = "reported"


@dataclass(frozen=True)
class PartnerSemanticCell:
    key: str
    label: str
    count: int | None
    state: str


@dataclass(frozen=True)
class PartnerSemanticDimension:
    key: str
    family: str
    mode: str
    denominator: int | None
    label: str
    note: str
    cells: tuple[PartnerSemanticCell, ...]
    unknown_count: int | None
    unknown_state: str


@dataclass(frozen=True)
class PartnerSemanticSummary:
    projection_version: str
    aggregate_sha256: str
    reviewed_denominator: int | None
    metrics: tuple[PartnerSemanticMetric, ...]
    source_coverage: tuple[tuple[str, int | None], ...]
    dimensions: tuple[PartnerSemanticDimension, ...] = ()
    public_groups: tuple[PartnerSemanticMetric, ...] = ()
    public_group_registry_version: str | None = None
    event_key: str | None = None
    event_definition_sha256: str | None = None
    event_approval_sha256: str | None = None
    source_snapshot_sha256: str | None = None
    population_sha256: str | None = None
    run_sha256: str | None = None
    taxonomy_sha256: str | None = None
    taxonomy_version: str | None = None
    eligible_denominator: int | None = None
    excluded_count: int | None = None
    total_population: int | None = None
    unknown_count: int | None = None
    whole_person_unresolved_count: int | None = None
    semantic_release_approval_sha256: str | None = None
    release_artifact_hashes: tuple[tuple[str, str], ...] = ()
    _integrity_proof: str = ""


@dataclass(frozen=True)
class PartnerSemanticCohort:
    key: str
    label: str
    denominator: int
    unattributed_membership_unknown_count: int
    summary: PartnerSemanticSummary


@dataclass(frozen=True)
class PartnerSemanticCohortBundle:
    projection_version: str
    minimum_group_size: int
    cohorts: tuple[PartnerSemanticCohort, ...]
    _integrity_proof: str = ""


def _summary_payload(summary: PartnerSemanticSummary) -> dict[str, object]:
    return {
        "aggregate_sha256": summary.aggregate_sha256,
        "eligible_denominator": summary.eligible_denominator,
        "event_approval_sha256": summary.event_approval_sha256,
        "event_definition_sha256": summary.event_definition_sha256,
        "event_key": summary.event_key,
        "excluded_count": summary.excluded_count,
        "metrics": [
            {
                "count": metric.count,
                "denominator": metric.denominator,
                "key": metric.key,
                "label": metric.label,
                "note": metric.note,
                "state": metric.state,
            }
            for metric in summary.metrics
        ],
        "dimensions": [
            {
                "cells": [
                    {
                        "count": cell.count,
                        "key": cell.key,
                        "label": cell.label,
                        "state": cell.state,
                    }
                    for cell in dimension.cells
                ],
                "denominator": dimension.denominator,
                "family": dimension.family,
                "key": dimension.key,
                "label": dimension.label,
                "mode": dimension.mode,
                "note": dimension.note,
                "unknown_count": dimension.unknown_count,
                "unknown_state": dimension.unknown_state,
            }
            for dimension in summary.dimensions
        ],
        "public_group_registry_version": summary.public_group_registry_version,
        "public_groups": [
            {
                "count": group.count,
                "denominator": group.denominator,
                "key": group.key,
                "label": group.label,
                "note": group.note,
                "state": group.state,
            }
            for group in summary.public_groups
        ],
        "population_sha256": summary.population_sha256,
        "projection_version": summary.projection_version,
        "release_artifact_hashes": [list(item) for item in summary.release_artifact_hashes],
        "reviewed_denominator": summary.reviewed_denominator,
        "run_sha256": summary.run_sha256,
        "semantic_release_approval_sha256": summary.semantic_release_approval_sha256,
        "source_coverage": [list(item) for item in summary.source_coverage],
        "source_snapshot_sha256": summary.source_snapshot_sha256,
        "taxonomy_sha256": summary.taxonomy_sha256,
        "taxonomy_version": summary.taxonomy_version,
        "total_population": summary.total_population,
        "unknown_count": summary.unknown_count,
        "whole_person_unresolved_count": summary.whole_person_unresolved_count,
    }


def _summary_integrity_proof(summary: PartnerSemanticSummary) -> str:
    payload = json.dumps(
        _summary_payload(summary), ensure_ascii=True, sort_keys=True,
        separators=(",", ":"), allow_nan=False,
    ).encode("utf-8")
    return hmac.new(_SUMMARY_INTEGRITY_KEY, payload, hashlib.sha256).hexdigest()


def _seal_summary(summary: PartnerSemanticSummary) -> PartnerSemanticSummary:
    return replace(summary, _integrity_proof=_summary_integrity_proof(summary))


def _cohort_bundle_payload(
    bundle: PartnerSemanticCohortBundle,
) -> dict[str, object]:
    return {
        "cohorts": [
            {
                "denominator": cohort.denominator,
                "key": cohort.key,
                "label": cohort.label,
                _UNATTRIBUTED_MEMBERSHIP_KEY: (
                    cohort.unattributed_membership_unknown_count
                ),
                "summary": _summary_payload(cohort.summary),
            }
            for cohort in bundle.cohorts
        ],
        "minimum_group_size": bundle.minimum_group_size,
        "projection_version": bundle.projection_version,
    }


def _cohort_bundle_integrity_proof(bundle: PartnerSemanticCohortBundle) -> str:
    payload = json.dumps(
        _cohort_bundle_payload(bundle), ensure_ascii=True, sort_keys=True,
        separators=(",", ":"), allow_nan=False,
    ).encode("utf-8")
    return hmac.new(_SUMMARY_INTEGRITY_KEY, payload, hashlib.sha256).hexdigest()


def _seal_cohort_bundle(
    bundle: PartnerSemanticCohortBundle,
) -> PartnerSemanticCohortBundle:
    return replace(bundle, _integrity_proof=_cohort_bundle_integrity_proof(bundle))


def _public_summary_counts(
    summary: PartnerSemanticSummary,
) -> dict[str, int | None]:
    counts = {
        f"metric:{metric.key}": metric.count for metric in summary.metrics
    }
    counts.update({
        f"source:{key}": count for key, count in summary.source_coverage
    })
    counts.update({
        f"group:{group.key}": group.count for group in summary.public_groups
    })
    for dimension in summary.dimensions:
        counts.update({
            f"dimension:{dimension.key}:{cell.key}": cell.count
            for cell in dimension.cells
        })
        counts[f"dimension:{dimension.key}:unknown"] = dimension.unknown_count
    counts["whole_person:unknown"] = summary.whole_person_unresolved_count
    return counts


def _cross_cohort_suppression_masks(
    aggregates: tuple[Mapping[str, object], ...],
    *,
    minimum_group_size: int,
) -> tuple[set[tuple[int, str]], set[tuple[int, str]]]:
    value_masks: set[tuple[int, str]] = set()
    full_dimension_masks: set[tuple[int, str]] = set()
    registry = semantic_taxonomy_dimension_registry()

    def raw_counts(aggregate: Mapping[str, object]) -> dict[str, int]:
        metrics = _mapping(aggregate["metrics"], label="cohort metrics")
        coverage = _mapping(
            aggregate["source_coverage"], label="cohort source coverage",
        )
        population = _mapping(aggregate["population"], label="cohort population")
        dimensions = _mapping(
            aggregate["taxonomy_dimensions"], label="cohort taxonomy dimensions",
        )
        counts = {
            f"metric:{key}": _integer(metrics[key], label=f"cohort metric {key}")
            for key, _label, _note in _PARTNER_METRICS
        }
        counts.update({
            f"source:{key}": _integer(
                coverage[key], label=f"cohort source coverage {key}",
            )
            for key in _POPULATION_SOURCE_KEYS
        })
        counts["whole_person:unknown"] = _integer(
            population["unknown_count"], label="cohort unknown count",
        )
        for dimension_key in _PARTNER_TAXONOMY_ORDER:
            dimension = _mapping(
                dimensions[dimension_key],
                label=f"cohort taxonomy dimension {dimension_key}",
            )
            cells = _mapping(
                dimension["cells"],
                label=f"cohort taxonomy cells {dimension_key}",
            )
            for cell_key in _PARTNER_TAXONOMY_CODES[dimension_key]:
                counts[f"dimension:{dimension_key}:{cell_key}"] = _integer(
                    cells[cell_key],
                    label=f"cohort taxonomy cell {dimension_key}.{cell_key}",
                )
            counts[f"dimension:{dimension_key}:unknown"] = _integer(
                dimension["unknown_count"],
                label=f"cohort taxonomy unknown {dimension_key}",
            )
        for group_key in _PUBLIC_GROUP_ORDER:
            spec = _mapping(
                _PUBLIC_GROUP_SPECS[group_key],
                label=f"public semantic group {group_key}",
            )
            dimension = _mapping(
                dimensions[str(spec["dimension"])],
                label=f"public semantic group dimension {group_key}",
            )
            cells = _mapping(
                dimension["cells"], label=f"public semantic group cells {group_key}",
            )
            values = spec["values"]
            assert isinstance(values, list)
            counts[f"group:{group_key}"] = sum(
                _integer(cells[value], label=f"public semantic group {group_key}")
                for value in values
            )
        return counts

    raw_by_cohort = tuple(raw_counts(aggregate) for aggregate in aggregates)
    for parent_index, child_index in ((0, 1), (1, 2)):
        parent = raw_by_cohort[parent_index]
        child = raw_by_cohort[child_index]
        if set(parent) != set(child):
            raise PermissionError("rich semantic cohort count sets are mixed")
        for path, parent_count in parent.items():
            child_count = child[path]
            if child_count > parent_count:
                raise PermissionError(
                    "rich semantic nested cohort count exceeds its parent"
                )
            if not 0 < parent_count - child_count < minimum_group_size:
                continue
            if path.startswith("dimension:"):
                _prefix, dimension_key, _cell_key = path.split(":", 2)
                spec = registry[dimension_key]
                if spec["mode"] == "exclusive":
                    full_dimension_masks.update({
                        (parent_index, dimension_key),
                        (child_index, dimension_key),
                    })
                    continue
            value_masks.update({
                (parent_index, path), (child_index, path),
            })
    return value_masks, full_dimension_masks


def _apply_cross_cohort_suppression(
    cohorts: tuple[PartnerSemanticCohort, ...],
    aggregates: tuple[Mapping[str, object], ...],
    *,
    minimum_group_size: int,
) -> tuple[PartnerSemanticCohort, ...]:
    value_masks, full_dimension_masks = _cross_cohort_suppression_masks(
        aggregates, minimum_group_size=minimum_group_size,
    )
    protected: list[PartnerSemanticCohort] = []
    for index, cohort in enumerate(cohorts):
        summary = cohort.summary
        metrics = tuple(
            replace(metric, count=None, state="withheld")
            if (index, f"metric:{metric.key}") in value_masks else metric
            for metric in summary.metrics
        )
        coverage = tuple(
            (key, None)
            if (index, f"source:{key}") in value_masks else (key, count)
            for key, count in summary.source_coverage
        )
        public_groups = tuple(
            replace(group, count=None, state="withheld")
            if (index, f"group:{group.key}") in value_masks else group
            for group in summary.public_groups
        )
        dimensions: list[PartnerSemanticDimension] = []
        for dimension in summary.dimensions:
            full = (index, dimension.key) in full_dimension_masks
            cells = tuple(
                replace(cell, count=None, state="withheld")
                if full or (
                    index, f"dimension:{dimension.key}:{cell.key}"
                ) in value_masks else cell
                for cell in dimension.cells
            )
            hide_unknown = full or (
                index, f"dimension:{dimension.key}:unknown"
            ) in value_masks
            dimensions.append(replace(
                dimension,
                cells=cells,
                unknown_count=None if hide_unknown else dimension.unknown_count,
                unknown_state=(
                    "withheld" if hide_unknown else dimension.unknown_state
                ),
            ))
        whole_person_unresolved_count = (
            None
            if (index, "whole_person:unknown") in value_masks
            else summary.whole_person_unresolved_count
        )
        protected_summary = _seal_summary(replace(
            summary,
            metrics=metrics,
            source_coverage=coverage,
            public_groups=public_groups,
            dimensions=tuple(dimensions),
            whole_person_unresolved_count=whole_person_unresolved_count,
        ))
        protected.append(replace(cohort, summary=protected_summary))
    return tuple(protected)


def _optional_count(value: object, *, label: str, ceiling: int) -> int | None:
    if value is None:
        return None
    normalized = _integer(value, label=label)
    if normalized > ceiling:
        raise PermissionError(f"rich semantic summary {label} exceeds population")
    return normalized


def validate_partner_semantic_summary(
    summary: PartnerSemanticSummary,
    *,
    allow_candidate: bool = True,
) -> PartnerSemanticSummary:
    """Reject caller-constructed or drifted summaries at every public boundary."""

    if not isinstance(summary, PartnerSemanticSummary):
        raise PermissionError("rich semantic summary is invalid")
    allowed_versions = {_APPROVED_PROJECTION_VERSION}
    if allow_candidate:
        allowed_versions.add(_CANDIDATE_PROJECTION_VERSION)
    if summary.projection_version not in allowed_versions:
        raise PermissionError("rich semantic summary projection is invalid")
    if not hmac.compare_digest(
        summary._integrity_proof, _summary_integrity_proof(summary),
    ):
        raise PermissionError("rich semantic summary integrity is invalid")
    if not isinstance(summary.aggregate_sha256, str) or not re.fullmatch(
        r"[0-9a-f]{64}", summary.aggregate_sha256,
    ):
        raise PermissionError("rich semantic summary aggregate hash is invalid")
    if not isinstance(summary.event_key, str) or not re.fullmatch(
        r"[a-z][a-z0-9._-]{0,127}", summary.event_key,
    ):
        raise PermissionError("rich semantic summary event key is invalid")
    for label, value in (
        ("event definition", summary.event_definition_sha256),
        ("event approval", summary.event_approval_sha256),
        ("source snapshot", summary.source_snapshot_sha256),
        ("population", summary.population_sha256),
        ("run", summary.run_sha256),
        ("taxonomy", summary.taxonomy_sha256),
    ):
        if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
            raise PermissionError(f"rich semantic summary {label} hash is invalid")
    if not isinstance(summary.taxonomy_version, str) or not re.fullmatch(
        r"[a-z][a-z0-9._-]{0,127}", summary.taxonomy_version,
    ):
        raise PermissionError("rich semantic summary taxonomy version is invalid")
    total = _integer(
        summary.total_population, label="summary total population", minimum=5,
    )
    eligible = _optional_count(
        summary.eligible_denominator, label="eligible denominator", ceiling=total,
    )
    reviewed = _optional_count(
        summary.reviewed_denominator, label="reviewed denominator", ceiling=total,
    )
    if eligible is not None and reviewed is not None and reviewed > eligible:
        raise PermissionError("rich semantic summary reviewed denominator is invalid")
    if summary.excluded_count is not None or summary.unknown_count is not None:
        raise PermissionError("rich semantic summary hidden population state is invalid")
    whole_person_unresolved = _optional_count(
        summary.whole_person_unresolved_count,
        label="whole-person unresolved count",
        ceiling=eligible if eligible is not None else total,
    )
    if (
        whole_person_unresolved is not None
        and eligible is not None
        and reviewed is not None
        and reviewed + whole_person_unresolved != eligible
    ):
        raise PermissionError("rich semantic summary whole-person count is invalid")
    if len(summary.metrics) != len(_PARTNER_METRICS):
        raise PermissionError("rich semantic summary metric set is invalid")
    for metric, (key, label, note) in zip(summary.metrics, _PARTNER_METRICS, strict=True):
        if not isinstance(metric, PartnerSemanticMetric) or (
            metric.key, metric.label, metric.note
        ) != (key, label, note):
            raise PermissionError("rich semantic summary metric definition is invalid")
        if metric.denominator != eligible:
            raise PermissionError("rich semantic summary metric denominator is invalid")
        if metric.state == "withheld":
            if metric.count is not None:
                raise PermissionError("rich semantic summary withheld metric is invalid")
        elif metric.state == "reported":
            _optional_count(metric.count, label=f"metric {key}", ceiling=total)
            if metric.count is None:
                raise PermissionError("rich semantic summary reported metric is invalid")
        else:
            raise PermissionError("rich semantic summary metric state is invalid")
    if tuple(key for key, _ in summary.source_coverage) != _POPULATION_SOURCE_KEYS:
        raise PermissionError("rich semantic summary source coverage is invalid")
    for key, count in summary.source_coverage:
        _optional_count(count, label=f"source coverage {key}", ceiling=total)

    if summary.public_group_registry_version != _PUBLIC_GROUP_REGISTRY_VERSION:
        raise PermissionError("rich semantic summary public group version is invalid")
    if tuple(group.key for group in summary.public_groups) != _PUBLIC_GROUP_ORDER:
        raise PermissionError("rich semantic summary public group set is invalid")
    for group in summary.public_groups:
        spec = _PUBLIC_GROUP_SPECS[group.key]
        assert isinstance(spec, dict)
        if (
            not isinstance(group, PartnerSemanticMetric)
            or group.label != _public_label(group.key)
            or group.note != spec["definition"]
            or group.denominator != eligible
        ):
            raise PermissionError("rich semantic summary public group definition is invalid")
        if group.state == "withheld":
            if group.count is not None:
                raise PermissionError("rich semantic summary withheld public group is invalid")
        elif group.state == "reported":
            if _optional_count(
                group.count, label=f"public group {group.key}", ceiling=total,
            ) is None:
                raise PermissionError("rich semantic summary public group is invalid")
        else:
            raise PermissionError("rich semantic summary public group state is invalid")

    registry = semantic_taxonomy_dimension_registry()
    if tuple(dimension.key for dimension in summary.dimensions) != _PARTNER_TAXONOMY_ORDER:
        raise PermissionError("rich semantic summary taxonomy dimensions are invalid")
    for dimension in summary.dimensions:
        spec = registry[dimension.key]
        if (
            not isinstance(dimension, PartnerSemanticDimension)
            or dimension.family != spec["family"]
            or dimension.mode != spec["mode"]
            or dimension.label != _public_label(dimension.key)
            or dimension.note != _PARTNER_TAXONOMY_NOTES[dimension.key]
            or dimension.denominator != eligible
            or tuple(cell.key for cell in dimension.cells)
            != _PARTNER_TAXONOMY_CODES[dimension.key]
        ):
            raise PermissionError("rich semantic summary taxonomy definition is invalid")
        values: list[int] = []
        states: list[str] = []
        for cell in dimension.cells:
            if (
                not isinstance(cell, PartnerSemanticCell)
                or cell.label != _public_label(cell.key)
                or cell.state not in {"reported", "withheld"}
            ):
                raise PermissionError("rich semantic summary taxonomy cell is invalid")
            states.append(cell.state)
            if cell.state == "withheld":
                if cell.count is not None:
                    raise PermissionError("rich semantic summary withheld taxonomy cell is invalid")
            else:
                count = _optional_count(
                    cell.count, label=f"taxonomy cell {dimension.key}.{cell.key}",
                    ceiling=total,
                )
                if count is None:
                    raise PermissionError("rich semantic summary taxonomy cell is invalid")
                values.append(count)
        if dimension.unknown_state not in {"reported", "withheld"}:
            raise PermissionError("rich semantic summary taxonomy unknown state is invalid")
        if dimension.unknown_state == "withheld":
            if dimension.unknown_count is not None:
                raise PermissionError("rich semantic summary withheld taxonomy unknown is invalid")
        else:
            if _optional_count(
                dimension.unknown_count,
                label=f"taxonomy unknown {dimension.key}", ceiling=total,
            ) is None:
                raise PermissionError("rich semantic summary taxonomy unknown is invalid")
        if eligible is None and (
            any(state != "withheld" for state in states)
            or dimension.unknown_state != "withheld"
        ):
            raise PermissionError("rich semantic summary hidden taxonomy denominator leaked")
        if dimension.mode == "exclusive" and "withheld" in states:
            if any(state != "withheld" for state in states) or dimension.unknown_state != "withheld":
                raise PermissionError("rich semantic summary exclusive taxonomy suppression is invalid")

    if summary.projection_version == _CANDIDATE_PROJECTION_VERSION:
        if (
            summary.semantic_release_approval_sha256 is not None
            or summary.release_artifact_hashes
        ):
            raise PermissionError("rich semantic summary candidate state is invalid")
    else:
        if not isinstance(summary.semantic_release_approval_sha256, str) or not re.fullmatch(
            r"[0-9a-f]{64}", summary.semantic_release_approval_sha256,
        ):
            raise PermissionError("rich semantic summary approval hash is invalid")
        expected_artifacts = (
            "html_sha256", "pdf_sha256", "qa_sha256", "report_candidate_sha256",
        )
        if tuple(key for key, _ in summary.release_artifact_hashes) != expected_artifacts:
            raise PermissionError("rich semantic summary artifact hashes are invalid")
        for _key, value in summary.release_artifact_hashes:
            if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
                raise PermissionError("rich semantic summary artifact hash is invalid")
    if not hmac.compare_digest(
        str(summary.taxonomy_sha256),
        semantic_taxonomy_sha256(str(summary.taxonomy_version)),
    ):
        raise PermissionError("rich semantic summary taxonomy binding is invalid")
    return summary


def validate_partner_semantic_release_context(
    summary: PartnerSemanticSummary,
    context: Mapping[str, object],
) -> dict[str, object]:
    """Require the caller's current release context to match every semantic binding."""

    validate_partner_semantic_summary(summary)
    if not isinstance(context, Mapping) or set(context) != _RELEASE_CONTEXT_KEYS:
        raise PermissionError("rich semantic release context keys are invalid")
    expected = {
        "event_approval_sha256": summary.event_approval_sha256,
        "event_definition_sha256": summary.event_definition_sha256,
        "event_key": summary.event_key,
        "population_sha256": summary.population_sha256,
        "run_sha256": summary.run_sha256,
        "source_snapshot_sha256": summary.source_snapshot_sha256,
        "taxonomy_sha256": summary.taxonomy_sha256,
        "taxonomy_version": summary.taxonomy_version,
        "total_population": summary.total_population,
    }
    normalized = dict(context)
    if normalized != expected:
        raise PermissionError("rich semantic release context does not match")
    return normalized


def semantic_summary_manifest_binding(
    summary: PartnerSemanticSummary,
) -> dict[str, object]:
    validate_partner_semantic_summary(summary)
    approval_sha256 = summary.semantic_release_approval_sha256
    return {
        "aggregate_sha256": summary.aggregate_sha256,
        "eligible_denominator": summary.eligible_denominator,
        "event_approval_sha256": summary.event_approval_sha256,
        "event_definition_sha256": summary.event_definition_sha256,
        "event_key": summary.event_key,
        "human_release_approval_sha256": approval_sha256,
        "population_sha256": summary.population_sha256,
        "projection_version": summary.projection_version,
        "release_eligible": approval_sha256 is not None,
        "reviewed_denominator": summary.reviewed_denominator,
        "run_sha256": summary.run_sha256,
        "source_snapshot_sha256": summary.source_snapshot_sha256,
        "taxonomy_sha256": summary.taxonomy_sha256,
        "taxonomy_version": summary.taxonomy_version,
        "total_population": summary.total_population,
    }


def _mapping(value: object, *, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise PermissionError(f"rich semantic {label} is invalid")
    return value


def _integer(value: object, *, label: str, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise PermissionError(f"rich semantic {label} is invalid")
    return value


def _validate_cell(
    value: object, *, label: str, denominator: int, minimum_group_size: int,
) -> tuple[int | None, str]:
    cell = _mapping(value, label=label)
    if set(cell) != {"count", "state"}:
        raise PermissionError(f"rich semantic {label} keys are invalid")
    count = cell["count"]
    state = cell["state"]
    if state == "withheld" and count is None:
        return None, "withheld"
    if state != "reported":
        raise PermissionError(f"rich semantic {label} state is invalid")
    normalized = _integer(count, label=f"{label} count", minimum=minimum_group_size)
    if normalized > denominator:
        raise PermissionError(f"rich semantic {label} count exceeds denominator")
    return normalized, "reported"


def _validate_dimensions(
    value: object, *, denominator: int, minimum_group_size: int,
) -> dict[str, dict[str, tuple[int | None, str]]]:
    dimensions = _mapping(value, label="dimensions")
    if set(dimensions) != _DIMENSIONS:
        raise PermissionError("rich semantic dimension keys are invalid")
    normalized: dict[str, dict[str, tuple[int | None, str]]] = {}
    for dimension_key in sorted(_DIMENSIONS):
        dimension = _mapping(
            dimensions[dimension_key], label=f"dimension {dimension_key}",
        )
        if set(dimension) != {"cells", "denominator", "unknown_cell"}:
            raise PermissionError(
                f"rich semantic dimension {dimension_key} keys are invalid",
            )
        if _integer(
            dimension["denominator"], label=f"dimension {dimension_key} denominator",
        ) != denominator:
            raise PermissionError(
                f"rich semantic dimension {dimension_key} denominator mismatch",
            )
        cells = _mapping(
            dimension["cells"], label=f"dimension {dimension_key} cells",
        )
        expected_cells = _CELL_KEYS[dimension_key]
        if set(cells) not in {
            expected_cells,
            expected_cells - {"unknown"},
        }:
            raise PermissionError(
                f"rich semantic dimension {dimension_key} cell keys are invalid",
            )
        normalized[dimension_key] = {
            cell_key: _validate_cell(
                cells[cell_key],
                label=f"dimension {dimension_key}.{cell_key}",
                denominator=denominator,
                minimum_group_size=minimum_group_size,
            )
            for cell_key in sorted(cells)
        }
        _validate_cell(
            dimension["unknown_cell"],
            label=f"dimension {dimension_key} unknown cell",
            denominator=denominator,
            minimum_group_size=minimum_group_size,
        )
    return normalized


def _reported_sum(
    dimensions: Mapping[str, Mapping[str, tuple[int | None, str]]],
    dimension_key: str,
    cell_keys: tuple[str, ...],
) -> int:
    total = 0
    for cell_key in cell_keys:
        count, state = dimensions[dimension_key][cell_key]
        if state != "reported" or count is None:
            raise PermissionError(
                f"rich semantic partner metric {dimension_key}.{cell_key} is withheld",
            )
        total += count
    return total


def _canonical_sha256(value: Mapping[str, object]) -> str:
    try:
        payload = json.dumps(
            value, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise PermissionError("rich semantic aggregate is not canonical JSON") from error
    return hashlib.sha256(payload).hexdigest()


def build_legacy_diagnostic_semantic_summary(
    aggregate: Mapping[str, object],
) -> PartnerSemanticSummary:
    """Read legacy v3/v4 aggregates for private diagnostics only."""

    value = _mapping(aggregate, label="aggregate")
    version = value.get("aggregate_version")
    expected_keys = (
        _V3_KEYS if version == "rich-semantic-internal-aggregate-v3"
        else _V4_KEYS if version == "rich-semantic-internal-aggregate-v4"
        else None
    )
    if expected_keys is None:
        raise PermissionError("rich semantic aggregate version is unsupported")
    if set(value) != expected_keys:
        raise PermissionError("rich semantic aggregate keys are invalid")
    if value["internal_only"] is not True or value["release_eligible"] is not False:
        raise PermissionError("rich semantic aggregate boundary flags are invalid")
    denominator = _integer(
        value["reviewed_denominator"], label="reviewed denominator", minimum=5,
    )
    minimum_group_size = _integer(
        value["minimum_group_size"], label="minimum group size", minimum=5,
    )
    if not isinstance(value["generated_at"], str) or not value["generated_at"]:
        raise PermissionError("rich semantic generated timestamp is invalid")
    if version == "rich-semantic-internal-aggregate-v3":
        event_counts = _mapping(value["event_counts"], label="legacy event counts")
        if set(event_counts) != {"accepted", "present"}:
            raise PermissionError("rich semantic legacy event count keys are invalid")
        for key in ("accepted", "present"):
            _integer(event_counts[key], label=f"legacy event count {key}")

    dimensions = _validate_dimensions(
        value["dimensions"], denominator=denominator,
        minimum_group_size=minimum_group_size,
    )
    metric_specs = (
        (
            "technical_depth", "technical_depth", ("moderate", "advanced"),
            "Moderate or advanced technical depth",
            "Substance visible in project descriptions, READMEs, releases, or deployment evidence.",
        ),
        (
            "originality", "originality", ("differentiated", "ambitious"),
            "Differentiated or ambitious problem framing",
            "The project goes beyond a routine implementation of a common template.",
        ),
        (
            "execution", "execution_scope",
            ("contributor", "substantial_contributor", "primary_builder", "end_to_end_builder"),
            "Attributable execution evidence",
            "Public or submitted evidence supports a concrete contribution scope.",
        ),
        (
            "external_validation", "external_validation", ("early_signal", "meaningful"),
            "Early or meaningful external validation",
            "Evidence includes real adoption, users, traction, or credible external recognition.",
        ),
        (
            "standout", "impressive_band", ("impressive",),
            "Strict multi-signal standout threshold",
            "A conservative positive threshold requiring several independent product and builder signals.",
        ),
    )
    metrics = tuple(
        PartnerSemanticMetric(
            key=key,
            count=_reported_sum(dimensions, dimension_key, cell_keys),
            denominator=denominator,
            label=label,
            note=note,
        )
        for key, dimension_key, cell_keys, label, note in metric_specs
    )
    if any(metric.count > denominator for metric in metrics):
        raise PermissionError("rich semantic partner metric exceeds denominator")

    source_coverage: tuple[tuple[str, int], ...] = ()
    if version == "rich-semantic-internal-aggregate-v4":
        coverage = _mapping(value["source_coverage"], label="source coverage")
        if set(coverage) != set(_SOURCE_KEYS):
            raise PermissionError("rich semantic source coverage keys are invalid")
        source_coverage = tuple(
            (
                key,
                _integer(coverage[key], label=f"source coverage {key}"),
            )
            for key in _SOURCE_KEYS
        )
        if any(count > denominator for _, count in source_coverage):
            raise PermissionError("rich semantic source coverage exceeds denominator")

    return PartnerSemanticSummary(
        projection_version="partner-semantic-diagnostic-v1",
        aggregate_sha256=_canonical_sha256(value),
        reviewed_denominator=denominator,
        metrics=metrics,
        source_coverage=source_coverage,
    )


_PARTNER_METRICS = (
    (
        "serious_product_builder",
        "Working product + substantial attributable execution",
        "Working or production maturity plus substantial, primary, or end-to-end attributable execution; a repository alone is insufficient.",
    ),
    (
        "advanced_technical_evidence",
        "Advanced or exceptional technical depth",
        "Non-trivial architecture, systems constraints, or production methods are visible in the work; language and stack lists alone do not qualify.",
    ),
    (
        "differentiated_problem",
        "Differentiated problem framing",
        "The work addresses a specific non-routine problem with a distinct approach or constraint; topic keywords alone do not qualify.",
    ),
    (
        "primary_execution",
        "Primary or end-to-end execution",
        "Application or submitted-project evidence attributes primary or end-to-end delivery to the participant; repository ownership alone does not qualify.",
    ),
    (
        "meaningful_validation",
        "Explicit external validation observed",
        "Reviewed evidence explicitly names users, adoption, traction, or credible third-party recognition. Non-observation means the current sources did not support this positive claim; it is not a negative rating.",
    ),
    (
        "substantive_technical_evidence",
        "Moderate-or-stronger technical depth",
        "Concrete implementation or systems evidence supports at least moderate technical depth; a stack list alone is insufficient.",
    ),
    (
        "standout_builder",
        "All five standout evidence conditions met",
        "Working or production maturity, advanced or exceptional technical depth, primary or end-to-end execution, meaningful or strong validation, and differentiated or ambitious problem framing are all required at once.",
    ),
)


def _privacy_safe_count(
    count: int, *, denominator: int, minimum_group_size: int,
) -> tuple[int | None, str]:
    complement = denominator - count
    if (
        (0 < count < minimum_group_size)
        or (0 < complement < minimum_group_size)
    ):
        return None, "withheld"
    return count, "reported"


def _project_public_semantic_groups(
    aggregate: Mapping[str, object],
    *,
    eligible_count: int | None,
    raw_eligible_count: int,
    minimum_group_size: int,
) -> tuple[PartnerSemanticMetric, ...]:
    raw_dimensions = _mapping(
        aggregate["taxonomy_dimensions"], label="taxonomy dimensions",
    )
    raw_counts: dict[str, int] = {}
    protected_counts: dict[str, tuple[int | None, str]] = {}
    for key in _PUBLIC_GROUP_ORDER:
        spec = _mapping(
            _PUBLIC_GROUP_SPECS[key], label=f"public semantic group {key}",
        )
        dimension_key = str(spec["dimension"])
        dimension = _mapping(
            raw_dimensions[dimension_key],
            label=f"taxonomy dimension {dimension_key}",
        )
        cells = _mapping(
            dimension["cells"], label=f"taxonomy dimension {dimension_key} cells",
        )
        unknown_count = _integer(
            dimension["unknown_count"],
            label=f"taxonomy dimension {dimension_key} unknown count",
        )
        known_denominator = raw_eligible_count - unknown_count
        values = spec["values"]
        assert isinstance(values, list)
        count = sum(
            _integer(
                cells[value], label=f"taxonomy cell {dimension_key}.{value}",
            )
            for value in values
        )
        if count > known_denominator:
            raise PermissionError(f"rich semantic public group {key} exceeds population")
        raw_counts[key] = count
        protected_counts[key] = (
            (None, "withheld")
            if eligible_count is None
            else (
                (None, "withheld")
                if "withheld" in {
                    _privacy_safe_count(
                        count,
                        denominator=known_denominator,
                        minimum_group_size=minimum_group_size,
                    )[1],
                    _privacy_safe_count(
                        count,
                        denominator=raw_eligible_count,
                        minimum_group_size=minimum_group_size,
                    )[1],
                }
                else (count, "reported")
            )
        )

    for broader, narrower in public_semantic_group_privacy_relations():
        difference = raw_counts[broader] - raw_counts[narrower]
        if difference < 0:
            raise PermissionError("rich semantic public group subset relation is invalid")
        if 0 < difference < minimum_group_size:
            protected_counts[broader] = (None, "withheld")

    return tuple(
        PartnerSemanticMetric(
            key=key,
            count=protected_counts[key][0],
            denominator=eligible_count,
            label=_public_label(key),
            note=str(_mapping(
                _PUBLIC_GROUP_SPECS[key], label=f"public semantic group {key}",
            )["definition"]),
            state=protected_counts[key][1],
        )
        for key in _PUBLIC_GROUP_ORDER
    )


def _project_taxonomy_dimensions(
    aggregate: Mapping[str, object],
    *,
    eligible_count: int | None,
    raw_eligible_count: int,
    minimum_group_size: int,
) -> tuple[PartnerSemanticDimension, ...]:
    registry = semantic_taxonomy_dimension_registry()
    raw_dimensions = _mapping(
        aggregate["taxonomy_dimensions"], label="taxonomy dimensions",
    )
    if set(raw_dimensions) != set(registry):
        raise PermissionError("rich semantic taxonomy dimension keys are invalid")

    projected: list[PartnerSemanticDimension] = []
    for field in _PARTNER_TAXONOMY_ORDER:
        spec = registry[field]
        raw_dimension = _mapping(
            raw_dimensions[field], label=f"taxonomy dimension {field}",
        )
        raw_cells = _mapping(
            raw_dimension.get("cells"), label=f"taxonomy dimension {field} cells",
        )
        if (
            raw_dimension.get("mode") != spec["mode"]
            or raw_dimension.get("denominator") != raw_eligible_count
            or set(raw_cells) != set(spec["values"])
        ):
            raise PermissionError(f"rich semantic taxonomy dimension {field} is invalid")
        raw_unknown = _integer(
            raw_dimension.get("unknown_count"),
            label=f"taxonomy dimension {field} unknown count",
        )
        if raw_unknown > raw_eligible_count:
            raise PermissionError(f"rich semantic taxonomy dimension {field} exceeds population")

        cell_states: list[tuple[str, int | None, str]] = []
        for code in _PARTNER_TAXONOMY_CODES[field]:
            raw_count = _integer(
                raw_cells.get(code), label=f"taxonomy cell {field}.{code}",
            )
            if raw_count > raw_eligible_count:
                raise PermissionError(f"rich semantic taxonomy cell {field}.{code} exceeds population")
            count, state = (
                (None, "withheld")
                if eligible_count is None
                else _privacy_safe_count(
                    raw_count,
                    denominator=raw_eligible_count,
                    minimum_group_size=minimum_group_size,
                )
            )
            cell_states.append((code, count, state))
        unknown_count, unknown_state = (
            (None, "withheld")
            if eligible_count is None
            else _privacy_safe_count(
                raw_unknown,
                denominator=raw_eligible_count,
                minimum_group_size=minimum_group_size,
            )
        )
        unsafe_exclusive_partition = False
        if spec["mode"] == "exclusive":
            omitted_codes = (
                set(str(code) for code in spec["values"])
                - set(_PARTNER_TAXONOMY_CODES[field])
                - {"unknown"}
            )
            omitted_residual = sum(
                _integer(
                    raw_cells[code], label=f"taxonomy cell {field}.{code}",
                )
                for code in omitted_codes
            )
            partition_total = (
                raw_unknown
                + omitted_residual
                + sum(
                    _integer(
                        raw_cells[code], label=f"taxonomy cell {field}.{code}",
                    )
                    for code in _PARTNER_TAXONOMY_CODES[field]
                )
            )
            if partition_total != raw_eligible_count:
                raise PermissionError(
                    f"rich semantic taxonomy dimension {field} partition is invalid",
                )
            unsafe_exclusive_partition = (
                0 < omitted_residual < minimum_group_size
            )
        if spec["mode"] == "exclusive" and (
            unsafe_exclusive_partition
            or unknown_state == "withheld"
            or any(state == "withheld" for _code, _count, state in cell_states)
        ):
            cell_states = [
                (code, None, "withheld") for code, _count, _state in cell_states
            ]
            unknown_count, unknown_state = None, "withheld"
        projected.append(PartnerSemanticDimension(
            key=field,
            family=str(spec["family"]),
            mode=str(spec["mode"]),
            denominator=eligible_count,
            label=_public_label(field),
            note=_PARTNER_TAXONOMY_NOTES[field],
            cells=tuple(
                PartnerSemanticCell(
                    key=code, label=_public_label(code), count=count, state=state,
                )
                for code, count, state in cell_states
            ),
            unknown_count=unknown_count,
            unknown_state=unknown_state,
        ))
    return tuple(projected)


def _project_population_aggregate(
    aggregate: Mapping[str, object],
    *,
    projection_version: str,
    aggregate_sha256: str,
    approval_sha256: str | None,
) -> PartnerSemanticSummary:
    population = _mapping(aggregate["population"], label="population")
    bindings = _mapping(aggregate["bindings"], label="bindings")
    metrics = _mapping(aggregate["metrics"], label="metrics")
    eligible = _integer(
        population["eligible_count"], label="eligible denominator", minimum=5,
    )
    assessed = _integer(population["assessed_count"], label="assessed count")
    unknown = _integer(population["unknown_count"], label="unknown count")
    excluded = _integer(population["excluded_count"], label="excluded count")
    total = _integer(population["total_count"], label="total population", minimum=5)
    minimum_group_size = _integer(
        aggregate["minimum_group_size"], label="minimum group size", minimum=5,
    )
    eligible_count, _eligible_state = _privacy_safe_count(
        eligible, denominator=total, minimum_group_size=minimum_group_size,
    )
    privacy_denominator = eligible if eligible_count is not None else total
    reviewed_count, _reviewed_state = _privacy_safe_count(
        assessed,
        denominator=privacy_denominator,
        minimum_group_size=minimum_group_size,
    )
    raw_metrics: dict[str, int] = {}
    protected_metrics: dict[str, tuple[int | None, str]] = {}
    for key, label, note in _PARTNER_METRICS:
        raw_count = _integer(metrics.get(key), label=f"metric {key}")
        raw_metrics[key] = raw_count
        protected_metrics[key] = _privacy_safe_count(
            raw_count,
            denominator=privacy_denominator,
            minimum_group_size=minimum_group_size,
        )
        if (
            reviewed_count is not None
            and 0 < reviewed_count - raw_count < minimum_group_size
        ):
            protected_metrics[key] = (None, "withheld")
    from community_os.semantic_metrics import metric_privacy_relations

    for broader, narrower in metric_privacy_relations():
        difference = raw_metrics[broader] - raw_metrics[narrower]
        if difference < 0:
            raise PermissionError("rich semantic metric subset relation is invalid")
        if 0 < difference < minimum_group_size:
            protected_metrics[broader] = (None, "withheld")

    projected_metrics: list[PartnerSemanticMetric] = []
    for key, label, note in _PARTNER_METRICS:
        count, state = protected_metrics[key]
        projected_metrics.append(PartnerSemanticMetric(
            key=key, count=count, denominator=eligible_count, label=label, note=note,
            state=state,
        ))

    coverage = _mapping(aggregate["source_coverage"], label="source coverage")
    source_coverage = tuple(
        (
            key,
            _privacy_safe_count(
                _integer(coverage[key], label=f"source coverage {key}"),
                denominator=privacy_denominator,
                minimum_group_size=minimum_group_size,
            )[0],
        )
        for key in ("application", "public_projects", "event_submission", "career_context")
    )
    dimensions = _project_taxonomy_dimensions(
        aggregate,
        eligible_count=eligible_count,
        raw_eligible_count=eligible,
        minimum_group_size=minimum_group_size,
    )
    public_groups = _project_public_semantic_groups(
        aggregate,
        eligible_count=eligible_count,
        raw_eligible_count=eligible,
        minimum_group_size=minimum_group_size,
    )
    whole_person_unresolved_count = (
        None
        if eligible_count is None
        else _privacy_safe_count(
            unknown,
            denominator=eligible,
            minimum_group_size=minimum_group_size,
        )[0]
    )
    return _seal_summary(PartnerSemanticSummary(
        projection_version=projection_version,
        aggregate_sha256=aggregate_sha256,
        reviewed_denominator=reviewed_count,
        metrics=tuple(projected_metrics),
        source_coverage=source_coverage,
        dimensions=dimensions,
        public_groups=public_groups,
        public_group_registry_version=_PUBLIC_GROUP_REGISTRY_VERSION,
        event_key=str(bindings["event_key"]),
        event_definition_sha256=str(bindings["event_definition_sha256"]),
        event_approval_sha256=str(bindings["event_approval_sha256"]),
        source_snapshot_sha256=str(bindings["source_snapshot_sha256"]),
        population_sha256=str(bindings["population_sha256"]),
        run_sha256=str(bindings["run_sha256"]),
        taxonomy_sha256=str(bindings["taxonomy_sha256"]),
        taxonomy_version=str(bindings["taxonomy_version"]),
        eligible_denominator=eligible_count,
        excluded_count=None,
        total_population=total,
        unknown_count=None,
        whole_person_unresolved_count=whole_person_unresolved_count,
        semantic_release_approval_sha256=approval_sha256,
    ))


def build_protected_partner_semantic_candidate_summary(
    aggregate: Mapping[str, object],
) -> PartnerSemanticSummary:
    """Build a local review candidate that is explicitly not partner-approved."""

    from community_os.semantic_release_approval import (
        validate_protected_semantic_aggregate,
    )

    normalized = validate_protected_semantic_aggregate(aggregate)
    return _project_population_aggregate(
        normalized,
        projection_version=_CANDIDATE_PROJECTION_VERSION,
        aggregate_sha256=_canonical_sha256(normalized),
        approval_sha256=None,
    )


def validate_partner_semantic_cohort_bundle(
    bundle: PartnerSemanticCohortBundle,
) -> PartnerSemanticCohortBundle:
    """Reject constructed, drifted, reordered, or cross-event cohort bundles."""

    if (
        not isinstance(bundle, PartnerSemanticCohortBundle)
        or bundle.projection_version != _COHORT_CANDIDATE_PROJECTION_VERSION
        or type(bundle.minimum_group_size) is not int
        or bundle.minimum_group_size < 5
    ):
        raise PermissionError("rich semantic cohort bundle is invalid")
    if not hmac.compare_digest(
        bundle._integrity_proof, _cohort_bundle_integrity_proof(bundle),
    ):
        raise PermissionError("rich semantic cohort bundle integrity is invalid")
    if len(bundle.cohorts) != len(_COHORT_SPECS):
        raise PermissionError("rich semantic cohort bundle set is invalid")

    shared_bindings: tuple[object, ...] | None = None
    for cohort, (key, label, _population_key) in zip(
        bundle.cohorts, _COHORT_SPECS, strict=True,
    ):
        if (
            not isinstance(cohort, PartnerSemanticCohort)
            or (cohort.key, cohort.label) != (key, label)
            or type(cohort.denominator) is not int
            or cohort.denominator < 5
            or type(cohort.unattributed_membership_unknown_count) is not int
            or cohort.unattributed_membership_unknown_count < 0
        ):
            raise PermissionError("rich semantic cohort bundle definition is invalid")
        summary = validate_partner_semantic_summary(cohort.summary)
        if (
            summary.projection_version != _CANDIDATE_PROJECTION_VERSION
            or summary.total_population is None
            or summary.total_population
            + cohort.unattributed_membership_unknown_count
            != cohort.denominator
        ):
            raise PermissionError("rich semantic cohort bundle denominator is invalid")
        cohort_bindings = (
            summary.event_key,
            summary.event_definition_sha256,
            summary.event_approval_sha256,
            summary.source_snapshot_sha256,
            summary.run_sha256,
            summary.taxonomy_sha256,
            summary.taxonomy_version,
        )
        if shared_bindings is None:
            shared_bindings = cohort_bindings
        elif cohort_bindings != shared_bindings:
            raise PermissionError("rich semantic cohort bundle bindings are mixed")
    if any(
        child.denominator > parent.denominator
        for parent, child in zip(bundle.cohorts, bundle.cohorts[1:])
    ):
        raise PermissionError("rich semantic cohort bundle denominators are not nested")
    public_counts = tuple(
        _public_summary_counts(cohort.summary) for cohort in bundle.cohorts
    )
    for parent, child in zip(public_counts, public_counts[1:]):
        if set(parent) != set(child):
            raise PermissionError("rich semantic cohort public count sets are mixed")
        for path, parent_count in parent.items():
            child_count = child[path]
            if parent_count is None or child_count is None:
                continue
            if child_count > parent_count:
                raise PermissionError(
                    "rich semantic public cohort count exceeds its parent"
                )
            if 0 < parent_count - child_count < bundle.minimum_group_size:
                raise PermissionError(
                    "rich semantic cross-cohort suppression is incomplete"
                )
    if "case:v1:" in json.dumps(
        _cohort_bundle_payload(bundle), ensure_ascii=True, sort_keys=True,
        separators=(",", ":"), allow_nan=False,
    ):
        raise PermissionError("rich semantic cohort bundle contains subject references")
    return bundle


def build_protected_partner_semantic_cohort_candidate_bundle(
    protected_aggregates: Mapping[str, Mapping[str, object]],
) -> PartnerSemanticCohortBundle:
    """Seal ordered aggregate-only candidates for all accepted/attended views.

    ``attended`` is the public label for the aggregate built from the protected
    ``present`` membership fact. Every cohort is projected independently, so one
    cohort's privacy-safe cells never authorize another cohort's cells.
    """

    expected_keys = tuple(spec[0] for spec in _COHORT_SPECS)
    if (
        not isinstance(protected_aggregates, Mapping)
        or set(protected_aggregates) != set(expected_keys)
        or len(protected_aggregates) != len(expected_keys)
    ):
        raise PermissionError("rich semantic cohort aggregate set is invalid")
    cohorts: list[PartnerSemanticCohort] = []
    projection_aggregates: list[Mapping[str, object]] = []
    minimum_group_sizes: set[int] = set()
    for key, label, population_key in _COHORT_SPECS:
        aggregate = _mapping(
            protected_aggregates[key], label=f"protected {key} aggregate",
        )
        unattributed = aggregate.get(_UNATTRIBUTED_MEMBERSHIP_KEY, 0)
        if type(unattributed) is not int or unattributed < 0:
            raise PermissionError(
                "rich semantic cohort linkage-unknown metadata is invalid"
            )
        projection_aggregate = dict(aggregate)
        projection_aggregate.pop(_UNATTRIBUTED_MEMBERSHIP_KEY, None)
        bindings = _mapping(
            projection_aggregate.get("bindings"), label=f"{key} bindings",
        )
        if bindings.get("population_key") != population_key:
            raise PermissionError(
                "rich semantic cohort aggregate population binding is invalid"
            )
        summary = build_protected_partner_semantic_candidate_summary(
            projection_aggregate,
        )
        attributed_denominator = summary.total_population
        if type(attributed_denominator) is not int:
            raise PermissionError("rich semantic cohort denominator is invalid")
        minimum_group_size = projection_aggregate.get("minimum_group_size")
        if type(minimum_group_size) is not int or minimum_group_size < 5:
            raise PermissionError("rich semantic cohort privacy threshold is invalid")
        minimum_group_sizes.add(minimum_group_size)
        projection_aggregates.append(projection_aggregate)
        cohorts.append(PartnerSemanticCohort(
            key=key,
            label=label,
            denominator=attributed_denominator + unattributed,
            unattributed_membership_unknown_count=unattributed,
            summary=summary,
        ))
    if len(minimum_group_sizes) != 1:
        raise PermissionError("rich semantic cohort privacy thresholds are mixed")
    minimum_group_size = next(iter(minimum_group_sizes))
    protected_cohorts = _apply_cross_cohort_suppression(
        tuple(cohorts), tuple(projection_aggregates),
        minimum_group_size=minimum_group_size,
    )
    sealed = _seal_cohort_bundle(PartnerSemanticCohortBundle(
        projection_version=_COHORT_CANDIDATE_PROJECTION_VERSION,
        minimum_group_size=minimum_group_size,
        cohorts=protected_cohorts,
    ))
    return validate_partner_semantic_cohort_bundle(sealed)


def build_partner_semantic_summary(
    approved_release: object, *, now: datetime, approval_secret: bytes,
) -> PartnerSemanticSummary:
    """Project only an exact, human-approved population aggregate."""

    from community_os.semantic_release_approval import (
        ApprovedSemanticRelease,
        SemanticReleaseApprovalError,
        build_semantic_release_candidate,
        validate_semantic_release_approval_record,
    )

    if not isinstance(approved_release, ApprovedSemanticRelease):
        raise PermissionError("rich semantic partner projection requires human approval")
    approval = _mapping(approved_release.approval, label="release approval")
    try:
        revalidated = validate_semantic_release_approval_record(
            approval, candidate=approved_release.candidate, now=now,
            signing_secret=approval_secret,
        )
    except SemanticReleaseApprovalError as error:
        raise PermissionError(
            "rich semantic human approval record is invalid or expired",
        ) from error
    if (
        approved_release.version != revalidated.version
        or approved_release.actor_type != "human"
        or not hmac.compare_digest(revalidated.sha256, approved_release.sha256)
    ):
        raise PermissionError("rich semantic human approval record drifted")
    revalidated_approval = _mapping(
        revalidated.approval, label="revalidated release approval",
    )
    approval_bindings = _mapping(
        revalidated_approval.get("bindings"), label="release approval bindings",
    )
    aggregate = _mapping(revalidated.aggregate, label="approved aggregate")
    reconstructed = build_semantic_release_candidate(
        aggregate,
        qa_sha256=str(approval_bindings.get("qa_sha256", "")),
        report_candidate_sha256=str(
            approval_bindings.get("report_candidate_sha256", ""),
        ),
        html_sha256=str(approval_bindings.get("html_sha256", "")),
        pdf_sha256=str(approval_bindings.get("pdf_sha256", "")),
    )
    if not hmac.compare_digest(
        json.dumps(
            reconstructed.approval_bindings(), ensure_ascii=True, sort_keys=True,
            separators=(",", ":"), allow_nan=False,
        ).encode("utf-8"),
        json.dumps(
            approval_bindings, ensure_ascii=True, sort_keys=True,
            separators=(",", ":"), allow_nan=False,
        ).encode("utf-8"),
    ):
        raise PermissionError("rich semantic human approval binding drifted")

    summary = _project_population_aggregate(
        reconstructed.aggregate,
        projection_version=_APPROVED_PROJECTION_VERSION,
        aggregate_sha256=str(approval_bindings["aggregate_sha256"]),
        approval_sha256=revalidated.sha256,
    )
    return _seal_summary(replace(
        summary,
        release_artifact_hashes=tuple(
            (key, str(approval_bindings[key]))
            for key in (
                "html_sha256", "pdf_sha256", "qa_sha256",
                "report_candidate_sha256",
            )
        ),
    ))


def load_legacy_diagnostic_semantic_summary(path: str | Path) -> PartnerSemanticSummary:
    """Load a legacy protected aggregate for private diagnostics only."""

    source = Path(path)
    if source.is_symlink() or not source.is_file():
        raise PermissionError("rich semantic aggregate is missing or unsafe")
    try:
        value = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise PermissionError("rich semantic aggregate is unreadable") from error
    if not isinstance(value, dict):
        raise PermissionError("rich semantic aggregate is invalid")
    return build_legacy_diagnostic_semantic_summary(value)


def load_partner_semantic_summary(
    path: str | Path,
    *,
    approval_path: str | Path | None = None,
    now: datetime | None = None,
    approval_secret: bytes | None = None,
) -> PartnerSemanticSummary:
    """Load and project only an aggregate with an exact current approval file."""

    if approval_path is None or now is None or approval_secret is None:
        raise PermissionError("rich semantic partner projection requires human approval")
    from community_os.semantic_release_approval import load_approved_semantic_release

    approved = load_approved_semantic_release(
        path, approval_path, now=now, signing_secret=approval_secret,
    )
    return build_partner_semantic_summary(
        approved, now=now, approval_secret=approval_secret,
    )


def load_protected_partner_semantic_candidate_summary(
    path: str | Path,
) -> PartnerSemanticSummary:
    """Load a protected population aggregate for local human-review rendering."""

    source = Path(path)
    if source.is_symlink() or not source.is_file():
        raise PermissionError("rich semantic candidate aggregate is missing or unsafe")
    try:
        value = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise PermissionError("rich semantic candidate aggregate is unreadable") from error
    if not isinstance(value, dict):
        raise PermissionError("rich semantic candidate aggregate is invalid")
    return build_protected_partner_semantic_candidate_summary(value)
