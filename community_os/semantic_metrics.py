"""Population-complete semantic facts and immutable partner metric definitions.

This module deliberately keeps person-level facts inside the protected pipeline.  It
owns deterministic schema validation, population reconciliation, and metric counting;
it does not authorize partner publication.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from datetime import UTC, datetime
import hashlib
import json
import re
from typing import Any

from community_os.enrichment.rich_semantic_assessment import (
    ASSESSMENT_ENUMS,
    REASON_CODES,
)
from community_os.enrichment.semantic_taxonomy import (
    ALL_DIMENSIONS,
    CAREER_ENUMS,
    CAREER_LIST_ENUMS,
    CAREER_SCALAR_FIELDS,
    PROJECT_ENUMS,
    PROJECT_LIST_ENUMS,
    PROJECT_SCALAR_FIELDS,
    TAXONOMY_SHA256,
    TAXONOMY_VERSION,
    semantic_taxonomy_contract,
    validate_semantic_taxonomy_fact,
)


LEGACY_FACT_VERSION = "population-semantic-fact-v1"
FACT_VERSION = "population-semantic-fact-v2"
LEGACY_AGGREGATE_VERSION = "population-semantic-aggregate-v1"
AGGREGATE_VERSION = "population-semantic-aggregate-v2"
REGISTRY_VERSION = "partner-metrics-v1"
PUBLIC_SEMANTIC_GROUP_REGISTRY_VERSION = "partner-public-semantic-groups-v1"

_HASH = re.compile(r"^[0-9a-f]{64}$")
_EVENT_KEY = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_SUBJECT = re.compile(r"^case:v1:[0-9a-f]{64}$")
_EVIDENCE_REF = re.compile(
    r"^(?:project|application|devpost|role)_[0-9]{2}:"
    r"(?:achievement|demo|deployment|description|experience|ownership|project|"
    r"readme|release|title)$"
)

_ASSESSMENT_STATES = frozenset({
    "assessed", "no_evidence", "provider_unavailable", "excluded", "conflict",
    "rejected",
})
_UNKNOWN_STATES = _ASSESSMENT_STATES - {"assessed", "excluded"}
_POPULATION_REASON_CODES = REASON_CODES | frozenset({
    "no_semantic_evidence", "semantic_evidence_conflict",
    "semantic_provider_unavailable", "semantic_review_rejected", "subject_excluded",
})
_DIMENSION_KEYS = frozenset({
    "builder_level", "execution_scope", "external_validation", "originality",
    "product_maturity", "technical_depth",
})
_LEGACY_FACT_KEYS = frozenset({
    "assessment_state", "bindings", "cohort_membership", "confidence",
    "evidence_refs", "evidence_scopes", "fact_version", "population_key",
    "reason_codes", "review_states", "semantic_dimensions", "subject_ref",
})
_FACT_KEYS = _LEGACY_FACT_KEYS | {"semantic_taxonomy"}
_BINDING_KEYS = frozenset({
    "event_approval_sha256", "event_definition_sha256", "event_key",
    "metric_registry_sha256", "metric_registry_version", "population_key",
    "population_sha256", "run_sha256", "source_snapshot_sha256",
    "taxonomy_sha256", "taxonomy_version",
})
_COHORT_KEYS = frozenset({"accepted", "applied", "present", "submitted"})
_COHORT_STATES = frozenset({"member", "not_member", "unknown"})
SEMANTIC_COHORT_KEYS = ("all", "accepted", "attended")
_SEMANTIC_COHORT_SPECS = {
    "all": ("applied", "all_applicants"),
    "accepted": ("accepted", "accepted_participants"),
    "attended": ("present", "confirmed_attendees"),
}
_SOURCE_KEYS = frozenset({
    "application", "career_context", "event_submission", "public_projects",
})
_SOURCE_STATES = frozenset({
    "observed", "not_provided", "provider_unavailable", "excluded", "conflict",
})
_REVIEW_KEYS = frozenset({"agent", "human", "model", "system"})
_REVIEW_STATES = {
    "agent": frozenset({"reviewed", "not_reviewed"}),
    "human": frozenset({"approved", "corrected", "rejected", "not_required"}),
    "model": frozenset({"complete", "not_run"}),
    "system": frozenset({"valid"}),
}


# The registry is data, not executable callbacks. Its canonical JSON hash is part of
# every fact, aggregate, and release approval.
_METRIC_REGISTRY: dict[str, object] = {
    "registry_version": REGISTRY_VERSION,
    "metrics": {
        "advanced_technical_evidence": {
            "definition": "Advanced or exceptional technical depth.",
            "predicate": {
                "in": {"path": "technical_depth", "values": ["advanced", "exceptional"]},
            },
        },
        "differentiated_problem": {
            "definition": "Differentiated or ambitious problem framing.",
            "predicate": {
                "in": {"path": "originality", "values": ["ambitious", "differentiated"]},
            },
        },
        "meaningful_validation": {
            "definition": "Meaningful or strong external validation.",
            "predicate": {
                "in": {"path": "external_validation", "values": ["meaningful", "strong"]},
            },
        },
        "primary_execution": {
            "definition": "Primary-builder or end-to-end execution evidence.",
            "predicate": {
                "in": {
                    "path": "execution_scope",
                    "values": ["end_to_end_builder", "primary_builder"],
                },
            },
        },
        "serious_product_builder": {
            "definition": "Substantial or standout builder with working or production maturity.",
            "predicate": {
                "all": [
                    {
                        "in": {
                            "path": "builder_level",
                            "values": ["standout", "substantial"],
                        },
                    },
                    {
                        "in": {
                            "path": "product_maturity",
                            "values": ["production_evidence", "working_product"],
                        },
                    },
                ],
            },
        },
        "standout_builder": {
            "definition": "Standout builder tier.",
            "predicate": {"eq": {"path": "builder_level", "value": "standout"}},
        },
        "substantive_technical_evidence": {
            "definition": "Moderate, advanced, or exceptional technical depth.",
            "predicate": {
                "in": {
                    "path": "technical_depth",
                    "values": ["advanced", "exceptional", "moderate"],
                },
            },
        },
    },
    "privacy_relations": [
        {
            "broader_metric": "substantive_technical_evidence",
            "narrower_metric": "advanced_technical_evidence",
        },
    ],
}

# These public unions are fixed before event counts are observed. They deliberately
# coarsen adjacent positive tiers so partner reporting can be useful without exposing
# a rare underlying taxonomy cell.
_PUBLIC_SEMANTIC_GROUP_REGISTRY: dict[str, object] = {
    "registry_version": PUBLIC_SEMANTIC_GROUP_REGISTRY_VERSION,
    "groups": {
        "advanced_or_exceptional_technical": {
            "definition": "Advanced or exceptional technical evidence.",
            "dimension": "technical_depth",
            "values": ["advanced", "exceptional"],
        },
        "differentiated_or_ambitious_problem": {
            "definition": "Differentiated or ambitious problem framing.",
            "dimension": "problem_differentiation",
            "values": ["ambitious", "differentiated"],
        },
        "early_or_greater_validation": {
            "definition": "Early, meaningful, or strong external validation.",
            "dimension": "external_validation",
            "values": ["early_signal", "meaningful", "strong"],
        },
        "meaningful_or_strong_validation": {
            "definition": "Meaningful or strong external validation.",
            "dimension": "external_validation",
            "values": ["meaningful", "strong"],
        },
        "moderate_or_stronger_technical": {
            "definition": "Moderate, advanced, or exceptional technical evidence.",
            "dimension": "technical_depth",
            "values": ["advanced", "exceptional", "moderate"],
        },
        "prototype_or_beyond": {
            "definition": "Prototype, working-product, or production maturity.",
            "dimension": "product_maturity",
            "values": ["production_evidence", "prototype", "working_product"],
        },
        "substantial_or_greater_execution": {
            "definition": "Substantial, primary, or end-to-end execution evidence.",
            "dimension": "execution_scope",
            "values": [
                "end_to_end_builder", "primary_builder", "substantial_contributor",
            ],
        },
        "working_or_production": {
            "definition": "Working-product or production maturity.",
            "dimension": "product_maturity",
            "values": ["production_evidence", "working_product"],
        },
    },
    "privacy_relations": [
        {
            "broader_group": "early_or_greater_validation",
            "narrower_group": "meaningful_or_strong_validation",
        },
        {
            "broader_group": "moderate_or_stronger_technical",
            "narrower_group": "advanced_or_exceptional_technical",
        },
        {
            "broader_group": "prototype_or_beyond",
            "narrower_group": "working_or_production",
        },
    ],
}

# This is the single allowlist for person-level taxonomy values that can become
# partner-facing aggregate cells. Values omitted here remain protected diagnostics.
_PARTNER_REPORT_TAXONOMY_CODES: dict[str, tuple[str, ...]] = {
    "product_maturity": ("prototype", "working_product", "production_evidence"),
    "technical_depth": ("moderate", "advanced", "exceptional"),
    "execution_scope": (
        "contributor", "substantial_contributor", "primary_builder",
        "end_to_end_builder",
    ),
    "external_validation": ("early_signal", "meaningful", "strong"),
    "problem_differentiation": ("differentiated", "ambitious"),
    "market_domains": (
        "climate_energy", "commerce_consumer", "developer_infrastructure",
        "education_learning", "enterprise_operations", "financial_services",
        "healthcare_life_sciences", "industrial_manufacturing", "media_creative",
        "mobility_logistics", "public_civic", "security_trust",
    ),
    "technical_methods": (
        "applied_ai_ml", "automation_orchestration", "blockchain_web3",
        "cloud_infrastructure", "computer_vision", "cybersecurity",
        "data_engineering", "distributed_systems", "hardware_iot",
        "mobile_native", "natural_language_processing", "realtime_systems",
        "spatial_computing", "web_full_stack",
    ),
    "demonstrated_capabilities": (
        "backend_engineering", "data_ai_engineering", "frontend_engineering",
        "go_to_market", "hardware_engineering", "infrastructure_devops",
        "mobile_engineering", "product_design", "product_engineering",
        "research_experimentation", "security_engineering",
        "technical_product_leadership",
    ),
    "career_stage": ("early_career", "mid_career", "senior", "executive"),
    "founder_state": ("former_founder", "current_founder"),
    "leadership_state": (
        "team_lead", "organizational_leader", "executive_leader",
    ),
    "career_functions": (
        "commercial", "data_ai", "design", "investing", "operations",
        "product", "research", "software_engineering",
    ),
    "career_delivery": (
        "customer_delivery", "founded_venture", "led_teams",
        "open_source_maintenance", "research_to_practice", "scaled_systems",
        "shipped_products",
    ),
}


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise ValueError("semantic metric value is not canonical JSON") from error


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _mapping(value: object, *, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ValueError(f"semantic {label} is invalid")
    return value


def _exact(
    value: object, *, label: str, keys: frozenset[str],
) -> Mapping[str, object]:
    mapping = _mapping(value, label=label)
    if set(mapping) != keys:
        raise ValueError(f"semantic {label} keys are invalid")
    return mapping


def _hash(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not _HASH.fullmatch(value):
        raise ValueError(f"semantic {label} is invalid")
    return value


def _plain_code(value: object, *, label: str) -> str:
    if (
        not isinstance(value, str) or not value or len(value) > 128
        or not re.fullmatch(r"^[a-z][a-z0-9._-]*$", value)
    ):
        raise ValueError(f"semantic {label} is invalid")
    return value


def _timestamp(value: datetime) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("semantic aggregate timestamp requires a timezone")
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _validate_predicate(value: object) -> None:
    predicate = _mapping(value, label="metric predicate")
    if set(predicate) == {"all"}:
        clauses = predicate["all"]
        if not isinstance(clauses, list) or len(clauses) < 2:
            raise ValueError("semantic metric all predicate is invalid")
        for clause in clauses:
            _validate_predicate(clause)
        return
    if set(predicate) == {"eq"}:
        clause = _exact(
            predicate["eq"], label="metric eq predicate",
            keys=frozenset({"path", "value"}),
        )
        path = clause["path"]
        if path not in _DIMENSION_KEYS or clause["value"] not in ASSESSMENT_ENUMS[path]:
            raise ValueError("semantic metric eq predicate is invalid")
        return
    if set(predicate) == {"in"}:
        clause = _exact(
            predicate["in"], label="metric in predicate",
            keys=frozenset({"path", "values"}),
        )
        path = clause["path"]
        values = clause["values"]
        if (
            path not in _DIMENSION_KEYS or not isinstance(values, list) or not values
            or values != sorted(set(values))
            or any(item not in ASSESSMENT_ENUMS[path] for item in values)
        ):
            raise ValueError("semantic metric in predicate is invalid")
        return
    raise ValueError("semantic metric predicate operator is invalid")


def _validate_registry() -> None:
    root = _exact(
        _METRIC_REGISTRY, label="metric registry",
        keys=frozenset({"metrics", "privacy_relations", "registry_version"}),
    )
    if root["registry_version"] != REGISTRY_VERSION:
        raise ValueError("semantic metric registry version is invalid")
    metrics = _mapping(root["metrics"], label="metric registry metrics")
    if set(metrics) != {
        "advanced_technical_evidence", "differentiated_problem",
        "meaningful_validation", "primary_execution", "serious_product_builder",
        "standout_builder", "substantive_technical_evidence",
    }:
        raise ValueError("semantic metric registry keys are invalid")
    for key, raw_spec in metrics.items():
        spec = _exact(
            raw_spec, label=f"metric registry {key}",
            keys=frozenset({"definition", "predicate"}),
        )
        if not isinstance(spec["definition"], str) or not spec["definition"]:
            raise ValueError("semantic metric definition is invalid")
        _validate_predicate(spec["predicate"])
    relations = root["privacy_relations"]
    if not isinstance(relations, list) or not relations:
        raise ValueError("semantic metric privacy relations are invalid")
    for relation in relations:
        value = _exact(
            relation, label="metric privacy relation",
            keys=frozenset({"broader_metric", "narrower_metric"}),
        )
        if (
            value["broader_metric"] not in metrics
            or value["narrower_metric"] not in metrics
            or value["broader_metric"] == value["narrower_metric"]
        ):
            raise ValueError("semantic metric privacy relation is invalid")


_validate_registry()


def _validate_public_semantic_group_registry() -> None:
    root = _exact(
        _PUBLIC_SEMANTIC_GROUP_REGISTRY,
        label="public semantic group registry",
        keys=frozenset({"groups", "privacy_relations", "registry_version"}),
    )
    if root["registry_version"] != PUBLIC_SEMANTIC_GROUP_REGISTRY_VERSION:
        raise ValueError("public semantic group registry version is invalid")
    groups = _mapping(root["groups"], label="public semantic groups")
    contract = semantic_taxonomy_contract()
    taxonomy: dict[str, dict[str, object]] = {}
    for family in ("project", "career"):
        dimensions = _mapping(contract[family], label=f"{family} taxonomy")
        for field, raw_spec in dimensions.items():
            spec = _mapping(raw_spec, label=f"taxonomy dimension {field}")
            taxonomy[field] = {
                "mode": "exclusive" if spec["kind"] == "scalar" else "overlapping",
                "values": list(spec["values"]),
            }
    for key, raw_spec in groups.items():
        _plain_code(key, label="public semantic group key")
        spec = _exact(
            raw_spec,
            label=f"public semantic group {key}",
            keys=frozenset({"definition", "dimension", "values"}),
        )
        dimension = spec["dimension"]
        values = spec["values"]
        if (
            not isinstance(spec["definition"], str)
            or not spec["definition"]
            or dimension not in taxonomy
            or taxonomy[str(dimension)]["mode"] != "exclusive"
            or not isinstance(values, list)
            or not values
            or values != sorted(set(values))
            or any(value not in taxonomy[str(dimension)]["values"] for value in values)
        ):
            raise ValueError(f"public semantic group {key} is invalid")
    relations = root["privacy_relations"]
    if not isinstance(relations, list):
        raise ValueError("public semantic group privacy relations are invalid")
    for raw_relation in relations:
        relation = _exact(
            raw_relation,
            label="public semantic group privacy relation",
            keys=frozenset({"broader_group", "narrower_group"}),
        )
        broader = relation["broader_group"]
        narrower = relation["narrower_group"]
        if broader not in groups or narrower not in groups or broader == narrower:
            raise ValueError("public semantic group privacy relation is invalid")
        broader_spec = _mapping(groups[broader], label="broader public semantic group")
        narrower_spec = _mapping(groups[narrower], label="narrower public semantic group")
        if (
            broader_spec["dimension"] != narrower_spec["dimension"]
            or not set(narrower_spec["values"]) < set(broader_spec["values"])
        ):
            raise ValueError("public semantic group privacy relation is invalid")


_validate_public_semantic_group_registry()


def metric_registry() -> dict[str, object]:
    """Return a detached canonical copy of the immutable registry."""

    return json.loads(_canonical(_METRIC_REGISTRY))


def metric_registry_sha256() -> str:
    return _sha256(_METRIC_REGISTRY)


def public_semantic_group_registry() -> dict[str, object]:
    """Return a detached copy of the fixed partner-facing semantic unions."""

    return json.loads(_canonical(_PUBLIC_SEMANTIC_GROUP_REGISTRY))


def public_semantic_group_privacy_relations() -> tuple[tuple[str, str], ...]:
    relations = _PUBLIC_SEMANTIC_GROUP_REGISTRY["privacy_relations"]
    assert isinstance(relations, list)
    return tuple(
        (str(item["broader_group"]), str(item["narrower_group"]))
        for item in relations
        if isinstance(item, Mapping)
    )


def semantic_taxonomy_sha256(taxonomy_version: str) -> str:
    """Hash the exact controlled semantic vocabulary used by one event."""

    version = _plain_code(taxonomy_version, label="taxonomy version")
    if version == TAXONOMY_VERSION:
        return TAXONOMY_SHA256
    return _sha256({
        "assessment_enums": {
            key: sorted(values) for key, values in sorted(ASSESSMENT_ENUMS.items())
        },
        "population_reason_codes": sorted(_POPULATION_REASON_CODES),
        "taxonomy_version": version,
    })


def metric_privacy_relations() -> tuple[tuple[str, str], ...]:
    relations = _METRIC_REGISTRY["privacy_relations"]
    assert isinstance(relations, list)
    return tuple(
        (str(item["broader_metric"]), str(item["narrower_metric"]))
        for item in relations
        if isinstance(item, Mapping)
    )


def population_snapshot_sha256(facts: Iterable[Mapping[str, object]]) -> str:
    """Hash population membership and coverage state without self-reference."""

    members: list[dict[str, object]] = []
    for raw in facts:
        fact = _mapping(raw, label="population fact")
        members.append({
            "assessment_state": fact.get("assessment_state"),
            "cohort_membership": fact.get("cohort_membership"),
            "population_key": fact.get("population_key"),
            "subject_ref": fact.get("subject_ref"),
        })
    members.sort(key=lambda item: str(item["subject_ref"]))
    return _sha256(members)


def _validate_bindings(value: object, *, population_key: str) -> dict[str, str]:
    raw = _exact(value, label="fact bindings", keys=_BINDING_KEYS)
    result = {
        "event_approval_sha256": _hash(
            raw["event_approval_sha256"], label="event approval hash",
        ),
        "event_definition_sha256": _hash(
            raw["event_definition_sha256"], label="event definition hash",
        ),
        "event_key": raw["event_key"],
        "metric_registry_sha256": _hash(
            raw["metric_registry_sha256"], label="metric registry hash",
        ),
        "metric_registry_version": _plain_code(
            raw["metric_registry_version"], label="metric registry version",
        ),
        "population_key": _plain_code(raw["population_key"], label="population key"),
        "population_sha256": _hash(raw["population_sha256"], label="population hash"),
        "run_sha256": _hash(raw["run_sha256"], label="run hash"),
        "source_snapshot_sha256": _hash(
            raw["source_snapshot_sha256"], label="source snapshot hash",
        ),
        "taxonomy_sha256": _hash(raw["taxonomy_sha256"], label="taxonomy hash"),
        "taxonomy_version": _plain_code(
            raw["taxonomy_version"], label="taxonomy version",
        ),
    }
    if (
        not isinstance(result["event_key"], str)
        or not _EVENT_KEY.fullmatch(result["event_key"])
    ):
        raise ValueError("semantic event key is invalid")
    if (
        result["metric_registry_version"] != REGISTRY_VERSION
        or result["metric_registry_sha256"] != metric_registry_sha256()
        or result["population_key"] != population_key
        or result["taxonomy_sha256"]
        != semantic_taxonomy_sha256(result["taxonomy_version"])
    ):
        raise ValueError("semantic fact binding mismatch")
    return result


def _validate_string_list(
    value: object, *, label: str, allowed: frozenset[str] | None = None,
) -> list[str]:
    if (
        not isinstance(value, list) or not value or value != sorted(set(value))
        or any(not isinstance(item, str) for item in value)
        or (allowed is not None and any(item not in allowed for item in value))
    ):
        raise ValueError(f"semantic {label} is invalid")
    return list(value)


def _validate_fact(value: object) -> dict[str, object]:
    candidate = _mapping(value, label="fact")
    version = candidate.get("fact_version")
    expected_keys = (
        _FACT_KEYS if version == FACT_VERSION
        else _LEGACY_FACT_KEYS if version == LEGACY_FACT_VERSION
        else None
    )
    if expected_keys is None:
        raise ValueError("semantic fact version is invalid")
    raw = _exact(candidate, label="fact", keys=expected_keys)
    subject_ref = raw["subject_ref"]
    if not isinstance(subject_ref, str) or not _SUBJECT.fullmatch(subject_ref):
        raise ValueError("semantic fact subject reference is invalid")
    population_key = _plain_code(raw["population_key"], label="population key")
    state = raw["assessment_state"]
    if state not in _ASSESSMENT_STATES:
        raise ValueError("semantic assessment state is invalid")
    bindings = _validate_bindings(raw["bindings"], population_key=population_key)

    cohort = _exact(raw["cohort_membership"], label="cohort membership", keys=_COHORT_KEYS)
    if any(item not in _COHORT_STATES for item in cohort.values()):
        raise ValueError("semantic cohort membership state is invalid")

    scopes = _exact(raw["evidence_scopes"], label="evidence scopes", keys=_SOURCE_KEYS)
    if any(item not in _SOURCE_STATES for item in scopes.values()):
        raise ValueError("semantic evidence scope state is invalid")
    if state == "excluded" and any(item != "excluded" for item in scopes.values()):
        raise ValueError("semantic excluded fact retains evidence scope")
    if state == "provider_unavailable" and "provider_unavailable" not in scopes.values():
        raise ValueError("semantic unavailable fact lacks provider state")

    dimensions = _exact(
        raw["semantic_dimensions"], label="semantic dimensions", keys=_DIMENSION_KEYS,
    )
    confidence = raw["confidence"]
    evidence_refs = raw["evidence_refs"]
    if not isinstance(evidence_refs, list) or evidence_refs != sorted(set(evidence_refs)):
        raise ValueError("semantic evidence references are invalid")
    if any(
        not isinstance(reference, str) or not _EVIDENCE_REF.fullmatch(reference)
        for reference in evidence_refs
    ):
        raise ValueError("semantic evidence references are invalid")
    if state == "assessed":
        if any(dimensions[key] not in ASSESSMENT_ENUMS[key] for key in _DIMENSION_KEYS):
            raise ValueError("semantic assessed dimensions are invalid")
        if confidence not in {"low", "medium", "high"} or not evidence_refs:
            raise ValueError("semantic assessed evidence is incomplete")
    elif (
        any(dimensions[key] is not None for key in _DIMENSION_KEYS)
        or confidence != "unknown" or evidence_refs
    ):
        raise ValueError("semantic non-assessed fact contains positive evidence")

    reasons = _validate_string_list(
        raw["reason_codes"], label="reason codes", allowed=_POPULATION_REASON_CODES,
    )
    review = _exact(raw["review_states"], label="review states", keys=_REVIEW_KEYS)
    if any(review[key] not in _REVIEW_STATES[key] for key in _REVIEW_KEYS):
        raise ValueError("semantic review state is invalid")
    if state == "assessed" and (
        review["agent"] != "reviewed" or review["model"] != "complete"
    ):
        raise ValueError("semantic assessed fact lacks agent review")
    if (
        state == "assessed" and confidence == "low"
        and review["human"] not in {"approved", "corrected"}
    ):
        raise ValueError("semantic uncertain fact lacks human review")
    if state == "assessed" and review["human"] == "rejected":
        raise ValueError("semantic assessed fact has rejected human review")
    if state == "rejected" and review["human"] != "rejected":
        raise ValueError("semantic rejected fact lacks rejection review")

    taxonomy_record: dict[str, object] | None = None
    if version == FACT_VERSION:
        taxonomy_value = raw["semantic_taxonomy"]
        if state == "assessed":
            try:
                taxonomy = validate_semantic_taxonomy_fact(taxonomy_value)
            except ValueError as error:
                raise ValueError("semantic population taxonomy is invalid") from error
            expected_overlap = {
                "product_maturity": dimensions["product_maturity"],
                "technical_depth": dimensions["technical_depth"],
                "execution_scope": dimensions["execution_scope"],
                "external_validation": (
                    "none_observed"
                    if dimensions["external_validation"] == "none"
                    else dimensions["external_validation"]
                ),
                "problem_differentiation": dimensions["originality"],
            }
            taxonomy_refs = {
                reference
                for references in taxonomy.evidence_by_dimension.values()
                for reference in references
            }
            if (
                taxonomy.builder_tier != dimensions["builder_level"]
                or any(
                    taxonomy.project[field] != expected
                    for field, expected in expected_overlap.items()
                )
                or taxonomy_refs != set(evidence_refs)
            ):
                raise ValueError("semantic population taxonomy binding mismatch")
            taxonomy_record = {
                "version": taxonomy.version,
                "project": taxonomy.project,
                "career": taxonomy.career,
                "evidence_by_dimension": taxonomy.evidence_by_dimension,
            }
        elif taxonomy_value is not None:
            raise ValueError("semantic non-assessed fact contains taxonomy")

    normalized = {
        "assessment_state": state,
        "bindings": bindings,
        "cohort_membership": dict(sorted(cohort.items())),
        "confidence": confidence,
        "evidence_refs": list(evidence_refs),
        "evidence_scopes": dict(sorted(scopes.items())),
        "fact_version": version,
        "population_key": population_key,
        "reason_codes": reasons,
        "review_states": dict(sorted(review.items())),
        "semantic_dimensions": dict(sorted(dimensions.items())),
        "subject_ref": subject_ref,
    }
    if version == FACT_VERSION:
        normalized["semantic_taxonomy"] = taxonomy_record
    return normalized


def validate_semantic_facts(
    facts: Iterable[Mapping[str, object]],
    *,
    expected_subject_refs: Sequence[str] | None = None,
) -> tuple[dict[str, object], ...]:
    normalized = tuple(_validate_fact(fact) for fact in facts)
    if not normalized:
        raise ValueError("semantic population facts are empty")
    versions = {str(fact["fact_version"]) for fact in normalized}
    if len(versions) != 1:
        raise ValueError("semantic population contains mixed fact versions")
    subject_refs = [str(fact["subject_ref"]) for fact in normalized]
    if len(subject_refs) != len(set(subject_refs)):
        raise ValueError("semantic population contains duplicate subjects")
    if expected_subject_refs is not None:
        expected = list(expected_subject_refs)
        if (
            expected != sorted(set(expected))
            or any(
                not isinstance(item, str) or not _SUBJECT.fullmatch(item)
                for item in expected
            )
            or set(subject_refs) != set(expected)
        ):
            raise ValueError("semantic population subjects do not reconcile")
    first_bindings = normalized[0]["bindings"]
    if any(fact["bindings"] != first_bindings for fact in normalized[1:]):
        raise ValueError("semantic population contains mixed bindings")
    expected_population_hash = population_snapshot_sha256(normalized)
    if first_bindings["population_sha256"] != expected_population_hash:
        raise ValueError("semantic population hash mismatch")
    return tuple(sorted(normalized, key=lambda fact: str(fact["subject_ref"])))


def _matches(predicate: Mapping[str, object], dimensions: Mapping[str, object]) -> bool:
    if set(predicate) == {"all"}:
        clauses = predicate["all"]
        assert isinstance(clauses, list)
        return all(_matches(_mapping(clause, label="metric clause"), dimensions) for clause in clauses)
    if set(predicate) == {"eq"}:
        clause = _mapping(predicate["eq"], label="metric eq clause")
        return dimensions[clause["path"]] == clause["value"]
    if set(predicate) == {"in"}:
        clause = _mapping(predicate["in"], label="metric in clause")
        return dimensions[clause["path"]] in clause["values"]
    raise ValueError("semantic metric predicate operator is invalid")


def _metric_from_validated(key: str, facts: Sequence[Mapping[str, object]]) -> int:
    metrics = _mapping(_METRIC_REGISTRY["metrics"], label="metric registry metrics")
    if key not in metrics:
        raise KeyError(f"unknown semantic metric: {key}")
    spec = _mapping(metrics[key], label=f"metric {key}")
    predicate = _mapping(spec["predicate"], label=f"metric {key} predicate")
    return sum(
        1 for fact in facts
        if fact["assessment_state"] == "assessed"
        and _matches(predicate, _mapping(fact["semantic_dimensions"], label="dimensions"))
    )


def metric(key: str, facts: Iterable[Mapping[str, object]]) -> int:
    """Calculate one registered metric from validated protected person-level facts."""

    return _metric_from_validated(key, validate_semantic_facts(facts))


def matching_metric_keys(dimensions: Mapping[str, object]) -> tuple[str, ...]:
    """Return registered positive claims supported by one validated dimension set."""

    normalized = _exact(
        dimensions, label="metric dimensions", keys=_DIMENSION_KEYS,
    )
    if any(
        normalized[key] not in ASSESSMENT_ENUMS[key]
        for key in _DIMENSION_KEYS
    ):
        raise ValueError("semantic metric dimensions are invalid")
    metrics = _mapping(_METRIC_REGISTRY["metrics"], label="metric registry metrics")
    return tuple(
        key for key in sorted(metrics)
        if _matches(
            _mapping(metrics[key], label=f"metric {key}")["predicate"],
            normalized,
        )
    )


def partner_report_taxonomy_codes() -> dict[str, tuple[str, ...]]:
    """Return the immutable taxonomy values eligible for partner aggregates."""

    return {
        field: tuple(values)
        for field, values in _PARTNER_REPORT_TAXONOMY_CODES.items()
    }


def partner_report_taxonomy_schema_sha256() -> str:
    """Bind the exact taxonomy cells allowed into partner-facing aggregates."""

    return _sha256({
        "codes": {
            field: list(values)
            for field, values in _PARTNER_REPORT_TAXONOMY_CODES.items()
        },
        "schema_version": "partner-report-taxonomy-v1",
    })


def partner_report_taxonomy_claim_keys(
    taxonomy: Mapping[str, object],
) -> tuple[str, ...]:
    """Return stable keys only for taxonomy values the partner report displays."""

    root = _exact(
        taxonomy,
        label="partner taxonomy",
        keys=frozenset({"career", "project"}),
    )
    project = _mapping(root["project"], label="partner taxonomy project")
    career = _mapping(root["career"], label="partner taxonomy career")
    expected_project = frozenset({*PROJECT_ENUMS, *PROJECT_LIST_ENUMS})
    expected_career = frozenset({*CAREER_ENUMS, *CAREER_LIST_ENUMS})
    if set(project) != expected_project or set(career) != expected_career:
        raise ValueError("semantic partner taxonomy dimensions are invalid")
    values = {**project, **career}
    registry = semantic_taxonomy_dimension_registry()
    claims: list[str] = []
    for field, public_codes in _PARTNER_REPORT_TAXONOMY_CODES.items():
        raw = values[field]
        allowed = frozenset(str(code) for code in registry[field]["values"])
        if registry[field]["mode"] == "overlapping":
            if (
                not isinstance(raw, list)
                or raw != sorted(set(raw))
                or any(not isinstance(code, str) or code not in allowed for code in raw)
            ):
                raise ValueError("semantic partner taxonomy list is invalid")
            claims.extend(
                f"taxonomy:{field}:{code}"
                for code in raw if code in public_codes
            )
        else:
            if not isinstance(raw, str) or raw not in allowed:
                raise ValueError("semantic partner taxonomy scalar is invalid")
            if raw in public_codes:
                claims.append(f"taxonomy:{field}:{raw}")
    return tuple(sorted(claims))


def semantic_taxonomy_dimension_registry() -> dict[str, dict[str, object]]:
    """Return the exact aggregate shape derived from the provider taxonomy."""

    contract = semantic_taxonomy_contract()
    result: dict[str, dict[str, object]] = {}
    for family in ("project", "career"):
        dimensions = contract[family]
        assert isinstance(dimensions, dict)
        for field, raw_spec in dimensions.items():
            assert isinstance(raw_spec, dict)
            result[field] = {
                "family": family,
                "mode": (
                    "exclusive" if raw_spec["kind"] == "scalar"
                    else "overlapping"
                ),
                "values": list(raw_spec["values"]),
            }
    return dict(sorted(result.items()))


def _build_taxonomy_dimensions(
    facts: Sequence[Mapping[str, object]], *, eligible_count: int,
) -> dict[str, dict[str, object]]:
    registry = semantic_taxonomy_dimension_registry()
    counts = {
        field: Counter({str(value): 0 for value in spec["values"]})
        for field, spec in registry.items()
    }
    observed_lists = Counter()
    for fact in facts:
        if fact["assessment_state"] == "excluded":
            continue
        taxonomy = fact.get("semantic_taxonomy")
        if fact["assessment_state"] != "assessed" or not isinstance(taxonomy, Mapping):
            for field, spec in registry.items():
                if spec["mode"] == "exclusive":
                    counts[field]["unknown"] += 1
            continue
        values = {
            **_mapping(taxonomy["project"], label="taxonomy project"),
            **_mapping(taxonomy["career"], label="taxonomy career"),
        }
        for field, spec in registry.items():
            value = values[field]
            if spec["mode"] == "exclusive":
                counts[field][str(value)] += 1
            else:
                assert isinstance(value, list)
                if value:
                    observed_lists[field] += 1
                counts[field].update(str(item) for item in value)
    return {
        field: {
            "cells": {
                code: counts[field][code] for code in spec["values"]
            },
            "denominator": eligible_count,
            "mode": spec["mode"],
            "unknown_count": (
                counts[field]["unknown"]
                if spec["mode"] == "exclusive"
                else eligible_count - observed_lists[field]
            ),
        }
        for field, spec in registry.items()
    }


def semantic_taxonomy_positive_claim_count(
    dimensions: Mapping[str, object],
) -> int:
    """Count evidence-bound aggregate claims represented by taxonomy cells."""

    registry = semantic_taxonomy_dimension_registry()
    negative = {
        "external_validation": "none_observed",
        "founder_state": "no_founder_evidence",
    }
    if set(dimensions) != set(registry):
        raise ValueError("semantic taxonomy aggregate dimensions are invalid")
    total = 0
    for field, spec in registry.items():
        dimension = _mapping(dimensions[field], label=f"taxonomy dimension {field}")
        cells = _mapping(dimension.get("cells"), label=f"taxonomy cells {field}")
        for code in spec["values"]:
            if code == "unknown" or negative.get(field) == code:
                continue
            value = cells.get(code)
            if type(value) is not int or value < 0:
                raise ValueError("semantic taxonomy aggregate count is invalid")
            total += value
    return total


def partner_report_taxonomy_positive_claim_count(
    dimensions: Mapping[str, object],
) -> int:
    """Count only taxonomy cells eligible for the partner report.

    The protected aggregate contains diagnostic values that never become public
    claims, such as ordinary problem framing or no founder evidence. Release QA
    must reconcile the exact public allowlist, not every internal taxonomy cell.
    """

    registry = semantic_taxonomy_dimension_registry()
    if set(dimensions) != set(registry):
        raise ValueError("semantic taxonomy aggregate dimensions are invalid")
    total = 0
    for field, public_codes in _PARTNER_REPORT_TAXONOMY_CODES.items():
        dimension = _mapping(
            dimensions[field], label=f"partner taxonomy dimension {field}",
        )
        cells = _mapping(
            dimension.get("cells"), label=f"partner taxonomy cells {field}",
        )
        if set(cells) != set(registry[field]["values"]):
            raise ValueError("semantic partner taxonomy aggregate cells are invalid")
        for code in public_codes:
            value = cells[code]
            if type(value) is not int or value < 0:
                raise ValueError("semantic partner taxonomy aggregate count is invalid")
            total += value
    return total


def build_semantic_aggregate(
    facts: Iterable[Mapping[str, object]],
    *,
    generated_at: datetime,
    expected_subject_refs: Sequence[str],
    minimum_group_size: int = 5,
) -> dict[str, object]:
    """Build a protected aggregate candidate. This function never grants release."""

    if type(minimum_group_size) is not int or minimum_group_size < 5:
        raise ValueError("semantic minimum group size is invalid")
    normalized = validate_semantic_facts(
        facts, expected_subject_refs=expected_subject_refs,
    )
    state_counts = Counter(str(fact["assessment_state"]) for fact in normalized)
    total_count = len(normalized)
    assessed_count = state_counts["assessed"]
    excluded_count = state_counts["excluded"]
    eligible_count = total_count - excluded_count
    unknown_count = sum(state_counts[state] for state in _UNKNOWN_STATES)
    if assessed_count + unknown_count != eligible_count:
        raise ValueError("semantic population arithmetic does not reconcile")

    bindings = dict(normalized[0]["bindings"])
    source_coverage = {
        source: sum(
            fact["evidence_scopes"][source] == "observed" for fact in normalized
        )
        for source in sorted(_SOURCE_KEYS)
    }
    metrics = {
        key: _metric_from_validated(key, normalized)
        for key in sorted(_mapping(
            _METRIC_REGISTRY["metrics"], label="metric registry metrics",
        ))
    }
    fact_version = str(normalized[0]["fact_version"])
    aggregate_version = (
        AGGREGATE_VERSION
        if fact_version == FACT_VERSION
        else LEGACY_AGGREGATE_VERSION
    )
    result = {
        "aggregate_version": aggregate_version,
        "bindings": bindings,
        "generated_at": _timestamp(generated_at),
        "internal_only": True,
        "metrics": metrics,
        "minimum_group_size": minimum_group_size,
        "population": {
            "assessed_count": assessed_count,
            "eligible_count": eligible_count,
            "excluded_count": excluded_count,
            "population_key": bindings["population_key"],
            "snapshot_sha256": bindings["population_sha256"],
            "state_counts": {
                state: state_counts[state] for state in sorted(_ASSESSMENT_STATES)
            },
            "total_count": total_count,
            "unknown_count": unknown_count,
        },
        "release_eligible": False,
        "source_coverage": source_coverage,
    }
    if fact_version == FACT_VERSION:
        result["taxonomy_dimensions"] = _build_taxonomy_dimensions(
            normalized, eligible_count=eligible_count,
        )
    return result


def build_semantic_cohort_aggregate_bundle(
    facts: Iterable[Mapping[str, object]],
    *,
    generated_at: datetime,
    expected_subject_refs: Sequence[str],
    minimum_group_size: int = 5,
    reviewed_cohort_totals: Mapping[str, int] | None = None,
) -> dict[str, dict[str, object]]:
    """Build ordered protected aggregates from explicit cohort membership.

    The public ``attended`` cohort is derived only from the protected ``present``
    membership fact. This function counts each cohort independently and makes no
    qualitative or comparative claim about accepted or attended participants.
    """

    candidates = tuple(_mapping(fact, label="cohort population fact") for fact in facts)
    if not candidates:
        raise ValueError("semantic cohort population facts are empty")
    for candidate in candidates:
        membership = _mapping(
            candidate.get("cohort_membership"), label="cohort membership",
        )
        if any(
            membership.get(key) not in {"member", "not_member"}
            for key in ("applied", "accepted", "present")
        ):
            raise ValueError(
                "semantic cohort bundle requires complete known applied, accepted, "
                "and present membership"
            )
        if (
            membership["accepted"] == "member"
            and membership["applied"] != "member"
        ):
            raise ValueError(
                "semantic accepted cohort member must also be an applied member"
            )
        if (
            membership["present"] == "member"
            and membership["accepted"] != "member"
        ):
            raise ValueError(
                "semantic present cohort member must also be an accepted member"
            )
        if membership["applied"] != "member":
            raise ValueError(
                "semantic all-applicants cohort requires every subject to be applied"
            )

    normalized = validate_semantic_facts(
        candidates, expected_subject_refs=expected_subject_refs,
    )
    if reviewed_cohort_totals is not None:
        if (
            not isinstance(reviewed_cohort_totals, Mapping)
            or tuple(reviewed_cohort_totals) != SEMANTIC_COHORT_KEYS
            or any(
                type(reviewed_cohort_totals[key]) is not int
                or reviewed_cohort_totals[key] < 0
                for key in SEMANTIC_COHORT_KEYS
            )
            or reviewed_cohort_totals["attended"]
            > reviewed_cohort_totals["accepted"]
            or reviewed_cohort_totals["accepted"] > reviewed_cohort_totals["all"]
        ):
            raise ValueError("reviewed cohort totals are invalid")

    def add_unattributed_unknowns(
        aggregate: dict[str, object], *, reviewed_total: int,
    ) -> dict[str, object]:
        population = aggregate["population"]
        assert isinstance(population, dict)
        known_total = int(population["total_count"])
        if reviewed_total < known_total:
            raise ValueError("reviewed cohort total is below attributable membership")
        unresolved = reviewed_total - known_total
        aggregate["unattributed_membership_unknown_count"] = unresolved
        return aggregate

    bundle: dict[str, dict[str, object]] = {}
    for cohort_key in SEMANTIC_COHORT_KEYS:
        membership_key, population_key = _SEMANTIC_COHORT_SPECS[cohort_key]
        selected: list[dict[str, object]] = []
        for fact in normalized:
            membership = fact["cohort_membership"]
            assert isinstance(membership, Mapping)
            if membership[membership_key] != "member":
                continue
            rebound = json.loads(_canonical(fact))
            rebound["population_key"] = population_key
            bindings = rebound["bindings"]
            assert isinstance(bindings, dict)
            bindings["population_key"] = population_key
            bindings["population_sha256"] = "0" * 64
            selected.append(rebound)
        if not selected:
            raise ValueError(f"semantic cohort {cohort_key} is empty")
        population_sha256 = population_snapshot_sha256(selected)
        for fact in selected:
            bindings = fact["bindings"]
            assert isinstance(bindings, dict)
            bindings["population_sha256"] = population_sha256
        aggregate = build_semantic_aggregate(
            selected,
            generated_at=generated_at,
            expected_subject_refs=sorted(
                str(fact["subject_ref"]) for fact in selected
            ),
            minimum_group_size=minimum_group_size,
        )
        reviewed_total = (
            len(selected)
            if reviewed_cohort_totals is None
            else reviewed_cohort_totals[cohort_key]
        )
        if cohort_key == "all" and reviewed_total != len(selected):
            raise ValueError("reviewed cohort total for all applicants must be exact")
        bundle[cohort_key] = add_unattributed_unknowns(
            aggregate,
            reviewed_total=reviewed_total,
        )
    return bundle


def semantic_aggregate_sha256(aggregate: Mapping[str, object]) -> str:
    return _sha256(aggregate)
