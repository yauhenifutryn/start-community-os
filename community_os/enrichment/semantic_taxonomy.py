"""Evidence-scoped semantic taxonomy for universal enrichment runs.

The model may claim only the controlled project and career dimensions. Builder
tier is derived locally from reviewed project dimensions and is never accepted
as model output.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from hashlib import sha256
import json
import re
from typing import Final


TAXONOMY_VERSION: Final = "semantic-taxonomy-v1"
BUILDER_TIER_DERIVATION_VERSION: Final = "builder-tier-v2"
MAX_CONTROLLED_VALUES_PER_DIMENSION: Final = 8
MAX_EVIDENCE_REFS_PER_DIMENSION: Final = 8

PROJECT_FIELDS: Final = (
    "product_maturity",
    "technical_depth",
    "execution_scope",
    "external_validation",
    "problem_differentiation",
    "market_domains",
    "technical_methods",
    "demonstrated_capabilities",
)
CAREER_FIELDS: Final = (
    "career_stage",
    "founder_state",
    "leadership_state",
    "career_functions",
    "career_delivery",
)
PROJECT_SCALAR_FIELDS: Final = PROJECT_FIELDS[:5]
PROJECT_LIST_FIELDS: Final = PROJECT_FIELDS[5:]
CAREER_SCALAR_FIELDS: Final = CAREER_FIELDS[:3]
CAREER_LIST_FIELDS: Final = CAREER_FIELDS[3:]
ALL_DIMENSIONS: Final = (*PROJECT_FIELDS, *CAREER_FIELDS)

PROJECT_ENUMS: Final = {
    "product_maturity": (
        "unknown",
        "concept",
        "prototype",
        "working_product",
        "production_evidence",
    ),
    "technical_depth": (
        "unknown",
        "basic",
        "moderate",
        "advanced",
        "exceptional",
    ),
    "execution_scope": (
        "unknown",
        "contributor",
        "substantial_contributor",
        "primary_builder",
        "end_to_end_builder",
    ),
    "external_validation": (
        "unknown",
        "none_observed",
        "early_signal",
        "meaningful",
        "strong",
    ),
    "problem_differentiation": (
        "unknown",
        "derivative",
        "ordinary",
        "differentiated",
        "ambitious",
    ),
}
PROJECT_LIST_ENUMS: Final = {
    "market_domains": (
        "climate_energy",
        "commerce_consumer",
        "developer_infrastructure",
        "education_learning",
        "enterprise_operations",
        "financial_services",
        "healthcare_life_sciences",
        "industrial_manufacturing",
        "media_creative",
        "mobility_logistics",
        "public_civic",
        "security_trust",
    ),
    "technical_methods": (
        "applied_ai_ml",
        "automation_orchestration",
        "blockchain_web3",
        "cloud_infrastructure",
        "computer_vision",
        "cybersecurity",
        "data_engineering",
        "distributed_systems",
        "hardware_iot",
        "mobile_native",
        "natural_language_processing",
        "realtime_systems",
        "spatial_computing",
        "web_full_stack",
    ),
    "demonstrated_capabilities": (
        "backend_engineering",
        "data_ai_engineering",
        "frontend_engineering",
        "go_to_market",
        "hardware_engineering",
        "infrastructure_devops",
        "mobile_engineering",
        "product_design",
        "product_engineering",
        "research_experimentation",
        "security_engineering",
        "technical_product_leadership",
    ),
}
CAREER_ENUMS: Final = {
    "career_stage": (
        "unknown",
        "early_career",
        "mid_career",
        "senior",
        "executive",
    ),
    "founder_state": (
        "unknown",
        "no_founder_evidence",
        "former_founder",
        "current_founder",
    ),
    "leadership_state": (
        "unknown",
        "individual_contributor",
        "team_lead",
        "organizational_leader",
        "executive_leader",
    ),
}
CAREER_LIST_ENUMS: Final = {
    "career_functions": (
        "commercial",
        "data_ai",
        "design",
        "investing",
        "operations",
        "product",
        "research",
        "software_engineering",
    ),
    "career_delivery": (
        "customer_delivery",
        "founded_venture",
        "led_teams",
        "open_source_maintenance",
        "research_to_practice",
        "scaled_systems",
        "shipped_products",
    ),
}

_TOP_LEVEL_FIELDS: Final = frozenset({
    "version",
    "project",
    "career",
    "evidence_by_dimension",
})
_PROJECT_EVIDENCE_SOURCES: Final = frozenset({
    "application",
    "devpost",
    "project",
})
_CAREER_EVIDENCE_SOURCES: Final = frozenset({"application", "role"})
_UNREFERENCED_NEGATIVE_VALUES: Final = {
    "external_validation": "none_observed",
    "founder_state": "no_founder_evidence",
}
_EVIDENCE_SUFFIXES_BY_SOURCE: Final = {
    "application": frozenset({"achievement", "experience"}),
    "devpost": frozenset({"demo", "project"}),
    "project": frozenset({
        "deployment",
        "description",
        "ownership",
        "readme",
        "release",
    }),
    "role": frozenset({"description", "title"}),
}
_EVIDENCE_REF = re.compile(
    r"^(?P<source>project|application|devpost|role)_[0-9]{2}:"
    r"(?P<suffix>achievement|demo|deployment|description|experience|ownership|"
    r"project|readme|release|title)$"
)

_STANDOUT_REQUIREMENTS: Final = {
    "product_maturity": frozenset({"working_product", "production_evidence"}),
    "technical_depth": frozenset({"advanced", "exceptional"}),
    "execution_scope": frozenset({"primary_builder", "end_to_end_builder"}),
    "external_validation": frozenset({"meaningful", "strong"}),
    "problem_differentiation": frozenset({"differentiated", "ambitious"}),
}
_SUBSTANTIAL_REQUIREMENTS: Final = {
    "product_maturity": frozenset({"working_product", "production_evidence"}),
    "technical_depth": frozenset({"moderate", "advanced", "exceptional"}),
    "execution_scope": frozenset({
        "substantial_contributor",
        "primary_builder",
        "end_to_end_builder",
    }),
}


def _canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)


def _taxonomy_contract() -> dict[str, object]:
    return {
        "version": TAXONOMY_VERSION,
        "project": {
            **{
                field: {"kind": "scalar", "values": list(PROJECT_ENUMS[field])}
                for field in PROJECT_SCALAR_FIELDS
            },
            **{
                field: {
                    "kind": "sorted_unique_list",
                    "max_values": MAX_CONTROLLED_VALUES_PER_DIMENSION,
                    "values": list(PROJECT_LIST_ENUMS[field]),
                }
                for field in PROJECT_LIST_FIELDS
            },
        },
        "career": {
            **{
                field: {"kind": "scalar", "values": list(CAREER_ENUMS[field])}
                for field in CAREER_SCALAR_FIELDS
            },
            **{
                field: {
                    "kind": "sorted_unique_list",
                    "max_values": MAX_CONTROLLED_VALUES_PER_DIMENSION,
                    "values": list(CAREER_LIST_ENUMS[field]),
                }
                for field in CAREER_LIST_FIELDS
            },
        },
        "evidence": {
            "career_sources": sorted(_CAREER_EVIDENCE_SOURCES),
            "max_refs_per_dimension": MAX_EVIDENCE_REFS_PER_DIMENSION,
            "project_sources": sorted(_PROJECT_EVIDENCE_SOURCES),
            "required_dimensions": list(ALL_DIMENSIONS),
            "unreferenced_negative_values": dict(_UNREFERENCED_NEGATIVE_VALUES),
            "source_suffixes": {
                source: sorted(suffixes)
                for source, suffixes in _EVIDENCE_SUFFIXES_BY_SOURCE.items()
            },
        },
        "builder_tier_derivation": {
            "version": BUILDER_TIER_DERIVATION_VERSION,
            "input_dimensions": list(PROJECT_SCALAR_FIELDS),
            "outputs": ["insufficient", "exploratory", "substantial", "standout"],
            "standout_all_of": {
                field: sorted(values)
                for field, values in _STANDOUT_REQUIREMENTS.items()
            },
            "substantial_all_of": {
                field: sorted(values)
                for field, values in _SUBSTANTIAL_REQUIREMENTS.items()
            },
            "exploratory_when_any_project_dimension_observed": True,
        },
    }


_TAXONOMY_JSON: Final = _canonical_json(_taxonomy_contract())
TAXONOMY_SHA256: Final = sha256(_TAXONOMY_JSON.encode("utf-8")).hexdigest()


def semantic_taxonomy_contract() -> dict[str, object]:
    """Return an independent copy of the canonical model-output contract."""

    return json.loads(_TAXONOMY_JSON)


def _exact_mapping(
    value: object,
    *,
    expected_fields: tuple[str, ...] | frozenset[str],
    label: str,
) -> dict[str, object]:
    if not isinstance(value, Mapping) or set(value) != set(expected_fields):
        raise ValueError(f"semantic taxonomy {label} fields are invalid")
    return dict(value)


def _validate_scalar_dimensions(
    value: Mapping[str, object],
    *,
    fields: tuple[str, ...],
    enums: Mapping[str, tuple[str, ...]],
    label: str,
) -> dict[str, str]:
    normalized: dict[str, str] = {}
    for field in fields:
        item = value[field]
        if not isinstance(item, str) or item not in enums[field]:
            raise ValueError(f"semantic taxonomy {label} {field} is invalid")
        normalized[field] = item
    return normalized


def _validate_list_dimensions(
    value: Mapping[str, object],
    *,
    fields: tuple[str, ...],
    enums: Mapping[str, tuple[str, ...]],
    label: str,
) -> dict[str, list[str]]:
    normalized: dict[str, list[str]] = {}
    for field in fields:
        item = value[field]
        if (
            not isinstance(item, list)
            or len(item) > MAX_CONTROLLED_VALUES_PER_DIMENSION
            or any(not isinstance(entry, str) for entry in item)
            or item != sorted(set(item))
            or any(entry not in enums[field] for entry in item)
        ):
            raise ValueError(f"semantic taxonomy {label} {field} is invalid")
        normalized[field] = list(item)
    return normalized


def _validate_project(value: object) -> dict[str, object]:
    project = _exact_mapping(
        value,
        expected_fields=PROJECT_FIELDS,
        label="project",
    )
    return {
        **_validate_scalar_dimensions(
            project,
            fields=PROJECT_SCALAR_FIELDS,
            enums=PROJECT_ENUMS,
            label="project",
        ),
        **_validate_list_dimensions(
            project,
            fields=PROJECT_LIST_FIELDS,
            enums=PROJECT_LIST_ENUMS,
            label="project",
        ),
    }


def _validate_career(value: object) -> dict[str, object]:
    career = _exact_mapping(
        value,
        expected_fields=CAREER_FIELDS,
        label="career",
    )
    return {
        **_validate_scalar_dimensions(
            career,
            fields=CAREER_SCALAR_FIELDS,
            enums=CAREER_ENUMS,
            label="career",
        ),
        **_validate_list_dimensions(
            career,
            fields=CAREER_LIST_FIELDS,
            enums=CAREER_LIST_ENUMS,
            label="career",
        ),
    }


def _has_semantic_value(value: object) -> bool:
    if isinstance(value, str):
        return value not in {
            "unknown",
            *_UNREFERENCED_NEGATIVE_VALUES.values(),
        }
    return bool(value)


def _validate_evidence(
    value: object,
    *,
    project: Mapping[str, object],
    career: Mapping[str, object],
) -> dict[str, list[str]]:
    evidence = _exact_mapping(
        value,
        expected_fields=ALL_DIMENSIONS,
        label="evidence_by_dimension",
    )
    normalized: dict[str, list[str]] = {}
    for field in ALL_DIMENSIONS:
        refs = evidence[field]
        if (
            not isinstance(refs, list)
            or len(refs) > MAX_EVIDENCE_REFS_PER_DIMENSION
            or any(not isinstance(ref, str) for ref in refs)
            or refs != sorted(set(refs))
        ):
            raise ValueError(f"semantic taxonomy evidence for {field} is invalid")
        allowed_sources = (
            _PROJECT_EVIDENCE_SOURCES
            if field in PROJECT_FIELDS
            else _CAREER_EVIDENCE_SOURCES
        )
        for ref in refs:
            match = _EVIDENCE_REF.fullmatch(ref)
            if (
                match is None
                or match.group("source") not in allowed_sources
                or match.group("suffix")
                not in _EVIDENCE_SUFFIXES_BY_SOURCE[match.group("source")]
            ):
                raise ValueError(f"semantic taxonomy evidence for {field} is invalid")
        dimension_value = project[field] if field in PROJECT_FIELDS else career[field]
        if _has_semantic_value(dimension_value) != bool(refs):
            raise ValueError(f"semantic taxonomy evidence for {field} is unbound")
        normalized[field] = list(refs)
    return normalized


def derive_builder_tier(project: Mapping[str, object]) -> str:
    """Derive a tier from project semantics only, never from career context."""

    normalized = _validate_project(project)
    if all(
        normalized[field] in accepted
        for field, accepted in _STANDOUT_REQUIREMENTS.items()
    ):
        return "standout"
    if all(
        normalized[field] in accepted
        for field, accepted in _SUBSTANTIAL_REQUIREMENTS.items()
    ):
        return "substantial"
    if any(_has_semantic_value(normalized[field]) for field in PROJECT_FIELDS):
        return "exploratory"
    return "insufficient"


def _normalize_fact_input(value: object) -> dict[str, object]:
    raw = _exact_mapping(
        value,
        expected_fields=_TOP_LEVEL_FIELDS,
        label="fact",
    )
    if raw["version"] != TAXONOMY_VERSION:
        raise ValueError("semantic taxonomy version is invalid")
    project = _validate_project(raw["project"])
    career = _validate_career(raw["career"])
    evidence = _validate_evidence(
        raw["evidence_by_dimension"],
        project=project,
        career=career,
    )
    return {
        "version": TAXONOMY_VERSION,
        "project": project,
        "career": career,
        "evidence_by_dimension": evidence,
    }


@dataclass(frozen=True, slots=True)
class SemanticTaxonomyFact:
    """Immutable canonical semantic fact plus its locally derived builder tier."""

    _canonical_input_json: str
    builder_tier: str = field(init=False)

    def __post_init__(self) -> None:
        if not isinstance(self._canonical_input_json, str):
            raise ValueError("semantic taxonomy fact serialization is invalid")
        try:
            raw = json.loads(self._canonical_input_json)
        except (json.JSONDecodeError, TypeError) as exc:
            raise ValueError("semantic taxonomy fact serialization is invalid") from exc
        normalized = _normalize_fact_input(raw)
        if self._canonical_input_json != _canonical_json(normalized):
            raise ValueError("semantic taxonomy fact serialization is not canonical")
        object.__setattr__(self, "builder_tier", derive_builder_tier(normalized["project"]))

    def _input_record(self) -> dict[str, object]:
        return json.loads(self._canonical_input_json)

    @property
    def version(self) -> str:
        return str(self._input_record()["version"])

    @property
    def project(self) -> dict[str, object]:
        return dict(self._input_record()["project"])

    @property
    def career(self) -> dict[str, object]:
        return dict(self._input_record()["career"])

    @property
    def evidence_by_dimension(self) -> dict[str, list[str]]:
        return {
            field: list(refs)
            for field, refs in self._input_record()["evidence_by_dimension"].items()
        }

    def to_record(self) -> dict[str, object]:
        record = self._input_record()
        record["builder_tier"] = self.builder_tier
        return record

    def canonical_json(self) -> str:
        return _canonical_json(self.to_record())

    def canonical_bytes(self) -> bytes:
        return self.canonical_json().encode("utf-8")

    @property
    def sha256(self) -> str:
        return sha256(self.canonical_bytes()).hexdigest()


def validate_semantic_taxonomy_fact(value: object) -> SemanticTaxonomyFact:
    """Validate an exact model fact and append only a locally derived tier."""

    normalized = _normalize_fact_input(value)
    return SemanticTaxonomyFact(_canonical_json(normalized))


def build_semantic_taxonomy_fact(
    *,
    project: Mapping[str, object],
    career: Mapping[str, object],
    evidence_by_dimension: Mapping[str, object],
) -> SemanticTaxonomyFact:
    """Build a canonical fact from the model-controlled semantic dimensions."""

    return validate_semantic_taxonomy_fact({
        "version": TAXONOMY_VERSION,
        "project": project,
        "career": career,
        "evidence_by_dimension": evidence_by_dimension,
    })


def empty_semantic_taxonomy() -> dict[str, object]:
    """Return the canonical no-evidence model record, without a derived tier."""

    project: dict[str, object] = {
        field: [] if field in PROJECT_LIST_FIELDS else "unknown"
        for field in PROJECT_FIELDS
    }
    career: dict[str, object] = {
        field: [] if field in CAREER_LIST_FIELDS else "unknown"
        for field in CAREER_FIELDS
    }
    value = {
        "version": TAXONOMY_VERSION,
        "project": project,
        "career": career,
        "evidence_by_dimension": {field: [] for field in ALL_DIMENSIONS},
    }
    validate_semantic_taxonomy_fact(value)
    return value


def semantic_taxonomy_claim_keys(value: object) -> tuple[str, ...]:
    """Return one stable key for every evidence-bound controlled taxonomy claim."""

    fact = validate_semantic_taxonomy_fact(value)
    values = {**fact.project, **fact.career}
    claims: list[str] = []
    for field, references in fact.evidence_by_dimension.items():
        if not references:
            continue
        item = values[field]
        if isinstance(item, list):
            claims.extend(f"{field}:{code}" for code in item)
        else:
            claims.append(f"{field}:{item}")
    return tuple(sorted(claims))


__all__ = [
    "BUILDER_TIER_DERIVATION_VERSION",
    "CAREER_FIELDS",
    "MAX_CONTROLLED_VALUES_PER_DIMENSION",
    "MAX_EVIDENCE_REFS_PER_DIMENSION",
    "PROJECT_FIELDS",
    "SemanticTaxonomyFact",
    "TAXONOMY_SHA256",
    "TAXONOMY_VERSION",
    "build_semantic_taxonomy_fact",
    "derive_builder_tier",
    "empty_semantic_taxonomy",
    "semantic_taxonomy_claim_keys",
    "semantic_taxonomy_contract",
    "validate_semantic_taxonomy_fact",
]
