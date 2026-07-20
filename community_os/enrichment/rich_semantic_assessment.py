"""Unified rich professional evidence contract and reviewed semantic assessment."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
import hashlib
import json
import re
from collections.abc import Callable, Iterable, Mapping

from community_os.enrichment.cache import CanonicalJsonCache
from community_os.enrichment.github_content_evidence import validate_rich_project_packets
from community_os.enrichment.profile_semantic_evidence import DEVPOST_TECHNOLOGY_CODES
from community_os.enrichment.semantic_evidence import (
    assert_no_known_identity_literals,
    assert_safe_semantic_payload,
    sanitize_professional_text,
)
from community_os.enrichment.semantic_taxonomy import (
    CAREER_ENUMS as TAXONOMY_CAREER_ENUMS,
    CAREER_LIST_ENUMS as TAXONOMY_CAREER_LIST_ENUMS,
    CAREER_LIST_FIELDS as TAXONOMY_CAREER_LIST_FIELDS,
    CAREER_SCALAR_FIELDS as TAXONOMY_CAREER_SCALAR_FIELDS,
    MAX_CONTROLLED_VALUES_PER_DIMENSION,
    MAX_EVIDENCE_REFS_PER_DIMENSION,
    PROJECT_ENUMS as TAXONOMY_PROJECT_ENUMS,
    PROJECT_LIST_ENUMS as TAXONOMY_PROJECT_LIST_ENUMS,
    PROJECT_LIST_FIELDS as TAXONOMY_PROJECT_LIST_FIELDS,
    PROJECT_SCALAR_FIELDS as TAXONOMY_PROJECT_SCALAR_FIELDS,
    TAXONOMY_SHA256,
    TAXONOMY_VERSION,
    derive_builder_tier,
    validate_semantic_taxonomy_fact,
)


PROFILE_FIELDS = frozenset({"application", "career", "devpost", "projects"})
APPLICATION_FIELDS = frozenset({
    "achievement_excerpt", "evidence_code", "evidence_refs", "experience_excerpt",
})
DEVPOST_FIELDS = frozenset({
    "demo_state", "evidence_code", "evidence_refs", "project_excerpt",
    "submission_state", "technology_codes",
})
CAREER_FIELDS = frozenset({
    "active_state", "description_excerpt", "duration_band", "evidence_refs",
    "industry_code", "organization_size_band", "role_code", "seniority_context",
    "title_excerpt",
})
PROFILE_ALLOWED_KEYS = frozenset().union(
    PROFILE_FIELDS, APPLICATION_FIELDS, DEVPOST_FIELDS, CAREER_FIELDS,
)
ASSESSMENT_FIELDS = frozenset({
    "builder_level", "career_summary", "cross_source_confidence", "evidence_refs",
    "execution_scope", "external_validation", "originality", "product_maturity",
    "project_summary", "rationale", "reason_codes", "review_state",
    "semantic_taxonomy", "technical_depth",
})
ASSESSMENT_ENUMS = {
    "builder_level": frozenset({"insufficient", "exploratory", "substantial", "standout"}),
    "product_maturity": frozenset({
        "unknown", "concept", "prototype", "working_product", "production_evidence",
    }),
    "technical_depth": frozenset({"unknown", "basic", "moderate", "advanced", "exceptional"}),
    "execution_scope": frozenset({
        "unknown", "contributor", "substantial_contributor", "primary_builder",
        "end_to_end_builder",
    }),
    "external_validation": frozenset({
        "unknown", "none", "early_signal", "meaningful", "strong",
    }),
    "originality": frozenset({"unknown", "derivative", "ordinary", "differentiated", "ambitious"}),
    "cross_source_confidence": frozenset({"low", "medium", "high"}),
    "review_state": frozenset({"human_review_required"}),
}


@dataclass(frozen=True)
class PreparedRichSemanticAssessment:
    """Immutable handoff for a provider-only production worker."""

    cache_key: str
    evidence: dict[str, object]
    request_metadata: dict[str, object]


REASON_CODES = frozenset({
    "advanced_system_design", "awards_or_recognition", "career_progression",
    "corroborated_across_sources", "differentiated_problem", "end_to_end_delivery",
    "evidence_conflict", "external_adoption", "insufficient_evidence",
    "open_source_adoption", "production_operations", "prototype_only",
    "shipped_working_product", "technically_substantial", "tutorial_or_template",
    "unclear_authorship",
})
SEMANTIC_NORMALIZATION_VERSION = "rich-semantic-normalization-v14"
SEMANTIC_NORMALIZATION_CODES = frozenset({
    "deterministic_model_summary_projection",
    "evidence_on_unknown_semantic_dimensions_cleared",
    "semantic_collection_order_canonicalized",
    "semantic_reference_union_synchronized",
    "reason_codes_synchronized",
    "derived_builder_tier_synchronized",
    "narrative_removed_after_semantic_downgrade",
    "unsupported_external_validation_downgraded",
    "unsupported_originality_claim_downgraded",
    "unsupported_production_claim_downgraded",
    "unsupported_shipping_claim_downgraded",
    "unreferenced_semantic_claims_downgraded",
    "unsupported_end_to_end_scope_bounded_to_cited_ownership",
    "unsupported_end_to_end_scope_bounded_to_observed_contribution",
    "unsupported_end_to_end_scope_downgraded_to_unknown",
    "unsupported_positive_execution_scope_downgraded_to_unknown",
    "unsupported_cross_source_confidence_downgraded",
})
MODEL_ALLOWLIST = frozenset({
    "gpt-5.6-luna", "gpt-5.6-sol", "gpt-5.6-terra",
})
REASONING_ALLOWLIST = frozenset({"none", "low", "medium", "high"})
PROMPT_VERSION = "rich-professional-evidence-a-v24"
_CODE = re.compile(r"^[a-z]+_[0-9]{2}$")
_EVIDENCE = re.compile(
    r"^(?:project|application|devpost|role)_[0-9]{2}:"
    r"(?:achievement|demo|deployment|description|experience|ownership|project|readme|release|title)$"
)
_CODE_VALUE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_COMPLETED_DELIVERY_ACTION = re.compile(
    r"\b(?:built|implemented|shipped|deployed|operated|delivered|launched|"
    r"created|developed|engineered|prototyped|made)\b",
    re.IGNORECASE,
)
_COMPLETED_DIRECTED_DELIVERY_ACTION = re.compile(
    r"\b(?:contributed(?:\s+directly)?\s+to|led)\s+"
    r"(?:the\s+)?(?:(?:core|product|software|system)\s+)?"
    r"(?:implementation|development|engineering|delivery|deployment|"
    r"operations?|runtime|code|build)\b",
    re.IGNORECASE,
)
_COMPLETED_EXPERIENCE_DELIVERY_ACTION = re.compile(
    r"\b(?:(?:(?:i\s+have|with)\s+)?experience(?:\s+in)?\s+|"
    r"worked\s+as\s+(?:an?\s+)?"
    r"(?:[a-z]+\s+){0,3})(?:building|implementing|delivering|developing|"
    r"engineering|deploying|operating|shipping)\b",
    re.IGNORECASE,
)
_COMPLETED_SELF_ATTRIBUTED_DELIVERY_ACTION = re.compile(
    r"\bbuilt\s+(?:most|all)\s+of\s+it\s+myself\b",
    re.IGNORECASE,
)
_COMPLETED_SUPPORTING_DELIVERY_ACTION = re.compile(
    r"\b(?:i|we)\s+[^.;:]{0,100}\bhelp(?:ed)?\b[^.;:]{0,100}"
    r"(?:and|to)\s+build\b",
    re.IGNORECASE,
)
_INCOMPLETE_ACTION_PREFIX = re.compile(
    r"(?:n['’]t\b|\b(?:not|never|without|almost|nearly|will|would|could|should|might|may|"
    r"plans?|planned|planning|intend(?:ed|ing)?|hope(?:d|s|ing)?|aim(?:ed|s|ing)?|"
    r"want(?:ed|s|ing)?|expect(?:ed|s|ing)?|going\s+to|yet\s+to)\b)",
    re.IGNORECASE,
)
_NEGATED_DELIVERY_COMPLEMENT = re.compile(
    r"\b(?:no\b(?!-code\b)|nothing|neither|without)\b",
    re.IGNORECASE,
)
_NON_DELIVERY_CONTEXT = re.compile(
    r"\b(?:architecture|design|plans?|planning|roadmap|strategy|readiness|"
    r"specification|proposal|documentation|committee|group)\b",
    re.IGNORECASE,
)
_DELIVERY_OBJECT = re.compile(
    r"\b(?:products?|projects?|platforms?|applications?|apps?|services?|runtimes?|"
    r"codebases?|code|backends?|frontends?|pipelines?|integrations?|features?|"
    r"systems?|tools?|tooling|workflows?|engines?|infrastructure|software|"
    r"implementations?|deployments?|operations?|delivery|builds?|prototypes?|"
    r"agents?|models?|solutions?|sites?|websites?)\b",
    re.IGNORECASE,
)
_PASSIVE_DELIVERY_ATTRIBUTION = re.compile(
    r"\bby\b",
    re.IGNORECASE,
)
_REDUCED_RELATIVE_BEFORE_BY = re.compile(
    r"\b[a-z]+(?:ed|en)\b(?:\s+[a-z]+){0,2}\s*$",
    re.IGNORECASE,
)
_APPLICANT_ACTIVE_PREFIX = re.compile(
    r"\b(?:i|we)(?:['’]ve|\s+have)?\s+"
    r"(?:(?:personally|directly|successfully|also)\s+)*$",
    re.IGNORECASE,
)
_SELF_DESCRIPTION_ACTIVE_PREFIX = re.compile(
    r"\b(?:engineer|developer|builder|founder|freelancer|researcher|scientist|"
    r"designer)\b[^.;:]{0,80}\bwith\s+$",
    re.IGNORECASE,
)
_APPLICANT_COORDINATED_ACTIVE_PREFIX = re.compile(
    r"\b(?:i|we)\s+(?:(?:personally|directly|successfully|also)\s+)*"
    r"(?:designed|architected|founded|created|developed|engineered|prototyped|led)\b"
    r"[^.;:]{0,120}?(?:,\s*)?(?:and|then)\s*$",
    re.IGNORECASE,
)
_IMPLIED_COORDINATED_ACTIVE_PREFIX = re.compile(
    r"^\s*(?:designed|architected|founded|created|developed|engineered|prototyped|led)\b"
    r"[^.;:]{0,120}?(?:,\s*)?(?:and|then)\s*$",
    re.IGNORECASE,
)
_APPLICANT_SUPPORTING_ACTIVE_PREFIX = re.compile(
    r"\b(?:i|we)\s+[^.;:]{0,100}\bhelp(?:ed)?\b[^.;:]{0,100}"
    r"(?:and|to)\s+$",
    re.IGNORECASE,
)
_EXECUTION_CLAUSE_BREAK = re.compile(
    r"[;\r\n]+|\s+-\s+|,\s*(?:but|however|then)\s+|"
    r"\s+(?:but|however|although|while|whereas|then)\s+",
    re.IGNORECASE,
)
_LIFECYCLE_OBJECT_PATTERN = (
    r"products?|platforms?|applications?|apps?|services?|runtimes?|systems?|"
    r"workflows?|tools?|engines?|software"
)
_FULL_LIFECYCLE_SHARED_OBJECT = re.compile(
    rf"(?:\b(?:i|we)\s+|^)"
    rf"(?:personally\s+|directly\s+)?(?:designed|architected)\s*,?\s*"
    rf"(?:and\s+)?(?:built|implemented)\s*,?\s*(?:and|then)\s+"
    rf"(?:shipped|deployed|operated|delivered|launched)\s+"
    rf"(?:the\s+)?(?:(?:same|this)\s+)?(?:core\s+)?"
    rf"(?:{_LIFECYCLE_OBJECT_PATTERN})\b",
    re.IGNORECASE,
)
_FULL_LIFECYCLE_REPEATED_OBJECT = re.compile(
    rf"(?:\b(?:i|we)\s+|^)"
    rf"(?:personally\s+|directly\s+)?(?:designed|architected)\s+"
    rf"(?:the\s+)?(?:same|this)\s+(?P<object>{_LIFECYCLE_OBJECT_PATTERN})\b"
    rf"[^;.!?]{{0,100}}?\b(?:built|implemented)\s+(?:the\s+)?"
    rf"(?:same|this)\s+(?P=object)\b[^;.!?]{{0,100}}?\b"
    rf"(?:shipped|deployed|operated|delivered|launched)\s+(?:the\s+)?"
    rf"(?:same|this)\s+(?P=object)\b",
    re.IGNORECASE,
)
_FULL_LIFECYCLE_TWO_PHASE = re.compile(
    rf"(?:\b(?:i|we)\s+|^)"
    rf"(?:personally\s+|directly\s+)?(?:designed|architected)\s+(?:and\s+)?"
    rf"(?:built|implemented)\s+(?:the\s+)?(?:same\s+|this\s+)?"
    rf"(?:core\s+)?(?P<object>{_LIFECYCLE_OBJECT_PATTERN})\b"
    rf"[^;.!?]{{0,100}}?\b(?:shipped|deployed|operated|delivered|launched)\s+"
    rf"(?:the\s+)?(?:same|this)\s+(?P=object)\b",
    re.IGNORECASE,
)
_LIFECYCLE_DISQUALIFIER = re.compile(
    r"\b(?:not|never|without|almost|nearly|will|would|could|should|might|may|"
    r"plans?|planned|planning|pending|readiness|roadmap|strategy|proposal|future|goal|"
    r"intend(?:ed|ing)?|hope(?:d|s|ing)?|aim(?:ed|s|ing)?|going\s+to|"
    r"another\s+team)\b",
    re.IGNORECASE,
)


def rich_semantic_contract_sha256() -> str:
    """Hash every controlled output-contract component used by cache and approval."""

    value = {
        "assessment_fields": sorted(ASSESSMENT_FIELDS),
        "assessment_enums": {
            key: sorted(values) for key, values in sorted(ASSESSMENT_ENUMS.items())
        },
        "reason_codes": sorted(REASON_CODES),
        "schema_version": "rich-semantic-evaluation-schema-v14",
        "semantic_normalization_version": SEMANTIC_NORMALIZATION_VERSION,
        "semantic_taxonomy_sha256": TAXONOMY_SHA256,
    }
    payload = json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _bounded_text(value: object, *, limit: int, field: str) -> str:
    if not isinstance(value, str) or len(value) > limit:
        raise ValueError(f"rich semantic {field} is invalid")
    return value


def _references(value: object, *, prefix: str, present_suffixes: set[str]) -> list[str]:
    if not isinstance(value, list) or value != list(dict.fromkeys(value)):
        raise ValueError("rich semantic evidence references are invalid")
    expected = {f"{prefix}:{suffix}" for suffix in present_suffixes}
    if any(
        not isinstance(item, str) or not _EVIDENCE.fullmatch(item)
        for item in value
    ) or set(value) != expected:
        raise ValueError("rich semantic evidence references are invalid")
    return list(value)


def _require_bound_project_references(projects: list[dict[str, object]]) -> None:
    for project in projects:
        code = str(project["project_code"])
        present_suffixes = {
            suffix for present, suffix in (
                (project["repository_relationship"] == "profile_owned_nonfork", "ownership"),
                (bool(project["description_excerpt"]), "description"),
                (bool(project["readme_excerpt"]), "readme"),
                (project["release_signal"] == "release_observed", "release"),
                (project["deployment_signal"] == "deployment_observed", "deployment"),
            ) if present
        }
        _references(
            project["evidence_refs"], prefix=code,
            present_suffixes=present_suffixes,
        )


def validate_profile_evidence(value: object) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != PROFILE_FIELDS:
        raise ValueError("rich semantic profile evidence fields are invalid")
    projects = validate_rich_project_packets(value["projects"])
    application = value["application"]
    devpost = value["devpost"]
    career = value["career"]
    if (
        not isinstance(application, list) or len(application) > 1
        or not isinstance(devpost, list) or len(devpost) > 3
        or not isinstance(career, list) or len(career) > 6
    ):
        raise ValueError("rich semantic profile evidence exceeds source bounds")
    _require_bound_project_references(projects)

    normalized_application: list[dict[str, object]] = []
    for ordinal, item in enumerate(application, start=1):
        if not isinstance(item, dict) or set(item) != APPLICATION_FIELDS:
            raise ValueError("rich semantic application evidence fields are invalid")
        code = f"application_{ordinal:02d}"
        if item["evidence_code"] != code:
            raise ValueError("rich semantic application code is invalid")
        achievement = _bounded_text(
            item["achievement_excerpt"], limit=1_500, field="application achievement",
        )
        experience = _bounded_text(
            item["experience_excerpt"], limit=2_000, field="application experience",
        )
        normalized_application.append({
            **item,
            "achievement_excerpt": achievement,
            "experience_excerpt": experience,
            "evidence_refs": _references(
                item["evidence_refs"], prefix=code,
                present_suffixes={
                    suffix for present, suffix in (
                        (bool(achievement), "achievement"),
                        (bool(experience), "experience"),
                    ) if present
                },
            ),
        })

    normalized_devpost: list[dict[str, object]] = []
    for ordinal, item in enumerate(devpost, start=1):
        if not isinstance(item, dict) or set(item) != DEVPOST_FIELDS:
            raise ValueError("rich semantic Devpost evidence fields are invalid")
        code = f"devpost_{ordinal:02d}"
        technologies = item["technology_codes"]
        if (
            item["evidence_code"] != code
            or item["demo_state"] not in {"unknown", "absent", "observed"}
            or item["submission_state"] not in {"unknown", "draft", "submitted"}
            or not isinstance(technologies, list) or technologies != sorted(set(technologies))
            or len(technologies) > 12
            or any(
                not isinstance(entry, str) or entry not in DEVPOST_TECHNOLOGY_CODES
                for entry in technologies
            )
        ):
            raise ValueError("rich semantic Devpost evidence is invalid")
        project_excerpt = _bounded_text(
            item["project_excerpt"], limit=2_000, field="Devpost project",
        )
        normalized_devpost.append({
            **item,
            "project_excerpt": project_excerpt,
            "evidence_refs": _references(
                item["evidence_refs"], prefix=code,
                present_suffixes={
                    suffix for present, suffix in (
                        (bool(project_excerpt), "project"),
                        (item["demo_state"] == "observed", "demo"),
                    ) if present
                },
            ),
        })

    normalized_career: list[dict[str, object]] = []
    for ordinal, item in enumerate(career, start=1):
        if not isinstance(item, dict) or set(item) != CAREER_FIELDS:
            raise ValueError("rich semantic career evidence fields are invalid")
        code = f"role_{ordinal:02d}"
        if (
            item["role_code"] != code
            or item["active_state"] not in {"current", "historic", "unknown"}
            or item["duration_band"] not in {
                "unknown", "under_one_year", "one_to_three_years", "over_three_years",
            }
            or not isinstance(item["seniority_context"], str)
            or not _CODE_VALUE.fullmatch(item["seniority_context"])
            or not isinstance(item["industry_code"], str)
            or not _CODE_VALUE.fullmatch(item["industry_code"])
            or item["organization_size_band"] not in {
                "unknown", "solo", "small", "medium", "large", "enterprise",
            }
        ):
            raise ValueError("rich semantic career evidence is invalid")
        title = _bounded_text(item["title_excerpt"], limit=300, field="career title")
        description = _bounded_text(
            item["description_excerpt"], limit=1_500, field="career description",
        )
        normalized_career.append({
            **item,
            "title_excerpt": title,
            "description_excerpt": description,
            "evidence_refs": _references(
                item["evidence_refs"], prefix=code,
                present_suffixes={
                    suffix for present, suffix in (
                        (bool(description), "description"), (bool(title), "title"),
                    ) if present
                },
            ),
        })

    normalized = {
        "projects": projects,
        "application": normalized_application,
        "devpost": normalized_devpost,
        "career": normalized_career,
    }
    assert_safe_semantic_payload(
        normalized, max_total_chars=40_000,
        allowed_keys=PROFILE_ALLOWED_KEYS.union(
            set().union(*(set(project) for project in projects)) if projects else set()
        ),
    )
    return normalized


def evidence_references(evidence: Mapping[str, object]) -> frozenset[str]:
    references: set[str] = set()
    for source in ("projects", "application", "devpost", "career"):
        for item in evidence[source]:
            references.update(str(value) for value in item["evidence_refs"])
    return frozenset(references)


def _observed_shipping(
    evidence: Mapping[str, object], references: set[str],
) -> bool:
    return any(
        (
            project["release_signal"] == "release_observed"
            and f'{project["project_code"]}:release' in references
        ) or (
            project["deployment_signal"] == "deployment_observed"
            and f'{project["project_code"]}:deployment' in references
        )
        for project in evidence["projects"]
    ) or any(
        f'{project["evidence_code"]}:demo' in references
        and project["demo_state"] == "observed"
        for project in evidence["devpost"]
    )


def _bound_delivery_claim(references: set[str]) -> bool:
    return any(
        reference.startswith("application_")
        and reference.rsplit(":", 1)[-1] in {"achievement", "experience"}
        for reference in references
    )


def _completed_delivery_action(excerpt: str) -> bool:
    """Recognize only completed applicant delivery in a concrete work context."""

    sentences = re.split(r"(?<=[.!?])\s+|[\r\n]+", excerpt)
    for sentence in sentences:
        for raw_clause in _EXECUTION_CLAUSE_BREAK.split(sentence):
            clause = raw_clause.strip()
            if not clause:
                continue
            matches = sorted(
                [*_COMPLETED_DELIVERY_ACTION.finditer(clause),
                 *_COMPLETED_DIRECTED_DELIVERY_ACTION.finditer(clause),
                 *_COMPLETED_EXPERIENCE_DELIVERY_ACTION.finditer(clause),
                 *_COMPLETED_SELF_ATTRIBUTED_DELIVERY_ACTION.finditer(clause),
                 *_COMPLETED_SUPPORTING_DELIVERY_ACTION.finditer(clause)],
                key=lambda item: item.start(),
            )
            for match in matches:
                prefix = clause[:match.start()]
                applicant_voice = (
                    bool(_APPLICANT_ACTIVE_PREFIX.search(prefix))
                    or bool(_SELF_DESCRIPTION_ACTIVE_PREFIX.search(prefix))
                    or match.re is _COMPLETED_EXPERIENCE_DELIVERY_ACTION
                    or match.re is _COMPLETED_SELF_ATTRIBUTED_DELIVERY_ACTION
                    or match.re is _COMPLETED_SUPPORTING_DELIVERY_ACTION
                    or bool(_APPLICANT_COORDINATED_ACTIVE_PREFIX.search(prefix))
                    or bool(_IMPLIED_COORDINATED_ACTIVE_PREFIX.search(prefix))
                    or bool(_APPLICANT_SUPPORTING_ACTIVE_PREFIX.search(prefix))
                    or bool(re.search(
                        r"\bmyself\b", clause[match.end():match.end() + 120],
                        re.IGNORECASE,
                    ))
                    or not prefix.strip()
                    or bool(re.fullmatch(
                        r"\s*(?:(?:personally|directly|successfully|also|previously)\s+)+",
                        prefix, re.IGNORECASE,
                    ))
                )
                if (
                    not applicant_voice
                    or _INCOMPLETE_ACTION_PREFIX.search(prefix)
                ):
                    continue
                local_context = clause[match.start():match.start() + 180]
                object_match = _DELIVERY_OBJECT.search(local_context)
                self_attributed_build = (
                    match.re is _COMPLETED_SELF_ATTRIBUTED_DELIVERY_ACTION
                )
                action_to_object = (
                    local_context[match.end() - match.start():object_match.end()]
                    if object_match is not None else ""
                )
                passive_delivery = False
                if object_match is not None:
                    for by_match in _PASSIVE_DELIVERY_ATTRIBUTION.finditer(
                        local_context,
                    ):
                        if by_match.start() <= object_match.end():
                            passive_delivery = True
                            break
                        intervening = local_context[
                            object_match.end():by_match.start()
                        ]
                        if not _REDUCED_RELATIVE_BEFORE_BY.search(intervening):
                            passive_delivery = True
                            break
                if (
                    _NON_DELIVERY_CONTEXT.search(local_context)
                    or (object_match is None and not self_attributed_build)
                    or _NEGATED_DELIVERY_COMPLEMENT.search(action_to_object)
                    or passive_delivery
                ):
                    continue
                return True
    return False


def _completed_same_product_lifecycle(excerpt: str) -> bool:
    """Recognize one coherent completed same-product lifecycle sentence."""

    for sentence in re.split(r"(?<=[.!?])\s+|[\r\n]+", excerpt):
        candidate = sentence.strip()
        if (
            not candidate
            or _LIFECYCLE_DISQUALIFIER.search(candidate)
            or _PASSIVE_DELIVERY_ATTRIBUTION.search(candidate)
        ):
            continue
        if any(pattern.search(candidate) for pattern in (
            _FULL_LIFECYCLE_SHARED_OBJECT,
            _FULL_LIFECYCLE_REPEATED_OBJECT,
            _FULL_LIFECYCLE_TWO_PHASE,
        )):
            return True
    return False


def _cited_application_delivery_support(
    evidence: Mapping[str, object], references: set[str],
) -> tuple[bool, bool]:
    """Return explicit-delivery and same-product full-lifecycle support."""

    application = evidence.get("application")
    if not isinstance(application, list):
        return False, False
    cited_excerpts: list[str] = []
    for item in application:
        if not isinstance(item, Mapping) or not isinstance(
            item.get("evidence_code"), str,
        ):
            continue
        code = str(item["evidence_code"])
        for suffix, field in (
            ("achievement", "achievement_excerpt"),
            ("experience", "experience_excerpt"),
        ):
            excerpt = item.get(field)
            if (
                f"{code}:{suffix}" in references
                and isinstance(excerpt, str)
                and excerpt.strip()
            ):
                cited_excerpts.append(excerpt)

    explicit_delivery = any(
        _completed_delivery_action(excerpt) for excerpt in cited_excerpts
    )
    full_lifecycle = any(
        _completed_same_product_lifecycle(excerpt) for excerpt in cited_excerpts
    )
    return explicit_delivery, full_lifecycle


def _bound_problem_evidence(references: set[str]) -> bool:
    return any(
        reference.startswith(("application_", "devpost_", "project_"))
        and reference.rsplit(":", 1)[-1]
        in {"achievement", "description", "experience", "project", "readme"}
        for reference in references
    )


def _external_validation_support(
    evidence: Mapping[str, object], references: set[str],
) -> tuple[str, bool]:
    cited_project_codes = {
        reference.split(":", 1)[0]
        for reference in references if reference.startswith("project_")
    }
    project_signals = [
        str(project[field])
        for project in evidence["projects"]
        if str(project["project_code"]) in cited_project_codes
        for field in ("stars_band", "forks_band")
        if project[field] in {"notable", "high"}
    ]
    project_validation = (
        "strong"
        if "high" in project_signals or project_signals.count("notable") >= 2
        else "meaningful"
        if "notable" in project_signals
        else "none"
    )
    achievement_validation = any(
        reference.startswith("application_")
        and reference.endswith(":achievement")
        for reference in references
    )
    return project_validation, achievement_validation


def validate_rich_semantic_assessment(
    value: object, *, evidence: Mapping[str, object],
) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != ASSESSMENT_FIELDS:
        raise ValueError("rich semantic assessment fields are invalid")
    if any(
        not isinstance(value.get(key), str) or value[key] not in allowed
        for key, allowed in ASSESSMENT_ENUMS.items()
    ):
        raise ValueError("rich semantic assessment enum is invalid")
    for key, limit in (("project_summary", 500), ("career_summary", 500), ("rationale", 1_000)):
        _bounded_text(value[key], limit=limit, field=key)
    references = value["evidence_refs"]
    allowed_references = evidence_references(evidence)
    if (
        not isinstance(references, list)
        or any(not isinstance(item, str) for item in references)
        or references != list(dict.fromkeys(references))
        or len(references) > 12
        or any(item not in allowed_references for item in references)
    ):
        raise ValueError("rich semantic assessment evidence references are invalid")
    semantic_fact = validate_semantic_taxonomy_fact(value["semantic_taxonomy"])
    project_evidence_reviewed = any(
        bool(evidence[family])
        for family in ("application", "devpost", "projects")
    )
    if (
        not project_evidence_reviewed
        and semantic_fact.project["external_validation"] != "unknown"
    ):
        raise ValueError(
            "project external validation requires reviewed project evidence",
        )
    expected_project_overlap = {
        "product_maturity": value["product_maturity"],
        "technical_depth": value["technical_depth"],
        "execution_scope": value["execution_scope"],
        "external_validation": (
            "unknown"
            if not project_evidence_reviewed
            else "none_observed"
            if value["external_validation"] == "none"
            else value["external_validation"]
        ),
        "problem_differentiation": value["originality"],
    }
    if any(
        semantic_fact.project[field] != expected
        for field, expected in expected_project_overlap.items()
    ):
        raise ValueError("rich semantic taxonomy project overlap is inconsistent")
    if semantic_fact.builder_tier != value["builder_level"]:
        raise ValueError("rich semantic taxonomy builder tier is inconsistent")
    taxonomy_references = {
        reference
        for field_references in semantic_fact.evidence_by_dimension.values()
        for reference in field_references
    }
    if taxonomy_references != set(references):
        raise ValueError("rich semantic taxonomy reference union is inconsistent")
    reasons = value["reason_codes"]
    if (
        not isinstance(reasons, list) or not reasons
        or any(not isinstance(reason, str) for reason in reasons)
        or len(reasons) != len(set(reasons))
        or any(reason not in REASON_CODES for reason in reasons)
    ):
        raise ValueError("rich semantic assessment reasons are invalid")
    source_families = {
        reference.split("_", 1)[0] for reference in references
    }
    dimension_references = {
        field: set(field_references)
        for field, field_references in semantic_fact.evidence_by_dimension.items()
    }
    maturity_references = dimension_references["product_maturity"]
    depth_references = dimension_references["technical_depth"]
    execution_references = dimension_references["execution_scope"]
    validation_references = dimension_references["external_validation"]
    problem_references = dimension_references["problem_differentiation"]
    observed_shipping = _observed_shipping(evidence, maturity_references)
    if value["product_maturity"] in {
        "working_product", "production_evidence",
    } and not observed_shipping:
        raise ValueError("working product requires a bound shipping signal")
    if (
        value["product_maturity"] == "production_evidence"
        and "production_operations" not in reasons
    ):
        raise ValueError(
            "production evidence requires a bound shipping signal and production operations"
        )
    explicit_delivery, full_lifecycle_delivery = (
        _cited_application_delivery_support(evidence, execution_references)
    )
    bound_delivery_claim = (
        _bound_delivery_claim(execution_references) and explicit_delivery
    )
    if value["execution_scope"] != "unknown" and not bound_delivery_claim:
        raise ValueError(
            "positive execution scope requires an explicit applicant delivery action"
        )
    if value["execution_scope"] == "end_to_end_builder" and (
        "end_to_end_delivery" not in reasons
        or not bound_delivery_claim
        or not full_lifecycle_delivery
    ):
        raise ValueError(
            "end-to-end execution scope requires one same-product full-lifecycle excerpt"
        )
    if value["cross_source_confidence"] == "high" and len(source_families) < 2:
        raise ValueError("high confidence requires evidence from multiple sources")
    if "corroborated_across_sources" in reasons and (
        value["cross_source_confidence"] != "high" or len(source_families) < 2
    ):
        raise ValueError(
            "cross-source corroboration requires high confidence and multiple source families"
        )
    reason_applicability = {
        "advanced_system_design": value["technical_depth"] in {"advanced", "exceptional"},
        "differentiated_problem": value["originality"] in {"differentiated", "ambitious"},
        "production_operations": value["product_maturity"] == "production_evidence",
        "prototype_only": value["product_maturity"] == "prototype",
        "shipped_working_product": value["product_maturity"] in {
            "working_product", "production_evidence",
        },
        "technically_substantial": value["technical_depth"] in {
            "advanced", "exceptional",
        },
        "unclear_authorship": value["execution_scope"] == "unknown",
    }
    if any(
        reason in reasons and not applies
        for reason, applies in reason_applicability.items()
    ):
        raise ValueError("rich semantic reason code applicability is invalid")
    if value["originality"] in {"differentiated", "ambitious"} and (
        "differentiated_problem" not in reasons
        or not _bound_problem_evidence(problem_references)
    ):
        raise ValueError("originality requires bound problem evidence")
    if value["external_validation"] in {"meaningful", "strong"}:
        project_validation, achievement_validation = _external_validation_support(
            evidence, validation_references,
        )
        if project_validation == "none" and not achievement_validation:
            raise ValueError("external validation requires bound adoption evidence")
        validation_source_families = {
            reference.split("_", 1)[0]
            for reference in validation_references
        }
        if value["external_validation"] == "strong" and not (
            project_validation == "strong"
            or (achievement_validation and len(validation_source_families) >= 2)
        ):
            raise ValueError("strong external validation requires corroborated support")
    if value["builder_level"] in {"substantial", "standout"}:
        builder_references = (
            maturity_references | depth_references | execution_references
        )
        product_content = {
            reference for reference in builder_references
            if reference.startswith(("application_", "devpost_", "project_"))
            and reference.rsplit(":", 1)[-1]
            in {"achievement", "description", "experience", "project", "readme"}
        }
        if not product_content or not observed_shipping:
            raise ValueError(
                "high building tiers require product content and a structural shipping signal"
            )
        if (
            value["product_maturity"] not in {"working_product", "production_evidence"}
            or value["technical_depth"] not in {"moderate", "advanced", "exceptional"}
            or value["execution_scope"] not in {
                "substantial_contributor", "primary_builder", "end_to_end_builder",
            }
            or "shipped_working_product" not in reasons
        ):
            raise ValueError("high building tier claims are not supported by bounded outputs")
        if value["builder_level"] == "standout" and (
            value["product_maturity"] not in {"working_product", "production_evidence"}
            or value["technical_depth"] not in {"advanced", "exceptional"}
            or value["execution_scope"] not in {"primary_builder", "end_to_end_builder"}
            or "technically_substantial" not in reasons
        ):
            raise ValueError("standout building evidence does not meet the deterministic gate")
    normalized = dict(value)
    if not project_evidence_reviewed and value["external_validation"] == "none":
        normalized["external_validation"] = "unknown"
    normalized["reason_codes"] = sorted(reasons)
    normalized["semantic_taxonomy"] = {
        "version": semantic_fact.version,
        "project": semantic_fact.project,
        "career": semantic_fact.career,
        "evidence_by_dimension": semantic_fact.evidence_by_dimension,
    }
    assert_safe_semantic_payload(normalized, allowed_keys=ASSESSMENT_FIELDS)
    return normalized


def conservatively_bound_unsupported_claims(
    value: object, *, evidence: Mapping[str, object],
) -> tuple[object, list[str]]:
    """Downgrade every positive execution claim lacking applicant evidence."""
    positive_scopes = {
        "contributor", "substantial_contributor", "primary_builder",
        "end_to_end_builder",
    }
    scope = value.get("execution_scope") if isinstance(value, dict) else None
    if (
        not isinstance(value, dict)
        or not isinstance(scope, str)
        or scope not in positive_scopes
    ):
        return value, []
    original_scope = scope
    semantic_taxonomy = value.get("semantic_taxonomy")
    if (
        not isinstance(semantic_taxonomy, Mapping)
        or not isinstance(semantic_taxonomy.get("project"), Mapping)
        or not isinstance(semantic_taxonomy.get("evidence_by_dimension"), Mapping)
        or semantic_taxonomy["project"].get("execution_scope")
        != value["execution_scope"]
    ):
        return value, []
    execution_value = semantic_taxonomy["evidence_by_dimension"].get(
        "execution_scope"
    )
    if not isinstance(execution_value, list) or any(
        not isinstance(reference, str) for reference in execution_value
    ):
        return value, []
    execution_references = set(execution_value)
    explicit_delivery, full_lifecycle_delivery = (
        _cited_application_delivery_support(evidence, execution_references)
    )
    bound_delivery = (
        _bound_delivery_claim(execution_references) and explicit_delivery
    )
    if bound_delivery and (
        original_scope != "end_to_end_builder" or full_lifecycle_delivery
    ):
        return value, []
    normalized = dict(value)
    normalized["execution_scope"] = "unknown"
    normalized_taxonomy = dict(semantic_taxonomy)
    normalized_project = dict(semantic_taxonomy["project"])
    normalized_project["execution_scope"] = normalized["execution_scope"]
    normalized_taxonomy["project"] = normalized_project
    normalized["semantic_taxonomy"] = normalized_taxonomy
    reasons = value.get("reason_codes")
    if isinstance(reasons, list):
        normalized["reason_codes"] = list(dict.fromkeys([
            *[reason for reason in reasons if reason != "end_to_end_delivery"],
            "unclear_authorship",
        ]))
    rationale = value.get("rationale")
    if isinstance(rationale, str):
        normalized["rationale"] = (
            rationale.rstrip()
            + " execution scope was conservatively bounded to cited evidence."
        )[:1_000]
    return normalized, [
        "unsupported_end_to_end_scope_downgraded_to_unknown"
        if original_scope == "end_to_end_builder"
        else "unsupported_positive_execution_scope_downgraded_to_unknown"
    ]


def conservatively_bound_unsupported_confidence(
    value: object,
) -> tuple[object, list[str]]:
    """Derive high-confidence eligibility from cited source families only."""

    if (
        not isinstance(value, dict)
        or value.get("cross_source_confidence") != "high"
    ):
        return value, []
    references = value.get("evidence_refs")
    reasons = value.get("reason_codes")
    if (
        not isinstance(references, list)
        or any(not isinstance(reference, str) for reference in references)
        or references != list(dict.fromkeys(references))
        or len(references) > 12
        or any(not _EVIDENCE.fullmatch(reference) for reference in references)
        or not isinstance(reasons, list)
        or not reasons
        or any(
            not isinstance(reason, str) or reason not in REASON_CODES
            for reason in reasons
        )
        or reasons != list(dict.fromkeys(reasons))
    ):
        return value, []
    source_families = {
        reference.split("_", 1)[0] for reference in references
    }
    if len(source_families) >= 2:
        return value, []
    normalized = dict(value)
    normalized["cross_source_confidence"] = (
        "medium" if source_families else "low"
    )
    normalized_reasons = [
        reason for reason in reasons
        if reason != "corroborated_across_sources"
    ]
    if not normalized_reasons:
        normalized_reasons.append("insufficient_evidence")
    normalized["reason_codes"] = normalized_reasons
    return normalized, ["unsupported_cross_source_confidence_downgraded"]


_LEGACY_PROJECT_FIELDS = {
    "product_maturity": "product_maturity",
    "technical_depth": "technical_depth",
    "execution_scope": "execution_scope",
    "external_validation": "external_validation",
    "problem_differentiation": "originality",
}
_PROJECT_DEFAULTS = {
    field: "unknown" for field in TAXONOMY_PROJECT_SCALAR_FIELDS
}
_UNREFERENCED_TAXONOMY_VALUES = frozenset({
    "unknown", "none_observed", "no_founder_evidence",
})
_PROJECT_REASON_CODES = {
    "product_maturity": frozenset({
        "production_operations", "prototype_only", "shipped_working_product",
    }),
    "technical_depth": frozenset({
        "advanced_system_design", "technically_substantial",
    }),
    "execution_scope": frozenset({"end_to_end_delivery"}),
    "external_validation": frozenset({
        "awards_or_recognition", "external_adoption", "open_source_adoption",
    }),
    "problem_differentiation": frozenset({
        "differentiated_problem", "tutorial_or_template",
    }),
}


def canonicalize_semantic_collection_order(
    value: object,
) -> tuple[object, list[str]]:
    """Canonicalize valid set-like collections and their reference union."""

    if (
        not isinstance(value, dict)
        or set(value) != ASSESSMENT_FIELDS
        or any(
            not isinstance(value.get(field), str)
            or value[field] not in allowed
            for field, allowed in ASSESSMENT_ENUMS.items()
        )
    ):
        return value, []
    taxonomy = value.get("semantic_taxonomy")
    if not isinstance(taxonomy, Mapping):
        return value, []
    project = taxonomy.get("project")
    career = taxonomy.get("career")
    dimension_evidence = taxonomy.get("evidence_by_dimension")
    project_fields = {
        *TAXONOMY_PROJECT_SCALAR_FIELDS,
        *TAXONOMY_PROJECT_LIST_FIELDS,
    }
    career_fields = {
        *TAXONOMY_CAREER_SCALAR_FIELDS,
        *TAXONOMY_CAREER_LIST_FIELDS,
    }
    if (
        not isinstance(project, Mapping)
        or not isinstance(career, Mapping)
        or not isinstance(dimension_evidence, Mapping)
        or set(taxonomy)
        != {"version", "project", "career", "evidence_by_dimension"}
        or taxonomy.get("version") != TAXONOMY_VERSION
        or set(project) != project_fields
        or set(career) != career_fields
        or set(dimension_evidence) != project_fields | career_fields
    ):
        return value, []
    top_level_references = value.get("evidence_refs")
    if (
        not isinstance(top_level_references, list)
        or any(
            not isinstance(reference, str) or not _EVIDENCE.fullmatch(reference)
            for reference in top_level_references
        )
        or len(top_level_references) > 12
    ):
        return value, []
    reasons = value.get("reason_codes")
    if (
        not isinstance(reasons, list)
        or not reasons
        or any(
            not isinstance(reason, str) or reason not in REASON_CODES
            for reason in reasons
        )
    ):
        return value, []
    for field in TAXONOMY_PROJECT_LIST_FIELDS:
        items = project[field]
        if (
            not isinstance(items, list)
            or len(items) > MAX_CONTROLLED_VALUES_PER_DIMENSION
            or any(
                not isinstance(item, str)
                or item not in TAXONOMY_PROJECT_LIST_ENUMS[field]
                for item in items
            )
        ):
            return value, []
    for field in TAXONOMY_CAREER_LIST_FIELDS:
        items = career[field]
        if (
            not isinstance(items, list)
            or len(items) > MAX_CONTROLLED_VALUES_PER_DIMENSION
            or any(
                not isinstance(item, str)
                or item not in TAXONOMY_CAREER_LIST_ENUMS[field]
                for item in items
            )
        ):
            return value, []
    for field in project_fields | career_fields:
        references = dimension_evidence[field]
        allowed_prefixes = (
            ("project_", "application_", "devpost_")
            if field in project_fields
            else ("application_", "role_")
        )
        if (
            not isinstance(references, list)
            or len(references) > MAX_EVIDENCE_REFS_PER_DIMENSION
            or any(
                not isinstance(reference, str)
                or not _EVIDENCE.fullmatch(reference)
                or not reference.startswith(allowed_prefixes)
                for reference in references
            )
        ):
            return value, []

    normalized_project = dict(project)
    normalized_career = dict(career)
    normalized_evidence = dict(dimension_evidence)
    collection_changed = False
    for field in TAXONOMY_PROJECT_LIST_FIELDS:
        items = project[field]
        if (
            isinstance(items, list)
            and len(items) <= MAX_CONTROLLED_VALUES_PER_DIMENSION
            and all(
                isinstance(item, str)
                and item in TAXONOMY_PROJECT_LIST_ENUMS[field]
                for item in items
            )
        ):
            canonical = sorted(set(items))
            if items != canonical:
                normalized_project[field] = canonical
                collection_changed = True
    for field in TAXONOMY_CAREER_LIST_FIELDS:
        items = career[field]
        if (
            isinstance(items, list)
            and len(items) <= MAX_CONTROLLED_VALUES_PER_DIMENSION
            and all(
                isinstance(item, str)
                and item in TAXONOMY_CAREER_LIST_ENUMS[field]
                for item in items
            )
        ):
            canonical = sorted(set(items))
            if items != canonical:
                normalized_career[field] = canonical
                collection_changed = True
    for field in project_fields | career_fields:
        references = dimension_evidence[field]
        allowed_prefixes = (
            ("project_", "application_", "devpost_")
            if field in project_fields
            else ("application_", "role_")
        )
        if (
            isinstance(references, list)
            and len(references) <= MAX_EVIDENCE_REFS_PER_DIMENSION
            and all(
                isinstance(reference, str)
                and _EVIDENCE.fullmatch(reference)
                and reference.startswith(allowed_prefixes)
                for reference in references
            )
        ):
            canonical = sorted(set(references))
            if references != canonical:
                normalized_evidence[field] = canonical
                collection_changed = True
    normalized_reasons = sorted(set(reasons))
    if reasons != normalized_reasons:
        collection_changed = True
    reference_union = sorted({
        reference
        for references in normalized_evidence.values()
        if isinstance(references, list)
        for reference in references
        if isinstance(reference, str)
    })
    union_changed = (
        len(reference_union) <= 12
        and top_level_references != reference_union
    )
    if not collection_changed and not union_changed:
        return value, []
    normalized_taxonomy = dict(taxonomy)
    normalized_taxonomy["project"] = normalized_project
    normalized_taxonomy["career"] = normalized_career
    normalized_taxonomy["evidence_by_dimension"] = normalized_evidence
    normalized = dict(value)
    normalized["reason_codes"] = normalized_reasons
    if union_changed:
        normalized["evidence_refs"] = reference_union
    normalized["semantic_taxonomy"] = normalized_taxonomy
    normalizations: list[str] = []
    if collection_changed:
        normalizations.append("semantic_collection_order_canonicalized")
    if union_changed:
        normalizations.append("semantic_reference_union_synchronized")
    return normalized, normalizations


def conservatively_bound_unsupported_project_claims(
    value: object, *, evidence: Mapping[str, object],
) -> tuple[object, list[str]]:
    """Downgrade positive project claims that exceed cited structural support."""

    if (
        not isinstance(value, dict)
        or set(value) != ASSESSMENT_FIELDS
        or any(
            not isinstance(value.get(field), str)
            or value[field] not in allowed
            for field, allowed in ASSESSMENT_ENUMS.items()
        )
        or not isinstance(value.get("reason_codes"), list)
        or any(
            not isinstance(reason, str) or reason not in REASON_CODES
            for reason in value["reason_codes"]
        )
    ):
        return value, []
    taxonomy = value.get("semantic_taxonomy")
    if not isinstance(taxonomy, Mapping):
        return value, []
    project = taxonomy.get("project")
    dimensions = taxonomy.get("evidence_by_dimension")
    if not isinstance(project, Mapping) or not isinstance(dimensions, Mapping):
        return value, []
    required_dimensions = {
        *TAXONOMY_PROJECT_SCALAR_FIELDS,
        *TAXONOMY_PROJECT_LIST_FIELDS,
        *TAXONOMY_CAREER_SCALAR_FIELDS,
        *TAXONOMY_CAREER_LIST_FIELDS,
    }
    if set(dimensions) != required_dimensions or any(
        not isinstance(dimensions[field], list)
        or any(not isinstance(reference, str) for reference in dimensions[field])
        for field in required_dimensions
    ):
        return value, []

    normalized = dict(value)
    normalized_taxonomy = dict(taxonomy)
    normalized_project = dict(project)
    reasons = list(value["reason_codes"])
    normalizations: list[str] = []

    maturity_references = set(dimensions["product_maturity"])
    maturity = str(value["product_maturity"])
    if maturity in {"working_product", "production_evidence"} and not _observed_shipping(
        evidence, maturity_references,
    ):
        bounded_maturity = "prototype" if maturity_references else "unknown"
        normalized["product_maturity"] = bounded_maturity
        normalized_project["product_maturity"] = bounded_maturity
        reasons = [
            reason for reason in reasons
            if reason not in {
                "production_operations", "shipped_working_product",
            }
        ]
        if bounded_maturity == "prototype":
            reasons.append("prototype_only")
        normalizations.append("unsupported_shipping_claim_downgraded")
    elif maturity == "production_evidence" and "production_operations" not in reasons:
        normalized["product_maturity"] = "working_product"
        normalized_project["product_maturity"] = "working_product"
        normalizations.append("unsupported_production_claim_downgraded")

    validation_references = set(dimensions["external_validation"])
    project_validation, achievement_validation = _external_validation_support(
        evidence, validation_references,
    )
    validation_sources = {
        reference.split("_", 1)[0] for reference in validation_references
    }
    supported_validation = (
        "strong"
        if project_validation == "strong"
        or (achievement_validation and len(validation_sources) >= 2)
        else "meaningful"
        if project_validation == "meaningful" or achievement_validation
        else "early_signal"
        if validation_references
        else "unknown"
    )
    validation_rank = {
        "unknown": 0, "none": 0, "early_signal": 1,
        "meaningful": 2, "strong": 3,
    }
    claimed_validation = str(value["external_validation"])
    evidence_free_legacy_none = (
        claimed_validation == "none"
        and not any(
            bool(evidence.get(family))
            for family in ("application", "devpost", "projects")
        )
    )
    if (
        validation_rank[claimed_validation] > validation_rank[supported_validation]
        or evidence_free_legacy_none
    ):
        normalized["external_validation"] = supported_validation
        normalized_project["external_validation"] = (
            "none_observed"
            if supported_validation == "none"
            else supported_validation
        )
        if supported_validation in {"unknown", "early_signal"}:
            reasons = [
                reason for reason in reasons
                if reason not in _PROJECT_REASON_CODES["external_validation"]
            ]
        normalizations.append("unsupported_external_validation_downgraded")

    problem_references = set(dimensions["problem_differentiation"])
    if value["originality"] in {"differentiated", "ambitious"} and (
        "differentiated_problem" not in reasons
        or not _bound_problem_evidence(problem_references)
    ):
        bounded_originality = "ordinary" if problem_references else "unknown"
        normalized["originality"] = bounded_originality
        normalized_project["problem_differentiation"] = bounded_originality
        reasons = [
            reason for reason in reasons if reason != "differentiated_problem"
        ]
        normalizations.append("unsupported_originality_claim_downgraded")

    if not normalizations:
        return value, []
    normalized["reason_codes"] = reasons
    normalized_taxonomy["project"] = normalized_project
    normalized["semantic_taxonomy"] = normalized_taxonomy
    return normalized, normalizations


def synchronize_reason_codes(value: object) -> tuple[object, list[str]]:
    """Make reason codes a deterministic explanation of final controlled claims."""

    if (
        not isinstance(value, dict)
        or set(value) != ASSESSMENT_FIELDS
        or any(
            not isinstance(value.get(field), str)
            or value[field] not in allowed
            for field, allowed in ASSESSMENT_ENUMS.items()
        )
        or not isinstance(value.get("reason_codes"), list)
        or any(
            not isinstance(reason, str) or reason not in REASON_CODES
            for reason in value["reason_codes"]
        )
    ):
        return value, []
    taxonomy = value.get("semantic_taxonomy")
    if not isinstance(taxonomy, Mapping):
        return value, []
    dimensions = taxonomy.get("evidence_by_dimension")
    if not isinstance(dimensions, Mapping):
        return value, []
    required = {
        "execution_scope", "problem_differentiation",
    }
    if any(
        not isinstance(dimensions.get(field), list)
        or any(not isinstance(reference, str) for reference in dimensions[field])
        for field in required
    ):
        return value, []

    reasons = set(value["reason_codes"])
    maturity = str(value["product_maturity"])
    depth = str(value["technical_depth"])
    scope = str(value["execution_scope"])
    originality = str(value["originality"])
    confidence = str(value["cross_source_confidence"])
    builder_level = str(value["builder_level"])
    source_families = {
        reference.split("_", 1)[0]
        for reference in value["evidence_refs"]
        if isinstance(reference, str)
    }

    applicability = {
        "advanced_system_design": depth in {"advanced", "exceptional"},
        "corroborated_across_sources": confidence == "high" and len(source_families) >= 2,
        "differentiated_problem": originality in {"differentiated", "ambitious"},
        "end_to_end_delivery": scope == "end_to_end_builder",
        "production_operations": maturity == "production_evidence",
        "prototype_only": maturity == "prototype",
        "shipped_working_product": maturity in {"working_product", "production_evidence"},
        "technically_substantial": depth in {"advanced", "exceptional"},
        "unclear_authorship": scope == "unknown",
    }
    reasons = {
        reason for reason in reasons
        if applicability.get(reason, True)
    }
    if maturity == "production_evidence":
        reasons.add("production_operations")
    if builder_level in {"substantial", "standout"}:
        reasons.add("shipped_working_product")
    if builder_level == "standout":
        reasons.add("technically_substantial")
    if originality in {"differentiated", "ambitious"} and _bound_problem_evidence(
        set(dimensions["problem_differentiation"]),
    ):
        reasons.add("differentiated_problem")
    if scope == "end_to_end_builder" and _bound_delivery_claim(
        set(dimensions["execution_scope"]),
    ):
        reasons.add("end_to_end_delivery")
    if not reasons:
        reasons.add("insufficient_evidence")
    normalized_reasons = sorted(reasons)
    if value["reason_codes"] == normalized_reasons:
        return value, []
    normalized = dict(value)
    normalized["reason_codes"] = normalized_reasons
    return normalized, ["reason_codes_synchronized"]


def conservatively_downgrade_unreferenced_semantic_claims(
    value: object,
) -> tuple[object, list[str]]:
    """Turn unsupported taxonomy claims into unknowns without moving evidence."""

    if (
        not isinstance(value, dict)
        or set(value) != ASSESSMENT_FIELDS
        or any(
            not isinstance(value.get(field), str)
            or value[field] not in allowed
            for field, allowed in ASSESSMENT_ENUMS.items()
        )
    ):
        return value, []
    taxonomy = value.get("semantic_taxonomy")
    if not isinstance(taxonomy, Mapping):
        return value, []
    project = taxonomy.get("project")
    career = taxonomy.get("career")
    evidence = taxonomy.get("evidence_by_dimension")
    if not all(isinstance(item, Mapping) for item in (project, career, evidence)):
        return value, []
    project_fields = {
        *TAXONOMY_PROJECT_SCALAR_FIELDS,
        *TAXONOMY_PROJECT_LIST_FIELDS,
    }
    career_fields = {
        *TAXONOMY_CAREER_SCALAR_FIELDS,
        *TAXONOMY_CAREER_LIST_FIELDS,
    }
    if (
        set(taxonomy) != {"version", "project", "career", "evidence_by_dimension"}
        or taxonomy.get("version") != TAXONOMY_VERSION
        or set(project) != project_fields
        or set(career) != career_fields
        or set(evidence) != project_fields | career_fields
    ):
        return value, []

    normalized_project = dict(project)
    normalized_career = dict(career)
    normalized_evidence = {
        field: evidence[field]
        for field in project_fields | career_fields
    }
    downgraded_fields: set[str] = set()

    for field in TAXONOMY_PROJECT_SCALAR_FIELDS:
        claim = project.get(field)
        default = _PROJECT_DEFAULTS[field]
        if (
            evidence.get(field) == []
            and isinstance(claim, str)
            and claim in TAXONOMY_PROJECT_ENUMS[field]
            and claim not in _UNREFERENCED_TAXONOMY_VALUES
        ):
            normalized_project[field] = default
            downgraded_fields.add(field)
    for field in TAXONOMY_CAREER_SCALAR_FIELDS:
        claim = career.get(field)
        if (
            evidence.get(field) == []
            and isinstance(claim, str)
            and claim in TAXONOMY_CAREER_ENUMS[field]
            and claim not in _UNREFERENCED_TAXONOMY_VALUES
        ):
            normalized_career[field] = "unknown"
            downgraded_fields.add(field)
    for field in TAXONOMY_PROJECT_LIST_FIELDS:
        claim = project.get(field)
        if (
            evidence.get(field) == []
            and isinstance(claim, list)
            and bool(claim)
            and all(isinstance(item, str) for item in claim)
            and claim == sorted(set(claim))
            and all(item in TAXONOMY_PROJECT_LIST_ENUMS[field] for item in claim)
        ):
            normalized_project[field] = []
            downgraded_fields.add(field)
    for field in TAXONOMY_CAREER_LIST_FIELDS:
        claim = career.get(field)
        if (
            evidence.get(field) == []
            and isinstance(claim, list)
            and bool(claim)
            and all(isinstance(item, str) for item in claim)
            and claim == sorted(set(claim))
            and all(item in TAXONOMY_CAREER_LIST_ENUMS[field] for item in claim)
        ):
            normalized_career[field] = []
            downgraded_fields.add(field)

    top_level_references = value.get("evidence_refs")
    safe_top_level_references = (
        set(top_level_references)
        if isinstance(top_level_references, list)
        and all(isinstance(item, str) for item in top_level_references)
        else set()
    )
    evidence_cleared = False
    for field in project_fields | career_fields:
        claim = (
            normalized_project[field]
            if field in project_fields
            else normalized_career[field]
        )
        has_semantic_value = (
            claim not in _UNREFERENCED_TAXONOMY_VALUES
            if isinstance(claim, str)
            else bool(claim)
        )
        refs = evidence[field]
        allowed_prefixes = (
            ("project_", "application_", "devpost_")
            if field in project_fields
            else ("application_", "role_")
        )
        if (
            not has_semantic_value
            and isinstance(refs, list)
            and bool(refs)
            and len(refs) <= MAX_EVIDENCE_REFS_PER_DIMENSION
            and all(
                isinstance(ref, str)
                and _EVIDENCE.fullmatch(ref)
                and ref.startswith(allowed_prefixes)
                and ref in safe_top_level_references
                for ref in refs
            )
            and refs == sorted(set(refs))
        ):
            normalized_evidence[field] = []
            evidence_cleared = True

    if not downgraded_fields and not evidence_cleared:
        return value, []

    normalized = dict(value)
    normalized_taxonomy = dict(taxonomy)
    normalized_taxonomy["project"] = normalized_project
    normalized_taxonomy["career"] = normalized_career
    normalized_taxonomy["evidence_by_dimension"] = normalized_evidence
    normalized["semantic_taxonomy"] = normalized_taxonomy
    for taxonomy_field, legacy_field in _LEGACY_PROJECT_FIELDS.items():
        if taxonomy_field not in downgraded_fields:
            continue
        normalized[legacy_field] = normalized_project[taxonomy_field]
    normalized["builder_level"] = derive_builder_tier(normalized_project)

    reasons = value.get("reason_codes")
    if isinstance(reasons, list):
        disallowed_reasons = {
            reason
            for field in downgraded_fields
            for reason in _PROJECT_REASON_CODES.get(field, frozenset())
        }
        normalized_reasons = [
            reason for reason in reasons if reason not in disallowed_reasons
        ]
        if "execution_scope" in downgraded_fields:
            normalized_reasons.append("unclear_authorship")
        if not normalized_reasons:
            normalized_reasons.append("insufficient_evidence")
        normalized["reason_codes"] = list(dict.fromkeys(normalized_reasons))

    normalization_codes: list[str] = []
    if downgraded_fields:
        normalization_codes.append("unreferenced_semantic_claims_downgraded")
    if evidence_cleared:
        normalization_codes.append(
            "evidence_on_unknown_semantic_dimensions_cleared"
        )
    return normalized, normalization_codes


def synchronize_derived_builder_tier(value: object) -> object:
    """Recompute the local-only builder tier after every claim downgrade."""

    if not isinstance(value, dict):
        return value
    taxonomy = value.get("semantic_taxonomy")
    if not isinstance(taxonomy, Mapping):
        return value
    project = taxonomy.get("project")
    if not isinstance(project, Mapping):
        return value
    normalized = dict(value)
    normalized["builder_level"] = derive_builder_tier(project)
    return normalized


def sanitize_assessment_free_text(
    value: object, *, forbidden_literals: Iterable[str] = (),
    retain_narrative: bool = True,
) -> tuple[object, list[str]]:
    """Retain only bounded identifier-free summaries; control the rationale."""
    if not isinstance(value, dict):
        return value, []
    enum_fields = (
        "builder_level", "product_maturity", "technical_depth", "execution_scope",
        "cross_source_confidence", "external_validation", "originality",
    )
    if any(
        not isinstance(value.get(field), str)
        or value[field] not in ASSESSMENT_ENUMS[field]
        for field in enum_fields
    ):
        return value, []
    reasons = value.get("reason_codes")
    if (
        not isinstance(reasons, list)
        or any(not isinstance(reason, str) or reason not in REASON_CODES for reason in reasons)
    ):
        return value, []
    if isinstance(forbidden_literals, (str, bytes)):
        raise TypeError("semantic narrative identity corpus must be an iterable")
    if type(retain_narrative) is not bool:
        raise TypeError("semantic narrative retention decision must be boolean")
    identity_literals = tuple(forbidden_literals)
    if any(not isinstance(literal, str) for literal in identity_literals):
        raise TypeError("semantic narrative identity corpus is invalid")
    def reviewed_summary(field: str) -> str:
        raw = value[field]
        if not retain_narrative or not isinstance(raw, str) or not raw.strip():
            return ""
        try:
            if identity_literals:
                assert_no_known_identity_literals(
                    {"text": raw}, identity_literals,
                )
            assert_safe_semantic_payload(
                {"text": raw}, max_total_chars=1_000,
                allowed_keys={"text"},
            )
            safe = sanitize_professional_text(
                raw, forbidden_literals=identity_literals, max_chars=500,
            )
            if identity_literals:
                assert_no_known_identity_literals(
                    {"text": safe}, identity_literals,
                )
            assert_safe_semantic_payload(
                {"text": safe}, max_total_chars=1_000,
                allowed_keys={"text"},
            )
        except (TypeError, ValueError):
            return ""
        return safe if safe and safe == raw.strip() else ""

    phrase = lambda item: str(item).replace("_", " ")
    normalized = dict(value)
    normalized["project_summary"] = reviewed_summary("project_summary")
    normalized["career_summary"] = reviewed_summary("career_summary")
    normalized["rationale"] = "review reasons " + ", ".join(
        phrase(reason) for reason in sorted(reasons)
    ) + "."
    normalizations = ["deterministic_model_summary_projection"]
    if not retain_narrative and any(
        isinstance(value.get(field), str) and value[field].strip()
        for field in ("project_summary", "career_summary")
    ):
        normalizations.append("narrative_removed_after_semantic_downgrade")
    return normalized, normalizations


class RichSemanticAssessor:
    VERSION = "rich-semantic-assessment-v19"
    CACHE_ENTRY_VERSION = "rich-semantic-paid-cache-v1"

    def __init__(
        self, *, provider: Callable[[dict[str, object]], dict[str, object]],
        cache: CanonicalJsonCache, clock: Callable[[], datetime], retention_days: int,
        model: str, reasoning_effort: str,
        privacy_context_sha256: str | None = None,
    ) -> None:
        if model not in MODEL_ALLOWLIST or reasoning_effort not in REASONING_ALLOWLIST:
            raise ValueError("rich semantic model posture is invalid")
        if type(retention_days) is not int or not 1 <= retention_days <= 7:
            raise ValueError("rich semantic retention must be between one and seven days")
        if (
            privacy_context_sha256 is not None
            and (
                not isinstance(privacy_context_sha256, str)
                or re.fullmatch(r"[0-9a-f]{64}", privacy_context_sha256) is None
            )
        ):
            raise ValueError("rich semantic privacy context hash is invalid")
        self.provider = provider
        self.cache = cache
        self.clock = clock
        self.retention_days = retention_days
        self.model = model
        self.reasoning_effort = reasoning_effort
        self.cache_identity = ":".join((
            self.VERSION, PROMPT_VERSION, SEMANTIC_NORMALIZATION_VERSION,
            rich_semantic_contract_sha256(), model, reasoning_effort,
            privacy_context_sha256 or "unbound",
        ))

    def _cached_value(
        self, cached: Mapping[str, object], *, evidence: Mapping[str, object],
    ) -> tuple[dict[str, object], dict[str, object] | None]:
        if "cache_entry_version" not in cached:
            return validate_rich_semantic_assessment(cached, evidence=evidence), None
        if (
            set(cached) != {
                "assessment", "cache_entry_version", "model_version",
                "normalizations", "usage",
            }
            or cached.get("cache_entry_version") != self.CACHE_ENTRY_VERSION
            or cached.get("model_version") != self.model
        ):
            raise ValueError("rich semantic paid cache entry is invalid")
        usage = cached.get("usage")
        normalizations = cached.get("normalizations")
        if (
            not isinstance(usage, Mapping)
            or set(usage) != {"input_tokens", "output_tokens"}
            or any(
                isinstance(usage.get(field), bool)
                or not isinstance(usage.get(field), int)
                or int(usage[field]) < 0
                for field in ("input_tokens", "output_tokens")
            )
            or not isinstance(normalizations, list)
            or any(
                not isinstance(item, str)
                or item not in SEMANTIC_NORMALIZATION_CODES
                for item in normalizations
            )
        ):
            raise ValueError("rich semantic paid cache entry is invalid")
        assessment = validate_rich_semantic_assessment(
            cached.get("assessment"), evidence=evidence,
        )
        return assessment, {
            "model_version": self.model,
            "normalizations": list(normalizations),
            "usage": {
                "input_tokens": int(usage["input_tokens"]),
                "output_tokens": int(usage["output_tokens"]),
            },
        }

    def assess(self, evidence: object) -> dict[str, object]:
        normalized = validate_profile_evidence(evidence)
        key = self.cache.key("rich_semantic", self.cache_identity, normalized)
        cached = self.cache.get(key)
        if cached is not None:
            assessment, _pending_usage = self._cached_value(
                cached, evidence=normalized,
            )
            return assessment
        result = validate_rich_semantic_assessment(
            self.provider(normalized), evidence=normalized,
        )
        self.cache.set(
            key, result,
            expires_at=self.clock() + timedelta(days=self.retention_days),
        )
        return result

    def prepare_with_metadata(
        self, evidence: object,
    ) -> tuple[PreparedRichSemanticAssessment, dict[str, object] | None]:
        """Check cache serially and prepare an immutable provider-only request."""
        normalized = validate_profile_evidence(evidence)
        request = json.dumps(
            normalized, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        request_metadata = {
            "request_byte_count": len(request),
            "request_sha256": hashlib.sha256(request).hexdigest(),
            "source_family_counts": {
                family: len(normalized[family])
                for family in ("application", "career", "devpost", "projects")
            },
        }
        key = self.cache.key("rich_semantic", self.cache_identity, normalized)
        prepared = PreparedRichSemanticAssessment(
            cache_key=key,
            evidence=normalized,
            request_metadata=request_metadata,
        )
        cached = self.cache.get(key)
        if cached is not None:
            assessment, pending_usage = self._cached_value(
                cached, evidence=normalized,
            )
            return prepared, {
                "assessment": assessment,
                "cache_status": "miss" if pending_usage is not None else "hit",
                "model_version": (
                    pending_usage["model_version"]
                    if pending_usage is not None else self.model
                ),
                "normalizations": (
                    pending_usage["normalizations"]
                    if pending_usage is not None else []
                ),
                **request_metadata,
                "usage": (
                    pending_usage["usage"]
                    if pending_usage is not None
                    else {"input_tokens": 0, "output_tokens": 0}
                ),
            }
        return prepared, None

    def acknowledge_prepared_usage(
        self, prepared: PreparedRichSemanticAssessment,
    ) -> None:
        """Clear pending paid usage only after its durable receipt is written."""

        if not isinstance(prepared, PreparedRichSemanticAssessment):
            raise TypeError("rich semantic prepared request is invalid")
        normalized = validate_profile_evidence(prepared.evidence)
        cached = self.cache.get(prepared.cache_key)
        if cached is None:
            return
        assessment, pending_usage = self._cached_value(
            cached, evidence=normalized,
        )
        if pending_usage is None:
            return
        self.cache.set(
            prepared.cache_key, assessment,
            expires_at=self.clock() + timedelta(days=self.retention_days),
        )

    def request_prepared_with_metadata(
        self, prepared: PreparedRichSemanticAssessment,
    ) -> object:
        """Make only the provider call; this method performs no filesystem writes."""

        if not isinstance(prepared, PreparedRichSemanticAssessment):
            raise TypeError("rich semantic prepared request is invalid")
        assess = getattr(self.provider, "assess_with_metadata", None)
        if not callable(assess):
            raise TypeError(
                "rich semantic production provider must expose usage metadata",
            )
        return assess(prepared.evidence, max_transport_attempts=1)

    def finalize_prepared_with_metadata(
        self, prepared: PreparedRichSemanticAssessment, result: object,
    ) -> dict[str, object]:
        """Validate and cache one provider result on the serial commit thread."""

        if not isinstance(prepared, PreparedRichSemanticAssessment):
            raise TypeError("rich semantic prepared request is invalid")
        normalized = validate_profile_evidence(prepared.evidence)
        request = json.dumps(
            normalized, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        expected_metadata = {
            "request_byte_count": len(request),
            "request_sha256": hashlib.sha256(request).hexdigest(),
            "source_family_counts": {
                family: len(normalized[family])
                for family in ("application", "career", "devpost", "projects")
            },
        }
        if prepared.request_metadata != expected_metadata:
            raise PermissionError("rich semantic prepared request metadata drifted")
        if not isinstance(result, Mapping) or set(result) != {
            "assessment", "model_version", "normalizations", "usage",
        }:
            raise ValueError("rich semantic provider metadata is invalid")
        model_version = result["model_version"]
        usage = result["usage"]
        normalizations = result["normalizations"]
        if (
            model_version != self.model
            or not isinstance(usage, Mapping)
            or set(usage) != {"input_tokens", "output_tokens"}
            or any(
                isinstance(usage[field], bool)
                or not isinstance(usage[field], int)
                or usage[field] < 0
                for field in ("input_tokens", "output_tokens")
            )
            or not isinstance(normalizations, list)
            or any(
                not isinstance(item, str)
                or item not in SEMANTIC_NORMALIZATION_CODES
                for item in normalizations
            )
        ):
            raise ValueError("rich semantic provider metadata is invalid")
        assessment = validate_rich_semantic_assessment(
            result["assessment"], evidence=normalized,
        )
        self.cache.set(
            prepared.cache_key, {
                "assessment": assessment,
                "cache_entry_version": self.CACHE_ENTRY_VERSION,
                "model_version": model_version,
                "normalizations": list(normalizations),
                "usage": {
                    "input_tokens": int(usage["input_tokens"]),
                    "output_tokens": int(usage["output_tokens"]),
                },
            },
            expires_at=self.clock() + timedelta(days=self.retention_days),
        )
        return {
            "assessment": assessment,
            "cache_status": "miss",
            "model_version": model_version,
            "normalizations": list(normalizations),
            **expected_metadata,
            "usage": {
                "input_tokens": int(usage["input_tokens"]),
                "output_tokens": int(usage["output_tokens"]),
            },
        }

    def assess_with_metadata(self, evidence: object) -> dict[str, object]:
        """Assess once and return only content-free request and usage metadata."""

        prepared, cached = self.prepare_with_metadata(evidence)
        if cached is not None:
            return cached
        result = self.request_prepared_with_metadata(prepared)
        metadata = self.finalize_prepared_with_metadata(prepared, result)
        self.acknowledge_prepared_usage(prepared)
        return metadata
