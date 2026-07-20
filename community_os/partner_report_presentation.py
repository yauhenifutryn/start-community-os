"""Validated aggregate-only presentation choices for partner reports."""

from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile

from community_os.partner_semantic_projection import (
    PartnerSemanticCohortBundle,
    PartnerSemanticMetric,
    PartnerSemanticSummary,
    validate_partner_semantic_cohort_bundle,
    validate_partner_semantic_summary,
)


_HASH = re.compile(r"[0-9a-f]{64}")
_KEY = re.compile(r"[a-z][a-z0-9_-]{0,63}")
_FORBIDDEN_COPY = re.compile(
    r"(?:https?://|www\.|[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}|[<>]|\d)",
    re.IGNORECASE,
)
_QUESTION_KEYS = ("overview", "invest", "hire", "portfolio")
_SECTION_KEYS = frozenset({
    "journey", "project-landscape", "semantic-evidence", "career-context",
    "capability-context", "domain-context", "evidence-boundary", "methodology",
})
_INTERACTION_PROFILE = "interactive-evidence-v1"
_VERSION = "partner-report-presentation-v1"
_DASHBOARD_VERSION = "partner-dashboard-v2"

_DASHBOARD_METRIC_GROUPS = (
    {
        "key": "project_evidence",
        "label": "Project evidence",
        "description": (
            "Comparable signals about work already built, technical substance, "
            "and problem framing."
        ),
        "metric_keys": (
            "prototype_or_beyond",
            "substantive_technical_evidence",
            "differentiated_problem",
            "advanced_technical_evidence",
        ),
    },
    {
        "key": "demonstrated_capabilities",
        "label": "Demonstrated capabilities",
        "description": (
            "Overlapping technical capability signals from reviewed work; these "
            "counts are not additive."
        ),
        "metric_keys": (
            "capability_product_engineering",
            "capability_data_ai_engineering",
            "capability_backend_engineering",
        ),
    },
    {
        "key": "career_delivery",
        "label": "Career delivery",
        "description": (
            "Overlapping evidence of shipping, founding, and customer delivery; "
            "this is not a seniority ladder."
        ),
        "metric_keys": (
            "career_delivery_shipped_products",
            "career_delivery_founded_venture",
            "career_delivery_customer_delivery",
        ),
    },
)
_DIMENSION_METRIC_SPECS = {
    "capability_product_engineering": (
        "demonstrated_capabilities", "product_engineering", "Product engineering",
        "Concrete reviewed work supports product engineering capability.",
    ),
    "capability_data_ai_engineering": (
        "demonstrated_capabilities", "data_ai_engineering",
        "Data and AI engineering",
        "Concrete reviewed work supports data and AI engineering capability.",
    ),
    "capability_backend_engineering": (
        "demonstrated_capabilities", "backend_engineering", "Backend engineering",
        "Concrete reviewed work supports backend engineering capability.",
    ),
    "career_delivery_shipped_products": (
        "career_delivery", "shipped_products", "Shipped products",
        "Reviewed evidence supports shipping a product or meaningful feature.",
    ),
    "career_delivery_founded_venture": (
        "career_delivery", "founded_venture", "Founded a venture",
        "Reviewed evidence supports starting or co-founding a venture.",
    ),
    "career_delivery_customer_delivery": (
        "career_delivery", "customer_delivery", "Customer delivery",
        "Reviewed evidence supports delivery for customers or users.",
    ),
}
_COHORT_DEFINITIONS = {
    "all": "All valid applicants in the reviewed event population.",
    "accepted": (
        "Organizer-selected after manual application review; selection is not a "
        "quality score or ground-truth ranking. Members without attributable reviewed "
        "evidence remain in the denominator and unknown."
    ),
    "attended": (
        "The reviewed organizer total for people present at the event. Attendees without "
        "attributable reviewed evidence remain in the denominator and unknown."
    ),
}
_SOURCE_COVERAGE = {
    "application": (
        "Application", "People whose reviewed evidence included application evidence."
    ),
    "public_projects": (
        "Public projects",
        "People whose reviewed evidence included public-project evidence; absence is not a quality judgment.",
    ),
    "event_submission": (
        "Event submission",
        "People whose reviewed evidence included event-submission evidence; this is not attendance or team-submission completion.",
    ),
    "career_context": (
        "Dedicated career-provider evidence",
        "People whose reviewed evidence included dedicated career-provider context.",
    ),
}


@dataclass(frozen=True)
class PartnerQuestion:
    key: str
    label: str
    answer: str
    evidence_refs: tuple[str, ...]
    target_sections: tuple[str, ...]


@dataclass(frozen=True)
class PartnerReportPresentation:
    version: str
    event_definition_sha256: str
    aggregate_sha256: str
    interaction_profile: str
    cover_title: str
    cover_dek: str
    questions: tuple[PartnerQuestion, ...]


class StalePartnerPresentationError(PermissionError):
    """The stored copy is valid, but belongs to a different bound input."""

    def __init__(self, binding: str) -> None:
        self.binding = binding
        super().__init__(f"partner presentation {binding} binding is stale")


_COPY_OPTIONS: dict[str, tuple[str, ...]] = {
    "cover_title": (
        "Builders who ship, shown through the work.",
        "A community of builders, understood through evidence.",
        "Technical ambition and delivery, made visible.",
    ),
    "cover_dek": (
        "An evidence-bound view of product seriousness, technical substance, "
        "originality, execution, and validation across the applicant community.",
        "A partner view of demonstrated product maturity, technical depth, "
        "execution, validation, and career context across the applicant community.",
        "A structured view of what the applicant community has built, how the work "
        "was delivered, and where external evidence supports the claims.",
    ),
    "overview": (
        "Start with participation, then follow the strongest project and technical "
        "evidence supported across the applicant community.",
        "Follow participation into the strongest supported evidence of building, "
        "delivery, and technical substance.",
    ),
    "invest": (
        "Start with products supported at prototype or beyond as evidence of work "
        "already underway. Then review differentiated problems, external validation, "
        "execution, and founder context separately, never as an investment score.",
        "Treat prototype-or-beyond products as evidence of work underway. Keep "
        "differentiated problems, external validation, execution, and founder context "
        "separate; none is an investment score.",
    ),
    "hire": (
        "Use demonstrated capabilities and technical methods to understand what the "
        "cohort has actually built, not merely claimed.",
        "Use concrete delivery, technical methods, and demonstrated capabilities to "
        "understand where the community has hands-on experience.",
    ),
    "portfolio": (
        "Compare overlapping evidence of shipped products, founded ventures, and customer "
        "delivery as inputs to team composition. People may appear in more than one signal; "
        "this is not a team score.",
        "Use overlapping career-delivery evidence to explore complementary experience. "
        "People may appear in several signals, so the counts must not be added and do not "
        "form a team score.",
    ),
}

_RETIRED_COPY_OPTIONS: dict[str, frozenset[str]] = {
    "portfolio": frozenset({
        "Execution, leadership, and delivery may inform team composition, but nested "
        "cohort-level counts are privacy-withheld in this comparison. Use the displayed "
        "technical and problem evidence as a starting point, not as a team score.",
        "Use execution, leadership, and delivery context to explore complementary "
        "experience. Nested cohort-level counts are privacy-withheld here, so the "
        "displayed technical and problem evidence is context, not a team score.",
        "Execution, leadership, and delivery evidence identify where people may "
        "complement ambitious product teams.",
        "Use execution, leadership, and delivery evidence to identify complementary "
        "experience across ambitious product teams.",
    }),
}

_QUESTION_CONTRACTS: dict[str, dict[str, object]] = {
    "overview": {
        "label": "Overview",
        "evidence_refs": (
            "metric:substantive_technical_evidence",
            "metric:differentiated_problem",
        ),
        "target_sections": ("journey", "project-landscape"),
    },
    "invest": {
        "label": "Invest",
        "evidence_refs": (
            "metric:differentiated_problem",
            "metric:meaningful_validation",
            "dimension:product_maturity",
            "dimension:founder_state",
        ),
        "target_sections": ("project-landscape", "career-context"),
    },
    "hire": {
        "label": "Hire",
        "evidence_refs": (
            "metric:advanced_technical_evidence",
            "metric:substantive_technical_evidence",
            "dimension:demonstrated_capabilities",
            "dimension:technical_methods",
        ),
        "target_sections": ("project-landscape", "capability-context"),
    },
    "portfolio": {
        "label": "Portfolio talent",
        "evidence_refs": (
            "metric:primary_execution",
            "dimension:leadership_state",
            "dimension:career_delivery",
        ),
        "target_sections": ("project-landscape", "career-context"),
    },
}


_PAYLOAD_KEYS = frozenset({
    "aggregate_sha256", "cover_dek", "cover_title",
    "event_definition_sha256", "interaction_profile", "questions", "version",
})
_QUESTION_PAYLOAD_KEYS = frozenset({
    "answer", "evidence_refs", "key", "label", "target_sections",
})


def _validate_copy(value: object, *, label: str, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or value != value.strip()
        or len(value) > maximum
        or _FORBIDDEN_COPY.search(value)
    ):
        raise PermissionError(f"partner presentation {label} is unsafe")
    return value


def _validate_copy_option(
    value: object, *, field: str, label: str, maximum: int,
) -> str:
    validated = _validate_copy(value, label=label, maximum=maximum)
    if validated not in _COPY_OPTIONS[field]:
        raise PermissionError(
            f"partner presentation {label} is not an approved evidence-bound option",
        )
    return validated


def _available_evidence_refs(summary: PartnerSemanticSummary) -> frozenset[str]:
    return frozenset({
        *(f"metric:{metric.key}" for metric in summary.metrics),
        *(f"dimension:{dimension.key}" for dimension in summary.dimensions),
    })


def validate_partner_report_presentation(
    presentation: PartnerReportPresentation,
    *,
    semantic_summary: PartnerSemanticSummary,
) -> PartnerReportPresentation:
    """Fail closed on stale bindings, authored numbers, or unbound evidence."""

    validate_partner_semantic_summary(semantic_summary)
    if not isinstance(presentation, PartnerReportPresentation):
        raise PermissionError("partner presentation is invalid")
    if presentation.version != _VERSION:
        raise PermissionError("partner presentation version is invalid")
    if presentation.interaction_profile != _INTERACTION_PROFILE:
        raise PermissionError("partner presentation interaction profile is invalid")
    _validate_copy_option(
        presentation.cover_title,
        field="cover_title", label="cover title", maximum=100,
    )
    _validate_copy_option(
        presentation.cover_dek,
        field="cover_dek", label="cover deck", maximum=320,
    )

    if tuple(question.key for question in presentation.questions) != _QUESTION_KEYS:
        raise PermissionError("partner presentation question order is invalid")
    available_refs = _available_evidence_refs(semantic_summary)
    for question in presentation.questions:
        if (
            not isinstance(question, PartnerQuestion)
            or not _KEY.fullmatch(question.key)
        ):
            raise PermissionError("partner presentation question is invalid")
        contract = _QUESTION_CONTRACTS[question.key]
        if question.label != contract["label"]:
            raise PermissionError("partner presentation question label is invalid")
        _validate_copy_option(
            question.answer,
            field=question.key, label="question answer", maximum=400,
        )
        if (
            question.evidence_refs != contract["evidence_refs"]
            or any(reference not in available_refs for reference in question.evidence_refs)
        ):
            raise PermissionError("partner presentation evidence reference is invalid")
        if (
            question.target_sections != contract["target_sections"]
            or any(section not in _SECTION_KEYS for section in question.target_sections)
        ):
            raise PermissionError("partner presentation target section is invalid")
    for label, actual, expected in (
        (
            "event definition",
            presentation.event_definition_sha256,
            semantic_summary.event_definition_sha256,
        ),
        ("aggregate", presentation.aggregate_sha256, semantic_summary.aggregate_sha256),
    ):
        if not isinstance(actual, str) or not _HASH.fullmatch(actual):
            raise PermissionError(f"partner presentation {label} binding is invalid")
        if actual != expected:
            raise StalePartnerPresentationError(label)
    return presentation


def build_default_partner_report_presentation(
    semantic_summary: PartnerSemanticSummary,
) -> PartnerReportPresentation:
    """Build polished deterministic copy from the validated aggregate schema."""

    validate_partner_semantic_summary(semantic_summary)
    presentation = PartnerReportPresentation(
        version=_VERSION,
        event_definition_sha256=str(semantic_summary.event_definition_sha256),
        aggregate_sha256=semantic_summary.aggregate_sha256,
        interaction_profile=_INTERACTION_PROFILE,
        cover_title=_COPY_OPTIONS["cover_title"][0],
        cover_dek=_COPY_OPTIONS["cover_dek"][0],
        questions=tuple(
            PartnerQuestion(
                key=key,
                label=str(_QUESTION_CONTRACTS[key]["label"]),
                answer=_COPY_OPTIONS[key][0],
                evidence_refs=tuple(_QUESTION_CONTRACTS[key]["evidence_refs"]),
                target_sections=tuple(_QUESTION_CONTRACTS[key]["target_sections"]),
            )
            for key in _QUESTION_KEYS
        ),
    )
    return validate_partner_report_presentation(
        presentation, semantic_summary=semantic_summary,
    )


def _dashboard_metric_payload(
    metric: object,
    *,
    cohort_denominator: int,
    unknown_count: int | None,
    unknown_context: str,
    unattributed_membership_unknown_count: int,
) -> dict[str, object]:
    """Expose one aggregate metric with the evidence needed to interpret it."""

    count = getattr(metric, "count")
    denominator = getattr(metric, "denominator")
    state = str(getattr(metric, "state"))
    attributed_denominator = (
        cohort_denominator - unattributed_membership_unknown_count
    )
    if (
        attributed_denominator < 0
        or denominator is not None
        and denominator != attributed_denominator
    ):
        raise PermissionError("dashboard metric denominator is inconsistent")
    public_unknown_count = (
        None
        if unknown_count is None
        else unknown_count + unattributed_membership_unknown_count
    )
    unknown_count_text = (
        "Count withheld by the small-group privacy rule."
        if public_unknown_count is None
        else f"{public_unknown_count} {unknown_context}."
    )
    return {
        "count": count,
        "definition": str(getattr(metric, "note")),
        "denominator": cohort_denominator,
        "evidence_standard": (
            "Reviewed application, public-project, and event-submission evidence; "
            "missing evidence remains unknown."
        ),
        "key": str(getattr(metric, "key")),
        "label": str(getattr(metric, "label")),
        "state": state,
        "unknown_state": {
            "count": public_unknown_count,
            "count_text": unknown_count_text,
            "meaning": (
                "Not every reviewed source can support every metric. No recorded "
                "positive evidence for this signal means unknown, not a negative "
                "assessment."
            ),
            "state": (
                "reported" if public_unknown_count is not None else "withheld"
            ),
        },
    }


def _dimension_dashboard_metrics(
    summary: PartnerSemanticSummary,
) -> tuple[dict[str, PartnerSemanticMetric], dict[str, int | None], dict[str, str]]:
    """Project selected overlapping dimensions into truthful dashboard metrics."""

    dimensions = {dimension.key: dimension for dimension in summary.dimensions}
    metrics: dict[str, PartnerSemanticMetric] = {}
    unknown_counts: dict[str, int | None] = {}
    unknown_contexts: dict[str, str] = {}
    for output_key, (
        dimension_key, cell_key, label, definition,
    ) in _DIMENSION_METRIC_SPECS.items():
        dimension = dimensions.get(dimension_key)
        if dimension is None:
            raise PermissionError(
                "dashboard lens references unavailable taxonomy evidence"
            )
        cell = next(
            (item for item in dimension.cells if item.key == cell_key),
            None,
        )
        if cell is None:
            raise PermissionError(
                "dashboard lens references unavailable taxonomy cell"
            )
        metrics[output_key] = PartnerSemanticMetric(
            key=output_key,
            count=cell.count,
            denominator=dimension.denominator,
            label=label,
            note=definition,
            state=cell.state,
        )
        unknown_counts[output_key] = dimension.unknown_count
        unknown_contexts[output_key] = (
            "people had no classified demonstrated-capability evidence"
            if dimension_key == "demonstrated_capabilities"
            else "people had no classified career-delivery evidence"
        )
    return metrics, unknown_counts, unknown_contexts


def build_partner_dashboard_state(
    cohort_bundle: PartnerSemanticCohortBundle,
    *,
    presentation: PartnerReportPresentation,
) -> dict[str, object]:
    """Build one unified aggregate evidence view for each reviewed cohort."""

    validated = validate_partner_semantic_cohort_bundle(cohort_bundle)
    all_summary = validated.cohorts[0].summary
    validate_partner_report_presentation(
        presentation,
        semantic_summary=all_summary,
    )
    metric_order = tuple(
        str(metric_key)
        for group in _DASHBOARD_METRIC_GROUPS
        for metric_key in group["metric_keys"]
    )
    if len(metric_order) != len(set(metric_order)):
        raise RuntimeError("dashboard metric groups contain duplicate metrics")
    cohorts: list[dict[str, object]] = []
    for cohort in validated.cohorts:
        summary = validate_partner_semantic_summary(cohort.summary)
        dimension_metrics, dimension_unknown_counts, dimension_unknown_contexts = (
            _dimension_dashboard_metrics(summary)
        )
        dashboard_metrics = (
            *summary.metrics, *summary.public_groups, *dimension_metrics.values(),
        )
        metrics_by_key = {metric.key: metric for metric in dashboard_metrics}
        if len(metrics_by_key) != len(dashboard_metrics):
            raise PermissionError("dashboard metric keys are not unique")
        coverage = [
            {
                "count": count,
                "definition": _SOURCE_COVERAGE[key][1],
                "key": key,
                "label": _SOURCE_COVERAGE[key][0],
                "state": "reported" if count is not None else "withheld",
            }
            for key, count in summary.source_coverage
            if count is not None
        ]
        if any(key not in metrics_by_key for key in metric_order):
            raise PermissionError("dashboard references unavailable aggregate evidence")
        metrics = [
            _dashboard_metric_payload(
                metrics_by_key[key],
                cohort_denominator=cohort.denominator,
                unknown_count=dimension_unknown_counts.get(
                    key, summary.unknown_count,
                ),
                unknown_context=dimension_unknown_contexts.get(
                    key,
                    "whole-person records had missing or conflicting reviewed evidence",
                ),
                unattributed_membership_unknown_count=(
                    cohort.unattributed_membership_unknown_count
                ),
            )
            for key in metric_order
        ]
        cohorts.append({
            "denominator": cohort.denominator,
            "definition": _COHORT_DEFINITIONS[cohort.key],
            "key": cohort.key,
            "label": cohort.label,
            "metrics": metrics,
            "source_coverage": coverage,
        })
    return {
        "cohorts": cohorts,
        "metric_groups": [
            {
                "description": str(group["description"]),
                "key": str(group["key"]),
                "label": str(group["label"]),
                "metric_keys": [str(key) for key in group["metric_keys"]],
            }
            for group in _DASHBOARD_METRIC_GROUPS
        ],
        "version": _DASHBOARD_VERSION,
    }


def partner_report_presentation_payload(
    presentation: PartnerReportPresentation,
) -> dict[str, object]:
    """Return the canonical JSON-safe editorial contract."""

    if not isinstance(presentation, PartnerReportPresentation):
        raise TypeError("partner presentation is invalid")
    return {
        "aggregate_sha256": presentation.aggregate_sha256,
        "cover_dek": presentation.cover_dek,
        "cover_title": presentation.cover_title,
        "event_definition_sha256": presentation.event_definition_sha256,
        "interaction_profile": presentation.interaction_profile,
        "questions": [
            {
                "answer": question.answer,
                "evidence_refs": list(question.evidence_refs),
                "key": question.key,
                "label": question.label,
                "target_sections": list(question.target_sections),
            }
            for question in presentation.questions
        ],
        "version": presentation.version,
    }


def _canonical_bytes(presentation: PartnerReportPresentation) -> bytes:
    return (
        json.dumps(
            partner_report_presentation_payload(presentation),
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def partner_report_presentation_sha256(
    presentation: PartnerReportPresentation,
) -> str:
    """Hash the exact validated presentation contract, not rendered HTML."""

    return hashlib.sha256(_canonical_bytes(presentation)).hexdigest()


def _presentation_from_payload(payload: object) -> PartnerReportPresentation:
    if not isinstance(payload, dict) or set(payload) != _PAYLOAD_KEYS:
        raise PermissionError("partner presentation payload is invalid")
    questions = payload.get("questions")
    if not isinstance(questions, list):
        raise PermissionError("partner presentation questions are invalid")
    parsed_questions: list[PartnerQuestion] = []
    for item in questions:
        if not isinstance(item, dict) or set(item) != _QUESTION_PAYLOAD_KEYS:
            raise PermissionError("partner presentation question payload is invalid")
        evidence_refs = item.get("evidence_refs")
        target_sections = item.get("target_sections")
        if (
            not isinstance(evidence_refs, list)
            or any(not isinstance(value, str) for value in evidence_refs)
            or not isinstance(target_sections, list)
            or any(not isinstance(value, str) for value in target_sections)
        ):
            raise PermissionError("partner presentation question payload is invalid")
        parsed_questions.append(PartnerQuestion(
            key=item.get("key"),
            label=item.get("label"),
            answer=item.get("answer"),
            evidence_refs=tuple(evidence_refs),
            target_sections=tuple(target_sections),
        ))
    return PartnerReportPresentation(
        version=payload.get("version"),
        event_definition_sha256=payload.get("event_definition_sha256"),
        aggregate_sha256=payload.get("aggregate_sha256"),
        interaction_profile=payload.get("interaction_profile"),
        cover_title=payload.get("cover_title"),
        cover_dek=payload.get("cover_dek"),
        questions=tuple(parsed_questions),
    )


def load_partner_report_presentation(
    path: str | Path,
    *,
    semantic_summary: PartnerSemanticSummary,
) -> PartnerReportPresentation:
    """Load a private presentation file and reject unsafe or stale content."""

    source = Path(path)
    if source.is_symlink() or not source.is_file():
        raise PermissionError("partner presentation file is unsafe")
    if source.stat().st_mode & 0o077:
        raise PermissionError("partner presentation file permissions are unsafe")
    try:
        payload = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PermissionError("partner presentation file is unreadable") from error
    return validate_partner_report_presentation(
        _presentation_from_payload(payload), semantic_summary=semantic_summary,
    )


def load_or_create_partner_report_presentation(
    path: str | Path,
    *,
    semantic_summary: PartnerSemanticSummary,
) -> PartnerReportPresentation:
    """Load current copy, or reset only an older aggregate-bound copy to defaults."""

    source = Path(path)
    if source.exists() or source.is_symlink():
        try:
            return load_partner_report_presentation(
                source, semantic_summary=semantic_summary,
            )
        except StalePartnerPresentationError as error:
            if error.binding != "aggregate":
                raise
        except PermissionError as original_error:
            if (
                source.is_symlink()
                or not source.is_file()
                or source.stat().st_mode & 0o077
            ):
                raise
            try:
                payload = json.loads(source.read_text(encoding="utf-8"))
                retired = _presentation_from_payload(payload)
                migrated_questions = tuple(
                    replace(
                        question,
                        answer=_COPY_OPTIONS[question.key][0],
                    )
                    if question.answer in _RETIRED_COPY_OPTIONS.get(
                        question.key, frozenset(),
                    )
                    else question
                    for question in retired.questions
                )
                if migrated_questions == retired.questions:
                    raise original_error
                presentation = validate_partner_report_presentation(
                    replace(retired, questions=migrated_questions),
                    semantic_summary=semantic_summary,
                )
            except (
                OSError, UnicodeDecodeError, json.JSONDecodeError,
                PermissionError, TypeError,
            ) as migration_error:
                raise original_error from migration_error
            return write_partner_report_presentation(
                source, presentation, semantic_summary=semantic_summary,
            )
    presentation = build_default_partner_report_presentation(semantic_summary)
    return write_partner_report_presentation(
        source, presentation, semantic_summary=semantic_summary,
    )


def partner_report_presentation_copy_options() -> dict[str, tuple[str, ...]]:
    """Return the server-owned truth-preserving copy choices for the operator UI."""

    return {key: tuple(values) for key, values in _COPY_OPTIONS.items()}


def write_partner_report_presentation(
    path: str | Path,
    presentation: PartnerReportPresentation,
    *,
    semantic_summary: PartnerSemanticSummary,
) -> PartnerReportPresentation:
    """Atomically persist reviewed report copy in restrictive private storage."""

    validated = validate_partner_report_presentation(
        presentation, semantic_summary=semantic_summary,
    )
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if target.parent.is_symlink() or target.is_symlink():
        raise PermissionError("partner presentation target is unsafe")
    target.parent.chmod(0o700)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{target.name}.", suffix=".tmp", dir=target.parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(_canonical_bytes(validated))
            stream.flush()
            os.fsync(stream.fileno())
        temporary.chmod(0o600)
        os.replace(temporary, target)
        target.chmod(0o600)
    finally:
        temporary.unlink(missing_ok=True)
    return validated


__all__ = (
    "PartnerQuestion",
    "PartnerReportPresentation",
    "StalePartnerPresentationError",
    "build_default_partner_report_presentation",
    "build_partner_dashboard_state",
    "load_or_create_partner_report_presentation",
    "load_partner_report_presentation",
    "partner_report_presentation_copy_options",
    "partner_report_presentation_payload",
    "partner_report_presentation_sha256",
    "validate_partner_report_presentation",
    "write_partner_report_presentation",
)
