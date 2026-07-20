"""Concise partner report generated from validated aggregate contracts."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from html import escape
import json
from pathlib import Path
from urllib.parse import quote

from community_os.partner_semantic_projection import (
    PartnerSemanticCohortBundle,
    PartnerSemanticDimension,
    PartnerSemanticMetric,
    PartnerSemanticSummary,
)
from community_os.partner_report_presentation import (
    PartnerReportPresentation,
    build_default_partner_report_presentation,
    build_partner_dashboard_state,
    validate_partner_report_presentation,
)
from community_os.report_contract import TalentReportContract
from community_os.talent_intelligence_contract import (
    CountValue,
    Dimension,
    DimensionItem,
    Intersection,
    TalentIntelligenceContract,
)


_EXTERNAL_DEFINITION_ORDER = (
    "prototype_or_beyond",
    "advanced_technical_evidence",
    "differentiated_problem",
    "primary_execution",
    "meaningful_validation",
    "substantive_technical_evidence",
)


def _external_definition_metrics(
    summary: PartnerSemanticSummary,
) -> tuple[PartnerSemanticMetric, ...]:
    metrics = {
        metric.key: metric
        for metric in (*summary.metrics, *summary.public_groups)
    }
    return tuple(
        metrics[key] for key in _EXTERNAL_DEFINITION_ORDER if key in metrics
    )


def _assert_contract_parity(
    report: TalentIntelligenceContract,
    event_report: TalentReportContract,
) -> None:
    for field in (
        "event_key", "event_name", "event_date", "generated_at", "synthetic",
        "publication_state",
    ):
        if getattr(report.metadata, field) != getattr(event_report.metadata, field):
            raise ValueError(f"contract drift: metadata.{field}")
    for field in ("mode", "minimum_count", "pii_included", "state"):
        if getattr(report.privacy, field) != getattr(event_report.privacy, field):
            raise ValueError(f"contract drift: privacy.{field}")
    if report.cohort.unit != event_report.attendance_funnel.unit:
        raise ValueError("contract drift: shared_funnel.unit")

    intelligence_stages = {
        stage.key: (stage.count.value, stage.count.privacy, stage.count.reason)
        for stage in report.cohort.stages
    }
    event_stages = {
        stage.key: (stage.count.value, stage.count.privacy, stage.count.reason)
        for stage in event_report.attendance_funnel.stages
    }

    def resolve(
        stages: dict[str, tuple[int | None, str, str | None]],
        aliases: tuple[str, ...],
    ) -> tuple[int | None, str, str | None] | None:
        return next((stages[key] for key in aliases if key in stages), None)

    shared = (
        ("applicants", ("valid_applicants",), ("applied",), False),
        ("accepted", ("going_accepted", "accepted"), ("going_accepted", "approved"), True),
        ("checked_in", ("on_site", "checked_in"), ("on_site", "checked_in"), True),
        ("submitted", ("submitted",), ("submitted",), False),
    )
    for label, intelligence_aliases, event_aliases, required in shared:
        intelligence_count = resolve(intelligence_stages, intelligence_aliases)
        event_count = resolve(event_stages, event_aliases)
        if required and (intelligence_count is None or event_count is None):
            raise ValueError(f"contract drift: shared_funnel.{label}")
        if label == "submitted" and (intelligence_count is None) != (event_count is None):
            raise ValueError(f"contract drift: shared_funnel.{label}")
        if intelligence_count is not None and event_count is not None and intelligence_count != event_count:
            raise ValueError(f"contract drift: shared_funnel.{label}")


def _logo_data_uri() -> str:
    asset = Path(__file__).resolve().parents[1] / "assets/brand/start-warsaw-white.svg"
    return "data:image/svg+xml," + quote(
        asset.read_text(encoding="utf-8"), safe="/,:;=()",
    )


def _dimension(report: TalentIntelligenceContract, key: str) -> Dimension | None:
    return next((item for item in report.dimensions if item.key == key), None)


def _item(
    report: TalentIntelligenceContract,
    dimension_key: str,
    item_key: str,
) -> DimensionItem | None:
    dimension = _dimension(report, dimension_key)
    if dimension is None:
        return None
    return next((item for item in dimension.items if item.key == item_key), None)


def _stage_count(
    report: TalentIntelligenceContract,
    aliases: tuple[str, ...],
) -> CountValue | None:
    return next(
        (stage.count for stage in report.cohort.stages if stage.key in aliases),
        None,
    )


def _event_stage_count(
    report: TalentReportContract,
    aliases: tuple[str, ...],
) -> CountValue | None:
    return next(
        (stage.count for stage in report.attendance_funnel.stages if stage.key in aliases),
        None,
    )


def _rate(value: int, denominator: int) -> int:
    return round(value / denominator * 100) if denominator else 0


def _count_line(value: int, denominator: int) -> str:
    return f"{value} of {denominator} ({_rate(value, denominator)}%)"


def _funnel_band(kind: str, value: int, denominator: int) -> str:
    ratio = max(0.0, min(value / denominator, 1.0)) if denominator else 0.0
    width = f"{ratio * 100:.6f}".rstrip("0").rstrip(".")
    return (
        '<svg class="funnel-track" aria-hidden="true" viewBox="0 0 100 10" '
        'preserveAspectRatio="none"><rect class="funnel-base" width="100" '
        'height="10"></rect><rect class="funnel-band '
        + escape(kind) + '" width="' + width + '" height="10"></rect></svg>'
    )


def _exact_percentage(value: int, denominator: int) -> str:
    if denominator == 0:
        return "0"
    return f"{value / denominator * 100:.6f}".rstrip("0").rstrip(".")


def _headline_finding(value: str, label: str) -> str:
    return (
        '<article class="cover-finding">'
        f'<strong>{escape(value)}</strong><span>{escape(label)}</span></article>'
    )


def _submitted_teams(report: TalentReportContract) -> tuple[int | None, int | None]:
    matrix_cells = tuple(report.team_submission_matrix.cells)
    if not matrix_cells or any(
        count.privacy != "published" or count.value is None
        for count in (cell.count for cell in matrix_cells)
    ):
        return None, None
    submitted = sum(
        cell.count.value
        for cell in matrix_cells
        if cell.column == "submitted" and cell.count.value is not None
    )
    eligible = sum(
        cell.count.value
        for cell in matrix_cells
        if cell.count.value is not None
    )
    return submitted, eligible


def _cover(
    report: TalentIntelligenceContract,
    event_report: TalentReportContract,
    semantic_summary: PartnerSemanticSummary | None,
    presentation: PartnerReportPresentation | None = None,
) -> str:
    denominator = report.cohort.denominator.value or 0
    submitted, eligible = _submitted_teams(event_report)
    if semantic_summary is None:
        shipped = _item(report, "builder_evidence", "shipped_product")
        data_ai = _item(report, "functional_role", "data_ai")
        accepted = _stage_count(report, ("going_accepted", "accepted"))
        findings = (
            _headline_finding(
                _count_line(shipped.count.value, denominator)
                if shipped is not None and shipped.count.value is not None else "Evidence pending",
                "show evidence of shipping a product beyond a concept",
            )
            + _headline_finding(
                _count_line(data_ai.count.value, denominator)
                if data_ai is not None and data_ai.count.value is not None else "Evidence pending",
                "mention data or AI in their submitted evidence",
            )
            + _headline_finding(
                f"{submitted} of {eligible}"
                if submitted is not None and eligible else "Evidence pending",
                "final teams submitted a project",
            )
            + _headline_finding(
                _count_line(accepted.value, denominator)
                if accepted is not None and accepted.value is not None
                else "Count withheld",
                "were accepted by organizers",
            )
        )
        dek = (
            "A compact view of demand, capabilities, career context, demonstrated "
            "building, and domain experience."
        )
    else:
        headline_order = (
            "advanced_technical_evidence", "differentiated_problem",
            "primary_execution", "meaningful_validation",
        )
        metrics_by_key = {
            metric.key: metric for metric in semantic_summary.metrics
        }
        headline_metrics = tuple(
            metrics_by_key[key] for key in headline_order
            if key in metrics_by_key
            and metrics_by_key[key].count is not None
            and int(metrics_by_key[key].count or 0) > 0
        )
        findings = "".join(
            _headline_finding(
                (
                    "Count withheld" if metric.count is None
                    else f"{metric.count} people" if metric.denominator is None
                    else _count_line(metric.count, metric.denominator)
                ),
                metric.label.casefold(),
            )
            for metric in headline_metrics
        )
        dek = (
            presentation.cover_dek
            if presentation is not None
            else "An AI-assisted, evidence-bound assessment of product seriousness, technical "
            "substance, originality, execution, and validation, connected to the event story."
        )
    synthetic = (
        '<p class="synthetic-label">Illustrative synthetic data</p>'
        if report.metadata.synthetic else ""
    )
    return (
        '<header class="cover report-page report-page-cover" data-pdf-page="1">'
        f'<img class="brand" src="{_logo_data_uri()}" alt="START Warsaw">'
        '<div class="cover-copy"><p class="eyebrow">Partner talent brief</p>'
        f'<h1>{escape(presentation.cover_title if presentation is not None else "Builders who ship, shown through the work.")}</h1>'
        f'<p class="dek">{escape(dek)}</p>'
        f'<div class="cover-findings">{findings}</div>{synthetic}</div>'
        '<div class="cover-meta">'
        f'<span>Event <b>{escape(report.metadata.event_name)}</b></span>'
        f'<span>Event date <b>{escape(report.metadata.event_date)}</b></span>'
        '<span>Scope <b>Partner-safe evidence summary</b></span>'
        '</div></header>'
    )


def _exhibit(
    key: str,
    number: str,
    title: str,
    scope: str,
    body: str,
) -> str:
    return (
        f'<section class="exhibit" id="{escape(key)}" data-section-key="{escape(key)}">'
        '<header class="exhibit-head">'
        f'<p class="exhibit-number">{escape(number)}</p><h2>{escape(title)}</h2>'
        f'<p>{escape(scope)}</p></header>{body}</section>'
    )


def _report_page(
    number: int,
    body: str,
    *,
    layout: str,
    decision_key: str | None = None,
    decision_question: str | None = None,
) -> str:
    if (decision_key is None) != (decision_question is None):
        raise ValueError("decision key and question must be supplied together")
    decision = ""
    if decision_key is not None and decision_question is not None:
        decision = (
            f' data-decision-question="{escape(decision_key)}"'
        )
    question = (
        f'<p class="decision-question">{escape(decision_question)}</p>'
        if decision_question is not None else ""
    )
    return (
        f'<div class="report-page report-page-{escape(layout)}" '
        f'{decision} data-pdf-page="{number}">{question}{body}</div>'
    )


def _presentation_evidence(
    summary: PartnerSemanticSummary,
    reference: str,
) -> str:
    family, key = reference.split(":", 1)
    if family == "metric":
        metric = next(item for item in summary.metrics if item.key == key)
        value = (
            "Count withheld"
            if metric.count is None
            else str(metric.count)
            if metric.denominator is None
            else _count_line(metric.count, metric.denominator)
        )
        return (
            '<li><strong>' + escape(value) + '</strong>'
            f'<span>{escape(metric.label)}</span></li>'
        )
    dimension = _semantic_dimension(summary, key)
    return (
        '<li><strong>Explore the evidence</strong>'
        f'<span>{escape(dimension.label)}</span></li>'
    )


def _partner_questions(
    summary: PartnerSemanticSummary,
    presentation: PartnerReportPresentation,
) -> str:
    controls = "".join(
        '<button type="button" data-partner-question="'
        + escape(question.key)
        + '" aria-pressed="'
        + ("true" if index == 0 else "false")
        + '">'
        + escape(question.label)
        + '</button>'
        for index, question in enumerate(presentation.questions)
    )
    answers = "".join(
        '<article class="partner-answer'
        + (" is-active" if index == 0 else "")
        + '" data-partner-answer="'
        + escape(question.key)
        + '" data-target-sections="'
        + escape(" ".join(question.target_sections))
        + '"><p>'
        + escape(question.answer)
        + '</p><ul>'
        + "".join(
            _presentation_evidence(summary, reference)
            for reference in question.evidence_refs
        )
        + '</ul></article>'
        for index, question in enumerate(presentation.questions)
    )
    return (
        '<section class="partner-questions" aria-labelledby="partner-questions-title">'
        '<div><p class="eyebrow">Explore by partner question</p>'
        '<h3 id="partner-questions-title">What do you need to know?</h3></div>'
        f'<div class="partner-question-controls" role="group" aria-label="Partner questions">{controls}</div>'
        f'<div class="partner-answer-region" aria-live="polite">{answers}</div>'
        '<div class="pdf-actions">'
        '<a href="talent-brief.real.pdf" download>Download PDF</a></div></section>'
    )


def _dashboard_metric(
    metric: Mapping[str, object], *, selected: bool = False,
) -> str:
    count = metric["count"]
    denominator = metric["denominator"]
    display = "Protected" if count is None else str(count)
    share = (
        0 if count is None or denominator in (None, 0)
        else round(int(count) / int(denominator) * 100, 1)
    )
    return (
        '<button type="button" class="dashboard-metric" data-dashboard-metric-select="'
        + escape(str(metric["key"]))
        + '" aria-pressed="' + ("true" if selected else "false") + '"><span><strong>'
        + escape(display) + '</strong>'
        + '<small>' + escape(str(metric["label"])) + '</small></span>'
        + '<i aria-hidden="true"><b style="--metric-share:' + str(share)
        + '%"></b></i></button>'
    )


def _dashboard_metric_from_cohort(
    cohort: Mapping[str, object], *, metric_key: str,
) -> Mapping[str, object] | None:
    metrics = cohort.get("metrics")
    if not isinstance(metrics, list):
        return None
    return next(
        (
            item for item in metrics
            if isinstance(item, Mapping) and item.get("key") == metric_key
        ),
        None,
    )


def _dashboard_comparison(
    state: Mapping[str, object], *, metric_key: str,
) -> str:
    cohorts = state["cohorts"]
    assert isinstance(cohorts, list)
    cells = ""
    for cohort in cohorts:
        assert isinstance(cohort, Mapping)
        metric = _dashboard_metric_from_cohort(cohort, metric_key=metric_key)
        denominator = int(cohort["denominator"])
        count = metric.get("count") if isinstance(metric, Mapping) else None
        share = (
            0 if count is None or denominator == 0
            else round(int(count) / denominator * 100, 1)
        )
        cells += (
            '<div class="dashboard-comparison-cell"><span>'
            + escape(str(cohort["label"])) + '</span><strong>'
            + escape("Protected" if count is None else f"{count} of {denominator}")
            + '</strong><i aria-hidden="true"><b style="--comparison-share:'
            + str(share) + '%"></b></i><small>'
            + escape("Not publishable" if count is None else f"{round(share)}% of cohort")
            + '</small></div>'
        )
    return '<div class="dashboard-comparison" data-dashboard-comparison>' + cells + '</div>'


def _dashboard_inspector(
    state: Mapping[str, object], *, metric: Mapping[str, object],
) -> str:
    unknown = metric["unknown_state"]
    assert isinstance(unknown, Mapping)
    denominator = metric["denominator"]
    return (
        '<article class="dashboard-inspector" data-dashboard-inspector '
        'aria-live="polite" aria-atomic="true"><div class="dashboard-inspector-copy">'
        '<p class="eyebrow">Selected evidence</p><h3 data-inspector-label>'
        + escape(str(metric["label"])) + '</h3><p data-inspector-definition>'
        + escape(str(metric["definition"])) + '</p><dl>'
        '<div><dt>Evidence standard</dt><dd data-inspector-standard>'
        + escape(str(metric["evidence_standard"])) + '</dd></div>'
        '<div><dt>Selected denominator</dt><dd data-inspector-denominator>'
        + escape("Protected" if denominator is None else str(denominator)) + '</dd></div>'
        '<div><dt>Evidence limits</dt><dd data-inspector-coverage>'
        + escape(str(unknown["count_text"]))
        + ' ' + escape(str(unknown["meaning"])) + '</dd></div></dl></div>'
        '<section><h3>Compare the same signal</h3>'
        + _dashboard_comparison(state, metric_key=str(metric["key"]))
        + '</section></article>'
    )


@dataclass(frozen=True)
class _PublishedOverlapData:
    total: int
    signal_keys: tuple[str, str, str]
    signal_items: Mapping[str, DimensionItem]
    exact_rows: tuple[Intersection, ...]
    unknown_copy: str
    student_overlay: Intersection | None


_PUBLISHED_OVERLAP_SIGNATURES = {
    "founder_technical_shipped_product_exact": (True, True, True),
    "founder_technical_exact": (True, True, False),
    "founder_shipped_product_exact": (True, False, True),
    "founder_only_exact": (True, False, False),
    "technical_shipped_product_exact": (False, True, True),
    "technical_only_exact": (False, True, False),
    "shipped_product_only_exact": (False, False, True),
    "neither_recorded_exact": (False, False, False),
}


def _overlap_signature(
    item: Intersection,
    signal_keys: tuple[str, str, str],
) -> tuple[bool, bool, bool]:
    components = set(item.component_keys)
    return tuple(
        f"cross_dimension_signals.{key}" in components
        for key in signal_keys
    )  # type: ignore[return-value]


def _published_overlap_data(
    report: TalentIntelligenceContract,
) -> _PublishedOverlapData | None:
    """Return one validated aggregate model for screen and PDF views."""

    total = report.cohort.denominator.value
    signal_dimension = _dimension(report, "cross_dimension_signals")
    if total is None or signal_dimension is None:
        return None
    signal_keys = (
        "founder_evidence",
        "technical_function",
        "shipped_product_evidence",
    )
    signal_items = {
        item.key: item for item in signal_dimension.items
    }
    if any(
        key not in signal_items
        or signal_items[key].count.value is None
        or signal_items[key].count.privacy != "published"
        for key in signal_keys
    ):
        return None

    exact_rows = tuple(
        item for item in report.intersections
        if item.key.endswith("_exact")
        and all(
            component.startswith("cross_dimension_signals.")
            for component in item.component_keys
        )
    )
    if (
        len(exact_rows) != 8
        or any(
            item.count.value is None or item.count.privacy != "published"
            for item in exact_rows
        )
        or sum(int(item.count.value or 0) for item in exact_rows) != total
    ):
        return None

    allowed_components = {
        f"cross_dimension_signals.{key}{suffix}"
        for key in signal_keys
        for suffix in ("", "_not_recorded")
    }
    for item in exact_rows:
        components = set(item.component_keys)
        if (
            len(components) != len(item.component_keys)
            or not components.issubset(allowed_components)
            or any(
                (
                    f"cross_dimension_signals.{key}" in components
                ) == (
                    f"cross_dimension_signals.{key}_not_recorded" in components
                )
                for key in signal_keys
            )
        ):
            return None

    if (
        {item.key for item in exact_rows}
        != set(_PUBLISHED_OVERLAP_SIGNATURES)
        or any(
            _overlap_signature(item, signal_keys)
            != _PUBLISHED_OVERLAP_SIGNATURES[item.key]
            for item in exact_rows
        )
    ):
        return None

    for index, key in enumerate(signal_keys):
        positive_total = sum(
            int(item.count.value or 0)
            for item in exact_rows
            if _overlap_signature(item, signal_keys)[index]
        )
        complement = signal_items.get(f"{key}_not_recorded")
        if (
            signal_items[key].count.value != positive_total
            or complement is None
            or complement.count.privacy != "published"
            or complement.count.value != total - positive_total
        ):
            return None

    exact_rows = tuple(sorted(
        exact_rows,
        key=lambda item: (-(item.count.value or 0), item.label),
    ))
    unknown_specs = (
        ("Insufficient founder context", _item(report, "professional_identity", "insufficient_evidence")),
        ("Unclassified role or stage", _item(report, "seniority", "unknown")),
        ("Unclassified function", _item(report, "functional_role", "unknown")),
        ("Insufficient shipping context", _item(report, "builder_evidence", "insufficient_evidence")),
    )
    unknown_copy = " · ".join(
        f"{label}: {item.count.value}"
        for label, item in unknown_specs
        if item is not None and item.count.value is not None
    )

    student_overlay = next(
        (
            item for item in report.intersections
            if item.key == "student_shipped_product"
            and item.count.value is not None
            and item.count.privacy == "published"
        ),
        None,
    )
    return _PublishedOverlapData(
        total=total,
        signal_keys=signal_keys,
        signal_items=signal_items,
        exact_rows=exact_rows,
        unknown_copy=unknown_copy,
        student_overlay=student_overlay,
    )


def _overlap_column_key() -> str:
    return (
        '<div class="upset-column-key"><span class="upset-set-key" '
        'aria-label="Signal columns: Founder or co-founder, Technical function, Shipped product">'
        '<span>Founder</span><span>Technical</span><span>Shipped</span></span>'
        '<span>Exact intersection</span><strong>People</strong>'
        '<small>Share</small></div>'
    )


def _overlap_display_label(active: tuple[bool, bool, bool]) -> str:
    """Return a compact, plain-language label for one exact intersection row."""

    names = tuple(
        name
        for name, is_active in zip(
            ("founder", "technical", "shipped"), active, strict=True,
        )
        if is_active
    )
    if not names:
        return "None recorded"
    if len(names) == 1:
        return (names[0] + " only").capitalize()
    return " + ".join(names).capitalize()


def _published_overlap_explorer(report: TalentIntelligenceContract) -> str:
    """Render a complete privacy-safe UpSet partition over three reviewed signals."""

    data = _published_overlap_data(report)
    if data is None:
        return ""
    total = data.total
    signal_keys = data.signal_keys
    signal_items = data.signal_items
    exact_rows = data.exact_rows
    unknown_copy = data.unknown_copy
    labels = {key: signal_items[key].label for key in signal_keys}
    maximum = max(int(item.count.value or 0) for item in exact_rows) or 1
    first_row = exact_rows[0]

    signal_headers = "".join(
        '<div><strong>' + escape(labels[key]) + '</strong><span>'
        + str(signal_items[key].count.value) + ' of ' + str(total)
        + '</span><i aria-hidden="true"><b style="--signal-share:'
        + f"{int(signal_items[key].count.value or 0) / total * 100:.1f}"
        + '%"></b></i></div>'
        for key in signal_keys
    )

    def row_button(item: Intersection, *, selected: bool) -> str:
        active = _overlap_signature(item, signal_keys)
        display_label = _overlap_display_label(active)
        active_labels = [
            labels[key] for key, is_active in zip(signal_keys, active, strict=True)
            if is_active
        ]
        inactive_labels = [
            labels[key] for key, is_active in zip(signal_keys, active, strict=True)
            if not is_active
        ]
        recorded = ", ".join(active_labels) if active_labels else "none of the three signals"
        not_recorded = ", ".join(inactive_labels) if inactive_labels else "none"
        copy = (
            "Exact application-evidence cell. Recorded: " + recorded
            + ". Signal not recorded: " + not_recorded
            + ". A signal not recorded is not a negative assessment."
        )
        count = int(item.count.value or 0)
        dots = "".join(
            '<span class="upset-dot' + (" is-on" if is_active else "")
            + '"></span>'
            for is_active in active
        )
        return (
            '<button type="button" data-overlap-region="' + escape(item.key)
            + '" data-overlap-count="' + str(count) + '" data-overlap-label="'
            + escape(display_label) + '" data-overlap-copy="' + escape(copy)
            + '" aria-pressed="' + ("true" if selected else "false") + '">'
            '<span class="upset-set-matrix" aria-hidden="true">' + dots + '</span>'
            '<span class="upset-region-bar"><i style="--bar-share:'
            + f"{count / maximum * 100:.1f}" + '%"></i><b>'
            + escape(display_label) + '</b></span><strong>' + str(count)
            + '</strong><small>' + f"{count / total * 100:.1f}"
            + '%</small></button>'
        )

    rows = "".join(
        row_button(item, selected=item.key == first_row.key)
        for item in exact_rows
    )
    first_active = _overlap_signature(first_row, signal_keys)
    first_display_label = _overlap_display_label(first_active)
    first_recorded = ", ".join(
        labels[key]
        for key, is_active in zip(signal_keys, first_active, strict=True)
        if is_active
    ) or "none of the three signals"
    first_not_recorded = ", ".join(
        labels[key]
        for key, is_active in zip(signal_keys, first_active, strict=True)
        if not is_active
    ) or "none"
    first_copy = (
        "Exact application-evidence cell. Recorded: " + first_recorded
        + ". Signal not recorded: " + first_not_recorded
        + ". A signal not recorded is not a negative assessment."
    )

    student_overlay = data.student_overlay
    overlay_html = (
        '<aside class="overlap-supporting"><span>Additional safe cross-section</span>'
        '<strong>' + escape(student_overlay.label) + '</strong><b>'
        + str(student_overlay.count.value) + ' of ' + str(total) + '</b><p>'
        'The student overlay is separate and non-additive. It uses reviewed application '
        'labels and does not imply externally verified product delivery.</p></aside>'
        if student_overlay is not None else ""
    )

    return (
        '<details class="overlap-explorer" open><summary>'
        '<span>Cross-dimensional evidence</span>'
        '<small>Full applicant pool · denominator ' + str(total) + '</small>'
        '</summary><div class="overlap-explorer-body">'
        '<div class="overlap-upset-panel"><p class="overlap-reading-note">'
        'Each applicant appears in exactly one intersection row. The eight rows partition all '
        + str(total) + ' applicants. Filled dots mean the application signal was recorded; '
        'empty dots mean signal not recorded. Signal not recorded is not a negative assessment.'
        '</p><div class="upset-signal-heads">' + signal_headers + '</div>'
        + _overlap_column_key()
        + '<div class="upset-overlap" role="group" aria-label="Exact founder, technical-function, '
        'and shipped-product evidence intersections">' + rows + '</div>'
        + ('<p class="overlap-unknowns">' + escape(unknown_copy) + '</p>' if unknown_copy else '')
        + overlay_html + '</div><article class="overlap-inspector" data-overlap-inspector '
        'aria-live="polite" aria-atomic="true"><strong data-overlap-inspector-label>'
        + escape(first_display_label) + ' · ' + str(first_row.count.value)
        + '</strong><p data-overlap-inspector-copy>' + escape(first_copy)
        + '</p><small>Reviewed application evidence, not a quality score.</small>'
        '</article></div></details>'
    )


def _published_overlap_static(report: TalentIntelligenceContract) -> str:
    """Render the static PDF twin of the validated interactive partition."""

    data = _published_overlap_data(report)
    if data is None:
        return ""
    total = data.total
    labels = {
        key: data.signal_items[key].label for key in data.signal_keys
    }
    maximum = max(int(item.count.value or 0) for item in data.exact_rows) or 1
    signal_summary = "".join(
        '<article><span>' + escape(labels[key]) + '</span><strong>'
        + str(data.signal_items[key].count.value) + ' of ' + str(total)
        + '</strong><i aria-hidden="true"><b style="--signal-share:'
        + f"{int(data.signal_items[key].count.value or 0) / total * 100:.1f}"
        + '%"></b></i></article>'
        for key in data.signal_keys
    )
    rows = ""
    for item in data.exact_rows:
        active = _overlap_signature(item, data.signal_keys)
        display_label = _overlap_display_label(active)
        dots = "".join(
            '<span class="upset-dot' + (" is-on" if is_active else "")
            + '"></span>'
            for is_active in active
        )
        count = int(item.count.value or 0)
        rows += (
            '<div class="upset-static-row"><span class="upset-set-matrix" '
            'aria-hidden="true">' + dots + '</span><span class="upset-region-bar">'
            '<i style="--bar-share:' + f"{count / maximum * 100:.1f}"
            + '%"></i><b>' + escape(display_label) + '</b></span><strong>'
            + str(count) + '</strong><small>' + f"{count / total * 100:.1f}"
            + '%</small></div>'
        )
    student = data.student_overlay
    student_copy = (
        '<article><span>Additional publishable cross-section</span><strong>'
        + escape(student.label) + '</strong><b>' + str(student.count.value)
        + ' of ' + str(total) + '</b><p>Separate, non-additive application '
        'evidence. It does not imply externally verified product delivery.</p></article>'
        if student is not None else ""
    )
    unknown_copy = (
        '<p class="upset-static-unknowns">Unclassified or insufficient context: '
        + escape(data.unknown_copy) + '.</p>'
        if data.unknown_copy else ""
    )
    return _exhibit(
        "cross-dimensional-evidence",
        "04",
        "How applicant signals intersect",
        (
            "Exact reviewed application-evidence intersections across founder role, "
            "technical function, and shipped-product evidence."
        ),
        '<div class="upset-static-layout"><div><p class="upset-static-note">'
        'Each applicant appears in exactly one intersection row. Filled dots mark '
        'recorded signals; empty dots mean signal not recorded, not a negative assessment.'
        '</p><div class="upset-static-signals">' + signal_summary
        + '</div>' + _overlap_column_key()
        + '<div class="upset-static-rows">' + rows + '</div>'
        + unknown_copy + '</div><aside class="upset-static-aside"><article>'
        '<span>How to read it</span><strong>One exact partition</strong><b>'
        + str(total) + ' applicants</b><p>The eight rows reconcile to the full applicant '
        'pool. This is application classification evidence, not a quality score.</p>'
        '</article>' + student_copy + '<article><span>Publication boundary</span>'
        '<strong>Safe intersections only</strong><p>Additional cross-sections appear only '
        'when they remain publishable under the small-group privacy rule.</p></article>'
        '</aside></div>',
    )


def _partner_dashboard(
    state: Mapping[str, object], report: TalentIntelligenceContract,
) -> str:
    cohorts = state["cohorts"]
    assert isinstance(cohorts, list) and cohorts
    metric_groups = state["metric_groups"]
    assert isinstance(metric_groups, list) and metric_groups
    first_cohort = cohorts[0]
    assert isinstance(first_cohort, Mapping)
    metrics = first_cohort["metrics"]
    assert isinstance(metrics, list) and metrics
    metrics_by_key = {
        str(metric["key"]): metric
        for metric in metrics
        if isinstance(metric, Mapping)
    }
    cohort_buttons = "".join(
        '<button type="button" data-cohort-select="' + escape(str(cohort["key"]))
        + '" aria-pressed="' + ("true" if index == 0 else "false") + '">'
        + escape(str(cohort["label"])) + '</button>'
        for index, cohort in enumerate(cohorts)
        if isinstance(cohort, Mapping)
    )
    first_metric = metrics[0]
    assert isinstance(first_metric, Mapping)
    metric_group_html = ""
    for group in metric_groups:
        assert isinstance(group, Mapping)
        keys = group["metric_keys"]
        assert isinstance(keys, list)
        metric_group_html += (
            '<section class="dashboard-metric-group" data-dashboard-metric-group="'
            + escape(str(group["key"])) + '"><header><h3>'
            + escape(str(group["label"])) + '</h3><p>'
            + escape(str(group["description"])) + '</p></header>'
            '<div role="group" aria-label="' + escape(str(group["label"])) + '">'
            + "".join(
                _dashboard_metric(
                    metrics_by_key[str(key)],
                    selected=str(key) == str(first_metric["key"]),
                )
                for key in keys
            )
            + '</div></section>'
        )
    return (
        '<section class="partner-dashboard" aria-labelledby="dashboard-title">'
        '<header><p class="eyebrow">Interactive aggregate view</p>'
        '<h2 id="dashboard-title">Choose a cohort, then inspect the evidence</h2>'
        '<p>The cohort control changes every count, share, denominator, and comparison. '
        'The metric groups stay fixed so the evidence remains comparable. Select or '
        'focus a metric for its definition and limits. No score or ranking is created.</p></header>'
        '<div class="dashboard-controls"><div role="group" aria-label="Cohort">'
        '<span>Cohort</span>' + cohort_buttons + '</div></div>'
        '<article class="dashboard-cohort-summary" aria-live="polite" '
        'aria-atomic="true"><p data-dashboard-context>'
        + escape(str(first_cohort["label"])) + '</p><strong '
        'data-dashboard-denominator>' + escape(str(first_cohort["denominator"]))
        + '</strong><span>people in the selected cohort</span>'
        '<p data-dashboard-cohort-definition>'
        + escape(str(first_cohort["definition"])) + '</p></article>'
        '<div class="dashboard-chart" data-dashboard-chart '
        'aria-label="Explore aggregate evidence">' + metric_group_html + '</div>'
        + _dashboard_inspector(state, metric=first_metric)
        + _published_overlap_explorer(report)
        + '<div class="pdf-actions"><a href="talent-brief.real.pdf" download>'
        'Download PDF</a></div></section>'
    )


def _journey(
    report: TalentIntelligenceContract,
    event_report: TalentReportContract,
) -> str:
    denominator = report.cohort.denominator.value or 0
    accepted = _stage_count(report, ("going_accepted", "accepted"))
    attendance = _event_stage_count(event_report, ("on_site", "checked_in"))
    accepted_value = accepted.value if accepted and accepted.value is not None else 0
    submitted_teams, eligible_teams = _submitted_teams(event_report)
    accepted_band = _funnel_band("accepted", accepted_value, denominator)
    if attendance is None or attendance.value is None:
        attendance_row = (
            '<div class="funnel-row attendance-hidden" data-value-state="hidden">'
            '<div><span>03</span><strong>Confirmed present at the event</strong>'
            '<small>Attendance count hidden</small></div>'
            '<span class="privacy-marker" aria-hidden="true"><i></i><i></i><i></i></span>'
            '<p>No value encoded</p></div>'
        )
    else:
        attendance_gap = accepted_value - attendance.value
        attendance_row = (
            '<div class="funnel-row" data-value-state="published"><div><span>03</span>'
            f'<strong>Confirmed present at the event</strong><small>{attendance.value} people</small></div>'
            + _funnel_band("attendance", attendance.value, denominator)
            + f'<p>{attendance.value} of {accepted_value} accepted participants were confirmed present; '
            f'{attendance_gap} were not in the reviewed attendance count.</p></div>'
        )

    operational_items: list[str] = []
    if submitted_teams is not None and eligible_teams is not None and eligible_teams > 0:
        operational_items.append(
            f'<li><strong>{submitted_teams} of {eligible_teams}</strong>'
            '<span>final teams submitted a project</span></li>'
        )
    operational_note = (
        '<aside class="operational-evidence"><header><strong>Team delivery</strong>'
        '<span>This is a team-level completion measure, not a participant quality signal '
        'or the count of people whose reviewed evidence cited an event submission.</span>'
        '</header><ul>'
        + "".join(operational_items)
        + '</ul></aside>'
        if operational_items else ""
    )
    composition_items = tuple(
        item for item in event_report.composition.categories
        if item.count.privacy == "published" and item.count.value is not None
    )
    composition_total = sum(int(item.count.value or 0) for item in composition_items)
    composition_note = ""
    if composition_items and composition_total == denominator:
        segments = "".join(
            '<span class="tone-' + str((index % 2) + 1) + '" style="--size:'
            + str(_exact_percentage(int(item.count.value or 0), denominator))
            + '%"></span>'
            for index, item in enumerate(composition_items)
        )
        labels = "".join(
            '<li><i class="tone-' + str((index % 2) + 1)
            + '" aria-hidden="true"></i><span>' + escape({
                "applied_solo": "Applied without a pre-formed team",
                "applied_with_team": "Applied with a pre-formed team",
                "solo": "Applied without a pre-formed team",
                "team": "Applied with a pre-formed team",
            }.get(item.key, item.label))
            + '</span><strong>' + escape(_count_line(int(item.count.value or 0), denominator))
            + '</strong></li>'
            for index, item in enumerate(composition_items)
        )
        composition_note = (
            '<section class="applicant-composition"><header><strong>Applicant starting point</strong>'
            '<span>Application-reported team status</span></header>'
            '<div class="composition-track" aria-hidden="true">' + segments + '</div>'
            '<ul>' + labels + '</ul></section>'
        )

    body = (
        '<div class="volume-funnel" aria-label="Application and participation volume">'
        '<div class="funnel-row" data-value-state="published"><div><span>01</span>'
        f'<strong>Applied</strong><small>{denominator} people</small></div>'
        + _funnel_band("applied", denominator, denominator)
        + '<p>Full applicant pool</p></div>'
        + '<div class="funnel-row" data-value-state="published"><div><span>02</span>'
        f'<strong>Accepted by organizers</strong><small>{accepted_value} people</small></div>'
        f'{accepted_band}<p>{_rate(accepted_value, denominator)}% of applicants</p></div>'
        f'{attendance_row}</div>'
        + composition_note
        + operational_note
    )
    scope = (
        "One people-based story. Width shows volume from application to reviewed attendance."
        if attendance is not None and attendance.value is not None
        else "One people-based story. Width shows volume; the hidden attendance row carries no implied value."
    )
    return _exhibit(
        "journey", "01", "Demand and participation",
        scope,
        body,
    )


def _ranked_items(
    dimension: Dimension | None,
    denominator: int,
    *,
    excluded_keys: frozenset[str] = frozenset(),
    limit: int = 6,
) -> tuple[str, DimensionItem | None]:
    if dimension is None:
        return '<p class="empty-evidence">Classification not available.</p>', None
    unknown = next(
        (
            item for item in dimension.items
            if item.key in {"unknown", "insufficient_evidence"}
        ),
        None,
    )
    ranked = sorted(
        (
            item for item in dimension.items
            if item.key not in {"unknown", "insufficient_evidence"}
            and item.key not in excluded_keys
            and item.count.value is not None
        ),
        key=lambda item: (-(item.count.value or 0), item.label),
    )[:limit]
    rows = "".join(
        '<li class="ranked-signal">'
        f'<span>{index:02d}</span><strong>{escape(item.label)}</strong>'
        f'<b>{escape(_count_line(item.count.value or 0, denominator))}</b></li>'
        for index, item in enumerate(ranked, start=1)
    )
    return f'<ol>{rows}</ol>', unknown


def _unknown_note(item: DimensionItem | None, denominator: int) -> str:
    if item is None or item.count.value is None:
        return '<p class="coverage-note"><strong>Unclassified coverage</strong> not available.</p>'
    return (
        '<p class="coverage-note"><strong>Unclassified coverage</strong> '
        f'{item.count.value} of {denominator} ({_rate(item.count.value, denominator)}%) '
        'unclassified.</p>'
    )


def _talent(report: TalentIntelligenceContract, *, number: str = "02") -> str:
    denominator = report.cohort.denominator.value or 0
    roles, role_unknown = _ranked_items(
        _dimension(report, "functional_role"), denominator,
        excluded_keys=frozenset({"data_ai"}),
    )
    capabilities, capability_unknown = _ranked_items(
        _dimension(report, "capabilities"), denominator,
        excluded_keys=frozenset({"design"}),
    )
    body = (
        '<div class="ranked-signal-grid">'
        f'<article><h3>Functional roles</h3>{roles}{_unknown_note(role_unknown, denominator)}</article>'
        f'<article><h3>Capabilities</h3>{capabilities}{_unknown_note(capability_unknown, denominator)}</article>'
        '</div><p class="chart-footnote">A person can appear in more than one category. '
        'The rankings describe evidence, not a score.</p>'
    )
    return _exhibit(
        "talent", number, "What the cohort can do",
        "The strongest non-duplicated role and capability signals, shown with count and share together.",
        body,
    )


def _career(report: TalentIntelligenceContract, *, number: str = "03") -> str:
    denominator = report.cohort.denominator.value or 0
    seniority = _dimension(report, "seniority")
    items = tuple(seniority.items) if seniority is not None else ()
    visible = tuple(item for item in items if item.count.value is not None)
    segments = "".join(
        f'<span class="tone-{(index % 6) + 1}" '
        f'style="--size:{_exact_percentage(item.count.value or 0, denominator)}%"></span>'
        for index, item in enumerate(visible)
    )
    legend = "".join(
        '<li>'
        f'<i class="tone-{(index % 6) + 1}" aria-hidden="true"></i>'
        f'<span>{escape("Unclassified" if item.key == "unknown" else "Founder evidence" if item.key == "founder" else item.label)}</span>'
        f'<strong>{escape(_count_line(item.count.value or 0, denominator))}</strong></li>'
        for index, item in enumerate(visible)
    )
    employer_unknown = _item(report, "employer_pedigree", "unknown")
    if employer_unknown is not None and employer_unknown.count.value is not None:
        unknown_value = employer_unknown.count.value
        classified = denominator - unknown_value
        employer_note = (
            '<aside class="coverage-callout"><strong>Employer context coverage</strong>'
            f'<p>{classified} of {denominator} ({_rate(classified, denominator)}%) classified; '
            f'{unknown_value} of {denominator} ({_rate(unknown_value, denominator)}%) unclassified.</p></aside>'
        )
    else:
        employer_note = ""
    body = (
        '<div class="composition-chart" aria-label="Career-stage evidence composition">'
        f'<div class="composition-track" aria-hidden="true">{segments}</div>'
        f'<ul>{legend}</ul></div>{employer_note}'
        '<p class="chart-footnote">Career stage is an evidence classification, not a judgment of quality. '
        'Optional enrichment can reduce the unclassified share later.</p>'
    )
    return _exhibit(
        "career-background", number, "Career context, with the gaps visible",
        "A 100% composition is used only for the contract's exclusive career-stage classification.",
        body,
    )


def _builder_evidence(
    report: TalentIntelligenceContract,
    event_report: TalentReportContract,
    *,
    number: str = "04",
    include_team_submission_summary: bool = False,
    key: str = "builder-evidence",
    title: str = "Evidence of building and delivery",
    scope: str = "Application evidence of shipped products and safe cross-dimensional combinations.",
    include_intersections: bool = True,
) -> str:
    denominator = report.cohort.denominator.value or 0
    metrics: list[tuple[str, str, int, str]] = []
    shipped = _item(report, "builder_evidence", "shipped_product")
    if shipped is not None and shipped.count.value is not None:
        metrics.append((
            "Application evidence", "Shipped-product evidence", shipped.count.value,
            "Explicit shipping, deployment, user, or customer language was recorded; external delivery was not independently verified.",
        ))
    supporting_intersection = None
    if include_intersections:
        supporting_intersection = next(
            (
                item for item in report.intersections
                if item.key == "founder_technical_shipped_product_exact"
                and item.count.value is not None
                and item.count.privacy == "published"
            ),
            None,
        )
    if supporting_intersection is not None:
        metrics.append((
            "Exact intersection", supporting_intersection.label,
            supporting_intersection.count.value or 0,
            "One exact, privacy-safe application-evidence combination.",
        ))
    cards = "".join(
        f'<article><span>{escape(badge)}</span>'
        f'<strong>{value}</strong><h3>{escape(label)}</h3>'
        f'<p>{escape(note)}</p><small>{_rate(value, denominator)}% of applicants</small></article>'
        for badge, label, value, note in metrics
    )
    submitted_teams, eligible_teams = _submitted_teams(event_report)
    if submitted_teams is not None and eligible_teams is not None:
        team_submission_note = (
            "Every reconciled final team submitted a project."
            if submitted_teams == eligible_teams
            else (
                f"{_rate(submitted_teams, eligible_teams)}% of reconciled final teams "
                "submitted a project."
            )
        )
    else:
        team_submission_note = ""
    team_submission_summary = (
        '<aside class="coverage-callout"><strong>'
        f'{submitted_teams} of {eligible_teams} submitted teams'
        f'</strong><p>{escape(team_submission_note)}</p></aside>'
        if (
            include_team_submission_summary
            and submitted_teams is not None
            and eligible_teams is not None
            and eligible_teams > 0
        ) else ""
    )
    interpretation = (
        "This observed fact is not a composite talent score."
        if len(metrics) == 1
        else "These are separate observed facts. They are not added into a composite talent score."
    )
    body = (
        f'<div class="evidence-strip">{cards}</div>'
        f'{team_submission_summary}'
        f'<p class="chart-footnote">{escape(interpretation)}</p>'
    )
    return _exhibit(
        key, number, title, scope,
        body,
    )


def _domains(report: TalentIntelligenceContract, *, number: str = "05") -> str:
    denominator = report.cohort.denominator.value or 0
    dimension = _dimension(report, "domains")
    items = sorted(
        (
            item for item in (dimension.items if dimension is not None else ())
            if item.key not in {"unknown", "insufficient_evidence"}
            and item.count.value is not None
        ),
        key=lambda item: (-(item.count.value or 0), item.label),
    )[:8]
    rows = "".join(
        '<li class="dot-row">'
        f'<strong>{escape(item.label)}</strong>'
        '<span class="dot-field" aria-hidden="true">'
        f'<i style="--position:{_rate(item.count.value or 0, denominator)}%"></i></span>'
        f'<b>{escape(_count_line(item.count.value or 0, denominator))}</b></li>'
        for item in items
    )
    unknown = next(
        (
            item for item in (dimension.items if dimension is not None else ())
            if item.key in {"unknown", "insufficient_evidence"}
        ),
        None,
    )
    body = (
        '<div class="dot-plot"><div class="dot-axis" aria-hidden="true">'
        '<span>0%</span><span>20%</span><span>40%</span><span>60%</span></div>'
        f'<ol>{rows}</ol></div>{_unknown_note(unknown, denominator)}'
        '<p class="chart-footnote">Dots share one applicant-percentage axis. Categories overlap, so shares do not sum to 100%.</p>'
    )
    return _exhibit(
        "domains", number, "Where applicants have domain evidence",
        "A shared-axis dot plot ranks overlapping domain evidence without making the rows look interactive.",
        body,
    )


def _semantic_evidence(summary: PartnerSemanticSummary) -> str:
    cards = ""
    for metric in _external_definition_metrics(summary):
        count_line = (
            "Count withheld" if metric.count is None
            else f"{metric.count} people" if metric.denominator is None
            else f"{metric.count} of {metric.denominator}"
        )
        rate_line = (
            f"{_rate(metric.count, metric.denominator)}% of the eligible population"
            if metric.count is not None and metric.denominator is not None
            else "Eligible denominator withheld" if metric.count is not None
            else "Privacy threshold applied"
        )
        cards += (
            '<article><span>Evidence-bound semantic finding</span>'
            f'<strong>{escape(count_line)}</strong>'
            f'<h3>{escape(metric.label)}</h3><p>{escape(metric.note)}</p>'
            f'<small>{escape(rate_line)}</small></article>'
        )
    assessment_scope = (
        "claims use the full eligible population as their denominator, while unavailable "
        "evidence remains unknown"
    )
    body = (
        f'<div class="evidence-strip semantic-strip">{cards}</div>'
        '<p class="semantic-sources"><strong>Evidence use</strong> Project and application '
        'evidence support the findings; source-use coverage is reported separately and is '
        'not a quality score.</p>'
        '<p class="chart-footnote">Each finding is an independent evidence signal, not a score. '
        'Missing public evidence remains unknown rather than negative.</p>'
    )
    return _exhibit(
        "semantic-evidence", "02", "What the project evidence shows",
        f"AI-assisted evidence assessment: {assessment_scope}, using fixed categories.",
        body,
    )


def _semantic_dimension(
    summary: PartnerSemanticSummary, key: str,
) -> PartnerSemanticDimension:
    dimension = next((item for item in summary.dimensions if item.key == key), None)
    if dimension is None:
        raise ValueError(f"semantic report dimension is missing: {key}")
    return dimension


def _semantic_dimension_panel(
    dimension: PartnerSemanticDimension,
    *,
    limit: int = 6,
    compact: bool = False,
    element_id: str | None = None,
    title: str | None = None,
    note: str | None = None,
) -> str:
    denominator = dimension.denominator
    visible = sorted(
        (
            cell for cell in dimension.cells
            if cell.state == "reported" and cell.count is not None and cell.count > 0
        ),
        key=lambda cell: (-int(cell.count or 0), cell.label),
    )[:limit]
    if not visible:
        return ""
    rows = "".join(
        '<li class="taxonomy-cell">'
        f'<span><strong>{escape(cell.label)}</strong>'
        f'<small>{escape(_count_line(cell.count or 0, denominator)) if denominator else f"{cell.count} people"}</small></span>'
        '<i aria-hidden="true"><b style="--share:'
        f'{_exact_percentage(cell.count or 0, denominator or 0)}%"></b></i></li>'
        for cell in visible
    )
    return (
        f'<article class="taxonomy-panel{" taxonomy-panel-compact" if compact else ""}"'
        + (f' id="{escape(element_id)}"' if element_id else "")
        + '>'
        f'<header><h3>{escape(title or dimension.label)}</h3>'
        f'<p>{escape(note or dimension.note)}</p></header>'
        f'<ol>{rows}</ol></article>'
    )


_PROJECT_CORE_DIMENSION_KEYS = (
    "product_maturity", "technical_depth", "execution_scope",
    "external_validation", "problem_differentiation",
)


def _project_has_dense_taxonomy(summary: PartnerSemanticSummary) -> bool:
    return sum(
        any(
            cell.state == "reported" and cell.count is not None and cell.count > 0
            for cell in _semantic_dimension(summary, key).cells
        )
        for key in _PROJECT_CORE_DIMENSION_KEYS
    ) > 2


_COHORT_SOURCE_LABELS = {
    "application": "Application",
    "public_projects": "Public projects",
    "event_submission": "Event submission",
    "career_context": "Dedicated career-provider evidence",
}


def _cohort_matrix_cell(
    count: int | None,
    denominator: int,
    cohort_label: str,
) -> str:
    if count is None:
        return (
            '<div class="cohort-matrix-cell is-withheld">'
            '<strong>Count withheld</strong><i aria-hidden="true"><b></b></i>'
            f'<small>{escape(cohort_label)} · Privacy-protected</small></div>'
        )
    share = _exact_percentage(count, denominator)
    return (
        '<div class="cohort-matrix-cell"><strong>'
        f'{count} of {denominator}</strong>'
        f'<i aria-hidden="true"><b style="--share:{share}%"></b></i>'
        f'<small>{escape(cohort_label)} · {_rate(count, denominator)}% of cohort</small></div>'
    )


def _definition_reference(key: str, number: int) -> str:
    return (
        '<sup class="definition-ref"><a href="#definition-'
        + escape(key)
        + f'" aria-label="Definition {number}">{number}</a></sup>'
    )


def _cohort_evidence_matrix(cohorts: PartnerSemanticCohortBundle) -> str:
    """Render one exact, non-causal comparison across the protected nested cohorts."""

    metric_order = _EXTERNAL_DEFINITION_ORDER
    metric_labels = {
        metric.key: metric.label
        for metric in _external_definition_metrics(cohorts.cohorts[0].summary)
    }
    metric_numbers = {
        key: index for index, key in enumerate(metric_order, start=1)
    }
    metric_maps = tuple(
        {
            metric.key: metric
            for metric in (*cohort.summary.metrics, *cohort.summary.public_groups)
            if metric.key in metric_order
        }
        for cohort in cohorts.cohorts
    )
    headers = "".join(
        '<div class="cohort-matrix-head"><strong>'
        f'{escape(cohort.label)}</strong><small>Denominator {cohort.denominator} · '
        f'Unknown {cohort.summary.unknown_count if cohort.summary.unknown_count is not None else "withheld"}'
        '</small></div>'
        for cohort in cohorts.cohorts
    )
    comparable_keys = tuple(
        key for key in metric_order
        if all(metric_map[key].count is not None for metric_map in metric_maps)
        and any(int(metric_map[key].count or 0) > 0 for metric_map in metric_maps)
    )
    all_only_keys = tuple(
        key for key in metric_order
        if metric_maps[0][key].count is not None
        and int(metric_maps[0][key].count or 0) > 0
        and any(metric_map[key].count is None for metric_map in metric_maps[1:])
    )
    rows = ""
    for key in comparable_keys:
        rows += (
            '<div class="cohort-matrix-label"><strong>'
            f'{escape(metric_labels[key])}'
            + _definition_reference(key, metric_numbers[key])
            + '</strong></div>'
            + "".join(
                _cohort_matrix_cell(
                    metric_maps[index][key].count,
                    cohort.denominator,
                    cohort.label,
                )
                for index, cohort in enumerate(cohorts.cohorts)
            )
        )
    all_only_rows = "".join(
        '<article><b>' + escape(metric_labels[key])
        + _definition_reference(key, metric_numbers[key])
        + '</b><strong>'
        + f'{metric_maps[0][key].count} of {cohorts.cohorts[0].denominator}'
        + '</strong></article>'
        for key in all_only_keys
    )

    coverage_maps = tuple(
        dict(cohort.summary.source_coverage) for cohort in cohorts.cohorts
    )
    project_source_counts = tuple(
        coverage.get("public_projects") for coverage in coverage_maps
    )
    project_source_note = ""
    if all(count is not None for count in project_source_counts):
        source_labels = {
            "all": "applicants",
            "accepted": "accepted participants",
            "attended": "confirmed attendees",
        }
        source_values = " · ".join(
            f'{int(project_source_counts[index])}/{cohort.denominator} '
            f'{source_labels.get(cohort.key, cohort.label.casefold())}'
            for index, cohort in enumerate(cohorts.cohorts)
        )
        project_source_note = (
            '<p><strong>Public-project evidence used</strong> '
            + escape(source_values)
            + '. Non-use is not a quality judgment.</p>'
        )
    return (
        '<section class="cohort-comparison" id="cohort-comparison" '
        'aria-label="Protected cohort evidence comparison">'
        '<div class="cohort-evidence-matrix" id="semantic-evidence"><div class="cohort-matrix-corner">'
        '<strong>Comparable cohort signals</strong><small>Descriptive shares, not a selection score</small>'
        f'</div>{headers}{rows}</div>'
        + (
            '<section class="all-applicant-signals"><header><strong>Positive evidence '
            'available for the full applicant pool</strong><span>Nested cohort counts are '
            'withheld by the privacy rule. Missing evidence is not a negative assessment.'
            '</span></header><div>'
            + all_only_rows + '</div></section>'
            if all_only_rows else ""
        )
        + (
            '<footer class="cohort-evidence-notes">'
            + project_source_note + '</footer>'
            if project_source_note else ""
        )
        + '</section>'
    )


def _project_landscape(
    summary: PartnerSemanticSummary,
    *,
    cohort_bundle: PartnerSemanticCohortBundle | None = None,
) -> str:
    if cohort_bundle is not None:
        return _exhibit(
            "project-landscape", "02", "What people have actually built",
            "A protected cohort matrix compares positive evidence and denominators without treating selection as quality.",
            _cohort_evidence_matrix(cohort_bundle),
        )
    groups = {group.key: group for group in summary.public_groups}
    group_families = (
        ("Product maturity", ("prototype_or_beyond", "working_or_production")),
        (
            "Technical depth",
            ("moderate_or_stronger_technical", "advanced_or_exceptional_technical"),
        ),
        ("Execution ownership", ("substantial_or_greater_execution",)),
        (
            "External validation",
            ("early_or_greater_validation", "meaningful_or_strong_validation"),
        ),
        ("Problem framing", ("differentiated_or_ambitious_problem",)),
    )
    core_panels = tuple(
        '<article class="taxonomy-panel taxonomy-panel-compact"><header><h3>'
        f'{escape(title)}</h3><p>Fixed positive evidence groups, defined before this event was observed.</p>'
        '</header><ol>'
        + "".join(
            '<li class="taxonomy-cell"><span><strong>'
            f'{escape(groups[key].label)}</strong><small>'
            f'{escape(_count_line(groups[key].count or 0, groups[key].denominator))}'
            '</small></span><i aria-hidden="true"><b style="--share:'
            f'{_exact_percentage(groups[key].count or 0, groups[key].denominator or 0)}%'
            '"></b></i></li>'
            for key in keys
            if key in groups and groups[key].state == "reported"
            and groups[key].count is not None and groups[key].count > 0
        )
        + '</ol></article>'
        for title, keys in group_families
        if any(
            key in groups and groups[key].state == "reported"
            and groups[key].count is not None and groups[key].count > 0
            for key in keys
        )
    )
    if not core_panels:
        domain_panel = _semantic_dimension_panel(
            _semantic_dimension(summary, "market_domains"),
            limit=8,
            compact=True,
            element_id="domain-context",
        )
        if domain_panel:
            core_panels = (domain_panel,)
    core = "".join(core_panels)
    visible_metrics = tuple(
        metric for metric in _external_definition_metrics(summary)
        if metric.count is not None and metric.count > 0
    )
    metrics = "".join(
        '<li><strong>'
        + (
            "Withheld" if metric.count is None
            else str(metric.count) if metric.denominator is None
            else f"{metric.count} of {metric.denominator}"
        )
        + f'</strong><span>{escape(metric.label)}</span></li>'
        for metric in visible_metrics
    )
    coverage = "Metrics use the full eligible population; unavailable evidence remains unknown"
    review_state = (
        "AI-assisted evidence assessment; reviewed against fixed evidence definitions."
    )
    body = (
        '<section class="semantic-evidence-compact" id="semantic-evidence" '
        'aria-label="Semantic headline evidence"><header><strong>'
        f'{escape(coverage)}</strong><span>{escape(review_state)}</span></header>'
        f'<ul style="--metric-columns:{len(visible_metrics)}">{metrics}</ul>'
        '<p class="semantic-compact-sources">'
        '<strong>Evidence use</strong> Project and application evidence support the findings; '
        'source-use coverage is reported separately and is not a quality score.</p></section>'
        + (
            '<div class="taxonomy-grid taxonomy-grid-core" '
            f'style="--taxonomy-columns:{len(core_panels)}">{core}</div>'
            if core_panels else ""
        )
        +
        '<p class="chart-footnote">These fixed groups combine adjacent positive tiers before '
        'counts are observed. They are evidence signals, not scores, and do not publish a '
        'negative-person count.</p>'
    )
    return _exhibit(
        "project-landscape", "02", "What people have actually built",
        "Evidence-bound project maturity, technical depth, execution ownership, external validation, and problem differentiation.",
        body,
    )


def _career_context(summary: PartnerSemanticSummary) -> str:
    stage = _semantic_dimension(summary, "career_stage")
    denominator = stage.denominator
    stage_cells = sorted(
        (
            cell for cell in stage.cells
            if cell.state == "reported" and cell.count is not None and cell.count > 0
        ),
        key=lambda cell: (-int(cell.count or 0), cell.label),
    )
    segments = "".join(
        f'<span class="tone-{(index % 6) + 1}" '
        f'style="--size:{_exact_percentage(cell.count or 0, denominator or 0)}%"></span>'
        for index, cell in enumerate(stage_cells)
    )
    legend = "".join(
        '<li class="taxonomy-cell">'
        f'<i class="tone-{(index % 6) + 1}" aria-hidden="true"></i>'
        f'<span>{escape(cell.label)}</span><strong>'
        f'{escape(_count_line(cell.count or 0, denominator)) if denominator else f"{cell.count} people"}'
        '</strong></li>'
        for index, cell in enumerate(stage_cells)
    )
    stage_chart = (
        '<article class="career-stage"><header><h3>Career stage</h3>'
        '<p>Sorted from the largest supported group to the smallest.</p></header>'
        f'<div class="composition-track" aria-hidden="true">{segments}</div>'
        f'<ul>{legend}</ul></article>'
    ) if stage_cells else ""
    capabilities = "".join(
        _semantic_dimension_panel(_semantic_dimension(summary, key), limit=6, compact=True)
        for key in ("technical_methods", "demonstrated_capabilities")
    )
    context = "".join(
        _semantic_dimension_panel(_semantic_dimension(summary, key), limit=5, compact=True)
        for key in (
            "founder_state", "leadership_state", "career_functions", "career_delivery",
        )
    )
    layout_class = (
        "capability-career-layout" if stage_cells
        else "capability-career-layout without-career-stage"
    )
    body = (
        f'<div class="{layout_class}"><section class="capability-context" '
        'id="capability-context"><header><h3>Demonstrated capabilities</h3>'
        '<p>Methods and capabilities supported by concrete project evidence.</p></header>'
        f'<div class="taxonomy-grid taxonomy-grid-capabilities">{capabilities}</div></section>'
        f'{stage_chart}<div class="taxonomy-grid taxonomy-grid-career">{context}</div></div>'
        '<aside class="career-overlay-note"><strong>Optional career context</strong>'
        '<p>Permitted professional-profile history may supplement application evidence, but it '
        'is never required and missing context is never treated as a negative signal. Source '
        'use is reported separately and is not a quality score.</p></aside>'
    )
    return _exhibit(
        "career-context", "03", "Capabilities and career context",
        "Stage, founder and leadership context, functions, and concrete delivery evidence; unavailable evidence is explained in the methodology.",
        body,
    )


def _application_career_stage(
    report: TalentIntelligenceContract,
) -> str:
    dimension = _dimension(report, "seniority")
    if dimension is None:
        return '<p class="empty-evidence">Application career-stage evidence is unavailable.</p>'
    denominator = report.cohort.denominator.value or 0
    visible = tuple(
        item for item in dimension.items
        if item.count.privacy == "published" and item.count.value is not None
    )
    segments = "".join(
        '<span class="tone-' + str((index % 6) + 1) + '" style="--size:'
        + str(_exact_percentage(int(item.count.value or 0), denominator))
        + '%"></span>'
        for index, item in enumerate(visible)
    )
    labels = "".join(
        '<li><i class="tone-' + str((index % 6) + 1) + '" aria-hidden="true"></i>'
        '<span>' + escape(
            "Founder / co-founder role" if item.key == "founder"
            else "Unknown / not classified" if item.key == "unknown"
            else item.label,
        ) + '</span><strong>'
        + escape(_count_line(int(item.count.value or 0), denominator))
        + '</strong></li>'
        for index, item in enumerate(visible)
    )
    return (
        '<article class="application-career-stage"><header><h3>Application-reported primary role or stage</h3>'
        '<p>One mutually exclusive role or career-stage category per applicant; the distribution totals 100%, including unknown.</p>'
        '</header><div class="composition-track" aria-hidden="true">' + segments
        + '</div><ul>' + labels + '</ul></article>'
    )


def _community_composition(
    report: TalentIntelligenceContract,
    summary: PartnerSemanticSummary,
) -> str:
    career_context_count = dict(summary.source_coverage).get("career_context", 0)
    career_context_note = (
        "Dedicated career-provider evidence supported the reviewed evidence."
        if career_context_count
        else "Dedicated career-provider evidence was not used in this release."
    )
    founder = _semantic_dimension_panel(
        _semantic_dimension(summary, "founder_state"), limit=3, compact=True,
        title="Reviewed founding evidence",
        note=(
            "Current and former founder states are mutually exclusive here; founder "
            "state may overlap the primary role or stage shown at left."
        ),
    )
    function_dimension = _semantic_dimension(summary, "career_functions")
    functions = _semantic_dimension_panel(
        function_dimension,
        limit=5,
        compact=True,
        note=f"Top functions shown. {function_dimension.note}",
    )
    overlap_reference = len(_EXTERNAL_DEFINITION_ORDER) + 1
    body = (
        '<div class="community-composition-layout">'
        + _application_career_stage(report)
        + '<div class="community-career-evidence">' + founder + functions + '</div></div>'
        + '<aside class="career-source-note category-model">'
        '<div class="category-model-base"><b>100%</b><span><strong>Primary role or stage</strong>'
        '<small>Each applicant appears once; categories total 100%.</small>'
        '</span></div><div class="category-model-overlays"><strong>Independent overlays'
        + _definition_reference("overlapping-categories", overlap_reference)
        + '</strong><p>The founder / co-founder role can be one primary role or stage. Reviewed '
        'founder state and career functions are non-exclusive; the same person may appear in '
        'more than one overlay. Different standards; do not add these counts. '
        + escape(career_context_note) + '</p></div></aside>'
    )
    return _exhibit(
        "career-context", "03", "Who is in the applicant community",
        "Student, seniority, founder, and technical-function context, with source boundaries and unknowns visible.",
        body,
    )


def _capability_market_context(
    summary: PartnerSemanticSummary,
    *,
    number: str = "04",
) -> str:
    methods = _semantic_dimension_panel(
        _semantic_dimension(summary, "technical_methods"), limit=6, compact=True,
    )
    capabilities = _semantic_dimension_panel(
        _semantic_dimension(summary, "demonstrated_capabilities"),
        limit=6,
        compact=True,
    )
    domain_dimension = _semantic_dimension(summary, "market_domains")
    domains = _semantic_dimension_panel(
        domain_dimension,
        limit=6,
        compact=True,
        element_id="domain-context",
        note=f"Top domains shown. {domain_dimension.note}",
    )
    body = (
        '<div class="capability-market-layout"><div class="capability-pair">'
        + methods + capabilities + '</div><section class="market-domain-strip">'
        +
        '<header><h3>Where the work is aimed</h3><p>Top domains shown; reviewed market context; categories may overlap.</p></header>'
        + domains + '</section></div>'
    )
    return _exhibit(
        "capability-context", number, "What the community can build",
        "Concrete methods and capabilities, followed by the market contexts visible in the reviewed work.",
        body,
    )


def _report_note(
    report: TalentIntelligenceContract,
    semantic_summary: PartnerSemanticSummary | None,
) -> str:
    threshold = (
        "five" if report.privacy.minimum_count == 5
        else str(report.privacy.minimum_count)
    )
    semantic = ""
    if semantic_summary is not None:
        semantic = (
            " Headline shares use the full eligible population; unavailable evidence remains "
            "unknown."
        )
    return (
        '<aside class="report-note" aria-label="Report interpretation note"><strong>Reading note</strong>'
        f'<p>{escape(semantic.strip()) + " " if semantic else ""}'
        f'Small group hidden: Counts below {threshold} are not shown. A hidden value is not zero. '
        'Missing evidence is not a negative finding. '
        'No names, contact details, or profile links are included.</p>'
        '<footer class="report-footer">'
        f'<span>Generated {escape(report.metadata.generated_at)}</span>'
        '<span>Aggregate-only partner brief</span>'
        '</footer></aside>'
    )


def _methodology(
    report: TalentIntelligenceContract,
    semantic_summary: PartnerSemanticSummary | None,
    *,
    number: str = "05",
) -> str:
    metric_definitions = ""
    if semantic_summary is not None:
        definitions: list[str] = []
        for definition_number, metric in enumerate(
            _external_definition_metrics(semantic_summary), start=1,
        ):
            definitions.append(
                '<div id="definition-' + escape(metric.key) + '"><dt>'
                f'<span class="definition-number" aria-hidden="true">{definition_number}</span>'
                + escape(metric.label) + '</dt><dd>'
                + escape(metric.note) + '</dd></div>'
            )
        metric_definitions = "".join(definitions)
        metric_definitions += (
            '<div id="definition-overlapping-categories"><dt>'
            f'<span class="definition-number" aria-hidden="true">{len(_EXTERNAL_DEFINITION_ORDER) + 1}</span>'
            'Category overlap</dt><dd>Primary role or stage is exclusive. Founder state, career '
            'functions, capabilities, methods, and domains are independent overlays; a person '
            'may appear in several. Do not sum the overlays or add them to the 100% distribution.'
            '</dd></div>'
        )
        if (
            semantic_summary.whole_person_unresolved_count is not None
            and semantic_summary.eligible_denominator is not None
        ):
            unresolved_definition = (
                '<div><dt>Whole-person unresolved</dt><dd>'
                f'{escape(_count_line(semantic_summary.whole_person_unresolved_count, semantic_summary.eligible_denominator))} '
                'had missing or conflicting reviewed evidence. They remain outside positive '
                'claims; this is not a negative judgment.</dd></div>'
            )
        else:
            unresolved_definition = (
                '<div><dt>Whole-person unresolved</dt><dd>The count is withheld under the '
                'privacy rule. These records remain outside positive evidence claims.</dd></div>'
            )
    else:
        metric_definitions = (
            '<div><dt>Classified evidence</dt><dd>Counts reflect explicit, reviewed '
            'category evidence in the supplied event sources.</dd></div>'
        )
        unresolved_definition = ""

    body = (
        '<div class="methodology-grid"><article><h3>Evidence definitions</h3>'
        f'<dl class="definition-list">{metric_definitions}</dl></article>'
        '<article><h3>Interpretation</h3><dl class="definition-list">'
        '<div><dt>Denominator</dt><dd>Evidence shares use the full eligible applicant '
        'population. Source-use coverage is reported separately and is not a quality score.</dd></div>'
        '<div><dt>Unknown</dt><dd>Evidence was missing, insufficient, unavailable, or '
        'unresolved. Unknown never means a negative assessment.</dd></div>'
        '<div><dt>Unclassified</dt><dd>The available inputs did not support one controlled '
        'career, role, capability, or domain category.</dd></div>'
        + '<div><dt>Not in this release</dt><dd>Gender, age, nationality, location, and '
        'graduation year were unavailable or unreviewed and were not inferred.</dd></div>'
        + unresolved_definition
        + f'<div><dt>Privacy threshold</dt><dd>Counts, complements, and related intersections '
        f'under {report.privacy.minimum_count} are withheld.</dd></div></dl></article></div>'
        + _report_note(report, semantic_summary)
    )
    return _exhibit(
        "methodology", number, "How to read the evidence",
        "Definitions, denominators, unknown states, and privacy rules for every claim.",
        body,
    )


def _evidence_boundary(
    semantic_summary: PartnerSemanticSummary,
    *,
    number: str = "05",
) -> str:
    """Show source coverage separately from quality and event operations."""

    denominator = semantic_summary.eligible_denominator
    career_context_count = dict(semantic_summary.source_coverage).get(
        "career_context", 0,
    )
    source_notes = {
        "application": "Application evidence cited in reviewed facts.",
        "public_projects": (
            "Public-project evidence cited in reviewed facts; non-use is not a quality judgment."
        ),
        "event_submission": (
            "Submission evidence cited for reviewed people; this is not attendance or team completion."
        ),
        "career_context": (
            "Dedicated career-provider evidence cited in reviewed facts."
            if career_context_count
            else "Dedicated career-provider evidence was not used in this release."
        ),
    }
    source_items = "".join(
        '<li><span>' + escape(_COHORT_SOURCE_LABELS[key]) + '</span><strong>'
        + (
            "Not used"
            if key == "career_context" and count == 0
            else f'{count} of {denominator}'
        )
        + '</strong><i aria-hidden="true"><b style="--share:'
        + (
            str(_exact_percentage(count, denominator))
            if denominator else "0"
        )
        + '%"></b></i><small>' + escape(source_notes[key]) + '</small></li>'
        for key, count in semantic_summary.source_coverage
    )
    if (
        semantic_summary.whole_person_unresolved_count is not None
        and denominator is not None
    ):
        unresolved = _count_line(
            semantic_summary.whole_person_unresolved_count, denominator,
        )
    else:
        unresolved = "Withheld"
    body = (
        '<section class="methodology-coverage source-boundary">'
        '<h3>Evidence source use</h3><p class="method-summary">'
        '<strong>Assessment boundary.</strong> These counts mean a source was cited in a '
        'person-level evidence review, not attendance, submission completion, or a quality score. '
        'The partner output excludes names, contacts, profile links, and raw provider records.'
        '</p><ul>' + source_items + '</ul></section>'
        '<aside class="source-boundary-notes">'
        '<article><strong>Coverage is not quality</strong><p>A source not being used only means '
        'the evidence review did not use it. It does not downgrade the person or project.</p></article>'
        '<article><strong>' + escape(unresolved) + ' unresolved</strong><p>Missing or '
        'conflicting reviewed evidence receives no positive claim in this report; this is '
        'not a negative assessment.</p></article>'
        '<article><strong>Aggregate output only</strong><p>Names, contacts, profile links, and '
        'person-level browsing remain outside the partner report.</p></article></aside>'
    )
    return _exhibit(
        "evidence-boundary", number, "What evidence was available",
        "Reviewed source use, explicit non-use, and the boundary between coverage and quality.",
        body,
    )


# Surface contract: bone is the continuous document canvas. Near-white is reserved
# for bounded evidence units that users compare or select, never narrative patches.
_CSS = r"""
:root{--navy:#00002c;--burgundy:#80011f;--canvas:#fcfbf7;--evidence-surface:#fffefd;--paper:var(--canvas);--surface:var(--evidence-surface);--ink:#171729;--muted:#5d5d6e;--rule:#d5d4db;--soft:#ecebef;--tint:#fff5f7;--focus:#d8a7b4;--success:#187447;--font:AvenirLTNextPro,"Avenir Next",Avenir,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
*{box-sizing:border-box}html{scroll-behavior:smooth;background:var(--paper)}body{margin:0;color:var(--ink);background:var(--paper);font:16px/1.5 var(--font);font-kerning:normal}a{color:inherit}.skip{position:fixed;left:-999px;top:12px;z-index:20;padding:12px 16px;color:var(--navy);background:var(--surface);font-weight:800}.skip:focus{left:12px}a:focus-visible{outline:3px solid var(--focus);outline-offset:4px}strong,b{font-variant-numeric:tabular-nums}h1,h2,h3{color:var(--navy);line-height:1.05;text-wrap:balance}p{max-width:70ch;text-wrap:pretty}
.cover{min-height:100svh;padding:32px max(32px,6vw);display:grid;grid-template-rows:auto 1fr auto;color:var(--paper);background:var(--navy)}.brand{width:168px;height:76px;object-fit:contain;object-position:left center}.cover-copy{align-self:center;max-width:1180px}.eyebrow,.exhibit-number{margin:0 0 16px;color:var(--burgundy);font-size:.72rem;font-weight:850;letter-spacing:.12em;text-transform:uppercase}.cover .eyebrow{color:#d8a7b4}.cover h1{max-width:14ch;margin:0;color:var(--paper);font-size:clamp(3.2rem,7vw,6.6rem);font-weight:900;letter-spacing:-.055em}.dek{margin:24px 0 32px;color:#d3d2dd;font-size:1.08rem}.cover-findings{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));max-width:1180px;border-top:1px solid #4b4b67}.cover-finding{padding:18px 24px 6px 0}.cover-finding strong,.cover-finding span{display:block}.cover-finding strong{color:var(--paper);font-size:1.45rem;line-height:1.1}.cover-finding span{margin-top:8px;color:#c7c6d1;font-size:.78rem;line-height:1.35}.cover-meta{display:flex;gap:24px;justify-content:space-between;padding-top:14px;border-top:1px solid #4b4b67;color:#c7c6d1;font-size:.76rem}.cover-meta b{color:var(--paper)}.synthetic-label{width:max-content;margin:24px 0 0;padding:6px 9px;color:var(--navy);background:#d8a7b4;font-size:.7rem;font-weight:850;text-transform:uppercase}
.report-shell{display:grid;grid-template-columns:220px minmax(0,1fr);max-width:1320px;margin:auto}.report-nav{position:sticky;top:0;height:100svh;padding:44px 24px;border-right:1px solid var(--rule)}.report-nav strong{display:block;margin-bottom:24px;color:var(--navy)}.report-nav a{display:block;padding:10px 0;color:var(--muted);font-size:.82rem;text-decoration:none}.report-nav a:hover{color:var(--burgundy)}main{min-width:0}.exhibit{min-height:90svh;padding:80px clamp(28px,6vw,88px);border-bottom:1px solid var(--rule)}.exhibit-head{display:grid;grid-template-columns:minmax(0,1fr) minmax(240px,.6fr);gap:40px;align-items:end;margin-bottom:44px}.exhibit-head .exhibit-number{grid-column:1/-1;margin-bottom:-24px}.exhibit-head h2{margin:0;font-size:clamp(2.3rem,4vw,4.2rem);letter-spacing:-.045em}.exhibit-head>p:last-child{margin:0;color:var(--muted);font-size:.9rem}
.volume-funnel{display:grid;gap:12px}.funnel-row{display:grid;grid-template-columns:minmax(190px,.75fr) minmax(240px,1.5fr) minmax(150px,.6fr);gap:24px;align-items:center;padding:14px 0;border-bottom:1px solid var(--rule)}.funnel-row>div{display:grid;grid-template-columns:28px 1fr}.funnel-row>div>span{grid-row:1/3;color:var(--burgundy);font-size:.7rem;font-weight:850}.funnel-row strong,.funnel-row small{grid-column:2;display:block}.funnel-row small,.funnel-row p{color:var(--muted);font-size:.78rem}.funnel-row p{margin:0}.funnel-track{display:block;width:100%;height:42px;overflow:hidden}.funnel-base{fill:var(--soft)}.funnel-band{fill:var(--burgundy)}.funnel-band.applied{fill:var(--navy)}.funnel-band.attendance{fill:#a85a70}.privacy-marker{display:inline-flex;width:max-content;gap:6px;justify-self:start;padding:12px 14px;background:var(--soft)}.privacy-marker i{width:8px;height:8px;border-radius:50%;background:var(--burgundy)}.selection-note{display:grid;grid-template-columns:180px minmax(0,1fr);gap:24px;margin-top:32px;padding:20px 0;border-top:2px solid var(--navy);border-bottom:1px solid var(--rule)}.selection-note p{margin:0;color:var(--muted)}
.ranked-signal-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:56px}.ranked-signal-grid h3{margin:0 0 18px;font-size:1.35rem}.ranked-signal-grid ol{margin:0;padding:0;border-top:2px solid var(--navy);list-style:none}.ranked-signal{display:grid;grid-template-columns:34px minmax(0,1fr) auto;gap:12px;align-items:center;padding:13px 0;border-bottom:1px solid var(--rule)}.ranked-signal>span{color:var(--burgundy);font-size:.68rem;font-weight:850}.ranked-signal strong{font-size:.9rem}.ranked-signal b{font-size:.78rem}.coverage-note{margin:16px 0 0;color:var(--muted);font-size:.78rem}.coverage-note strong{color:var(--navy)}.chart-footnote{margin:28px 0 0;color:var(--muted);font-size:.82rem}
.composition-chart{display:grid;grid-template-columns:minmax(0,1.2fr) minmax(320px,.8fr);gap:44px;align-items:start}.composition-track{display:flex;height:72px;overflow:hidden;background:var(--soft)}.composition-track span{display:block;width:var(--size);min-width:2px}.tone-1{background:#80011f}.tone-2{background:#00002c}.tone-3{background:#a85a70}.tone-4{background:#474767}.tone-5{background:#c88a9c}.tone-6{background:#77778a}.composition-chart ul{margin:0;padding:0;border-top:1px solid var(--navy);list-style:none}.composition-chart li{display:grid;grid-template-columns:12px minmax(0,1fr) auto;gap:12px;align-items:center;padding:10px 0;border-bottom:1px solid var(--rule);font-size:.8rem}.composition-chart li i{width:10px;height:10px}.composition-chart li strong{font-size:.76rem}.coverage-callout{display:grid;grid-template-columns:220px minmax(0,1fr);gap:24px;margin-top:32px;padding:18px 0;border-top:2px solid var(--navy);border-bottom:1px solid var(--rule)}.coverage-callout p{margin:0;color:var(--muted)}
.evidence-strip{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:1px;background:var(--rule)}.evidence-strip article{min-width:0;padding:28px;background:var(--surface)}.evidence-strip article>span{color:var(--burgundy);font-size:.65rem;font-weight:850;letter-spacing:.08em;text-transform:uppercase}.evidence-strip strong{display:block;margin:24px 0 8px;color:var(--navy);font-size:3rem;line-height:1}.evidence-strip h3{margin:0;font-size:1rem;line-height:1.2}.evidence-strip p,.evidence-strip small{color:var(--muted);font-size:.75rem}
.semantic-strip{grid-template-columns:repeat(5,minmax(0,1fr))}.semantic-strip article{padding:24px}.semantic-strip strong{font-size:2rem}.semantic-sources{margin:30px 0 0;padding:18px 0;border-top:2px solid var(--navy);border-bottom:1px solid var(--rule);color:var(--muted);font-size:.82rem}.semantic-sources strong{color:var(--navy)}
.taxonomy-grid{display:grid;gap:18px}.taxonomy-grid-core{grid-template-columns:repeat(5,minmax(0,1fr))}.taxonomy-grid-signals{grid-template-columns:repeat(3,minmax(0,1fr));margin-top:24px}.taxonomy-grid-career{grid-template-columns:repeat(2,minmax(0,1fr))}.taxonomy-panel{min-width:0;padding:18px;border-top:2px solid var(--navy);background:var(--surface)}.taxonomy-panel header h3,.career-stage header h3{margin:0;font-size:1rem}.taxonomy-panel header p,.career-stage header p{margin:7px 0 14px;color:var(--muted);font-size:.7rem;line-height:1.35}.taxonomy-panel ol,.career-stage ul{margin:0;padding:0;list-style:none}.taxonomy-cell{display:grid;grid-template-columns:minmax(0,1fr) 42%;gap:10px;align-items:center;padding:8px;border-bottom:1px solid var(--rule)}.taxonomy-cell span{min-width:0}.taxonomy-cell span strong,.taxonomy-cell span small{display:block}.taxonomy-cell span strong{font-size:.72rem}.taxonomy-cell span small{margin-top:2px;color:var(--muted);font-size:.62rem}.taxonomy-cell>i{display:block;height:6px;overflow:hidden;background:var(--soft)}.taxonomy-cell>i b{display:block;width:var(--share);height:100%;min-width:2px;background:var(--burgundy)}.taxonomy-empty{padding:8px;color:var(--muted);font-size:.68rem}.taxonomy-unknown{margin:10px 0 0;color:var(--muted);font-size:.64rem;line-height:1.35}.taxonomy-unknown strong{color:var(--navy)}.career-semantic-layout{display:grid;grid-template-columns:.8fr 1.2fr;gap:24px}.career-stage{padding:20px;border-top:2px solid var(--navy);background:var(--surface)}.career-stage .composition-track{margin:16px 0}.career-stage .taxonomy-cell{grid-template-columns:12px minmax(0,1fr) auto}.career-stage .taxonomy-cell>i{width:10px;height:10px}.career-stage .taxonomy-cell>strong{font-size:.66rem}.career-overlay-note{display:grid;grid-template-columns:220px minmax(0,1fr);gap:24px;margin-top:22px;padding:15px 0;border-top:2px solid var(--navy);border-bottom:1px solid var(--rule)}.career-overlay-note p{margin:0;color:var(--muted);font-size:.76rem}.methodology-details{margin-top:18px;border-top:2px solid var(--navy);border-bottom:1px solid var(--rule)}.methodology-details summary{padding:12px 0;color:var(--navy);font-size:.82rem;font-weight:850;cursor:pointer}.methodology-details summary:hover{color:var(--burgundy)}.methodology-details-body{display:grid;grid-template-columns:1fr 1.35fr;gap:28px;padding:4px 0 14px}.methodology-details-body p,.methodology-details-body li{color:var(--muted);font-size:.7rem}.methodology-details-body p{margin:0}.methodology-details-body ul{margin:0;padding-left:18px}.taxonomy-definitions .definition-list{grid-template-columns:repeat(3,minmax(0,1fr));padding-bottom:12px}
.semantic-evidence-compact{margin-bottom:24px;border-top:2px solid var(--navy);border-bottom:1px solid var(--rule)}.semantic-evidence-compact>header{display:flex;gap:18px;justify-content:space-between;padding:12px 0;color:var(--muted);font-size:.72rem}.semantic-evidence-compact>header strong{color:var(--navy)}.semantic-evidence-compact ul{display:grid;grid-template-columns:repeat(auto-fit,minmax(138px,1fr));margin:0;padding:0;list-style:none}.semantic-evidence-compact li{display:grid;gap:4px;padding:12px 14px 14px 0;border-top:1px solid var(--rule)}.semantic-evidence-compact li strong{color:var(--navy);font-size:1rem}.semantic-evidence-compact li span{color:var(--muted);font-size:.66rem;line-height:1.3}.semantic-compact-sources{margin:0;padding:10px 0;color:var(--muted);font-size:.68rem}.semantic-compact-sources strong{color:var(--navy)}.capability-career-layout{display:grid;grid-template-columns:.72fr .78fr 1.5fr;gap:18px}.capability-context{display:flex;min-width:0;flex-direction:column}.capability-context>header{padding:18px;border-top:2px solid var(--navy);background:var(--surface)}.capability-context>header h3,.domain-context>header h3{margin:0;font-size:1rem}.capability-context>header p,.domain-context>header p{margin:7px 0 0;color:var(--muted);font-size:.7rem}.taxonomy-grid-capabilities{grid-template-columns:1fr;flex:1}.domain-context{display:grid;grid-template-columns:minmax(220px,.55fr) minmax(0,1.45fr);gap:18px;margin-bottom:24px}.domain-context>header{padding:18px 18px 18px 0;border-top:2px solid var(--navy)}
.cohort-comparison{min-width:0}.cohort-evidence-matrix{display:grid;grid-template-columns:minmax(220px,1.15fr) repeat(3,minmax(150px,1fr));border-top:2px solid var(--navy);border-left:1px solid var(--rule)}.cohort-evidence-matrix>*{min-width:0;border-right:1px solid var(--rule);border-bottom:1px solid var(--rule)}.cohort-matrix-corner,.cohort-matrix-head{padding:14px;background:var(--navy);color:var(--paper)}.cohort-matrix-corner strong,.cohort-matrix-corner small,.cohort-matrix-head strong,.cohort-matrix-head small{display:block}.cohort-matrix-corner small,.cohort-matrix-head small{margin-top:5px;color:#d3d2dd;font-size:.65rem}.cohort-matrix-label{padding:10px 14px;background:var(--surface)}.cohort-matrix-label strong,.cohort-matrix-label small{display:block}.cohort-matrix-label strong{font-size:.78rem}.cohort-matrix-label small{margin-top:3px;color:var(--muted);font-size:.58rem;line-height:1.25}.cohort-matrix-cell{display:grid;grid-template-columns:minmax(0,1fr) 42%;gap:4px 10px;align-content:center;padding:9px 12px;background:var(--paper)}.cohort-matrix-cell strong{color:var(--navy);font-size:.75rem}.cohort-matrix-cell>i{display:block;height:7px;overflow:hidden;background:var(--soft)}.cohort-matrix-cell>i b{display:block;width:var(--share,0%);height:100%;background:var(--burgundy)}.cohort-matrix-cell small{grid-column:1/-1;color:var(--muted);font-size:.56rem}.cohort-matrix-cell.is-withheld strong{color:var(--muted)}.cohort-source-use{margin-top:18px;border-top:2px solid var(--navy)}.cohort-source-use>header{display:flex;gap:18px;justify-content:space-between;padding:10px 0;color:var(--muted);font-size:.66rem}.cohort-source-use>header strong{color:var(--navy)}.cohort-source-use>div{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:1px;background:var(--rule)}.cohort-source-use article{padding:10px;background:var(--surface)}.cohort-source-use article>strong{font-size:.68rem}.cohort-source-use article>div{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:6px;margin-top:7px}.cohort-source-use span b,.cohort-source-use span small{display:block}.cohort-source-use span b{font-size:.62rem}.cohort-source-use span small{color:var(--muted);font-size:.52rem}
.dot-plot{display:grid;grid-template-columns:minmax(180px,.7fr) minmax(320px,1.3fr) 118px}.dot-axis{grid-column:2;display:flex;justify-content:space-between;padding-bottom:8px;color:var(--muted);font-size:.65rem}.dot-plot ol{display:contents}.dot-row{display:grid;grid-column:1/-1;grid-template-columns:subgrid;align-items:center;min-height:48px;border-bottom:1px solid var(--rule)}.dot-row strong{padding-right:18px;font-size:.85rem}.dot-row b{text-align:right;font-size:.76rem}.dot-field{position:relative;height:100%;background:linear-gradient(90deg,transparent 0,transparent calc(33.333% - 1px),var(--soft) 33.333%,transparent calc(33.333% + 1px),transparent calc(66.666% - 1px),var(--soft) 66.666%,transparent calc(66.666% + 1px))}.dot-field i{position:absolute;top:50%;left:min(calc(var(--position) / .6),100%);width:14px;height:14px;border:3px solid var(--surface);border-radius:50%;background:var(--burgundy);box-shadow:0 0 0 1px var(--burgundy);transform:translate(-50%,-50%)}
.methodology-grid{display:grid;grid-template-columns:1.35fr .65fr;gap:56px}.methodology-grid h3,.methodology-coverage h3{margin:0 0 18px;font-size:1.15rem}.definition-list{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:0 28px;margin:0}.definition-list div{padding:12px 0;border-top:1px solid var(--rule)}.definition-list dt{color:var(--navy);font-size:.82rem;font-weight:850}.definition-list dd{margin:5px 0 0;color:var(--muted);font-size:.74rem}.methodology-grid article:last-child .definition-list{grid-template-columns:1fr}.methodology-coverage{margin-top:28px;padding-top:18px;border-top:2px solid var(--navy)}.methodology-coverage ul{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:18px;margin:0;padding:0;list-style:none}.methodology-coverage li{display:grid;gap:4px}.methodology-coverage li span,.methodology-coverage p{color:var(--muted);font-size:.72rem}.methodology-coverage li strong{font-size:1.2rem}.report-note{margin:0;padding:28px 0 0;color:var(--muted);background:transparent;font-size:.78rem}.report-note>strong{color:var(--navy)}.report-note p{margin:8px 0 0}.report-footer{display:flex;justify-content:space-between;gap:24px;margin-top:18px;padding-top:12px;border-top:1px solid var(--rule);color:var(--muted);font-size:.7rem}
.source-boundary{margin-top:0}.source-boundary li{grid-template-rows:auto auto 8px auto;padding:18px;border-top:2px solid var(--navy);background:var(--surface)}.source-boundary li i{display:block;overflow:hidden;background:var(--soft)}.source-boundary li i b{display:block;width:var(--share);height:100%;background:var(--burgundy)}.source-boundary li small{color:var(--muted);font-size:.72rem;line-height:1.4}.source-boundary-notes{display:grid;grid-template-columns:.9fr 1.1fr .9fr;gap:32px;margin-top:32px;padding-top:18px;border-top:2px solid var(--navy)}.source-boundary-notes article{min-width:0;padding-top:10px;border-top:1px solid var(--rule)}.source-boundary-notes strong{color:var(--navy)}.source-boundary-notes p{margin:8px 0 0;color:var(--muted);font-size:.78rem}
.partner-questions{display:grid;grid-template-columns:minmax(220px,.7fr) minmax(0,1.3fr);gap:28px;align-items:start;padding:34px clamp(28px,6vw,88px);border-bottom:1px solid var(--rule);background:var(--canvas)}.partner-questions h3{max-width:14ch;margin:4px 0 0;color:var(--navy);font-size:1.55rem}.partner-question-controls{display:none;flex-wrap:wrap;gap:8px;grid-column:2}.js .partner-question-controls{display:flex}.partner-question-controls button{min-height:42px;padding:9px 14px;border:1px solid var(--rule);border-radius:999px;color:var(--navy);background:var(--paper);font:inherit;font-size:.76rem;font-weight:800;cursor:pointer}.partner-question-controls button[aria-pressed=true]{color:var(--paper);background:var(--navy);border-color:var(--navy)}.partner-answer-region{grid-column:2}.partner-answer{padding-top:18px;border-top:2px solid var(--navy)}.js .partner-answer{display:none}.js .partner-answer.is-active{display:grid}.partner-answer p{max-width:70ch;margin:0;color:var(--ink)}.partner-answer ul{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:1px;margin:18px 0 0;padding:1px;background:var(--rule);list-style:none}.partner-answer li{display:grid;gap:4px;padding:12px;background:var(--paper)}.partner-answer li strong{color:var(--navy);font-size:.9rem}.partner-answer li span{color:var(--muted);font-size:.68rem}.pdf-actions{display:flex;grid-column:2;flex-wrap:wrap;gap:10px}.pdf-actions a{display:inline-flex;min-height:44px;align-items:center;padding:10px 15px;border:1px solid var(--burgundy);color:var(--burgundy);font-size:.76rem;font-weight:800;text-decoration:none}.pdf-actions a:first-child{color:var(--surface);background:var(--burgundy)}.report-reading-progress{position:fixed;z-index:20;top:0;left:0;width:0;height:3px;background:var(--burgundy);transform-origin:left center;transition:width 180ms cubic-bezier(.25,1,.5,1)}.exhibit.is-question-target{outline:2px solid color-mix(in oklch,var(--burgundy) 38%,transparent);outline-offset:-12px}.report-nav a[aria-current=true]{color:var(--burgundy);font-weight:800}.decision-question{margin:0 0 5mm;color:var(--burgundy);font-size:.72rem;font-weight:850;letter-spacing:.08em;text-transform:uppercase}
.operational-evidence{display:grid;grid-template-columns:42mm minmax(0,1fr);gap:18px;margin-top:18px;padding-top:14px;border-top:2px solid var(--navy)}.operational-evidence header strong,.operational-evidence header span{display:block}.operational-evidence header span{margin-top:5px;color:var(--muted);font-size:.72rem}.operational-evidence ul{display:grid;grid-template-columns:1fr;gap:1px;margin:0;padding:1px;background:var(--rule);list-style:none}.operational-evidence li{padding:10px;background:var(--surface)}.operational-evidence li strong,.operational-evidence li span{display:block}.operational-evidence li strong{color:var(--navy)}.operational-evidence li span{margin-top:3px;color:var(--muted);font-size:.72rem}
.partner-dashboard{display:grid;grid-template-columns:minmax(220px,.65fr) minmax(0,1.35fr);gap:28px;padding:44px clamp(28px,6vw,88px);border-bottom:1px solid var(--rule);background:var(--canvas)}.partner-dashboard>header h2{max-width:16ch;margin:0;font-size:clamp(2rem,3vw,3.2rem);letter-spacing:-.035em}.partner-dashboard>header>p:last-child{color:var(--muted);font-size:.82rem}.dashboard-controls{display:grid;gap:14px}.dashboard-controls>div{display:flex;flex-wrap:wrap;gap:8px}.dashboard-controls span{width:72px;align-self:center;color:var(--muted);font-size:.68rem;font-weight:850;text-transform:uppercase}.dashboard-controls button{min-height:44px;padding:9px 14px;border:1px solid var(--rule);color:var(--navy);background:var(--paper);font:inherit;font-size:.76rem;font-weight:800;cursor:pointer}.dashboard-controls button[aria-pressed=true]{color:var(--surface);background:var(--navy);border-color:var(--navy)}
@media (max-width:1100px){.semantic-strip{grid-template-columns:repeat(2,minmax(0,1fr))}.taxonomy-grid-core{grid-template-columns:repeat(3,minmax(0,1fr))}.career-semantic-layout{grid-template-columns:1fr}}
@media (max-width:900px){.capability-career-layout,.domain-context{grid-template-columns:1fr}.taxonomy-grid-capabilities{grid-template-columns:repeat(2,minmax(0,1fr))}.partner-questions{grid-template-columns:1fr}.partner-question-controls,.partner-answer-region,.pdf-actions{grid-column:1}.cohort-evidence-matrix{grid-template-columns:minmax(180px,1fr) repeat(3,minmax(125px,1fr))}.cohort-source-use>div{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media (max-width:900px){.partner-dashboard{grid-template-columns:1fr}}
@media (max-width:900px){.cover-findings{grid-template-columns:repeat(2,minmax(0,1fr))}.report-shell{display:block}.report-nav{position:static;width:100%;height:auto;padding:18px 24px;display:flex;flex-wrap:wrap;gap:4px 18px;border-right:0;border-bottom:1px solid var(--rule)}.report-nav strong{width:100%;margin:0 0 8px}.report-nav a{padding:4px 0}.exhibit{min-height:auto}.exhibit-head{grid-template-columns:1fr;gap:18px}.exhibit-head .exhibit-number{margin-bottom:-6px}.composition-chart{grid-template-columns:1fr}.dot-plot{grid-template-columns:minmax(150px,.8fr) minmax(260px,1.2fr) 108px}}
@media (max-width:640px){body{font-size:16px}.cover{min-height:100svh;padding:24px 20px}.brand{width:142px;height:64px}.cover h1{font-size:3.1rem}.cover-findings{grid-template-columns:1fr 1fr}.cover-finding{padding:14px 14px 6px 0}.cover-finding strong{font-size:1.08rem}.cover-meta{display:grid;grid-template-columns:1fr 1fr;gap:8px 16px}.report-nav{padding:14px 18px}.report-nav a{min-height:44px;display:flex;align-items:center;padding:10px 0;font-size:.76rem}.exhibit{padding:56px 18px}.exhibit-head h2{font-size:2.25rem}.ranked-signal-grid,.taxonomy-grid-core,.taxonomy-grid-signals,.taxonomy-grid-career,.career-semantic-layout{grid-template-columns:1fr;gap:40px}.funnel-row{grid-template-columns:1fr;gap:8px}.funnel-track{height:28px}.privacy-marker{padding:10px 12px}.funnel-row p{margin-left:28px}.selection-note,.coverage-callout,.career-overlay-note,.methodology-details-body{grid-template-columns:1fr;gap:8px}.composition-track{height:52px}.evidence-strip,.semantic-strip{grid-template-columns:1fr}.evidence-strip article{padding:20px}.dot-plot{display:block}.dot-axis{display:none}.dot-row{display:grid;grid-template-columns:minmax(0,1fr) auto;min-height:52px}.dot-row .dot-field{grid-column:1/-1;grid-row:2;height:18px}.dot-row b{grid-column:2;grid-row:1}.taxonomy-definitions .definition-list{grid-template-columns:1fr}.report-footer{display:grid}}
@media (max-width:640px){.semantic-evidence-compact>header{display:grid}.semantic-evidence-compact ul,.taxonomy-grid-capabilities{grid-template-columns:1fr}.capability-context>header,.domain-context>header{padding:18px 0}}
@media (max-width:640px){.partner-questions,.partner-dashboard{padding:28px 18px}.partner-answer ul,.dashboard-chart{grid-template-columns:1fr}.dashboard-controls>div{display:grid;grid-template-columns:1fr 1fr}.dashboard-controls span{grid-column:1/-1;width:auto}}
@media (max-width:640px){.cohort-evidence-matrix{grid-template-columns:1fr}.cohort-matrix-corner{display:none}.cohort-matrix-head{padding:12px}.cohort-source-use>header{display:block}.cohort-source-use>header span{display:block;margin-top:5px}.cohort-source-use>div{grid-template-columns:1fr}}
@media (max-width:640px){.operational-evidence{grid-template-columns:1fr}.operational-evidence ul{grid-template-columns:1fr}}
@media (prefers-reduced-motion:reduce){html{scroll-behavior:auto}.report-reading-progress{transition:none}.exhibit.is-question-target{outline-offset:-8px}}
@page{size:A4 landscape;margin:0}
@media print{*{-webkit-print-color-adjust:exact;print-color-adjust:exact}html,body{width:297mm;margin:0;background:var(--paper);font-size:7.8pt}.skip,.report-nav{display:none!important}.report-shell{display:block;width:297mm;max-width:none}.report-page{width:297mm;min-height:210mm;padding:10mm 13mm;break-after:page;overflow:hidden}.report-page:last-child{break-after:auto}.cover{min-height:210mm;padding:10mm 13mm}.cover h1{font-size:42pt}.cover .dek{margin:5mm 0}.cover-findings{grid-template-columns:repeat(4,minmax(0,1fr))}.cover-finding{padding:4mm 5mm 2mm 0}.cover-finding strong{font-size:13pt}.report-page-evidence{display:grid;grid-template-rows:auto 1fr;gap:5mm}.report-page-pair{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10mm}.exhibit{min-height:0;padding:0;border:0;break-inside:avoid}.exhibit-head{display:grid;grid-template-columns:minmax(0,1fr) 58mm;gap:5mm;margin-bottom:4mm}.exhibit-head .exhibit-number{margin-bottom:-2mm}.exhibit-head h2{font-size:18pt}.exhibit-head>p:last-child{font-size:6.8pt}.report-page-pair .exhibit-head{display:block}.report-page-pair .exhibit-head .exhibit-number{margin-bottom:1mm}.report-page-pair .exhibit-head h2{font-size:18pt}.report-page-pair .exhibit-head>p:last-child{margin-top:2mm}.funnel-row{grid-template-columns:43mm minmax(0,1fr) 48mm;gap:4mm;padding:1.2mm 0}.funnel-track{height:6mm}.privacy-marker{padding:2mm}.selection-note{grid-template-columns:38mm minmax(0,1fr);gap:4mm;margin-top:2.5mm;padding:2mm 0}.selection-note p{font-size:6.8pt}.ranked-signal-grid{gap:4mm}.ranked-signal-grid h3{margin-bottom:2mm;font-size:10pt}.ranked-signal{grid-template-columns:6mm minmax(0,1fr) auto;gap:2mm;padding:1mm 0}.ranked-signal strong{font-size:7pt}.ranked-signal b,.coverage-note{font-size:6.3pt}.composition-chart{display:block}.composition-track{height:10mm;margin-bottom:3mm}.composition-chart li{padding:1mm 0;font-size:6.8pt}.coverage-callout{display:block;margin-top:3mm;padding:2mm 0}.coverage-callout strong,.coverage-callout p{font-size:6.8pt}.evidence-strip{grid-template-columns:repeat(2,minmax(0,1fr))}.semantic-strip{grid-template-columns:repeat(7,minmax(0,1fr))}.evidence-strip article,.semantic-strip article{padding:3mm}.evidence-strip strong{margin:3mm 0 1.5mm;font-size:18pt}.semantic-strip strong{font-size:13pt}.semantic-strip h3{font-size:6.8pt}.semantic-strip p,.semantic-strip small{font-size:5.8pt}.semantic-sources{margin-top:3mm;padding:2mm 0;font-size:6.3pt}.taxonomy-grid{gap:2mm}.taxonomy-grid-core{grid-template-columns:repeat(5,minmax(0,1fr))}.taxonomy-grid-signals{grid-template-columns:repeat(3,minmax(0,1fr));margin-top:3mm}.taxonomy-panel{padding:2.2mm}.taxonomy-panel header h3,.career-stage header h3{font-size:7.2pt}.taxonomy-panel header p,.career-stage header p{margin:1mm 0 1.5mm;font-size:5.3pt}.taxonomy-cell{grid-template-columns:minmax(0,1fr) 37%;gap:1.5mm;padding:1mm}.taxonomy-cell span strong{font-size:5.6pt}.taxonomy-cell span small,.taxonomy-unknown,.taxonomy-empty{font-size:4.9pt}.career-semantic-layout{grid-template-columns:.75fr 1.25fr;gap:3mm}.career-stage{padding:2.5mm}.career-stage .composition-track{margin:2mm 0}.career-overlay-note{grid-template-columns:42mm minmax(0,1fr);gap:3mm;margin-top:2.5mm;padding:2mm 0}.career-overlay-note p{font-size:5.6pt}.dot-plot{display:block}.dot-axis{display:none}.dot-row{display:grid;grid-template-columns:minmax(0,1fr) auto;min-height:6mm}.dot-row .dot-field{grid-column:1/-1;grid-row:2;height:3mm}.dot-row strong,.dot-row b{font-size:6.5pt}.chart-footnote{margin-top:3mm;font-size:6.4pt}.report-page-methodology .exhibit-head{margin-bottom:3mm}.methodology-grid{grid-template-columns:1.4fr .6fr;gap:5mm}.methodology-grid h3,.methodology-coverage h3{margin-bottom:1.5mm;font-size:8pt}.definition-list{gap:0 3mm}.definition-list div{padding:.8mm 0}.definition-list dt{font-size:5.7pt}.definition-list dd{margin-top:.4mm;font-size:4.9pt}.methodology-details{margin-top:2mm}.methodology-details summary{padding:1mm 0;font-size:5.8pt}.methodology-details-body{grid-template-columns:1fr 1.3fr;gap:3mm;padding-bottom:1mm}.methodology-details-body p,.methodology-details-body li{font-size:4.7pt}.taxonomy-definitions .definition-list{grid-template-columns:repeat(3,minmax(0,1fr));padding-bottom:1mm}.methodology-coverage{margin-top:2mm;padding-top:1.5mm}.methodology-coverage ul{gap:2mm}.methodology-coverage li span,.methodology-coverage p{font-size:4.9pt}.methodology-coverage li strong{font-size:8pt}.report-note{padding:1.5mm 0 0;break-inside:avoid;font-size:5pt}.report-footer{margin-top:1mm}.report-note p{margin-top:.5mm}}
@media print{.report-page-taxonomy .exhibit{display:grid;height:190mm;grid-template-rows:auto auto minmax(0,1fr) auto}.report-page-career .exhibit{display:grid;height:190mm;grid-template-rows:auto minmax(0,1fr) auto}.report-page-taxonomy .exhibit{row-gap:3mm}.report-page-taxonomy .exhibit-head,.report-page-career .exhibit-head{margin-bottom:0}.report-page-taxonomy .semantic-evidence-compact{margin:0}.report-page-taxonomy .semantic-evidence-compact>header{padding:1.5mm 0;font-size:5.8pt}.report-page-taxonomy .semantic-evidence-compact ul{grid-template-columns:repeat(7,minmax(0,1fr))}.report-page-taxonomy .semantic-evidence-compact li{padding:1.5mm 1.5mm 1.5mm 0}.report-page-taxonomy .semantic-evidence-compact li strong{font-size:7pt}.report-page-taxonomy .semantic-evidence-compact li span{font-size:5.2pt}.report-page-taxonomy .taxonomy-grid{min-height:0;align-items:stretch}.report-page-taxonomy .taxonomy-grid-core{height:100%}.report-page-taxonomy .taxonomy-panel,.report-page-career .taxonomy-panel,.report-page-career .career-stage{display:flex;height:100%;flex-direction:column}.report-page-taxonomy .taxonomy-panel ol,.report-page-career .taxonomy-panel ol,.report-page-career .career-stage ul{display:flex;flex:1;flex-direction:column;justify-content:center}.report-page-taxonomy .taxonomy-unknown,.report-page-career .taxonomy-unknown{margin-top:auto}.report-page-taxonomy .taxonomy-panel header h3,.report-page-career .taxonomy-panel header h3,.report-page-career .career-stage header h3{font-size:8.4pt}.report-page-taxonomy .taxonomy-panel header p,.report-page-career .taxonomy-panel header p,.report-page-career .career-stage header p{font-size:6.2pt;line-height:1.4}.report-page-taxonomy .taxonomy-cell span strong,.report-page-career .taxonomy-cell span strong{font-size:6.5pt}.report-page-taxonomy .taxonomy-cell span small,.report-page-career .taxonomy-cell span small,.report-page-taxonomy .taxonomy-unknown,.report-page-career .taxonomy-unknown,.report-page-taxonomy .taxonomy-empty,.report-page-career .taxonomy-empty{font-size:5.6pt}.report-page-taxonomy .taxonomy-empty,.report-page-career .taxonomy-empty{padding:4mm 2mm;border-top:1px solid var(--rule);border-bottom:1px solid var(--rule);background:var(--paper)}.report-page-career .capability-career-layout{display:grid;grid-template-columns:.72fr .78fr 1.5fr}.report-page-career .capability-career-layout{min-height:0;gap:2mm}.report-page-career .capability-context{min-height:0}.report-page-career .capability-context>header{padding:2mm}.report-page-career .capability-context>header h3{font-size:8.4pt}.report-page-career .capability-context>header p{font-size:5.6pt}.report-page-career .taxonomy-grid-capabilities{grid-template-rows:repeat(2,minmax(0,1fr));gap:2mm}.report-page-career .taxonomy-grid-career{grid-template-rows:repeat(2,minmax(0,1fr))}.report-page-career .career-stage .composition-track{height:14mm}.report-page-career .career-stage .taxonomy-cell{padding:2.5mm 1mm}.report-page-career .career-overlay-note{margin-top:3mm}.report-page-methodology{padding-top:7mm;padding-bottom:7mm}.report-page-methodology .exhibit-head{margin-bottom:2mm}.report-page-methodology .domain-context{display:grid;grid-template-columns:42mm minmax(0,1fr)}.report-page-methodology .domain-context{gap:3mm;margin:0 0 2mm}.report-page-methodology .domain-context>header{padding:2mm 2mm 2mm 0}.report-page-methodology .domain-context>header h3{font-size:8pt}.report-page-methodology .domain-context>header p{font-size:5.4pt}.report-page-methodology .domain-context .taxonomy-panel{padding:2mm}.report-page-methodology .domain-context .taxonomy-panel header p{margin:1mm 0;font-size:5.2pt}.report-page-methodology .domain-context .taxonomy-cell{padding:1mm}.report-page-methodology .domain-context .taxonomy-unknown{margin:1mm 0 0;font-size:5pt}}
@media print{.report-page-cohort-taxonomy .exhibit{display:grid;height:190mm;grid-template-rows:auto minmax(0,1fr);gap:3mm}.report-page-cohort-taxonomy .exhibit-head{margin:0}.report-page-cohort-taxonomy .cohort-comparison{display:flex;min-height:0;flex-direction:column}.report-page-cohort-taxonomy .cohort-evidence-matrix{flex:1;grid-template-columns:48mm repeat(3,minmax(0,1fr))}.report-page-cohort-taxonomy .cohort-matrix-corner,.report-page-cohort-taxonomy .cohort-matrix-head{padding:2mm}.report-page-cohort-taxonomy .cohort-matrix-corner strong,.report-page-cohort-taxonomy .cohort-matrix-head strong,.report-page-cohort-taxonomy .cohort-matrix-corner small,.report-page-cohort-taxonomy .cohort-matrix-head small{font-size:7.5pt}.report-page-cohort-taxonomy .cohort-matrix-label{display:flex;align-items:center;padding:1.2mm 2mm}.report-page-cohort-taxonomy .cohort-matrix-label strong{font-size:7.5pt}.report-page-cohort-taxonomy .cohort-matrix-label small{display:none}.report-page-cohort-taxonomy .cohort-matrix-cell{padding:1.2mm 2mm}.report-page-cohort-taxonomy .cohort-matrix-cell strong,.report-page-cohort-taxonomy .cohort-matrix-cell small{font-size:7.5pt}.report-page-cohort-taxonomy .cohort-source-use{margin-top:2mm}.report-page-cohort-taxonomy .cohort-source-use>header{padding:1.5mm 0;font-size:7.5pt}.report-page-cohort-taxonomy .cohort-source-use article{padding:1.5mm}.report-page-cohort-taxonomy .cohort-source-use article>strong,.report-page-cohort-taxonomy .cohort-source-use span b,.report-page-cohort-taxonomy .cohort-source-use span small{font-size:7.5pt}.report-page-cohort-taxonomy .chart-footnote{margin-top:2mm;font-size:7.5pt}}
@media print{.report-page-methodology .definition-list dt{font-size:6.5pt}.report-page-methodology .definition-list dd{font-size:5.8pt}.report-page-methodology .definition-list div{padding:1.2mm 0}.report-page-methodology .methodology-details summary{font-size:6.5pt}.report-page-methodology .methodology-details-body p,.report-page-methodology .methodology-details-body li{font-size:5.6pt}.report-page-methodology .methodology-coverage li span,.report-page-methodology .methodology-coverage p{font-size:5.6pt}.report-page-methodology .report-note{font-size:5.6pt}.report-page-methodology .methodology-coverage{margin-top:3mm;padding-top:2mm}.report-page-methodology .report-note{padding-top:2mm}}
@media print{.report-page-taxonomy .taxonomy-panel ol,.report-page-career .taxonomy-panel ol,.report-page-career .career-stage ul{justify-content:space-evenly}.report-page-methodology .exhibit-number{font-size:7.5pt}.report-page-methodology .domain-context>header h3{font-size:9pt}.report-page-methodology .domain-context>header p,.report-page-methodology .domain-context .taxonomy-panel header p,.report-page-methodology .domain-context .taxonomy-cell span small,.report-page-methodology .domain-context .taxonomy-unknown{font-size:7.5pt}.report-page-methodology .domain-context .taxonomy-cell span strong{font-size:7.5pt}.report-page-methodology .definition-list dt{font-size:8pt}.report-page-methodology .definition-list dd{font-size:7.5pt}.report-page-methodology .methodology-details summary{font-size:8pt}.report-page-methodology .methodology-details-body p,.report-page-methodology .methodology-details-body li,.report-page-methodology .methodology-coverage li span,.report-page-methodology .methodology-coverage p{font-size:7.5pt}.report-page-methodology .report-note{font-size:7.5pt}.report-page-methodology .report-footer{font-size:7.5pt}}
@media print{.report-page-methodology .domain-context .taxonomy-panel ol{display:grid;grid-template-columns:repeat(6,minmax(0,1fr));gap:1mm 2mm}.report-page-methodology .domain-context .taxonomy-cell{grid-template-columns:minmax(0,1fr);align-content:start}.report-page-methodology .domain-context .taxonomy-cell>i{height:1.2mm}.report-page-methodology .definition-list div{padding:.8mm 0}.report-page-methodology .methodology-details{margin-top:1.2mm}.report-page-methodology .methodology-details-body{padding-bottom:.5mm}.report-page-methodology .methodology-coverage{margin-top:2mm;padding-top:1.2mm}.report-page-methodology .report-note{padding-top:1.2mm}}
@media print{.report-page-methodology{position:relative}.report-page-methodology .report-note{position:absolute;right:13mm;bottom:7mm;left:13mm;display:grid;grid-template-columns:20mm minmax(0,1fr);gap:1mm 3mm;align-items:start}.report-page-methodology .report-note p{max-width:none;margin:0}.report-page-methodology .report-footer{grid-column:1/-1;margin-top:.5mm}}
@media print{.report-page-evidence .evidence-strip article:only-child{grid-column:1/-1;align-items:center;text-align:center}}
@media print{.report-page-evidence{height:190mm;grid-template-rows:minmax(0,1fr) minmax(0,.95fr)}.report-page-evidence .exhibit{display:flex;min-height:0;flex-direction:column}.report-page-evidence .volume-funnel{display:flex;flex:1;flex-direction:column;justify-content:center}.report-page-evidence .evidence-strip{flex:1}.report-page-evidence .evidence-strip article{display:flex;flex-direction:column;justify-content:center}}
@media print{.report-page-journey{height:190mm}.report-page-journey .exhibit{display:flex;height:100%;flex-direction:column}.report-page-journey .volume-funnel{display:flex;flex:1;flex-direction:column;justify-content:space-evenly}.report-page-journey .selection-note{margin-top:3mm}.report-page-journey .operational-evidence{grid-template-columns:38mm minmax(0,1fr);gap:3mm;margin-top:2.5mm;padding-top:2mm}.report-page-journey .operational-evidence ul{grid-template-columns:1fr}.report-page-journey .operational-evidence header span,.report-page-journey .operational-evidence li span{font-size:7.5pt}}
.taxonomy-grid-core{grid-template-columns:repeat(var(--taxonomy-columns,5),minmax(0,1fr))}.capability-career-layout.without-career-stage{grid-template-columns:1fr 2fr}
.capability-career-layout.without-career-stage .taxonomy-grid-career .taxonomy-panel:nth-child(3){grid-column:1/-1}
@media print{.report-page-taxonomy .semantic-evidence-compact ul{grid-template-columns:repeat(var(--metric-columns,7),minmax(0,1fr))}.report-page-taxonomy .taxonomy-grid-core{grid-template-columns:repeat(var(--taxonomy-columns,5),minmax(0,1fr))}.report-page-career .capability-career-layout.without-career-stage{grid-template-columns:1fr 2fr}}
@media print{.report-page-methodology.methodology-without-domain .report-note{position:static;margin-top:4mm}}
@media print{.partner-questions,.partner-dashboard,.report-reading-progress,.pdf-actions{display:none!important}.decision-question{margin-bottom:3mm;font-size:8pt}.exhibit.is-question-target{outline:0}.report-nav a[aria-current=true]{color:inherit;font-weight:inherit}}
@media print{.report-page{height:210mm;min-height:0}.report-page[data-decision-question]{display:grid;grid-template-rows:auto minmax(0,1fr);gap:3mm}.report-page[data-decision-question]>.decision-question{margin:0}.report-page[data-decision-question]>.exhibit{height:100%!important;min-height:0}}
@media print{.report-page .exhibit-head>p:last-child,.report-page .selection-note p,.report-page .semantic-evidence-compact>header,.report-page .semantic-evidence-compact li span,.report-page .taxonomy-panel header p,.report-page .career-stage header p,.report-page .taxonomy-cell span strong,.report-page .taxonomy-cell span small,.report-page .taxonomy-unknown,.report-page .taxonomy-empty,.report-page .capability-context>header p,.report-page .career-overlay-note p{font-size:7.5pt}.report-page .taxonomy-panel header h3,.report-page .career-stage header h3,.report-page .capability-context>header h3{font-size:9pt}}
@media screen and (max-width:640px){.taxonomy-grid-core,.taxonomy-grid-signals,.taxonomy-grid-capabilities,.taxonomy-grid-career,.capability-career-layout,.capability-career-layout.without-career-stage{grid-template-columns:1fr}.capability-career-layout.without-career-stage .taxonomy-grid-career .taxonomy-panel:nth-child(3){grid-column:auto}}

/* Evidence comparator and six-page analytical report overrides. */
button:focus-visible{outline:3px solid var(--focus);outline-offset:3px}
.report-reading-progress{width:100%;transform:scaleX(0);transition:transform 180ms cubic-bezier(.16,1,.3,1)}
.dashboard-controls{display:none}.js .dashboard-controls{display:grid}
.partner-dashboard{grid-template-columns:minmax(230px,.5fr) minmax(0,1.5fr);gap:32px 48px;padding-top:52px;padding-bottom:52px;background:var(--canvas)}
.partner-dashboard>header>p:last-child{max-width:46ch;font-size:.86rem}
.dashboard-controls>div{align-items:center}.dashboard-controls button{border-radius:999px;transition:color 180ms cubic-bezier(.16,1,.3,1),background-color 180ms cubic-bezier(.16,1,.3,1),transform 180ms cubic-bezier(.16,1,.3,1)}
.dashboard-controls button:hover{transform:translateY(-1px)}
.dashboard-cohort-summary{grid-column:1;align-self:start;padding:22px 0;background:transparent;border-top:2px solid var(--navy)}.dashboard-cohort-summary>p:first-child{margin:0;color:var(--burgundy);font-size:.72rem;font-weight:850;text-transform:uppercase}.dashboard-cohort-summary>strong{display:block;margin-top:18px;color:var(--navy);font-size:clamp(3.5rem,5vw,5rem);line-height:1}.dashboard-cohort-summary>span{display:block;margin-top:6px;color:var(--navy);font-size:.76rem;font-weight:800}.dashboard-cohort-summary>p:last-child{margin:18px 0 0;padding-top:16px;border-top:1px solid var(--rule);color:var(--muted);font-size:.76rem}
.dashboard-chart{grid-column:2;display:grid;gap:26px;padding:0;background:transparent}
.dashboard-metric-group>header{display:grid;grid-template-columns:180px minmax(0,1fr);gap:20px;margin-bottom:12px}.dashboard-metric-group h3{margin:0;color:var(--navy);font-size:1rem}.dashboard-metric-group header p{max-width:54ch;margin:0;color:var(--muted);font-size:.72rem}.dashboard-metric-group>div{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px}.dashboard-metric-group:not(:first-child)>div{grid-template-columns:repeat(3,minmax(0,1fr))}
.dashboard-metric{display:grid;grid-template-rows:1fr auto;gap:16px;min-height:132px;padding:18px;border:1px solid var(--rule);color:var(--ink);background:var(--evidence-surface);font:inherit;text-align:left;cursor:pointer;opacity:1;transition:color 200ms cubic-bezier(.16,1,.3,1),background-color 200ms cubic-bezier(.16,1,.3,1),transform 200ms cubic-bezier(.16,1,.3,1),opacity 200ms cubic-bezier(.16,1,.3,1)}
.dashboard-metric:hover{transform:translateY(-2px)}.dashboard-metric[aria-pressed=true]{color:var(--paper);background:var(--navy)}
.dashboard-metric span>*{display:block}.dashboard-metric strong{color:var(--navy);font-size:2.15rem;line-height:1}.dashboard-metric[aria-pressed=true] strong{color:var(--paper)}
.dashboard-metric small{margin-top:8px;color:var(--muted);font-size:.72rem;line-height:1.3}.dashboard-metric[aria-pressed=true] small{color:#d3d2dd}
.dashboard-metric i,.dashboard-comparison-cell i{display:block;height:8px;overflow:hidden;background:var(--soft)}
.dashboard-metric i b,.dashboard-comparison-cell i b{display:block;width:var(--metric-share,0%);height:100%;background:var(--burgundy);transform:scaleX(1);transform-origin:left center;transition:transform 220ms cubic-bezier(.16,1,.3,1)}
.dashboard-chart:not(.is-entered) .dashboard-metric i b,.dashboard-inspector.is-updating .dashboard-comparison-cell i b{transform:scaleX(0)}
.dashboard-inspector{grid-column:1/-1;display:grid;grid-template-columns:minmax(260px,.78fr) minmax(0,1.22fr);gap:44px;margin-top:2px;padding:30px 0;border-top:2px solid var(--navy);border-bottom:1px solid var(--rule);opacity:1;transform:translateY(0);transition:opacity 180ms cubic-bezier(.16,1,.3,1),transform 180ms cubic-bezier(.16,1,.3,1)}
.dashboard-inspector.is-updating{opacity:.58;transform:translateY(4px)}
.dashboard-inspector-copy>.eyebrow{margin-bottom:10px}.dashboard-inspector h3{margin:0 0 12px;font-size:1.25rem}.dashboard-inspector-copy>p:not(.eyebrow){margin:0;color:var(--muted);font-size:.82rem}
.dashboard-inspector dl{display:grid;gap:0;margin:22px 0 0}.dashboard-inspector dl>div{display:grid;grid-template-columns:132px minmax(0,1fr);gap:14px;padding:9px 0;border-top:1px solid var(--rule)}.dashboard-inspector dt{color:var(--navy);font-size:.68rem;font-weight:850}.dashboard-inspector dd{margin:0;color:var(--muted);font-size:.7rem}
.dashboard-comparison{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:1px;padding:1px;background:var(--rule)}.dashboard-comparison-cell{display:grid;gap:8px;padding:15px;background:var(--paper)}.dashboard-comparison-cell span,.dashboard-comparison-cell strong,.dashboard-comparison-cell small{display:block}.dashboard-comparison-cell span{color:var(--muted);font-size:.65rem}.dashboard-comparison-cell strong{color:var(--navy);font-size:1.1rem}.dashboard-comparison-cell small{color:var(--muted);font-size:.62rem}.dashboard-comparison-cell i b{width:var(--comparison-share,0%)}
.overlap-explorer{grid-column:1/-1;border-top:2px solid var(--navy);border-bottom:1px solid var(--rule)}.overlap-explorer>summary{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:20px;align-items:baseline;padding:18px 0;cursor:pointer;list-style:none}.overlap-explorer>summary::-webkit-details-marker{display:none}.overlap-explorer>summary span{color:var(--navy);font-size:1.15rem;font-weight:850}.overlap-explorer>summary small{color:var(--muted);font-size:.7rem}.overlap-explorer-body{display:grid;grid-template-columns:minmax(540px,1.5fr) minmax(220px,.5fr);gap:32px;padding:4px 0 28px}.overlap-reading-note{max-width:76ch;margin:0 0 16px;color:var(--muted);font-size:.72rem}.upset-signal-heads{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:1px;margin-left:150px;border:1px solid var(--rule);background:var(--rule)}.upset-signal-heads>div{display:grid;grid-template-rows:minmax(32px,auto) auto 4px;gap:4px;padding:9px 10px;background:var(--paper);text-align:center}.upset-signal-heads strong{color:var(--navy);font-size:.63rem;line-height:1.25}.upset-signal-heads span{color:var(--muted);font-size:.58rem}.upset-signal-heads i{display:block;overflow:hidden;background:var(--soft)}.upset-signal-heads i b{display:block;width:var(--signal-share);height:4px;background:var(--burgundy)}.upset-column-key{display:grid;grid-template-columns:132px minmax(0,1fr) 32px 42px;gap:10px;align-items:center;padding:8px 10px;color:var(--muted);border-right:1px solid var(--rule);border-left:1px solid var(--rule);font-size:.56rem}.upset-set-key{display:grid;grid-template-columns:repeat(3,1fr);justify-items:center}.upset-set-key b{color:var(--burgundy);font-size:.6rem}.upset-column-key>strong,.upset-column-key>small{font-size:.56rem}.upset-column-key>small{text-align:right}.upset-overlap{border-right:1px solid var(--rule);border-bottom:1px solid var(--rule);border-left:1px solid var(--rule)}.upset-overlap button{display:grid;grid-template-columns:132px minmax(0,1fr) 32px 42px;gap:10px;align-items:center;width:100%;min-height:48px;padding:7px 10px;color:var(--navy);border:0;border-top:1px solid var(--rule);background:var(--surface);font:inherit;text-align:left;cursor:pointer;transition:background-color 180ms cubic-bezier(.16,1,.3,1),transform 180ms cubic-bezier(.16,1,.3,1)}.upset-overlap button:first-child{border-top:0}.upset-overlap button:hover{background:var(--paper);transform:translateY(-1px)}.upset-overlap button[aria-pressed=true]{background:var(--tint);box-shadow:inset 0 0 0 2px var(--navy)}.upset-set-matrix{display:grid;grid-template-columns:repeat(3,1fr);align-items:center;justify-items:center}.upset-dot{width:12px;height:12px;border:1px solid var(--rule);border-radius:50%;background:var(--surface)}.upset-dot.is-on{border-color:var(--burgundy);background:var(--burgundy);box-shadow:0 0 0 2px var(--tint)}.upset-region-bar{position:relative;display:grid;align-items:center;min-height:28px;overflow:hidden;background:var(--soft)}.upset-region-bar i{position:absolute;inset:0 auto 0 0;width:var(--bar-share);background:var(--navy)}.upset-region-bar b{position:relative;padding:0 9px;color:var(--surface);font-size:.62rem;line-height:1.2;mix-blend-mode:difference}.upset-overlap button>strong{font-size:.86rem}.upset-overlap button>small{color:var(--muted);font-size:.58rem;text-align:right}.overlap-unknowns{margin:12px 0 0;color:var(--muted);font-size:.62rem}.overlap-supporting{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:3px 16px;margin-top:16px;padding:14px 0;border-top:1px solid var(--rule)}.overlap-supporting>span{grid-column:1/-1;color:var(--burgundy);font-size:.58rem;font-weight:850;letter-spacing:.04em;text-transform:uppercase}.overlap-supporting>strong{color:var(--navy);font-size:.76rem}.overlap-supporting>b{color:var(--navy);font-size:.76rem}.overlap-supporting>p{grid-column:1/-1;max-width:72ch;margin:3px 0 0;color:var(--muted);font-size:.66rem}.overlap-inspector{align-self:start;margin-top:42px;padding:18px 0;border-top:2px solid var(--burgundy);border-bottom:1px solid var(--rule);background:transparent}.overlap-inspector strong{color:var(--navy);font-size:.9rem}.overlap-inspector p{margin:7px 0 0;color:var(--muted);font-size:.74rem}.overlap-inspector small{display:block;margin-top:12px;color:var(--muted);font-size:.6rem}.partner-dashboard>.pdf-actions{grid-column:1}.partner-dashboard>.pdf-actions a{min-width:148px;justify-content:center}
.upset-set-key span{color:var(--burgundy);font-size:.64rem;font-weight:850;line-height:1.12;text-align:center}.upset-set-key{column-gap:6px}
.upset-signal-heads{margin-left:174px}.upset-column-key,.upset-overlap button{grid-template-columns:156px minmax(0,1fr) 32px 42px}
.upset-region-bar i{background:var(--focus)}.upset-region-bar b{color:var(--navy);mix-blend-mode:normal}
.applicant-composition{display:grid;grid-template-columns:180px minmax(0,1fr);gap:12px 24px;margin-top:24px;padding-top:18px;border-top:2px solid var(--navy)}.applicant-composition header strong,.applicant-composition header span{display:block}.applicant-composition header span{margin-top:4px;color:var(--muted);font-size:.7rem}.applicant-composition .composition-track{height:26px}.applicant-composition ul{grid-column:2;display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:1px;margin:0;padding:1px;background:var(--rule);list-style:none}.applicant-composition li{display:grid;grid-template-columns:10px minmax(0,1fr) auto;gap:8px;align-items:center;padding:9px;background:var(--surface);font-size:.72rem}.applicant-composition li i{width:8px;height:8px}
.all-applicant-signals{display:grid;grid-template-columns:220px minmax(0,1fr);gap:32px;margin-top:22px;padding-top:18px;border-top:2px solid var(--navy)}.all-applicant-signals header strong,.all-applicant-signals header span{display:block}.all-applicant-signals header strong{font-size:.9rem;line-height:1.3}.all-applicant-signals header span{margin-top:7px;color:var(--muted);font-size:.72rem;line-height:1.45}.all-applicant-signals>div{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:16px}.all-applicant-signals article{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:16px;align-items:start;padding:10px 0}.all-applicant-signals article b{font-size:.82rem;line-height:1.35}.all-applicant-signals article strong{color:var(--navy);font-size:.9rem;white-space:nowrap}
.cohort-source-use>aside{margin-top:10px;padding-top:10px;border-top:1px solid var(--rule)}.cohort-source-use>aside>strong,.cohort-source-use>aside>p{display:block}.cohort-source-use>aside>p{margin:3px 0;color:var(--muted);font-size:.66rem}.cohort-source-use>aside>div{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:8px}.cohort-source-use>aside span b,.cohort-source-use>aside span strong,.cohort-source-use>aside span small{display:block}.cohort-source-zero>div{margin-top:7px}.cohort-source-zero>div span{padding-top:6px;border-top:1px solid var(--rule)}
.community-composition-layout{display:grid;grid-template-columns:minmax(0,1.05fr) minmax(0,.95fr);gap:28px}.application-career-stage{padding:20px;border-top:2px solid var(--navy);background:var(--surface)}.application-career-stage header h3{margin:0;font-size:1.05rem}.application-career-stage header p{margin:6px 0 16px;color:var(--muted);font-size:.7rem}.application-career-stage .composition-track{height:32px;margin-bottom:12px}.application-career-stage ul{margin:0;padding:0;list-style:none}.application-career-stage li{display:grid;grid-template-columns:10px minmax(0,1fr) auto;gap:10px;align-items:center;padding:8px 0;border-bottom:1px solid var(--rule);font-size:.72rem}.application-career-stage li i{width:8px;height:8px}.community-career-evidence{display:grid;grid-template-rows:auto 1fr;gap:18px}.career-source-note{display:grid;grid-template-columns:180px minmax(0,1fr);gap:24px;margin-top:22px;padding:14px 0;border-top:2px solid var(--navy);border-bottom:1px solid var(--rule)}.career-source-note p{margin:0;color:var(--muted);font-size:.74rem}.category-model{grid-template-columns:minmax(210px,.75fr) minmax(0,1.25fr)}.category-model-base{display:grid;grid-template-columns:54px minmax(0,1fr);gap:12px;align-items:center;padding-left:14px}.category-model-base,.category-model-overlays{border-left:1px solid var(--navy)}.category-model-base b{color:var(--navy);font-size:1.3rem;line-height:1}.category-model-base span strong,.category-model-base span small{display:block}.category-model-base span small{margin-top:4px;color:var(--muted);font-size:.7rem}.category-model-overlays{padding-left:14px}.category-model-overlays>strong{display:block;color:var(--navy)}.category-model-overlays p{margin-top:4px}
.overlap-observation{display:grid;grid-template-columns:auto minmax(0,1fr);gap:10px;align-items:baseline;margin-top:8px;padding-top:8px;border-top:1px solid var(--rule)}.overlap-observation b{color:var(--burgundy);font-size:.86rem}.overlap-observation small{color:var(--muted);font-size:.68rem}
.definition-ref{margin-left:.22em;font-size:.72em;vertical-align:super}.definition-ref a{color:var(--burgundy);font-weight:850;text-decoration:none}.definition-number{display:inline-block;min-width:1.35em;margin-right:.35em;color:var(--burgundy);font-variant-numeric:tabular-nums}
.capability-market-layout{display:grid;gap:28px}.capability-pair{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:24px}.market-domain-strip{display:grid;grid-template-columns:180px minmax(0,1fr);gap:24px;padding-top:18px;border-top:2px solid var(--navy)}.market-domain-strip>header h3{margin:0;font-size:1.05rem}.market-domain-strip>header p{margin:6px 0 0;color:var(--muted);font-size:.7rem}.market-domain-strip>.taxonomy-panel{padding:0;border-top:0;background:transparent}.market-domain-strip>.taxonomy-panel>header{display:none}.market-domain-strip>.taxonomy-panel ol{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:0 16px}
.method-summary{margin:20px 0 0;padding-top:14px;border-top:1px solid var(--rule);color:var(--muted);font-size:.72rem}.methodology-coverage .method-summary{margin:0;padding:0;border:0}
.upset-static-layout{display:grid;grid-template-columns:minmax(0,1.55fr) minmax(240px,.45fr);gap:32px}.upset-static-note{max-width:78ch;margin:0 0 14px;color:var(--muted)}.upset-static-signals{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:1px;padding:1px;background:var(--rule)}.upset-static-signals article{display:grid;gap:5px;padding:12px;background:var(--paper)}.upset-static-signals span{color:var(--muted);font-size:.68rem}.upset-static-signals strong{color:var(--navy);font-size:.82rem}.upset-static-signals i{height:4px;overflow:hidden;background:var(--soft)}.upset-static-signals i b{display:block;width:var(--signal-share);height:100%;background:var(--burgundy)}.upset-static-rows{border:1px solid var(--rule);border-top:0}.upset-static-row{display:grid;grid-template-columns:132px minmax(0,1fr) 34px 44px;gap:10px;align-items:center;min-height:46px;padding:7px 10px;border-top:1px solid var(--rule)}.upset-static-row:first-child{border-top:0}.upset-static-row>strong{color:var(--navy);font-size:.9rem}.upset-static-row>small{color:var(--muted);font-size:.66rem;text-align:right}.upset-static-unknowns{margin:10px 0 0;color:var(--muted);font-size:.66rem}.upset-static-aside{display:grid;align-content:start;gap:18px}.upset-static-aside article{display:grid;gap:5px;padding:16px 0;border-top:2px solid var(--burgundy)}.upset-static-aside article>span{color:var(--burgundy);font-size:.62rem;font-weight:850;letter-spacing:.04em;text-transform:uppercase}.upset-static-aside article>strong{color:var(--navy);font-size:.9rem}.upset-static-aside article>b{color:var(--navy);font-size:1.25rem}.upset-static-aside article>p{margin:3px 0 0;color:var(--muted);font-size:.72rem}
@media screen{.report-page-cross-dimension{display:none!important}}
@media screen{.report-page[data-decision-question]{background:var(--paper)}.report-page[data-decision-question]>.decision-question{padding:42px clamp(28px,6vw,88px) 0;margin:0}.report-page[data-decision-question]>.exhibit{padding-top:38px}}
.partner-dashboard>.pdf-actions{grid-column:1;justify-content:flex-start}.partner-dashboard>.pdf-actions a{min-width:148px;justify-content:center}
.dashboard-chart:not(.is-entered) .dashboard-metric{opacity:.45;transform:translateY(6px)}
.dashboard-comparison{gap:14px;padding:0;background:transparent}.dashboard-comparison-cell{padding:14px 0;border-top:2px solid var(--navy);background:transparent}
.dashboard-inspector dt{font-size:.76rem}.dashboard-inspector dd{font-size:.76rem;line-height:1.45}
.operational-evidence ul,.applicant-composition ul,.all-applicant-signals>div{gap:16px;padding:0;background:transparent}.operational-evidence li,.applicant-composition li,.all-applicant-signals article{padding:10px 0;border-top:1px solid var(--rule);background:transparent}
.taxonomy-panel,.application-career-stage{background:transparent}.cohort-evidence-notes{margin-top:18px;padding-top:14px;border-top:1px solid var(--rule)}.cohort-evidence-notes p{max-width:none;margin:0;color:var(--muted);font-size:.74rem;line-height:1.5}.cohort-evidence-notes strong{color:var(--navy)}
@media (max-width:900px){.partner-dashboard,.dashboard-inspector,.overlap-explorer-body,.community-composition-layout{grid-template-columns:1fr}.partner-dashboard>header,.dashboard-controls,.dashboard-cohort-summary,.dashboard-chart,.dashboard-inspector,.overlap-explorer,.partner-dashboard>.pdf-actions{grid-column:1;grid-row:auto}.dashboard-metric-group>div{grid-template-columns:repeat(2,minmax(0,1fr))!important}.overlap-inspector{margin-top:0}.community-career-evidence{grid-template-columns:repeat(2,minmax(0,1fr));grid-template-rows:auto}}
@media (max-width:640px){.dashboard-metric-group>header,.dashboard-metric-group>div,.dashboard-comparison,.capability-pair{grid-template-columns:1fr!important}.dashboard-metric{min-height:118px}.overlap-explorer>summary{grid-template-columns:1fr;gap:4px}.overlap-explorer-body{gap:18px}.overlap-matrix{grid-template-columns:88px repeat(2,minmax(0,1fr))}.overlap-matrix-corner,.overlap-axis-x,.overlap-column-head,.overlap-row-head{padding:9px}.overlap-matrix-corner span,.overlap-axis-x span,.overlap-column-head span,.overlap-row-head span{font-size:.6rem}.overlap-matrix-corner strong,.overlap-axis-x strong,.overlap-column-head strong,.overlap-row-head strong{font-size:.66rem}.overlap-matrix button{grid-template-columns:1fr;grid-template-rows:auto auto auto 5px;gap:3px;min-height:112px;padding:10px}.overlap-matrix button strong{grid-row:auto;font-size:1.35rem}.overlap-matrix button span{font-size:.64rem}.overlap-matrix button small{font-size:.58rem}.applicant-composition,.all-applicant-signals,.career-source-note,.market-domain-strip{grid-template-columns:1fr}.applicant-composition ul{grid-column:1}.all-applicant-signals>div,.community-career-evidence,.market-domain-strip>.taxonomy-panel ol{grid-template-columns:1fr}.dashboard-inspector dl>div{grid-template-columns:1fr;gap:3px}.category-model-base,.category-model-overlays{min-height:54px}}
@media (max-width:640px){.upset-signal-heads{margin-left:0}.upset-signal-heads>div{padding:7px 5px}.upset-signal-heads strong{font-size:.58rem}.upset-column-key{grid-template-columns:78px minmax(0,1fr) 28px;gap:7px;padding:7px}.upset-column-key>small{display:none}.upset-overlap button{grid-template-columns:78px minmax(0,1fr) 28px;gap:7px;padding:7px}.upset-overlap button>small{display:none}.upset-region-bar b{padding:0 6px;font-size:.58rem}.upset-dot{width:10px;height:10px}.overlap-supporting{grid-template-columns:1fr}.overlap-supporting>span,.overlap-supporting>p{grid-column:1}}
@media (max-width:640px){.upset-column-key,.upset-overlap button{grid-template-columns:132px minmax(0,1fr) 28px}.upset-set-key span{font-size:.62rem}}
@media (max-width:640px){.methodology-coverage ul,.source-boundary-notes{grid-template-columns:1fr}}
@media (prefers-reduced-motion:reduce){.dashboard-controls button,.dashboard-metric,.dashboard-metric i b,.dashboard-comparison-cell i b,.dashboard-inspector,.overlap-matrix button,.upset-overlap button,.report-reading-progress{transition:none!important}}

@media print{
html,body{width:297mm;margin:0;background:var(--paper);font-size:10pt}
.report-page{position:relative;height:210mm;min-height:0;padding:9mm 12mm}.report-page:not(.report-page-cover)::after{content:"";position:absolute;right:12mm;bottom:6mm;left:12mm;border-top:1px solid var(--rule)}.cover{height:210mm;min-height:0;padding:10mm 13mm}.cover h1{font-size:44pt}.cover-finding strong{font-size:14pt}.cover-finding span,.cover-meta{font-size:9pt}
.report-page[data-decision-question]{grid-template-rows:auto minmax(0,1fr);gap:3mm}.decision-question{font-size:9pt}.report-page .exhibit{height:100%!important}.report-page .exhibit-head{grid-template-columns:minmax(0,1fr) 70mm;gap:7mm;margin-bottom:4mm}.report-page .exhibit-head .exhibit-number{margin-bottom:-1mm;font-size:9pt}.report-page .exhibit-head h2{font-size:22pt}.report-page .exhibit-head>p:last-child{font-size:10pt;line-height:1.35}
.report-page p,.report-page small,.report-page span,.report-page li,.report-page dt,.report-page dd,.report-page strong,.report-page b{font-size:9pt}.report-page .definition-ref,.report-page .definition-ref a{font-size:8.5pt}
.report-page-journey .exhibit{display:grid;grid-template-rows:auto auto auto auto;align-content:start}.report-page-journey .volume-funnel{display:grid;gap:0}.report-page-journey .funnel-row{grid-template-columns:46mm minmax(0,1fr) 64mm;gap:5mm;padding:2mm 0}.report-page-journey .funnel-row strong,.report-page-journey .funnel-row small,.report-page-journey .funnel-row p{font-size:10pt}.report-page-journey .funnel-row>div>span{font-size:9pt}.report-page-journey .funnel-track{height:8mm}.report-page-journey .applicant-composition{grid-template-columns:43mm minmax(0,1fr);gap:2mm 5mm;margin-top:4mm;padding-top:3mm}.report-page-journey .applicant-composition .composition-track{height:7mm}.report-page-journey .applicant-composition ul{grid-column:2}.report-page-journey .applicant-composition li,.report-page-journey .applicant-composition header span{font-size:9pt}.report-page-journey .operational-evidence{grid-template-columns:43mm minmax(0,1fr);gap:5mm;margin-top:3mm;padding-top:3mm}.report-page-journey .operational-evidence li{padding:2mm}.report-page-journey .operational-evidence header span,.report-page-journey .operational-evidence li span{font-size:9pt}
.report-page-cohort-taxonomy .exhibit{display:grid;grid-template-rows:auto minmax(0,1fr);gap:2mm}.report-page-cohort-taxonomy .cohort-comparison{display:grid;align-content:start}.report-page-cohort-taxonomy .cohort-evidence-matrix{display:grid;grid-template-columns:56mm repeat(3,minmax(0,1fr));flex:none}.report-page-cohort-taxonomy .cohort-matrix-corner,.report-page-cohort-taxonomy .cohort-matrix-head{padding:2.4mm}.report-page-cohort-taxonomy .cohort-matrix-corner strong,.report-page-cohort-taxonomy .cohort-matrix-head strong{font-size:10pt}.report-page-cohort-taxonomy .cohort-matrix-corner small,.report-page-cohort-taxonomy .cohort-matrix-head small{font-size:9pt}.report-page-cohort-taxonomy .cohort-matrix-label{padding:2mm 2.4mm}.report-page-cohort-taxonomy .cohort-matrix-label strong{font-size:9.5pt}.report-page-cohort-taxonomy .cohort-matrix-cell{padding:2mm 2.4mm}.report-page-cohort-taxonomy .cohort-matrix-cell strong{font-size:10pt}.report-page-cohort-taxonomy .cohort-matrix-cell small{font-size:9pt}.report-page-cohort-taxonomy .all-applicant-signals{grid-template-columns:43mm minmax(0,1fr);gap:4mm;margin-top:3mm;padding-top:2.5mm}.report-page-cohort-taxonomy .all-applicant-signals header span,.report-page-cohort-taxonomy .all-applicant-signals article span,.report-page-cohort-taxonomy .all-applicant-signals article small{font-size:9pt}.report-page-cohort-taxonomy .all-applicant-signals article{padding:1.6mm}.report-page-cohort-taxonomy .cohort-source-use{margin-top:3mm}.report-page-cohort-taxonomy .cohort-source-use>header{padding:2mm 0;font-size:9pt}.report-page-cohort-taxonomy .cohort-source-use>header strong,.report-page-cohort-taxonomy .cohort-source-use>header span{font-size:9pt}.report-page-cohort-taxonomy .cohort-source-use>div{grid-template-columns:1fr}.report-page-cohort-taxonomy .cohort-source-use article{padding:1.8mm}.report-page-cohort-taxonomy .cohort-source-use article>strong,.report-page-cohort-taxonomy .cohort-source-use span b,.report-page-cohort-taxonomy .cohort-source-use span small,.report-page-cohort-taxonomy .cohort-source-use>aside>p{font-size:9pt}.report-page-cohort-taxonomy .cohort-source-use>aside{margin-top:2mm;padding-top:2mm}.report-page-cohort-taxonomy .chart-footnote{margin-top:2.5mm;font-size:9pt}
.report-page-community .exhibit{display:flex;flex-direction:column}.report-page-capability-market .exhibit{display:grid;grid-template-rows:auto minmax(0,1fr)}.report-page-community .community-composition-layout{grid-template-columns:minmax(0,1.06fr) minmax(0,.94fr);gap:6mm}.report-page-community .community-career-evidence{gap:2mm}.report-page-community .application-career-stage{padding:4mm}.report-page-community .application-career-stage header h3,.report-page-community .taxonomy-panel header h3{font-size:12pt}.report-page-community .application-career-stage header p,.report-page-community .taxonomy-panel header p{font-size:9pt}.report-page-community .application-career-stage .composition-track{height:8mm;margin:3mm 0 2mm}.report-page-community .application-career-stage li{padding:1.5mm 0}.report-page-community .taxonomy-panel{padding:3.5mm}.report-page-community .taxonomy-cell{padding:1.5mm}.report-page-community .community-career-evidence .taxonomy-cell{padding:1.1mm 1.5mm}.report-page-community .taxonomy-cell span strong,.report-page-community .taxonomy-cell span small{font-size:9pt}.report-page-community .career-source-note{grid-template-columns:43mm minmax(0,1fr);gap:5mm;margin-top:3mm;padding:2.5mm 0}.report-page-community .category-model-base span small{display:none}.report-page-community .career-source-note p{font-size:10pt}
.report-page-capability-market .capability-market-layout{gap:4mm}.report-page-capability-market .capability-pair{grid-template-columns:repeat(2,minmax(0,1fr));gap:6mm}.report-page-capability-market .taxonomy-panel{padding:3.5mm}.report-page-capability-market .taxonomy-panel header h3,.report-page-capability-market .market-domain-strip>header h3{font-size:12pt}.report-page-capability-market .taxonomy-panel header p,.report-page-capability-market .market-domain-strip>header p{font-size:9pt}.report-page-capability-market .taxonomy-cell{padding:1.5mm}.report-page-capability-market .taxonomy-cell span strong,.report-page-capability-market .taxonomy-cell span small{font-size:9pt}.report-page-capability-market .market-domain-strip{grid-template-columns:43mm minmax(0,1fr);gap:5mm;padding-top:3mm}.report-page-capability-market .market-domain-strip>.taxonomy-panel{padding:0}.report-page-capability-market .market-domain-strip>.taxonomy-panel ol{grid-template-columns:repeat(3,minmax(0,1fr));gap:0 4mm}
.report-page-methodology{padding-top:7mm;padding-bottom:7mm}.report-page-methodology .exhibit-head{margin-bottom:3mm}.report-page-methodology .exhibit-head h2{font-size:21pt}.report-page-methodology .methodology-grid{grid-template-columns:minmax(0,1.45fr) minmax(0,.55fr);gap:6mm}.report-page-methodology .methodology-grid h3,.report-page-methodology .methodology-coverage h3{margin-bottom:1.5mm;font-size:11pt}.report-page-methodology .definition-list{gap:0 4mm}.report-page-methodology .definition-list div{padding:1.1mm 0}.report-page-methodology .definition-list dt{font-size:10pt}.report-page-methodology .definition-list dd{font-size:9.5pt;line-height:1.3}.report-page-methodology .methodology-coverage{margin-top:2.5mm;padding-top:2mm}.report-page-methodology .methodology-coverage ul{gap:4mm}.report-page-methodology .methodology-coverage li span,.report-page-methodology .methodology-coverage p{font-size:9pt}.report-page-methodology .methodology-coverage li strong{font-size:10pt}.report-page-methodology .method-summary{margin-top:2.5mm;padding-top:2mm;font-size:9pt}.report-page-methodology .report-note{position:static;display:grid;grid-template-columns:22mm minmax(0,1fr);gap:1mm 4mm;margin-top:2.5mm;padding:2mm 0 0;font-size:9pt}.report-page-methodology .report-note p,.report-page-methodology .report-note>strong,.report-page-methodology .report-footer{font-size:9pt}.report-page-methodology .report-note p{max-width:none;margin:0}.report-page-methodology .report-footer{grid-column:1/-1;margin-top:1mm;padding-top:1mm}
.report-page-methodology .definition-list dd{font-size:9.5pt}
.report-page-methodology .report-note{font-size:9pt}
.report-page-methodology .method-summary{margin-top:1.5mm;padding-top:1mm}
.report-page-methodology .report-note{display:none!important}
.report-page-evidence-boundary .exhibit{display:grid;grid-template-rows:auto minmax(0,1fr);align-content:start}.report-page-evidence-boundary .methodology-coverage{margin-top:0;padding-top:0;border-top:0}.report-page-evidence-boundary .methodology-coverage h3{font-size:13pt}.report-page-evidence-boundary .method-summary{margin:2mm 0 4mm;padding:0;font-size:10pt}.report-page-evidence-boundary .methodology-coverage ul{grid-template-columns:repeat(4,minmax(0,1fr));gap:4mm}.report-page-evidence-boundary .methodology-coverage li{grid-template-rows:auto auto 2mm auto;padding:4mm}.report-page-evidence-boundary .methodology-coverage li span,.report-page-evidence-boundary .methodology-coverage li small{font-size:9.5pt}.report-page-evidence-boundary .methodology-coverage li strong{font-size:15pt}.report-page-evidence-boundary .source-boundary-notes{gap:8mm;margin-top:6mm;padding-top:4mm}.report-page-evidence-boundary .source-boundary-notes strong{font-size:10.5pt}.report-page-evidence-boundary .source-boundary-notes p{font-size:9pt}
.report-page-cross-dimension .exhibit{display:grid;grid-template-rows:auto minmax(0,1fr)}.report-page-cross-dimension .upset-static-layout{grid-template-columns:minmax(0,1.55fr) 58mm;gap:7mm}.report-page-cross-dimension .upset-static-note{margin-bottom:3mm;font-size:9.5pt}.report-page-cross-dimension .upset-static-signals article{padding:2.5mm}.report-page-cross-dimension .upset-static-signals span{font-size:8.5pt}.report-page-cross-dimension .upset-static-signals strong{font-size:9.5pt}.report-page-cross-dimension .upset-column-key{grid-template-columns:34mm minmax(0,1fr) 9mm 12mm;gap:2.5mm;padding:1.5mm 2mm}.report-page-cross-dimension .upset-column-key,.report-page-cross-dimension .upset-column-key>strong,.report-page-cross-dimension .upset-column-key>small,.report-page-cross-dimension .upset-set-key b{font-size:8pt}.report-page-cross-dimension .upset-static-row{grid-template-columns:34mm minmax(0,1fr) 9mm 12mm;gap:2.5mm;min-height:11mm;padding:1.5mm 2mm}.report-page-cross-dimension .upset-static-row .upset-region-bar{min-height:6mm}.report-page-cross-dimension .upset-static-row .upset-region-bar b{font-size:8.5pt}.report-page-cross-dimension .upset-static-row>strong,.report-page-cross-dimension .upset-static-row>small{font-size:9pt}.report-page-cross-dimension .upset-static-unknowns{margin-top:2mm;font-size:8.5pt}.report-page-cross-dimension .upset-static-aside{gap:4mm}.report-page-cross-dimension .upset-static-aside article{gap:1mm;padding:3mm 0}.report-page-cross-dimension .upset-static-aside article>span{font-size:8pt}.report-page-cross-dimension .upset-static-aside article>strong{font-size:10pt}.report-page-cross-dimension .upset-static-aside article>b{font-size:15pt}.report-page-cross-dimension .upset-static-aside article>p{font-size:8.5pt;line-height:1.4}
.report-page-cross-dimension .upset-column-key{grid-template-columns:42mm minmax(0,1fr) 9mm 12mm}.report-page-cross-dimension .upset-static-row{grid-template-columns:42mm minmax(0,1fr) 9mm 12mm}.report-page-cross-dimension .upset-set-key{column-gap:1.5mm}.report-page-cross-dimension .upset-set-key span{font-size:8.5pt}
.report-page-taxonomy .semantic-evidence-compact li strong{font-size:9pt}
.report-page-cohort-taxonomy .cohort-source-use{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:0 4mm;margin-top:2mm}.report-page-cohort-taxonomy .cohort-source-use>header{grid-column:1/-1;padding:1.5mm 0}.report-page-cohort-taxonomy .cohort-source-use>div{display:grid;grid-column:1/-1;grid-template-columns:repeat(auto-fit,minmax(0,1fr));gap:1mm;background:transparent}.report-page-cohort-taxonomy .cohort-source-use article{padding:.8mm}.report-page-cohort-taxonomy .cohort-source-use article>div{margin-top:.6mm}.report-page-cohort-taxonomy .cohort-source-use>aside{margin:0;padding:.7mm 0}.report-page-cohort-taxonomy .cohort-source-use>aside:nth-of-type(even){padding-left:4mm;border-left:1px solid var(--rule)}.report-page-cohort-taxonomy .cohort-source-use>aside:not(.cohort-source-zero){display:grid;grid-template-columns:38mm minmax(0,1fr);gap:3mm;align-items:start}.report-page-cohort-taxonomy .cohort-source-zero{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:0 3mm;align-items:start}.report-page-cohort-taxonomy .cohort-source-zero>p{margin:0;text-align:right}.report-page-cohort-taxonomy .cohort-source-zero>div{grid-column:1/-1}.report-page-cohort-taxonomy .cohort-source-use>aside>div{gap:2mm;margin-top:.7mm}.report-page-cohort-taxonomy .chart-footnote{margin-top:.8mm}
.report-page p,.report-page small,.report-page span,.report-page li,.report-page dt,.report-page dd,.report-page strong,.report-page b{font-size:10pt}.report-page-journey .applicant-composition li,.report-page-journey .applicant-composition header span,.report-page-journey .operational-evidence header span,.report-page-journey .operational-evidence li span{font-size:10pt}.report-page-community .application-career-stage header p,.report-page-community .taxonomy-panel header p,.report-page-community .taxonomy-cell span strong,.report-page-community .taxonomy-cell span small,.report-page-community .career-source-note p{font-size:10pt}.report-page-capability-market .taxonomy-panel header p,.report-page-capability-market .market-domain-strip>header p,.report-page-capability-market .taxonomy-cell span strong,.report-page-capability-market .taxonomy-cell span small{font-size:10pt}.report-page-cohort-taxonomy .cohort-evidence-notes{margin-top:2.5mm;padding-top:2mm}.report-page-cohort-taxonomy .cohort-evidence-notes p{font-size:9.5pt;line-height:1.4}.report-page-methodology .methodology-coverage .method-summary{margin:0;padding:0;border:0;line-height:1.35}
.partner-questions,.partner-dashboard,.report-reading-progress,.pdf-actions{display:none!important}
}
"""


_INTERACTION_SCRIPT = r"""
document.documentElement.classList.add('js');
const progress=document.querySelector('.report-reading-progress');
let progressFrame=0;
function updateProgress(){
  if(!progress||progressFrame)return;
  progressFrame=requestAnimationFrame(()=>{
    const root=document.documentElement;
    const range=Math.max(root.scrollHeight-root.clientHeight,1);
    const value=Math.min(1,Math.max(0,root.scrollTop/range));
    progress.style.transform='scaleX('+value+')';
    progressFrame=0;
  });
}
addEventListener('scroll',updateProgress,{passive:true});
updateProgress();
const navLinks=[...document.querySelectorAll('.report-nav a[href^="#"]')];
const observed=navLinks.map(link=>document.querySelector(link.getAttribute('href'))).filter(Boolean);
if('IntersectionObserver' in window){
  const observer=new IntersectionObserver(entries=>{
    const visible=entries.filter(entry=>entry.isIntersecting).sort((a,b)=>b.intersectionRatio-a.intersectionRatio)[0];
    if(!visible)return;
    navLinks.forEach(link=>link.setAttribute('aria-current',String(link.getAttribute('href')==='#'+visible.target.id)));
  },{rootMargin:'-20% 0px -65% 0px',threshold:[0,.25,.5]});
  observed.forEach(section=>observer.observe(section));
}
"""


_QUESTION_INTERACTION_SCRIPT = r"""
const questionButtons=[...document.querySelectorAll('[data-partner-question]')];
const questionAnswers=[...document.querySelectorAll('[data-partner-answer]')];
const targetSections=[...document.querySelectorAll('.exhibit')];
function selectQuestion(key){
  questionButtons.forEach(button=>button.setAttribute('aria-pressed',String(button.dataset.partnerQuestion===key)));
  questionAnswers.forEach(answer=>answer.classList.toggle('is-active',answer.dataset.partnerAnswer===key));
  const active=questionAnswers.find(answer=>answer.dataset.partnerAnswer===key);
  const targets=new Set((active?.dataset.targetSections||'').split(/\s+/).filter(Boolean));
  targetSections.forEach(section=>section.classList.toggle('is-question-target',targets.has(section.id)));
}
questionButtons.forEach(button=>button.addEventListener('click',()=>selectQuestion(button.dataset.partnerQuestion)));
selectQuestion(questionButtons[0]?.dataset.partnerQuestion||'overview');
"""


_DASHBOARD_INTERACTION_SCRIPT = r"""
const dashboardState=JSON.parse(document.querySelector('#partner-dashboard-state').textContent);
const cohortButtons=[...document.querySelectorAll('[data-cohort-select]')];
const dashboardChart=document.querySelector('[data-dashboard-chart]');
const dashboardInspector=document.querySelector('[data-dashboard-inspector]');
let selectedCohort=cohortButtons[0]?.dataset.cohortSelect||'all';
let selectedMetric=dashboardState.cohorts[0]?.metrics[0]?.key||'';
function dashboardText(tag,className,text){
  const node=document.createElement(tag);if(className)node.className=className;node.textContent=text;return node;
}
function dashboardMetric(metric,isSelected){
  const button=document.createElement('button');button.type='button';button.className='dashboard-metric';
  button.dataset.dashboardMetricSelect=metric.key;
  button.setAttribute('aria-pressed',String(isSelected));
  const label=document.createElement('span');
  label.append(dashboardText('strong','',metric.count===null?'Protected':String(metric.count)));
  label.append(dashboardText('small','',metric.label));
  const bar=document.createElement('i');
  const share=metric.count===null||!metric.denominator?0:Math.round(metric.count/metric.denominator*1000)/10;
  const fill=document.createElement('b');fill.style.setProperty('--metric-share',share+'%');bar.append(fill);
  bar.setAttribute('aria-hidden','true');button.append(label,bar);return button;
}
function cohortFor(key){return dashboardState.cohorts.find(item=>item.key===key);}
function metricFor(cohort,metricKey){return cohort?.metrics.find(item=>item.key===metricKey);}
function dashboardGroup(group,cohort){
  const section=document.createElement('section');section.className='dashboard-metric-group';
  section.dataset.dashboardMetricGroup=group.key;
  const header=document.createElement('header');
  header.append(dashboardText('h3','',group.label),dashboardText('p','',group.description));
  const metrics=document.createElement('div');metrics.setAttribute('role','group');
  metrics.setAttribute('aria-label',group.label);
  metrics.append(...group.metric_keys.map(key=>dashboardMetric(metricFor(cohort,key),key===selectedMetric)));
  section.append(header,metrics);return section;
}
function dashboardComparison(metricKey){
  const comparison=document.createElement('div');comparison.className='dashboard-comparison';
  comparison.dataset.dashboardComparison='';
  for(const cohort of dashboardState.cohorts){
    const metric=metricFor(cohort,metricKey);
    const count=metric?.count??null;
    const share=count===null||!cohort.denominator?0:Math.round(count/cohort.denominator*1000)/10;
    const cell=document.createElement('div');cell.className='dashboard-comparison-cell';
    const bar=document.createElement('i');bar.setAttribute('aria-hidden','true');
    const fill=document.createElement('b');fill.style.setProperty('--comparison-share',share+'%');bar.append(fill);
    cell.append(
      dashboardText('span','',cohort.label),
      dashboardText('strong','',count===null?'Protected':count+' of '+cohort.denominator),
      bar,
      dashboardText('small','',count===null?'Not publishable':Math.round(share)+'% of cohort')
    );
    comparison.append(cell);
  }
  return comparison;
}
function renderInspector(metric){
  if(!metric||!dashboardInspector)return;
  dashboardInspector.classList.add('is-updating');
  document.querySelector('[data-inspector-label]').textContent=metric.label;
  document.querySelector('[data-inspector-definition]').textContent=metric.definition;
  document.querySelector('[data-inspector-standard]').textContent=metric.evidence_standard;
  document.querySelector('[data-inspector-denominator]').textContent=metric.denominator===null?'Protected':String(metric.denominator);
  document.querySelector('[data-inspector-coverage]').textContent=metric.unknown_state.count_text+' '+metric.unknown_state.meaning;
  document.querySelector('[data-dashboard-comparison]').replaceWith(dashboardComparison(metric.key));
  requestAnimationFrame(()=>dashboardInspector.classList.remove('is-updating'));
}
function selectMetric(key){
  const cohort=cohortFor(selectedCohort);const metric=metricFor(cohort,key);
  if(!metric)return;
  selectedMetric=key;
  dashboardChart.querySelectorAll('[data-dashboard-metric-select]').forEach(button=>{
    button.setAttribute('aria-pressed',String(button.dataset.dashboardMetricSelect===selectedMetric));
  });
  renderInspector(metric);
}
function renderDashboard(){
  const cohort=cohortFor(selectedCohort);
  if(!cohort)return;
  if(!cohort.metrics.some(item=>item.key===selectedMetric))selectedMetric=cohort.metrics[0]?.key||'';
  cohortButtons.forEach(button=>button.setAttribute('aria-pressed',String(button.dataset.cohortSelect===selectedCohort)));
  document.querySelector('[data-dashboard-context]').textContent=cohort.label;
  document.querySelector('[data-dashboard-denominator]').textContent=String(cohort.denominator);
  document.querySelector('[data-dashboard-cohort-definition]').textContent=cohort.definition;
  dashboardChart.classList.remove('is-entered');
  dashboardChart.replaceChildren(...dashboardState.metric_groups.map(group=>dashboardGroup(group,cohort)));
  renderInspector(metricFor(cohort,selectedMetric));
  requestAnimationFrame(()=>dashboardChart.classList.add('is-entered'));
}
cohortButtons.forEach(button=>button.addEventListener('click',()=>{selectedCohort=button.dataset.cohortSelect;renderDashboard();}));
function wireChoiceGroup(buttons){
  buttons.forEach((button,index)=>{
    button.tabIndex=index===0?0:-1;
    button.addEventListener('keydown',event=>{
      if(!['ArrowLeft','ArrowRight'].includes(event.key))return;
      event.preventDefault();
      const delta=event.key==='ArrowRight'?1:-1;
      const target=buttons[(index+delta+buttons.length)%buttons.length];
      buttons.forEach(item=>item.tabIndex=item===target?0:-1);target.focus();target.click();
    });
  });
}
wireChoiceGroup(cohortButtons);
dashboardChart.addEventListener('click',event=>{
  const button=event.target.closest('[data-dashboard-metric-select]');
  if(button&&dashboardChart.contains(button))selectMetric(button.dataset.dashboardMetricSelect);
});
dashboardChart.addEventListener('focus',event=>{
  const button=event.target.closest('[data-dashboard-metric-select]');
  if(button&&dashboardChart.contains(button))selectMetric(button.dataset.dashboardMetricSelect);
},true);
renderDashboard();
"""


_OVERLAP_INTERACTION_SCRIPT = r"""
const overlapButtons=[...document.querySelectorAll('[data-overlap-region]')];
function selectOverlap(button){
  if(!button)return;
  overlapButtons.forEach(item=>item.setAttribute('aria-pressed',String(item===button)));
  document.querySelector('[data-overlap-inspector-label]').textContent=button.dataset.overlapLabel+' · '+button.dataset.overlapCount;
  document.querySelector('[data-overlap-inspector-copy]').textContent=button.dataset.overlapCopy;
}
overlapButtons.forEach(button=>{
  button.addEventListener('click',()=>selectOverlap(button));
  button.addEventListener('focus',()=>selectOverlap(button));
});
"""


def render_partner_talent_report(
    report: TalentIntelligenceContract,
    event_report: TalentReportContract,
    *,
    semantic_summary: PartnerSemanticSummary | None = None,
    semantic_cohorts: PartnerSemanticCohortBundle | None = None,
    semantic_context: Mapping[str, object] | None = None,
    presentation: PartnerReportPresentation | None = None,
) -> str:
    """Render one self-contained report from parity-checked aggregate contracts."""
    _assert_contract_parity(report, event_report)
    dashboard_state = None
    if semantic_cohorts is not None:
        from community_os.partner_semantic_projection import (
            validate_partner_semantic_cohort_bundle,
        )

        validated_cohorts = validate_partner_semantic_cohort_bundle(
            semantic_cohorts,
        )
        cohort_summary = validated_cohorts.cohorts[0].summary
        if semantic_summary is None:
            semantic_summary = cohort_summary
        elif semantic_summary.aggregate_sha256 != cohort_summary.aggregate_sha256:
            raise ValueError("semantic cohort bundle does not match report summary")
    if semantic_summary is not None:
        from community_os.partner_semantic_projection import (
            validate_partner_semantic_release_context,
        )

        if semantic_context is None:
            raise ValueError("semantic release context is required")
        validate_partner_semantic_release_context(
            semantic_summary, semantic_context,
        )
        if semantic_summary.event_key != report.metadata.event_key:
            raise ValueError("semantic event does not match report event")
        applicant_count = _stage_count(
            report, ("valid_applicants", "applicants", "applied"),
        )
        if (
            applicant_count is None
            or applicant_count.value is None
            or semantic_summary.total_population != applicant_count.value
        ):
            raise ValueError("semantic population does not match report population")
        presentation = presentation or build_default_partner_report_presentation(
            semantic_summary,
        )
        validate_partner_report_presentation(
            presentation, semantic_summary=semantic_summary,
        )
        if semantic_cohorts is not None:
            dashboard_state = build_partner_dashboard_state(
                semantic_cohorts,
                presentation=presentation,
            )
    elif presentation is not None or semantic_cohorts is not None:
        raise ValueError("partner presentation requires semantic evidence")
    static_overlap = (
        _published_overlap_static(report) if semantic_summary is not None else ""
    )
    screen_overlap = (
        _published_overlap_explorer(report) if semantic_summary is not None else ""
    )
    if semantic_summary is None:
        nav_links = (
            '<a href="#journey">Demand and participation</a>'
            '<a href="#talent">Capabilities</a>'
            '<a href="#career-background">Career context</a>'
            '<a href="#builder-evidence">Building together</a>'
            '<a href="#domains">Domains</a>'
            '<a href="#methodology">Definitions</a>'
        )
    else:
        nav_links = (
            '<a href="#journey">Demand and participation</a>'
            '<a href="#project-landscape">Project evidence</a>'
            '<a href="#career-context">Community composition</a>'
            '<a href="#capability-context">Capabilities and domains</a>'
            '<a href="#evidence-boundary">Evidence coverage</a>'
            '<a href="#methodology">Method and definitions</a>'
        )
    nav = (
        '<nav class="report-nav" aria-label="Report sections">'
        f'<strong>Partner talent brief</strong>{nav_links}</nav>'
    )
    if semantic_summary is None:
        body = (
            _report_page(
                2, _journey(report, event_report), layout="evidence",
                decision_key="demand-participation",
                decision_question="How much demand converted into participation?",
            )
            + _report_page(
                3, _talent(report) + _career(report), layout="pair",
                decision_key="talent-capability",
                decision_question="Which capabilities and career contexts are represented?",
            )
            + _report_page(
                4,
                _builder_evidence(report, event_report) + _domains(report),
                layout="pair",
                decision_key="builder-evidence",
                decision_question="What have applicants actually built?",
            )
        )
    else:
        body = (
            _report_page(
                2,
                _journey(report, event_report),
                layout="journey",
                decision_key="demand-participation",
                decision_question="How much demand converted into participation?",
            )
            + _report_page(
                3,
                _project_landscape(
                    semantic_summary,
                    cohort_bundle=(
                        validated_cohorts if semantic_cohorts is not None else None
                    ),
                ),
                layout=(
                    "cohort-taxonomy" if semantic_cohorts is not None else "taxonomy"
                ),
                decision_key="project-evidence",
                decision_question="What have applicants actually built?",
            )
            + _report_page(
                4,
                _community_composition(report, semantic_summary),
                layout="community",
                decision_key="community-composition",
                decision_question="Who is represented in the applicant community?",
            )
        )
        if static_overlap:
            body += _report_page(
                5,
                static_overlap,
                layout="cross-dimension",
                decision_key="cross-dimensional-evidence",
                decision_question=(
                    "Where do role, technical function, and shipped-product "
                    "evidence intersect?"
                ),
            )
        body += _report_page(
            6 if static_overlap else 5,
            _capability_market_context(
                semantic_summary,
                number="05" if static_overlap else "04",
            ),
            layout="capability-market",
            decision_key="capability-market",
            decision_question="Which capabilities and market contexts are represented?",
        )
    if semantic_summary is not None:
        body += _report_page(
            7 if static_overlap else 6,
            _evidence_boundary(
                semantic_summary,
                number="06" if static_overlap else "05",
            ),
            layout="evidence-boundary",
            decision_key="evidence-boundary",
            decision_question="What evidence was available for this release?",
        )
    methodology_page = (
        8 if static_overlap else 7 if semantic_summary is not None else 5
    )
    body += _report_page(
        methodology_page,
        _methodology(
            report, semantic_summary,
            number=(
                "07" if static_overlap
                else "06" if semantic_summary is not None
                else "05"
            ),
        ),
        layout="methodology",
        decision_key="interpretation",
        decision_question="How should partners interpret the evidence?",
    )
    questions = ""
    if dashboard_state is not None:
        questions = _partner_dashboard(dashboard_state, report)
    elif semantic_summary is not None and presentation is not None:
        questions = _partner_questions(semantic_summary, presentation)
        if screen_overlap:
            questions += (
                '<section class="partner-dashboard partner-overlap-only">'
                + screen_overlap + '</section>'
            )
    progress = (
        '<div class="report-reading-progress" aria-hidden="true"></div>'
        if semantic_summary is not None else ""
    )
    script = ""
    if semantic_summary is not None:
        script = f'<script>{_INTERACTION_SCRIPT}</script>'
    if dashboard_state is None and questions:
        script += f'<script>{_QUESTION_INTERACTION_SCRIPT}</script>'
    if screen_overlap:
        script += f'<script>{_OVERLAP_INTERACTION_SCRIPT}</script>'
    if dashboard_state is not None:
        dashboard_json = json.dumps(
            dashboard_state,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).replace("<", "\\u003c")
        script = (
            '<script id="partner-dashboard-state" type="application/json">'
            + dashboard_json
            + '</script><script>' + _DASHBOARD_INTERACTION_SCRIPT + '</script>'
            + script
        )
    return (
        '<!doctype html>\n<html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">'
        '<link rel="icon" href="data:,">'
        f'<title>Partner talent brief | {escape(report.metadata.event_name)}</title>'
        f'<style>{_CSS}</style></head><body>{progress}<a class="skip" href="#report">Skip to report</a>'
        f'{_cover(report, event_report, semantic_summary, presentation)}{questions}'
        f'<div class="report-shell">{nav}<main id="report">{body}</main></div>{script}</body></html>'
    )
