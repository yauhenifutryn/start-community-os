"""Self-contained audience briefs for a validated talent-intelligence contract."""

from __future__ import annotations

from html import escape
import json
from pathlib import Path
from urllib.parse import quote

from community_os.talent_intelligence_contract import (
    CountValue,
    Dimension,
    DimensionItem,
    TalentIntelligenceContract,
)


def _script_json(value: object) -> str:
    return (
        json.dumps(value, separators=(",", ":"))
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("&", "\\u0026")
    )


def _logo_data_uri() -> str:
    asset = Path(__file__).resolve().parents[1] / "assets/brand/start-warsaw-white.svg"
    return "data:image/svg+xml," + quote(
        asset.read_text(encoding="utf-8"), safe="/,:;=()"
    )


def _count(value: CountValue) -> str:
    return str(value.value) if value.value is not None else "Not shown to protect privacy"


def _rate(value: CountValue, denominator: int) -> str:
    if value.value is None or denominator == 0:
        return "Not shown to protect privacy"
    return f"{round(value.value / denominator * 100)}%"


def _dimension(report: TalentIntelligenceContract, key: str) -> Dimension:
    return next(item for item in report.dimensions if item.key == key)


def _item(report: TalentIntelligenceContract, dimension_key: str, item_key: str) -> DimensionItem:
    dimension = _dimension(report, dimension_key)
    return next(item for item in dimension.items if item.key == item_key)


def _intersection(report: TalentIntelligenceContract, key: str):
    return next(item for item in report.intersections if item.key == key)


def _optional_intersection_finding(
    report: TalentIntelligenceContract, key: str, *, present_label: str,
    pending_label: str,
) -> str:
    item = next((value for value in report.intersections if value.key == key), None)
    if item is None:
        return f"{pending_label} pending or unknown"
    return f"{_count(item.count)} {present_label}"


def _table(caption: str, headings: tuple[str, ...], rows: list[tuple[str, ...]]) -> str:
    head = "".join(f'<th scope="col">{escape(item)}</th>' for item in headings)
    body = "".join(
        "<tr>" + "".join(
            f'<{("th scope=\"row\"" if index == 0 else "td")}>{escape(cell)}</{("th" if index == 0 else "td")}>'
            for index, cell in enumerate(row)
        ) + "</tr>"
        for row in rows
    )
    return (
        '<details class="table-fallback"><summary>Open evidence table</summary>'
        '<div class="table-scroll">'
        f'<table><caption>{escape(caption)}</caption><thead><tr>{head}</tr></thead>'
        f'<tbody>{body}</tbody></table></div></details>'
    )


def _funnel(report: TalentIntelligenceContract) -> str:
    denominator = report.cohort.denominator.value or 0
    cards = []
    rows = []
    stages = report.cohort.stages
    for index, stage in enumerate(stages):
        value = stage.count.value
        terminal = index + 1 == len(stages)
        next_value = stages[index + 1].count.value if not terminal else None
        share = f"{value / denominator * 100:.1f}%" if value is not None and denominator else None
        if value is None:
            dots = '<span class="stage-private">Protected value</span>'
            state = "withheld"
        elif terminal:
            dots = '<i class="cohort-dot terminal"></i>' * value
            state = "published"
        elif next_value is None:
            dots = '<i class="cohort-dot unknown"></i>' * value
            state = "protected-next-stage"
        else:
            dots = "".join(
                f'<i class="cohort-dot {"advanced" if dot < next_value else "stopped"}"></i>'
                for dot in range(value)
            )
            state = "published"
        style = f' style="--stage-share:{share}"' if share is not None else ""
        cards.append(
            f'<li class="funnel-step" data-stage-key="{escape(stage.key)}" '
            f'data-volume-state="{state}"{style}>'
            '<div class="funnel-copy">'
            f'<span>{stage.order:02d}</span><b>{escape(stage.label)}</b>'
            f'<strong>{escape(_count(stage.count))}</strong>'
            f'<small>{escape(_rate(stage.count, denominator))} of valid applicants</small></div>'
            '<div class="funnel-visual"><span class="stage-meter" aria-hidden="true"><i></i></span>'
            f'<span class="stage-dots" aria-hidden="true">{dots}</span></div>'
            '</li>'
        )
        rows.append((stage.label, _count(stage.count), _rate(stage.count, denominator)))
    outcome_segments = []
    outcome_legend = []
    selection_rows = [
        (
            item.label,
            _count(item.count),
            _rate(item.count, denominator),
            item.reason_state.replace("_", " ").title(),
        )
        for item in report.selection_outcomes.categories
    ]
    for item in report.selection_outcomes.categories:
        value = item.count.value
        share = f"{value / denominator * 100:.1f}%" if value is not None and denominator else None
        if item.reason_state == "unknown":
            tone = "unknown"
        elif item.key in {"accepted", "going_accepted", "approved"}:
            tone = "accepted"
        elif "waitlist" in item.key or "held" in item.key:
            tone = "held"
        elif "withdraw" in item.key or "declined" in item.key:
            tone = "withdrawn"
        else:
            tone = "neutral"
        if share is not None:
            outcome_segments.append(
                f'<i class="outcome-segment outcome-{tone}" '
                f'style="--outcome-share:{share}" title="{escape(item.label)}: {escape(_count(item.count))} people"></i>'
            )
        outcome_legend.append(
            f'<li class="outcome-key outcome-{tone}"><span>{escape(item.label)}</span>'
            f'<strong>{escape(_count(item.count))}</strong><small>{escape(_rate(item.count, denominator))}</small></li>'
        )
    return (
        '<div class="section-head"><div><p class="kicker">Applicant funnel</p>'
        '<h2>Who applied, who entered, and what remains unknown</h2></div>'
        f'<p class="scope">Primary denominator: {denominator} valid applicants. '
        'The current source does not prove capacity exclusion, so unknown selection reasons stay unknown.</p></div>'
        '<p class="funnel-encoding">Each square represents one applicant. Burgundy reached the next recorded stage; '
        'gray did not. Hatched marks mean the next-stage split is protected, and navy marks a published terminal stage.</p>'
        '<ol class="funnel" data-volume-funnel="cohort" '
        'aria-label="Volume-adjusted applicant funnel in people">' + "".join(cards) + '</ol>'
        '<section class="selection-volume" data-outcome-split="selection" aria-labelledby="selection-volume-title">'
        '<div class="selection-volume-head"><h3 id="selection-volume-title">Selection outcome volume</h3>'
        '<p>Widths are shares of valid applicants. Unknown remains an explicit evidence state.</p></div>'
        '<div class="outcome-track" aria-hidden="true">' + "".join(outcome_segments) + '</div>'
        '<ol class="outcome-legend">' + "".join(outcome_legend) + '</ol></section>'
        '<div class="paired-tables">'
        + _table("Applicant funnel", ("Stage", "People", "Share"), rows)
        + _table(
            "Selection outcomes",
            ("Outcome", "People", "Share", "Reason evidence"),
            selection_rows,
        )
        + '</div>'
    )


def _dimension_block(
    report: TalentIntelligenceContract,
    key: str,
    title: str,
    description: str,
    *,
    item_keys: tuple[str, ...] | None = None,
) -> str:
    dimension = _dimension(report, key)
    denominator = report.cohort.denominator.value or 0
    if item_keys is None:
        items = tuple(sorted(
            dimension.items,
            key=lambda item: (item.count.value is None, -(item.count.value or 0), item.label),
        ))
    else:
        by_key = {item.key: item for item in dimension.items}
        items = tuple(by_key[item_key] for item_key in item_keys if item_key in by_key)
    missing = (
        tuple(item_key for item_key in item_keys if item_key not in by_key)
        if item_keys is not None
        else ()
    )
    bars = []
    segments = []
    rows = []
    for item in items:
        width = round((item.count.value or 0) / denominator * 100) if denominator else 0
        state = item.count.reason or ", ".join(item.evidence_sources)
        bars.append(
            '<li class="bar-row lollipop-row">'
            f'<div><strong>{escape(item.label)}</strong><span>{escape(item.definition)}</span></div>'
            f'<i aria-hidden="true"><b style="width:{width}%"></b></i>'
            f'<em>{escape(_count(item.count))}<small>{escape(_rate(item.count, denominator))}</small></em>'
            '</li>'
        )
        if item.count.value is not None:
            segments.append(
                f'<span style="--size:{width}%" title="{escape(item.label)}: '
                f'{escape(_count(item.count))} people"><i></i></span>'
            )
        rows.append((item.label, _count(item.count), _rate(item.count, denominator), state))
    mode_note = (
        "Categories are mutually exclusive."
        if dimension.mode == "exclusive"
        else "Categories overlap; shares do not sum to 100%."
    )
    pending = ""
    if missing:
        labels = ", ".join(item.replace("_", " ").capitalize() for item in missing)
        pending = (
            '<p class="scope pending-evidence"><strong>Unavailable enrichment-dependent '
            'categories are pending or unknown:</strong> '
            f'{escape(labels)}.</p>'
        )
    chart = (
        '<div class="composition-stack" aria-label="' + escape(title) + '">'
        + "".join(segments) + '</div><ul class="composition-legend bars">'
        + "".join(bars) + '</ul>'
        if dimension.mode == "exclusive"
        else '<ul class="bars lollipop-list" aria-label="' + escape(title) + '">' + "".join(bars) + '</ul>'
    )
    return (
        '<div class="section-head"><div><p class="kicker">Evidence distribution</p>'
        f'<h2>{escape(title)}</h2></div><p class="scope">{escape(description)} '
        f'{escape(mode_note)} Denominator: {denominator} valid applicants.</p></div>'
        + pending
        + chart
        + _table(
            f"{title} evidence",
            ("Category", "People", "Share", "Evidence or privacy state"),
            rows,
        )
    )


def _intersections_block(report: TalentIntelligenceContract, title: str) -> str:
    denominator = report.cohort.denominator.value or 0
    rows = []
    cards = []
    ordered = sorted(
        report.intersections,
        key=lambda item: (item.count.value is None, -(item.count.value or 0), item.label),
    )
    for item in ordered:
        sources = ", ".join(item.evidence_sources)
        value = item.count.value
        share = f"{value / denominator * 100:.1f}%" if value is not None and denominator else None
        style = f' style="--intersection-share:{share}"' if share is not None else ""
        cards.append(
            f'<article class="intersection"{style}>'
            f'<span>{escape(_rate(item.count, denominator))} of applicants</span>'
            f'<strong>{escape(_count(item.count))}</strong><h3>{escape(item.label)}</h3>'
            '<span class="intersection-meter" aria-hidden="true"><i></i></span>'
            f'<p>Evidence: {escape(sources)}</p></article>'
        )
        rows.append((item.label, _count(item.count), _rate(item.count, denominator), sources))
    return (
        '<div class="section-head"><div><p class="kicker">Privacy-safe intersections</p>'
        f'<h2>{escape(title)}</h2></div><p class="scope">Each segment is bounded by every component population. '
        'No person-level profile can be opened from this report.</p></div>'
        f'<div class="intersection-grid" style="--intersection-columns:{max(1, min(len(cards), 5))}">' + "".join(cards) + '</div>'
        + _table(
            "Talent intersections",
            ("Segment", "People", "Share", "Evidence"),
            rows,
        )
    )


def _themes(report: TalentIntelligenceContract) -> str:
    rows = []
    items = []
    for theme in report.qualitative_themes:
        items.append(
            '<article class="theme">'
            f'<span>{escape(theme.confidence.title())} confidence</span>'
            f'<h3>{escape(theme.label)}</h3><p>{escape(theme.statement)}</p>'
            f'<strong>{escape(_count(theme.count))}</strong>'
            f'<small>{escape(theme.count.reason or ", ".join(theme.evidence_sources))}</small>'
            '</article>'
        )
        rows.append((
            theme.label,
            _count(theme.count),
            theme.statement,
            theme.count.reason or theme.review_state,
        ))
    scope = (
        "Synthetic statements demonstrate the approved editorial form. "
        "Distinctive or small-group facts remain withheld."
        if report.metadata.synthetic
        else "Reviewed aggregate statements come from the validated contract. "
        "Distinctive or small-group facts remain withheld."
    )
    return (
        '<div class="section-head"><div><p class="kicker">Aggregate qualitative themes</p>'
        '<h2>Interesting evidence, generalized before publication</h2></div>'
        f'<p class="scope">{escape(scope)}</p></div>'
        f'<div class="theme-list" style="--theme-columns:{max(1, min(len(items), 2))}">' + "".join(items) + '</div>'
        + _table(
            "Aggregate qualitative themes",
            ("Theme", "People", "Statement", "Review or privacy state"),
            rows,
        )
    )


def _coverage(report: TalentIntelligenceContract) -> str:
    rows = []
    items = []
    for item in report.evidence_coverage:
        eligible = item.eligible.value or 0
        rate = _rate(item.covered, eligible)
        items.append(
            '<li>'
            f'<div><strong>{escape(item.label)}</strong><span>{escape(item.note)}</span></div>'
            f'<b>{escape(_count(item.covered))} / {escape(_count(item.eligible))}</b>'
            f'<em class="state state-{escape(item.state)}">{escape(item.state)}</em>'
            '</li>'
        )
        rows.append((item.label, _count(item.eligible), _count(item.covered), rate, item.state, item.note))
    return (
        '<div class="section-head"><div><p class="kicker">Coverage and readiness</p>'
        '<h2>Evidence coverage</h2></div><p class="scope">Coverage is reported separately from talent counts. '
        'A missing source never becomes a negative talent classification.</p></div>'
        '<ul class="coverage">' + "".join(items) + '</ul>'
        + _table(
            "Evidence-source coverage",
            ("Source", "Eligible", "Covered", "Coverage", "State", "Note"),
            rows,
        )
    )


def _readiness(report: TalentIntelligenceContract) -> str:
    readiness = "".join(
        '<li>'
        f'<strong>{escape(item.component.replace("_", " ").title())}</strong>'
        f'<span>{escape(item.note)}</span><em class="state state-{escape(item.state)}">{escape(item.state)}</em>'
        '</li>'
        for item in report.readiness
    )
    gate = next(item for item in report.feature_gates if item.feature == "gated_talent_appendix")
    sources = "".join(
        f'<li><strong>{escape(item.source.replace("_", " ").title())}</strong>'
        f'<span>{escape(item.note)}</span><em class="state state-{escape(item.state)}">{escape(item.state)}</em></li>'
        for item in report.source_notes
    )
    return (
        '<div class="readiness-grid"><div><h3>Publication readiness</h3><ul>' + readiness + '</ul></div>'
        '<div><h3>Source state</h3><ul>' + sources + '</ul></div></div>'
        '<aside class="gate"><strong>Named talent appendix remains disabled</strong>'
        f'<p>{escape(gate.note)}</p><span>{escape(gate.state)}</span></aside>'
    )


def _analytics_config(key: str | None, host: str) -> str:
    if not key:
        return "null"
    return _script_json({
        "key": key,
        "host": host.rstrip("/"),
        "persistence": "memory",
        "autocapture": False,
        "disable_session_recording": True,
    })


def _audience_config(report: TalentIntelligenceContract, audience: str) -> dict[str, object]:
    if audience == "vc":
        return {
            "label": "VC talent brief",
            "title": "Founder access, backed by evidence",
            "dek": "An anonymized view of founder density, senior technical builders, startup pedigree, investable domains, and demonstrated shipping across the full applicant pool.",
            "findings": (
                (f'{_count(_item(report, "professional_identity", "founder_cofounder").count)} founders or co-founders', "Professional identity"),
                (
                    _optional_intersection_finding(
                        report,
                        "senior_technical_builders",
                        present_label="senior technical builders",
                        pending_label="Senior technical-builder intersection",
                    ),
                    "Evidence intersection",
                ),
            ),
            "sections": (
                ("founders", "Founder and operator composition", "professional_identity", ("founder_cofounder", "startup_operator", "venture_backed_startup", "independent_builder", "flagship_technology_company"), "Professional identities can overlap and remain evidence-scoped."),
                ("density", "Senior technical-builder density", "intersections", None, "The most decision-useful evidence is in intersections, not an opaque score."),
                ("pedigree", "Employer and startup pedigree", "employer_pedigree", None, "Employers are grouped through a reviewed taxonomy; names are not published."),
                ("domains", "Investable domains", "domains", None, "Domain evidence is classified from available application and project sources."),
                ("shipping", "Shipping evidence", "builder_evidence", ("shipped_product", "active_github", "founded_company", "startup_operating", "technical_leadership", "traction_evidence"), "Hackathon output is supporting evidence, not the talent thesis."),
            ),
        }
    return {
        "label": "Company talent brief",
        "title": "Experienced technical talent, mapped to hiring decisions",
        "dek": "An anonymized view of seniority, functional roles, technical capabilities, employer pedigree, and demonstrated shipping across the full applicant pool.",
        "findings": (
            (
                f'{_count(_item(report, "seniority", "senior").count)} senior applicants and '
                f'{_count(_item(report, "seniority", "lead_staff_executive").count)} lead, staff, principal, or executive applicants',
                "Seniority",
            ),
            (f'{_count(_item(report, "functional_role", "engineering").count)} applicants with engineering evidence', "Functional role"),
        ),
        "sections": (
            ("roles", "Seniority and functional roles", "roles", None, "Seniority is exclusive; functional roles may overlap."),
            ("capabilities", "Capabilities you can recruit", "capabilities", None, "Capabilities are evidence-backed and may overlap."),
            ("pedigree", "Employer pedigree", "employer_pedigree", None, "Employers are grouped through a reviewed taxonomy; names are not published."),
            ("shipping", "Demonstrated builder evidence", "builder_evidence", ("shipped_product", "active_github", "open_source", "technical_leadership", "traction_evidence", "hackathon_submission"), "Evidence describes demonstrated activity, not a composite score."),
            ("domains", "Domain experience", "domains", None, "Domain evidence is classified from available application and project sources."),
        ),
    }


def render_talent_intelligence_brief(
    report: TalentIntelligenceContract,
    *,
    audience: str,
    posthog_key: str | None = None,
    posthog_host: str = "https://eu.i.posthog.com",
) -> str:
    """Render a static-first VC or company brief from one validated contract."""
    if audience not in {"vc", "company"}:
        raise ValueError("audience must be vc or company")
    config = _audience_config(report, audience)
    denominator = report.cohort.denominator.value or 0
    sections = []
    for section_id, title, kind, item_keys, description in config["sections"]:
        if kind == "intersections":
            content = _intersections_block(report, title)
        elif kind == "roles":
            content = (
                _dimension_block(report, "seniority", title, description)
                + '<div class="subsection">'
                + _dimension_block(
                    report,
                    "functional_role",
                    "Functional roles",
                    "A person may contribute across more than one function.",
                )
                + '</div>'
            )
        else:
            content = _dimension_block(
                report,
                kind,
                title,
                description,
                item_keys=item_keys,
            )
        sections.append(
            f'<section class="section" id="{escape(section_id)}" data-section="{escape(section_id)}">{content}</section>'
        )
    findings = "".join(
        f'<article><strong>{escape(finding)}</strong><span>{escape(source)}</span></article>'
        for finding, source in config["findings"]
    )
    nav = "".join(
        f'<a href="#{escape(section_id)}">{escape(title)}</a>'
        for section_id, title, *_ in config["sections"]
    )
    synthetic_label = "Illustrative synthetic data" if report.metadata.synthetic else "Validated aggregate evidence"
    methodology_data_note = (
        "This fixture is synthetic and must not be represented as observed cohort evidence."
        if report.metadata.synthetic
        else "Missing enrichment remains pending or unknown and is not treated as negative evidence."
    )
    synthetic_flag = (
        f'<div class="synthetic-flag">{escape(synthetic_label)} · '
        "Do not distribute as observed event evidence</div>"
        if report.metadata.synthetic
        else ""
    )
    analytics = _analytics_config(posthog_key, posthog_host)
    logo = _logo_data_uri()
    return f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"><title>{escape(str(config["label"]))} | {escape(report.metadata.event_name)}</title><link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'%3E%3Crect width='64' height='64' fill='%2300002c'/%3E%3Cpath d='M14 48 29 16h7l14 32h-9l-3-8H25l-3 8h-8Zm14-15h7l-3.5-9L28 33Z' fill='%23fcfbf7'/%3E%3C/svg%3E">
<style>
:root{{--navy:#00002c;--burgundy:#80011f;--paper:#fcfbf7;--surface:#fffefd;--ink:#171729;--muted:#5d5d6e;--rule:#d5d4db;--focus:#d8a7b4;--tint:#fff5f7;--success:#187447;--warn:#735000;--font:AvenirLTNextPro,"Avenir Next",Avenir,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;--ease:cubic-bezier(.16,1,.3,1)}}
*{{box-sizing:border-box}}html{{scroll-behavior:smooth;background:var(--paper)}}body{{margin:0;color:var(--ink);background:var(--paper);font:16px/1.55 var(--font)}}a{{color:inherit}}a:focus-visible,button:focus-visible,summary:focus-visible{{outline:3px solid var(--focus);outline-offset:3px}}.skip{{position:fixed;left:-999px;top:14px;z-index:30;padding:10px 14px;background:var(--surface)}}.skip:focus{{left:14px}}.progress{{position:fixed;z-index:25;inset:0 auto auto 0;width:100%;height:3px;transform:scaleX(0);transform-origin:left;background:var(--burgundy)}}
.cover{{min-height:88vh;padding:32px max(40px,6vw);display:grid;grid-template-rows:auto 1fr auto;color:var(--paper);background:var(--navy)}}.brand{{width:174px;height:82px;object-fit:contain;object-position:left center}}.cover-copy{{align-self:center;max-width:1180px}}.eyebrow,.kicker{{margin:0 0 16px;color:var(--burgundy);font-size:.69rem;font-weight:850;letter-spacing:.16em;text-transform:uppercase}}.cover .eyebrow{{color:#d8a7b4}}h1{{max-width:15ch;margin:0;font-size:clamp(3rem,6vw,6.2rem);font-weight:900;letter-spacing:-.06em;line-height:.9}}.dek{{max-width:72ch;margin:22px 0 30px;color:#d3d2dd;font-size:1.08rem}}.findings{{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));max-width:1050px;border-top:1px solid #4b4b67}}.findings article{{padding:20px 24px 8px 0}}.findings strong,.findings span{{display:block}}.findings strong{{max-width:24ch;font-size:clamp(1.25rem,2.2vw,2rem);line-height:1.1}}.findings span{{margin-top:7px;color:#b8b7c7;font-size:.72rem;letter-spacing:.1em;text-transform:uppercase}}.cover-meta{{display:flex;gap:24px;justify-content:space-between;padding-top:15px;border-top:1px solid #4b4b67;color:#c7c6d1;font-size:.76rem}}.cover-meta b{{color:var(--paper)}}
.shell{{display:grid;grid-template-columns:240px minmax(0,1fr)}}nav{{position:sticky;top:0;align-self:start;height:100vh;padding:36px 24px;border-right:1px solid var(--rule)}}nav strong{{display:block;margin-bottom:20px;color:var(--navy);font-size:.75rem;letter-spacing:.12em;text-transform:uppercase}}nav a{{display:block;padding:7px 0;color:var(--muted);font-size:.8rem;text-decoration:none}}nav a:hover,nav a[aria-current=true]{{color:var(--burgundy)}}main{{min-width:0}}.section{{padding:82px max(40px,6vw);border-bottom:1px solid var(--rule)}}.section:nth-child(even){{background:var(--surface)}}.section-head{{display:grid;grid-template-columns:minmax(0,1fr) minmax(220px,.7fr);gap:44px;align-items:end;margin-bottom:34px}}h2{{max-width:18ch;margin:0;color:var(--navy);font-size:clamp(2.2rem,4vw,4.5rem);font-weight:900;letter-spacing:-.05em;line-height:.96}}.scope{{margin:0;padding-top:12px;border-top:1px solid var(--navy);color:var(--muted);font-size:.8rem}}.subsection{{margin-top:72px;padding-top:56px;border-top:1px solid var(--rule)}}
.funnel-encoding{{max-width:76ch;margin:0 0 20px;color:var(--muted);font-size:.8rem}}.funnel{{display:grid;gap:8px;margin:0 0 30px;padding:0;list-style:none}}.funnel-step{{display:grid;grid-template-columns:minmax(150px,.35fr) minmax(0,1fr);gap:22px;align-items:center;min-width:0;padding:16px 18px;border:1px solid var(--rule);background:var(--surface)}}.funnel-copy{{display:grid;grid-template-columns:1fr auto;gap:4px 14px;align-items:baseline}}.funnel-copy span,.funnel-copy strong,.funnel-copy b,.funnel-copy small{{display:block}}.funnel-copy span{{grid-column:1/-1;color:var(--burgundy);font-size:.68rem;font-weight:850}}.funnel-copy b{{color:var(--navy);font-size:.9rem}}.funnel-copy strong{{color:var(--navy);font-size:2rem;line-height:1}}.funnel-copy small{{grid-column:1/-1;color:var(--muted);font-size:.7rem}}.funnel-visual{{display:grid;gap:11px;min-width:0}}.stage-meter{{display:block;height:7px;background:#ecebef}}.stage-meter>i{{display:block;width:var(--stage-share);height:100%;background:var(--burgundy)}}.stage-dots{{display:flex;width:var(--stage-share);min-height:17px;flex-wrap:wrap;gap:3px;align-content:center}}.cohort-dot{{display:block;width:5px;height:5px;flex:0 0 5px;background:var(--rule)}}.cohort-dot.advanced{{background:var(--burgundy)}}.cohort-dot.terminal{{background:var(--navy)}}.cohort-dot.unknown{{border:1px solid var(--muted);background:repeating-linear-gradient(135deg,transparent 0,transparent 2px,var(--muted) 2px,var(--muted) 3px)}}.stage-private{{display:block;width:100%;min-height:17px;border:1px solid var(--rule);background:repeating-linear-gradient(135deg,#f2f1f3 0,#f2f1f3 5px,#e7e6e9 5px,#e7e6e9 6px);color:transparent;font-size:0}}.funnel-step[data-volume-state=withheld] .stage-meter>i{{display:none}}.selection-volume{{margin:0 0 44px;padding:22px;border:1px solid var(--rule);background:var(--surface)}}.selection-volume-head{{display:flex;justify-content:space-between;gap:24px;align-items:baseline}}.selection-volume h3{{margin:0;color:var(--navy);font-size:1rem}}.selection-volume p{{max-width:58ch;margin:0;color:var(--muted);font-size:.75rem}}.outcome-track{{display:flex;height:18px;margin:18px 0 14px;background:#ecebef;overflow:hidden}}.outcome-segment{{display:block;width:var(--outcome-share);height:100%}}.outcome-legend{{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:1px;margin:0;padding:0;background:var(--rule);list-style:none}}.outcome-key{{display:grid;grid-template-columns:10px minmax(0,1fr) auto;gap:8px;align-items:center;padding:10px;background:var(--surface);font-size:.75rem}}.outcome-key::before{{width:8px;height:8px;content:""}}.outcome-key small{{grid-column:3;color:var(--muted)}}.outcome-segment.outcome-accepted,.outcome-key.outcome-accepted::before{{background:#a0012a}}.outcome-segment.outcome-held,.outcome-key.outcome-held::before{{background:#9a6b00}}.outcome-segment.outcome-unknown,.outcome-key.outcome-unknown::before{{background:#757483}}.outcome-segment.outcome-withdrawn,.outcome-key.outcome-withdrawn::before{{background:#6d4fa8}}.outcome-segment.outcome-neutral,.outcome-key.outcome-neutral::before{{background:#2f5fc4}}.paired-tables{{display:grid;grid-template-columns:1fr 1fr;gap:40px}}
.composition-stack{{display:flex;width:100%;height:22px;margin:0 0 20px;overflow:hidden;background:#ecebef}}.composition-stack>span{{display:block;width:var(--size);height:100%;border-right:2px solid var(--surface);background:var(--burgundy)}}.composition-stack>span:nth-child(2n){{background:var(--navy)}}.composition-stack>span:nth-child(3n){{background:#a85a70}}.bars{{margin:0 0 34px;padding:0;border-top:1px solid var(--navy);list-style:none}}.bar-row{{display:grid;grid-template-columns:minmax(220px,1.35fr) minmax(180px,1fr) 88px;gap:22px;align-items:center;padding:16px 0;border-bottom:1px solid var(--rule)}}.bar-row strong,.bar-row span,.bar-row em,.bar-row small{{display:block}}.bar-row span{{max-width:58ch;color:var(--muted);font-size:.77rem}}.bar-row>i{{height:12px;background:#ecebef}}.bar-row>i b{{display:block;height:100%;background:var(--burgundy)}}.lollipop-row>i{{position:relative;height:2px;background:var(--rule)}}.lollipop-row>i b{{position:relative;height:2px}}.lollipop-row>i b::after{{position:absolute;top:50%;right:-6px;width:12px;height:12px;border-radius:50%;background:var(--burgundy);content:"";transform:translateY(-50%)}}.composition-legend .bar-row>i{{display:none}}.composition-legend .bar-row{{grid-template-columns:minmax(220px,1fr) 88px}}.bar-row em{{font-style:normal;text-align:right;font-size:1.1rem;font-weight:850}}.bar-row small{{color:var(--muted);font-size:.7rem;font-weight:500}}.intersection-grid{{display:grid;grid-template-columns:repeat(var(--intersection-columns),1fr);gap:1px;margin-bottom:34px;background:var(--rule)}}.intersection{{min-width:0;padding:24px;background:var(--surface)}}.intersection>span:first-child{{color:var(--burgundy);font-size:.68rem;font-weight:850;text-transform:uppercase}}.intersection strong{{display:block;margin:22px 0 8px;color:var(--navy);font-size:2.6rem;line-height:1}}.intersection h3{{margin:0;font-size:.98rem;line-height:1.2}}.intersection-meter{{display:block;height:8px;margin-top:18px;background:#ecebef}}.intersection-meter i{{display:block;width:var(--intersection-share);height:100%;background:var(--burgundy)}}.intersection p{{color:var(--muted);font-size:.72rem}}
.table-fallback{{border-top:1px solid var(--rule)}}details.table-fallback>summary{{padding:14px 0;color:var(--burgundy);font-size:.72rem;font-weight:850;cursor:pointer;text-transform:uppercase}}.table-scroll{{max-width:100%;overflow-x:auto}}table{{width:100%;border-collapse:collapse;font-size:.8rem}}caption{{padding:12px 0;color:var(--muted);text-align:left}}th,td{{padding:10px;border-bottom:1px solid var(--rule);text-align:left;vertical-align:top}}thead th{{color:var(--burgundy);font-size:.67rem;letter-spacing:.08em;text-transform:uppercase}}.theme-list{{display:grid;grid-template-columns:repeat(var(--theme-columns),1fr);gap:1px;margin-bottom:34px;background:var(--rule)}}.theme{{padding:28px;background:var(--surface)}}.theme span{{color:var(--burgundy);font-size:.67rem;font-weight:850;text-transform:uppercase}}.theme h3{{margin:14px 0 6px;color:var(--navy);font-size:1.35rem}}.theme p{{max-width:54ch;color:var(--muted)}}.theme strong{{font-size:1.7rem}}.theme small{{display:block;color:var(--muted)}}
.coverage,.readiness-grid ul{{margin:0 0 34px;padding:0;border-top:1px solid var(--navy);list-style:none}}.coverage li,.readiness-grid li{{display:grid;grid-template-columns:minmax(200px,1fr) auto auto;gap:18px;align-items:center;padding:16px 0;border-bottom:1px solid var(--rule)}}.coverage strong,.coverage span,.readiness-grid strong,.readiness-grid span{{display:block}}.coverage span,.readiness-grid span{{color:var(--muted);font-size:.78rem}}.coverage b{{color:var(--navy)}}.state{{width:max-content;padding:5px 8px;font-size:.65rem;font-style:normal;font-weight:850;letter-spacing:.06em;text-transform:uppercase}}.state-ready,.state-validated,.state-schema_reference{{color:var(--success);background:#e8f4ed}}.state-partial,.state-pending{{color:var(--warn);background:#fff4cc}}.state-off,.state-disabled{{color:var(--muted);background:#ecebef}}.readiness-grid{{display:grid;grid-template-columns:1fr 1fr;gap:48px}}.readiness-grid h3{{color:var(--navy)}}.gate{{display:grid;grid-template-columns:1fr auto;gap:4px 24px;margin:34px 0;padding:24px;border:1px solid var(--rule);background:var(--tint)}}.gate strong{{color:var(--navy);font-size:1.15rem}}.gate p{{grid-column:1;margin:0;color:var(--muted)}}.gate span{{grid-row:1/3;grid-column:2;align-self:center;color:var(--burgundy);font-size:.7rem;font-weight:850;text-transform:uppercase}}details.methodology{{max-width:960px;border-top:1px solid var(--navy)}}details.methodology summary{{padding:18px 0;color:var(--navy);font-weight:850;cursor:pointer}}details.methodology p{{max-width:74ch;color:var(--muted)}}.print-button{{margin-top:24px;padding:12px 16px;border:0;color:var(--paper);background:var(--burgundy);font-weight:850;cursor:pointer}}.synthetic-flag{{position:sticky;z-index:20;bottom:0;padding:10px 24px;color:var(--paper);background:var(--burgundy);font-size:.7rem;font-weight:850;letter-spacing:.09em;text-align:center;text-transform:uppercase}}footer{{padding:32px 40px;color:#c6c5d0;background:var(--navy);font-size:.75rem}}
@media(max-width:900px){{.cover{{min-height:92vh;padding:24px}}.findings,.section-head,.paired-tables,.theme-list,.readiness-grid{{grid-template-columns:1fr}}.findings article{{padding-right:0}}.shell{{display:block}}nav{{display:none}}.section{{min-width:0;padding:64px 24px}}.bar-row{{grid-template-columns:1fr 72px}}.bar-row>i{{grid-column:1/-1;grid-row:2}}.bar-row em{{grid-column:2;grid-row:1}}.intersection-grid{{grid-template-columns:1fr 1fr}}.cover-meta{{display:grid;grid-template-columns:1fr 1fr}}.paired-tables{{gap:28px}}.readiness-grid>div{{min-width:0}}.readiness-grid li{{grid-template-columns:minmax(0,1fr) auto}}.readiness-grid li>strong,.readiness-grid li>span{{grid-column:1}}.readiness-grid li>em{{grid-column:2;grid-row:1/3}}}}
@media(max-width:560px){{.funnel-step{{grid-template-columns:1fr;gap:14px;padding:15px}}.stage-dots{{width:100%}}.selection-volume{{padding:16px}}.selection-volume-head{{display:grid;gap:6px}}.outcome-legend{{grid-template-columns:1fr}}.intersection-grid{{grid-template-columns:1fr}}.intersection,.intersection *{{min-width:0;overflow-wrap:anywhere}}}}
@media (prefers-reduced-motion:reduce){{html{{scroll-behavior:auto}}*,*::before,*::after{{animation:none!important;transition:none!important}}}}
@page{{size:A4;margin:14mm 13mm 15mm}}@media print{{html,body{{background:white;font-size:9pt}}.cover{{min-height:257mm;padding:18mm 12mm;break-after:page}}.cover h1{{font-size:50pt}}.shell{{display:block}}nav,.progress,.print-button,.synthetic-flag{{display:none!important}}.section{{padding:8mm 0;background:white!important;break-before:page;border:0}}.section-head{{margin-bottom:6mm}}h2{{font-size:24pt}}.funnel,.selection-volume{{break-inside:avoid}}.funnel-step{{grid-template-columns:33mm minmax(0,1fr);gap:3mm;padding:2.5mm}}.funnel-copy strong{{font-size:18pt}}.cohort-dot{{width:3px;height:3px;flex-basis:3px}}.stage-dots{{gap:2px}}.selection-volume{{padding:3mm}}.outcome-legend{{grid-template-columns:repeat(2,minmax(0,1fr))}}.paired-tables,.readiness-grid{{grid-template-columns:1fr 1fr;gap:7mm}}.intersection-grid{{grid-template-columns:repeat(var(--intersection-columns),1fr);break-inside:avoid}}.intersection{{padding:3mm}}.intersection strong{{font-size:20pt}}.theme-list,.coverage,.readiness-grid,.gate,.table-scroll,table{{break-inside:avoid}}.bars{{break-inside:auto}}.bar-row{{padding:2mm 0;break-inside:avoid}}details.table-fallback>summary{{display:none}}details.table-fallback:not([open])>.table-scroll{{display:block!important}}.table-scroll{{overflow:visible}}.theme-list{{grid-template-columns:repeat(var(--theme-columns),1fr)}}table{{font-size:7pt}}th,td{{padding:1.6mm}}#methodology{{padding-top:4mm}}#methodology .section-head{{margin-bottom:3mm}}#methodology .readiness-grid{{gap:4mm}}#methodology .readiness-grid li{{padding:1.2mm 0}}#methodology .readiness-grid ul{{margin-bottom:3mm}}#methodology .gate{{margin:3mm 0;padding:3mm}}#methodology details.methodology summary{{padding:3mm 0}}#methodology details.methodology p{{margin:2mm 0;font-size:7.5pt;line-height:1.35}}footer{{display:none}}}}
</style></head><body><a class="skip" href="#report">Skip to report</a><div class="progress" data-progress></div>
<header class="cover"><img class="brand" src="{logo}" alt="START Warsaw"><div class="cover-copy"><p class="eyebrow">{escape(str(config["label"]))} · {escape(synthetic_label)}</p><h1>{escape(str(config["title"]))}</h1><p class="dek">{escape(str(config["dek"]))}</p><div class="findings">{findings}</div></div><div class="cover-meta"><span>Event <b>{escape(report.metadata.event_name)}</b></span><span>Primary cohort <b>{denominator} valid applicants</b></span><span>Evidence state <b>{escape(report.privacy.state.replace("_", " ").title())}</b></span><span>Contract <b>{escape(report.metadata.contract_version)}</b></span></div></header>
<div class="shell"><nav aria-label="Report sections"><strong>{escape(str(config["label"]))}</strong><a href="#funnel">Applicant funnel</a>{nav}<a href="#themes">Qualitative themes</a><a href="#coverage">Evidence coverage</a><a href="#methodology">Methodology and privacy</a></nav><main id="report">
<section class="section" id="funnel" data-section="funnel">{_funnel(report)}</section>{''.join(sections)}
<section class="section" id="themes" data-section="themes">{_themes(report)}</section>
<section class="section" id="coverage" data-section="coverage">{_coverage(report)}</section>
<section class="section" id="methodology" data-section="methodology"><div class="section-head"><div><p class="kicker">Audit trail</p><h2>Methodology and privacy</h2></div><p class="scope">Generated {escape(report.metadata.generated_at)}. Publication state: {escape(report.metadata.publication_state)}.</p></div>{_readiness(report)}<details class="methodology" open data-methodology><summary>Definitions and publication rules</summary><p>The renderer consumes only the validated aggregate contract. Published non-zero cells meet k={report.privacy.minimum_count}; smaller groups are withheld. Professional identity, roles, capabilities, domains, and builder evidence may overlap. Seniority and employer pedigree are exclusive distributions with explicit unknown categories.</p><p>All applicant classifications retain evidence-source references in the internal model. The forwardable briefs contain no names, contact details, profile links, named employers, source filenames, or person-level biographies. {escape(methodology_data_note)}</p></details><button class="print-button" type="button" data-print>Print report</button></section></main></div>
{synthetic_flag}<footer>START Warsaw · {escape(str(config["label"]))} · {escape(report.metadata.contract_version)}</footer>
<script>window.talentBriefAnalytics={analytics};
(()=>{{const allowed=new Set(['report_opened','section_viewed','methodology_opened','report_completed','print_requested']);const send=(event,properties={{}})=>{{const cfg=window.talentBriefAnalytics;if(!cfg||!allowed.has(event))return;const body=JSON.stringify({{api_key:cfg.key,event,properties:{{report_version:{_script_json(report.metadata.contract_version)},event_key:{_script_json(report.metadata.event_key)},audience:{_script_json(audience)},...properties}}}});navigator.sendBeacon?.(cfg.host+'/capture/',new Blob([body],{{type:'application/json'}}))||fetch(cfg.host+'/capture/',{{method:'POST',mode:'no-cors',keepalive:true,headers:{{'content-type':'application/json'}},body}})}};send('report_opened');const sections=[...document.querySelectorAll('[data-section]')],seen=new Set();if('IntersectionObserver'in window){{const observer=new IntersectionObserver(entries=>entries.forEach(entry=>{{if(!entry.isIntersecting)return;const key=entry.target.dataset.section;document.querySelectorAll('nav a').forEach(link=>link.setAttribute('aria-current',String(link.hash==='#'+entry.target.id)));if(!seen.has(key)){{seen.add(key);send('section_viewed',{{section_key:key}})}}if(key==='methodology')send('report_completed')}}),{{rootMargin:'-25% 0px -60%'}});sections.forEach(section=>observer.observe(section))}}document.querySelector('[data-methodology]')?.addEventListener('toggle',event=>event.target.open&&send('methodology_opened',{{section_key:'methodology'}}));document.querySelector('[data-print]')?.addEventListener('click',()=>{{send('print_requested');print()}});const progress=document.querySelector('[data-progress]');addEventListener('scroll',()=>{{const range=document.documentElement.scrollHeight-innerHeight;progress.style.transform=`scaleX(${{range?scrollY/range:0}})`}},{{passive:true}})}})();</script></body></html>'''
