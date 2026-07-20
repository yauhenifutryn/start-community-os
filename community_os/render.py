"""Render a forwardable, interactive, and print-ready talent briefing."""

from __future__ import annotations

from html import escape
import json

from community_os.report import ReportData, ReportSlice
from community_os.report_contract import TalentReportContract
from community_os.talent_intelligence_contract import TalentIntelligenceContract


def _share(count: int, total: int) -> int:
    return round((count / total) * 100) if total else 0


def _script_json(value: object) -> str:
    """Serialize data for a script element without permitting tag termination."""
    return json.dumps(value).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")


def _empty_state(label: str) -> str:
    return (
        '<div class="empty-state"><span>Awaiting classified data</span>'
        f'<p>{escape(label)} will populate automatically when the validated source fields are available.</p></div>'
    )


def _stage_markup(data: ReportData) -> str:
    blocks: list[str] = []
    rows: list[str] = []
    previous: int | None = None
    first_detail = ""
    for index, stage in enumerate(data.stages):
        if stage.count is None:
            value = "Withheld"
            conversion = "Privacy threshold applies"
            dots = '<span class="unit-dot withheld"></span>'
        else:
            value = str(stage.count)
            conversion = (
                "Baseline" if previous is None
                else f"{_share(stage.count, previous)}% from prior stage"
            )
            has_next = index + 1 < len(data.stages)
            next_count = data.stages[index + 1].count if has_next else stage.count
            if has_next and next_count is None:
                dots = '<span class="unit-dot withheld"></span>' * stage.count
            else:
                advanced = next_count if isinstance(next_count, int) else stage.count
                dots = "".join(
                    '<span class="unit-dot advanced"></span>' if dot < advanced
                    else '<span class="unit-dot stopped"></span>'
                    for dot in range(stage.count)
                )
            previous = stage.count
        terminal = index + 1 >= len(data.stages)
        if stage.count is None:
            advanced_text = "Withheld"
            stopped_text = "Withheld"
        elif terminal:
            advanced_text = ""
            stopped_text = ""
        elif data.stages[index + 1].count is None:
            advanced_text = "Withheld"
            stopped_text = "Withheld"
        else:
            advanced_text = str(data.stages[index + 1].count)
            stopped_text = str(stage.count - data.stages[index + 1].count)
        detail = (
            f"{stage.label}: {value} reached the terminal stage. {conversion}."
            if terminal
            else f"{stage.label}: {value} reached this stage; {advanced_text} advanced; "
            f"{stopped_text} stopped or is withheld. {conversion}."
        )
        if index == 0:
            first_detail = detail
        blocks.append(
            '<button class="funnel-step reveal" type="button" '
            f'data-funnel-stage="{index}" data-stage-detail="{escape(detail)}" '
            f'aria-controls="funnel-detail" aria-pressed="{"true" if index == 0 else "false"}" '
            f'style="--order:{index}" disabled>'
            f'<span class="funnel-value">{escape(value)}</span>'
            f'<span class="funnel-label">{escape(stage.label)}</span>'
            f'<span class="dot-field" aria-hidden="true">{dots}</span>'
            f'<span class="funnel-note">{escape(conversion)}</span></button>'
        )
        rows.append(
            f'<tr><th scope="row">{escape(stage.label)}</th><td>{escape(value)}</td>'
            f'<td>{escape(stage.withheld_reason or conversion)}</td></tr>'
        )
    return '<div class="funnel">' + "".join(blocks) + "</div>" + (
        f'<div class="funnel-detail interactive-only" id="funnel-detail" data-funnel-detail '
        f'aria-live="polite">{escape(first_detail)}</div>'
        '<details class="data-table"><summary>View as table</summary><table><thead>'
        '<tr><th>Stage</th><th>People</th><th>Conversion</th></tr></thead><tbody>'
        + "".join(rows) + "</tbody></table></details>"
    )


def _slice_chart(
    slices: tuple[ReportSlice, ...], *, total: int, chart_key: str,
) -> str:
    rows: list[str] = []
    table_rows: list[str] = []
    for item in slices:
        share = _share(item.count, total)
        rows.append(
            '<div class="bar-row reveal">'
            f'<div class="bar-copy"><strong>{escape(item.label)}</strong>'
            f'<span>{escape(item.note)}</span></div>'
            '<div class="bar-track" aria-hidden="true">'
            f'<i style="--bar:{share}%"></i></div>'
            f'<div class="bar-value"><span class="value-count">{item.count}</span>'
            f'<span class="value-separator"> · </span><span class="value-share">{share}%</span></div>'
            '</div>'
        )
        table_rows.append(
            f'<tr><th scope="row">{escape(item.label)}</th><td>{item.count}</td>'
            f'<td>{share}%</td><td>{escape(item.note)}</td></tr>'
        )
    controls = (
        '<div class="chart-controls enhancement" role="group" '
        f'aria-label="{escape(chart_key.title())} chart value display">'
        '<button type="button" data-chart-mode="people" aria-pressed="true">People</button>'
        '<button type="button" data-chart-mode="share" aria-pressed="false">Share</button></div>'
    )
    table = (
        '<details class="data-table"><summary>View as table</summary><table><thead><tr>'
        '<th>Category</th><th>People</th><th>Share</th><th>Definition</th>'
        '</tr></thead><tbody>' + "".join(table_rows) + '</tbody></table></details>'
    )
    return (
        f'<div class="chart-view" data-chart-view="{escape(chart_key)}" data-display="people">'
        + controls + '<div class="bar-chart">' + "".join(rows) + "</div>" + table + '</div>'
    )


def _trend_chart(data: ReportData) -> str:
    if not data.trends:
        return _empty_state("Cross-event applications and submission trends")
    width, height, pad = 720, 260, 42
    maximum = max(point.applications for point in data.trends)
    step = (width - pad * 2) / max(1, len(data.trends) - 1)
    def coordinates(field: str) -> list[tuple[float, float]]:
        return [
            (pad + index * step, height - pad - (getattr(point, field) / maximum) * (height - pad * 2))
            for index, point in enumerate(data.trends)
        ]
    applications = coordinates("applications")
    submissions = coordinates("submissions")
    def points(values: list[tuple[float, float]]) -> str:
        return " ".join(f"{x:.1f},{y:.1f}" for x, y in values)
    labels = "".join(
        f'<text x="{x:.1f}" y="244" text-anchor="middle">{escape(point.label)}</text>'
        for point, (x, _) in zip(data.trends, applications)
    )
    marks = "".join(
        f'<circle class="series-app" cx="{x:.1f}" cy="{y:.1f}" r="4"></circle>'
        for x, y in applications
    ) + "".join(
        f'<circle class="series-submit" cx="{x:.1f}" cy="{y:.1f}" r="4"></circle>'
        for x, y in submissions
    )
    rows = "".join(
        f'<tr><th scope="row">{escape(point.label)}</th><td>{point.applications}</td><td>{point.submissions}</td></tr>'
        for point in data.trends
    )
    event_buttons: list[str] = []
    previous_rate: int | None = None
    for index, point in enumerate(data.trends):
        rate = _share(point.submissions, point.applications)
        delta = "Baseline" if previous_rate is None else f"{rate - previous_rate:+d} pp vs prior"
        event_buttons.append(
            '<button type="button" class="trend-event" '
            f'data-trend-event="{index}" data-trend-detail="{escape(point.label)}: '
            f'{point.applications} applications, {point.submissions} submissions, '
            f'{rate}% submission rate, {escape(delta)}" '
            f'aria-controls="trend-detail" aria-pressed="{"true" if index == len(data.trends) - 1 else "false"}" disabled>'
            f'<span>{escape(point.label)}</span><strong>{rate}%</strong></button>'
        )
        previous_rate = rate
    latest = data.trends[-1]
    latest_rate = _share(latest.submissions, latest.applications)
    prior_rate = _share(data.trends[-2].submissions, data.trends[-2].applications) if len(data.trends) > 1 else latest_rate
    latest_delta = (
        f"{latest_rate - prior_rate:+d} pp vs prior"
        if len(data.trends) > 1 else "Baseline"
    )
    latest_detail = (
        f"{latest.label}: {latest.applications} applications, {latest.submissions} submissions, "
        f"{latest_rate}% submission rate, {latest_delta}."
    )
    return (
        '<div class="trend-legend"><span><i class="legend-app"></i>Applications</span>'
        '<span><i class="legend-submit"></i>Submissions</span></div>'
        '<svg class="trend-chart reveal" viewBox="0 0 720 260" role="img" '
        'aria-label="Applications and submissions across three illustrative events">'
        '<line class="axis" x1="42" y1="218" x2="678" y2="218"></line>'
        f'<polyline class="series-app" points="{points(applications)}"></polyline>'
        f'<polyline class="series-submit" points="{points(submissions)}"></polyline>{marks}{labels}</svg>'
        '<details class="data-table"><summary>View as table</summary><table><thead><tr>'
        '<th>Event</th><th>Applications</th><th>Submissions</th></tr></thead><tbody>'
        f'{rows}</tbody></table></details>'
        f'<div class="trend-events interactive-only">{"".join(event_buttons)}</div>'
        f'<div class="trend-detail interactive-only" id="trend-detail" data-trend-detail '
        f'aria-live="polite"><span>Submission rate</span><p>{escape(latest_detail)}</p></div>'
    )


def _readout(data: ReportData) -> str:
    items = []
    targets = {
        "builder evidence": ("signals", "03"),
        "participation quality": ("funnel", "01"),
        "partner relevance": ("composition", "02"),
    }
    for index, finding in enumerate(data.executive_readout, start=1):
        target = targets.get(finding.label.casefold())
        link = (
            f'<a href="#{target[0]}" data-evidence-target="{target[0]}">'
            f'View exhibit {target[1]}</a>'
            if target else ""
        )
        items.append(
            '<article class="finding reveal">'
            f'<div class="finding-index">0{index}</div><div><p class="finding-label">'
            f'{escape(finding.label)}</p><h3>{escape(finding.statement)}</h3>'
            f'<p>{escape(finding.evidence)}</p>{link}</div></article>'
        )
    return "".join(items)


def _readiness(data: ReportData) -> str:
    if data.readiness:
        items = data.readiness
    else:
        from community_os.report import ReadinessItem

        items = (
            ReadinessItem("Luma export", "Schema validated", "ready"),
            ReadinessItem("Devpost export", "Awaiting real file", "pending"),
            ReadinessItem("Taxonomy", data.taxonomy_status, "pending"),
            ReadinessItem("Coresignal", "Not enabled", "off"),
        )
    return "".join(
        '<div class="status-row">'
        f'<span><i class="status-dot status-{escape(item.state)}" aria-hidden="true"></i>'
        f'{escape(item.label)}</span><strong>{escape(item.status)}</strong></div>'
        for item in items
    )


def _analytics(data: ReportData, key: str | None, host: str) -> str:
    if not key:
        return ""
    props = _script_json({
        "report_version": "talent-data-room-v2",
        "partner_id": data.partner_key,
        "event_id": data.event_key,
    })
    return f"""
<script src="https://eu-assets.i.posthog.com/static/array.js"></script>
<script>
posthog.init({_script_json(key)}, {{
  api_host: {_script_json(host)},
  persistence: 'memory',
  autocapture: false,
  disable_session_recording: true,
  person_profiles: 'never',
  capture_pageview: false,
  capture_pageleave: false
}});
window.reportAnalytics = {props};
</script>"""


def render_report(
    data: ReportData | TalentReportContract | TalentIntelligenceContract, *,
    audience: str | None = None, posthog_key: str | None = None,
    posthog_host: str = "https://eu.i.posthog.com",
) -> str:
    """Return escaped HTML. Applicant-derived HTML is never interpreted."""
    if isinstance(data, TalentIntelligenceContract):
        if audience is None:
            raise ValueError("audience is required for a talent-intelligence contract")
        from community_os.talent_intelligence_renderer import render_talent_intelligence_brief

        return render_talent_intelligence_brief(
            data,
            audience=audience,
            posthog_key=posthog_key,
            posthog_host=posthog_host,
        )
    if isinstance(data, TalentReportContract):
        from community_os.report_v3_renderer import render_v3_report

        return render_v3_report(
            data, posthog_key=posthog_key, posthog_host=posthog_host,
        )
    sources = ", ".join(escape(item) for item in data.source_notes) or "No source loaded"
    analytics = _analytics(data, posthog_key, posthog_host)
    eligible_label = (
        str(data.eligible_people)
        if data.stages and data.stages[0].count is not None else "Withheld"
    )
    status = "Illustrative synthetic cohort" if data.synthetic else "Privacy-checked event report"
    cohort = _slice_chart(data.cohort_mix, total=data.eligible_people, chart_key="cohort") if data.cohort_mix else _empty_state("Occupation and affiliation composition")
    signals = _slice_chart(data.builder_signals, total=data.eligible_people, chart_key="signals") if data.builder_signals else _empty_state("Verified builder evidence")
    domains = _slice_chart(data.build_domains, total=data.eligible_people, chart_key="domains") if data.build_domains else _empty_state("Project domains and technology adoption")
    print_label = "Illustrative synthetic data" if data.synthetic else "Privacy-checked aggregate report"
    funnel_title = (
        "Accepted builders converted into active participation" if data.synthetic
        else "How eligible participation moved through the event"
    )
    composition_title = (
        "Founders and startup operators anchor the cohort" if data.cohort_mix
        else "Cohort composition awaits validated classification"
    )
    signals_title = (
        "Evidence separates verified shipping from uncorroborated claims" if data.builder_signals
        else "Builder evidence awaits validated classification"
    )
    domains_title = (
        "AI applications lead, with meaningful breadth beyond AI" if data.build_domains
        else "Build domains await validated project data"
    )
    trends_title = (
        "Participation is growing while submission volume compounds" if data.trends
        else "Longitudinal evidence awaits comparable events"
    )
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>{escape(data.event_name)} | Talent Data Room</title>
<style>
:root{{--ink:oklch(20% .025 275);--navy:oklch(20% .09 270);--navy-2:oklch(27% .08 270);--crimson:oklch(43% .17 18);--paper:oklch(99% .004 275);--canvas:oklch(96% .008 275);--soft:oklch(94% .01 275);--muted:oklch(49% .025 275);--line:oklch(87% .012 275);--ready:oklch(49% .1 155);--pending:oklch(58% .12 73);--space-xs:.25rem;--space-sm:.5rem;--space-md:1rem;--space-lg:1.5rem;--space-xl:2rem;--space-2xl:3rem;--space-3xl:4.5rem;--ease-out:cubic-bezier(.16,1,.3,1)}}
*{{box-sizing:border-box}} html{{scroll-behavior:smooth;background:var(--canvas);color-scheme:light}} body{{margin:0;background:var(--paper);color:var(--ink);font:1rem/1.55 Inter,-apple-system,BlinkMacSystemFont,"Segoe UI",system-ui,sans-serif;font-kerning:normal}} button,summary{{font:inherit}} a{{color:inherit}} .skip{{position:fixed;left:-999px;top:var(--space-md)}} .skip:focus-visible{{left:var(--space-md);z-index:20;background:var(--paper);padding:.75rem 1rem;outline:3px solid var(--crimson);outline-offset:2px}}
.reading-progress{{position:fixed;top:0;left:0;z-index:30;width:100%;height:3px;transform:scaleX(0);transform-origin:left;background:var(--crimson);pointer-events:none}}
.cover{{position:relative;overflow:hidden;background:var(--navy);color:oklch(97% .008 275);padding:var(--space-xl) var(--space-lg) var(--space-2xl)}} .cover:after{{content:"";position:absolute;right:-8rem;bottom:-10rem;width:24rem;height:24rem;border:1px solid oklch(82% .04 270 / .25);border-radius:50%;box-shadow:0 0 0 3rem oklch(82% .04 270 / .08),0 0 0 7rem oklch(82% .04 270 / .05);pointer-events:none}} .cover-top{{position:relative;z-index:1;display:flex;flex-direction:column;justify-content:space-between;gap:var(--space-md);align-items:flex-start}} .brand{{font-size:.72rem;font-weight:750;letter-spacing:.14em;text-transform:uppercase}} .report-status{{display:inline-flex;align-items:center;gap:.5rem;border:1px solid oklch(86% .04 270 / .35);padding:.45rem .7rem;font-size:.72rem;letter-spacing:.04em;white-space:nowrap}} .report-status i{{width:.4rem;height:.4rem;background:var(--crimson);border-radius:50%}} h1{{position:relative;z-index:1;margin:var(--space-3xl) 0 var(--space-md);max-width:12ch;font-size:clamp(2.65rem,8vw,5.6rem);line-height:.92;letter-spacing:-.055em;text-wrap:balance}} .cover-deck{{position:relative;z-index:1;max-width:60ch;margin:0;color:oklch(83% .025 275);font-size:1.08rem}} .cover-meta{{position:relative;z-index:1;display:grid;gap:var(--space-lg);margin-top:var(--space-3xl);padding-top:var(--space-lg);border-top:1px solid oklch(86% .03 275 / .25)}} .cover-meta strong{{display:block;margin-bottom:.2rem;color:oklch(98% .004 275);font-size:.72rem;letter-spacing:.06em;text-transform:uppercase}} .cover-meta span{{color:oklch(81% .025 275);font-variant-numeric:tabular-nums}}
.report-shell{{max-width:92rem;margin:0 auto}} .report-rail{{position:sticky;top:0;z-index:10;background:var(--paper);border-bottom:1px solid var(--line);overflow-x:auto}} .report-rail nav{{display:flex;min-width:max-content;padding:0 var(--space-md)}} .report-rail a{{position:relative;display:flex;align-items:center;min-height:3rem;padding:0 .75rem;color:var(--muted);font-size:.78rem;text-decoration:none}} .report-rail a[aria-current="true"]{{color:var(--ink);font-weight:700}} .report-rail a[aria-current="true"]:after{{content:"";position:absolute;left:.75rem;right:.75rem;bottom:0;height:2px;background:var(--crimson)}}
main{{min-width:0;padding:0 var(--space-lg)}} .report-section{{padding:var(--space-3xl) 0;border-bottom:1px solid var(--line);scroll-margin-top:4rem}} .section-kicker{{margin:0 0 var(--space-sm);color:var(--crimson);font-size:.7rem;font-weight:800;letter-spacing:.13em;text-transform:uppercase}} h2{{margin:0;max-width:24ch;font-size:2rem;line-height:1.08;letter-spacing:-.035em;text-wrap:balance}} .section-intro{{max-width:66ch;margin:var(--space-md) 0 var(--space-xl);color:var(--muted);text-wrap:pretty}} .exhibit-head{{display:flex;flex-wrap:wrap;justify-content:space-between;gap:var(--space-md);align-items:end;margin-bottom:var(--space-lg)}} .exhibit-note{{margin:0;color:var(--muted);font-size:.78rem}}
.readout-list{{border-top:1px solid var(--ink)}} .finding{{display:grid;grid-template-columns:2.5rem 1fr;gap:var(--space-md);padding:var(--space-xl) 0;border-bottom:1px solid var(--line)}} .finding-index{{padding-top:.2rem;color:var(--crimson);font-size:.72rem;font-weight:800;letter-spacing:.08em}} .finding-label{{margin:0 0 .35rem;color:var(--muted);font-size:.7rem;font-weight:750;letter-spacing:.08em;text-transform:uppercase}} .finding h3{{max-width:29ch;margin:0;font-size:1.4rem;line-height:1.18;letter-spacing:-.025em}} .finding p:last-of-type{{max-width:66ch;margin:.65rem 0 0;color:var(--muted)}} .finding a{{display:inline-flex;min-height:2.75rem;align-items:center;margin-top:.55rem;color:var(--crimson);font-size:.78rem;font-weight:750;text-decoration:none}} .finding a:hover{{text-decoration:underline}}
.funnel{{display:grid;border-top:1px solid var(--ink)}} .funnel-step{{display:block;width:100%;padding:var(--space-lg) 0;border:0;border-bottom:1px solid var(--line);background:transparent;color:var(--ink);text-align:left;cursor:pointer;transition:background-color 180ms var(--ease-out),transform 180ms var(--ease-out)}} .funnel-step:hover{{background:var(--soft)}} .funnel-step[aria-pressed="true"]{{background:oklch(96% .012 18)}} .funnel-step:focus-visible{{position:relative;z-index:1;outline:3px solid var(--crimson);outline-offset:3px}} .funnel-value,.funnel-label,.funnel-note{{display:block}} .funnel-value{{font-size:2.5rem;font-weight:760;line-height:1;font-variant-numeric:tabular-nums;letter-spacing:-.04em}} .funnel-label{{margin-top:.35rem;font-weight:700}} .dot-field{{display:grid;grid-template-columns:repeat(12,7px);gap:4px;min-height:62px;margin:var(--space-md) 0 .7rem;align-content:start}} .unit-dot{{width:7px;height:7px;border-radius:50%;background:var(--line)}} .unit-dot.advanced{{background:var(--crimson)}} .unit-dot.withheld{{outline:1px solid var(--muted);background:transparent}} .funnel-note{{color:var(--muted);font-size:.78rem}} .funnel-detail,.trend-detail{{margin-top:var(--space-lg);padding:var(--space-md) 0;border-top:1px solid var(--ink);border-bottom:1px solid var(--line);font-size:.9rem}} .trend-detail span{{color:var(--crimson);font-size:.68rem;font-weight:800;letter-spacing:.1em;text-transform:uppercase}} .trend-detail p{{margin:.35rem 0 0}}
.chart-controls{{gap:.2rem;padding:.2rem;border:1px solid var(--line);background:var(--soft)}} .enhancement{{display:none}} .js .enhancement{{display:flex}} .chart-controls button,.print-button{{min-height:2.75rem;border:0;background:transparent;color:var(--muted);padding:.5rem .8rem;cursor:pointer}} .chart-controls button[aria-pressed="true"]{{background:var(--paper);color:var(--ink);box-shadow:0 1px 2px oklch(20% .03 275 / .08)}} .chart-controls button:focus-visible,.print-button:focus-visible,summary:focus-visible,.report-rail a:focus-visible{{outline:3px solid var(--crimson);outline-offset:3px}} .print-button{{display:inline-flex;align-items:center;gap:.45rem;border:1px solid var(--line);color:var(--ink)}}
.bar-chart{{border-top:1px solid var(--ink)}} .bar-row{{display:grid;grid-template-columns:1fr auto;gap:.55rem var(--space-md);padding:var(--space-md) 0;border-bottom:1px solid var(--line)}} .bar-copy{{display:flex;flex-direction:column}} .bar-copy strong{{font-size:.92rem}} .bar-copy span{{color:var(--muted);font-size:.75rem}} .bar-track{{grid-column:1 / -1;height:.42rem;background:var(--soft);overflow:hidden}} .bar-track i{{display:block;width:var(--bar);height:100%;background:var(--navy-2);transform-origin:left}} .bar-row:first-child .bar-track i{{background:var(--crimson)}} .bar-value{{grid-row:1;color:var(--ink);font-size:.86rem;font-variant-numeric:tabular-nums}} [data-display="people"] .value-share,[data-display="people"] .value-separator{{display:none}} [data-display="share"] .value-count,[data-display="share"] .value-separator{{display:none}}
.empty-state{{padding:var(--space-xl);border:1px dashed var(--line);background:var(--soft)}} .empty-state span{{font-weight:750}} .empty-state p{{max-width:55ch;margin:.35rem 0 0;color:var(--muted)}} .trend-chart{{display:block;width:100%;height:auto;overflow:visible}} .trend-chart text{{fill:var(--muted);font:11px Inter,system-ui,sans-serif}} .trend-chart .axis{{stroke:var(--line)}} .trend-chart polyline{{fill:none;stroke-width:3;stroke-linecap:round;stroke-linejoin:round}} .trend-chart .series-app{{stroke:var(--crimson);fill:var(--crimson)}} .trend-chart .series-submit{{stroke:var(--navy-2);fill:var(--navy-2)}} .trend-legend{{display:flex;gap:var(--space-lg);margin-bottom:var(--space-md);font-size:.78rem;color:var(--muted)}} .trend-legend span{{display:flex;align-items:center;gap:.45rem}} .trend-legend i{{width:1.5rem;height:3px}} .legend-app{{background:var(--crimson)}} .legend-submit{{background:var(--navy-2)}} .trend-events{{display:grid;grid-template-columns:repeat(auto-fit,minmax(9rem,1fr));gap:1px;margin-top:var(--space-md);background:var(--line)}} .trend-event{{min-height:4rem;border:0;background:var(--paper);color:var(--muted);padding:.7rem;text-align:left;cursor:pointer}} .trend-event span,.trend-event strong{{display:block}} .trend-event strong{{color:var(--ink);font-size:1.1rem}} .trend-event[aria-pressed="true"]{{background:var(--navy);color:oklch(85% .02 275)}} .trend-event[aria-pressed="true"] strong{{color:var(--paper)}} .trend-event:focus-visible{{outline:3px solid var(--crimson);outline-offset:-3px}} .print-folio{{display:none}}
.data-table{{margin-top:var(--space-lg)}} summary{{display:inline-flex;align-items:center;min-height:2.75rem;color:var(--muted);font-size:.78rem;cursor:pointer}} table{{width:100%;border-collapse:collapse;margin-top:var(--space-sm);font-size:.8rem}} th,td{{padding:.7rem .6rem .7rem 0;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}} td{{font-variant-numeric:tabular-nums}}
.confidence-grid{{display:grid;gap:var(--space-xl)}} .status-list{{border-top:1px solid var(--ink)}} .status-row{{display:flex;justify-content:space-between;gap:var(--space-md);padding:.9rem 0;border-bottom:1px solid var(--line)}} .status-row span{{display:flex;gap:.6rem;align-items:center}} .status-row strong{{max-width:55%;text-align:right;font-size:.82rem}} .status-dot{{width:.45rem;height:.45rem;border-radius:50%;background:var(--muted)}} .status-ready{{background:var(--ready)}} .status-pending{{background:var(--pending)}} .methodology{{margin:0;border-top:1px solid var(--ink)}} .methodology summary{{width:100%;justify-content:space-between;color:var(--ink);font-weight:700}} .methodology summary:after{{content:"+";color:var(--crimson);font-size:1.2rem}} .methodology[open] summary:after{{content:"−"}} .methodology-copy{{display:grid;gap:var(--space-lg);padding:var(--space-lg) 0}} .methodology-copy p{{margin:0;color:var(--muted)}} .methodology-copy strong{{color:var(--ink)}}
footer{{padding:var(--space-xl) var(--space-lg);background:var(--soft);color:var(--muted);font-size:.75rem}} footer strong{{color:var(--ink)}} .footer-inner{{max-width:92rem;margin:auto;display:flex;flex-wrap:wrap;justify-content:space-between;gap:var(--space-md)}}
.js .reveal{{opacity:0;transform:translateY(.75rem);transition:opacity 500ms var(--ease-out),transform 500ms var(--ease-out)}} .js .reveal.is-visible{{opacity:1;transform:none}} .js .funnel-step{{transition-delay:calc(var(--order,0) * 65ms)}} .js .funnel-step .dot-field{{opacity:.15;transform:translateX(-.35rem);transition:opacity 420ms var(--ease-out),transform 420ms var(--ease-out);transition-delay:calc(var(--order,0) * 65ms + 120ms)}} .js .funnel-step.is-visible .dot-field{{opacity:1;transform:none}} .js .bar-track i{{transform:scaleX(0);transition:transform 700ms var(--ease-out)}} .js .bar-row.is-visible .bar-track i{{transform:scaleX(1)}}
@media(min-width:42rem){{.cover{{padding:var(--space-2xl) var(--space-3xl) var(--space-3xl)}} .cover-top{{flex-direction:row;align-items:center}} .cover-meta{{grid-template-columns:2fr 1fr 1fr 1fr}} main{{padding:0 var(--space-3xl)}} .funnel{{grid-template-columns:repeat(4,1fr)}} .funnel-step{{padding:var(--space-xl) var(--space-lg);border-bottom:0;border-right:1px solid var(--line)}} .funnel-step:first-child{{padding-left:0}} .funnel-step:last-child{{border-right:0;padding-right:0}} .bar-row{{grid-template-columns:minmax(14rem,1fr) minmax(14rem,2fr) 4.5rem;align-items:center}} .bar-track{{grid-column:2;grid-row:1}} .bar-value{{grid-column:3}} .confidence-grid{{grid-template-columns:1fr 1fr}}}}
@media(min-width:64rem){{.report-shell{{display:grid;grid-template-columns:13rem minmax(0,1fr)}} .report-rail{{top:0;height:100dvh;border-right:1px solid var(--line);border-bottom:0;overflow:visible}} .report-rail nav{{display:flex;flex-direction:column;min-width:0;padding:var(--space-2xl) var(--space-lg)}} .report-rail a{{min-height:2.75rem;padding:0}} .report-rail a[aria-current="true"]:after{{left:0;right:auto;bottom:.45rem;width:2rem;height:2px}} main{{padding:0 clamp(3rem,6vw,7rem)}} .report-section{{padding:6rem 0}} .readout-list{{max-width:64rem}}}}
@media(prefers-reduced-motion:reduce){{html{{scroll-behavior:auto}} *,*::before,*::after{{animation-duration:.01ms!important;transition-duration:.01ms!important}} .js .reveal{{opacity:1;transform:none}} .js .bar-track i{{transform:scaleX(1)}}}}
@media print{{@page{{size:A4;margin:12mm}} html,body{{background:var(--paper);font-size:10pt}} .screen-only,.chart-controls,.interactive-only{{display:none!important}} .print-folio{{display:block;margin-bottom:7mm;padding-bottom:2mm;border-bottom:1px solid var(--line);color:var(--muted);font-size:7pt;letter-spacing:.08em;text-transform:uppercase}} .cover{{min-height:273mm;padding:14mm;background:var(--navy)!important;print-color-adjust:exact}} .cover:after{{display:none}} h1{{font-size:42pt;margin-top:46mm}} .cover-meta{{grid-template-columns:2fr 1fr 1fr 1fr;margin-top:48mm}} .report-shell{{display:block;max-width:none}} main{{padding:0}} .report-section{{padding:12mm 4mm;break-inside:avoid;scroll-margin:0}} #funnel,#signals,#trends,#confidence{{break-before:page}} h2{{font-size:21pt}} .section-intro{{margin-bottom:6mm}} .finding{{padding:5mm 0}} .finding h3{{font-size:15pt}} .funnel{{grid-template-columns:repeat(4,1fr)}} .funnel-step{{padding:5mm 4mm;border-right:1px solid var(--line);border-bottom:0}} .dot-field{{grid-template-columns:repeat(9,5px);gap:2px;min-height:45px}} .unit-dot{{width:5px;height:5px}} .bar-row{{grid-template-columns:45mm 1fr 15mm;padding:3mm 0}} .bar-track{{grid-column:2;grid-row:1}} .bar-value{{grid-column:3}} .confidence-grid{{grid-template-columns:1fr 1fr}} details>summary{{display:none}} details:not([open])>*:not(summary){{display:block}} footer{{padding:7mm 4mm}} .js .reveal{{opacity:1;transform:none}} .js .bar-track i{{transform:scaleX(1)}}}}
</style></head><body><div class="reading-progress interactive-only" data-reading-progress aria-hidden="true"></div><a class="skip" href="#main">Skip to report</a>
<script>document.documentElement.classList.add('js')</script>
<header class="cover"><div class="cover-top"><div class="brand">START Warsaw · Community Intelligence</div><div class="report-status"><i aria-hidden="true"></i>{escape(status)}</div></div>
<h1>Talent<br>Data Room</h1><p class="cover-deck">Evidence about the builders who apply, participate, and ship through START Warsaw.</p>
<div class="cover-meta"><div><strong>Event</strong><span>{escape(data.event_name)}</span></div><div><strong>Prepared for</strong><span>{escape(data.partner_key)}</span></div><div><strong>Eligible records</strong><span>{eligible_label}</span></div><div><strong>Generated</strong><span>{escape(data.generated_at)}</span></div></div></header>
<div class="report-shell"><aside class="report-rail screen-only"><nav aria-label="Report sections"><a href="#readout" data-nav-key="readout" aria-current="true">Executive readout</a><a href="#funnel" data-nav-key="funnel">Participation</a><a href="#composition" data-nav-key="composition">Composition</a><a href="#signals" data-nav-key="signals">Builder evidence</a><a href="#domains" data-nav-key="domains">Build domains</a><a href="#trends" data-nav-key="trends">Longitudinal</a><a href="#confidence" data-nav-key="confidence">Data confidence</a></nav></aside>
<main id="main"><section class="report-section" id="readout" data-section-key="readout"><span class="print-folio">{print_label} · Executive readout</span><p class="section-kicker">Executive readout</p><h2>What a partner should know in 90 seconds</h2><p class="section-intro">Three conclusions supported by the exhibits below. Synthetic demo values are illustrative; the production report uses only privacy-checked canonical records.</p><div class="readout-list">{_readout(data) or _empty_state("Evidence-backed executive conclusions")}</div></section>
<section class="report-section" id="funnel" data-section-key="funnel"><span class="print-folio">{print_label} · Exhibit 01</span><div class="exhibit-head"><div><p class="section-kicker">Exhibit 01 · Participation funnel</p><h2>{funnel_title}</h2></div><p class="exhibit-note">Denominator: {eligible_label} eligible people</p></div><p class="section-intro">Each dot is one person. Crimson reached the next publishable stage; neutral stopped at the current stage; outlined dots mean the next-stage result is withheld. The terminal stage shows everyone who reached submission.</p>{_stage_markup(data)}</section>
<section class="report-section" id="composition" data-section-key="composition"><span class="print-folio">{print_label} · Exhibit 02</span><div class="exhibit-head"><div><p class="section-kicker">Exhibit 02 · Cohort composition</p><h2>{composition_title}</h2></div><p class="exhibit-note">Mutually exclusive taxonomy · n={eligible_label}</p></div>{cohort}</section>
<section class="report-section" id="signals" data-section-key="signals"><span class="print-folio">{print_label} · Exhibit 03</span><div class="exhibit-head"><div><p class="section-kicker">Exhibit 03 · Builder evidence</p><h2>{signals_title}</h2></div><p class="exhibit-note">Draft taxonomy · n={eligible_label}</p></div><p class="section-intro">Classification remains provisional until taxonomy approval. No real-person AI classification is enabled.</p>{signals}</section>
<section class="report-section" id="domains" data-section-key="domains"><span class="print-folio">{print_label} · Exhibit 04</span><div class="exhibit-head"><div><p class="section-kicker">Exhibit 04 · Build domains</p><h2>{domains_title}</h2></div><p class="exhibit-note">Primary project domain · n={eligible_label}</p></div>{domains}</section>
<section class="report-section" id="trends" data-section-key="trends"><span class="print-folio">{print_label} · Exhibit 05</span><div class="exhibit-head"><div><p class="section-kicker">Exhibit 05 · Longitudinal evidence</p><h2>{trends_title}</h2></div><p class="exhibit-note">{"Illustrative event series" if data.synthetic else "Comparable events only"}</p></div><p class="section-intro">The production exhibit appears only after at least two comparable, privacy-checked events.</p>{_trend_chart(data)}</section>
<section class="report-section" id="confidence" data-section-key="confidence"><span class="print-folio">{print_label} · Exhibit 06</span><div class="exhibit-head"><div><p class="section-kicker">Exhibit 06 · Data confidence</p><h2>The report distinguishes evidence from what is still pending</h2></div><button class="print-button screen-only enhancement" type="button" data-action="print" aria-label="Print or save report as PDF">Print report</button></div><div class="confidence-grid"><div class="status-list">{_readiness(data)}</div><details class="methodology" open data-methodology><summary>Methodology and privacy</summary><div class="methodology-copy"><p><strong>Sources.</strong> {sources}.</p><p><strong>Identity.</strong> Exact normalized email can link automatically. Bilateral applicant-provided profile evidence may link with an explicit email-mismatch flag. Weak or one-sided evidence requires review and stays out of aggregates.</p><p><strong>Disclosure.</strong> Values below the active group threshold are withheld. The partner artifact contains aggregates only, never applicant profiles or attributable free text.</p><p><strong>Scope.</strong> Coresignal is not enabled. Devpost remains provisional until both track adapters pass strict validation and the records are reconciled. AI classification remains disabled pending taxonomy and data-egress approval.</p></div></details></div></section></main></div>
<footer><div class="footer-inner"><span><strong>START Warsaw Community Intelligence</strong> · {"Synthetic interface preview" if data.synthetic else "Audited aggregate report"}</span><span>Report version talent-data-room-v2{" · Privacy-safe analytics enabled" if posthog_key else ""}</span></div></footer>
{analytics}<script>
(() => {{
  const base = window.reportAnalytics || {{report_version:'talent-data-room-v2',event_id:{_script_json(data.event_key)},partner_id:{_script_json(data.partner_key)}}};
  const allowed = new Set(['data_room_opened','report_section_viewed','chart_mode_changed','methodology_opened','print_requested','funnel_stage_opened','trend_point_inspected','evidence_link_clicked','report_completed','section_engaged']);
  const track = (name, properties={{}}) => {{ if (allowed.has(name) && window.posthog) window.posthog.capture(name, Object.assign({{}}, base, properties)); }};
  track('data_room_opened');
  const reveal = document.querySelectorAll('.reveal');
  const revealObserver = 'IntersectionObserver' in window ? new IntersectionObserver(entries => entries.forEach(entry => {{ if (entry.isIntersecting) {{ entry.target.classList.add('is-visible'); revealObserver.unobserve(entry.target); }} }}), {{threshold:.12}}) : null;
  reveal.forEach(item => revealObserver ? revealObserver.observe(item) : item.classList.add('is-visible'));
  const seen = new Set(); const engaged = new Set(); const engagementTimers = new Map();
  const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  let reportCompleted = false;
  const sections = document.querySelectorAll('[data-section-key]');
  const nav = document.querySelectorAll('[data-nav-key]');
  const sectionObserver = 'IntersectionObserver' in window ? new IntersectionObserver(entries => entries.forEach(entry => {{ const key=entry.target.dataset.sectionKey; if (!entry.isIntersecting) {{ clearTimeout(engagementTimers.get(key)); engagementTimers.delete(key); return; }} nav.forEach(link => link.setAttribute('aria-current', String(link.dataset.navKey===key))); if (!seen.has(key)) {{ seen.add(key); track('report_section_viewed', {{section_id:key}}); }} if (!engaged.has(key) && !engagementTimers.has(key)) engagementTimers.set(key,setTimeout(() => {{ engaged.add(key); engagementTimers.delete(key); track('section_engaged', {{section_id:key}}); }},4000)); if (key==='confidence' && !reportCompleted) {{ reportCompleted=true; track('report_completed'); }} }}), {{rootMargin:'-20% 0px -55% 0px'}}) : null;
  sections.forEach(section => sectionObserver && sectionObserver.observe(section));
  document.querySelectorAll('[data-chart-mode]').forEach(button => button.addEventListener('click', () => {{ const mode=button.dataset.chartMode; const chart=button.closest('[data-chart-view]'); if (!chart) return; chart.dataset.display=mode; chart.querySelectorAll('[data-chart-mode]').forEach(peer => peer.setAttribute('aria-pressed', String(peer.dataset.chartMode===mode))); track('chart_mode_changed', {{chart_id:chart.dataset.chartView,chart_mode:mode}}); }}));
  const funnelDetail=document.querySelector('[data-funnel-detail]'); document.querySelectorAll('[data-funnel-stage]').forEach(button=>{{ button.disabled=false; button.addEventListener('click',()=>{{ document.querySelectorAll('[data-funnel-stage]').forEach(peer=>peer.setAttribute('aria-pressed',String(peer===button))); if(funnelDetail) funnelDetail.textContent=button.dataset.stageDetail; track('funnel_stage_opened',{{stage_id:button.dataset.funnelStage}}); }}); }});
  const trendDetail=document.querySelector('[data-trend-detail] p'); document.querySelectorAll('[data-trend-event]').forEach(button=>{{ button.disabled=false; button.addEventListener('click',()=>{{ document.querySelectorAll('[data-trend-event]').forEach(peer=>peer.setAttribute('aria-pressed',String(peer===button))); if(trendDetail) trendDetail.textContent=button.dataset.trendDetail; track('trend_point_inspected',{{event_index:button.dataset.trendEvent}}); }}); }});
  document.querySelectorAll('[data-evidence-target]').forEach(link=>link.addEventListener('click',()=>{{ const target=link.dataset.evidenceTarget; track('evidence_link_clicked',{{target_section:target}}); const section=document.getElementById(target); section && !reduceMotion && setTimeout(()=>{{ section.animate([{{backgroundColor:'oklch(96% .02 18)'}},{{backgroundColor:'transparent'}}],{{duration:700,easing:'cubic-bezier(.16,1,.3,1)'}}); }},300); }}));
  const progress=document.querySelector('[data-reading-progress]'); let progressFrame=0; const updateProgress=()=>{{ progressFrame=0; const distance=document.documentElement.scrollHeight-innerHeight; const ratio=distance>0?Math.min(1,scrollY/distance):0; if(progress) progress.style.transform=`scaleX(${{ratio}})`; }}; addEventListener('scroll',()=>{{ if(!progressFrame) progressFrame=requestAnimationFrame(updateProgress); }},{{passive:true}}); updateProgress();
  const methodology = document.querySelector('[data-methodology]');
  methodology && methodology.addEventListener('toggle', () => {{ if (methodology.open) track('methodology_opened'); }});
  const printButton = document.querySelector('[data-action="print"]');
  printButton && printButton.addEventListener('click', () => {{ track('print_requested'); window.print(); }});
}})();
</script></body></html>"""
