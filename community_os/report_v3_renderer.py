"""Self-contained HTML renderer for the frozen talent-report-v3 contract."""

from __future__ import annotations

from dataclasses import dataclass
from html import escape
import json
from pathlib import Path
from urllib.parse import quote

from community_os.report_contract import CountValue, TalentReportContract


@dataclass(frozen=True)
class V3ExhibitBundle:
    """Static exhibit markup and CSS for embedding in another report shell."""

    html: str
    css: str


def _label(key: str) -> str:
    return {
        "on_site": "Checked in at event",
        "checked_in": "Checked in at event",
        "going_accepted": "Accepted or confirmed",
        "not_accepted_reason_unknown": "Not accepted; source does not record why",
    }.get(key, key.replace("_", " ").title())


def _public_label(key: str, label: str) -> str:
    return {
        "on_site": "Checked in at event",
        "checked_in": "Checked in at event",
        "going_accepted": "Accepted or confirmed",
        "not_accepted_reason_unknown": "Not accepted; source does not record why",
    }.get(key, label)


def _count(value: CountValue) -> str:
    return str(value.value) if value.value is not None else "Withheld"


def _reason(value: CountValue) -> str:
    return value.reason or "Published aggregate"


def _rate(numerator: int | None, denominator: int | None) -> int | None:
    if numerator is None or denominator in (None, 0):
        return None
    return round(numerator / denominator * 100)


def _inspector(key: str, title: str, value: str, note: str) -> str:
    return (
        f'<aside class="inspector" id="{escape(key)}-inspector" data-inspector="{escape(key)}" '
        'aria-live="polite"><span>Selected evidence</span>'
        f'<strong data-inspector-title>{escape(title)}</strong>'
        f'<b data-inspector-value>{escape(value)}</b>'
        f'<p data-inspector-note>{escape(note)}</p></aside>'
    )


def _mode_switch(group: str, primary: str, alternate: str) -> str:
    return (
        f'<div class="mode-switch js-only" data-mode-group="{escape(group)}" '
        f'aria-label="{escape(group.title())} value display">'
        f'<button type="button" data-mode-value="primary" aria-pressed="true">{escape(primary)}</button>'
        f'<button type="button" data-mode-value="rate" aria-pressed="false">{escape(alternate)}</button></div>'
    )


def _script_json(value: object) -> str:
    return json.dumps(value, separators=(",", ":")).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")


def _logo_data_uri() -> str:
    asset = Path(__file__).resolve().parents[1] / "assets/brand/start-warsaw-white.svg"
    return "data:image/svg+xml," + quote(asset.read_text(encoding="utf-8"), safe="/,:;=()")


def _table(caption: str, headings: tuple[str, ...], rows: list[tuple[str, ...]]) -> str:
    head = "".join(f"<th scope=\"col\">{escape(item)}</th>" for item in headings)
    body = "".join(
        "<tr>" + "".join(
            f"<{('th scope=\"row\"' if index == 0 else 'td')}>{escape(cell)}</{('th' if index == 0 else 'td')}>"
            for index, cell in enumerate(row)
        ) + "</tr>" for row in rows
    )
    return (
        '<details class="data-fallback"><summary>Open evidence table</summary>'
        f'<table><caption>{escape(caption)}</caption><thead><tr>{head}</tr></thead>'
        f'<tbody>{body}</tbody></table></details>'
    )


def _attendance(report: TalentReportContract) -> str:
    stages = report.attendance_funnel.stages
    maximum = max((stage.count.value or 0) for stage in stages)
    cards = []
    for index, stage in enumerate(stages):
        value = stage.count.value
        terminal = index + 1 == len(stages)
        next_value = stages[index + 1].count.value if not terminal else None
        dots = ""
        if value is None:
            dots = '<span class="privacy-placeholder">Protected value</span>'
        elif terminal:
            dots = '<i class="person-dot terminal" style="background:var(--navy)"></i>' * value
        elif next_value is None:
            dots = '<i class="person-dot unknown" title="Next-stage split withheld"></i>' * value
        else:
            advanced = next_value if next_value is not None else 0
            dots = "".join(
                f'<i class="person-dot {"advanced" if dot < advanced else "stopped"}"></i>'
                for dot in range(value)
            )
        conversion = "Starting cohort" if index == 0 else (
            "Withheld" if value is None or stages[index - 1].count.value is None
            else f"{round(value / stages[index - 1].count.value * 100)}% from prior stage"
        )
        detail = (
            f"{stage.label}: {_count(stage.count)} people. {conversion}. "
            f"Unit: {report.attendance_funnel.unit}; {_reason(stage.count).lower()}."
        )
        cards.append(
            f'<li class="funnel-stage reveal" style="--delay:{index * 90}ms"><a '
            f'href="#attendance-inspector" data-inspect="attendance" data-datum-key="{escape(stage.key)}" '
            f'data-title="{escape(stage.label)}" data-value="{escape(_count(stage.count))} people" '
            f'data-note="{escape(detail)}">'
            f'<span class="stage-index">0{index + 1}</span><strong>{escape(stage.label)}</strong>'
            f'<b data-mode-display="attendance" data-primary="{escape(_count(stage.count))}" '
            f'data-alternate="{escape(conversion)}">{escape(_count(stage.count))}</b>'
            f'<span>{escape(conversion)}</span><span class="dot-field" aria-hidden="true">{dots}</span>'
            '</a></li>'
        )
    return (
        '<p class="encoding">Each dot represents one person. Burgundy marks people who reached the next stage; gray marks people who stopped. Hatched dots mark a protected next-stage split. Navy marks the observed terminal cohort.</p>'
        f'<ol class="funnel" aria-label="Attendance funnel, maximum {maximum} people">{"".join(cards)}</ol>'
        + _inspector(
            "attendance", stages[0].label, f"{_count(stages[0].count)} people",
            f"Starting cohort. Unit: {report.attendance_funnel.unit}; {_reason(stages[0].count).lower()}.",
        )
    )


def _journey(report: TalentReportContract) -> str:
    nodes = {node.key: node for node in report.journey.nodes}
    depths = {key: 0 for key in nodes}
    for _ in nodes:
        changed = False
        for link in report.journey.links:
            candidate = depths[link.source] + 1
            if candidate > depths[link.target]:
                depths[link.target] = candidate
                changed = True
        if not changed:
            break
    columns: dict[int, list[str]] = {}
    for node in report.journey.nodes:
        columns.setdefault(depths[node.key], []).append(node.key)
    targets = {link.target for link in report.journey.links}
    roots = [node for node in report.journey.nodes if node.key not in targets]
    root_total = max((node.count.value or 0 for node in roots), default=0)
    incoming: dict[str, list[object]] = {key: [] for key in nodes}
    for link in report.journey.links:
        incoming[link.target].append(link)

    levels = []
    level_labels = ("Starting cohort", "Recorded outcome", "Event attendance")
    for depth in sorted(columns):
        bands = []
        for key in columns[depth]:
            node = nodes[key]
            value = node.count.value
            share = (value / root_total * 100) if value is not None and root_total else 0
            node_links = incoming[key]
            if depth == 0:
                context = "100% of starting cohort"
            elif len(node_links) == 1:
                source = nodes[node_links[0].source]
                context = (
                    f"{round(value / source.count.value * 100)}% of {source.label}"
                    if value is not None and source.count.value
                    else _reason(node.count)
                )
            else:
                context = f"{round(share)}% of starting cohort" if value is not None else _reason(node.count)
            public_label = _public_label(node.key, node.label)
            note = (
                f"{public_label}: {_count(node.count)} people. {context}. "
                f"Unit: {report.journey.unit}; {_reason(node.count).lower()}."
            )
            muted = any(token in key for token in ("not_", "unknown", "rejected", "declined"))
            bands.append(
                f'<a class="journey-band{" outcome-muted" if muted else ""}" '
                f'style="--weight:{value or report.privacy.minimum_count};--share:{share:.1f}%" '
                f'href="#journey-inspector" data-inspect="journey" data-datum-key="{escape(key)}" '
                f'data-title="{escape(public_label)}" data-value="{escape(_count(node.count))} people" '
                f'data-note="{escape(note)}"><span class="journey-copy"><strong>{escape(public_label)}</strong>'
                f'<b>{escape(_count(node.count))}</b><small>{escape(context)}</small></span>'
                f'<span class="journey-meter" aria-hidden="true"><i></i></span></a>'
            )
        label = level_labels[depth] if depth < len(level_labels) else f"Step {depth + 1}"
        levels.append(
            f'<div class="journey-level" data-funnel-depth="{depth}"><span class="journey-level-label">'
            f'{depth + 1:02d} · {escape(label)}</span><div class="journey-bands">{"".join(bands)}</div></div>'
        )
    rows = [(nodes[link.source].label + " to " + nodes[link.target].label, _count(link.count), _reason(link.count)) for link in report.journey.links]
    return (
        '<p class="encoding">Band widths encode people within each step; inset bars preserve the share of the starting cohort. On mobile, cards stack while the bars keep the scale.</p>'
        '<div class="chart-frame reveal" data-chart-key="journey"><div class="volume-funnel" '
        'data-volume-funnel="journey" role="img" aria-label="Volume-adjusted participant funnel in people">'
        f'{"".join(levels)}</div></div>'
        + _inspector(
            "journey", report.journey.nodes[0].label,
            f"{_count(report.journey.nodes[0].count)} people",
            f"Starting journey node. Unit: {report.journey.unit}; {_reason(report.journey.nodes[0].count).lower()}.",
        )
        + _table("Participant journey fallback", ("Path", "People", "State"), rows)
    )


def _matrix(report: TalentReportContract) -> str:
    matrix = report.team_submission_matrix
    lookup = {(cell.row, cell.column): cell.count for cell in matrix.cells}
    header = "".join(f'<span class="matrix-head">{escape(_label(key))}</span>' for key in matrix.column_keys)
    body = []
    rows = []
    for row in matrix.row_keys:
        cells = []
        row_values = []
        for column in matrix.column_keys:
            count = lookup[row, column]
            state = "withheld" if count.value is None else "published"
            title = f"{_label(row)} · {_label(column)}"
            note = f"{title}: {_count(count)} teams. {_reason(count)}."
            cells.append(
                f'<a href="#submissions-inspector" class="matrix-cell {state}" '
                f'data-inspect="submissions" data-datum-key="{escape(row)}-{escape(column)}" '
                f'data-title="{escape(title)}" data-value="{escape(_count(count))} teams" '
                f'data-note="{escape(note)}" title="{escape(_reason(count))}"><b>{escape(_count(count))}</b></a>'
            )
            row_values.append(_count(count))
        body.append(f'<strong class="matrix-label">{escape(_label(row))}</strong>{"".join(cells)}')
        rows.append((_label(row), *row_values))
    return (
        f'<div class="matrix reveal" style="--columns:{len(matrix.column_keys)}"><span></span>{header}{"".join(body)}</div>'
        + _inspector(
            "submissions", f"{_label(matrix.row_keys[0])} · {_label(matrix.column_keys[0])}",
            f"{_count(lookup[matrix.row_keys[0], matrix.column_keys[0]])} teams",
            f"Unit: {matrix.unit}; {_reason(lookup[matrix.row_keys[0], matrix.column_keys[0]]).lower()}.",
        )
        + _table("Track by submission state fallback", ("Track", *tuple(_label(key) for key in matrix.column_keys)), rows)
    )


def _intersections(report: TalentReportContract) -> str:
    data = report.builder_signal_intersections
    maximum = max((item.count.value or 0) for item in data.intersections) or 1
    rows_markup = []
    rows = []
    for item in data.intersections:
        active = set(item.signals)
        markers = "".join(f'<i class="{("on" if key in active else "off")}" title="{escape(_label(key))}"></i>' for key in data.signal_keys)
        width = 100 if item.count.value is None else round(item.count.value / maximum * 100)
        title = " + ".join(_label(key) for key in item.signals)
        note = f"{title}: {_count(item.count)} people. {_reason(item.count)}."
        rows_markup.append(
            f'<a href="#signals-inspector" class="upset-row" data-inspect="signals" '
            f'data-datum-key="{escape("-".join(item.signals))}" data-title="{escape(title)}" '
            f'data-value="{escape(_count(item.count))} people" data-note="{escape(note)}">'
            f'<span class="signal-set">{markers}</span>'
            f'<span class="intersection-bar {"withheld" if item.count.value is None else ""}"><i style="--size:{width}%"></i></span>'
            f'<strong>{escape(_count(item.count))}</strong></a>'
        )
        rows.append((" + ".join(_label(key) for key in item.signals), _count(item.count), _reason(item.count)))
    legend = "".join(f'<span><i></i>{escape(_label(key))}</span>' for key in data.signal_keys)
    first = data.intersections[0]
    first_title = " + ".join(_label(key) for key in first.signals)
    return (
        f'<div class="upset reveal" data-chart-key="signal-intersections"><div class="signal-legend">{legend}</div>{"".join(rows_markup)}</div>'
        + _inspector(
            "signals", first_title, f"{_count(first.count)} people",
            f"Aggregate signal intersection. Unit: {data.unit}; {_reason(first.count).lower()}.",
        )
        + _table("Builder signal intersections fallback", ("Signal intersection", "People", "State"), rows)
    )


def _heatmap(report: TalentReportContract) -> str:
    data = report.track_domain_heatmap
    lookup = {(cell.track, cell.domain): cell.count for cell in data.cells}
    maximum = max((cell.count.value or 0) for cell in data.cells) or 1
    header = "".join(f'<span>{escape(_label(key))}</span>' for key in data.domain_keys)
    body = []
    rows = []
    for track in data.track_keys:
        values = []
        cells = []
        for domain in data.domain_keys:
            count = lookup[track, domain]
            level = 0 if count.value is None else round(count.value / maximum * 4)
            title = f"{_label(track)} · {_label(domain)}"
            note = f"{title}: {_count(count)} projects. {_reason(count)}."
            cells.append(
                f'<a href="#domains-inspector" class="heat-cell level-{level} '
                f'{"withheld" if count.value is None else ""}" data-inspect="domains" '
                f'data-datum-key="{escape(track)}-{escape(domain)}" data-title="{escape(title)}" '
                f'data-value="{escape(_count(count))} projects" data-note="{escape(note)}" '
                f'title="{escape(_reason(count))}">{escape(_count(count))}</a>'
            )
            values.append(_count(count))
        body.append(f'<strong>{escape(_label(track))}</strong>{"".join(cells)}')
        rows.append((_label(track), *values))
    first_count = lookup[data.track_keys[0], data.domain_keys[0]]
    return (
        f'<div class="heatmap reveal" style="--columns:{len(data.domain_keys)}"><span></span>{header}{"".join(body)}</div>'
        + _inspector(
            "domains", f"{_label(data.track_keys[0])} · {_label(data.domain_keys[0])}",
            f"{_count(first_count)} projects",
            f"Unit: {data.unit}; {_reason(first_count).lower()}.",
        )
        + _table("Track and domain fallback", ("Track", *tuple(_label(key) for key in data.domain_keys)), rows)
    )


def _composition(report: TalentReportContract) -> str:
    total = sum(item.count.value or 0 for item in report.composition.categories)
    bars = []
    rows = []
    for item in report.composition.categories:
        share = round((item.count.value or 0) / total * 100) if total else 0
        note = f"{item.label}: {_count(item.count)} people, {share}% of published composition. {_reason(item.count)}."
        bars.append(
            f'<a href="#composition-inspector" class="composition-row" data-inspect="composition" '
            f'data-datum-key="{escape(item.key)}" data-title="{escape(item.label)}" '
            f'data-value="{escape(_count(item.count))} people · {share}%" data-note="{escape(note)}">'
            f'<span><strong>{escape(item.label)}</strong><small>{escape(_reason(item.count))}</small></span>'
            f'<i><b style="--size:{share}%"></b></i><em data-mode-display="composition" '
            f'data-primary="{escape(_count(item.count))} people" data-alternate="{share}%">'
            f'{escape(_count(item.count))} people</em></a>'
        )
        rows.append((item.label, _count(item.count), f"{share}%", _reason(item.count)))
    first = report.composition.categories[0]
    first_share = _rate(first.count.value, total)
    segments = "".join(
        f'<span style="--size:{round((item.count.value or 0) / total * 100) if total else 0}%" '
        f'title="{escape(item.label)}: {escape(_count(item.count))} people"></span>'
        for item in report.composition.categories if item.count.value is not None
    )
    return (
        '<div class="composition-stack" aria-label="100% cohort composition">' + segments + '</div>'
        '<div class="composition reveal">' + "".join(bars) + '</div>'
        + _inspector(
            "composition", first.label, f"{_count(first.count)} people · {first_share}%",
            f"Share of published composition. Unit: {report.composition.unit}; {_reason(first.count).lower()}.",
        )
        + _table("Cohort composition fallback", ("Category", "People", "Share", "State"), rows)
    )


def _artifacts(report: TalentReportContract) -> str:
    items = []
    rows = []
    for item in report.artifact_completeness.items:
        present, eligible = item.present.value, item.eligible.value
        share = _rate(present, eligible)
        share_label = f"{share}%" if share is not None else "Coverage withheld"
        meter_share = share if share is not None else 0
        note = (
            f"{item.label}: {_count(item.present)} of {_count(item.eligible)} eligible projects, "
            f"{share_label.lower()}. Status: {item.status}."
        )
        items.append(
            f'<a href="#artifacts-inspector" class="artifact" data-inspect="artifacts" '
            f'data-datum-key="{escape(item.key)}" data-title="{escape(item.label)}" '
            f'data-value="{escape(_count(item.present))} of {escape(_count(item.eligible))} projects · {share_label}" '
            f'data-note="{escape(note)}"><span class="status status-{escape(item.status)}">'
            f'{escape(item.status)}</span><strong>{escape(item.label)}</strong><b data-mode-display="artifacts" '
            f'data-primary="{escape(_count(item.present))} / {escape(_count(item.eligible))}" '
            f'data-alternate="{share_label}">{escape(_count(item.present))} / {escape(_count(item.eligible))}</b>'
            f'<i><span style="--size:{meter_share}%"></span></i></a>'
        )
        rows.append((item.label, _count(item.present), _count(item.eligible), item.status))
    first = report.artifact_completeness.items[0]
    first_share = _rate(first.present.value, first.eligible.value)
    first_share_label = f"{first_share}%" if first_share is not None else "Coverage withheld"
    return (
        '<div class="artifacts reveal">' + "".join(items) + '</div>'
        + _inspector(
            "artifacts", first.label,
            f"{_count(first.present)} of {_count(first.eligible)} projects · {first_share_label}",
            f"Artifact coverage. Status: {first.status}; unit: {report.artifact_completeness.unit}.",
        )
        + _table("Artifact completeness fallback", ("Artifact", "Present", "Eligible projects", "Status"), rows)
    )


def _readiness(report: TalentReportContract) -> str:
    readiness = "".join(f'<li><span class="state state-{escape(item.state)}">{escape(item.state)}</span><strong>{escape(_label(item.component))}</strong><p>{escape(item.note)}</p><small>{"Required" if item.required else "Optional"}</small></li>' for item in report.readiness)
    sources = "".join(f'<li><span class="state state-{escape(item.state)}">{escape(item.state)}</span><strong>{escape(_label(item.source))}</strong><p>{escape(item.note)}</p></li>' for item in report.source_notes)
    rows = [(_label(item.component), item.state, "Required" if item.required else "Optional", item.note) for item in report.readiness]
    rows += [(_label(item.source), item.state, "Source", item.note) for item in report.source_notes]
    return f'<div class="readiness-grid"><div><h3>Pipeline gates</h3><ul>{readiness}</ul></div><div><h3>Source state</h3><ul>{sources}</ul></div></div>' + _table("Data readiness fallback", ("Component", "State", "Role", "Note"), rows)


def render_v3_exhibits(report: TalentReportContract) -> V3ExhibitBundle:
    """Return all V3 evidence as one script-free, namespace-scoped bundle."""
    metadata = report.metadata
    html = f'''
<div class="event-evidence-intro">
  <p class="kicker">START-owned event evidence</p>
  <h2>Attendance, participation, and submitted-work evidence</h2>
  <p class="scope">Contract {escape(metadata.contract_version)}. Generated {escape(metadata.generated_at)}. Evidence state: {escape(report.privacy.state.replace("_", " "))}. Counts retain their original people, teams, or projects unit.</p>
</div>
<div class="event-evidence-grid">
  <article class="event-exhibit event-exhibit-wide" id="event-attendance">
    <div class="event-exhibit-head"><p>People</p><h3>Attendance progression</h3></div>
    {_attendance(report)}
  </article>
  <article class="event-exhibit event-exhibit-wide" id="event-journey">
    <div class="event-exhibit-head"><p>People</p><h3>Application and participation funnel</h3></div>
    {_journey(report)}
  </article>
  <article class="event-exhibit" id="event-submissions">
    <div class="event-exhibit-head"><p>Teams</p><h3>Track and submission state</h3></div>
    {_matrix(report)}
  </article>
  <article class="event-exhibit" id="event-signals">
    <div class="event-exhibit-head"><p>People</p><h3>Builder signal intersections</h3></div>
    {_intersections(report)}
  </article>
  <article class="event-exhibit event-exhibit-wide" id="event-domains">
    <div class="event-exhibit-head"><p>Projects</p><h3>Track and project domain</h3></div>
    {_heatmap(report)}
  </article>
  <article class="event-exhibit" id="event-composition">
    <div class="event-exhibit-head"><p>People</p><h3>Cohort composition</h3></div>
    {_composition(report)}
  </article>
  <article class="event-exhibit" id="event-artifacts">
    <div class="event-exhibit-head"><p>Projects</p><h3>Artifact completeness</h3></div>
    {_artifacts(report)}
  </article>
  <article class="event-exhibit event-exhibit-wide" id="event-readiness">
    <div class="event-exhibit-head"><p>Sources and pipeline</p><h3>Data readiness</h3></div>
    {_readiness(report)}
  </article>
</div>'''
    css = '''
#event-evidence .event-evidence-intro{display:grid;grid-template-columns:minmax(0,1fr) minmax(220px,.72fr);gap:18px 44px;align-items:end;margin-bottom:38px}
#event-evidence .event-evidence-intro .kicker{grid-column:1/-1;margin:0}
#event-evidence .event-evidence-intro h2{margin:0}
#event-evidence .event-evidence-intro .scope{margin:0}
#event-evidence .event-evidence-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:1px;background:var(--rule);border:1px solid var(--rule)}
#event-evidence .event-exhibit{min-width:0;padding:28px;background:var(--surface)}
#event-evidence .event-exhibit-wide{grid-column:1/-1}
#event-evidence .event-exhibit-head{display:flex;justify-content:space-between;gap:20px;align-items:baseline;margin-bottom:22px;padding-bottom:14px;border-bottom:1px solid var(--navy)}
#event-evidence .event-exhibit-head p{margin:0;color:var(--burgundy);font-size:.67rem;font-weight:850;letter-spacing:.1em;text-transform:uppercase}
#event-evidence .event-exhibit-head h3{margin:0;color:var(--navy);font-size:1.35rem;text-align:right}
#event-evidence .encoding{color:var(--muted);font-size:.78rem}
#event-evidence .signature{display:none}
#event-evidence .funnel{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:1px;margin:18px 0 0;padding:0;background:var(--rule);list-style:none}
#event-evidence .funnel-stage{min-width:0;background:var(--surface)}
#event-evidence .funnel-stage>a{display:block;height:100%;padding:18px;color:inherit;text-decoration:none}
#event-evidence .funnel-stage strong,#event-evidence .funnel-stage b,#event-evidence .funnel-stage a>span{display:block}
#event-evidence .funnel-stage b{margin:7px 0;color:var(--navy);font-size:2rem}
#event-evidence .funnel-stage a>span:not(.dot-field):not(.stage-index){color:var(--muted);font-size:.72rem}
#event-evidence .stage-index{color:var(--burgundy);font-size:.66rem;font-weight:850}
#event-evidence .dot-field{display:flex!important;flex-wrap:wrap;gap:3px;margin-top:14px}
#event-evidence .person-dot{width:5px;height:5px;background:var(--rule)}
#event-evidence .person-dot.advanced{background:var(--burgundy)}
#event-evidence .person-dot.terminal{background:var(--navy)}
#event-evidence .privacy-placeholder{display:block;width:100%;min-height:12px;border:1px solid var(--rule);background:repeating-linear-gradient(135deg,#f2f1f3 0,#f2f1f3 5px,#e7e6e9 5px,#e7e6e9 6px);color:transparent;font-size:0}
#event-evidence .person-dot.unknown{border:1px solid var(--muted);background:repeating-linear-gradient(135deg,transparent 0,transparent 2px,var(--muted) 2px,var(--muted) 3px)}
#event-evidence .chart-frame{padding:16px;border:1px solid var(--rule);background:var(--surface)}
#event-evidence .volume-funnel{display:grid;gap:18px}
#event-evidence .journey-level{display:grid;grid-template-columns:112px minmax(0,1fr);gap:14px;align-items:stretch}
#event-evidence .journey-level-label{padding-top:13px;color:var(--burgundy);font-size:.65rem;font-weight:850;letter-spacing:.08em;text-transform:uppercase}
#event-evidence .journey-bands{display:flex;gap:8px;min-width:0}
#event-evidence .journey-band{display:grid;flex:var(--weight) 1 0;min-width:145px;gap:14px;padding:14px;border:1px solid var(--rule);color:inherit;background:var(--surface);text-decoration:none}
#event-evidence .journey-band:hover,#event-evidence .journey-band:focus-visible,#event-evidence .journey-band[aria-current=true]{background:var(--tint);outline:3px solid var(--focus);outline-offset:-3px}
#event-evidence .journey-copy{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:3px 14px;align-items:start}
#event-evidence .journey-copy strong{color:var(--navy);font-size:.86rem}
#event-evidence .journey-copy b{color:var(--navy);font-size:1.45rem;line-height:1}
#event-evidence .journey-copy small{grid-column:1/-1;color:var(--muted);font-size:.7rem}
#event-evidence .journey-meter{height:8px;background:#eeeef1}
#event-evidence .journey-meter i{display:block;width:var(--share);height:100%;background:var(--burgundy)}
#event-evidence .journey-band.outcome-muted .journey-meter i{background:var(--muted)}
#event-evidence .matrix,#event-evidence .heatmap{display:grid;grid-template-columns:minmax(90px,1.2fr) repeat(var(--columns),minmax(82px,1fr));gap:1px;overflow:auto;background:var(--rule);border:1px solid var(--rule)}
#event-evidence .matrix>*,#event-evidence .heatmap>*{display:grid;place-items:center;min-height:62px;padding:9px;background:var(--surface);text-align:center}
#event-evidence .matrix-head,#event-evidence .heatmap>span{color:var(--muted);font-size:.68rem;letter-spacing:.06em;text-transform:uppercase}
#event-evidence .matrix-cell,#event-evidence .heat-cell{color:inherit;text-decoration:none}
#event-evidence .withheld{background:repeating-linear-gradient(135deg,#f2f1f3 0,#f2f1f3 5px,#e7e6e9 5px,#e7e6e9 6px)!important;color:var(--muted)}
#event-evidence .signal-legend{display:flex;flex-wrap:wrap;gap:12px;margin-bottom:16px;color:var(--muted);font-size:.72rem}
#event-evidence .signal-legend span{display:flex;align-items:center;gap:6px}
#event-evidence .signal-legend i{width:8px;height:8px;background:var(--navy)}
#event-evidence .upset-row{display:grid;grid-template-columns:100px minmax(0,1fr) 54px;gap:12px;align-items:center;padding:10px 6px;border-bottom:1px solid var(--rule);color:inherit;text-decoration:none}
#event-evidence .signal-set{display:flex;justify-content:space-around}
#event-evidence .signal-set i{width:11px;height:11px;border:1px solid var(--rule);border-radius:50%}
#event-evidence .signal-set i.on{border-color:var(--burgundy);background:var(--burgundy)}
#event-evidence .intersection-bar{height:18px;background:#eeeef1}
#event-evidence .intersection-bar i{display:block;width:var(--size);height:100%;background:var(--navy)}
#event-evidence .level-0{color:var(--muted)}#event-evidence .level-1{background:#f9e6eb!important}#event-evidence .level-2{background:#e4b7c2!important}#event-evidence .level-3{color:white;background:#ad5369!important}#event-evidence .level-4{color:white;background:var(--burgundy)!important}
#event-evidence .composition-row{display:grid;grid-template-columns:minmax(130px,1fr) 1.4fr 80px;gap:14px;align-items:center;padding:13px 4px;border-bottom:1px solid var(--rule);color:inherit;text-decoration:none}
#event-evidence .composition-stack{display:flex;width:100%;height:22px;margin-bottom:16px;overflow:hidden;background:#eeeef1}
#event-evidence .composition-stack>span{display:block;width:var(--size);height:100%;border-right:2px solid var(--surface);background:var(--burgundy)}
#event-evidence .composition-stack>span:nth-child(2n){background:var(--navy)}
#event-evidence .composition-row span>*,#event-evidence .artifact>*{display:block}
#event-evidence .composition-row small{color:var(--muted)}
#event-evidence .composition-row>i,#event-evidence .artifact>i{height:8px;background:#eeeef1}
#event-evidence .composition-row>i b,#event-evidence .artifact>i span{display:block;width:var(--size);height:100%;background:var(--burgundy)}
#event-evidence .composition-row em{font-style:normal;font-weight:850;text-align:right}
#event-evidence .artifacts{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:1px;background:var(--rule)}
@media(max-width:640px){#event-evidence .journey-level{grid-template-columns:1fr;gap:7px}#event-evidence .journey-level-label{padding-top:0}#event-evidence .journey-bands{display:grid;grid-template-columns:1fr}#event-evidence .journey-band{min-width:0}}
#event-evidence .artifact{display:grid;gap:11px;padding:20px;color:inherit;background:var(--surface);text-decoration:none}
#event-evidence .artifact>b{color:var(--navy);font-size:1.55rem}
#event-evidence .status,#event-evidence .state{width:max-content;padding:4px 7px;font-size:.62rem;font-weight:850;letter-spacing:.06em;text-transform:uppercase}
#event-evidence .status-complete,#event-evidence .state-ready,#event-evidence .state-validated{color:var(--success);background:#e8f4ed}
#event-evidence .status-partial,#event-evidence .state-pending{color:var(--warn);background:#fff4cc}
#event-evidence .state-off,#event-evidence .state-not_enabled{color:var(--muted);background:#eeeef1}
#event-evidence .readiness-grid{display:grid;grid-template-columns:1fr 1fr;gap:28px}
#event-evidence .readiness-grid h3{color:var(--navy);font-size:1rem}
#event-evidence .readiness-grid ul{margin:0;padding:0;border-top:1px solid var(--navy);list-style:none}
#event-evidence .readiness-grid li{display:grid;grid-template-columns:auto 1fr auto;gap:9px;align-items:center;padding:12px 0;border-bottom:1px solid var(--rule)}
#event-evidence .readiness-grid p{grid-column:2/-1;margin:0;color:var(--muted);font-size:.74rem}
#event-evidence .readiness-grid small{color:var(--muted)}
#event-evidence .inspector{display:grid;grid-template-columns:minmax(0,.7fr) minmax(0,.6fr) minmax(0,1.4fr);gap:5px 18px;align-items:end;margin-top:18px;padding:14px 0;border-top:2px solid var(--burgundy);border-bottom:1px solid var(--rule)}
#event-evidence .inspector>span{grid-column:1/-1;color:var(--burgundy);font-size:.62rem;font-weight:850;letter-spacing:.1em;text-transform:uppercase}
#event-evidence .inspector strong{color:var(--navy)}#event-evidence .inspector b{color:var(--burgundy);font-size:1.2rem}#event-evidence .inspector p{margin:0;color:var(--muted);font-size:.74rem}
#event-evidence .data-fallback{margin-top:16px;border-top:1px solid var(--rule)}
#event-evidence details.data-fallback>summary{padding:11px 0;color:var(--burgundy);font-size:.68rem;font-weight:850;letter-spacing:.06em;text-transform:uppercase;cursor:pointer}
#event-evidence table{font-size:.75rem}
@media(max-width:900px){#event-evidence .event-evidence-intro,#event-evidence .event-evidence-grid{grid-template-columns:1fr}#event-evidence .event-exhibit-wide{grid-column:1}#event-evidence .event-evidence-intro .kicker{grid-column:1}#event-evidence .funnel,#event-evidence .artifacts,#event-evidence .readiness-grid{grid-template-columns:1fr}#event-evidence .composition-row{grid-template-columns:1fr auto;gap:8px}#event-evidence .composition-row>i{grid-column:1/-1;grid-row:2}#event-evidence .composition-row em{grid-column:2;grid-row:1;text-align:right}#event-evidence .inspector{grid-template-columns:1fr}#event-evidence .inspector>span{grid-column:1}}
@media print{#event-evidence .event-evidence-grid{display:block;border:0}#event-evidence .event-exhibit{padding:5mm 0;break-inside:avoid;border-bottom:1px solid var(--rule)}#event-evidence .event-exhibit-wide{break-before:auto}#event-evidence .funnel{grid-template-columns:repeat(3,1fr)}#event-evidence .artifacts,#event-evidence .readiness-grid{grid-template-columns:repeat(2,1fr)}#event-evidence .inspector{display:none}#event-evidence details.data-fallback{display:block!important}#event-evidence details.data-fallback>summary{display:none!important}#event-evidence details.data-fallback>table{display:table!important}}
@media print{#event-evidence .event-evidence-grid{background:transparent}}
'''
    return V3ExhibitBundle(html=html, css=css)


def _analytics(report: TalentReportContract, key: str | None, host: str) -> str:
    if not key:
        return ""
    config = {"key": key, "host": host.rstrip("/"), "persistence": "memory", "autocapture": False, "disable_session_recording": True}
    return f"window.reportAnalytics={_script_json(config)};"


def _cockpit(report: TalentReportContract) -> str:
    stages = report.attendance_funnel.stages
    approved = stages[0].count.value
    submitted = stages[-1].count.value
    checked_in = next((stage.count.value for stage in stages if stage.key == "checked_in"), None)
    team_node = next((node for node in report.journey.nodes if node.key == "team_path"), None)
    submitted_teams = sum(
        cell.count.value or 0
        for cell in report.team_submission_matrix.cells
        if cell.column == "submitted" and cell.count.value is not None
    )
    repository = next(
        (item for item in report.artifact_completeness.items if item.key == "repository"),
        report.artifact_completeness.items[0],
    )
    ship_rate = _rate(submitted, approved)
    team_rate = _rate(team_node.count.value if team_node else None, checked_in)
    repo_rate = _rate(repository.present.value, repository.eligible.value)
    items = (
        ("attendance", "Attendance", f"{submitted if submitted is not None else 'Withheld'} people shipped", f"{ship_rate}% of approved people" if ship_rate is not None else "Conversion withheld"),
        ("journey", "Participation path", f"{_count(team_node.count) if team_node else 'Withheld'} team-path people", f"{team_rate}% of check-ins" if team_rate is not None else "Share withheld"),
        ("submissions", "Track output", f"{submitted_teams} submitted teams", "Across published track cells"),
        ("evidence", "Artifact depth", f"{_count(repository.present)} repositories", f"{repo_rate}% of eligible projects" if repo_rate is not None else "Coverage withheld"),
    )
    links = "".join(
        f'<a href="#{escape(target)}" data-evidence-target="{escape(target)}"><span>{escape(label)}</span>'
        f'<strong>{escape(value)}</strong><small>{escape(context)}</small><i aria-hidden="true">View evidence</i></a>'
        for target, label, value, context in items
    )
    return (
        '<section class="cockpit" aria-labelledby="cockpit-title"><div class="cockpit-head">'
        '<p class="kicker">Start with the evidence</p><h2 id="cockpit-title">Evidence cockpit</h2>'
        '<p>Four findings, each linked to the contract exhibit that supports it.</p></div>'
        f'<div class="cockpit-ledger">{links}</div></section>'
    )


def render_v3_report(report: TalentReportContract, *, posthog_key: str | None = None, posthog_host: str = "https://eu.i.posthog.com") -> str:
    """Render only validated aggregate contract values and privacy states."""
    metadata = report.metadata
    synthetic = "Synthetic evidence briefing" if metadata.synthetic else "Validated event evidence briefing"
    approved = report.attendance_funnel.stages[0].count
    checked_in = report.attendance_funnel.stages[1].count
    submitted = report.attendance_funnel.stages[-1].count
    analytics = _analytics(report, posthog_key, posthog_host)
    logo = _logo_data_uri()
    return f'''<!doctype html>
<html lang="en" class="no-js"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"><title>{escape(metadata.title)} | {escape(metadata.event_name)}</title><link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'%3E%3Crect width='64' height='64' fill='%2300002c'/%3E%3Cpath d='M14 48 29 16h7l14 32h-9l-3-8H25l-3 8h-8Zm14-15h7l-3.5-9L28 33Z' fill='%23fcfbf7'/%3E%3C/svg%3E">
<script>document.documentElement.className="js"</script>
<style>
:root{{--navy:#00002c;--burgundy:#80011f;--paper:#fcfbf7;--surface:#ffffff;--ink:#171729;--muted:#5d5d6e;--rule:#d5d4db;--focus:#d8a7b4;--tint:#fff5f7;--error:#94252a;--success:#187447;--font:AvenirLTNextPro,"Avenir Next",Avenir,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;--ease:cubic-bezier(.16,1,.3,1)}}
*{{box-sizing:border-box}}html{{scroll-behavior:smooth;background:var(--paper)}}body{{margin:0;color:var(--ink);background:var(--paper);font:16px/1.55 var(--font)}}a{{color:inherit}}button,summary{{font:inherit}}button:focus-visible,a:focus-visible,summary:focus-visible{{outline:3px solid var(--focus);outline-offset:3px}}.skip{{position:fixed;left:-999px;top:16px;z-index:20;padding:10px 14px;background:var(--surface)}}.skip:focus{{left:16px}}.progress{{position:fixed;z-index:20;inset:0 auto auto 0;width:100%;height:3px;transform:scaleX(0);transform-origin:left;background:var(--burgundy)}}
.cover{{min-height:52vh;padding:24px;color:var(--paper);background:var(--navy);display:grid;grid-template-rows:auto 1fr auto}}.brand{{width:172px;height:88px;object-fit:contain;object-position:left center}}.cover-copy{{align-self:center;max-width:980px}}.eyebrow,.kicker{{margin:0 0 16px;color:var(--burgundy);font-size:.69rem;font-weight:850;letter-spacing:.16em;text-transform:uppercase}}.cover .eyebrow{{color:#d8a7b4}}h1{{max-width:13ch;margin:0;font-size:clamp(3rem,6vw,5.8rem);font-weight:900;letter-spacing:-.065em;line-height:.86}}.dek{{max-width:64ch;margin:20px 0 0;color:#d8d7e0;font-size:1.04rem}}.cover-meta{{display:grid;grid-template-columns:repeat(3,1fr);gap:1px;border-top:1px solid #4b4b67}}.cover-meta span{{padding:14px 0;color:#bcbccc;font-size:.72rem;text-transform:uppercase;letter-spacing:.08em}}.cover-meta strong{{display:block;margin-top:4px;color:var(--paper);font-size:.98rem;letter-spacing:0;text-transform:none}}
.cockpit{{padding:64px max(40px,6vw);border-bottom:1px solid var(--rule);background:var(--surface)}}.cockpit-head{{display:grid;grid-template-columns:minmax(0,1fr) minmax(240px,.7fr);gap:20px 48px;align-items:end;margin-bottom:28px}}.cockpit-head .kicker{{grid-column:1/-1;margin:0}}.cockpit-head h2{{font-size:clamp(2.5rem,5vw,5.2rem)}}.cockpit-head>p:last-child{{max-width:42ch;margin:0;color:var(--muted)}}.cockpit-ledger{{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));border-top:1px solid var(--navy)}}.cockpit-ledger a{{position:relative;display:grid;grid-template-columns:1fr auto;gap:4px 20px;padding:24px 36px 24px 0;border-bottom:1px solid var(--rule);text-decoration:none;transition:background-color 180ms var(--ease),padding 180ms var(--ease)}}.cockpit-ledger a:nth-child(odd){{padding-right:36px}}.cockpit-ledger a:nth-child(even){{padding-left:36px;border-left:1px solid var(--rule)}}.cockpit-ledger a:hover,.cockpit-ledger a:focus-visible{{background:var(--tint)}}.cockpit-ledger span{{grid-column:1/-1;color:var(--burgundy);font-size:.68rem;font-weight:850;letter-spacing:.12em;text-transform:uppercase}}.cockpit-ledger strong{{color:var(--navy);font-size:clamp(1.5rem,3vw,2.7rem);line-height:1}}.cockpit-ledger small{{align-self:end;color:var(--muted)}}.cockpit-ledger i{{grid-column:1/-1;margin-top:10px;color:var(--burgundy);font-size:.72rem;font-style:normal;font-weight:800}}
.shell{{display:grid;grid-template-columns:220px minmax(0,1fr)}}nav{{position:sticky;top:0;align-self:start;height:100vh;padding:40px 24px;border-right:1px solid var(--rule);background:var(--paper)}}nav strong{{display:block;margin-bottom:24px;color:var(--navy);font-size:.76rem;letter-spacing:.12em;text-transform:uppercase}}nav a{{display:block;padding:8px 0;color:var(--muted);font-size:.82rem;text-decoration:none}}nav a[aria-current=true]{{color:var(--burgundy);font-weight:800}}main{{min-width:0}}.section{{padding:88px max(40px,6vw);border-bottom:1px solid var(--rule)}}.section:nth-child(even){{background:var(--surface)}}.section-head{{display:grid;grid-template-columns:minmax(0,1fr) minmax(180px,280px);gap:40px;align-items:end;margin-bottom:36px}}h2{{max-width:17ch;margin:0;color:var(--navy);font-size:clamp(2.35rem,4vw,4.7rem);font-weight:900;letter-spacing:-.055em;line-height:.94}}.scope{{margin:0;padding-top:12px;border-top:1px solid var(--navy);color:var(--muted);font-size:.78rem}}.encoding{{max-width:70ch;color:var(--muted)}}
.signature{{display:grid;grid-template-columns:repeat(3,1fr);gap:1px;margin-bottom:52px;background:var(--rule)}}.signature div{{padding:28px;background:var(--surface)}}.signature b{{display:block;color:var(--navy);font-size:3rem;line-height:1}}.signature span{{color:var(--muted);font-size:.78rem}}.funnel{{display:grid;grid-template-columns:repeat(3,1fr);gap:1px;margin:28px 0 0;padding:0;background:var(--rule);list-style:none}}.funnel-stage{{min-width:0;background:var(--surface)}}.funnel-stage>a{{display:block;height:100%;padding:22px;text-decoration:none;transition:background-color 180ms var(--ease),color 180ms var(--ease)}}.funnel-stage>a:hover,.funnel-stage>a:focus-visible,.funnel-stage>a[aria-current=true]{{background:var(--tint)}}.funnel-stage strong,.funnel-stage b,.funnel-stage a>span{{display:block}}.funnel-stage b{{margin:8px 0;color:var(--navy);font-size:2.4rem}}.funnel-stage a>span:not(.dot-field):not(.stage-index){{color:var(--muted);font-size:.75rem}}.stage-index{{color:var(--burgundy);font-size:.68rem;font-weight:800}}.dot-field{{display:flex!important;flex-wrap:wrap;gap:3px;margin-top:18px}}.person-dot{{width:6px;height:6px;background:var(--rule)}}.person-dot.advanced{{background:var(--burgundy)}}.privacy-placeholder{{display:block;width:100%;min-height:12px;border:1px solid var(--rule);background:repeating-linear-gradient(135deg,#f2f1f3 0,#f2f1f3 5px,#e7e6e9 5px,#e7e6e9 6px);color:transparent;font-size:0}}.person-dot.unknown{{border:1px solid var(--muted);background:repeating-linear-gradient(135deg,transparent 0,transparent 2px,var(--muted) 2px,var(--muted) 3px)}}
.chart-frame{{padding:20px;border:1px solid var(--rule);background:var(--surface)}}.volume-funnel{{display:grid;gap:22px}}.journey-level{{display:grid;grid-template-columns:130px minmax(0,1fr);gap:18px;align-items:stretch}}.journey-level-label{{padding-top:15px;color:var(--burgundy);font-size:.67rem;font-weight:850;letter-spacing:.09em;text-transform:uppercase}}.journey-bands{{display:flex;gap:10px;min-width:0}}.journey-band{{display:grid;flex:var(--weight) 1 0;min-width:160px;gap:16px;padding:17px;border:1px solid var(--rule);color:inherit;background:var(--surface);text-decoration:none;transition:background-color 180ms var(--ease)}}.journey-band:hover,.journey-band:focus-visible,.journey-band[aria-current=true]{{background:var(--tint);outline:3px solid var(--focus);outline-offset:-3px}}.journey-copy{{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:4px 16px;align-items:start}}.journey-copy strong{{color:var(--navy);font-size:.92rem}}.journey-copy b{{color:var(--navy);font-size:1.7rem;line-height:1}}.journey-copy small{{grid-column:1/-1;color:var(--muted);font-size:.73rem}}.journey-meter{{height:9px;background:#eeeef1}}.journey-meter i{{display:block;width:var(--share);height:100%;background:var(--burgundy)}}.journey-band.outcome-muted .journey-meter i{{background:var(--muted)}}.matrix,.heatmap{{display:grid;grid-template-columns:minmax(100px,1.2fr) repeat(var(--columns),minmax(100px,1fr));gap:1px;background:var(--rule);border:1px solid var(--rule)}}.matrix>* ,.heatmap>*{{display:grid;place-items:center;min-height:72px;padding:12px;background:var(--surface);text-align:center}}.matrix-head,.heatmap>span{{color:var(--muted);font-size:.72rem;text-transform:uppercase;letter-spacing:.08em}}.matrix-cell,.heat-cell{{color:inherit;text-decoration:none;transition:background-color 180ms var(--ease),color 180ms var(--ease)}}.matrix-cell:hover,.matrix-cell:focus-visible,.matrix-cell[aria-current=true],.heat-cell:hover,.heat-cell:focus-visible,.heat-cell[aria-current=true]{{position:relative;z-index:1;outline:3px solid var(--focus);outline-offset:-3px;background:var(--tint)}}.matrix-cell b{{font-size:1.65rem}}.withheld{{background:repeating-linear-gradient(135deg,#f2f1f3 0,#f2f1f3 5px,#e7e6e9 5px,#e7e6e9 6px)!important;color:var(--muted)}}
.upset{{max-width:820px}}.signal-legend{{display:flex;flex-wrap:wrap;gap:14px;margin-bottom:20px;color:var(--muted);font-size:.76rem}}.signal-legend span{{display:flex;align-items:center;gap:6px}}.signal-legend i{{width:9px;height:9px;background:var(--navy)}}.upset-row{{display:grid;grid-template-columns:120px minmax(0,1fr) 60px;gap:18px;align-items:center;padding:12px 8px;border-bottom:1px solid var(--rule);color:inherit;text-decoration:none;transition:background-color 180ms var(--ease)}}.upset-row:hover,.upset-row:focus-visible,.upset-row[aria-current=true]{{background:var(--tint)}}.signal-set{{display:flex;justify-content:space-around}}.signal-set i{{width:13px;height:13px;border:1px solid var(--rule);border-radius:50%}}.signal-set i.on{{border-color:var(--burgundy);background:var(--burgundy)}}.intersection-bar{{height:22px;background:#eeeef1}}.intersection-bar i{{display:block;width:var(--size);height:100%;background:var(--navy)}}.heat-cell{{font-weight:800}}.level-0{{color:var(--muted)}}.level-1{{background:#f9e6eb!important}}.level-2{{background:#e4b7c2!important}}.level-3{{color:white;background:#ad5369!important}}.level-4{{color:white;background:var(--burgundy)!important}}
.composition-row{{display:grid;grid-template-columns:minmax(180px,1fr) 2fr 110px;gap:20px;align-items:center;padding:18px 8px;border-bottom:1px solid var(--rule);color:inherit;text-decoration:none;transition:background-color 180ms var(--ease)}}.composition-row:hover,.composition-row:focus-visible,.composition-row[aria-current=true]{{background:var(--tint)}}.composition-row span>*{{display:block}}.composition-row small{{color:var(--muted)}}.composition-row>i,.artifact>i{{height:10px;background:#eeeef1}}.composition-row>i b,.artifact>i span{{display:block;width:var(--size);height:100%;background:var(--burgundy)}}.composition-row em{{font-style:normal;font-weight:800;text-align:right}}.artifacts{{display:grid;grid-template-columns:repeat(2,1fr);gap:1px;background:var(--rule)}}.artifact{{display:grid;gap:14px;padding:28px;color:inherit;background:var(--surface);text-decoration:none;transition:background-color 180ms var(--ease)}}.artifact:hover,.artifact:focus-visible,.artifact[aria-current=true]{{position:relative;z-index:1;background:var(--tint);outline:3px solid var(--focus);outline-offset:-3px}}.artifact>b{{color:var(--navy);font-size:1.8rem}}.status,.state{{width:max-content;padding:5px 8px;font-size:.66rem;font-weight:850;letter-spacing:.08em;text-transform:uppercase}}.status-complete,.state-ready,.state-validated{{color:var(--success);background:#e8f4ed}}.status-partial,.state-pending{{color:#735000;background:#fff4cc}}.state-off,.state-not_enabled{{color:var(--muted);background:#eeeef1}}.readiness-grid{{display:grid;grid-template-columns:1fr 1fr;gap:48px}}.readiness-grid h3{{color:var(--navy)}}.readiness-grid ul{{margin:0;padding:0;border-top:1px solid var(--navy);list-style:none}}.readiness-grid li{{display:grid;grid-template-columns:auto 1fr auto;gap:12px;align-items:center;padding:16px 0;border-bottom:1px solid var(--rule)}}.readiness-grid p{{grid-column:2/-1;margin:0;color:var(--muted);font-size:.8rem}}.readiness-grid small{{color:var(--muted)}}
.inspector{{display:grid;grid-template-columns:minmax(150px,.7fr) minmax(150px,.6fr) minmax(280px,1.4fr);gap:6px 28px;align-items:end;margin-top:24px;padding:18px 0;border-top:2px solid var(--burgundy);border-bottom:1px solid var(--rule);background:var(--paper)}}.inspector>span{{grid-column:1/-1;color:var(--burgundy);font-size:.66rem;font-weight:850;letter-spacing:.12em;text-transform:uppercase}}.inspector strong{{color:var(--navy);font-size:1.05rem}}.inspector b{{color:var(--burgundy);font-size:1.45rem}}.inspector p{{margin:0;color:var(--muted);font-size:.8rem}}.inspector.updated{{animation:inspector-update 420ms var(--ease)}}@keyframes inspector-update{{0%{{background:var(--tint)}}100%{{background:var(--paper)}}}}.mode-switch{{display:flex;justify-content:flex-end;gap:1px;margin:0 0 20px}}.mode-switch button{{min-width:92px;padding:9px 12px;border:1px solid var(--rule);color:var(--muted);background:var(--surface);font-size:.72rem;font-weight:800;cursor:pointer}}.mode-switch button[aria-pressed=true]{{border-color:var(--burgundy);color:white;background:var(--burgundy)}}.data-fallback{{margin-top:20px;border-top:1px solid var(--rule)}}details.data-fallback>summary{{padding:14px 0;color:var(--burgundy);font-size:.72rem;font-weight:850;letter-spacing:.08em;text-transform:uppercase;cursor:pointer}}table{{width:100%;border-collapse:collapse;font-size:.82rem}}caption{{padding:12px 0;color:var(--muted);text-align:left}}th,td{{padding:10px;border-bottom:1px solid var(--rule);text-align:left}}details.methodology{{max-width:920px;border-top:1px solid var(--navy)}}details.methodology summary{{padding:18px 0;color:var(--navy);font-weight:800;cursor:pointer}}details.methodology p{{max-width:72ch;color:var(--muted)}}.synthetic-flag{{position:sticky;z-index:10;bottom:0;padding:10px 24px;color:var(--paper);background:var(--burgundy);font-size:.72rem;font-weight:850;letter-spacing:.1em;text-align:center;text-transform:uppercase}}.print-button{{margin-top:28px;padding:14px 18px;border:0;color:white;background:var(--burgundy);font-weight:800;cursor:pointer}}footer{{padding:36px 40px;color:#c4c3ce;background:var(--navy);font-size:.76rem}}.js-only{{display:none}}.js .js-only{{display:block}}.js .mode-switch{{display:flex}}noscript p{{margin:0;padding:12px 24px;background:#fff4cc;text-align:center}}
.reveal{{opacity:1;transform:none}}.js .reveal{{opacity:0;transform:translateY(10px);transition:opacity 600ms var(--ease) var(--delay,0ms),transform 600ms var(--ease) var(--delay,0ms)}}.js .reveal.visible{{opacity:1;transform:none}}.evidence-pulse{{animation:evidence-pulse 700ms var(--ease)}}@keyframes evidence-pulse{{0%{{background:var(--tint)}}100%{{background:inherit}}}}
@media(max-width:840px){{.cover{{min-height:52vh;padding:18px 24px}}.cover .brand{{height:64px}}.cover h1{{font-size:2.75rem}}.cover .dek{{margin-top:14px;font-size:.96rem}}.cover-meta span{{padding:10px 0}}.signature,.funnel,.artifacts,.readiness-grid,.cockpit-ledger{{grid-template-columns:1fr}}.cockpit{{padding:44px 24px}}.cockpit-head{{grid-template-columns:1fr}}.cockpit-ledger a,.cockpit-ledger a:nth-child(odd),.cockpit-ledger a:nth-child(even){{padding:20px 0;border-left:0}}.shell{{display:block}}nav{{display:none}}.section{{padding:64px 24px}}.section-head{{grid-template-columns:1fr;gap:20px}}.journey-level{{grid-template-columns:1fr;gap:8px}}.journey-level-label{{padding-top:0}}.journey-bands{{display:grid;grid-template-columns:1fr}}.journey-band{{min-width:0}}.matrix,.heatmap{{font-size:.75rem;grid-template-columns:minmax(82px,1fr) repeat(var(--columns),minmax(82px,1fr));overflow:auto}}.composition-row{{grid-template-columns:1fr auto;gap:8px}}.composition-row>i{{grid-column:1/-1;grid-row:2}}.composition-row em{{grid-column:2;grid-row:1;text-align:right}}.inspector{{grid-template-columns:1fr;gap:6px;padding:16px 0}}.inspector>span{{grid-column:1}}.mode-switch{{justify-content:flex-start}}}}
@media (prefers-reduced-motion:reduce){{html{{scroll-behavior:auto}}*,*::before,*::after{{animation:none!important;transition:none!important}}.js .reveal{{opacity:1;transform:none}}}}
@page{{size:A4;margin:14mm 13mm 15mm}}@media print{{html,body{{background:white;font-size:9pt}}.cover{{min-height:257mm;padding:18mm 12mm;break-after:page}}.cover h1{{font-size:54pt}}.shell{{display:block}}nav,.progress,.print-button,.synthetic-flag,.js-only,noscript,.cockpit,.inspector,.mode-switch{{display:none!important}}.section{{padding:8mm 0;background:white!important;break-before:page;border:0}}.section-head{{margin-bottom:6mm}}h2{{font-size:25pt}}.signature,.funnel{{grid-template-columns:repeat(3,1fr)}}.artifacts,.readiness-grid{{grid-template-columns:repeat(2,1fr)}}.signature,.funnel{{break-inside:avoid}}.chart-frame{{padding:3mm}}.volume-funnel{{gap:3mm}}.journey-level{{grid-template-columns:28mm minmax(0,1fr);gap:3mm}}.journey-band{{min-width:0;padding:3mm}}details.data-fallback{{display:block!important;overflow:visible}}details.data-fallback>summary{{display:none!important}}details.data-fallback>*:not(summary){{display:table-row-group}}details.data-fallback>table{{display:table!important}}table{{font-size:7.5pt}}th,td{{padding:2mm}}.matrix>*,.heatmap>*{{min-height:14mm;padding:2mm}}.readiness-grid{{gap:8mm}}#evidence{{font-size:8pt}}#evidence .section-head{{margin-bottom:3mm}}#evidence h2{{font-size:18pt}}#evidence h3{{margin:4mm 0 2mm!important}}#evidence .composition-row{{padding:1mm 0}}#evidence .artifact{{padding:2mm}}#evidence .data-fallback{{margin-top:1mm}}.reveal,.js .reveal{{opacity:1!important;transform:none!important}}footer{{display:none}}}}
</style></head><body>
<a class="skip" href="#report">Skip to report</a><div class="progress js-only" data-progress></div>
<header class="cover"><img class="brand" src="{logo}" alt="START Warsaw"><div class="cover-copy"><p class="eyebrow">{escape(synthetic)}</p><h1>{escape(metadata.title)}</h1><p class="dek">A 90-second evidence briefing on attendance, participant paths, submitted work, builder signals, and the readiness of START-owned artifacts.</p></div><div class="cover-meta"><span>Event<strong>{escape(metadata.event_name)}</strong></span><span>Event date<strong>{escape(metadata.event_date)}</strong></span><span>Evidence state<strong>{escape(report.privacy.state.replace('_',' ').title())}</strong></span></div></header>
<noscript><p>All evidence and tables remain available without JavaScript.</p></noscript>
{_cockpit(report)}
<div class="shell"><nav aria-label="Report sections"><strong>Evidence map</strong><a href="#attendance">01 Attendance</a><a href="#journey">02 Journey</a><a href="#submissions">03 Submissions</a><a href="#signals">04 Signals</a><a href="#domains">05 Domains</a><a href="#evidence">06 Evidence</a><a href="#readiness">07 Readiness</a></nav><main id="report">
<section class="section" id="attendance" data-section="attendance"><div class="section-head"><div><p class="kicker">01 · Attendance signature</p><h2>Approved people showed up and shipped.</h2></div><p class="scope">Scope: {escape(report.attendance_funnel.unit)}. Counts are validated contract aggregates. No team or project units appear in this exhibit.</p></div>{_mode_switch("attendance", "People", "Conversion")}<div class="signature"><div><b>{escape(_count(approved))}</b><span>approved people</span></div><div><b>{escape(_count(checked_in))}</b><span>checked in</span></div><div><b>{escape(_count(submitted))}</b><span>submitted</span></div></div>{_attendance(report)}</section>
<section class="section" id="journey" data-section="journey"><div class="section-head"><div><p class="kicker">02 · Participant journey</p><h2>Checked-in people split between team and solo paths.</h2></div><p class="scope">Scope: people only. Flow width encodes published people counts; it never mixes teams or projects.</p></div>{_journey(report)}</section>
<section class="section" id="submissions" data-section="submissions"><div class="section-head"><div><p class="kicker">03 · Track and submission state</p><h2>Track output is visible without exposing small teams.</h2></div><p class="scope">Scope: teams. Hatched cells are withheld, not zero. Matrix geometry remains stable across privacy states.</p></div>{_matrix(report)}</section>
<section class="section" id="signals" data-section="signals"><div class="section-head"><div><p class="kicker">04 · Builder signal intersections</p><h2>START owns overlapping evidence of prior building.</h2></div><p class="scope">Scope: people. Each row is an aggregate intersection, not a participant-level profile.</p></div>{_intersections(report)}</section>
<section class="section" id="domains" data-section="domains"><div class="section-head"><div><p class="kicker">05 · Track and project domain</p><h2>Project concentration differs by track.</h2></div><p class="scope">Scope: projects. Color intensity encodes published project count; hatching marks withheld cells.</p></div>{_heatmap(report)}</section>
<section class="section" id="evidence" data-section="evidence"><div class="section-head"><div><p class="kicker">06 · Evidence composition</p><h2>Participant composition and artifact coverage stay distinct.</h2></div><p class="scope">Composition uses people. Artifact completeness uses eligible projects. The exhibits never combine denominators.</p></div><h3>Cohort composition</h3>{_mode_switch("composition", "People", "Share")}{_composition(report)}<h3 style="margin-top:52px">Artifact completeness</h3>{_mode_switch("artifacts", "Count", "Coverage")}{_artifacts(report)}</section>
<section class="section" id="readiness" data-section="readiness"><div class="section-head"><div><p class="kicker">07 · Data readiness</p><h2>Observed, withheld, pending, and off are explicit.</h2></div><p class="scope">Generated {escape(metadata.generated_at)}. Contract {escape(metadata.contract_version)}. Publication state: {escape(metadata.publication_state)}.</p></div>{_readiness(report)}<details class="methodology" open data-methodology><summary>Methodology</summary><p>The renderer consumes only the frozen, validated aggregate contract. Published counts are either zero or at least k={report.privacy.minimum_count}. Small non-zero cells remain withheld with their reason. The artifact contains no participant records, contact details, profile URLs, free text, partner outcomes, or local source paths.</p><p>This example is synthetic. Its values demonstrate layout and disclosure behavior and must not be presented as observed event performance.</p></details><button class="print-button js-only" type="button" data-print>Print report</button></section>
</main></div><div class="synthetic-flag">{escape(synthetic)} · Do not distribute as observed event evidence</div><footer>START Warsaw · Talent Data Room · {escape(metadata.contract_version)}</footer>
<script>{analytics}
(()=>{{
  const allowed=new Set(['report_opened','section_viewed','exhibit_mode_changed','methodology_opened','evidence_link_followed','datum_inspected','report_completed','print_requested']);
  const send=(event,properties={{}})=>{{
    if(!allowed.has(event)||!window.reportAnalytics)return;
    const cfg=window.reportAnalytics;
    const body=JSON.stringify({{api_key:cfg.key,event,properties:{{report_version:{_script_json(metadata.contract_version)},event_key:{_script_json(metadata.event_key)},...properties}}}});
    navigator.sendBeacon?.(cfg.host+'/capture/',new Blob([body],{{type:'application/json'}}))||fetch(cfg.host+'/capture/',{{method:'POST',mode:'no-cors',keepalive:true,headers:{{'content-type':'application/json'}},body}})
  }};
  send('report_opened');
  const fallbackTables=[...document.querySelectorAll('details.data-fallback')];
  fallbackTables.forEach(details=>{{details.open=false}});
  let printOpenState=[];
  addEventListener('beforeprint',()=>{{
    printOpenState=fallbackTables.map(details=>details.open);
    fallbackTables.forEach(details=>{{details.open=true}})
  }});
  addEventListener('afterprint',()=>{{
    fallbackTables.forEach((details,index)=>{{details.open=printOpenState[index]??false}})
  }});
  document.querySelectorAll('.reveal').forEach(el=>{{
    if(!('IntersectionObserver'in window))return el.classList.add('visible');
    new IntersectionObserver((entries,observer)=>entries.forEach(entry=>{{
      if(entry.isIntersecting){{entry.target.classList.add('visible');observer.unobserve(entry.target)}}
    }}),{{threshold:.12}}).observe(el)
  }});
  const sections=[...document.querySelectorAll('[data-section]')];
  const seen=new Set();
  if('IntersectionObserver'in window){{
    const observer=new IntersectionObserver(entries=>entries.forEach(entry=>{{
      if(!entry.isIntersecting)return;
      const key=entry.target.dataset.section;
      document.querySelectorAll('nav a').forEach(link=>link.setAttribute('aria-current',String(link.hash==='#'+entry.target.id)));
      if(!seen.has(key)){{seen.add(key);send('section_viewed',{{section_key:key}})}}
      if(key==='readiness')send('report_completed')
    }}),{{rootMargin:'-25% 0px -60%'}});
    sections.forEach(section=>observer.observe(section))
  }}
  document.querySelectorAll('[data-inspect]').forEach(mark=>mark.addEventListener('click',event=>{{
    event.preventDefault();
    const chartKey=mark.dataset.inspect;
    const inspector=document.querySelector(`[data-inspector="${{chartKey}}"]`);
    if(!inspector)return;
    document.querySelectorAll(`[data-inspect="${{chartKey}}"]`).forEach(peer=>peer.setAttribute('aria-current',String(peer===mark)));
    inspector.querySelector('[data-inspector-title]').textContent=mark.dataset.title;
    inspector.querySelector('[data-inspector-value]').textContent=mark.dataset.value;
    inspector.querySelector('[data-inspector-note]').textContent=mark.dataset.note;
    inspector.classList.remove('updated');void inspector.offsetWidth;inspector.classList.add('updated');
    send('datum_inspected',{{chart_key:chartKey,datum_key:mark.dataset.datumKey}})
  }}));
  document.querySelectorAll('[data-mode-group]').forEach(control=>{{
    control.querySelectorAll('[data-mode-value]').forEach(button=>button.addEventListener('click',()=>{{
      const alternate=button.dataset.modeValue==='rate';
      control.querySelectorAll('[data-mode-value]').forEach(peer=>peer.setAttribute('aria-pressed',String(peer===button)));
      document.querySelectorAll(`[data-mode-display="${{control.dataset.modeGroup}}"]`).forEach(value=>{{
        value.textContent=alternate?value.dataset.alternate:value.dataset.primary
      }});
      send('exhibit_mode_changed',{{chart_key:control.dataset.modeGroup,display_mode:button.dataset.modeValue}})
    }}))
  }});
  document.querySelectorAll('[data-evidence-target]').forEach(link=>link.addEventListener('click',()=>{{
    const section=document.getElementById(link.dataset.evidenceTarget);
    if(section){{section.classList.remove('evidence-pulse');void section.offsetWidth;section.classList.add('evidence-pulse')}}
    send('evidence_link_followed',{{section_key:link.dataset.evidenceTarget}})
  }}));
  const progress=document.querySelector('[data-progress]');
  addEventListener('scroll',()=>{{const range=document.documentElement.scrollHeight-innerHeight;progress.style.transform=`scaleX(${{range?scrollY/range:0}})`}},{{passive:true}});
  document.querySelector('[data-methodology]')?.addEventListener('toggle',event=>event.target.open&&send('methodology_opened',{{section_key:'readiness'}}));
  document.querySelector('[data-print]')?.addEventListener('click',()=>{{send('print_requested');print()}})
}})();
</script></body></html>'''
