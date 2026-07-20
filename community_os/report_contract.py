"""Frozen aggregate-only data contract for the talent report v3 renderer."""

from __future__ import annotations

from dataclasses import dataclass, fields, is_dataclass
import json
from pathlib import Path
import re
from typing import Any, Iterable

from community_os.privacy_text import STABLE_PSEUDONYM_RE


class ReportContractError(ValueError):
    """Raised when a talent report payload is unsafe or structurally invalid."""


@dataclass(frozen=True)
class CountValue:
    value: int | None
    privacy: str
    reason: str | None


@dataclass(frozen=True)
class ReportMetadata:
    contract_version: str
    title: str
    event_key: str
    event_name: str
    event_date: str
    generated_at: str
    synthetic: bool
    publication_state: str


@dataclass(frozen=True)
class PrivacyState:
    mode: str
    minimum_count: int
    pii_included: bool
    state: str


@dataclass(frozen=True)
class FunnelStage:
    key: str
    label: str
    order: int
    count: CountValue


@dataclass(frozen=True)
class AttendanceFunnel:
    unit: str
    stages: tuple[FunnelStage, ...]


@dataclass(frozen=True)
class JourneyNode:
    key: str
    label: str
    order: int
    count: CountValue
    unit: str


@dataclass(frozen=True)
class JourneyLink:
    source: str
    target: str
    count: CountValue
    unit: str


@dataclass(frozen=True)
class Journey:
    unit: str
    nodes: tuple[JourneyNode, ...]
    links: tuple[JourneyLink, ...]


@dataclass(frozen=True)
class MatrixCell:
    row: str
    column: str
    count: CountValue


@dataclass(frozen=True)
class TeamSubmissionMatrix:
    unit: str
    row_keys: tuple[str, ...]
    column_keys: tuple[str, ...]
    cells: tuple[MatrixCell, ...]


@dataclass(frozen=True)
class SignalIntersection:
    signals: tuple[str, ...]
    count: CountValue


@dataclass(frozen=True)
class BuilderSignalIntersections:
    unit: str
    signal_keys: tuple[str, ...]
    intersections: tuple[SignalIntersection, ...]


@dataclass(frozen=True)
class HeatmapCell:
    track: str
    domain: str
    count: CountValue


@dataclass(frozen=True)
class TrackDomainHeatmap:
    unit: str
    track_keys: tuple[str, ...]
    domain_keys: tuple[str, ...]
    cells: tuple[HeatmapCell, ...]


@dataclass(frozen=True)
class CompositionCategory:
    key: str
    label: str
    count: CountValue


@dataclass(frozen=True)
class Composition:
    unit: str
    categories: tuple[CompositionCategory, ...]


@dataclass(frozen=True)
class ArtifactItem:
    key: str
    label: str
    status: str
    present: CountValue
    eligible: CountValue


@dataclass(frozen=True)
class ArtifactCompleteness:
    unit: str
    items: tuple[ArtifactItem, ...]


@dataclass(frozen=True)
class ReadinessItem:
    component: str
    state: str
    required: bool
    note: str


@dataclass(frozen=True)
class SourceNote:
    source: str
    state: str
    note: str


@dataclass(frozen=True)
class TalentReportContract:
    metadata: ReportMetadata
    privacy: PrivacyState
    attendance_funnel: AttendanceFunnel
    journey: Journey
    team_submission_matrix: TeamSubmissionMatrix
    builder_signal_intersections: BuilderSignalIntersections
    track_domain_heatmap: TrackDomainHeatmap
    composition: Composition
    artifact_completeness: ArtifactCompleteness
    readiness: tuple[ReadinessItem, ...]
    source_notes: tuple[SourceNote, ...]


_KEY_RE = re.compile(r"^[a-z][a-z0-9_]*$")
_EVENT_KEY_RE = re.compile(r"^[a-z0-9]+(?:[-_][a-z0-9]+)*$")
_PII_RE = re.compile(r"(?:[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}|https?://|www\.)", re.IGNORECASE)
_UNITS = {"people", "teams", "projects"}


def _object(value: object, path: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ReportContractError(f"{path} must be an object")
    return value


def _exact(value: object, keys: set[str], path: str) -> dict[str, Any]:
    raw = _object(value, path)
    missing = sorted(keys - set(raw))
    extra = sorted(set(raw) - keys)
    if missing or extra:
        details = []
        if missing:
            details.append("missing " + ", ".join(missing))
        if extra:
            details.append("unexpected " + ", ".join(extra))
        raise ReportContractError(f"{path} has invalid keys: {'; '.join(details)}")
    return raw


def _list(value: object, path: str, *, nonempty: bool = True) -> list[Any]:
    if not isinstance(value, list) or (nonempty and not value):
        qualifier = "non-empty " if nonempty else ""
        raise ReportContractError(f"{path} must be a {qualifier}list")
    return value


def _string(value: object, path: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ReportContractError(f"{path} must be a non-empty string")
    return value.strip()


def _key(value: object, path: str) -> str:
    result = _string(value, path)
    if not _KEY_RE.fullmatch(result):
        raise ReportContractError(f"{path} must be a lower_snake_case key")
    return result


def _event_key(value: object, path: str) -> str:
    result = _string(value, path)
    if not _EVENT_KEY_RE.fullmatch(result):
        raise ReportContractError(f"{path} must be a lowercase event slug")
    return result


def _integer(value: object, path: str, *, minimum: int = 0) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        raise ReportContractError(f"{path} must be an integer >= {minimum}")
    return value


def _boolean(value: object, path: str) -> bool:
    if not isinstance(value, bool):
        raise ReportContractError(f"{path} must be a boolean")
    return value


def _choice(value: object, choices: set[str], path: str) -> str:
    result = _string(value, path)
    if result not in choices:
        raise ReportContractError(f"{path} must be one of {', '.join(sorted(choices))}")
    return result


def _unit(value: object, path: str) -> str:
    return _choice(value, _UNITS, path)


def _unique(values: Iterable[str], path: str) -> tuple[str, ...]:
    result = tuple(values)
    if len(result) != len(set(result)):
        raise ReportContractError(f"{path} contains duplicates")
    return result


def _count(value: object, path: str, minimum_count: int) -> CountValue:
    raw = _exact(value, {"value", "privacy", "reason"}, path)
    privacy = _choice(raw["privacy"], {"published", "withheld"}, f"{path}.privacy")
    reason = raw["reason"]
    if privacy == "withheld":
        if raw["value"] is not None:
            raise ReportContractError(f"{path} withheld value must be null")
        if not isinstance(reason, str) or not reason.strip():
            raise ReportContractError(f"{path} withheld count requires a reason")
        reason_text = _string(reason, f"{path}.reason")
        return CountValue(None, privacy, reason_text)
    if reason is not None:
        raise ReportContractError(f"{path} published count reason must be null")
    published = _integer(raw["value"], f"{path}.value")
    if 0 < published < minimum_count:
        raise ReportContractError(
            f"{path}.value is below minimum_count {minimum_count}; withhold it instead"
        )
    return CountValue(published, privacy, None)


def _scan_for_pii(value: object, path: str = "report") -> None:
    if isinstance(value, str) and (
        _PII_RE.search(value) or STABLE_PSEUDONYM_RE.search(value)
    ):
        raise ReportContractError(f"{path} contains PII-like or link-like content")
    if isinstance(value, dict):
        for key, child in value.items():
            _scan_for_pii(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _scan_for_pii(child, f"{path}[{index}]")


def _metadata(value: object) -> ReportMetadata:
    raw = _exact(value, {
        "contract_version", "title", "event_key", "event_name", "event_date",
        "generated_at", "synthetic", "publication_state",
    }, "metadata")
    version = _string(raw["contract_version"], "metadata.contract_version")
    if version != "talent-report-v3":
        raise ReportContractError("metadata.contract_version must be talent-report-v3")
    return ReportMetadata(
        version,
        _string(raw["title"], "metadata.title"),
        _event_key(raw["event_key"], "metadata.event_key"),
        _string(raw["event_name"], "metadata.event_name"),
        _string(raw["event_date"], "metadata.event_date"),
        _string(raw["generated_at"], "metadata.generated_at"),
        _boolean(raw["synthetic"], "metadata.synthetic"),
        _choice(raw["publication_state"], {"draft", "review_ready", "published"},
                "metadata.publication_state"),
    )


def _privacy(value: object) -> PrivacyState:
    raw = _exact(value, {"mode", "minimum_count", "pii_included", "state"}, "privacy")
    minimum = _integer(raw["minimum_count"], "privacy.minimum_count")
    if minimum < 5:
        raise ReportContractError("privacy.minimum_count must be at least 5")
    mode = _choice(raw["mode"], {"aggregate_only"}, "privacy.mode")
    pii = _boolean(raw["pii_included"], "privacy.pii_included")
    if pii:
        raise ReportContractError("privacy.pii_included must be false")
    return PrivacyState(
        mode, minimum, pii,
        _choice(raw["state"], {"safe", "withheld_cells", "blocked"}, "privacy.state"),
    )


def _attendance_funnel(value: object, minimum: int) -> AttendanceFunnel:
    raw = _exact(value, {"unit", "stages"}, "attendance_funnel")
    unit = _unit(raw["unit"], "attendance_funnel.unit")
    if unit != "people":
        raise ReportContractError("attendance_funnel.unit must be people")
    stages = []
    for index, value in enumerate(_list(raw["stages"], "attendance_funnel.stages")):
        path = f"attendance_funnel.stages[{index}]"
        item = _exact(value, {"key", "label", "order", "count"}, path)
        stages.append(FunnelStage(
            _key(item["key"], f"{path}.key"),
            _string(item["label"], f"{path}.label"),
            _integer(item["order"], f"{path}.order", minimum=1),
            _count(item["count"], f"{path}.count", minimum),
        ))
    _unique((stage.key for stage in stages), "attendance_funnel stage keys")
    _unique((str(stage.order) for stage in stages), "attendance_funnel stage order")
    ordered = tuple(sorted(stages, key=lambda stage: stage.order))
    visible = [stage.count.value for stage in ordered if stage.count.value is not None]
    if visible != sorted(visible, reverse=True):
        raise ReportContractError("attendance_funnel published stages must be non-increasing")
    for parent, child in zip(ordered, ordered[1:]):
        if parent.count.value is None or child.count.value is None:
            continue
        if 0 < parent.count.value - child.count.value < minimum:
            raise ReportContractError(
                "attendance_funnel contains a below-threshold stage dropoff"
            )
    return AttendanceFunnel(unit, ordered)


def _journey(value: object, minimum: int, *, synthetic: bool) -> Journey:
    raw = _exact(value, {"unit", "nodes", "links"}, "journey")
    unit = _unit(raw["unit"], "journey.unit")
    nodes = []
    for index, value in enumerate(_list(raw["nodes"], "journey.nodes")):
        path = f"journey.nodes[{index}]"
        item = _exact(value, {"key", "label", "order", "count", "unit"}, path)
        node_unit = _unit(item["unit"], f"{path}.unit")
        if node_unit != unit:
            raise ReportContractError(f"{path} unit does not match journey unit")
        nodes.append(JourneyNode(
            _key(item["key"], f"{path}.key"),
            _string(item["label"], f"{path}.label"),
            _integer(item["order"], f"{path}.order", minimum=1),
            _count(item["count"], f"{path}.count", minimum),
            node_unit,
        ))
    node_keys = _unique((node.key for node in nodes), "journey node keys")
    _unique((str(node.order) for node in nodes), "journey node order")
    node_by_key = {node.key: node for node in nodes}
    applied_node = node_by_key.get("applied")
    accepted_node = node_by_key.get("going_accepted") or node_by_key.get("accepted")
    not_accepted_nodes = [
        node for node in nodes if node.key.startswith("not_accepted")
    ]
    if (
        applied_node is not None
        and applied_node.count.value is not None
        and accepted_node is not None
        and not_accepted_nodes
    ):
        partition_nodes = [accepted_node, *not_accepted_nodes]
        withheld_nodes = sum(node.count.value is None for node in partition_nodes)
        published_partition = sum(
            node.count.value or 0 for node in partition_nodes
            if node.count.value is not None
        )
        if withheld_nodes == 1:
            raise ReportContractError(
                "journey cannot contain a single withheld exact complement"
            )
        if (
            withheld_nodes > 0
            and 0 < applied_node.count.value - published_partition < minimum
        ):
            raise ReportContractError(
                "journey cannot expose a below-threshold withheld node remainder"
            )
    links = []
    for index, value in enumerate(_list(raw["links"], "journey.links", nonempty=False)):
        path = f"journey.links[{index}]"
        item = _exact(value, {"source", "target", "count", "unit"}, path)
        source = _key(item["source"], f"{path}.source")
        target = _key(item["target"], f"{path}.target")
        link_unit = _unit(item["unit"], f"{path}.unit")
        if link_unit != unit:
            raise ReportContractError(f"{path} unit does not match journey unit")
        if source not in node_keys or target not in node_keys:
            raise ReportContractError(f"{path} references an unknown node")
        if source == target:
            raise ReportContractError(f"{path} cannot link a node to itself")
        if node_by_key[source].order >= node_by_key[target].order:
            raise ReportContractError(f"{path} must flow forward in stage order")
        count = _count(item["count"], f"{path}.count", minimum)
        if count.value is not None:
            for endpoint in (node_by_key[source], node_by_key[target]):
                if endpoint.count.value is not None and count.value > endpoint.count.value:
                    raise ReportContractError(f"{path} count exceeds an endpoint node count")
            source_value = node_by_key[source].count.value
            target_value = node_by_key[target].count.value
            if (
                source_value is not None
                and target_value is not None
                and 0 < source_value - target_value < minimum
            ):
                raise ReportContractError(
                    f"{path} exposes a below-threshold nested cohort remainder"
                )
        links.append(JourneyLink(source, target, count, link_unit))
    _unique((f"{link.source}->{link.target}" for link in links), "journey links")
    if not synthetic:
        public_nodes = {
            "applied", "going_accepted", "not_accepted_reason_unknown", "on_site",
        }
        public_links = {
            "applied->going_accepted",
            "applied->not_accepted_reason_unknown",
            "going_accepted->on_site",
        }
        operator_nodes = {"approved", "checked_in", "team_path", "solo_path"}
        operator_links = {
            "approved->checked_in",
            "checked_in->team_path",
            "checked_in->solo_path",
        }
        topology = (set(node_by_key), {
            f"{link.source}->{link.target}" for link in links
        })
        if topology not in (
            (public_nodes, public_links),
            (operator_nodes, operator_links),
        ):
            raise ReportContractError(
                "non-synthetic report requires a closed real journey topology"
            )
        for link in links:
            if link.count != node_by_key[link.target].count:
                raise ReportContractError(
                    "real journey link count must equal its target node count"
                )
        if topology == (public_nodes, public_links):
            source = node_by_key["applied"].count.value
            partition = (
                node_by_key["going_accepted"].count.value,
                node_by_key["not_accepted_reason_unknown"].count.value,
            )
            partition_name = "accepted outcomes"
        else:
            source = node_by_key["checked_in"].count.value
            partition = (
                node_by_key["team_path"].count.value,
                node_by_key["solo_path"].count.value,
            )
            partition_name = "attendance paths"
        if source is not None and all(value is not None for value in partition):
            if sum(value for value in partition if value is not None) != source:
                raise ReportContractError(
                    f"real journey {partition_name} must reconcile to their source"
                )
    for node in nodes:
        outgoing_links = [link for link in links if link.source == node.key]
        withheld_outgoing = sum(link.count.value is None for link in outgoing_links)
        published_outgoing = sum(
            link.count.value or 0 for link in outgoing_links
            if link.count.value is not None
        )
        if (
            node.count.value is not None
            and len(outgoing_links) >= 2
            and withheld_outgoing == 1
        ):
            raise ReportContractError(
                "journey cannot contain a single withheld exact complement"
            )
        if (
            node.count.value is not None
            and withheld_outgoing > 0
            and 0 < node.count.value - published_outgoing < minimum
        ):
            raise ReportContractError(
                "journey cannot expose a below-threshold withheld outgoing remainder"
            )
        if node.count.value is None:
            continue
        outgoing = published_outgoing
        incoming = sum(
            link.count.value or 0 for link in links
            if link.target == node.key and link.count.value is not None
        )
        if outgoing > node.count.value:
            raise ReportContractError(
                f"journey node {node.key} outgoing links exceed its published count"
            )
        if incoming > node.count.value:
            raise ReportContractError(
                f"journey node {node.key} incoming links exceed its published count"
            )
    return Journey(
        unit,
        tuple(sorted(nodes, key=lambda node: node.order)),
        tuple(sorted(links, key=lambda link: (link.source, link.target))),
    )


def _axis(value: object, path: str) -> tuple[str, ...]:
    return _unique((_key(item, f"{path}[]") for item in _list(value, path)), path)


def _team_matrix(value: object, minimum: int) -> TeamSubmissionMatrix:
    raw = _exact(value, {"unit", "row_keys", "column_keys", "cells"},
                 "team_submission_matrix")
    unit = _unit(raw["unit"], "team_submission_matrix.unit")
    if unit != "teams":
        raise ReportContractError("team_submission_matrix.unit must be teams")
    rows = _axis(raw["row_keys"], "team_submission_matrix.row_keys")
    columns = _axis(raw["column_keys"], "team_submission_matrix.column_keys")
    cells = []
    for index, value in enumerate(_list(raw["cells"], "team_submission_matrix.cells")):
        path = f"team_submission_matrix.cells[{index}]"
        item = _exact(value, {"row", "column", "count"}, path)
        row = _key(item["row"], f"{path}.row")
        column = _key(item["column"], f"{path}.column")
        if row not in rows or column not in columns:
            raise ReportContractError(f"{path} references an unknown axis key")
        cells.append(MatrixCell(row, column, _count(item["count"], f"{path}.count", minimum)))
    actual = {(cell.row, cell.column) for cell in cells}
    expected = {(row, column) for row in rows for column in columns}
    if len(cells) != len(actual) or actual != expected:
        raise ReportContractError("team_submission_matrix cells must form one complete rectangle")
    return TeamSubmissionMatrix(
        unit, rows, columns, tuple(sorted(cells, key=lambda cell: (cell.row, cell.column)))
    )


def _builder_signals(value: object, minimum: int) -> BuilderSignalIntersections:
    raw = _exact(value, {"unit", "signal_keys", "intersections"},
                 "builder_signal_intersections")
    unit = _unit(raw["unit"], "builder_signal_intersections.unit")
    if unit != "people":
        raise ReportContractError("builder_signal_intersections.unit must be people")
    signals = _axis(raw["signal_keys"], "builder_signal_intersections.signal_keys")
    intersections = []
    for index, value in enumerate(_list(raw["intersections"],
                                        "builder_signal_intersections.intersections")):
        path = f"builder_signal_intersections.intersections[{index}]"
        item = _exact(value, {"signals", "count"}, path)
        signature = tuple(sorted(_axis(item["signals"], f"{path}.signals")))
        if not set(signature).issubset(signals):
            raise ReportContractError(f"{path}.signals references an unknown signal")
        intersections.append(SignalIntersection(
            signature, _count(item["count"], f"{path}.count", minimum)
        ))
    _unique(("|".join(item.signals) for item in intersections),
            "builder_signal_intersections signatures")
    return BuilderSignalIntersections(
        unit, signals, tuple(sorted(intersections, key=lambda item: item.signals))
    )


def _heatmap(value: object, minimum: int) -> TrackDomainHeatmap:
    raw = _exact(value, {"unit", "track_keys", "domain_keys", "cells"},
                 "track_domain_heatmap")
    unit = _unit(raw["unit"], "track_domain_heatmap.unit")
    if unit != "projects":
        raise ReportContractError("track_domain_heatmap.unit must be projects")
    tracks = _axis(raw["track_keys"], "track_domain_heatmap.track_keys")
    domains = _axis(raw["domain_keys"], "track_domain_heatmap.domain_keys")
    cells = []
    for index, value in enumerate(_list(raw["cells"], "track_domain_heatmap.cells")):
        path = f"track_domain_heatmap.cells[{index}]"
        item = _exact(value, {"track", "domain", "count"}, path)
        track = _key(item["track"], f"{path}.track")
        domain = _key(item["domain"], f"{path}.domain")
        if track not in tracks or domain not in domains:
            raise ReportContractError(f"{path} references an unknown axis key")
        cells.append(HeatmapCell(track, domain, _count(item["count"], f"{path}.count", minimum)))
    actual = {(cell.track, cell.domain) for cell in cells}
    expected = {(track, domain) for track in tracks for domain in domains}
    if len(cells) != len(actual) or actual != expected:
        raise ReportContractError("track_domain_heatmap cells must form one complete rectangle")
    return TrackDomainHeatmap(
        unit, tracks, domains, tuple(sorted(cells, key=lambda cell: (cell.track, cell.domain)))
    )


def _composition(value: object, minimum: int) -> Composition:
    raw = _exact(value, {"unit", "categories"}, "composition")
    unit = _unit(raw["unit"], "composition.unit")
    categories = []
    for index, value in enumerate(_list(raw["categories"], "composition.categories")):
        path = f"composition.categories[{index}]"
        item = _exact(value, {"key", "label", "count"}, path)
        categories.append(CompositionCategory(
            _key(item["key"], f"{path}.key"),
            _string(item["label"], f"{path}.label"),
            _count(item["count"], f"{path}.count", minimum),
        ))
    _unique((item.key for item in categories), "composition category keys")
    return Composition(unit, tuple(sorted(categories, key=lambda item: item.key)))


def _artifacts(value: object, minimum: int) -> ArtifactCompleteness:
    raw = _exact(value, {"unit", "items"}, "artifact_completeness")
    unit = _unit(raw["unit"], "artifact_completeness.unit")
    items = []
    for index, value in enumerate(_list(raw["items"], "artifact_completeness.items")):
        path = f"artifact_completeness.items[{index}]"
        item = _exact(value, {"key", "label", "status", "present", "eligible"}, path)
        status = _choice(item["status"], {"complete", "partial", "missing"}, f"{path}.status")
        present = _count(item["present"], f"{path}.present", minimum)
        eligible = _count(item["eligible"], f"{path}.eligible", minimum)
        if present.value is not None and eligible.value is not None:
            if present.value > eligible.value:
                raise ReportContractError(f"{path}.present cannot exceed eligible")
            if 0 < eligible.value - present.value < minimum:
                raise ReportContractError(
                    f"{path} exposes a below-threshold artifact complement"
                )
            if status == "complete" and present.value != eligible.value:
                raise ReportContractError(f"{path} complete status requires equal counts")
            if status == "partial" and not present.value < eligible.value:
                raise ReportContractError(f"{path} partial status requires present < eligible")
            if status == "missing" and present.value != 0:
                raise ReportContractError(f"{path} missing status requires zero present")
        items.append(ArtifactItem(
            _key(item["key"], f"{path}.key"),
            _string(item["label"], f"{path}.label"), status, present, eligible,
        ))
    _unique((item.key for item in items), "artifact_completeness item keys")
    return ArtifactCompleteness(unit, tuple(sorted(items, key=lambda item: item.key)))


def _readiness(value: object) -> tuple[ReadinessItem, ...]:
    items = []
    for index, value in enumerate(_list(value, "readiness")):
        path = f"readiness[{index}]"
        item = _exact(value, {"component", "state", "required", "note"}, path)
        items.append(ReadinessItem(
            _key(item["component"], f"{path}.component"),
            _choice(item["state"], {"ready", "pending", "blocked", "off"}, f"{path}.state"),
            _boolean(item["required"], f"{path}.required"),
            _string(item["note"], f"{path}.note"),
        ))
    _unique((item.component for item in items), "readiness components")
    return tuple(sorted(items, key=lambda item: item.component))


def _source_notes(value: object) -> tuple[SourceNote, ...]:
    items = []
    for index, value in enumerate(_list(value, "source_notes")):
        path = f"source_notes[{index}]"
        item = _exact(value, {"source", "state", "note"}, path)
        items.append(SourceNote(
            _key(item["source"], f"{path}.source"),
            _choice(item["state"], {"received", "validated", "pending", "not_enabled"},
                    f"{path}.state"),
            _string(item["note"], f"{path}.note"),
        ))
    _unique((item.source for item in items), "source_notes sources")
    return tuple(sorted(items, key=lambda item: item.source))


def _all_counts(value: object) -> Iterable[CountValue]:
    if isinstance(value, CountValue):
        yield value
    elif is_dataclass(value):
        for field in fields(value):
            yield from _all_counts(getattr(value, field.name))
    elif isinstance(value, tuple):
        for item in value:
            yield from _all_counts(item)


def load_report_contract(path: str | Path) -> TalentReportContract:
    """Load, canonicalize, and validate a talent-report-v3 JSON document."""
    source = Path(path)
    try:
        payload = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ReportContractError(f"cannot load report contract {source}: {error}") from error
    _scan_for_pii(payload)
    raw = _exact(payload, {
        "metadata", "privacy", "attendance_funnel", "journey",
        "team_submission_matrix", "builder_signal_intersections",
        "track_domain_heatmap", "composition", "artifact_completeness",
        "readiness", "source_notes",
    }, "report")
    metadata = _metadata(raw["metadata"])
    privacy = _privacy(raw["privacy"])
    report = TalentReportContract(
        metadata=metadata,
        privacy=privacy,
        attendance_funnel=_attendance_funnel(raw["attendance_funnel"], privacy.minimum_count),
        journey=_journey(
            raw["journey"], privacy.minimum_count, synthetic=metadata.synthetic,
        ),
        team_submission_matrix=_team_matrix(raw["team_submission_matrix"], privacy.minimum_count),
        builder_signal_intersections=_builder_signals(
            raw["builder_signal_intersections"], privacy.minimum_count
        ),
        track_domain_heatmap=_heatmap(raw["track_domain_heatmap"], privacy.minimum_count),
        composition=_composition(raw["composition"], privacy.minimum_count),
        artifact_completeness=_artifacts(raw["artifact_completeness"], privacy.minimum_count),
        readiness=_readiness(raw["readiness"]),
        source_notes=_source_notes(raw["source_notes"]),
    )
    has_withheld = any(item.privacy == "withheld" for item in _all_counts(report))
    if privacy.state == "safe" and has_withheld:
        raise ReportContractError("privacy.state safe cannot contain withheld cells")
    if privacy.state == "withheld_cells" and not has_withheld:
        raise ReportContractError("privacy.state withheld_cells requires at least one withheld cell")
    if metadata.publication_state == "published":
        if privacy.state == "blocked":
            raise ReportContractError("published report cannot have blocked privacy state")
        if any(item.required and item.state != "ready" for item in report.readiness):
            raise ReportContractError("published report has an unresolved required readiness gate")
    return report
