"""Validated aggregate boundary for VC and company talent-intelligence briefs."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import re
from typing import Any, Iterable

from community_os.privacy_text import STABLE_PSEUDONYM_RE


class TalentIntelligenceContractError(ValueError):
    """Raised when a talent-intelligence payload is unsafe or inconsistent."""


@dataclass(frozen=True)
class CountValue:
    value: int | None
    privacy: str
    reason: str | None


@dataclass(frozen=True)
class Metadata:
    contract_version: str
    title: str
    event_key: str
    event_name: str
    event_date: str
    generated_at: str
    synthetic: bool
    publication_state: str


@dataclass(frozen=True)
class Privacy:
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
class Cohort:
    unit: str
    denominator: CountValue
    stages: tuple[FunnelStage, ...]


@dataclass(frozen=True)
class SelectionCategory:
    key: str
    label: str
    reason_state: str
    count: CountValue


@dataclass(frozen=True)
class SelectionOutcomes:
    unit: str
    denominator_key: str
    categories: tuple[SelectionCategory, ...]


@dataclass(frozen=True)
class DimensionItem:
    key: str
    label: str
    count: CountValue
    definition: str
    evidence_sources: tuple[str, ...]


@dataclass(frozen=True)
class Dimension:
    key: str
    label: str
    mode: str
    denominator_key: str
    known_count: CountValue
    items: tuple[DimensionItem, ...]


@dataclass(frozen=True)
class Intersection:
    key: str
    label: str
    count: CountValue
    component_keys: tuple[str, ...]
    evidence_sources: tuple[str, ...]


@dataclass(frozen=True)
class QualitativeTheme:
    key: str
    label: str
    statement: str
    count: CountValue
    confidence: str
    review_state: str
    evidence_sources: tuple[str, ...]


@dataclass(frozen=True)
class EvidenceCoverage:
    source: str
    label: str
    eligible: CountValue
    covered: CountValue
    state: str
    note: str


@dataclass(frozen=True)
class ReadinessItem:
    component: str
    state: str
    required: bool
    note: str


@dataclass(frozen=True)
class FeatureGate:
    feature: str
    state: str
    required: bool
    note: str


@dataclass(frozen=True)
class SourceNote:
    source: str
    state: str
    note: str


@dataclass(frozen=True)
class TalentIntelligenceContract:
    metadata: Metadata
    privacy: Privacy
    cohort: Cohort
    selection_outcomes: SelectionOutcomes
    dimensions: tuple[Dimension, ...]
    intersections: tuple[Intersection, ...]
    qualitative_themes: tuple[QualitativeTheme, ...]
    evidence_coverage: tuple[EvidenceCoverage, ...]
    readiness: tuple[ReadinessItem, ...]
    feature_gates: tuple[FeatureGate, ...]
    source_notes: tuple[SourceNote, ...]


_KEY_RE = re.compile(r"^[a-z][a-z0-9_]*$")
_EVENT_KEY_RE = re.compile(r"^[a-z0-9]+(?:[-_][a-z0-9]+)*$")
_PII_RE = re.compile(r"(?:[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}|https?://|www\.)", re.IGNORECASE)


def _object(value: object, path: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise TalentIntelligenceContractError(f"{path} must be an object")
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
        raise TalentIntelligenceContractError(
            f"{path} has invalid keys: {'; '.join(details)}"
        )
    return raw


def _list(value: object, path: str, *, nonempty: bool = True) -> list[Any]:
    if not isinstance(value, list) or (nonempty and not value):
        qualifier = "non-empty " if nonempty else ""
        raise TalentIntelligenceContractError(f"{path} must be a {qualifier}list")
    return value


def _string(value: object, path: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise TalentIntelligenceContractError(f"{path} must be a non-empty string")
    return value.strip()


def _key(value: object, path: str) -> str:
    result = _string(value, path)
    if not _KEY_RE.fullmatch(result):
        raise TalentIntelligenceContractError(f"{path} must be a lower_snake_case key")
    return result


def _event_key(value: object, path: str) -> str:
    result = _string(value, path)
    if not _EVENT_KEY_RE.fullmatch(result):
        raise TalentIntelligenceContractError(f"{path} must be a lowercase event slug")
    return result


def _integer(value: object, path: str, *, minimum: int = 0) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        raise TalentIntelligenceContractError(f"{path} must be an integer >= {minimum}")
    return value


def _boolean(value: object, path: str) -> bool:
    if not isinstance(value, bool):
        raise TalentIntelligenceContractError(f"{path} must be a boolean")
    return value


def _choice(value: object, choices: set[str], path: str) -> str:
    result = _string(value, path)
    if result not in choices:
        raise TalentIntelligenceContractError(
            f"{path} must be one of {', '.join(sorted(choices))}"
        )
    return result


def _unique(values: Iterable[str], path: str) -> tuple[str, ...]:
    result = tuple(values)
    if len(result) != len(set(result)):
        raise TalentIntelligenceContractError(f"{path} contains duplicates")
    return result


def _count(value: object, path: str, minimum_count: int) -> CountValue:
    raw = _exact(value, {"value", "privacy", "reason"}, path)
    privacy = _choice(raw["privacy"], {"published", "withheld"}, f"{path}.privacy")
    if privacy == "withheld":
        if raw["value"] is not None:
            raise TalentIntelligenceContractError(f"{path} withheld value must be null")
        reason = _string(raw["reason"], f"{path}.reason")
        return CountValue(None, privacy, reason)
    if raw["reason"] is not None:
        raise TalentIntelligenceContractError(f"{path} published count reason must be null")
    published = _integer(raw["value"], f"{path}.value")
    if 0 < published < minimum_count:
        raise TalentIntelligenceContractError(
            f"{path}.value is below minimum_count {minimum_count}; withhold it instead"
        )
    return CountValue(published, privacy, None)


def _scan_for_pii(value: object, path: str = "contract") -> None:
    if isinstance(value, str) and (
        _PII_RE.search(value) or STABLE_PSEUDONYM_RE.search(value)
    ):
        raise TalentIntelligenceContractError(f"{path} contains PII-like or link-like content")
    if isinstance(value, dict):
        for key, child in value.items():
            _scan_for_pii(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _scan_for_pii(child, f"{path}[{index}]")


def _contains_withheld_count(value: object) -> bool:
    if isinstance(value, dict):
        if set(value) == {"value", "privacy", "reason"}:
            return value.get("privacy") == "withheld"
        return any(_contains_withheld_count(child) for child in value.values())
    if isinstance(value, list):
        return any(_contains_withheld_count(child) for child in value)
    return False


def _metadata(value: object) -> Metadata:
    raw = _exact(value, {
        "contract_version", "title", "event_key", "event_name", "event_date",
        "generated_at", "synthetic", "publication_state",
    }, "metadata")
    version = _string(raw["contract_version"], "metadata.contract_version")
    if version != "talent-intelligence-v1":
        raise TalentIntelligenceContractError(
            "metadata.contract_version must be talent-intelligence-v1"
        )
    return Metadata(
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


def _privacy(value: object) -> Privacy:
    raw = _exact(value, {"mode", "minimum_count", "pii_included", "state"}, "privacy")
    minimum = _integer(raw["minimum_count"], "privacy.minimum_count", minimum=5)
    pii = _boolean(raw["pii_included"], "privacy.pii_included")
    if pii:
        raise TalentIntelligenceContractError("privacy.pii_included must be false")
    return Privacy(
        _choice(raw["mode"], {"aggregate_only"}, "privacy.mode"),
        minimum,
        pii,
        _choice(raw["state"], {"safe", "withheld_cells", "blocked"}, "privacy.state"),
    )


def _cohort(value: object, minimum: int) -> Cohort:
    raw = _exact(value, {"unit", "denominator", "stages"}, "cohort")
    unit = _choice(raw["unit"], {"people"}, "cohort.unit")
    denominator = _count(raw["denominator"], "cohort.denominator", minimum)
    if denominator.value is None or denominator.value == 0:
        raise TalentIntelligenceContractError("cohort.denominator must be a positive published count")
    stages = []
    for index, value in enumerate(_list(raw["stages"], "cohort.stages")):
        path = f"cohort.stages[{index}]"
        item = _exact(value, {"key", "label", "order", "count"}, path)
        stages.append(FunnelStage(
            _key(item["key"], f"{path}.key"),
            _string(item["label"], f"{path}.label"),
            _integer(item["order"], f"{path}.order", minimum=1),
            _count(item["count"], f"{path}.count", minimum),
        ))
    _unique((stage.key for stage in stages), "cohort stage keys")
    _unique((str(stage.order) for stage in stages), "cohort stage orders")
    ordered = tuple(sorted(stages, key=lambda stage: stage.order))
    if ordered[0].key != "valid_applicants" or ordered[0].count.value != denominator.value:
        raise TalentIntelligenceContractError(
            "cohort first stage must be valid_applicants and equal the denominator"
        )
    visible = [stage.count.value for stage in ordered if stage.count.value is not None]
    if visible != sorted(visible, reverse=True):
        raise TalentIntelligenceContractError("cohort published stages must be non-increasing")
    for parent, child in zip(ordered, ordered[1:]):
        if parent.count.value is None or child.count.value is None:
            continue
        if 0 < parent.count.value - child.count.value < minimum:
            raise TalentIntelligenceContractError(
                "cohort contains a below-threshold stage dropoff"
            )
    return Cohort(unit, denominator, ordered)


def _selection(value: object, cohort: Cohort, minimum: int) -> SelectionOutcomes:
    raw = _exact(value, {"unit", "denominator_key", "categories"}, "selection_outcomes")
    unit = _choice(raw["unit"], {"people"}, "selection_outcomes.unit")
    denominator_key = _key(raw["denominator_key"], "selection_outcomes.denominator_key")
    if denominator_key != "valid_applicants":
        raise TalentIntelligenceContractError(
            "selection_outcomes.denominator_key must be valid_applicants"
        )
    categories = []
    for index, value in enumerate(_list(raw["categories"], "selection_outcomes.categories")):
        path = f"selection_outcomes.categories[{index}]"
        item = _exact(value, {"key", "label", "reason_state", "count"}, path)
        categories.append(SelectionCategory(
            _key(item["key"], f"{path}.key"),
            _string(item["label"], f"{path}.label"),
            _choice(item["reason_state"], {"observed", "operator_reviewed", "unknown"},
                    f"{path}.reason_state"),
            _count(item["count"], f"{path}.count", minimum),
        ))
    _unique((item.key for item in categories), "selection outcome keys")
    visible = [item.count.value for item in categories if item.count.value is not None]
    has_withheld = any(item.count.value is None for item in categories)
    withheld_count = sum(item.count.value is None for item in categories)
    if withheld_count == 1:
        raise TalentIntelligenceContractError(
            "selection outcomes cannot contain a single withheld exact complement"
        )
    total = sum(value for value in visible if value is not None)
    denominator = cohort.denominator.value or 0
    if has_withheld and 0 < denominator - total < minimum:
        raise TalentIntelligenceContractError(
            "selection outcomes contain a below-threshold withheld selection remainder"
        )
    if (not has_withheld and total != denominator) or (has_withheld and total > denominator):
        raise TalentIntelligenceContractError("selection outcomes must reconcile to valid applicants")
    return SelectionOutcomes(unit, denominator_key, tuple(sorted(categories, key=lambda item: item.key)))


def _dimensions(value: object, cohort: Cohort, minimum: int) -> tuple[Dimension, ...]:
    dimensions = []
    denominator = cohort.denominator.value or 0
    for index, value in enumerate(_list(value, "dimensions")):
        path = f"dimensions[{index}]"
        raw = _exact(value, {
            "key", "label", "mode", "denominator_key", "known_count", "items",
        }, path)
        key = _key(raw["key"], f"{path}.key")
        denominator_key = _key(raw["denominator_key"], f"{path}.denominator_key")
        if denominator_key != "valid_applicants":
            raise TalentIntelligenceContractError(f"{path}.denominator_key must be valid_applicants")
        known = _count(raw["known_count"], f"{path}.known_count", minimum)
        if known.value is None or known.value > denominator:
            raise TalentIntelligenceContractError(f"{path}.known_count must be published and within denominator")
        items = []
        for item_index, value in enumerate(_list(raw["items"], f"{path}.items")):
            item_path = f"{path}.items[{item_index}]"
            item = _exact(value, {
                "key", "label", "count", "definition", "evidence_sources",
            }, item_path)
            sources = _unique(
                (_key(source, f"{item_path}.evidence_sources[]")
                 for source in _list(item["evidence_sources"], f"{item_path}.evidence_sources")),
                f"{item_path}.evidence_sources",
            )
            count = _count(item["count"], f"{item_path}.count", minimum)
            if count.value is not None and count.value > known.value:
                raise TalentIntelligenceContractError(f"{item_path}.count exceeds known_count")
            items.append(DimensionItem(
                _key(item["key"], f"{item_path}.key"),
                _string(item["label"], f"{item_path}.label"),
                count,
                _string(item["definition"], f"{item_path}.definition"),
                sources,
            ))
        _unique((item.key for item in items), f"dimension {key} item keys")
        mode = _choice(raw["mode"], {"exclusive", "overlapping"}, f"{path}.mode")
        if mode == "exclusive":
            visible = [item.count.value for item in items if item.count.value is not None]
            withheld_count = sum(item.count.value is None for item in items)
            has_withheld = withheld_count > 0
            total = sum(item for item in visible if item is not None)
            if (not has_withheld and total != known.value) or (has_withheld and total > known.value):
                raise TalentIntelligenceContractError(
                    f"exclusive dimension {key} must reconcile to known_count"
                )
            if withheld_count == 1:
                raise TalentIntelligenceContractError(
                    f"exclusive dimension {key} requires complementary suppression"
                )
        dimensions.append(Dimension(
            key,
            _string(raw["label"], f"{path}.label"),
            mode,
            denominator_key,
            known,
            tuple(sorted(items, key=lambda item: item.key)),
        ))
    _unique((dimension.key for dimension in dimensions), "dimension keys")
    return tuple(sorted(dimensions, key=lambda dimension: dimension.key))


def _intersections(
    value: object, dimensions: tuple[Dimension, ...], minimum: int,
) -> tuple[Intersection, ...]:
    components = {
        f"{dimension.key}.{item.key}": item.count
        for dimension in dimensions for item in dimension.items
    }
    intersections = []
    for index, value in enumerate(_list(value, "intersections", nonempty=False)):
        path = f"intersections[{index}]"
        raw = _exact(value, {
            "key", "label", "count", "component_keys", "evidence_sources",
        }, path)
        component_keys = _unique(
            (_string(item, f"{path}.component_keys[]")
             for item in _list(raw["component_keys"], f"{path}.component_keys")),
            f"{path}.component_keys",
        )
        if len(component_keys) < 2:
            raise TalentIntelligenceContractError(f"{path} must reference at least two components")
        count = _count(raw["count"], f"{path}.count", minimum)
        for component_key in component_keys:
            if component_key not in components:
                raise TalentIntelligenceContractError(f"{path} references unknown component {component_key}")
            component = components[component_key]
            if count.value is not None and component.value is None:
                raise TalentIntelligenceContractError(
                    f"{path} cannot publish a count for withheld component {component_key}"
                )
            if count.value is not None and component.value is not None and count.value > component.value:
                raise TalentIntelligenceContractError(
                    f"{path} count exceeds component {component_key}"
                )
        sources = _unique(
            (_key(item, f"{path}.evidence_sources[]")
             for item in _list(raw["evidence_sources"], f"{path}.evidence_sources")),
            f"{path}.evidence_sources",
        )
        intersections.append(Intersection(
            _key(raw["key"], f"{path}.key"),
            _string(raw["label"], f"{path}.label"),
            count,
            component_keys,
            sources,
        ))
    _unique((item.key for item in intersections), "intersection keys")
    return tuple(sorted(intersections, key=lambda item: item.key))


def _themes(value: object, denominator: int, minimum: int) -> tuple[QualitativeTheme, ...]:
    themes = []
    for index, value in enumerate(_list(value, "qualitative_themes", nonempty=False)):
        path = f"qualitative_themes[{index}]"
        raw = _exact(value, {
            "key", "label", "statement", "count", "confidence", "review_state",
            "evidence_sources",
        }, path)
        count = _count(raw["count"], f"{path}.count", minimum)
        if count.value is not None and count.value > denominator:
            raise TalentIntelligenceContractError(f"{path}.count exceeds cohort denominator")
        sources = _unique(
            (_key(item, f"{path}.evidence_sources[]")
             for item in _list(raw["evidence_sources"], f"{path}.evidence_sources")),
            f"{path}.evidence_sources",
        )
        themes.append(QualitativeTheme(
            _key(raw["key"], f"{path}.key"),
            _string(raw["label"], f"{path}.label"),
            _string(raw["statement"], f"{path}.statement"),
            count,
            _choice(raw["confidence"], {"low", "medium", "high"}, f"{path}.confidence"),
            _choice(raw["review_state"], {"synthetic", "reviewed", "pending"},
                    f"{path}.review_state"),
            sources,
        ))
    _unique((item.key for item in themes), "qualitative theme keys")
    return tuple(sorted(themes, key=lambda item: item.key))


def _coverage(value: object, minimum: int) -> tuple[EvidenceCoverage, ...]:
    coverage = []
    for index, value in enumerate(_list(value, "evidence_coverage")):
        path = f"evidence_coverage[{index}]"
        raw = _exact(value, {
            "source", "label", "eligible", "covered", "state", "note",
        }, path)
        eligible = _count(raw["eligible"], f"{path}.eligible", minimum)
        covered = _count(raw["covered"], f"{path}.covered", minimum)
        if eligible.value is None:
            raise TalentIntelligenceContractError(f"{path}.eligible must be published")
        if covered.value is not None and covered.value > eligible.value:
            raise TalentIntelligenceContractError(f"{path}.covered exceeds eligible")
        if (
            covered.value is not None
            and 0 < eligible.value - covered.value < minimum
        ):
            raise TalentIntelligenceContractError(
                f"{path} exposes a below-threshold coverage complement"
            )
        coverage.append(EvidenceCoverage(
            _key(raw["source"], f"{path}.source"),
            _string(raw["label"], f"{path}.label"),
            eligible,
            covered,
            _choice(raw["state"], {"ready", "partial", "pending", "off"}, f"{path}.state"),
            _string(raw["note"], f"{path}.note"),
        ))
    _unique((item.source for item in coverage), "evidence coverage sources")
    return tuple(sorted(coverage, key=lambda item: item.source))


def _readiness(value: object) -> tuple[ReadinessItem, ...]:
    items = []
    for index, value in enumerate(_list(value, "readiness")):
        path = f"readiness[{index}]"
        raw = _exact(value, {"component", "state", "required", "note"}, path)
        items.append(ReadinessItem(
            _key(raw["component"], f"{path}.component"),
            _choice(raw["state"], {"ready", "pending", "blocked", "off"}, f"{path}.state"),
            _boolean(raw["required"], f"{path}.required"),
            _string(raw["note"], f"{path}.note"),
        ))
    _unique((item.component for item in items), "readiness components")
    return tuple(sorted(items, key=lambda item: item.component))


def _feature_gates(value: object) -> tuple[FeatureGate, ...]:
    gates = []
    for index, value in enumerate(_list(value, "feature_gates")):
        path = f"feature_gates[{index}]"
        raw = _exact(value, {"feature", "state", "required", "note"}, path)
        feature = _key(raw["feature"], f"{path}.feature")
        state = _choice(raw["state"], {"disabled", "pending", "enabled"}, f"{path}.state")
        if feature == "gated_talent_appendix" and state != "disabled":
            raise TalentIntelligenceContractError("gated_talent_appendix must remain disabled")
        gates.append(FeatureGate(
            feature,
            state,
            _boolean(raw["required"], f"{path}.required"),
            _string(raw["note"], f"{path}.note"),
        ))
    _unique((item.feature for item in gates), "feature gate keys")
    if "gated_talent_appendix" not in {item.feature for item in gates}:
        raise TalentIntelligenceContractError("feature_gates must include gated_talent_appendix")
    return tuple(sorted(gates, key=lambda item: item.feature))


def _source_notes(value: object) -> tuple[SourceNote, ...]:
    notes = []
    for index, value in enumerate(_list(value, "source_notes")):
        path = f"source_notes[{index}]"
        raw = _exact(value, {"source", "state", "note"}, path)
        notes.append(SourceNote(
            _key(raw["source"], f"{path}.source"),
            _choice(raw["state"], {"schema_reference", "validated", "partial", "pending", "off"},
                    f"{path}.state"),
            _string(raw["note"], f"{path}.note"),
        ))
    _unique((item.source for item in notes), "source note keys")
    return tuple(sorted(notes, key=lambda item: item.source))


def load_talent_intelligence_contract(path: str | Path) -> TalentIntelligenceContract:
    """Load, canonicalize, and validate a talent-intelligence-v1 JSON document."""
    source = Path(path)
    try:
        raw = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise TalentIntelligenceContractError(f"cannot load contract {source}: {error}") from error
    root = _exact(raw, {
        "metadata", "privacy", "cohort", "selection_outcomes", "dimensions",
        "intersections", "qualitative_themes", "evidence_coverage", "readiness",
        "feature_gates", "source_notes",
    }, "contract")
    _scan_for_pii(root)
    metadata = _metadata(root["metadata"])
    privacy = _privacy(root["privacy"])
    cohort = _cohort(root["cohort"], privacy.minimum_count)
    selection = _selection(root["selection_outcomes"], cohort, privacy.minimum_count)
    dimensions = _dimensions(root["dimensions"], cohort, privacy.minimum_count)
    intersections = _intersections(root["intersections"], dimensions, privacy.minimum_count)
    report = TalentIntelligenceContract(
        metadata,
        privacy,
        cohort,
        selection,
        dimensions,
        intersections,
        _themes(root["qualitative_themes"], cohort.denominator.value or 0, privacy.minimum_count),
        _coverage(root["evidence_coverage"], privacy.minimum_count),
        _readiness(root["readiness"]),
        _feature_gates(root["feature_gates"]),
        _source_notes(root["source_notes"]),
    )
    has_withheld_counts = _contains_withheld_count(root)
    if privacy.state == "safe" and has_withheld_counts:
        raise TalentIntelligenceContractError(
            "privacy.state safe contradicts withheld counts"
        )
    if privacy.state == "withheld_cells" and not has_withheld_counts:
        raise TalentIntelligenceContractError(
            "privacy.state withheld_cells requires at least one withheld count"
        )
    if metadata.publication_state == "published":
        if privacy.state == "blocked":
            raise TalentIntelligenceContractError("published contract cannot have blocked privacy")
        if any(item.required and item.state != "ready" for item in report.readiness):
            raise TalentIntelligenceContractError(
                "published contract has unresolved required readiness"
            )
    return report
