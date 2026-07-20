"""Build a privacy-safe report model from the canonical store."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
import json
from pathlib import Path
import re
import sqlite3

from community_os.privacy import effective_k


ELIGIBLE_APPLICATION_FILTER = """p.state='active'
  AND NOT EXISTS (
    SELECT 1 FROM identity_review ir
    WHERE ir.provisional_person_id=a.person_id AND ir.status='open'
  )
  AND NOT EXISTS (
    SELECT 1 FROM consent_assertion c
    WHERE c.person_id=a.person_id AND c.event_id=a.event_id
      AND c.purpose='aggregate_stats' AND c.granted=0
      AND NOT EXISTS (
        SELECT 1 FROM consent_assertion n WHERE n.supersedes_assertion_id=c.id
      )
  )"""


@dataclass(frozen=True)
class FunnelStage:
    label: str
    count: int | None
    withheld_reason: str | None = None


@dataclass(frozen=True)
class ReportSlice:
    label: str
    count: int
    note: str = ""


@dataclass(frozen=True)
class ExecutiveFinding:
    label: str
    statement: str
    evidence: str


@dataclass(frozen=True)
class ReadinessItem:
    label: str
    status: str
    state: str


@dataclass(frozen=True)
class TrendPoint:
    label: str
    applications: int
    submissions: int


@dataclass(frozen=True)
class ReportData:
    event_key: str
    event_name: str
    event_date: str
    partner_key: str
    generated_at: str
    eligible_people: int
    stages: tuple[FunnelStage, ...]
    source_notes: tuple[str, ...]
    taxonomy_status: str = "Draft taxonomy pending approval"
    synthetic: bool = False
    executive_readout: tuple[ExecutiveFinding, ...] = ()
    cohort_mix: tuple[ReportSlice, ...] = ()
    builder_signals: tuple[ReportSlice, ...] = ()
    build_domains: tuple[ReportSlice, ...] = ()
    readiness: tuple[ReadinessItem, ...] = ()
    trends: tuple[TrendPoint, ...] = ()


def _reject_profile_pii(value: object) -> None:
    """Keep the checked-in demo profile aggregate-only and non-attributable."""
    if isinstance(value, str):
        if re.search(r"@|https?://|www\.", value, re.IGNORECASE):
            raise ValueError("report profile contains personal or link-like content")
        if len(value) > 240:
            raise ValueError("report profile text exceeds the aggregate narrative limit")
    elif isinstance(value, dict):
        for item in value.values():
            _reject_profile_pii(item)
    elif isinstance(value, list):
        for item in value:
            _reject_profile_pii(item)


def _profile_slices(
    payload: object, *, field: str, threshold: int, eligible: int,
) -> tuple[ReportSlice, ...]:
    if not isinstance(payload, list) or not payload:
        raise ValueError(f"report profile {field} must be a non-empty list")
    slices: list[ReportSlice] = []
    for item in payload:
        if not isinstance(item, dict) or set(item) != {"label", "count", "note"}:
            raise ValueError(f"report profile {field} has invalid entries")
        count = item["count"]
        if not isinstance(count, int) or isinstance(count, bool) or count < threshold:
            raise ValueError(f"report profile {field} violates the disclosure threshold")
        if count > eligible:
            raise ValueError(f"report profile {field} count exceeds eligible population")
        slices.append(ReportSlice(item["label"], count, item["note"]))
    return tuple(slices)


def load_report_profile(
    path: str | Path, *, event_key: str, event_name: str, event_date: str,
    partner_key: str, generated_at: str,
) -> ReportData:
    """Load an aggregate-only synthetic profile for design and sales demos."""
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    _reject_profile_pii(payload)
    required = {
        "synthetic", "eligible_people", "stages", "executive_readout",
        "cohort_mix", "builder_signals", "build_domains", "source_notes",
        "taxonomy_status", "readiness", "trends",
    }
    if set(payload) != required or payload["synthetic"] is not True:
        raise ValueError("report profile must be explicitly synthetic and match the schema")
    eligible = payload["eligible_people"]
    if not isinstance(eligible, int) or isinstance(eligible, bool) or eligible < 10:
        raise ValueError("synthetic report profile needs at least 10 eligible people")
    threshold = effective_k(eligible)
    raw_stages = payload["stages"]
    if not isinstance(raw_stages, list) or len(raw_stages) < 3:
        raise ValueError("report profile stages are incomplete")
    stages = tuple(FunnelStage(item["label"], item["count"]) for item in raw_stages)
    stage_counts = [stage.count for stage in stages]
    if stage_counts[0] != eligible or any(
        not isinstance(count, int) or count < threshold for count in stage_counts
    ) or stage_counts != sorted(stage_counts, reverse=True):
        raise ValueError("report profile stages must be monotonic and disclosure safe")
    findings = tuple(
        ExecutiveFinding(item["label"], item["statement"], item["evidence"])
        for item in payload["executive_readout"]
    )
    if len(findings) < 3:
        raise ValueError("report profile needs at least three executive findings")
    readiness = tuple(
        ReadinessItem(item["label"], item["status"], item["state"])
        for item in payload["readiness"]
    )
    trends = tuple(
        TrendPoint(item["label"], item["applications"], item["submissions"])
        for item in payload["trends"]
    )
    if len(trends) < 2 or any(
        point.applications < point.submissions or point.submissions < threshold
        for point in trends
    ):
        raise ValueError("report profile trends must be longitudinal and disclosure safe")
    return ReportData(
        event_key=event_key, event_name=event_name, event_date=event_date,
        partner_key=partner_key, generated_at=generated_at,
        eligible_people=eligible, stages=stages,
        source_notes=tuple(payload["source_notes"]),
        taxonomy_status=payload["taxonomy_status"], synthetic=True,
        executive_readout=findings,
        cohort_mix=_profile_slices(
            payload["cohort_mix"], field="cohort_mix", threshold=threshold, eligible=eligible,
        ),
        builder_signals=_profile_slices(
            payload["builder_signals"], field="builder_signals",
            threshold=threshold, eligible=eligible,
        ),
        build_domains=_profile_slices(
            payload["build_domains"], field="build_domains", threshold=threshold,
            eligible=eligible,
        ),
        readiness=readiness, trends=trends,
    )


def _publishable(count: int, threshold: int) -> tuple[int | None, str | None]:
    if count < threshold:
        return None, f"Withheld: fewer than {threshold} people"
    return count, None


def build_report_data(
    connection: sqlite3.Connection, *, event_id: int, partner_key: str,
    generated_at: datetime | None = None,
) -> ReportData:
    event = connection.execute(
        "SELECT event_key,name,starts_at FROM event WHERE id=?", (event_id,)
    ).fetchone()
    if event is None:
        raise ValueError("event does not exist")
    eligible = connection.execute(
        f"""SELECT COUNT(DISTINCT a.person_id) FROM application a
           JOIN person p ON p.id=a.person_id
           WHERE a.event_id=? AND {ELIGIBLE_APPLICATION_FILTER}""",
        (event_id,),
    ).fetchone()[0]
    threshold = effective_k(eligible)
    raw_stages = (
        ("Applied", eligible),
        ("Accepted", connection.execute(
            f"""SELECT COUNT(DISTINCT a.person_id) FROM application a
                JOIN person p ON p.id=a.person_id
                WHERE a.event_id=? AND a.status='accepted'
                  AND {ELIGIBLE_APPLICATION_FILTER}""", (event_id,)
        ).fetchone()[0]),
        ("Checked in", connection.execute(
            f"""SELECT COUNT(DISTINCT pa.person_id) FROM participation pa
                JOIN application a ON a.person_id=pa.person_id AND a.event_id=pa.event_id
                JOIN person p ON p.id=pa.person_id
                WHERE pa.event_id=? AND pa.checked_in=1
                  AND {ELIGIBLE_APPLICATION_FILTER}""", (event_id,)
        ).fetchone()[0]),
        ("Submitted", connection.execute(
            f"""SELECT COUNT(DISTINCT pa.person_id) FROM participation pa
                JOIN application a ON a.person_id=pa.person_id AND a.event_id=pa.event_id
                JOIN person p ON p.id=pa.person_id
                WHERE pa.event_id=? AND pa.submission_id IS NOT NULL
                  AND {ELIGIBLE_APPLICATION_FILTER}""", (event_id,)
        ).fetchone()[0]),
    )
    stages = tuple(
        FunnelStage(label, *_publishable(count, threshold)) for label, count in raw_stages
    )
    sources = tuple(
        row[0].replace("_", " ").title()
        for row in connection.execute(
            "SELECT DISTINCT source_type FROM source_file WHERE event_id=? ORDER BY source_type", (event_id,)
        )
    )
    timestamp = generated_at or datetime.now(UTC)
    return ReportData(
        event_key=event[0], event_name=event[1], event_date=event[2][:10],
        partner_key=partner_key, generated_at=timestamp.date().isoformat(),
        eligible_people=eligible, stages=stages, source_notes=sources,
    )
