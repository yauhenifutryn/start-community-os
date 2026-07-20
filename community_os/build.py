"""Orchestrate one-command local report generation."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
import json
import os
from pathlib import Path

from community_os.config import load_mapping
from community_os.db import initialize
from community_os.pdf_export import export_pdf
from community_os.pipeline import ingest_file
from community_os.report import build_report_data, load_report_profile
from community_os.render import render_report
from community_os.retention import cleanup_expired


@dataclass(frozen=True)
class BuildResult:
    database_path: Path
    html_path: Path
    pdf_path: Path | None
    accepted_records: int
    rejected_records: int


def _path(root: Path, value: str) -> Path:
    candidate = Path(value)
    return candidate if candidate.is_absolute() else root / candidate


def build_from_config(
    config_path: str | Path, *, output_root: Path | None = None,
    include_pdf: bool = False,
) -> BuildResult:
    config_file = Path(config_path).resolve()
    config = json.loads(config_file.read_text(encoding="utf-8"))
    project_root = Path(__file__).resolve().parents[1]
    destination = output_root.resolve() if output_root else project_root
    database_path = _path(destination, config["database"])
    html_path = _path(destination, config["output_html"])
    pdf_path = _path(destination, config["output_pdf"]) if include_pdf else None
    database_path.parent.mkdir(parents=True, exist_ok=True)
    html_path.parent.mkdir(parents=True, exist_ok=True)
    connection = initialize(database_path)
    try:
        cleanup_expired(connection, apply=True)
        event = config["event"]
        connection.execute(
            """INSERT OR IGNORE INTO event(event_key,name,starts_at,ends_at,event_type)
               VALUES(?,?,?,?,?)""",
            (event["key"], event["name"], event["starts_at"], event.get("ends_at"), event["type"]),
        )
        event_id = connection.execute(
            "SELECT id FROM event WHERE event_key=?", (event["key"],)
        ).fetchone()[0]
        ghost_secrets: dict[str, str] = {}
        for key_version, environment_name in config.get("ghost_identity_key_env", {}).items():
            secret = os.environ.get(environment_name)
            if not secret:
                raise ValueError(f"missing ghost identity secret environment variable: {environment_name}")
            ghost_secrets[key_version] = secret
        accepted = rejected = 0
        for source in config["sources"]:
            mapping = load_mapping(_path(project_root, source["mapping"]))
            summary = ingest_file(
                connection, event_id=event_id, path=_path(project_root, source["path"]),
                mapping=mapping, observed_at=source["observed_at"],
                authority=source.get("authority"), reingest=source.get("reingest", False),
                ghost_secrets=ghost_secrets,
            )
            accepted += summary.accepted
            rejected += summary.rejected
        connection.commit()
        generated_at = datetime.now(UTC)
        if config.get("report_profile"):
            if config.get("demo_mode") is not True:
                raise ValueError("report_profile is restricted to explicit demo_mode")
            data = load_report_profile(
                _path(project_root, config["report_profile"]),
                event_key=event["key"], event_name=event["name"],
                event_date=event["starts_at"][:10], partner_key=config["partner_key"],
                generated_at=generated_at.date().isoformat(),
            )
        else:
            data = build_report_data(
                connection, event_id=event_id, partner_key=config["partner_key"],
                generated_at=generated_at,
            )
        analytics = config.get("analytics", {})
        html_path.write_text(
            render_report(
                data,
                posthog_key=analytics.get("public_key") if analytics.get("enabled") else None,
                posthog_host=analytics.get("host", "https://eu.i.posthog.com"),
            ),
            encoding="utf-8",
        )
        if pdf_path is not None:
            export_pdf(html_path, pdf_path)
        return BuildResult(database_path, html_path, pdf_path, accepted, rejected)
    finally:
        connection.close()
