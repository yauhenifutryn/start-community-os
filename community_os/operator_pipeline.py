"""Privacy-safe validation and aggregate output for the local event operator."""

from __future__ import annotations

import csv
from dataclasses import dataclass
from enum import StrEnum
import hashlib
import io
import json
from pathlib import Path
import re
import tempfile
from typing import Iterable, Mapping, Sequence
from xml.etree import ElementTree
from zipfile import BadZipFile, ZipFile

from community_os.report_contract import load_report_contract
from community_os.event_definition import EventSource
from community_os.ingest.base import MappedRecord, ingest_table
from community_os.operator_store import FinalRecord, normalize_track
from community_os.source_contract import (
    RegisteredSourceContract,
    load_registered_source_contract,
)


class OperatorError(ValueError):
    """A blocking operator validation error safe to display without raw PII."""


class SourceSlot(StrEnum):
    LUMA = "luma"
    TRACK = "track_preferences"
    DEVPOST = "devpost"


LUMA_HEADERS = (
    "name", "first_name", "last_name", "email", "approval_status", "checked_in_at",
    "Are you applying solo or with a team? Each team member has to register separately.",
    "Team name (if applying with a team)",
)
TRACK_HEADERS = ("Submission ID", "Submitted at", "Status", "Track ID", "Track", "Team name", "Team size", "Member names", "Member emails", "Organiser note")
DEVPOST_HEADERS = ("Project Title", "Submission Url", "Project Status", "Judging Status", "Highest Step Completed", "Project Created At", "Project Submitted At", "About The Project", '"Try it out" Links', "Video Demo Link", "Image Gallery URLs", "Attached File S3 Key", "Opt-In Prizes", "Built With", "Submitter First Name", "Submitter Last Name", "Submitter Email", "Notes", "Track", "Team Colleges/Universities", "Additional Team Member Count", "Team Member 1 First Name", "Team Member 1 Last Name", "Team Member 1 Email", "...", "Column1", "Column2", "Column3", "Column4", "Column5")
_MAIN_NS = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
_REL_NS = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
_MAX_XLSX_ENTRIES = 200
_MAX_XLSX_EXPANDED_BYTES = 100 * 1024 * 1024
_MAX_XLSX_EXPANSION_RATIO = 100
_MAX_XLSX_COLUMNS = 512
_MAX_XLSX_ROWS = 100_000
_MAX_XLSX_CELLS = 2_000_000


@dataclass(frozen=True)
class PreflightResult:
    source: str
    sha256: str
    row_count: int
    warnings: tuple[str, ...] = ()


@dataclass(frozen=True)
class RegisteredSourceData:
    """Mapped rows read through one hash-bound registered source contract."""

    contract: RegisteredSourceContract
    records: tuple[MappedRecord, ...]
    rejected_count: int


def file_sha256(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def validate_distinct_inputs(paths: Mapping[SourceSlot, str | Path]) -> dict[str, str]:
    hashes: dict[str, str] = {}
    seen: set[str] = set()
    for slot, path in paths.items():
        digest = file_sha256(path)
        if digest in seen:
            raise OperatorError(f"{slot.value}: duplicate input hash")
        hashes[slot.value] = digest
        seen.add(digest)
    return hashes


def preflight_csv(path: str | Path, slot: SourceSlot) -> PreflightResult:
    if slot is not SourceSlot.LUMA:
        raise OperatorError(f"{slot.value}: CSV is not accepted in this slot")
    source = Path(path)
    try:
        text = source.read_text(encoding="utf-8-sig")
    except UnicodeDecodeError as exc:
        raise OperatorError("luma: file is not valid UTF-8 CSV") from exc
    if "\x00" in text:
        raise OperatorError("luma: malformed CSV contains a NUL byte")
    try:
        rows = csv.reader(io.StringIO(text, newline=""))
        header = tuple(next(rows))
        if header != LUMA_HEADERS:
            raise OperatorError("luma: row 1 has unexpected columns")
        count = 0
        for row_number, row in enumerate(rows, start=2):
            if len(row) != len(header):
                raise OperatorError(f"luma: row {row_number} has {len(row)} columns; expected {len(header)}")
            count += 1
    except csv.Error as exc:
        raise OperatorError(f"luma: malformed CSV near line {exc}") from exc
    if count == 0:
        raise OperatorError("luma: no data rows")
    return PreflightResult(slot.value, file_sha256(source), count)


def preflight_xlsx_container(path: str | Path) -> None:
    """Reject archive expansion hazards before any workbook XML is parsed."""

    try:
        with ZipFile(path) as archive:
            entries = archive.infolist()
            if len(entries) > _MAX_XLSX_ENTRIES:
                raise OperatorError("XLSX contains too many archive entries")
            member_names = [item.filename for item in entries]
            if len(member_names) != len(set(member_names)):
                raise OperatorError("XLSX contains a duplicate archive member name")
            total = sum(item.file_size for item in entries)
            compressed = sum(max(1, item.compress_size) for item in entries)
            if (
                total > _MAX_XLSX_EXPANDED_BYTES
                or total / compressed > _MAX_XLSX_EXPANSION_RATIO
            ):
                raise OperatorError("XLSX expansion exceeds protected parsing limits")
    except BadZipFile as error:
        raise OperatorError("upload is not a valid XLSX container") from error


def read_xlsx(
    path: str | Path,
    *,
    selected_sheets: Iterable[str] | None = None,
) -> dict[str, list[list[str]]]:
    """Read selected cell tables from a bounded Office Open XML workbook."""

    preflight_xlsx_container(path)
    ns = {"m": _MAIN_NS, "r": _REL_NS}
    try:
        with ZipFile(path) as archive:
            required = {"xl/workbook.xml", "xl/_rels/workbook.xml.rels"}
            if not required.issubset(archive.namelist()):
                raise OperatorError("XLSX package is missing workbook metadata")
            relations = ElementTree.fromstring(archive.read("xl/_rels/workbook.xml.rels"))
            targets: dict[str, str] = {}
            for item in relations:
                relation_id = item.attrib["Id"]
                if relation_id in targets:
                    raise OperatorError("XLSX contains duplicate workbook relationships")
                targets[relation_id] = item.attrib["Target"]
            workbook = ElementTree.fromstring(archive.read("xl/workbook.xml"))
            sheet_elements = workbook.findall(".//m:sheets/m:sheet", ns)
            sheet_names = [item.attrib["name"] for item in sheet_elements]
            if len(sheet_names) != len(set(sheet_names)):
                raise OperatorError("XLSX contains a duplicate sheet name")
            selected = None if selected_sheets is None else tuple(selected_sheets)
            if selected is not None:
                missing = [sheet for sheet in selected if sheet not in sheet_names]
                if missing:
                    raise OperatorError(
                        "configured sheet is missing: " + ", ".join(missing)
                    )
                selected_set = set(selected)
            else:
                selected_set = set(sheet_names)

            shared: list[str] = []
            if selected_set and "xl/sharedStrings.xml" in archive.namelist():
                root = ElementTree.fromstring(archive.read("xl/sharedStrings.xml"))
                shared = ["".join(item.itertext()) for item in root.findall("m:si", ns)]
            result: dict[str, list[list[str]]] = {}
            total_cells = 0
            for sheet in sheet_elements:
                sheet_name = sheet.attrib["name"]
                if sheet_name not in selected_set:
                    continue
                target = targets[sheet.attrib[f"{{{_REL_NS}}}id"]]
                member = target if target.startswith("xl/") else "xl/" + target.lstrip("/")
                if not member.startswith("xl/worksheets/") or ".." in Path(member).parts:
                    raise OperatorError("XLSX worksheet relationship target is unsafe")
                root = ElementTree.fromstring(archive.read(member))
                dimension = root.find("m:dimension", ns)
                maximum_column = 0
                if dimension is not None:
                    end = dimension.attrib.get("ref", "A1").split(":")[-1]
                    boundary = re.fullmatch(r"([A-Z]+)([0-9]+)", end)
                    if boundary:
                        maximum_column = sum(
                            (ord(char) - 64) * (26 ** index)
                            for index, char in enumerate(reversed(boundary.group(1)))
                        )
                        maximum_row = int(boundary.group(2))
                        if (
                            maximum_column > _MAX_XLSX_COLUMNS
                            or maximum_row > _MAX_XLSX_ROWS
                            or maximum_column * maximum_row > _MAX_XLSX_CELLS
                        ):
                            raise OperatorError("XLSX sheet dimensions exceed parsing limits")
                rows: list[list[str]] = []
                for row in root.findall(".//m:sheetData/m:row", ns):
                    if len(rows) >= _MAX_XLSX_ROWS:
                        raise OperatorError("XLSX row count exceeds parsing limits")
                    values: list[str] = []
                    for cell in row.findall("m:c", ns):
                        total_cells += 1
                        if total_cells > _MAX_XLSX_CELLS:
                            raise OperatorError("XLSX cell count exceeds parsing limits")
                        reference = cell.attrib.get("r", "A1")
                        letters = re.match(r"[A-Z]+", reference)
                        column = sum((ord(char) - 64) * (26 ** index) for index, char in enumerate(reversed(letters.group()))) if letters else len(values) + 1
                        if column > _MAX_XLSX_COLUMNS:
                            raise OperatorError("XLSX column count exceeds parsing limits")
                        values.extend([""] * max(0, column - len(values) - 1))
                        cell_type = cell.attrib.get("t")
                        inline = cell.find("m:is", ns)
                        value = cell.find("m:v", ns)
                        text = "".join(inline.itertext()) if inline is not None else (value.text or "" if value is not None else "")
                        if cell_type == "s" and text:
                            text = shared[int(text)]
                        values.append(text)
                    values.extend([""] * max(0, maximum_column - len(values)))
                    rows.append(values)
                result[sheet_name] = rows
            return result
    except OperatorError:
        raise
    except (BadZipFile, KeyError, ElementTree.ParseError, IndexError, ValueError) as exc:
        raise OperatorError("file is not a valid XLSX workbook") from exc


def preflight_xlsx(
    path: str | Path,
    slot: SourceSlot,
    *,
    selected_sheets: Sequence[str] | None = None,
) -> PreflightResult:
    if slot not in {SourceSlot.TRACK, SourceSlot.DEVPOST}:
        raise OperatorError(f"{slot.value}: XLSX is not accepted in this slot")
    configured = None if selected_sheets is None else tuple(selected_sheets)
    if configured is not None and (
        not configured or len(configured) != len(set(configured))
    ):
        raise OperatorError(f"{slot.value}: configured sheets are invalid")
    sheets = read_xlsx(path, selected_sheets=configured)
    if slot is SourceSlot.TRACK:
        names = configured or ("Submissions",)
        if set(sheets) != set(names):
            raise OperatorError("track_preferences: configured sheets do not match workbook")
        count = 0
        for name in names:
            rows = sheets[name]
            if not rows or tuple(rows[0]) != TRACK_HEADERS:
                raise OperatorError(
                    f"track_preferences: {name} row 1 has unexpected columns"
                )
            count += len([row for row in rows[1:] if any(row)])
    else:
        names = configured or ("solidgate", "boski")
        if set(sheets) != set(names):
            raise OperatorError("devpost: configured sheets do not match workbook")
        primary = sheets[names[0]]
        if not primary or tuple(primary[0]) != DEVPOST_HEADERS:
            raise OperatorError(
                f"devpost: {names[0]} row 1 must match the exact 30-column schema"
            )
        count = 0
        for name in names:
            rows = sheets[name]
            data_rows = (
                rows[1:]
                if rows and tuple(rows[0]) == DEVPOST_HEADERS
                else rows
            )
            if any(len(row) != len(DEVPOST_HEADERS) for row in data_rows if any(row)):
                raise OperatorError(
                    f"devpost: {name} data row has an unexpected column count"
                )
            count += len([row for row in data_rows if any(row)])
    if count == 0:
        raise OperatorError(f"{slot.value}: no data rows")
    return PreflightResult(slot.value, file_sha256(path), count)


def read_registered_source_data(
    path: str | Path,
    source: EventSource,
) -> RegisteredSourceData:
    """Read a configured tabular source using its registered adapter layout."""

    contract = load_registered_source_contract(source)
    tables: list[tuple[str | None, Sequence[str], Sequence[Sequence[str]]]] = []
    if contract.table_layout == "single_table":
        try:
            text = Path(path).read_text(encoding="utf-8-sig")
            if "\x00" in text:
                raise OperatorError(f"{source.role}: malformed CSV contains a NUL byte")
            rows = list(csv.reader(io.StringIO(text, newline="")))
        except UnicodeDecodeError as error:
            raise OperatorError(f"{source.role}: file is not valid UTF-8 CSV") from error
        except csv.Error as error:
            raise OperatorError(f"{source.role}: malformed CSV") from error
        if not rows:
            raise OperatorError(f"{source.role}: CSV has no header row")
        tables.append((None, rows[0], rows[1:]))
    elif contract.table_layout in {"header_per_sheet", "shared_first_header"}:
        sheets = read_xlsx(path, selected_sheets=source.sheets)
        if contract.table_layout == "shared_first_header":
            first_rows = sheets[source.sheets[0]]
            if not first_rows:
                raise OperatorError(
                    f"{source.role}: {source.sheets[0]} has no header row"
                )
            shared_header = first_rows[0]
            for index, sheet_name in enumerate(source.sheets):
                rows = sheets[sheet_name]
                data_rows = rows[1:] if index == 0 else rows
                if index > 0 and rows and tuple(rows[0]) == tuple(shared_header):
                    data_rows = rows[1:]
                tables.append((sheet_name, shared_header, data_rows))
        else:
            for sheet_name in source.sheets:
                rows = sheets[sheet_name]
                if not rows:
                    raise OperatorError(f"{source.role}: {sheet_name} has no header row")
                tables.append((sheet_name, rows[0], rows[1:]))
    else:
        raise OperatorError(f"{source.role}: source is not a registered tabular adapter")

    mapped_records: list[MappedRecord] = []
    rejected_count = 0
    for partition, headers, rows in tables:
        result = ingest_table(
            headers,
            rows,
            contract.mapping,
            authority=contract.authority,
            source_partition=partition,
        )
        mapped_records.extend(result.records)
        rejected_count += len(result.rejected)
    if not mapped_records:
        raise OperatorError(f"{source.role}: no valid mapped rows")
    return RegisteredSourceData(
        contract=contract,
        records=tuple(mapped_records),
        rejected_count=rejected_count,
    )


def split_people(value: object) -> list[str]:
    return [item.strip() for item in re.split(r"[\n,;|]+", str(value or "")) if item.strip()]


def records_from_source(
    path: str | Path,
    slot: SourceSlot,
    *,
    selected_sheets: Sequence[str] | None = None,
    source: EventSource | None = None,
) -> list[FinalRecord]:
    """Convert one validated final export into deterministic person-scoped records."""
    if source is not None:
        expected_roles = {
            SourceSlot.LUMA: frozenset({"applications", "attendance"}),
            SourceSlot.TRACK: frozenset({"preferences"}),
            SourceSlot.DEVPOST: frozenset({"submissions"}),
        }
        if source.role not in expected_roles[slot]:
            raise OperatorError(f"{source.role}: source does not match {slot.value}")
        if selected_sheets is not None and tuple(selected_sheets) != source.sheets:
            raise OperatorError(f"{source.role}: selected sheets do not match the event")
        registered = read_registered_source_data(path, source)
        mapped_records = registered.records

        if slot is SourceSlot.LUMA:
            multiple_partitions = len(source.sheets) > 1
            records: list[FinalRecord] = []
            for record in mapped_records:
                values = record.values
                name = values.get("name") or " ".join(filter(None, (
                    values.get("first_name", ""), values.get("last_name", ""),
                )))
                prefix = (
                    f"luma-{record.source_partition}-{record.row_number:04d}"
                    if multiple_partitions else f"luma-{record.row_number:04d}"
                )
                records.append(FinalRecord(
                    prefix,
                    record.raw,
                    record.applicant_identity,
                    name or "Participant",
                    github=values.get("github") or None,
                    linkedin=values.get("linkedin") or None,
                    checked_in_at=values.get("checked_in_at") or None,
                    team_name=values.get("team_name") or None,
                ))
            return records

        if slot is SourceSlot.TRACK:
            records = []
            for record in mapped_records:
                values = record.values
                emails = split_people(values.get("member_emails"))
                names = split_people(values.get("member_names"))
                submission_id = (
                    values.get("submission_id")
                    or record.external_record_id
                    or f"row-{record.row_number}"
                ).strip()
                source_prefix = (
                    f"track-{record.source_partition}-{submission_id}"
                    if len(source.sheets) > 1 else f"track-{submission_id}"
                )
                for member_index, email in enumerate(emails, start=1):
                    name = (
                        names[member_index - 1]
                        if member_index <= len(names) else f"Member {member_index}"
                    )
                    records.append(FinalRecord(
                        f"{source_prefix}-member-{member_index}",
                        record.raw,
                        email,
                        name,
                        team_name=values.get("team_name") or None,
                        track=normalize_track(values.get("track")),
                    ))
            return records

        records = []
        member_fields = (
            ("submitter_first_name", "submitter_last_name", "submitter_email"),
            ("team_member_1_first_name", "team_member_1_last_name", "team_member_1_email"),
            ("team_member_2_first_name", "team_member_2_last_name", "team_member_2_email"),
            ("team_member_3_first_name", "team_member_3_last_name", "team_member_3_email"),
        )
        for record in mapped_records:
            values = record.values
            project_index = max(1, record.row_number - 1)
            title = values.get("project_title") or f"Project {project_index}"
            repository_value = values.get("try_links", "")
            github = (
                repository_value
                if "github.com" in repository_value.casefold() else None
            )
            for member_index, fields in enumerate(member_fields, start=1):
                first_key, last_key, email_key = fields
                email = values.get(email_key, "").strip()
                if not email:
                    continue
                name = " ".join(filter(None, (
                    values.get(first_key, "").strip(),
                    values.get(last_key, "").strip(),
                )))
                records.append(FinalRecord(
                    f"devpost-{record.source_partition}-{project_index:02d}-member-{member_index}",
                    record.raw,
                    email,
                    name or f"Member {member_index}",
                    github=github,
                    team_name=title,
                    track=normalize_track(
                        values.get("track") or record.source_partition,
                    ),
                    submission_title=title,
                    repository_present=bool(repository_value.strip()),
                    demo_present=bool(values.get("demo_video", "").strip()),
                ))
        return records

    if slot is SourceSlot.LUMA:
        preflight_csv(path, slot)
        with Path(path).open(encoding="utf-8-sig", newline="") as stream:
            rows = list(csv.DictReader(stream))
        return [FinalRecord(
            f"luma-{index:04d}", row, row["email"], row["name"],
            checked_in_at=row["checked_in_at"].strip() or None,
            team_name=row["Team name (if applying with a team)"].strip() or None,
        ) for index, row in enumerate(rows, start=2)]

    configured = None if selected_sheets is None else tuple(selected_sheets)
    preflight_xlsx(path, slot, selected_sheets=configured)
    sheets = read_xlsx(path, selected_sheets=configured)
    records: list[FinalRecord] = []
    if slot is SourceSlot.TRACK:
        sheet_names = configured or ("Submissions",)
        for sheet_name in sheet_names:
            header = sheets[sheet_name][0]
            for row_index, values in enumerate(sheets[sheet_name][1:], start=2):
                if not any(values):
                    continue
                row = dict(zip(header, values, strict=False))
                emails = split_people(row.get("Member emails"))
                names = split_people(row.get("Member names"))
                submission_id = str(row.get("Submission ID") or f"row-{row_index}").strip()
                source_prefix = (
                    f"track-{sheet_name}-{submission_id}"
                    if len(sheet_names) > 1 else f"track-{submission_id}"
                )
                for member_index, email in enumerate(emails, start=1):
                    name = names[member_index - 1] if member_index <= len(names) else f"Member {member_index}"
                    records.append(FinalRecord(
                        f"{source_prefix}-member-{member_index}", row, email, name,
                        team_name=str(row.get("Team name") or "").strip() or None,
                        track=normalize_track(row.get("Track")),
                    ))
        return records

    sheet_names = configured or ("solidgate", "boski")
    header = sheets[sheet_names[0]][0]
    member_columns = (
        ("Submitter First Name", "Submitter Last Name", "Submitter Email"),
        ("Team Member 1 First Name", "Team Member 1 Last Name", "Team Member 1 Email"),
        ("...", "Column1", "Column2"),
        ("Column3", "Column4", "Column5"),
    )
    for sheet_name in sheet_names:
        rows = sheets[sheet_name]
        data_rows = (
            rows[1:] if rows and tuple(rows[0]) == tuple(header) else rows
        )
        for project_index, values in enumerate(data_rows, start=1):
            if not any(values):
                continue
            row = dict(zip(header, values, strict=False))
            title = str(row.get("Project Title") or f"Project {project_index}").strip()
            repository_value = str(row.get('"Try it out" Links') or "")
            github = repository_value if "github.com" in repository_value.casefold() else None
            for member_index, (first_key, last_key, email_key) in enumerate(member_columns, start=1):
                email = str(row.get(email_key) or "").strip()
                if not email:
                    continue
                name = " ".join(filter(None, (str(row.get(first_key) or "").strip(), str(row.get(last_key) or "").strip())))
                records.append(FinalRecord(
                    f"devpost-{sheet_name}-{project_index:02d}-member-{member_index}",
                    row, email, name or f"Member {member_index}", github=github,
                    team_name=title, track=normalize_track(row.get("Track") or sheet_name),
                    submission_title=title, repository_present=bool(repository_value.strip()),
                    demo_present=bool(str(row.get("Video Demo Link") or "").strip()),
                ))
    return records




def _count(value: int, minimum: int = 5) -> dict[str, object]:
    if value == 0 or value >= minimum:
        return {"value": value, "privacy": "published", "reason": None}
    return {"value": None, "privacy": "withheld", "reason": "Below publication threshold"}


def build_report_payload(
    facts: Mapping[str, object], *, open_review_count: int, generated_at: str
) -> dict[str, object]:
    if open_review_count:
        raise OperatorError("unresolved identity review blocks aggregate generation")
    approved = int(facts["approved"])
    checked = int(facts["checked_in"])
    submitted = int(facts["submitted_people"])
    composition = dict(facts["composition"])
    team_people = int(composition.get("team", 0))
    solo_people = int(composition.get("solo", 0))
    teams = dict(facts["teams_by_track"])
    projects = dict(facts["projects_by_track_domain"])
    tracks = sorted(set(teams) | set(projects))
    domains = sorted({domain for values in projects.values() for domain in values}) or ["unclassified"]
    artifacts = dict(facts["artifact_counts"])
    payload: dict[str, object] = {
        "metadata": {"contract_version": "talent-report-v3", "title": "START Warsaw Talent Data Room", "event_key": "openai-hackathon-2026", "event_name": "OpenAI Hackathon", "event_date": "2026-07-11", "generated_at": generated_at, "synthetic": False, "publication_state": "review_ready"},
        "privacy": {"mode": "aggregate_only", "minimum_count": 5, "pii_included": False, "state": "withheld_cells"},
        "attendance_funnel": {"unit": "people", "stages": [
            {"key": "approved", "label": "Approved", "order": 1, "count": _count(approved)},
            {"key": "checked_in", "label": "Checked in", "order": 2, "count": _count(checked)},
            {"key": "submitted", "label": "Submitted", "order": 3, "count": _count(submitted)},
        ]},
        "journey": {"unit": "people", "nodes": [
            {"key": "approved", "label": "Approved", "order": 1, "count": _count(approved), "unit": "people"},
            {"key": "checked_in", "label": "Checked in", "order": 2, "count": _count(checked), "unit": "people"},
            {"key": "team_path", "label": "Joined with a team", "order": 3, "count": _count(team_people), "unit": "people"},
            {"key": "solo_path", "label": "Joined solo", "order": 4, "count": _count(solo_people), "unit": "people"},
        ], "links": [
            {"source": "approved", "target": "checked_in", "count": _count(checked), "unit": "people"},
            {"source": "checked_in", "target": "team_path", "count": _count(team_people), "unit": "people"},
            {"source": "checked_in", "target": "solo_path", "count": _count(solo_people), "unit": "people"},
        ]},
        "team_submission_matrix": {"unit": "teams", "row_keys": tracks, "column_keys": ["submitted", "not_submitted"], "cells": [
            {"row": track, "column": column, "count": _count(int(dict(teams.get(track, {})).get(column, 0)))}
            for track in tracks for column in ("submitted", "not_submitted")
        ]},
        "builder_signal_intersections": {"unit": "people", "signal_keys": ["github"], "intersections": [{"signals": ["github"], "count": _count(int(facts.get("github_people", 0)))}]},
        "track_domain_heatmap": {"unit": "projects", "track_keys": tracks, "domain_keys": domains, "cells": [
            {"track": track, "domain": domain, "count": _count(int(dict(projects.get(track, {})).get(domain, 0)))}
            for track in tracks for domain in domains
        ]},
        "composition": {"unit": "people", "categories": [
            {"key": key, "label": "Joined with a team" if key == "team" else "Joined solo", "count": _count(int(value))}
            for key, value in sorted(composition.items())
        ]},
        "artifact_completeness": {"unit": "projects", "items": [
            {"key": key, "label": key.replace("_", " ").title(), "status": "complete" if present == eligible else ("missing" if present == 0 else "partial"), "present": _count(int(present)), "eligible": _count(int(eligible))}
            for key, (present, eligible) in sorted(artifacts.items())
        ]},
        "readiness": [{"component": "identity_review", "state": "ready", "required": True, "note": "All blocking reviews resolved"}, {"component": "coresignal", "state": "off", "required": False, "note": "Not enabled"}],
        "source_notes": [{"source": "devpost", "state": "validated", "note": "Two track sheets validated"}, {"source": "luma", "state": "validated", "note": "Final approval and check-in export"}, {"source": "track_preferences", "state": "validated", "note": "Final preference export"}],
    }
    def has_withheld(value: object) -> bool:
        if isinstance(value, dict):
            return value.get("privacy") == "withheld" or any(has_withheld(item) for item in value.values())
        if isinstance(value, list):
            return any(has_withheld(item) for item in value)
        return False

    payload["privacy"]["state"] = "withheld_cells" if has_withheld(payload) else "safe"
    with tempfile.TemporaryDirectory() as directory:
        candidate = Path(directory) / "candidate.json"
        candidate.write_text(json.dumps(payload), encoding="utf-8")
        load_report_contract(candidate)
    return payload


def write_outputs(
    directory: str | Path, payload: Mapping[str, object], *, source_hashes: Mapping[str, str],
    counts: Mapping[str, int], warnings: Sequence[str], generated_at: str,
) -> tuple[Path, Path]:
    target = Path(directory)
    target.mkdir(parents=True, exist_ok=True)
    report = target / "talent-report-v3.aggregate.json"
    report.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    output_hash = file_sha256(report)
    manifest_payload = {
        "adapter_versions": {"luma": "final-v1", "track_preferences": "final-v1", "devpost": "final-v1"},
        "contract_version": "talent-report-v3", "counts": dict(sorted(counts.items())),
        "generated_at": generated_at, "mapping_versions": {"identity": "strict-v1"},
        "open_review_count": 0, "output_hashes": {report.name: output_hash},
        "source_hashes": dict(sorted(source_hashes.items())), "warning_codes": sorted(warnings),
    }
    manifest = target / "talent-report-v3.manifest.json"
    manifest.write_text(json.dumps(manifest_payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return report, manifest
