"""Mapping-driven workbook selection for normalized event sources."""

from __future__ import annotations

import csv
from html import escape
from pathlib import Path
import tempfile
import unittest
import warnings
from zipfile import ZIP_DEFLATED, ZipFile

from community_os.config import load_mapping
from community_os.normalized_event import MappedSourceInput, normalize_mapped_sources


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"


def _column_name(index: int) -> str:
    result = ""
    while index:
        index, remainder = divmod(index - 1, 26)
        result = chr(65 + remainder) + result
    return result


def _worksheet_xml(rows: list[list[str]]) -> str:
    width = max((len(row) for row in rows), default=1)
    cells: list[str] = []
    for row_index, row in enumerate(rows, start=1):
        rendered = "".join(
            f'<c r="{_column_name(column_index)}{row_index}" t="inlineStr">'
            f"<is><t>{escape(value)}</t></is></c>"
            for column_index, value in enumerate(row, start=1)
        )
        cells.append(f'<row r="{row_index}">{rendered}</row>')
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        f'<dimension ref="A1:{_column_name(width)}{max(len(rows), 1)}"/>'
        f"<sheetData>{''.join(cells)}</sheetData></worksheet>"
    )


def _write_workbook(
    path: Path,
    sheets: dict[str, list[list[str]] | str] | list[tuple[str, list[list[str]] | str]],
) -> None:
    sheet_items = list(sheets.items()) if isinstance(sheets, dict) else list(sheets)
    workbook_sheets = "".join(
        f'<sheet name="{escape(name)}" sheetId="{index}" r:id="rId{index}"/>'
        for index, (name, _) in enumerate(sheet_items, start=1)
    )
    relationships = "".join(
        f'<Relationship Id="rId{index}" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" '
        f'Target="worksheets/sheet{index}.xml"/>'
        for index in range(1, len(sheet_items) + 1)
    )
    with ZipFile(path, "w", compression=ZIP_DEFLATED) as archive:
        archive.writestr(
            "xl/workbook.xml",
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
            'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
            f"<sheets>{workbook_sheets}</sheets></workbook>",
        )
        archive.writestr(
            "xl/_rels/workbook.xml.rels",
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            f"{relationships}</Relationships>",
        )
        for index, (_, rows) in enumerate(sheet_items, start=1):
            payload = rows if isinstance(rows, str) else _worksheet_xml(rows)
            archive.writestr(f"xl/worksheets/sheet{index}.xml", payload)


def _csv_rows(path: Path) -> list[list[str]]:
    with path.open(encoding="utf-8", newline="") as stream:
        return list(csv.reader(stream))


class MappedWorkbookIngestTests(unittest.TestCase):
    def _sources(self, workbook: Path, *, sheets: tuple[str, ...]) -> list[MappedSourceInput]:
        mapping_root = FIXTURES / "mappings"
        event_root = FIXTURES / "events"
        return [
            MappedSourceInput(
                "applications",
                True,
                event_root / "second-applications.csv",
                load_mapping(mapping_root / "second-applications.json"),
            ),
            MappedSourceInput(
                "attendance",
                True,
                event_root / "second-attendance.csv",
                load_mapping(mapping_root / "second-attendance.json"),
                positive_values=("admitted",),
            ),
            MappedSourceInput(
                "teams",
                False,
                event_root / "second-teams.csv",
                load_mapping(mapping_root / "second-teams.json"),
            ),
            MappedSourceInput(
                "submissions",
                False,
                workbook,
                load_mapping(mapping_root / "second-submissions.json"),
                positive_values=("final",),
                sheets=sheets,
            ),
        ]

    def test_configured_sheet_is_selected_and_unselected_sheet_is_ignored(self) -> None:
        selected = _csv_rows(FIXTURES / "events" / "second-submissions.csv")
        selected.append(
            [
                "",
                "gamma@example.test",
                "P-INVALID",
                "T-B",
                "Invalid Row",
                "final",
                "Civic Tech",
            ]
        )
        decoy = [
            selected[0],
            [
                "OLD-1",
                "gamma@example.test",
                "P-OLD",
                "T-B",
                "Old Build",
                "final",
                "Civic Tech",
            ],
        ]
        with tempfile.TemporaryDirectory() as directory:
            workbook = Path(directory) / "builds.xlsx"
            _write_workbook(workbook, {"Final builds": selected, "Old builds": decoy})

            data = normalize_mapped_sources(
                event_key="second-hackathon",
                sources=self._sources(workbook, sheets=("Final builds",)),
            )

        self.assertEqual(len(data.projects), 1)
        self.assertEqual(len(data.submitted_project_memberships), 2)
        self.assertEqual(data.projects[0].track, "Robotics")
        self.assertIn("Final builds", {item.source_partition for item in data.rejected_rows})

    def test_missing_configured_sheet_fails_closed(self) -> None:
        selected = _csv_rows(FIXTURES / "events" / "second-submissions.csv")
        with tempfile.TemporaryDirectory() as directory:
            workbook = Path(directory) / "builds.xlsx"
            _write_workbook(workbook, {"Final builds": selected})

            with self.assertRaisesRegex(ValueError, "Missing builds"):
                normalize_mapped_sources(
                    event_key="second-hackathon",
                    sources=self._sources(workbook, sheets=("Missing builds",)),
                )

    def test_unselected_invalid_sheet_is_not_parsed(self) -> None:
        selected = _csv_rows(FIXTURES / "events" / "second-submissions.csv")
        with tempfile.TemporaryDirectory() as directory:
            workbook = Path(directory) / "builds.xlsx"
            _write_workbook(
                workbook,
                {"Final builds": selected, "Broken archive": "<not-valid-xml"},
            )

            data = normalize_mapped_sources(
                event_key="second-hackathon",
                sources=self._sources(workbook, sheets=("Final builds",)),
            )

        self.assertEqual(len(data.projects), 1)

    def test_duplicate_sheet_names_fail_closed(self) -> None:
        selected = _csv_rows(FIXTURES / "events" / "second-submissions.csv")
        with tempfile.TemporaryDirectory() as directory:
            workbook = Path(directory) / "builds.xlsx"
            _write_workbook(
                workbook,
                [("Final builds", selected), ("Final builds", selected)],
            )

            with self.assertRaisesRegex(ValueError, "duplicate sheet"):
                normalize_mapped_sources(
                    event_key="second-hackathon",
                    sources=self._sources(workbook, sheets=("Final builds",)),
                )

    def test_duplicate_external_id_across_selected_sheets_fails_closed(self) -> None:
        selected = _csv_rows(FIXTURES / "events" / "second-submissions.csv")
        with tempfile.TemporaryDirectory() as directory:
            workbook = Path(directory) / "builds.xlsx"
            _write_workbook(
                workbook,
                [("Final builds", selected), ("Backup builds", selected)],
            )

            with self.assertRaisesRegex(ValueError, "duplicate external record"):
                normalize_mapped_sources(
                    event_key="second-hackathon",
                    sources=self._sources(
                        workbook,
                        sheets=("Final builds", "Backup builds"),
                    ),
                )

    def test_high_expansion_workbook_fails_before_xml_parsing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workbook = Path(directory) / "builds.xlsx"
            with ZipFile(workbook, "w", compression=ZIP_DEFLATED) as archive:
                archive.writestr("high-expansion.bin", b"A" * (1024 * 1024))

            with self.assertRaisesRegex(ValueError, "expansion"):
                normalize_mapped_sources(
                    event_key="second-hackathon",
                    sources=self._sources(workbook, sheets=("Final builds",)),
                )

    def test_duplicate_archive_member_name_fails_before_xml_parsing(self) -> None:
        selected = _csv_rows(FIXTURES / "events" / "second-submissions.csv")
        with tempfile.TemporaryDirectory() as directory:
            workbook = Path(directory) / "builds.xlsx"
            _write_workbook(workbook, {"Final builds": selected})
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                with ZipFile(workbook, "a", compression=ZIP_DEFLATED) as archive:
                    archive.writestr("xl/workbook.xml", "<ambiguous-workbook/>")

            with self.assertRaisesRegex(ValueError, "duplicate archive member"):
                normalize_mapped_sources(
                    event_key="second-hackathon",
                    sources=self._sources(workbook, sheets=("Final builds",)),
                )


if __name__ == "__main__":
    unittest.main()
