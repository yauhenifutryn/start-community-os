"""Universal normalized-event contract behavior."""

from __future__ import annotations

import csv
from dataclasses import fields
from pathlib import Path
import tempfile
import unittest

from community_os.config import load_mapping
from community_os.normalized_event import (
    EntityKind,
    MappedSourceInput,
    NormalizedApplicant,
    NormalizedAttendance,
    NormalizedEventData,
    NormalizedProject,
    NormalizedTeam,
    RejectedRow,
    RejectionReason,
    SourceCoverage,
    SourceCoverageState,
    StableIdStrategy,
    SubmittedProjectMembership,
    TeamMembership,
    normalize_mapped_sources,
    stable_reference,
)


ROOT = Path(__file__).resolve().parents[1]


class NormalizedEventTests(unittest.TestCase):
    def _applicant(self, event_key: str, provider_id: str) -> NormalizedApplicant:
        return NormalizedApplicant(
            ref=stable_reference(
                event_key=event_key,
                kind=EntityKind.APPLICANT,
                strategy=StableIdStrategy.PROVIDER_ID,
                stable_value=provider_id,
            ),
            source_refs=(
                stable_reference(
                    event_key=event_key,
                    kind=EntityKind.SOURCE_RECORD,
                    strategy=StableIdStrategy.PROVIDER_ID,
                    stable_value=f"applications:{provider_id}",
                ),
            ),
        )

    def test_stable_references_and_contract_survive_input_reordering(self) -> None:
        def build(applicant_ids: list[str]) -> NormalizedEventData:
            applicants = [self._applicant("second-hackathon", item) for item in applicant_ids]
            applicants_by_provider_id = dict(zip(applicant_ids, applicants, strict=True))
            team = NormalizedTeam(
                ref=stable_reference(
                    event_key="second-hackathon",
                    kind=EntityKind.TEAM,
                    strategy=StableIdStrategy.PROVIDER_ID,
                    stable_value="team-krk-7",
                )
            )
            project = NormalizedProject(
                ref=stable_reference(
                    event_key="second-hackathon",
                    kind=EntityKind.PROJECT,
                    strategy=StableIdStrategy.PROVIDER_ID,
                    stable_value="project-42",
                ),
                team_ref=team.ref,
                submitted=True,
            )
            return NormalizedEventData.create(
                event_key="second-hackathon",
                applicants=applicants,
                teams=[team],
                projects=[project],
                team_memberships=[
                    TeamMembership(team.ref, applicant.ref) for applicant in applicants
                ],
                submitted_project_memberships=[
                    SubmittedProjectMembership(
                        project.ref,
                        applicants_by_provider_id["person-a"].ref,
                    )
                ],
                coverage=[
                    SourceCoverage("applications", required=True, state=SourceCoverageState.AVAILABLE)
                ],
            )

        first = build(["person-b", "person-a"])
        second = build(["person-a", "person-b"])

        self.assertEqual(first, second)
        self.assertNotEqual(
            first.applicants[0].ref,
            stable_reference(
                event_key="another-event",
                kind=EntityKind.APPLICANT,
                strategy=StableIdStrategy.PROVIDER_ID,
                stable_value="person-a",
            ),
        )
        self.assertNotIn("row", first.applicants[0].ref)

    def test_team_can_exist_without_a_project(self) -> None:
        applicant = self._applicant("second-hackathon", "person-a")
        team = NormalizedTeam(
            ref=stable_reference(
                event_key="second-hackathon",
                kind=EntityKind.TEAM,
                strategy=StableIdStrategy.PROVIDER_ID,
                stable_value="team-without-submission",
            )
        )

        data = NormalizedEventData.create(
            event_key="second-hackathon",
            applicants=[applicant],
            teams=[team],
            team_memberships=[TeamMembership(team.ref, applicant.ref)],
        )

        self.assertEqual(len(data.teams), 1)
        self.assertEqual(data.projects, ())

    def test_team_and_submitted_project_membership_are_separate(self) -> None:
        first = self._applicant("second-hackathon", "person-a")
        second = self._applicant("second-hackathon", "person-b")
        team = NormalizedTeam(
            ref=stable_reference(
                event_key="second-hackathon",
                kind=EntityKind.TEAM,
                strategy=StableIdStrategy.PROVIDER_ID,
                stable_value="team-7",
            )
        )
        project = NormalizedProject(
            ref=stable_reference(
                event_key="second-hackathon",
                kind=EntityKind.PROJECT,
                strategy=StableIdStrategy.PROVIDER_ID,
                stable_value="project-7",
            ),
            team_ref=team.ref,
            submitted=True,
        )

        data = NormalizedEventData.create(
            event_key="second-hackathon",
            applicants=[first, second],
            teams=[team],
            projects=[project],
            team_memberships=[
                TeamMembership(team.ref, first.ref),
                TeamMembership(team.ref, second.ref),
            ],
            submitted_project_memberships=[
                SubmittedProjectMembership(project.ref, first.ref)
            ],
        )

        self.assertEqual(len(data.team_memberships), 2)
        self.assertEqual(len(data.submitted_project_memberships), 1)
        self.assertNotEqual(
            {item.applicant_ref for item in data.team_memberships},
            {item.applicant_ref for item in data.submitted_project_memberships},
        )

    def test_missing_optional_source_is_a_coverage_state(self) -> None:
        data = NormalizedEventData.create(
            event_key="second-hackathon",
            coverage=[
                SourceCoverage(
                    "career",
                    required=False,
                    state=SourceCoverageState.MISSING_OPTIONAL,
                )
            ],
        )

        self.assertEqual(data.coverage[0].state, SourceCoverageState.MISSING_OPTIONAL)

    def test_rejected_rows_keep_only_bounded_provenance(self) -> None:
        rejected = RejectedRow(
            source_role="applications",
            source_sha256="a" * 64,
            row_number=7,
            reason=RejectionReason.MISSING_STABLE_ID,
        )
        data = NormalizedEventData.create(
            event_key="second-hackathon",
            rejected_rows=[rejected],
        )

        self.assertEqual(
            {item.name for item in fields(RejectedRow)},
            {
                "source_role",
                "source_sha256",
                "row_number",
                "reason",
                "source_partition",
            },
        )
        self.assertFalse(hasattr(data.rejected_rows[0], "raw"))
        self.assertEqual(data.applicants, ())

    def test_mutable_constructor_inputs_are_defensively_copied(self) -> None:
        applicant_ref = stable_reference(
            event_key="second-hackathon",
            kind=EntityKind.APPLICANT,
            strategy=StableIdStrategy.PROVIDER_ID,
            stable_value="person-a",
        )
        mutable_source_refs = [
            stable_reference(
                event_key="second-hackathon",
                kind=EntityKind.SOURCE_RECORD,
                strategy=StableIdStrategy.PROVIDER_ID,
                stable_value="applications:person-a",
            )
        ]
        applicant = NormalizedApplicant(
            ref=applicant_ref,
            source_refs=mutable_source_refs,  # type: ignore[arg-type]
        )
        mutable_applicants = [applicant]
        data = NormalizedEventData(
            event_key="second-hackathon",
            applicants=mutable_applicants,  # type: ignore[arg-type]
        )

        mutable_source_refs.clear()
        mutable_applicants.clear()

        self.assertIsInstance(applicant.source_refs, tuple)
        self.assertEqual(len(applicant.source_refs), 1)
        self.assertIsInstance(data.applicants, tuple)
        self.assertEqual(len(data.applicants), 1)

    def test_cross_event_references_are_rejected(self) -> None:
        other_event_applicant = NormalizedApplicant(
            ref=stable_reference(
                event_key="another-event",
                kind=EntityKind.APPLICANT,
                strategy=StableIdStrategy.PROVIDER_ID,
                stable_value="person-a",
            )
        )

        with self.assertRaisesRegex(ValueError, "event"):
            NormalizedEventData.create(
                event_key="second-hackathon",
                applicants=[other_event_applicant],
            )

    def test_applicant_source_reference_order_is_canonical(self) -> None:
        applicant_ref = stable_reference(
            event_key="second-hackathon",
            kind=EntityKind.APPLICANT,
            strategy=StableIdStrategy.PROVIDER_ID,
            stable_value="person-a",
        )
        source_refs = tuple(
            stable_reference(
                event_key="second-hackathon",
                kind=EntityKind.SOURCE_RECORD,
                strategy=StableIdStrategy.PROVIDER_ID,
                stable_value=f"{role}:person-a",
            )
            for role in ("attendance", "applications")
        )

        first = NormalizedApplicant(applicant_ref, source_refs)
        second = NormalizedApplicant(applicant_ref, tuple(reversed(source_refs)))

        self.assertEqual(first, second)

    def test_rejected_row_number_must_be_an_integer(self) -> None:
        with self.assertRaisesRegex(ValueError, "positive integer"):
            RejectedRow(
                source_role="applications",
                source_sha256="a" * 64,
                row_number="7",  # type: ignore[arg-type]
                reason=RejectionReason.MALFORMED_RECORD,
            )


class MappedSourceNormalizationTests(unittest.TestCase):
    mapping_root = ROOT / "tests" / "fixtures" / "mappings"
    event_root = ROOT / "tests" / "fixtures" / "events"

    def _applicant(self, event_key: str, provider_id: str) -> NormalizedApplicant:
        return NormalizedApplicant(
            ref=stable_reference(
                event_key=event_key,
                kind=EntityKind.APPLICANT,
                strategy=StableIdStrategy.PROVIDER_ID,
                stable_value=provider_id,
            ),
            source_refs=(
                stable_reference(
                    event_key=event_key,
                    kind=EntityKind.SOURCE_RECORD,
                    strategy=StableIdStrategy.PROVIDER_ID,
                    stable_value=f"attendance:{provider_id}",
                ),
            ),
        )

    def _sources(
        self,
        *,
        paths: dict[str, Path | None] | None = None,
    ) -> list[MappedSourceInput]:
        selected = paths or {}

        def path(role: str) -> Path | None:
            return selected.get(role, self.event_root / f"second-{role}.csv")

        return [
            MappedSourceInput(
                role="applications",
                required=True,
                path=path("applications"),
                mapping=load_mapping(self.mapping_root / "second-applications.json"),
            ),
            MappedSourceInput(
                role="attendance",
                required=True,
                path=path("attendance"),
                mapping=load_mapping(self.mapping_root / "second-attendance.json"),
                positive_values=("admitted",),
            ),
            MappedSourceInput(
                role="teams",
                required=False,
                path=path("teams"),
                mapping=load_mapping(self.mapping_root / "second-teams.json"),
            ),
            MappedSourceInput(
                role="submissions",
                required=False,
                path=path("submissions"),
                mapping=load_mapping(self.mapping_root / "second-submissions.json"),
                positive_values=("final",),
            ),
        ]

    def test_different_mappings_normalize_second_event_structure(self) -> None:
        sources = self._sources()

        data = normalize_mapped_sources(
            event_key="second-hackathon",
            sources=sources,
        )

        self.assertEqual(len(data.applicants), 3)
        self.assertEqual(len(data.attendance), 3)
        self.assertEqual(sum(item.accepted is True for item in data.attendance), 2)
        self.assertEqual(sum(item.present is True for item in data.attendance), 1)
        self.assertEqual(len(data.teams), 2)
        self.assertEqual({item.track for item in data.teams}, {"Civic Tech", "Robotics"})
        self.assertEqual(len(data.projects), 1)
        self.assertEqual(data.projects[0].track, "Robotics")
        self.assertEqual(
            sum(bool(getattr(item, "github_supplied", False)) for item in data.applicants),
            2,
        )
        self.assertIs(getattr(data.projects[0], "repository_supplied", None), True)
        self.assertIs(getattr(data.projects[0], "demo_supplied", None), True)
        self.assertEqual(len(data.team_memberships), 3)
        self.assertEqual(len(data.submitted_project_memberships), 2)
        self.assertEqual(len(data.rejected_rows), 2)
        self.assertNotIn("unknown@example.test", repr(data))
        self.assertNotIn("alpha-builder", repr(data))
        self.assertNotIn("code.example.test", repr(data))
        self.assertNotIn("video.example.test", repr(data))
        self.assertEqual(
            {source.mapping.metadata["fixture_sheet"] for source in sources},
            {"Applications 2027", "Door scans", "Final builds", "Squad roster"},
        )
        self.assertEqual(
            sources[0].mapping.expected_headers,
            (
                "Application Code", "Contact Address", "Home Market",
                "Challenge Choice", "Code Profile",
            ),
        )

    def test_reversing_every_raw_source_does_not_change_normalized_data(self) -> None:
        expected = normalize_mapped_sources(
            event_key="second-hackathon",
            sources=self._sources(),
        )

        with tempfile.TemporaryDirectory() as directory:
            temporary = Path(directory)
            reversed_paths: dict[str, Path] = {}
            for role in ("applications", "attendance", "teams", "submissions"):
                source = self.event_root / f"second-{role}.csv"
                target = temporary / source.name
                with source.open(encoding="utf-8", newline="") as stream:
                    rows = list(csv.reader(stream))
                with target.open("w", encoding="utf-8", newline="") as stream:
                    writer = csv.writer(stream)
                    writer.writerow(rows[0])
                    writer.writerows(reversed(rows[1:]))
                reversed_paths[role] = target

            actual = normalize_mapped_sources(
                event_key="second-hackathon",
                sources=self._sources(paths=reversed_paths),
            )

        self.assertEqual(actual.applicants, expected.applicants)
        self.assertEqual(actual.attendance, expected.attendance)
        self.assertEqual(actual.teams, expected.teams)
        self.assertEqual(actual.projects, expected.projects)
        self.assertEqual(actual.team_memberships, expected.team_memberships)
        self.assertEqual(
            actual.submitted_project_memberships,
            expected.submitted_project_memberships,
        )
        self.assertEqual(actual.coverage, expected.coverage)
        self.assertEqual(
            sorted(item.reason for item in actual.rejected_rows),
            sorted(item.reason for item in expected.rejected_rows),
        )

    def test_missing_optional_submission_source_preserves_coverage_and_teams(self) -> None:
        data = normalize_mapped_sources(
            event_key="second-hackathon",
            sources=self._sources(paths={"submissions": None}),
        )

        coverage = {item.source_role: item.state for item in data.coverage}
        self.assertEqual(coverage["submissions"], SourceCoverageState.MISSING_OPTIONAL)
        self.assertEqual(len(data.teams), 2)
        self.assertEqual(data.projects, ())
        self.assertEqual(data.submitted_project_memberships, ())

    def test_unrecognized_attendance_status_remains_unknown(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            attendance = Path(directory) / "second-attendance.csv"
            attendance.write_text(
                (self.event_root / "second-attendance.csv")
                .read_text(encoding="utf-8")
                .replace("waitlisted", "provider_new_state"),
                encoding="utf-8",
            )
            data = normalize_mapped_sources(
                event_key="second-hackathon",
                sources=self._sources(paths={"attendance": attendance}),
            )

        gamma_ref = stable_reference(
            event_key="second-hackathon",
            kind=EntityKind.APPLICANT,
            strategy=StableIdStrategy.CANONICAL_CONTENT_KEY,
            stable_value="gamma@example.test",
        )
        observation = next(
            item for item in data.attendance if item.applicant_ref == gamma_ref
        )
        self.assertIsNone(observation.accepted)

    def test_blank_presence_and_unrecognized_submission_status_remain_unknown(self) -> None:
        attendance_data = normalize_mapped_sources(
            event_key="second-hackathon",
            sources=self._sources(),
        )
        self.assertNotIn(False, [item.present for item in attendance_data.attendance])

        with tempfile.TemporaryDirectory() as directory:
            submissions = Path(directory) / "second-submissions.csv"
            submissions.write_text(
                (self.event_root / "second-submissions.csv")
                .read_text(encoding="utf-8")
                .replace(",final,", ",provider_new_state,")
                .replace("https://code.example.test/signalmesh", "")
                .replace("https://video.example.test/signalmesh", ""),
                encoding="utf-8",
            )
            submission_data = normalize_mapped_sources(
                event_key="second-hackathon",
                sources=self._sources(paths={"submissions": submissions}),
            )

        self.assertEqual(len(submission_data.projects), 1)
        self.assertIsNone(submission_data.projects[0].submitted)
        self.assertIs(submission_data.projects[0].repository_supplied, False)
        self.assertIs(submission_data.projects[0].demo_supplied, False)
        self.assertEqual(submission_data.submitted_project_memberships, ())

    def test_attendance_observation_is_immutable_and_relation_checked(self) -> None:
        applicant = self._applicant("second-hackathon", "person-a")
        attendance = NormalizedAttendance(
            applicant_ref=applicant.ref,
            source_ref=applicant.source_refs[0],
            accepted=True,
            present=None,
        )

        data = NormalizedEventData.create(
            event_key="second-hackathon",
            applicants=[applicant],
            attendance=[attendance],
        )

        self.assertEqual(data.attendance, (attendance,))


if __name__ == "__main__":
    unittest.main()
