"""Behavioral tests for the one-time real talent-report release workflow."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


def _current_event_definition():
    from community_os.event_definition import load_event_definition

    return load_event_definition(
        Path(__file__).resolve().parents[1]
        / "config/events/openai-hackathon-2026.json"
    )


class RealReportTests(unittest.TestCase):
    def test_partner_feedback_template_requests_decision_relevant_future_data(self) -> None:
        from community_os.real_report import _partner_feedback_template

        template = _partner_feedback_template()

        self.assertIn("Which additional aggregate would change a decision?", template)
        self.assertIn("decision or purpose", template)
        self.assertIn("acceptable denominator", template)
        self.assertIn("applicants can provide it directly", template)
        self.assertIn("Which demographics are truly decision-relevant", template)
        self.assertIn("collection notice", template)
        self.assertIn("Keep qualitative notes outside report analytics", template)

    def test_reusable_payload_and_release_builders_require_an_explicit_event_definition(self) -> None:
        from inspect import Parameter, signature
        from community_os.real_report import (
            _application_reconciliation,
            _application_rows,
            build_real_release,
            build_v1_payload,
            build_v3_payload,
        )

        for builder in (
            _application_reconciliation,
            _application_rows,
            build_v1_payload,
            build_v3_payload,
            build_real_release,
        ):
            with self.subTest(builder=builder.__name__):
                parameter = signature(builder).parameters["event_definition"]
                self.assertIs(parameter.default, Parameter.empty)

    def test_real_release_grouping_uses_event_configured_workbook_sheets(self) -> None:
        from community_os.operator_pipeline import SourceSlot
        from community_os.real_report import _group_final_sources

        definition = _current_event_definition()
        with patch(
            "community_os.operator_pipeline.records_from_source",
            return_value=[],
        ) as records:
            _group_final_sources(
                Path("preferences.xlsx"),
                Path("submissions.xlsx"),
                event_definition=definition,
            )

        self.assertEqual(records.call_count, 2)
        self.assertEqual(
            records.call_args_list[0].args,
            (Path("preferences.xlsx"), SourceSlot.TRACK),
        )
        self.assertEqual(
            records.call_args_list[0].kwargs,
            {
                "selected_sheets": definition.source("preferences").sheets,
                "source": definition.source("preferences"),
            },
        )
        self.assertEqual(
            records.call_args_list[1].args,
            (Path("submissions.xlsx"), SourceSlot.DEVPOST),
        )
        self.assertEqual(
            records.call_args_list[1].kwargs,
            {
                "selected_sheets": definition.source("submissions").sheets,
                "source": definition.source("submissions"),
            },
        )

    def test_normalized_event_payloads_are_definition_driven_and_order_independent(self) -> None:
        from community_os.event_definition import load_event_definition
        from community_os.normalized_event import (
            EntityKind,
            NormalizedApplicant,
            NormalizedAttendance,
            NormalizedEventData,
            NormalizedProject,
            NormalizedTeam,
            StableIdStrategy,
            SubmittedProjectMembership,
            TeamMembership,
            stable_reference,
        )
        from community_os.real_report import build_event_payloads

        root = Path(__file__).resolve().parents[1]
        loaded = load_event_definition(
            root / "tests/fixtures/events/second-hackathon.synthetic.json",
        )
        definition = replace(
            loaded,
            sources=loaded.sources[:2],
            sha256="e" * 64,
        )

        def reference(kind: EntityKind, value: str) -> str:
            return stable_reference(
                event_key=definition.event_key,
                kind=kind,
                strategy=StableIdStrategy.PROVIDER_ID,
                stable_value=value,
            )

        applicants = tuple(
            NormalizedApplicant(
                reference(EntityKind.APPLICANT, f"app-{index}"),
                github_supplied=index < 14,
            )
            for index in range(28)
        )
        attendance = tuple(
            NormalizedAttendance(
                applicant_ref=applicant.ref,
                source_ref=reference(EntityKind.SOURCE_RECORD, f"door-{index}"),
                accepted=True if index < 21 else None,
                present=True if index < 14 else None,
            )
            for index, applicant in enumerate(applicants)
        )
        teams = tuple(
            NormalizedTeam(reference(EntityKind.TEAM, f"team-{index}"), track="robotics")
            for index in range(14)
        )
        projects = tuple(
            NormalizedProject(
                reference(EntityKind.PROJECT, f"project-{index}"),
                team_ref=teams[index].ref,
                submitted=True,
                track="robotics",
                repository_supplied=True,
                demo_supplied=True,
            )
            for index in range(7)
        )
        memberships = tuple(
            TeamMembership(team.ref, applicants[index].ref)
            for index, team in enumerate(teams)
        )
        submitted_memberships = tuple(
            SubmittedProjectMembership(project.ref, applicants[index].ref)
            for index, project in enumerate(projects)
        )
        data = NormalizedEventData.create(
            event_key=definition.event_key,
            applicants=applicants,
            attendance=attendance,
            teams=teams,
            projects=projects,
            team_memberships=memberships,
            submitted_project_memberships=submitted_memberships,
        )
        reversed_data = NormalizedEventData.create(
            event_key=definition.event_key,
            applicants=reversed(applicants),
            attendance=reversed(attendance),
            teams=reversed(teams),
            projects=reversed(projects),
            team_memberships=reversed(memberships),
            submitted_project_memberships=reversed(submitted_memberships),
        )

        expected = build_event_payloads(
            event_definition=definition,
            normalized_event=data,
            generated_at="2027-02-22T12:00:00Z",
            synthetic=True,
        )
        actual = build_event_payloads(
            event_definition=definition,
            normalized_event=reversed_data,
            generated_at="2027-02-22T12:00:00Z",
            synthetic=True,
        )

        self.assertEqual(actual, expected)
        for payload in expected.values():
            self.assertEqual(payload["metadata"]["event_key"], definition.event_key)
            self.assertEqual(payload["metadata"]["event_name"], definition.event_name)
            self.assertEqual(payload["metadata"]["event_date"], "2027-02-20")
            self.assertTrue(payload["metadata"]["synthetic"])
            self.assertEqual(payload["privacy"]["minimum_count"], 7)
            self.assertNotIn("Twenty", json.dumps(payload))
            self.assertNotIn("four source", json.dumps(payload).casefold())
        matrix = expected["v3"]["team_submission_matrix"]
        self.assertEqual(matrix["row_keys"], ["robotics"])
        self.assertEqual(
            {(cell["column"], cell["count"]["value"]) for cell in matrix["cells"]},
            {("submitted", 7), ("not_submitted", 7)},
        )
        self.assertEqual(expected["v1"]["cohort"]["denominator"]["value"], 28)
        self.assertNotIn(
            "github_supplied",
            expected["v3"]["builder_signal_intersections"]["signal_keys"],
        )
        builder_evidence = next(
            dimension for dimension in expected["v1"]["dimensions"]
            if dimension["key"] == "builder_evidence"
        )
        self.assertNotIn(
            "github_supplied", {item["key"] for item in builder_evidence["items"]},
        )
        artifacts = {
            item["key"]: item
            for item in expected["v3"]["artifact_completeness"]["items"]
        }
        self.assertEqual(artifacts["repository"]["present"]["value"], 7)
        self.assertEqual(artifacts["demo"]["present"]["value"], 7)
        self.assertEqual(artifacts["repository"]["status"], "complete")
        self.assertEqual(artifacts["demo"]["status"], "complete")

    def test_normalized_event_payloads_preserve_missing_optional_source_state(self) -> None:
        from community_os.event_definition import load_event_definition
        from community_os.normalized_event import (
            EntityKind,
            NormalizedApplicant,
            NormalizedAttendance,
            NormalizedEventData,
            SourceCoverage,
            SourceCoverageState,
            StableIdStrategy,
            stable_reference,
        )
        from community_os.real_report import build_event_payloads

        root = Path(__file__).resolve().parents[1]
        definition = load_event_definition(
            root / "tests/fixtures/events/second-hackathon.synthetic.json",
        )

        def reference(kind: EntityKind, value: str) -> str:
            return stable_reference(
                event_key=definition.event_key,
                kind=kind,
                strategy=StableIdStrategy.PROVIDER_ID,
                stable_value=value,
            )

        applicants = tuple(
            NormalizedApplicant(reference(EntityKind.APPLICANT, f"app-{index}"))
            for index in range(28)
        )
        data = NormalizedEventData.create(
            event_key=definition.event_key,
            applicants=applicants,
            attendance=(
                NormalizedAttendance(
                    applicant_ref=applicant.ref,
                    source_ref=reference(EntityKind.SOURCE_RECORD, f"door-{index}"),
                    accepted=True if index < 21 else None,
                    present=True if index < 14 else None,
                )
                for index, applicant in enumerate(applicants)
            ),
            coverage=(
                SourceCoverage(
                    source.role,
                    source.required,
                    SourceCoverageState.AVAILABLE
                    if source.required else SourceCoverageState.MISSING_OPTIONAL,
                )
                for source in definition.sources
            ),
        )

        payloads = build_event_payloads(
            event_definition=definition,
            normalized_event=data,
            generated_at="2027-02-22T12:00:00Z",
        )

        for payload in payloads.values():
            states = {
                note["source"]: note["state"] for note in payload["source_notes"]
            }
            self.assertEqual(states["applications"], "validated")
            self.assertEqual(states["attendance"], "validated")
            self.assertEqual(states["teams"], "pending")
            self.assertEqual(states["submissions"], "pending")
            source_readiness = next(
                item for item in payload["readiness"]
                if item["component"] == "source_reconciliation"
            )
            self.assertIn("2 of 4", source_readiness["note"])

    def test_current_event_uses_the_same_normalized_payload_entry_point(self) -> None:
        from community_os.event_definition import load_event_definition
        from community_os.normalized_event import (
            EntityKind,
            NormalizedApplicant,
            NormalizedAttendance,
            NormalizedEventData,
            NormalizedProject,
            NormalizedTeam,
            StableIdStrategy,
            SubmittedProjectMembership,
            TeamMembership,
            stable_reference,
        )
        from community_os.real_report import build_event_payloads

        root = Path(__file__).resolve().parents[1]
        definition = load_event_definition(
            root / "config/events/openai-hackathon-2026.json",
        )

        def reference(kind: EntityKind, value: str) -> str:
            return stable_reference(
                event_key=definition.event_key,
                kind=kind,
                strategy=StableIdStrategy.PROVIDER_ID,
                stable_value=value,
            )

        applicants = tuple(
            NormalizedApplicant(
                reference(EntityKind.APPLICANT, f"app-{index}"),
                github_supplied=index < 120,
            )
            for index in range(286)
        )
        teams = tuple(
            NormalizedTeam(
                reference(EntityKind.TEAM, f"team-{index}"),
                track="boski" if index < 10 else "solidgate",
            )
            for index in range(20)
        )
        projects = tuple(
            NormalizedProject(
                reference(EntityKind.PROJECT, f"project-{index}"),
                team_ref=teams[index].ref,
                submitted=True,
                track=teams[index].track,
                repository_supplied=index < 19,
                demo_supplied=index < 2,
            )
            for index in range(20)
        )
        normalized = NormalizedEventData.create(
            event_key=definition.event_key,
            applicants=applicants,
            attendance=(
                NormalizedAttendance(
                    applicant_ref=applicant.ref,
                    source_ref=reference(EntityKind.SOURCE_RECORD, f"door-{index}"),
                    accepted=True if index < 82 else None,
                    present=True if index < 78 else None,
                )
                for index, applicant in enumerate(applicants)
            ),
            teams=teams,
            projects=projects,
            team_memberships=(
                TeamMembership(teams[index % len(teams)].ref, applicants[index].ref)
                for index in range(90)
            ),
            submitted_project_memberships=(
                SubmittedProjectMembership(
                    projects[index % len(projects)].ref,
                    applicants[index].ref,
                )
                for index in range(76)
            ),
        )

        payloads = build_event_payloads(
            event_definition=definition,
            normalized_event=normalized,
            generated_at="2026-07-13T12:00:00Z",
        )

        self.assertEqual(set(payloads), {"v1", "v3"})
        for payload in payloads.values():
            self.assertEqual(payload["metadata"]["event_key"], definition.event_key)
            self.assertEqual(payload["metadata"]["event_name"], definition.event_name)
            self.assertEqual(payload["privacy"]["minimum_count"], 5)
        self.assertEqual(
            sum(item.present is True for item in normalized.attendance),
            78,
        )
        self.assertEqual(
            [
                stage["count"]["value"]
                for stage in payloads["v3"]["attendance_funnel"]["stages"]
            ],
            [286, 82, None],
        )
        self.assertEqual(
            payloads["v3"]["attendance_funnel"]["stages"][2]["count"]["reason"],
            "Complement below publication threshold",
        )
        self.assertNotIn(
            "github_supplied",
            payloads["v3"]["builder_signal_intersections"]["signal_keys"],
        )
        builder_evidence = next(
            dimension for dimension in payloads["v1"]["dimensions"]
            if dimension["key"] == "builder_evidence"
        )
        self.assertNotIn(
            "github_supplied", {item["key"] for item in builder_evidence["items"]},
        )
        artifacts = {
            item["key"]: item
            for item in payloads["v3"]["artifact_completeness"]["items"]
        }
        self.assertEqual(artifacts["repository"]["status"], "partial")
        self.assertIsNone(artifacts["repository"]["present"]["value"])
        self.assertEqual(artifacts["demo"]["status"], "partial")
        self.assertIsNone(artifacts["demo"]["present"]["value"])

    def test_event_source_bindings_and_code_provenance_are_manifest_ready(self) -> None:
        from community_os.event_definition import load_event_definition
        from community_os.real_report import (
            _code_provenance,
            _population_sha256,
            _release_manifest_context,
            _validated_event_source_bindings,
        )

        root = Path(__file__).resolve().parents[1]
        definition = load_event_definition(
            root / "tests/fixtures/events/second-hackathon.synthetic.json",
        )
        approved = {
            source.role: f"{index + 1:x}" * 64
            for index, source in enumerate(definition.sources)
        }
        bindings = _validated_event_source_bindings(
            definition,
            observed_source_hashes=approved,
            approved_source_hashes=approved,
        )
        self.assertEqual(set(bindings), {source.role for source in definition.sources})
        for source in definition.sources:
            self.assertEqual(bindings[source.role]["adapter_id"], source.adapter_id)
            self.assertEqual(
                bindings[source.role]["mapping_sha256"], source.mapping_sha256,
            )
            self.assertEqual(bindings[source.role]["source_sha256"], approved[source.role])
        with self.assertRaisesRegex(ValueError, "source hash drift"):
            _validated_event_source_bindings(
                definition,
                observed_source_hashes={**approved, "applications": "f" * 64},
                approved_source_hashes=approved,
            )

        with tempfile.TemporaryDirectory() as first_directory, tempfile.TemporaryDirectory() as second_directory:
            first = Path(first_directory)
            second = Path(second_directory)
            for repository in (first, second):
                package = repository / "community_os"
                package.mkdir()
                (package / "b.py").write_text("B = 2\n", encoding="utf-8")
                (package / "a.py").write_text("A = 1\n", encoding="utf-8")
            first_provenance = _code_provenance(first, git_sha="a" * 40)
            second_provenance = _code_provenance(second, git_sha="a" * 40)
            self.assertEqual(first_provenance, second_provenance)
            (second / "community_os" / "a.py").write_text("A = 3\n", encoding="utf-8")
            self.assertNotEqual(
                first_provenance["python_source_sha256"],
                _code_provenance(second, git_sha="a" * 40)["python_source_sha256"],
            )

        context = _release_manifest_context(
            definition,
            source_bindings=bindings,
            code_provenance=first_provenance,
            event_approval_sha256="b" * 64,
        )
        self.assertEqual(context["event"]["definition_sha256"], definition.sha256)
        self.assertEqual(context["event"]["privacy_minimum_count"], 7)
        self.assertEqual(context["event_approval_sha256"], "b" * 64)
        self.assertEqual(context["semantic"]["taxonomy_version"], "semantic-taxonomy-v1")
        self.assertEqual(context["code_provenance"]["git_sha"], "a" * 40)
        self.assertEqual(
            _population_sha256(("app-b", "app-a"), event_key=definition.event_key),
            _population_sha256(("app-a", "app-b"), event_key=definition.event_key),
        )
        self.assertRegex(
            _population_sha256(("app-a", "app-b"), event_key=definition.event_key),
            r"^[0-9a-f]{64}$",
        )

    def test_code_provenance_refuses_python_bytes_not_committed_at_head(self) -> None:
        from community_os.real_report import _code_provenance

        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory)
            package = repository / "community_os"
            package.mkdir()
            source = package / "module.py"
            source.write_text("VALUE = 1\n", encoding="utf-8")
            for command in (
                ("git", "init", "--quiet"),
                ("git", "config", "user.name", "Test Operator"),
                ("git", "config", "user.email", "operator@example.invalid"),
                ("git", "add", "community_os/module.py"),
                ("git", "commit", "--quiet", "-m", "fixture"),
            ):
                subprocess.run(command, cwd=repository, check=True, timeout=10)

            committed = _code_provenance(repository)
            self.assertRegex(str(committed["git_sha"]), r"^[0-9a-f]{40}$")
            source.write_text("VALUE = 2\n", encoding="utf-8")

            with self.assertRaisesRegex(
                ValueError, "uncommitted Python source changes",
            ):
                _code_provenance(repository)

    def test_release_source_bindings_require_the_exact_event_approval(self) -> None:
        from community_os.event_approval import EventApproval, EventSourceApproval
        from community_os.event_definition import load_event_definition
        from community_os.real_report import (
            _validate_event_approval_exclusions,
            _validated_event_approval_bindings,
        )

        root = Path(__file__).resolve().parents[1]
        definition = load_event_definition(
            root / "tests/fixtures/events/second-hackathon.synthetic.json",
        )
        observed = {
            source.role: f"{index + 1:x}" * 64
            for index, source in enumerate(definition.sources)
        }
        approval = EventApproval(
            version="event-approval-v2",
            event_key=definition.event_key,
            event_definition_sha256=definition.sha256,
            policy_profile=definition.privacy.policy_profile,
            taxonomy_version=definition.semantic.taxonomy_version,
            metric_registry_version=definition.semantic.metric_registry_version,
            sources=tuple(
                EventSourceApproval(
                    role=source.role,
                    adapter_id=source.adapter_id,
                    mapping_sha256=source.mapping_sha256,
                    source_sha256=observed[source.role],
                )
                for source in definition.sources
            ),
            excluded_subject_refs=frozenset(),
            actor_code="privacy_owner",
            approved_at=datetime(2027, 2, 19, 12, tzinfo=UTC),
            sha256="f" * 64,
        )

        bindings = _validated_event_approval_bindings(
            definition,
            event_approval=approval,
            observed_source_hashes=observed,
        )
        self.assertEqual(
            {role: binding["source_sha256"] for role, binding in bindings.items()},
            observed,
        )
        with self.assertRaisesRegex(ValueError, "event definition"):
            _validated_event_approval_bindings(
                definition,
                event_approval=replace(
                    approval, event_definition_sha256="e" * 64,
                ),
                observed_source_hashes=observed,
            )

        from community_os.enrichment.state import pseudonymous_id

        pseudonym_secret = b"event-exclusion-secret"
        excluded_ref = pseudonymous_id(
            "app-approved", secret=pseudonym_secret, key_version="v1",
        )
        excluded_approval = replace(
            approval, excluded_subject_refs=frozenset({excluded_ref}),
        )
        exclusion_sha256 = hashlib.sha256(
            json.dumps([excluded_ref], separators=(",", ":")).encode("utf-8"),
        ).hexdigest()
        _validate_event_approval_exclusions(
            excluded_approval,
            excluded_application_ids=frozenset({"app-approved"}),
            excluded_subject_refs_by_application_id={"app-approved": excluded_ref},
            exclusion_set_sha256=exclusion_sha256,
            pseudonym_secret=pseudonym_secret,
        )
        with self.assertRaisesRegex(ValueError, "exclusion"):
            _validate_event_approval_exclusions(
                excluded_approval,
                excluded_application_ids=frozenset({"app-different"}),
                excluded_subject_refs_by_application_id={
                    "app-approved": excluded_ref,
                },
                exclusion_set_sha256=exclusion_sha256,
                pseudonym_secret=pseudonym_secret,
            )
        with self.assertRaisesRegex(ValueError, "pseudonym"):
            _validate_event_approval_exclusions(
                excluded_approval,
                excluded_application_ids=frozenset({"app-approved"}),
                excluded_subject_refs_by_application_id={
                    "app-approved": pseudonymous_id(
                        "someone-else", secret=pseudonym_secret, key_version="v1",
                    ),
                },
                exclusion_set_sha256=exclusion_sha256,
                pseudonym_secret=pseudonym_secret,
            )

    def test_application_reconciliation_uses_the_configured_mapping_without_fixed_counts(self) -> None:
        from community_os.event_definition import load_event_definition
        from community_os.real_report import _application_reconciliation

        root = Path(__file__).resolve().parents[1]
        definition = load_event_definition(
            root / "config/events/openai-hackathon-2026.json",
        )
        rows, rejected_count = _application_reconciliation(
            root / "tests/fixtures/luma_guests_synthetic.csv",
            event_definition=definition,
        )

        self.assertEqual([row["external_id"] for row in rows], ["gst_synthetic_001"])
        self.assertEqual(rejected_count, 2)

    def test_reviewed_operational_facts_are_event_scoped_and_count_agnostic(self) -> None:
        from community_os.real_report import _reviewed_operational_facts

        facts = _reviewed_operational_facts(
            {
                "operational_facts": [
                    {
                        "funnel_stage": False,
                        "note": "Separate reviewed operational fact",
                        "reason": "organizer_observation",
                        "stable_key": "event:second-hackathon-synthetic:mid_event_departures",
                        "unit": "people",
                        "value": 3,
                    },
                ],
            },
            event_key="second-hackathon-synthetic",
        )

        self.assertEqual(
            facts,
            {
                "mid_event_departures": {
                    "note": "Separate reviewed operational fact",
                    "reason": "organizer_observation",
                    "unit": "people",
                    "value": 3,
                },
            },
        )

    def test_semantic_release_context_rejects_source_snapshot_drift(self) -> None:
        from community_os.partner_semantic_projection import (
            build_protected_partner_semantic_candidate_summary,
        )
        from community_os.real_report import _validate_semantic_release_context
        from tests.test_partner_semantic_projection import semantic_aggregate

        summary = build_protected_partner_semantic_candidate_summary(
            semantic_aggregate(),
        )
        semantic_context = {
            "event_approval_sha256": summary.event_approval_sha256,
            "event_definition_sha256": summary.event_definition_sha256,
            "event_key": summary.event_key,
            "population_sha256": summary.population_sha256,
            "run_sha256": summary.run_sha256,
            "source_snapshot_sha256": summary.source_snapshot_sha256,
            "taxonomy_sha256": summary.taxonomy_sha256,
            "taxonomy_version": summary.taxonomy_version,
            "total_population": summary.total_population,
        }
        with self.assertRaisesRegex(ValueError, "source snapshot"):
            _validate_semantic_release_context(
                summary,
                event_key=str(summary.event_key),
                source_snapshot_sha256="f" * 64,
                total_population=int(summary.total_population or 0),
                semantic_context=semantic_context,
            )

    def test_semantic_classification_review_requires_complete_reproducible_provenance(self) -> None:
        from community_os.real_report import _validated_classification_review

        review = _validated_classification_review({
            "classifier_version": "semantic-v1", "model": "gpt-5.6-terra",
            "prompt_version": "talent-structured-v1",
            "processor_approval_hash": "a" * 64,
            "reviewer": "privacy_lead", "status": "approved",
        })
        self.assertEqual(review["model"], "gpt-5.6-terra")
        with self.assertRaisesRegex(ValueError, "provenance"):
            _validated_classification_review({
                **review, "processor_approval_hash": None,
            })

    def test_reproduction_guide_is_path_independent(self) -> None:
        from community_os.real_report import _reproduction_guide

        first = _reproduction_guide(
            "2026-07-13T12:00:00Z", semantic_mode="candidate",
        )
        second = _reproduction_guide(
            "2026-07-13T12:00:00Z", semantic_mode="candidate",
        )

        self.assertEqual(first, second)
        self.assertNotIn("/Users/", first)
        self.assertNotIn("protected/", first)
        for variable in (
            "$EVENT_CONFIG", "$EVENT_APPROVAL",
            "$APPLICATIONS_EXPORT", "$ATTENDANCE_EXPORT", "$PREFERENCES_EXPORT",
            "$SUBMISSIONS_EXPORT", "$OVERRIDE_FILE", "$OUTPUT_ROOT",
            "$SEMANTIC_AGGREGATE",
        ):
            self.assertIn(variable, first)
        self.assertIn('--semantic-aggregate "$SEMANTIC_AGGREGATE"', first)
        self.assertIn('--event-config "$EVENT_CONFIG"', first)
        self.assertIn('--event-approval "$EVENT_APPROVAL"', first)
        self.assertIn("--semantic-candidate", first)
        self.assertNotIn("posthog", first.casefold())
        self.assertNotIn("analytics", first.casefold())
        self.assertNotIn(
            "--semantic-aggregate",
            _reproduction_guide(
                "2026-07-13T12:00:00Z", semantic_mode=None,
            ),
        )
        with_exclusions = _reproduction_guide(
            "2026-07-13T12:00:00Z", semantic_mode=None,
            exclusion_bindings=True,
        )
        self.assertIn('--exclusion-bindings "$EXCLUSION_BINDINGS"', with_exclusions)
        self.assertIn(
            "--pseudonym-secret-env REAL_RELEASE_PSEUDONYM_SECRET",
            with_exclusions,
        )

    def test_private_json_write_is_atomic_and_restrictive(self) -> None:
        from community_os.real_report import _private_json_write
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "private" / "state.json"
            _private_json_write(path, {"state": "protected"})
            self.assertEqual(path.read_text(encoding="utf-8"), '{"state":"protected"}\n')
            self.assertEqual(path.parent.stat().st_mode & 0o777, 0o700)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertFalse(path.with_suffix(".tmp").exists())

    def test_team_normalization_and_reviewed_matching_are_conservative(self) -> None:
        from community_os.real_report import match_teams, normalize_team_name

        self.assertEqual(normalize_team_name(" KOD.AI - PACT "), "kod ai pact")
        preferences = {
            "KOD.AI": {"track": "boski", "emails": {"one@example.org"}},
            "Shrek": {"track": "solidgate", "emails": {"two@example.org"}},
        }
        projects = {
            "KOD.AI": {"track": "boski", "emails": {"one@example.org"}},
            "Markit": {"track": "solidgate", "emails": set()},
        }
        with self.assertRaisesRegex(ValueError, "reviewed team link"):
            match_teams(preferences, projects, reviewed_links={})

        matches = match_teams(
            preferences,
            projects,
            reviewed_links={"Shrek": "Markit"},
        )
        self.assertEqual(matches, {"KOD.AI": "KOD.AI", "Shrek": "Markit"})

    def test_attendance_override_is_versioned_auditable_and_exact(self) -> None:
        from community_os.real_report import apply_attendance_overrides

        override = {
            "override_version": "attendance-2026-07-13-v1",
            "operator": "integration-review",
            "timestamp": "2026-07-13T12:00:00Z",
            "corrections": [
                {
                    "stable_key": "event:openai-hackathon-2026:going_accepted",
                    "field": "going_accepted",
                    "source_value": 83,
                    "corrected_value": 82,
                    "reason": "Final organizer correction",
                    "evidence_note": "Aggregate correction supplied by event owner",
                },
                {
                    "stable_key": "event:openai-hackathon-2026:on_site_builders",
                    "field": "on_site_builders",
                    "source_value": 72,
                    "corrected_value": 78,
                    "reason": "Final organizer correction",
                    "evidence_note": "Aggregate correction supplied by event owner",
                },
            ],
        }
        result = apply_attendance_overrides(
            {"applied": 286, "going_accepted": 83, "on_site_builders": 72},
            override,
            event_key="openai-hackathon-2026",
        )
        self.assertEqual(result, {"applied": 286, "going_accepted": 82, "on_site_builders": 78})

        invalid = {**override, "operator": ""}
        with self.assertRaisesRegex(ValueError, "operator"):
            apply_attendance_overrides(
                {"applied": 286, "going_accepted": 83, "on_site_builders": 72},
                invalid,
                event_key="openai-hackathon-2026",
            )

        wrong_event = {
            **override,
            "corrections": [
                {
                    **override["corrections"][0],
                    "stable_key": "event:different-event:going_accepted",
                },
            ],
        }
        with self.assertRaisesRegex(ValueError, "event"):
            apply_attendance_overrides(
                {"applied": 286, "going_accepted": 83, "on_site_builders": 72},
                wrong_event,
                event_key="openai-hackathon-2026",
            )

    def test_person_resolution_uses_only_email_or_reviewed_links(self) -> None:
        from community_os.real_report import resolve_submission_people

        applications = {
            "app-1": {"email": "one@example.org", "name": "One"},
            "app-2": {"email": "two@example.org", "name": "Two"},
        }
        source_people = [
            {"source_ref": "track-1", "email": "ONE@example.org", "name": "One"},
            {"source_ref": "track-2", "email": "changed@example.org", "name": "Two"},
            {"source_ref": "track-3", "email": "unknown@example.org", "name": "Unknown"},
        ]
        result = resolve_submission_people(
            applications,
            source_people,
            reviewed_links={"track-2": "app-2"},
            quarantined_refs={"track-3"},
        )
        self.assertEqual(result.resolved_application_ids, frozenset({"app-1", "app-2"}))
        self.assertEqual(result.quarantined_refs, frozenset({"track-3"}))
        self.assertEqual(result.unresolved_refs, frozenset())

    def test_v3_funnel_uses_correct_public_event_semantics(self) -> None:
        from community_os.real_report import build_v3_payload

        payload = build_v3_payload(
            applied=286,
            going_accepted=82,
            on_site_builders=78,
            track_project_counts={"boski": 10, "solidgate": 10},
            submitted_people=76,
            github_supplied=120,
            team_applicants=90,
            solo_applicants=196,
            repository_projects=19,
            demo_projects=2,
            generated_at="2026-07-13T12:00:00Z",
            event_definition=_current_event_definition(),
        )
        stages = payload["attendance_funnel"]["stages"]
        self.assertEqual([stage["key"] for stage in stages], ["applied", "going_accepted", "on_site"])
        self.assertNotIn("eligible", " ".join(stage["label"] for stage in stages).casefold())
        self.assertEqual(
            stages[2]["count"],
            {"value": None, "privacy": "withheld", "reason": "Complement below publication threshold"},
        )
        journey_nodes = {
            node["key"]: node["count"]["value"]
            for node in payload["journey"]["nodes"]
        }
        self.assertEqual(journey_nodes, {
            "applied": 286,
            "going_accepted": 82,
            "not_accepted_reason_unknown": 204,
            "on_site": None,
        })
        self.assertIn(
            {
                "source": "applied", "target": "not_accepted_reason_unknown",
                "count": {"value": 204, "privacy": "published", "reason": None},
                "unit": "people",
            },
            payload["journey"]["links"],
        )
        self.assertEqual(
            payload["builder_signal_intersections"]["signal_keys"],
            ["submitted_team"],
        )
        self.assertNotIn("github_supplied", json.dumps(payload))
        submitted = next(
            item for item in payload["builder_signal_intersections"]["intersections"]
            if item["signals"] == ["submitted_team"]
        )
        self.assertEqual(submitted["count"]["value"], 76)
        repository = next(
            item for item in payload["artifact_completeness"]["items"]
            if item["key"] == "repository"
        )
        self.assertEqual(repository["present"]["value"], None)
        self.assertEqual(payload["privacy"]["state"], "withheld_cells")

    def test_public_contracts_fail_closed_when_a_suppressed_complement_is_derivable(self) -> None:
        from community_os.real_report import build_v1_payload, build_v3_payload

        applications = [{"external_id": f"app-{index}"} for index in range(10)]
        for going_accepted in (2, 8):
            with self.subTest(going_accepted=going_accepted):
                with self.assertRaisesRegex(ValueError, "suppressed complement"):
                    build_v3_payload(
                        applied=10,
                        going_accepted=going_accepted,
                        on_site_builders=going_accepted,
                        track_project_counts={"boski": 5},
                        submitted_people=5,
                        github_supplied=5,
                        team_applicants=5,
                        solo_applicants=5,
                        repository_projects=5,
                        demo_projects=5,
                        generated_at="2026-07-13T12:00:00Z",
                        event_definition=_current_event_definition(),
                    )
                with self.assertRaisesRegex(ValueError, "suppressed complement"):
                    build_v1_payload(
                        applications,
                        going_accepted=going_accepted,
                        on_site_builders=going_accepted,
                        submitted_application_ids=set(),
                        generated_at="2026-07-13T12:00:00Z",
                        event_definition=_current_event_definition(),
                    )

        with self.assertRaisesRegex(ValueError, "suppressed complement"):
            build_v3_payload(
                applied=20,
                going_accepted=10,
                on_site_builders=5,
                track_project_counts={"boski": 5},
                submitted_people=5,
                github_supplied=5,
                team_applicants=2,
                solo_applicants=18,
                repository_projects=5,
                demo_projects=5,
                generated_at="2026-07-13T12:00:00Z",
                event_definition=_current_event_definition(),
            )

    def test_rule_classification_preserves_unknowns_and_evidence(self) -> None:
        from community_os.real_report import classify_application

        unknown = classify_application({"external_id": "a", "occupation": "", "experience": ""})
        self.assertEqual(unknown["seniority"], {"unknown"})
        self.assertEqual(unknown["functional_role"], {"unknown"})
        self.assertEqual(unknown["evidence_refs"], {"application:a"})

        classified = classify_application({
            "external_id": "b",
            "occupation": "Senior ML Engineer and co-founder",
            "experience": "Built and deployed an AI product used by customers",
            "github": "builder",
        })
        self.assertIn("founder_cofounder", classified["professional_identity"])
        self.assertIn("founder", classified["seniority"])
        self.assertIn("data_ai", classified["functional_role"])
        self.assertIn("shipped_product", classified["builder_evidence"])
        self.assertIn("github_supplied", classified["builder_evidence"])

        senior = classify_application({
            "external_id": "c",
            "occupation": "Senior Data Scientist",
            "experience": "Built analytics pipelines",
        })
        self.assertEqual(senior["seniority"], {"senior"})
        self.assertNotIn("researcher_academic", senior["professional_identity"])

        student = classify_application({
            "external_id": "d",
            "occupation": "Computer science student",
            "organization": "Warsaw University",
            "experience": "Course projects",
        })
        self.assertEqual(student["seniority"], {"student"})
        self.assertNotIn("researcher_academic", student["professional_identity"])
        self.assertEqual(student["employer_pedigree"], {"student_no_employer"})

    def test_unified_report_lenses_do_not_change_contract_counts(self) -> None:
        from community_os.real_report import render_unified_report

        html = render_unified_report(
            {
                "metadata": {"title": "Real report", "generated_at": "2026-07-13T12:00:00Z"},
                "headline": {"applied": 286, "going_accepted": 82, "on_site": 78, "submitted_people": 76},
                "sections": [{"key": "seniority", "title": "Seniority", "counts": {"unknown": 100}}],
                "methodology": {"minimum_count": 5, "limitations": ["Two on-site builders lack submitted-team linkage"]},
            }
        )
        for lens in ("Overview", "Invest", "Hire", "Portfolio talent"):
            self.assertIn(lens, html)
        self.assertEqual(html.count('data-evidence-count="286"'), 1)
        self.assertIn("Evidence trace", html)
        self.assertIn("No JavaScript is required", html)
        self.assertIn('rel="icon" href="data:image/svg+xml', html)
        self.assertIn("footer{display:none}", html)
        self.assertIn('data-section-key="seniority"', html)
        self.assertNotIn("<script", html.casefold())
        self.assertNotIn("javascript:", html.casefold())
        self.assertNotIn("<button", html.casefold())

    def test_release_output_root_rejects_symlinks_and_non_regular_targets_before_mutation(self) -> None:
        from community_os.real_report import _validate_release_output_root

        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            outside = parent / "outside"
            outside.mkdir()
            symlink = parent / "release-link"
            symlink.symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(PermissionError, "symlink"):
                _validate_release_output_root(symlink, export_pdf=True)
            self.assertEqual(tuple(outside.iterdir()), ())

            root = parent / "release"
            root.mkdir()
            unsafe_target = root / "talent-brief.real.html"
            unsafe_target.mkdir()
            with self.assertRaisesRegex(PermissionError, "regular file"):
                _validate_release_output_root(root, export_pdf=False)
            self.assertTrue(unsafe_target.is_dir())

    def test_candidate_pdf_lifecycle_is_atomic_zero_javascript_and_six_page_landscape(self) -> None:
        from community_os.__main__ import _install_candidate_report
        from community_os.controlled_release import (
            _public_funnel_claims,
            _public_semantic_claims,
            _semantic_release_artifact_checks,
        )
        from community_os.partner_semantic_projection import (
            build_protected_partner_semantic_candidate_summary,
        )
        from tests.test_partner_semantic_projection import population_aggregate

        with tempfile.TemporaryDirectory() as directory:
            protected = Path(directory) / "protected"
            release = protected / "release"
            release.mkdir(parents=True)
            html = release / "report.html"
            pdf = release / "report.pdf"
            v1 = release / "v1.json"
            v3 = release / "v3.json"
            aggregate = population_aggregate()
            aggregate["minimum_group_size"] = 7
            (protected / "rich-semantic-internal.aggregate.json").write_text(
                json.dumps(aggregate), encoding="utf-8",
            )
            summary = build_protected_partner_semantic_candidate_summary(aggregate)
            headline_counts = {
                "applied": 286,
                "going_accepted": 82,
                "on_site": 78,
            }
            required_claims = (
                _public_funnel_claims(headline_counts)
                + _public_semantic_claims(summary)
            )
            claim_text = " ".join(
                f"{label} {display}" for label, display in required_claims
            )
            rendered = (
                "<!doctype html><h1>Current report</h1>" + claim_text
                + "".join(
                    f'<section data-pdf-page="{number}">'
                    f'<h2>Decision page {number}</h2></section>'
                    for number in range(1, 7)
                )
            )

            def fake_export(_html, destination, **_kwargs):
                Path(destination).write_bytes(b"%PDF-1.4\nfixture\n%%EOF")
                return Path(destination)

            with patch("community_os.pdf_export.export_pdf", side_effect=fake_export):
                installed = _install_candidate_report(
                    rendered, html_path=html, pdf_path=pdf,
                    stable_timestamp="2026-07-13T12:00:00Z",
                )
            self.assertEqual(installed, pdf)
            self.assertNotIn("<script", html.read_text(encoding="utf-8").casefold())
            privacy = {
                "minimum_count": 7, "mode": "aggregate_only",
                "pii_included": False, "state": "withheld_cells",
            }
            v1.write_text(json.dumps({
                "privacy": privacy,
                "cohort": {"stages": [
                    {"key": "valid_applicants", "count": {"value": 286}},
                    {"key": "going_accepted", "count": {"value": 82}},
                    {"key": "on_site", "count": {"value": 78}},
                ]},
            }), encoding="utf-8")
            v3.write_text(json.dumps({
                "privacy": privacy,
                "attendance_funnel": {"stages": [
                    {"key": "applied", "count": {"value": 286}},
                    {"key": "going_accepted", "count": {"value": 82}},
                    {"key": "on_site", "count": {"value": 78}},
                ]},
            }), encoding="utf-8")
            pdfinfo = SimpleNamespace(
                returncode=0,
                stdout="Pages:          6\nPage size:      841.89 x 595.28 pts\n",
            )
            with (
                patch(
                    "community_os.publication._pdf_text",
                    return_value=(
                        "Current report " + claim_text + " "
                        + " ".join(
                            f"Decision page {number}" for number in range(1, 7)
                        )
                    ),
                ),
                patch(
                    "community_os.controlled_release.subprocess.run",
                    return_value=pdfinfo,
                ),
            ):
                receipt = _semantic_release_artifact_checks(
                    html_path=html, pdf_path=pdf,
                    aggregate_paths=(v1, v3), minimum_group_size=7,
                )
            self.assertEqual(receipt["pdf_layout"], {
                "passed": True, "evidence_count": 5, "expected_count": 5,
            })

    def test_row_audit_only_marks_resolved_submission_members_as_affected(self) -> None:
        from community_os.real_report import audit_row

        state = {
            "sources": {
                "application": {
                    "app-1": {"email": "one@example.org", "team": "A"},
                    "app-2": {"email": "two@example.org", "team": "B"},
                },
                "preference": {},
                "devpost": {},
            },
            "person_links": {},
            "quarantined_refs": [],
            "submitted_application_ids": ["app-1"],
            "classifications": {"app-1": {"seniority": ["senior"]}, "app-2": {"seniority": ["unknown"]}},
            "enrichment_coverage": {"github": 2},
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            path.write_text(json.dumps(state), encoding="utf-8")
            submitted = audit_row(path, source="application", row_id="app-1")
            not_submitted = audit_row(path, source="application", row_id="app-2")
        self.assertTrue(submitted["submission_linkage"])
        self.assertEqual(submitted["aggregate_cells_affected"], ["submitted_team_people"])
        self.assertFalse(not_submitted["submission_linkage"])
        self.assertEqual(not_submitted["aggregate_cells_affected"], [])
        self.assertEqual(
            submitted["enrichment"],
            {"coresignal": "off", "github_live": "observed_only"},
        )

    def test_structural_provider_coverage_stays_private_until_semantic_review(self) -> None:
        from community_os.real_report import audit_row, build_v1_payload

        applications = [
            {
                "external_id": f"app-{index}",
                "github": "builder" if index < 8 else "",
            }
            for index in range(20)
        ]
        payload = build_v1_payload(
            applications,
            going_accepted=10,
            on_site_builders=8,
            submitted_application_ids=frozenset(),
            generated_at="2026-07-13T12:00:00Z",
            enrichment_coverage={"github": 8, "coresignal": 6},
            event_definition=_current_event_definition(),
        )

        self.assertEqual(
            {item["source"] for item in payload["evidence_coverage"]},
            {"application"},
        )
        self.assertNotIn("github_supplied", json.dumps(payload))
        semantic_readiness = next(
            item for item in payload["readiness"]
            if item["component"] == "semantic_enrichment"
        )
        self.assertEqual(semantic_readiness["state"], "pending")
        reviewed_payload = build_v1_payload(
            applications,
            going_accepted=10,
            on_site_builders=8,
            submitted_application_ids=frozenset(),
            generated_at="2026-07-13T12:00:00Z",
            enrichment_coverage={"github": 8, "coresignal": 6},
            rich_semantic_reviewed=True,
            event_definition=_current_event_definition(),
        )
        reviewed_semantic_readiness = next(
            item for item in reviewed_payload["readiness"]
            if item["component"] == "semantic_enrichment"
        )
        self.assertEqual(reviewed_semantic_readiness["state"], "ready")
        self.assertEqual(
            {item["source"] for item in reviewed_payload["evidence_coverage"]},
            {"application"},
        )

        state = {
            "sources": {
                "application": {"app-1": {"email": "one@example.org"}},
                "preference": {},
                "devpost": {},
            },
            "person_links": {},
            "quarantined_refs": [],
            "submitted_application_ids": [],
            "classifications": {"app-1": {"seniority": ["unknown"]}},
            "enrichment_coverage": {"github": 8},
            "semantic_enrichment_reviewed": True,
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            path.write_text(json.dumps(state), encoding="utf-8")
            audited = audit_row(path, source="application", row_id="app-1")
        self.assertEqual(audited["enrichment"]["github_live"], "observed_only")

    def test_v1_projection_loads_strict_contract_and_keeps_unknowns(self) -> None:
        from community_os.real_report import build_v1_payload, classification_confidence_summary
        from community_os.talent_intelligence_contract import load_talent_intelligence_contract

        applications = []
        for index in range(20):
            applications.append({
                "external_id": f"app-{index}",
                "email": f"person-{index}@example.org",
                "occupation": "Senior ML Engineer" if index < 6 else "",
                "experience": "Built and deployed an AI product" if index < 8 else "",
                "github": "builder" if index < 5 else "",
                "organization": "",
                "impressive_thing": "",
            })
        payload = build_v1_payload(
            applications,
            going_accepted=10,
            on_site_builders=8,
            submitted_application_ids={f"app-{index}" for index in range(5)},
            generated_at="2026-07-13T12:00:00Z",
            event_definition=_current_event_definition(),
        )
        self.assertEqual(
            [stage["key"] for stage in payload["cohort"]["stages"]],
            ["valid_applicants", "going_accepted", "on_site"],
        )
        self.assertIsNone(payload["cohort"]["stages"][2]["count"]["value"])
        self.assertNotIn(
            "submission", {item["source"] for item in payload["evidence_coverage"]},
        )
        self.assertEqual(payload["metadata"]["publication_state"], "review_ready")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "v1.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            report = load_talent_intelligence_contract(path)
        seniority = next(item for item in report.dimensions if item.key == "seniority")
        self.assertIn("unknown", {item.key for item in seniority.items})
        self.assertEqual(report.cohort.denominator.value, 20)
        confidence = classification_confidence_summary(payload)
        self.assertEqual(confidence["seniority"]["explicit_rule_match"] + confidence["seniority"]["unknown"], 20)
        self.assertEqual(confidence["employer_pedigree"]["explicit_rule_match"] + confidence["employer_pedigree"]["unknown"], 20)

    def test_v1_projection_consumes_reviewed_classification_projection_instead_of_reclassifying(self) -> None:
        from community_os.real_report import build_v1_payload, classify_application

        applications = [{"external_id": f"app-{index}"} for index in range(10)]
        projection = {
            item["external_id"]: {
                key: set(value) for key, value in classify_application(item).items()
                if key != "evidence_refs"
            }
            for item in applications
        }
        for index in range(5):
            projection[f"app-{index}"]["professional_identity"] = {"founder_cofounder"}
            projection[f"app-{index}"]["seniority"] = {"founder"}
            projection[f"app-{index}"]["employer_pedigree"] = {"self_employed_founder"}
            projection[f"app-{index}"]["builder_evidence"] = {
                "active_github", "founded_company",
            }

        payload = build_v1_payload(
            applications, going_accepted=5, on_site_builders=5,
            submitted_application_ids=set(), generated_at="2026-07-13T12:00:00Z",
            classification_projection=projection,
            event_definition=_current_event_definition(),
        )

        professional = next(
            item for item in payload["dimensions"] if item["key"] == "professional_identity"
        )
        founder = next(item for item in professional["items"] if item["key"] == "founder_cofounder")
        self.assertEqual(founder["count"]["value"], 5)
        self.assertNotIn("active_github", json.dumps(payload))

    def test_v1_projection_builds_reusable_cross_dimension_intersections_from_reviewed_application_facts(self) -> None:
        from community_os.real_report import build_v1_payload

        patterns = tuple(
            pattern
            for pattern in (
                ("founder", True, True),
                ("founder", True, False),
                ("founder", False, True),
                ("founder", False, False),
                ("student", True, True),
                ("student", True, False),
                ("student", False, True),
                ("student", False, False),
            )
            for _index in range(6)
        )
        applications = [
            {"external_id": f"app-{index}"}
            for index in range(len(patterns))
        ]
        projection = {}
        for application, (stage, technical, shipped) in zip(
            applications, patterns, strict=True,
        ):
            founder = stage == "founder"
            projection[application["external_id"]] = {
                "professional_identity": {
                    "founder_cofounder" if founder else "insufficient_evidence"
                },
                "seniority": {stage},
                "functional_role": {"engineering" if technical else "unknown"},
                "employer_pedigree": {
                    "self_employed_founder" if founder else "student_no_employer"
                },
                "builder_evidence": (
                    ({"founded_company"} if founder else set())
                    | ({"shipped_product"} if shipped else set())
                    or {"insufficient_evidence"}
                ),
                "capabilities": {"backend" if technical else "unknown"},
                "domains": {"unknown"},
            }

        payload = build_v1_payload(
            applications,
            going_accepted=24,
            on_site_builders=18,
            submitted_application_ids=set(),
            generated_at="2026-07-13T12:00:00Z",
            classification_projection=projection,
            event_definition=_current_event_definition(),
        )

        signals = next(
            dimension for dimension in payload["dimensions"]
            if dimension["key"] == "cross_dimension_signals"
        )
        self.assertEqual(signals["mode"], "overlapping")
        self.assertEqual(
            {
                item["key"]: item["count"]["value"]
                for item in signals["items"]
                if not item["key"].endswith("_not_recorded")
            },
            {
                "founder_evidence": 24,
                "student_stage": 24,
                "technical_function": 24,
                "shipped_product_evidence": 24,
            },
        )
        self.assertEqual(
            {
                item["key"]: item["count"]["value"]
                for item in payload["intersections"]
            },
            {
                "founder_only_exact": 6,
                "founder_shipped_product_exact": 6,
                "founder_technical_exact": 6,
                "founder_technical_shipped_product_exact": 6,
                "neither_recorded_exact": 6,
                "shipped_product_only_exact": 6,
                "student_shipped_product": 12,
                "technical_only_exact": 6,
                "technical_shipped_product_exact": 6,
            },
        )
        self.assertTrue(all(
            item["evidence_sources"] == ["application"]
            for item in payload["intersections"]
        ))
        serialized = json.dumps(payload)
        self.assertNotIn("founders_with_submission_evidence", serialized)
        self.assertNotIn("hackathon_submission", serialized)

    def test_cross_dimension_intersections_withhold_small_or_unsafe_components(self) -> None:
        from community_os.real_report import build_v1_payload, classify_application

        applications = [{"external_id": f"app-{index}"} for index in range(10)]
        projection = {
            item["external_id"]: {
                key: set(value) for key, value in classify_application(item).items()
                if key != "evidence_refs"
            }
            for item in applications
        }
        for index in range(10):
            projection[f"app-{index}"].update({
                "seniority": {"student"},
                "employer_pedigree": {"student_no_employer"},
            })
        for index in range(6):
            projection[f"app-{index}"].update({
                "functional_role": {"engineering"},
                "capabilities": {"backend"},
            })
        for index in range(4):
            projection[f"app-{index}"].update({
                "professional_identity": {"founder_cofounder"},
                "builder_evidence": {"founded_company", "shipped_product"},
            })

        payload = build_v1_payload(
            applications,
            going_accepted=5,
            on_site_builders=5,
            submitted_application_ids=set(),
            generated_at="2026-07-13T12:00:00Z",
            classification_projection=projection,
            event_definition=_current_event_definition(),
        )

        signals = next(
            dimension for dimension in payload["dimensions"]
            if dimension["key"] == "cross_dimension_signals"
        )
        founder = next(
            item for item in signals["items"]
            if item["key"] == "founder_evidence"
        )
        partition = tuple(
            item for item in payload["intersections"]
            if item["key"].endswith("_exact")
        )
        student_shipped = next(
            item for item in payload["intersections"]
            if item["key"] == "student_shipped_product"
        )
        self.assertEqual(founder["count"]["privacy"], "withheld")
        self.assertIsNone(founder["count"]["value"])
        self.assertTrue(
            all(item["count"]["privacy"] == "withheld" for item in partition),
            "a partition with any small nonzero cell must fail closed as a whole",
        )
        self.assertTrue(all(
            item["count"]["value"] in (None, 0)
            or item["count"]["value"] >= 5
            for item in partition
        ))
        self.assertEqual(student_shipped["count"]["privacy"], "withheld")
        self.assertIsNone(student_shipped["count"]["value"])

    def test_existing_aggregate_can_be_refreshed_from_retained_reviewed_classifications(self) -> None:
        import community_os.real_report as real_report

        self.assertTrue(
            hasattr(real_report, "refresh_cross_dimension_evidence"),
            "current protected aggregates need a reusable no-provider refresh path",
        )
        applications = [{"external_id": f"app-{index}"} for index in range(16)]
        projection = {
            item["external_id"]: {
                key: set(value)
                for key, value in real_report.classify_application(item).items()
                if key != "evidence_refs"
            }
            for item in applications
        }
        for index in range(8):
            projection[f"app-{index}"].update({
                "professional_identity": {"founder_cofounder"},
                "seniority": {"founder"},
                "functional_role": {"engineering"},
                "employer_pedigree": {"self_employed_founder"},
                "builder_evidence": {"founded_company", "shipped_product"},
                "capabilities": {"backend"},
            })
        payload = real_report.build_v1_payload(
            applications,
            going_accepted=8,
            on_site_builders=8,
            submitted_application_ids=set(),
            generated_at="2026-07-13T12:00:00Z",
            classification_projection=projection,
            event_definition=_current_event_definition(),
        )
        legacy = deepcopy(payload)
        legacy["dimensions"] = [
            dimension for dimension in legacy["dimensions"]
            if dimension["key"] != "cross_dimension_signals"
        ]
        legacy["intersections"] = [{
            "key": "legacy_operational_overlap",
            "label": "Legacy operational overlap",
            "count": {"value": 8, "privacy": "published", "reason": None},
            "component_keys": [
                "professional_identity.founder_cofounder",
                "builder_evidence.shipped_product",
            ],
            "evidence_sources": ["application"],
        }]
        refreshed = real_report.refresh_cross_dimension_evidence(
            legacy,
            classification_projection=projection,
        )

        self.assertEqual(
            sum(
                dimension["key"] == "cross_dimension_signals"
                for dimension in refreshed["dimensions"]
            ),
            1,
        )
        self.assertNotIn("legacy_operational_overlap", json.dumps(refreshed))
        self.assertNotIn("app-0", json.dumps(refreshed))
        self.assertEqual(legacy["intersections"][0]["key"], "legacy_operational_overlap")

    def test_cli_exposes_one_command_release_and_row_audit(self) -> None:
        from community_os.__main__ import build_parser

        parser = build_parser()
        release = parser.parse_args([
            "real-release",
            "--event-config", "event.json", "--event-approval", "private/event-approval.json",
            "--applications", "applications.csv",
            "--attendance", "attendance.csv",
            "--preferences", "preferences.xlsx",
            "--submissions", "submissions.xlsx",
            "--override", "private/override.json",
            "--output", "output/real",
        ])
        self.assertEqual(release.command, "real-release")
        self.assertFalse(hasattr(release, "posthog_key"))
        self.assertIsNone(release.semantic_aggregate)
        self.assertFalse(hasattr(release, "posthog_token_env"))
        self.assertFalse(hasattr(release, "posthog_host"))
        enriched = parser.parse_args([
            "real-release",
            "--event-config", "event.json", "--event-approval", "private/event-approval.json",
            "--applications", "applications.csv",
            "--attendance", "attendance.csv",
            "--preferences", "preferences.xlsx",
            "--submissions", "submissions.xlsx",
            "--override", "private/override.json",
            "--output", "output/real",
            "--semantic-aggregate", "private/rich-semantic.json",
        ])
        self.assertEqual(enriched.semantic_aggregate, "private/rich-semantic.json")
        with self.assertRaises(SystemExit):
            parser.parse_args([
                "real-release", "--event-config", "event.json",
                "--event-approval", "private/event-approval.json",
                "--applications", "a.csv", "--attendance", "b.csv",
                "--preferences", "c.xlsx", "--submissions", "d.xlsx",
                "--override", "o.json", "--output", "out",
                "--posthog-token-env", "POSTHOG_PROJECT_TOKEN",
            ])
        audit = parser.parse_args([
            "real-audit", "--state", "private/state.json", "--source", "application", "--row-id", "app-1",
        ])
        self.assertEqual(audit.command, "real-audit")


if __name__ == "__main__":
    unittest.main()
