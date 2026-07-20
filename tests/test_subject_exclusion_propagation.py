from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


def _subject(seed: str) -> str:
    return "pid:v1:" + hashlib.sha256(seed.encode("utf-8")).hexdigest()


class SubjectExclusionPlanAcceptanceTests(unittest.TestCase):
    def test_plan_filters_known_subject_and_emits_identifier_free_deterministic_audit(self) -> None:
        try:
            from community_os.privacy_operations import build_subject_exclusion_plan
        except ImportError:
            self.fail(
                "privacy operations must expose build_subject_exclusion_plan for enforced propagation"
            )

        included = _subject("included")
        excluded = _subject("excluded")
        plan = build_subject_exclusion_plan(
            excluded_subject_refs=(excluded,),
            known_subject_refs=(included, excluded),
        )

        self.assertEqual(plan.allowed_subject_refs, frozenset({included}))
        self.assertEqual(plan.excluded_count, 1)
        self.assertRegex(plan.exclusion_set_sha256, r"^[0-9a-f]{64}$")
        self.assertEqual(
            plan.audit_record,
            {
                "action": "subject_exclusions_propagated",
                "excluded_count": 1,
                "exclusion_set_sha256": plan.exclusion_set_sha256,
                "reason_code": "rights_request",
            },
        )
        self.assertNotIn(excluded, json.dumps(plan.audit_record, sort_keys=True))
        repeated = build_subject_exclusion_plan(
            excluded_subject_refs=(excluded,),
            known_subject_refs=(excluded, included),
        )
        self.assertEqual(repeated, plan)

    def test_plan_fails_closed_on_malformed_duplicate_or_unknown_subject_refs(self) -> None:
        try:
            from community_os.privacy_operations import build_subject_exclusion_plan
        except ImportError:
            self.fail(
                "privacy operations must expose build_subject_exclusion_plan for enforced propagation"
            )

        known = _subject("known")
        cases = (
            (("",), "malformed"),
            ((known, known), "duplicated"),
            ((_subject("unknown"),), "unknown"),
        )
        for excluded, message in cases:
            with self.subTest(excluded=excluded):
                with self.assertRaisesRegex(ValueError, message):
                    build_subject_exclusion_plan(
                        excluded_subject_refs=excluded,
                        known_subject_refs=(known,),
                    )

    def test_controlled_privacy_record_accepts_well_formed_nonempty_exclusion_set(self) -> None:
        from community_os.controlled_release import _validate_privacy_operations
        from tests.test_controlled_release import _event_definition, _privacy_operations

        privacy = _privacy_operations()
        privacy["excluded_subject_refs"] = [_subject("excluded")]

        try:
            _validate_privacy_operations(privacy, definition=_event_definition())
        except PermissionError as error:
            self.fail(f"valid subject exclusions must be propagated, not blanket-blocked: {error}")


class AggregateExclusionAcceptanceTests(unittest.TestCase):
    def test_excluded_membership_rows_cannot_leave_team_or_project_aggregate_evidence(self) -> None:
        try:
            from community_os.real_report import _filter_final_sources
        except ImportError:
            self.fail("real report must filter team and project maps before aggregate counting")

        preference_records = (
            SimpleNamespace(external_id="pref-excluded", email="one@example.org", team_name="Excluded Team", track="alpha"),
            SimpleNamespace(external_id="pref-included", email="two@example.org", team_name="Included Team", track="alpha"),
        )
        submission_records = (
            SimpleNamespace(external_id="sub-excluded", email="one@example.org", team_name="Excluded Team", track="alpha", repository_present=True, demo_present=True),
            SimpleNamespace(external_id="sub-included", email="two@example.org", team_name="Included Team", track="alpha", repository_present=False, demo_present=True),
        )

        filtered = _filter_final_sources(
            preference_records, submission_records,
            excluded_source_refs={"pref-excluded", "sub-excluded"},
        )

        self.assertEqual(
            tuple(record.external_id for record in filtered[0]), ("pref-included",),
        )
        self.assertEqual(
            tuple(record.external_id for record in filtered[1]), ("sub-included",),
        )
        self.assertEqual(tuple(filtered[2]), ("Included Team",))
        self.assertEqual(tuple(filtered[3]), ("Included Team",))
        self.assertFalse(filtered[3]["Included Team"]["repository_present"])

    def test_ambiguous_attendance_linkage_blocks_exclusion_instead_of_leaking_counts(self) -> None:
        try:
            from community_os.real_report import _excluded_attendance_records
        except ImportError:
            self.fail("real report must fail closed when attendance exclusion linkage is ambiguous")

        records = (SimpleNamespace(email="different@example.org"),)
        with self.assertRaisesRegex(ValueError, "reviewed attendance linkage"):
            _excluded_attendance_records(
                records, excluded_emails={"excluded@example.org"},
            )
        matched = SimpleNamespace(email="excluded@example.org")
        self.assertEqual(
            _excluded_attendance_records(
                (*records, matched), excluded_emails={"excluded@example.org"},
            ),
            (matched,),
        )

    def test_aggregate_builder_removes_excluded_applicant_from_denominator_and_dimensions(self) -> None:
        from community_os.real_report import build_v1_payload

        applications = [
            {
                "external_id": f"app-{index}",
                "occupation": "Engineer",
                "experience": "Built and shipped a product",
                "github": "builder" if index == 0 else "",
            }
            for index in range(12)
        ]
        try:
            from community_os.event_definition import load_event_definition

            payload = build_v1_payload(
                applications,
                going_accepted=5,
                on_site_builders=0,
                submitted_application_ids=set(),
                generated_at="2026-07-13T12:00:00Z",
                excluded_application_ids={"app-0"},
                event_definition=load_event_definition(
                    Path(__file__).resolve().parents[1]
                    / "config/events/openai-hackathon-2026.json"
                ),
            )
        except TypeError as error:
            self.fail(
                "aggregate builder must accept reviewed excluded_application_ids after source hash validation: "
                + str(error)
            )

        self.assertEqual(payload["cohort"]["denominator"]["value"], 11)
        builder_evidence = next(
            dimension for dimension in payload["dimensions"]
            if dimension["key"] == "builder_evidence"
        )
        self.assertNotIn(
            "github_supplied",
            {item["key"] for item in builder_evidence["items"]},
        )
        self.assertNotIn("github_supplied", json.dumps(payload))


class ControlledReleaseExclusionAcceptanceTests(unittest.TestCase):
    def test_excluded_subject_is_removed_from_every_applicant_bound_service(self) -> None:
        from community_os.controlled_release import (
            ControlledReleaseRuntime, build_controlled_release_factory,
        )
        from community_os.enrichment.state import pseudonymous_id
        from tests.test_controlled_release import (
            NOW, _bundle, _event_definition, ControlledReleaseTests,
        )

        secret = b"fixture-pseudonym-secret"
        applications = (
            {"external_id": "app-1", "email": "one@example.org"},
            {"external_id": "app-2", "email": "two@example.org"},
        )
        excluded = pseudonymous_id("app-1", secret=secret, key_version="v1")
        captured_loaders = []
        captured_reconciliation_loaders = []

        def adapter_service(*args, **kwargs):
            captured_loaders.append(kwargs["application_loader"])
            return lambda: []

        def reconcile_service(*args, **kwargs):
            captured_reconciliation_loaders.append(kwargs["source_loader"])
            return lambda: []

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = ControlledReleaseTests._state_with_sources(root)
            state.record_reviewed_value(
                "going_accepted",
                source_value=0,
                reviewed_value=0,
                reason_code="fixture_reviewed",
            )
            state.record_reviewed_value(
                "on_site_builders",
                source_value=0,
                reviewed_value=0,
                reason_code="fixture_reviewed",
            )
            bundle = _bundle()
            bundle["privacy_operations"]["excluded_subject_refs"] = [excluded]
            bundle["event_approval"]["excluded_subject_refs"] = [excluded]
            bundle_path = root / "approval.json"
            bundle_path.write_text(json.dumps(bundle), encoding="utf-8")
            stale_stage = state.root / "protected" / "stages" / "github.json"
            stale_stage.parent.mkdir(parents=True)
            stale_stage.write_text("stale person-level result", encoding="utf-8")
            stale_public = state.root / "public-staging" / "talent-brief.real.html"
            stale_public.parent.mkdir(parents=True)
            stale_public.write_text("stale public report", encoding="utf-8")
            with (
                patch("community_os.release_operations._load_applications", return_value=applications),
                patch("community_os.controlled_release.build_adapter_service", side_effect=adapter_service),
                patch("community_os.controlled_release.build_reconcile_service", side_effect=reconcile_service),
            ):
                operations = build_controlled_release_factory(ControlledReleaseRuntime(
                    approval_bundle=bundle_path, pseudonym_secret=secret,
                    event_definition=_event_definition(),
                    clock=lambda: NOW,
                ))(state)
                loaded_ids = [
                    [item["external_id"] for item in loader(state)]
                    for loader in captured_loaders
                ]

            from community_os.release_operations import ReconciliationInputs
            included_preference = SimpleNamespace(
                email="two@example.org", team_name="Included Team", track="alpha",
                external_id="pref-2",
            )
            excluded_preference = SimpleNamespace(
                email="one@example.org", team_name="Excluded Team", track="alpha",
                external_id="pref-1",
            )
            included_submission = SimpleNamespace(
                email="two@example.org", team_name="Included Team", track="alpha",
                external_id="sub-2", repository_present=True, demo_present=True,
            )
            excluded_submission = SimpleNamespace(
                email="one@example.org", team_name="Excluded Team", track="alpha",
                external_id="sub-1", repository_present=True, demo_present=True,
            )
            reconciliation_inputs = ReconciliationInputs(
                applications=applications,
                preference_records=(excluded_preference, included_preference),
                submission_records=(excluded_submission, included_submission),
                preferences={
                    "Excluded Team": {"track": "alpha"},
                    "Included Team": {"track": "alpha"},
                },
                projects={
                    "Excluded Team": {"track": "alpha"},
                    "Included Team": {"track": "alpha"},
                },
            )
            with patch(
                "community_os.release_operations._load_reconciliation_inputs",
                return_value=reconciliation_inputs,
            ):
                filtered_inputs = captured_reconciliation_loaders[0](state)

            manifest = root / "manifest.json"
            manifest.write_text("{}", encoding="utf-8")
            with (
                patch(
                    "community_os.release_operations._load_applications",
                    return_value=applications,
                ),
                patch(
                    "community_os.controlled_release.persist_internal_rich_semantic_aggregate",
                    return_value=None,
                ),
                patch(
                    "community_os.controlled_release.build_reviewed_override",
                    return_value={"override_version": "fixture"},
                ),
                patch(
                    "community_os.controlled_release.load_reviewed_classification_projection",
                    return_value={},
                ),
                patch(
                    "community_os.controlled_release.finalize_reviewed_evidence",
                    return_value={
                        "projection_sha256": "a" * 64,
                        "raw_evidence_deleted": 0,
                        "transient_cache_deleted": 0,
                    },
                ),
                patch(
                    "community_os.real_report.build_real_release",
                    return_value={"manifest": manifest},
                ) as real_release,
                patch(
                    "community_os.controlled_release._scan_local_partner_share",
                    return_value={},
                ),
                patch(
                    "community_os.release_operations.derive_semantic_application_cohort_membership",
                    return_value={
                        "app-2": {
                            "applied": True,
                            "accepted": False,
                            "present": False,
                        },
                    },
                ),
            ):
                operations["aggregate"]()

            self.assertEqual(len(captured_loaders), 3)
            self.assertEqual(loaded_ids, [["app-2"], ["app-2"], ["app-2"]])
            self.assertEqual(tuple(filtered_inputs.preferences), ("Included Team",))
            self.assertEqual(tuple(filtered_inputs.projects), ("Included Team",))
            self.assertFalse(stale_stage.exists())
            self.assertFalse(stale_public.exists())
            evidence = json.loads(
                (state.root / "protected" / "subject-exclusions.json").read_text(
                    encoding="utf-8",
                )
            )
            self.assertEqual(evidence["excluded_count"], 1)
            self.assertNotIn(excluded, json.dumps(evidence, sort_keys=True))
            self.assertEqual(state.snapshot()["privacy_exclusions"], {
                "excluded_count": 1,
                "exclusion_set_sha256": evidence["exclusion_set_sha256"],
                "state": "registered",
            })
            self.assertEqual(
                real_release.call_args.kwargs["pseudonym_secret"], secret,
            )


if __name__ == "__main__":
    unittest.main()
