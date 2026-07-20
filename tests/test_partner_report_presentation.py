from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
import tempfile
import unittest


class PartnerReportPresentationTests(unittest.TestCase):
    def setUp(self) -> None:
        from community_os.partner_semantic_projection import (
            build_protected_partner_semantic_candidate_summary,
        )
        from tests.test_partner_semantic_projection import semantic_aggregate

        self.summary = build_protected_partner_semantic_candidate_summary(
            semantic_aggregate(),
        )

    def test_default_presentation_is_bound_to_the_exact_aggregate(self) -> None:
        from community_os.partner_report_presentation import (
            build_default_partner_report_presentation,
            validate_partner_report_presentation,
        )

        presentation = build_default_partner_report_presentation(self.summary)
        validated = validate_partner_report_presentation(
            presentation, semantic_summary=self.summary,
        )

        self.assertIs(validated, presentation)
        self.assertEqual(
            presentation.version, "partner-report-presentation-v1",
        )
        self.assertEqual(
            presentation.aggregate_sha256, self.summary.aggregate_sha256,
        )
        self.assertEqual(
            presentation.event_definition_sha256,
            self.summary.event_definition_sha256,
        )
        self.assertEqual(
            tuple(question.key for question in presentation.questions),
            ("overview", "invest", "hire", "portfolio"),
        )
        self.assertEqual(
            presentation.interaction_profile, "interactive-evidence-v1",
        )
        self.assertEqual(
            presentation.cover_title,
            "Builders who ship, shown through the work.",
        )
        self.assertIn("evidence", presentation.cover_dek.casefold())

    def test_dashboard_state_recomposes_unified_evidence_for_every_cohort(self) -> None:
        from community_os.partner_report_presentation import (
            build_default_partner_report_presentation,
            build_partner_dashboard_state,
        )
        from community_os.partner_semantic_projection import (
            build_protected_partner_semantic_cohort_candidate_bundle,
        )
        from tests.test_partner_semantic_projection import NOW
        from tests.test_rich_semantic_review import (
            RichSemanticReviewTests,
            population_context,
            proposal,
        )

        with tempfile.TemporaryDirectory() as directory:
            store, _repository = RichSemanticReviewTests().create_store(directory)
            expected = []
            for ordinal in range(1, 16):
                candidate = proposal(ordinal)
                expected.append(str(candidate["subject_ref"]))
                case = store.submit(candidate)
                store.decide(
                    case.case_code,
                    action="approved",
                    actor_code="release_owner",
                    decided_at=NOW,
                )
            membership = {
                subject: {
                    "applied": "member",
                    "accepted": "member" if ordinal <= 10 else "not_member",
                    "present": "member" if ordinal <= 5 else "not_member",
                }
                for ordinal, subject in enumerate(expected, start=1)
            }
            protected = store.build_population_aggregate(
                expected_subject_refs=expected,
                binding_context=population_context(),
                generated_at=NOW,
                minimum_group_size=5,
                membership_by_subject=membership,
                reviewed_cohort_totals={
                    "all": 15,
                    "accepted": 11,
                    "attended": 6,
                },
            )
        cohorts = build_protected_partner_semantic_cohort_candidate_bundle(
            protected,
        )
        presentation = build_default_partner_report_presentation(
            cohorts.cohorts[0].summary,
        )

        state = build_partner_dashboard_state(
            cohorts,
            presentation=presentation,
        )

        self.assertEqual(state["version"], "partner-dashboard-v2")
        self.assertEqual(
            [(cohort["key"], cohort["denominator"]) for cohort in state["cohorts"]],
            [("all", 15), ("accepted", 11), ("attended", 6)],
        )
        self.assertEqual(
            [
                cohort["metrics"][0]["denominator"]
                for cohort in state["cohorts"]
            ],
            [15, 11, 6],
        )
        self.assertEqual(
            [
                (group["key"], tuple(group["metric_keys"]))
                for group in state["metric_groups"]
            ],
            [
                (
                    "project_evidence",
                    (
                        "prototype_or_beyond",
                        "substantive_technical_evidence",
                        "differentiated_problem",
                        "advanced_technical_evidence",
                    ),
                ),
                (
                    "demonstrated_capabilities",
                    (
                        "capability_product_engineering",
                        "capability_data_ai_engineering",
                        "capability_backend_engineering",
                    ),
                ),
                (
                    "career_delivery",
                    (
                        "career_delivery_shipped_products",
                        "career_delivery_founded_venture",
                        "career_delivery_customer_delivery",
                    ),
                ),
            ],
        )
        accepted_definition = state["cohorts"][1]["definition"].casefold()
        self.assertIn("organizer-selected", accepted_definition)
        self.assertIn("manual application review", accepted_definition)
        self.assertIn("not a quality score", accepted_definition)
        event_submission = next(
            item for item in state["cohorts"][0]["source_coverage"]
            if item["key"] == "event_submission"
        )
        self.assertIn("not attendance", event_submission["definition"].casefold())
        self.assertIn("not a quality judgment", next(
            item for item in state["cohorts"][0]["source_coverage"]
            if item["key"] == "public_projects"
        )["definition"].casefold())
        expected_order = tuple(
            metric_key
            for group in state["metric_groups"]
            for metric_key in group["metric_keys"]
        )
        for cohort in state["cohorts"]:
            self.assertNotIn("lenses", cohort)
            self.assertEqual(
                tuple(metric["key"] for metric in cohort["metrics"]),
                expected_order,
            )
            self.assertEqual(
                {metric["denominator"] for metric in cohort["metrics"]},
                {cohort["denominator"]},
            )
            for metric in cohort["metrics"]:
                self.assertIn("definition", metric)
                self.assertIn("evidence_standard", metric)
                self.assertIn("unknown_state", metric)
                self.assertIn("count_text", metric["unknown_state"])
                self.assertNotIn("count protected", metric["unknown_state"]["count_text"].casefold())

        all_metrics = {
            metric["key"]: metric for metric in state["cohorts"][0]["metrics"]
        }
        self.assertEqual(
            [
                all_metrics[key]["label"]
                for key in state["metric_groups"][1]["metric_keys"]
            ],
            ["Product engineering", "Data and AI engineering", "Backend engineering"],
        )
        self.assertEqual(
            [
                all_metrics[key]["label"]
                for key in state["metric_groups"][2]["metric_keys"]
            ],
            ["Shipped products", "Founded a venture", "Customer delivery"],
        )

        encoded = json.dumps(state, sort_keys=True)
        self.assertIn("remain in the denominator and unknown", encoded)
        self.assertIn("not every reviewed source can support every metric", encoded.casefold())
        self.assertNotIn("outside positive claims", encoded)
        self.assertNotIn("exact person-level linkage", encoded)
        self.assertNotIn("contributes only to the unknown state", encoded)
        for forbidden in (
            "subject_ref", "case:v1:", "@example.org", "github.com/",
            "linkedin.com/", "coresignal", "accepted participants are stronger",
            "accepted cohort is stronger", "accepted participants outperform",
        ):
            self.assertNotIn(forbidden, encoded.casefold())

    def test_operator_copy_options_are_distinct(self) -> None:
        from community_os.partner_report_presentation import (
            partner_report_presentation_copy_options,
        )

        for field, options in partner_report_presentation_copy_options().items():
            with self.subTest(field=field):
                self.assertEqual(len(options), len(set(options)))

    def test_presentation_rejects_stale_or_unbound_evidence(self) -> None:
        from community_os.partner_report_presentation import (
            PartnerQuestion,
            build_default_partner_report_presentation,
            validate_partner_report_presentation,
        )

        presentation = build_default_partner_report_presentation(self.summary)
        cases = (
            replace(presentation, aggregate_sha256="f" * 64),
            replace(
                presentation,
                questions=(
                    PartnerQuestion(
                        key="overview",
                        label="Overview",
                        answer="Evidence summary.",
                        evidence_refs=("metric:not_registered",),
                        target_sections=("journey",),
                    ),
                    *presentation.questions[1:],
                ),
            ),
        )
        for candidate in cases:
            with self.subTest(candidate=candidate):
                with self.assertRaises((PermissionError, ValueError)):
                    validate_partner_report_presentation(
                        candidate, semantic_summary=self.summary,
                    )

    def test_presentation_copy_is_bounded_and_cannot_carry_authored_claims_or_pii(self) -> None:
        from community_os.partner_report_presentation import (
            build_default_partner_report_presentation,
            validate_partner_report_presentation,
        )

        presentation = build_default_partner_report_presentation(self.summary)
        unsafe_answers = (
            "Contact person@example.org for details.",
            "See https://example.org/evidence.",
            "<strong>Untrusted HTML</strong>",
            "Exactly 48 applicants qualify.",
            "x" * 401,
        )
        for answer in unsafe_answers:
            candidate = replace(
                presentation,
                questions=(
                    replace(presentation.questions[0], answer=answer),
                    *presentation.questions[1:],
                ),
            )
            with self.subTest(answer=answer):
                with self.assertRaises((PermissionError, ValueError)):
                    validate_partner_report_presentation(
                        candidate, semantic_summary=self.summary,
                    )

    def test_presentation_copy_cannot_invent_universal_causal_or_comparative_claims(self) -> None:
        from community_os.partner_report_presentation import (
            build_default_partner_report_presentation,
            validate_partner_report_presentation,
        )

        presentation = build_default_partner_report_presentation(self.summary)
        unsupported_answers = (
            "Every applicant has strong external validation.",
            "Project evidence proves the community will outperform other cohorts.",
            "GitHub activity caused stronger event participation.",
            "This is the most technically advanced community in Europe.",
        )
        for answer in unsupported_answers:
            candidate = replace(
                presentation,
                questions=(
                    replace(presentation.questions[0], answer=answer),
                    *presentation.questions[1:],
                ),
            )
            with self.subTest(answer=answer):
                with self.assertRaises(PermissionError):
                    validate_partner_report_presentation(
                        candidate, semantic_summary=self.summary,
                    )

    def test_stale_aggregate_copy_resets_to_current_server_owned_defaults(self) -> None:
        from community_os.partner_report_presentation import (
            build_default_partner_report_presentation,
            load_or_create_partner_report_presentation,
            load_partner_report_presentation,
            write_partner_report_presentation,
        )
        from community_os.partner_semantic_projection import (
            build_protected_partner_semantic_candidate_summary,
        )
        from tests.test_partner_semantic_projection import semantic_aggregate

        stale = build_default_partner_report_presentation(self.summary)
        changed_aggregate = semantic_aggregate()
        changed_aggregate["metrics"]["standout_builder"] = 6
        current_summary = build_protected_partner_semantic_candidate_summary(
            changed_aggregate,
        )
        self.assertNotEqual(
            self.summary.aggregate_sha256, current_summary.aggregate_sha256,
        )

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "partner-report-presentation.json"
            write_partner_report_presentation(
                path, stale, semantic_summary=self.summary,
            )

            current = load_or_create_partner_report_presentation(
                path, semantic_summary=current_summary,
            )

            self.assertEqual(current.aggregate_sha256, current_summary.aggregate_sha256)
            self.assertEqual(
                current,
                load_partner_report_presentation(
                    path, semantic_summary=current_summary,
                ),
            )

    def test_stale_aggregate_copy_with_tampered_claim_fails_closed(self) -> None:
        from community_os.partner_report_presentation import (
            build_default_partner_report_presentation,
            load_or_create_partner_report_presentation,
            partner_report_presentation_payload,
        )
        from community_os.partner_semantic_projection import (
            build_protected_partner_semantic_candidate_summary,
        )
        from tests.test_partner_semantic_projection import semantic_aggregate

        changed_aggregate = semantic_aggregate()
        changed_aggregate["metrics"]["standout_builder"] = 6
        stale_summary = build_protected_partner_semantic_candidate_summary(
            changed_aggregate,
        )
        payload = partner_report_presentation_payload(
            build_default_partner_report_presentation(stale_summary),
        )
        payload["cover_title"] = "Every applicant has strong external validation."

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "partner-report-presentation.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            path.chmod(0o600)

            with self.assertRaisesRegex(PermissionError, "approved evidence-bound"):
                load_or_create_partner_report_presentation(
                    path, semantic_summary=self.summary,
                )

            self.assertEqual(
                json.loads(path.read_text(encoding="utf-8"))["cover_title"],
                "Every applicant has strong external validation.",
            )

    def test_retired_server_owned_portfolio_copy_migrates_to_current_default(self) -> None:
        from community_os.partner_report_presentation import (
            build_default_partner_report_presentation,
            load_or_create_partner_report_presentation,
            load_partner_report_presentation,
            partner_report_presentation_payload,
        )

        current = build_default_partner_report_presentation(self.summary)
        retired_answer = (
            "Execution, leadership, and delivery evidence identify where people may "
            "complement ambitious product teams."
        )
        retired = replace(
            current,
            questions=tuple(
                replace(question, answer=retired_answer)
                if question.key == "portfolio" else question
                for question in current.questions
            ),
        )

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "partner-report-presentation.json"
            path.write_text(
                json.dumps(partner_report_presentation_payload(retired)),
                encoding="utf-8",
            )
            path.chmod(0o600)

            migrated = load_or_create_partner_report_presentation(
                path, semantic_summary=self.summary,
            )

            portfolio = next(
                question for question in migrated.questions
                if question.key == "portfolio"
            )
            self.assertIn("overlapping evidence", portfolio.answer)
            self.assertIn("not a team score", portfolio.answer)
            self.assertEqual(
                migrated,
                load_partner_report_presentation(
                    path, semantic_summary=self.summary,
                ),
            )

    def test_presentation_round_trips_through_protected_atomic_storage(self) -> None:
        from community_os.partner_report_presentation import (
            build_default_partner_report_presentation,
            load_partner_report_presentation,
            partner_report_presentation_sha256,
            write_partner_report_presentation,
        )

        presentation = build_default_partner_report_presentation(self.summary)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "partner-report-presentation.json"
            written = write_partner_report_presentation(
                path, presentation, semantic_summary=self.summary,
            )
            loaded = load_partner_report_presentation(
                path, semantic_summary=self.summary,
            )

            self.assertEqual(loaded, presentation)
            self.assertEqual(written, presentation)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(
                partner_report_presentation_sha256(loaded),
                partner_report_presentation_sha256(presentation),
            )
            self.assertEqual(
                set(json.loads(path.read_text(encoding="utf-8"))),
                {
                    "aggregate_sha256", "cover_dek", "cover_title",
                    "event_definition_sha256", "interaction_profile",
                    "questions", "version",
                },
            )

    def test_presentation_storage_rejects_unknown_keys_and_stale_bindings(self) -> None:
        from community_os.partner_report_presentation import (
            build_default_partner_report_presentation,
            load_partner_report_presentation,
            partner_report_presentation_payload,
        )

        presentation = build_default_partner_report_presentation(self.summary)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "partner-report-presentation.json"
            payload = partner_report_presentation_payload(presentation)
            payload["unexpected"] = "ignored only by unsafe loaders"
            path.write_text(json.dumps(payload), encoding="utf-8")
            path.chmod(0o600)
            with self.assertRaises(PermissionError):
                load_partner_report_presentation(
                    path, semantic_summary=self.summary,
                )

            payload.pop("unexpected")
            payload["aggregate_sha256"] = "f" * 64
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaises(PermissionError):
                load_partner_report_presentation(
                    path, semantic_summary=self.summary,
                )


if __name__ == "__main__":
    unittest.main()
