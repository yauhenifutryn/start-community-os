from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
import re
import tempfile
import unittest


def _semantic_context(summary):
    return {
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


def _semantic_cohort_bundle_fixture(*, with_all_only_signal: bool = False):
    from community_os.partner_semantic_projection import (
        build_protected_partner_semantic_cohort_candidate_bundle,
    )
    from tests.test_partner_semantic_projection import NOW
    from tests.test_rich_semantic_review import (
        RichSemanticReviewTests,
        assessment,
        population_context,
        proposal,
    )

    with tempfile.TemporaryDirectory() as directory:
        store, _repository = RichSemanticReviewTests().create_store(directory)
        expected = []
        total = 20 if with_all_only_signal else 15
        execution_scope_by_ordinal = {
            1: "primary_builder", 2: "primary_builder", 3: "primary_builder",
            4: "substantial_contributor", 5: "substantial_contributor",
            6: "substantial_contributor", 7: "substantial_contributor",
            8: "contributor", 9: "contributor", 10: "contributor",
            11: "primary_builder", 12: "primary_builder",
            13: "primary_builder", 14: "primary_builder",
            15: "primary_builder", 16: "primary_builder",
            17: "primary_builder", 18: "substantial_contributor",
            19: "contributor", 20: "contributor",
        }
        for ordinal in range(1, total + 1):
            candidate = (
                proposal(
                    ordinal,
                    assessment=assessment(
                        builder_level=(
                            "exploratory"
                            if execution_scope_by_ordinal[ordinal] == "contributor"
                            else "substantial"
                        ),
                        execution_scope=execution_scope_by_ordinal[ordinal],
                        originality="differentiated",
                        reason_codes=[
                            "differentiated_problem",
                            "shipped_working_product",
                            "technically_substantial",
                        ],
                    ),
                )
                if with_all_only_signal
                else proposal(ordinal)
            )
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
        )
    return build_protected_partner_semantic_cohort_candidate_bundle(protected)


def _cross_dimension_report_fixture(report):
    from community_os.talent_intelligence_contract import (
        CountValue, Dimension, DimensionItem, Intersection,
    )

    signal_counts = {
        "founder_evidence": 53,
        "student_stage": 40,
        "technical_function": 213,
        "shipped_product_evidence": 84,
    }
    signal_labels = {
        "founder_evidence": "Founder / co-founder evidence",
        "student_stage": "Student stage",
        "technical_function": "Technical function",
        "shipped_product_evidence": "Shipped-product evidence",
    }
    complements = {
        "founder_evidence_not_recorded": 233,
        "technical_function_not_recorded": 73,
        "shipped_product_evidence_not_recorded": 202,
    }
    signal_dimension = Dimension(
        key="cross_dimension_signals",
        label="Cross-dimensional evidence signals",
        mode="overlapping",
        denominator_key="valid_applicants",
        known_count=CountValue(286, "published", None),
        items=tuple(
            DimensionItem(
                key=key,
                label=label,
                count=CountValue(signal_counts[key], "published", None),
                definition=f"Reviewed application evidence for {label.casefold()}.",
                evidence_sources=("application",),
            )
            for key, label in signal_labels.items()
        ) + tuple(
            DimensionItem(
                key=key,
                label=key.replace("_", " ").title(),
                count=CountValue(count, "published", None),
                definition=(
                    "The positive application signal was not recorded; "
                    "this is not a negative assessment."
                ),
                evidence_sources=("application",),
            )
            for key, count in complements.items()
        ),
    )
    rows = (
        ("technical_only_exact", 125, ("founder_evidence_not_recorded", "technical_function", "shipped_product_evidence_not_recorded")),
        ("technical_shipped_product_exact", 53, ("founder_evidence_not_recorded", "technical_function", "shipped_product_evidence")),
        ("neither_recorded_exact", 48, ("founder_evidence_not_recorded", "technical_function_not_recorded", "shipped_product_evidence_not_recorded")),
        ("founder_technical_shipped_product_exact", 18, ("founder_evidence", "technical_function", "shipped_product_evidence")),
        ("founder_technical_exact", 17, ("founder_evidence", "technical_function", "shipped_product_evidence_not_recorded")),
        ("founder_only_exact", 12, ("founder_evidence", "technical_function_not_recorded", "shipped_product_evidence_not_recorded")),
        ("shipped_product_only_exact", 7, ("founder_evidence_not_recorded", "technical_function_not_recorded", "shipped_product_evidence")),
        ("founder_shipped_product_exact", 6, ("founder_evidence", "technical_function_not_recorded", "shipped_product_evidence")),
    )
    intersections = tuple(
        Intersection(
            key=key,
            label=key.replace("_", " ").title(),
            count=CountValue(count, "published", None),
            component_keys=tuple(
                f"cross_dimension_signals.{signal}" for signal in signals
            ),
            evidence_sources=("application",),
        )
        for key, count, signals in rows
    ) + (
        Intersection(
            key="student_shipped_product",
            label="Student stage + shipped-product evidence",
            count=CountValue(12, "published", None),
            component_keys=(
                "cross_dimension_signals.student_stage",
                "cross_dimension_signals.shipped_product_evidence",
            ),
            evidence_sources=("application",),
        ),
    )
    return replace(
        report,
        dimensions=(
            *(
                dimension for dimension in report.dimensions
                if dimension.key != "cross_dimension_signals"
            ),
            signal_dimension,
        ),
        intersections=intersections,
    )


class PartnerReportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from community_os.report_contract import load_report_contract
        from community_os.talent_intelligence_contract import load_talent_intelligence_contract
        repo = Path(__file__).resolve().parents[1]
        cls.report = load_talent_intelligence_contract(
            repo / "config/contracts/talent-intelligence-v1.synthetic.json"
        )
        v3 = load_report_contract(repo / "config/contracts/talent-report-v3.synthetic.json")
        shared = {
            "approved": next(stage.count for stage in cls.report.cohort.stages if stage.key == "accepted"),
            "checked_in": next(stage.count for stage in cls.report.cohort.stages if stage.key == "checked_in"),
            "submitted": next(stage.count for stage in cls.report.cohort.stages if stage.key == "submitted"),
        }
        stages = tuple(
            replace(
                stage,
                count=replace(
                    stage.count,
                    value=shared[stage.key].value,
                    privacy=shared[stage.key].privacy,
                    reason=shared[stage.key].reason,
                ),
            )
            for stage in v3.attendance_funnel.stages
        )
        cls.v3_report = replace(
            v3,
            metadata=replace(
                v3.metadata,
                generated_at=cls.report.metadata.generated_at,
            ),
            attendance_funnel=replace(v3.attendance_funnel, stages=stages),
        )

    def test_partner_report_is_zero_javascript_with_five_composed_pages(self):
        from community_os.partner_report import render_partner_talent_report

        html = render_partner_talent_report(self.report, self.v3_report)

        core_sections = (
            "journey", "talent", "career-background", "builder-evidence", "domains",
        )
        for section in core_sections:
            self.assertEqual(html.count(f'id="{section}"'), 1)
            self.assertIn(f'data-section-key="{section}"', html)
        self.assertIn('id="methodology"', html)
        self.assertIn('href="#methodology"', html)
        self.assertEqual(html.count('class="exhibit"'), 6)
        self.assertEqual(html.count("data-pdf-page="), 5)
        self.assertEqual(html.count('class="cover-finding"'), 4)
        self.assertNotIn("<script", html.casefold())
        self.assertNotIn("javascript:", html.casefold())
        self.assertNotIn("data-lens", html)
        self.assertNotIn("Partner report controls", html)
        self.assertNotIn("Print report", html)
        self.assertNotIn("window.", html)
        self.assertNotRegex(html, r'(?:src|href)="https?://')
        self.assertIn('<link rel="icon" href="data:,">', html)
        self.assertIn('<a href="#journey">Demand and participation</a>', html)
        self.assertIn("@media print", html)
        self.assertIn("@media (max-width:640px)", html)
        self.assertIn("@media (prefers-reduced-motion:reduce)", html)
        self.assertIn('<a class="skip" href="#report">Skip to report</a>', html)
        self.assertIn("a:focus-visible", html)
        self.assertIn("AvenirLTNextPro", html)
        self.assertNotIn("linkedin.com/in/", html)
        self.assertNotIn("github.com/", html)
        self.assertNotIn("Open evidence table", html)
        self.assertNotIn("lollipop", html.casefold())
        self.assertNotIn("heatmap", html.casefold())
        self.assertNotIn("interesting evidence", html.casefold())
        self.assertNotIn("artifact completeness", html.casefold())
        self.assertNotIn("builder signal intersections", html.casefold())

    def test_partner_report_uses_plain_selection_and_privacy_language(self):
        from community_os.partner_report import render_partner_talent_report

        html = render_partner_talent_report(self.report, self.v3_report)

        self.assertIn("Applied", html)
        self.assertIn("Accepted by organizers", html)
        self.assertNotIn("Demand exceeded event capacity", html)
        self.assertNotIn("applicants were not in the accepted group", html)
        self.assertNotIn("Individual non-selection reasons were not recorded", html)
        self.assertIn("Small group hidden", html)
        self.assertIn("A hidden value is not zero", html)
        for jargon in (
            "Starting cohort", "Accepted or confirmed", "Further progression",
            "Explicit unknown evidence", "Withheld Cells", "On site",
        ):
            self.assertNotIn(jargon, html)
        self.assertNotIn("less talented", html.casefold())
        self.assertNotIn("rejected", html.casefold())

    def test_chart_forms_match_the_question_and_unknown_is_coverage_not_a_rank(self):
        from community_os.partner_report import render_partner_talent_report

        html = render_partner_talent_report(self.report, self.v3_report)

        self.assertEqual(html.count('class="volume-funnel"'), 1)
        self.assertEqual(html.count('class="composition-chart"'), 1)
        self.assertEqual(html.count('class="ranked-signal-grid"'), 1)
        self.assertEqual(html.count('class="dot-plot"'), 1)
        self.assertIn("Unclassified coverage", html)
        self.assertRegex(html, r"\d+ of 286 \(\d+%\) unclassified")
        self.assertNotRegex(html, r'<li class="ranked-signal"[^>]*>\s*<[^>]+>Unknown')
        self.assertEqual(html.count(">Design</strong>"), 1)
        self.assertNotIn('title="Unknown:', html)
        composition_sizes = tuple(
            float(value) for value in re.findall(r'style="--size:([0-9.]+)%"', html)
        )
        self.assertTrue(composition_sizes)
        self.assertAlmostEqual(sum(composition_sizes), 100.0, places=3)

    def test_cover_findings_are_not_repeated_in_exhibits(self):
        from community_os.partner_report import render_partner_talent_report

        html = render_partner_talent_report(self.report, self.v3_report)

        for evidence in ("112 of 286", "84 of 286"):
            self.assertEqual(html.count(evidence), 1, evidence)
        self.assertEqual(html.count("Evidence pending"), 1)
        self.assertEqual(html.count("final teams submitted a project"), 1)
        self.assertEqual(html.count("mention data or AI in their submitted evidence"), 1)
        self.assertEqual(html.count("were accepted by organizers"), 1)
        self.assertNotIn("GitHub", html)
        self.assertNotIn("repository activity", html)
        self.assertNotIn("data or AI role evidence", html)
        self.assertNotIn("public GitHub handle", html)
        self.assertNotIn(">Data and AI</strong>", html)

    def test_partner_report_never_publishes_enrichment_source_completeness(self):
        from community_os.partner_report import render_partner_talent_report

        html = render_partner_talent_report(self.report, self.v3_report)

        for source_completeness_claim in (
            "GitHub coverage",
            "profiles enriched",
            "profiles observed",
            "README packets",
            "repository activity",
            "Coresignal coverage",
        ):
            self.assertNotIn(source_completeness_claim.casefold(), html.casefold())

    def test_published_attendance_states_the_reviewed_counts_and_gap(self):
        from community_os.partner_report import render_partner_talent_report

        intelligence_stages = tuple(
            replace(
                stage,
                count=replace(stage.count, value=83, privacy="published", reason=None),
            ) if stage.key == "accepted" else replace(
                stage,
                count=replace(stage.count, value=78, privacy="published", reason=None),
            ) if stage.key == "checked_in" else stage
            for stage in self.report.cohort.stages
        )
        event_stages = tuple(
            replace(
                stage,
                count=replace(stage.count, value=83, privacy="published", reason=None),
            ) if stage.key == "approved" else replace(
                stage,
                count=replace(stage.count, value=78, privacy="published", reason=None),
            ) if stage.key == "checked_in" else stage
            for stage in self.v3_report.attendance_funnel.stages
        )
        report = replace(
            self.report,
            cohort=replace(self.report.cohort, stages=intelligence_stages),
        )
        event_report = replace(
            self.v3_report,
            attendance_funnel=replace(self.v3_report.attendance_funnel, stages=event_stages),
        )

        html = render_partner_talent_report(report, event_report)

        self.assertIn("83 people", html)
        self.assertIn("78 people", html)
        self.assertIn("Confirmed present at the event", html)
        self.assertIn("78 of 83 accepted participants were confirmed present", html)
        self.assertIn("5 were not in the reviewed attendance count", html)
        self.assertNotIn("accepted participants checked in", html)
        self.assertNotIn("reviewed check-in", html)
        self.assertNotIn("hidden attendance row", html)
        self.assertNotIn('data-value-state="hidden"', html)

    def test_founder_counts_are_labeled_as_evidence_not_verified_identity(self):
        from community_os.partner_report import render_partner_talent_report

        dimensions = tuple(
            replace(
                dimension,
                items=(
                    replace(dimension.items[0], key="founder", label="Founder"),
                    *dimension.items[1:],
                ),
            ) if dimension.key == "seniority" else dimension
            for dimension in self.report.dimensions
        )
        report = replace(
            self.report,
            dimensions=dimensions,
        )

        html = render_partner_talent_report(report, self.v3_report)

        self.assertEqual(html.count("Founder evidence"), 1)
        self.assertIn("<span>Founder evidence</span>", html)
        self.assertNotIn("<h3>Founder evidence</h3>", html)
        self.assertNotIn("founder evidence linked to submitted teams", html.casefold())
        self.assertNotIn("founders represented by submitted teams", html.casefold())

    def test_partner_report_has_no_analytics_injection_path(self):
        import inspect

        from community_os.partner_report import render_partner_talent_report

        html = render_partner_talent_report(self.report, self.v3_report)
        parameters = inspect.signature(render_partner_talent_report).parameters

        self.assertNotIn("posthog_key", parameters)
        self.assertNotIn("posthog_host", parameters)
        self.assertNotIn("posthog", html.casefold())
        self.assertNotIn("<script", html.casefold())

    def test_public_report_has_no_ornamental_controls_or_inspectors(self):
        from community_os.partner_report import render_partner_talent_report

        html = render_partner_talent_report(self.report, self.v3_report)

        self.assertIn('<html lang="en">', html)
        self.assertNotIn("data-inspect=", html)
        self.assertNotIn("data-inspector=", html)
        self.assertNotIn("datum_inspected", html)
        self.assertNotIn("<button", html.casefold())

    def test_missing_enrichment_does_not_add_a_partner_facing_coverage_appendix(self):
        from community_os.partner_report import render_partner_talent_report
        from community_os.talent_intelligence_contract import load_talent_intelligence_contract
        source = Path(__file__).resolve().parents[1] / "config/contracts/talent-intelligence-v1.synthetic.json"
        payload = json.loads(source.read_text(encoding="utf-8"))
        payload["metadata"]["synthetic"] = False
        payload["intersections"] = [
            item for item in payload["intersections"]
            if item["key"] != "senior_technical_builders"
        ]
        professional = next(
            item for item in payload["dimensions"]
            if item["key"] == "professional_identity"
        )
        professional["items"] = [
            item for item in professional["items"]
            if item["key"] != "venture_backed_startup"
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "real-shaped.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            report = load_talent_intelligence_contract(path)
        v3_report = replace(
            self.v3_report,
            metadata=replace(self.v3_report.metadata, synthetic=False),
        )
        html = render_partner_talent_report(report, v3_report)

        self.assertNotIn("Professional-profile enrichment", html)
        self.assertNotIn("Evidence coverage", html)
        self.assertIn("Counts below five are not shown", html)
        self.assertNotIn("Venture backed startup", html)
        self.assertNotIn("This fixture is synthetic", html)
        self.assertNotIn("Synthetic statements", html)
        self.assertNotIn("Do not distribute as observed event evidence", html)

    def test_compact_report_note_replaces_the_methodology_appendix(self):
        from community_os.partner_report import render_partner_talent_report

        html = render_partner_talent_report(self.report, self.v3_report)

        self.assertNotIn("Methodology, coverage, and privacy", html)
        self.assertNotIn("Evidence coverage", html)
        self.assertIn("Counts below five are not shown", html)
        self.assertIn("No names, contact details, or profile links are included", html)

    def test_semantic_summary_is_rendered_as_fixed_aggregate_evidence(self):
        from community_os.partner_report import render_partner_talent_report
        from community_os.partner_semantic_projection import (
            build_protected_partner_semantic_candidate_summary,
        )
        from tests.test_partner_semantic_projection import semantic_aggregate

        summary = build_protected_partner_semantic_candidate_summary(
            semantic_aggregate(),
        )
        published_matrix = tuple(
            replace(
                cell,
                count=replace(
                    cell.count, value=0, privacy="published", reason=None,
                ),
            ) if cell.count.value is None else cell
            for cell in self.v3_report.team_submission_matrix.cells
        )
        event_report = replace(
            self.v3_report,
            team_submission_matrix=replace(
                self.v3_report.team_submission_matrix,
                cells=published_matrix,
            ),
        )
        html = render_partner_talent_report(
            self.report, event_report, semantic_summary=summary,
            semantic_context=_semantic_context(summary),
        )

        self.assertEqual(html.count('id="semantic-evidence"'), 1)
        self.assertIn("What people have actually built", html)
        for finding in (
            "69 of 286", "19 of 286", "62 of 286", "22 of 286", "6 of 286",
            "133 of 286",
        ):
            self.assertIn(finding, html)
        self.assertNotIn("169 public project profiles", html)
        self.assertNotIn("12 optional professional-profile context records", html)
        self.assertIn("Evidence coverage", html)
        self.assertIn("12 of 286", html)
        self.assertIn(
            "Dedicated career-provider evidence cited in reviewed facts",
            html,
        )
        for private_qa_term in (
            "source_coverage", "public_projects", "career_context",
            "GitHub coverage", "GitHub available", "profiles observed",
            "subject_ref",
        ):
            self.assertNotIn(private_qa_term, html)
        self.assertNotRegex(html, r">\s*1 of 286\s*<")
        self.assertIn(
            "Project and application evidence support the findings; source-use coverage is reported separately and is not a quality score",
            html,
        )
        self.assertIn(
            "AI-assisted evidence assessment; reviewed against fixed evidence definitions",
            html,
        )
        self.assertNotIn("195 of 286 eligible profiles", html)
        self.assertIn("full eligible population", html)
        for internal_release_term in (
            "private QA", "agent-reviewed", "hash-bound human release approval",
            "Publication is controlled", "Contracts talent-intelligence",
        ):
            self.assertNotIn(internal_release_term, html)
        self.assertIn('id="project-landscape"', html)
        self.assertIn('id="career-context"', html)
        self.assertIn("Technical depth", html)
        self.assertIn("133 of 286", html)
        self.assertIn("Application-reported primary role or stage", html)
        self.assertIn("Independent overlays", html)
        self.assertNotIn(
            "Dedicated career-provider evidence was not used in this release",
            html,
        )
        self.assertNotIn("not_impressive", html)
        self.assertNotIn("not impressive", html.casefold())
        self.assertNotIn("supported by reviewed", html.casefold())
        self.assertNotIn("had reviewed semantic", html.casefold())
        self.assertNotIn('id="talent"', html)
        self.assertNotIn('id="builder-evidence"', html)
        self.assertNotIn('id="domains"', html)
        self.assertNotIn("github.com/", html)
        self.assertNotIn("linkedin.com/", html)
        self.assertIn("@page{size:A4 landscape", html)

    def test_hash_bound_semantic_approval_does_not_change_report_bytes(self):
        from community_os.partner_report import render_partner_talent_report
        from community_os.partner_semantic_projection import (
            _seal_summary,
            build_protected_partner_semantic_candidate_summary,
        )
        from tests.test_partner_semantic_projection import semantic_aggregate

        candidate = build_protected_partner_semantic_candidate_summary(
            semantic_aggregate(),
        )
        approved = _seal_summary(replace(
            candidate,
            projection_version="partner-semantic-summary-v3",
            semantic_release_approval_sha256="a" * 64,
            release_artifact_hashes=tuple(
                (key, value * 64)
                for key, value in (
                    ("html_sha256", "1"),
                    ("pdf_sha256", "2"),
                    ("qa_sha256", "3"),
                    ("report_candidate_sha256", "4"),
                )
            ),
        ))

        candidate_html = render_partner_talent_report(
            self.report,
            self.v3_report,
            semantic_summary=candidate,
            semantic_context=_semantic_context(candidate),
        )
        approved_html = render_partner_talent_report(
            self.report,
            self.v3_report,
            semantic_summary=approved,
            semantic_context=_semantic_context(approved),
        )

        self.assertEqual(candidate_html, approved_html)
        self.assertNotIn("hash-bound human release approval", candidate_html)
        self.assertIn(
            "AI-assisted evidence assessment; reviewed against fixed evidence definitions",
            candidate_html,
        )

    def test_semantic_html_progressively_enhances_partner_questions_without_changing_evidence(self):
        from community_os.partner_report import render_partner_talent_report
        from community_os.partner_report_presentation import (
            build_default_partner_report_presentation,
        )
        from community_os.partner_semantic_projection import (
            build_protected_partner_semantic_candidate_summary,
        )
        from tests.test_partner_semantic_projection import semantic_aggregate

        summary = build_protected_partner_semantic_candidate_summary(
            semantic_aggregate(),
        )
        presentation = build_default_partner_report_presentation(summary)
        html = render_partner_talent_report(
            self.report, self.v3_report, semantic_summary=summary,
            semantic_context=_semantic_context(summary),
            presentation=presentation,
        )

        self.assertNotIn('<details class="methodology-details"', html)
        self.assertIn('class="method-summary"', html)
        self.assertIn('class="taxonomy-cell"', html)
        self.assertIn('class="partner-questions"', html)
        self.assertEqual(html.count('data-partner-question='), 4)
        for key in ("overview", "invest", "hire", "portfolio"):
            self.assertIn(f'data-partner-question="{key}"', html)
            self.assertIn(f'data-partner-answer="{key}"', html)
        self.assertIn('aria-live="polite"', html)
        self.assertIn('type="button"', html)
        self.assertIn('aria-pressed="true"', html)
        self.assertIn('class="report-reading-progress"', html)
        self.assertNotIn('class="screen-pdf-action"', html)
        self.assertEqual(html.count("Download PDF"), 1)
        self.assertNotIn("View PDF", html)
        self.assertIn('<script>', html)
        for forbidden in (
            "fetch(", "sendBeacon", "XMLHttpRequest", "WebSocket",
            "localStorage", "sessionStorage", "document.cookie", "posthog",
        ):
            self.assertNotIn(forbidden, html)
        self.assertIn('@media print{.partner-questions', html)
        self.assertIn('@media (prefers-reduced-motion:reduce)', html)

    def test_semantic_report_has_one_download_action_and_one_question_per_pdf_page(self):
        from community_os.partner_report import render_partner_talent_report
        from community_os.partner_report_presentation import (
            build_default_partner_report_presentation,
        )
        from community_os.partner_semantic_projection import (
            build_protected_partner_semantic_candidate_summary,
        )
        from tests.test_partner_semantic_projection import semantic_aggregate

        summary = build_protected_partner_semantic_candidate_summary(
            semantic_aggregate(),
        )
        presentation = build_default_partner_report_presentation(summary)
        html = render_partner_talent_report(
            self.report,
            self.v3_report,
            semantic_summary=summary,
            semantic_context=_semantic_context(summary),
            presentation=presentation,
        )

        self.assertIn('class="pdf-actions"', html)
        self.assertIn('href="talent-brief.real.pdf" download', html)
        self.assertNotIn('href="talent-brief.real.pdf" target="_blank"', html)
        self.assertNotIn("View PDF", html)
        self.assertIn("Download PDF", html)
        self.assertEqual(html.count('href="talent-brief.real.pdf" download'), 1)
        self.assertIn("Event date", html)
        self.assertNotIn("<span>Date <b>", html)
        self.assertEqual(html.count('data-decision-question="'), 7)
        self.assertEqual(html.count('class="decision-question"'), 7)
        for question in (
            "How much demand converted into participation?",
            "What have applicants actually built?",
            "Who is represented in the applicant community?",
            "Where do role, technical function, and shipped-product evidence intersect?",
            "Which capabilities and market contexts are represented?",
            "How should partners interpret the evidence?",
        ):
            self.assertEqual(html.count(question), 1)

    def test_semantic_dashboard_controls_recompose_aggregate_state_not_only_copy(self):
        from community_os.partner_report import render_partner_talent_report
        from community_os.partner_report_presentation import (
            build_default_partner_report_presentation,
        )

        cohorts = _semantic_cohort_bundle_fixture()
        summary = cohorts.cohorts[0].summary
        presentation = build_default_partner_report_presentation(summary)
        report_values = {
            "valid_applicants": 15, "accepted": 10, "checked_in": 5,
        }
        event_values = {"applied": 20, "approved": 10, "checked_in": 5}
        report = replace(
            self.report,
            metadata=replace(self.report.metadata, event_key=summary.event_key),
            cohort=replace(
                self.report.cohort,
                denominator=replace(self.report.cohort.denominator, value=15),
                stages=tuple(
                    replace(stage, count=replace(stage.count, value=report_values[stage.key]))
                    if stage.key in report_values else stage
                    for stage in self.report.cohort.stages
                ),
            ),
        )
        event_report = replace(
            self.v3_report,
            metadata=replace(self.v3_report.metadata, event_key=summary.event_key),
            attendance_funnel=replace(
                self.v3_report.attendance_funnel,
                stages=tuple(
                    replace(stage, count=replace(stage.count, value=event_values[stage.key]))
                    if stage.key in event_values else stage
                    for stage in self.v3_report.attendance_funnel.stages
                ),
            ),
        )
        html = render_partner_talent_report(
            report,
            event_report,
            semantic_summary=summary,
            semantic_cohorts=cohorts,
            semantic_context=_semantic_context(summary),
            presentation=presentation,
        )

        self.assertEqual(html.count("data-cohort-select="), 3)
        self.assertEqual(html.count("data-lens-select="), 0)
        self.assertIn('role="group" aria-label="Cohort"', html)
        self.assertNotIn('role="group" aria-label="Report lens"', html)
        self.assertIn('id="partner-dashboard-state" type="application/json"', html)
        self.assertIn('data-dashboard-denominator', html)
        self.assertIn('data-dashboard-chart', html)
        self.assertIn('data-dashboard-metric-group', html)
        self.assertIn('data-dashboard-metric-select', html)
        self.assertIn('data-dashboard-inspector', html)
        self.assertIn('data-dashboard-comparison', html)
        self.assertIn('aria-label="Explore aggregate evidence"', html)
        self.assertIn("addEventListener('focus'", html)
        self.assertIn("['ArrowLeft','ArrowRight']", html)
        self.assertIn("requestAnimationFrame", html)
        self.assertIn("cubic-bezier(.16,1,.3,1)", html)
        self.assertNotIn("transition:all", html)
        self.assertIn("renderDashboard", html)
        self.assertIn("replaceChildren", html)
        self.assertNotIn("selectedLens", html)
        self.assertNotIn("lensFor", html)
        self.assertNotIn("renderRoute", html)
        self.assertNotIn("data-partner-question", html)
        self.assertNotIn("selectQuestion", html)

        match = re.search(
            r'<script id="partner-dashboard-state" type="application/json">(.*?)</script>',
            html,
            re.DOTALL,
        )
        self.assertIsNotNone(match)
        state = json.loads(match.group(1))
        self.assertEqual(
            [(item["key"], item["denominator"]) for item in state["cohorts"]],
            [("all", 15), ("accepted", 10), ("attended", 5)],
        )
        self.assertEqual(
            state["version"],
            "partner-dashboard-v2",
        )
        self.assertEqual(len(state["metric_groups"]), 3)
        for cohort in state["cohorts"]:
            self.assertNotIn("lenses", cohort)
            self.assertEqual(len(cohort["metrics"]), 10)
        self.assertIn('class="cohort-evidence-matrix"', html)
        self.assertEqual(html.count('class="cohort-matrix-head"'), 3)
        for label, denominator in (
            ("All applicants", 15),
            ("Accepted participants", 10),
            ("Confirmed attendees", 5),
        ):
            self.assertIn(
                f"{label}</strong><small>Denominator {denominator}", html,
            )
        self.assertIn("Choose a cohort, then inspect the evidence", html)
        self.assertIn("The metric groups stay fixed", html)
        self.assertIn("No score or ranking is created", html)
        self.assertNotIn("Aggregate reviewed-fact source use", html)
        self.assertNotIn("Reviewed-fact evidence use:", html)
        self.assertIn("Evidence limits", html)
        self.assertEqual(html.count("dashboardText('span','',cohort.label)"), 1)
        self.assertNotIn("<dt>Unknown state</dt>", html)
        self.assertIn("Not every reviewed source can support every metric", html)
        self.assertIn("unknown, not a negative assessment", html)
        self.assertNotIn("may be omitted", html)
        self.assertNotIn("Submission operations", html)
        self.assertNotIn("Linkage reviewed", html)
        self.assertIn("Application-reported primary role or stage", html)
        self.assertIn("Primary role or stage", html)
        self.assertIn("Different standards; do not add these counts", html)
        self.assertIn(
            "Gender, age, nationality, location, and graduation year", html,
        )
        self.assertIn("were not inferred", html)
        self.assertIn(
            ".partner-dashboard>.pdf-actions{grid-column:1;justify-content:flex-start}",
            html,
        )
        self.assertIn(
            ".report-page[data-decision-question]>.decision-question{padding:",
            html,
        )
        self.assertIn(
            ".category-model-base{display:grid;grid-template-columns:54px minmax(0,1fr);gap:12px;align-items:center",
            html,
        )
        self.assertIn(
            ".category-model-base,.category-model-overlays{border-left:1px solid var(--navy)}",
            html,
        )
        self.assertIn(
            ".report-note{margin:0;padding:28px 0 0;color:var(--muted);background:transparent",
            html,
        )
        self.assertIn("--canvas:#fcfbf7;--evidence-surface:#fffefd", html)
        self.assertIn(
            ".partner-questions{display:grid;grid-template-columns:minmax(220px,.7fr) minmax(0,1.3fr);gap:28px;align-items:start;padding:34px clamp(28px,6vw,88px);border-bottom:1px solid var(--rule);background:var(--canvas)}",
            html,
        )
        self.assertIn(
            ".dashboard-cohort-summary{grid-column:1;align-self:start;padding:22px 0;background:transparent;border-top:2px solid var(--navy)",
            html,
        )
        self.assertIn(
            ".dashboard-metric{display:grid;grid-template-rows:1fr auto;gap:16px;min-height:132px;padding:18px;border:1px solid var(--rule);color:var(--ink);background:var(--evidence-surface)",
            html,
        )
        self.assertIn(
            ".partner-dashboard{grid-template-columns:minmax(230px,.5fr) minmax(0,1.5fr);gap:32px 48px;padding-top:52px;padding-bottom:52px;background:var(--canvas)}",
            html,
        )
        self.assertIn(
            "@media (max-width:640px){.upset-column-key,.upset-overlap button{grid-template-columns:132px minmax(0,1fr) 28px}",
            html,
        )
        self.assertIn(
            ".upset-set-key span{color:var(--burgundy);font-size:.64rem;font-weight:850;line-height:1.12;text-align:center}.upset-set-key{column-gap:6px}",
            html,
        )
        self.assertIn(
            "@media (max-width:640px){.upset-column-key,.upset-overlap button{grid-template-columns:132px minmax(0,1fr) 28px}.upset-set-key span{font-size:.62rem}}",
            html,
        )
        self.assertIn(
            ".report-page-cross-dimension .upset-set-key span{font-size:8.5pt}",
            html,
        )
        self.assertIn(
            ".report-page-cross-dimension .upset-column-key{grid-template-columns:42mm minmax(0,1fr) 9mm 12mm",
            html,
        )
        for internal_release_term in (
            "private QA", "agent-reviewed", "hash-bound human release approval",
            "Publication is controlled", "talent-report-v3",
        ):
            self.assertNotIn(internal_release_term, html)
        page_three = re.search(
            r'data-pdf-page="3".*?</div>(?=<div class="report-page|</main>)',
            html,
            re.DOTALL,
        )
        self.assertIsNotNone(page_three)
        self.assertIn('class="cohort-evidence-matrix"', page_three.group(0))
        encoded = json.dumps(state, sort_keys=True).casefold()
        for forbidden in (
            "subject_ref", "case:v1:", "@example.org", "github.com/",
            "linkedin.com/", "coresignal", "accepted participants are stronger",
            "accepted cohort is stronger", "accepted participants outperform",
        ):
            self.assertNotIn(forbidden, encoded)

    def test_cohort_pdf_matrix_compares_only_publishable_rows_and_explains_omissions(self):
        from community_os.partner_report import _cohort_evidence_matrix

        fixture = _semantic_cohort_bundle_fixture()
        counts = {
            "all": {
                "serious_product_builder": None,
                "advanced_technical_evidence": 15,
                "differentiated_problem": 8,
                "primary_execution": 4,
                "meaningful_validation": 4,
                "substantive_technical_evidence": 12,
                "standout_builder": 0,
            },
            "accepted": {
                "serious_product_builder": None,
                "advanced_technical_evidence": 10,
                "differentiated_problem": 5,
                "primary_execution": None,
                "meaningful_validation": None,
                "substantive_technical_evidence": 8,
                "standout_builder": 0,
            },
            "attended": {
                "serious_product_builder": None,
                "advanced_technical_evidence": 5,
                "differentiated_problem": 5,
                "primary_execution": None,
                "meaningful_validation": None,
                "substantive_technical_evidence": 5,
                "standout_builder": 0,
            },
        }
        current_like = replace(
            fixture,
            cohorts=tuple(
                replace(
                    cohort,
                    summary=replace(
                        cohort.summary,
                        metrics=tuple(
                            replace(metric, count=counts[cohort.key][metric.key])
                            for metric in cohort.summary.metrics
                        ),
                    ),
                )
                for cohort in fixture.cohorts
            ),
        )

        html = _cohort_evidence_matrix(current_like)

        self.assertIn("Comparable cohort signals", html)
        self.assertIn("Prototype or beyond", html)
        self.assertIn("Positive evidence available for the full applicant pool", html)
        self.assertIn("Primary or end-to-end execution", html)
        self.assertIn("Explicit external validation observed", html)
        self.assertIn("Nested cohort counts are withheld by the privacy rule", html)
        self.assertNotIn("All applicants only", html)
        self.assertNotIn("Count withheld", html)
        self.assertNotIn("Standout builders", html)
        self.assertNotIn("Serious product builders", html)
        self.assertIn("Public-project evidence used", html)
        self.assertRegex(
            html,
            r"Public-project evidence used</strong> \d+/\d+ applicants",
        )
        self.assertNotIn("These counts show where project evidence supported", html)
        self.assertIn("not a selection score", html)
        self.assertIn('class="cohort-evidence-notes"', html)

    def test_cohort_evidence_labels_link_to_numbered_methodology_definitions(self):
        from community_os.partner_report import _cohort_evidence_matrix, _methodology

        fixture = _semantic_cohort_bundle_fixture(with_all_only_signal=True)
        cohorts = replace(
            fixture,
            cohorts=tuple(
                replace(
                    cohort,
                    summary=replace(
                        cohort.summary,
                        metrics=tuple(
                            replace(
                                metric,
                                count=(5 if cohort.key == "all" else None),
                            )
                            if metric.key == "meaningful_validation" else metric
                            for metric in cohort.summary.metrics
                        ),
                    ),
                )
                for cohort in fixture.cohorts
            ),
        )
        summary = cohorts.cohorts[0].summary

        matrix = _cohort_evidence_matrix(cohorts)
        methodology = _methodology(self.report, summary)

        expected_matrix_references = {
            "prototype_or_beyond": 1,
            "advanced_technical_evidence": 2,
            "differentiated_problem": 3,
            "primary_execution": 4,
            "meaningful_validation": 5,
            "substantive_technical_evidence": 6,
        }
        for key, number in expected_matrix_references.items():
            self.assertIn(
                f'href="#definition-{key}" aria-label="Definition {number}">{number}</a>',
                matrix,
            )
        external_definitions = (
            "prototype_or_beyond", "advanced_technical_evidence",
            "differentiated_problem", "primary_execution",
            "meaningful_validation", "substantive_technical_evidence",
        )
        for number, key in enumerate(external_definitions, start=1):
            self.assertIn(f'id="definition-{key}"', methodology)
            self.assertIn(
                f'<span class="definition-number" aria-hidden="true">{number}</span>',
                methodology,
            )
        self.assertIn('id="definition-overlapping-categories"', methodology)
        self.assertIn(
            '<span class="definition-number" aria-hidden="true">7</span>'
            'Category overlap',
            methodology,
        )
        self.assertLess(
            methodology.index('id="definition-overlapping-categories"'),
            methodology.index('<article><h3>Interpretation</h3>'),
            "all inline-referenced definitions should appear together in numeric order",
        )
        self.assertEqual(methodology.count('class="definition-number"'), 7)
        self.assertNotIn('id="definition-serious_product_builder"', methodology)
        self.assertNotIn('id="definition-standout_builder"', methodology)

    def test_community_composition_separates_exclusive_stage_from_overlays(self):
        from community_os.partner_report import _community_composition, _methodology

        cohorts = _semantic_cohort_bundle_fixture()
        summary = cohorts.cohorts[0].summary
        composition = _community_composition(self.report, summary)
        methodology = _methodology(self.report, summary)

        self.assertIn('class="career-source-note category-model"', composition)
        self.assertIn(
            "One mutually exclusive role or career-stage category per applicant",
            composition,
        )
        self.assertIn("Primary role or stage", composition)
        self.assertIn("Independent overlays", composition)
        self.assertIn("the same person may appear in more than one overlay", composition)
        self.assertNotIn("linked to a submitted team", composition.casefold())
        self.assertIn('href="#definition-overlapping-categories"', composition)
        self.assertNotIn("residual", composition.casefold())
        self.assertIn('id="definition-overlapping-categories"', methodology)
        self.assertIn(
            "do not sum the overlays or add them to the 100% distribution",
            methodology.casefold(),
        )
        self.assertIn("primary role or stage is exclusive", methodology.casefold())

    def test_published_overlap_explorer_uses_multi_signal_upset_grammar_and_plain_language(self):
        from community_os.partner_report import _published_overlap_explorer
        report = _cross_dimension_report_fixture(self.report)

        html = _published_overlap_explorer(report)

        self.assertIn('class="overlap-explorer"', html)
        self.assertIn("Cross-dimensional evidence", html)
        self.assertIn('class="upset-overlap"', html)
        self.assertIn('class="upset-column-key"', html)
        self.assertIn('aria-label="Signal columns: Founder or co-founder, Technical function, Shipped product"', html)
        for label in ("Founder", "Technical", "Shipped"):
            self.assertIn(f'<span>{label}</span>', html)
        self.assertIn("Exact intersection", html)
        self.assertNotIn('<b>F</b>', html)
        self.assertNotIn('<b>T</b>', html)
        self.assertNotIn('<b>S</b>', html)
        self.assertNotIn("Founder · Technical · Shipped", html)
        self.assertNotIn("overlap-matrix", html)
        for label in (
            "Founder / co-founder evidence", "Student stage",
            "Technical function", "Shipped-product evidence",
        ):
            self.assertIn(label, html)
        self.assertEqual(html.count("data-overlap-region="), 8)
        self.assertEqual(html.count('class="upset-dot is-on"'), 12)
        for label in (
            "Technical only", "Technical + shipped", "None recorded",
            "Founder + technical + shipped", "Founder + technical",
            "Founder only", "Shipped only", "Founder + shipped",
        ):
            self.assertIn(f'data-overlap-label="{label}"', html)
        self.assertNotIn("Only Exact", html)
        self.assertNotIn("Recorded Exact", html)
        for key, count in (
            ("technical_only_exact", 125),
            ("technical_shipped_product_exact", 53),
            ("neither_recorded_exact", 48),
            ("founder_technical_shipped_product_exact", 18),
            ("founder_technical_exact", 17),
            ("founder_only_exact", 12),
            ("shipped_product_only_exact", 7),
            ("founder_shipped_product_exact", 6),
        ):
            self.assertIn(f'data-overlap-region="{key}"', html)
            self.assertIn(f'data-overlap-count="{count}"', html)
        self.assertIn("Each applicant appears in exactly one intersection row", html)
        self.assertIn("The student overlay is separate and non-additive", html)
        self.assertIn("The eight rows partition all 286 applicants", html)
        self.assertIn("Signal not recorded is not a negative assessment", html)
        self.assertIn("Student stage + shipped-product evidence", html)
        self.assertIn("12 of 286", html)
        self.assertIn("Reviewed application evidence", html)
        self.assertIn("not a quality score", html)
        self.assertIn('aria-pressed="true"', html)
        self.assertNotIn("submitted-team", html.casefold())
        self.assertNotIn("linked to a submitted team", html.casefold())
        self.assertNotIn("case:v1", html)

    def test_published_overlap_rejects_marginals_that_do_not_match_exact_rows(self):
        from community_os.partner_report import (
            _published_overlap_explorer,
            _published_overlap_static,
        )

        report = _cross_dimension_report_fixture(self.report)
        dimensions = []
        for dimension in report.dimensions:
            if dimension.key != "cross_dimension_signals":
                dimensions.append(dimension)
                continue
            dimensions.append(replace(
                dimension,
                items=tuple(
                    replace(item, count=replace(item.count, value=54))
                    if item.key == "founder_evidence" else item
                    for item in dimension.items
                ),
            ))
        mismatched = replace(report, dimensions=tuple(dimensions))

        self.assertEqual(_published_overlap_explorer(mismatched), "")
        self.assertEqual(_published_overlap_static(mismatched), "")

    def test_published_overlap_rejects_row_keys_bound_to_wrong_signatures(self):
        from community_os.partner_report import _published_overlap_explorer

        report = _cross_dimension_report_fixture(self.report)
        by_key = {item.key: item for item in report.intersections}
        founder_only = by_key["founder_only_exact"]
        technical_only = by_key["technical_only_exact"]
        swapped = replace(
            report,
            intersections=tuple(
                replace(
                    item,
                    count=technical_only.count,
                    component_keys=technical_only.component_keys,
                )
                if item.key == founder_only.key
                else replace(
                    item,
                    count=founder_only.count,
                    component_keys=founder_only.component_keys,
                )
                if item.key == technical_only.key
                else item
                for item in report.intersections
            ),
        )

        self.assertEqual(_published_overlap_explorer(swapped), "")

    def test_semantic_pdf_adds_a_static_cross_dimension_page_from_the_same_partition(self):
        from community_os.partner_report import render_partner_talent_report
        from community_os.partner_semantic_projection import (
            build_protected_partner_semantic_candidate_summary,
        )
        from tests.test_partner_semantic_projection import semantic_aggregate

        summary = build_protected_partner_semantic_candidate_summary(
            semantic_aggregate(),
        )
        html = render_partner_talent_report(
            _cross_dimension_report_fixture(self.report),
            self.v3_report,
            semantic_summary=summary,
            semantic_context=_semantic_context(summary),
        )

        self.assertEqual(html.count("data-pdf-page="), 8)
        page = html.split('data-pdf-page="5">', 1)[1].split(
            'data-pdf-page="6">', 1,
        )[0]
        self.assertIn('id="cross-dimensional-evidence"', page)
        self.assertIn("How applicant signals intersect", page)
        self.assertEqual(page.count('class="upset-static-row"'), 8)
        self.assertEqual(page.count('class="upset-column-key"'), 1)
        for label in ("Founder", "Technical", "Shipped"):
            self.assertIn(f'<span>{label}</span>', page)
        self.assertIn("Exact intersection", page)
        self.assertNotIn('<b>F</b>', page)
        self.assertNotIn('<b>T</b>', page)
        self.assertNotIn('<b>S</b>', page)
        self.assertNotIn("Founder · Technical · Shipped", page)
        self.assertEqual(page.count('class="upset-dot is-on"'), 12)
        for label in (
            "Technical only", "Technical + shipped", "None recorded",
            "Founder + technical + shipped", "Founder + technical",
            "Founder only", "Shipped only", "Founder + shipped",
        ):
            self.assertIn(f'<b>{label}</b>', page)
        self.assertNotIn("Only Exact", page)
        self.assertNotIn("Recorded Exact", page)
        for count in (125, 53, 48, 18, 17, 12, 7, 6):
            self.assertIn(f'<strong>{count}</strong>', page)
        self.assertIn("Student stage + shipped-product evidence", page)
        self.assertIn("12 of 286", page)
        self.assertIn("exactly one intersection row", page)
        self.assertIn("not a quality score", page)
        self.assertNotIn("submitted-team", page.casefold())
        self.assertIn(
            "@media screen{.report-page-cross-dimension{display:none!important}}",
            html,
        )
        self.assertEqual(
            html.count("data-overlap-region="),
            8,
            "screen HTML must retain the interactive partition without cohort data",
        )
        self.assertIn("data-overlap-inspector", html)

    def test_pdf_pages_use_one_consistent_terminal_rule(self):
        from community_os.partner_report import render_partner_talent_report

        html = render_partner_talent_report(self.report, self.v3_report)

        self.assertIn(
            '.report-page:not(.report-page-cover)::after{content:"";position:absolute;'
            'right:12mm;bottom:6mm;left:12mm;border-top:1px solid var(--rule)}',
            html,
        )
        self.assertEqual(
            html.count('.report-page:not(.report-page-cover)::after'),
            1,
        )

    def test_partner_report_uses_one_editorial_rule_hierarchy(self):
        from community_os.partner_report import render_partner_talent_report

        html = render_partner_talent_report(self.report, self.v3_report)

        self.assertNotIn("border-top:3px solid var(--navy)", html)
        self.assertNotIn("border-top:3px solid var(--burgundy)", html)
        self.assertIn(
            ".operational-evidence{display:grid;grid-template-columns:42mm "
            "minmax(0,1fr);gap:18px;margin-top:18px;padding-top:14px;"
            "border-top:2px solid var(--navy)}",
            html,
        )
        self.assertIn(
            ".operational-evidence ul{display:grid;grid-template-columns:1fr",
            html,
        )
        self.assertNotIn(
            ".report-page-journey .operational-evidence ul{"
            "grid-template-columns:repeat(2",
            html,
        )
        self.assertIn(
            ".market-domain-strip{display:grid;grid-template-columns:180px "
            "minmax(0,1fr);gap:24px;padding-top:18px;"
            "border-top:2px solid var(--navy)}",
            html,
        )
        self.assertIn(".cohort-evidence-notes p{max-width:none", html)

    def test_semantic_sections_omit_empty_diagnostics_and_nonpositive_metrics(self):
        from community_os.partner_report import (
            _capability_market_context, _career_context, _project_landscape,
        )
        from community_os.partner_semantic_projection import (
            build_protected_partner_semantic_candidate_summary,
        )
        from tests.test_partner_semantic_projection import semantic_aggregate

        summary = build_protected_partner_semantic_candidate_summary(
            semantic_aggregate(),
        )
        empty_keys = {
            "product_maturity", "execution_scope", "external_validation",
            "problem_differentiation", "career_stage", "leadership_state",
        }
        summary = replace(
            summary,
            metrics=(
                replace(summary.metrics[0], count=None),
                replace(summary.metrics[1], count=0),
                summary.metrics[2],
            ),
            dimensions=tuple(
                replace(dimension, cells=())
                if dimension.key in empty_keys else dimension
                for dimension in summary.dimensions
            ),
            public_groups=(),
        )

        project = _project_landscape(summary)
        career = _career_context(summary)

        self.assertNotIn(summary.metrics[0].label, project)
        self.assertNotIn(summary.metrics[1].label, project)
        self.assertIn(summary.metrics[2].label, project)
        for key in (
            "product_maturity", "execution_scope", "external_validation",
            "problem_differentiation",
        ):
            self.assertNotIn(
                next(item.label for item in summary.dimensions if item.key == key),
                project,
            )
        self.assertNotIn("Career stage", career)
        self.assertNotIn("Leadership state", career)
        self.assertIn("capability-career-layout without-career-stage", career)
        self.assertIn('id="domain-context"', project)
        self.assertIn('id="domain-context"', _capability_market_context(summary))

    def test_semantic_report_has_eight_readable_full_bleed_pdf_pages(self):
        from community_os.partner_report import render_partner_talent_report
        from community_os.partner_semantic_projection import (
            build_protected_partner_semantic_candidate_summary,
        )
        from tests.test_partner_semantic_projection import (
            _rebase_taxonomy_to_population,
            semantic_aggregate,
        )

        summary = build_protected_partner_semantic_candidate_summary(
            semantic_aggregate(),
        )
        html = render_partner_talent_report(
            self.report, self.v3_report, semantic_summary=summary,
            semantic_context=_semantic_context(summary),
        )

        self.assertEqual(html.count("data-pdf-page="), 8)
        for page in range(1, 9):
            self.assertEqual(html.count(f'data-pdf-page="{page}"'), 1)
        self.assertIn("@page{size:A4 landscape;margin:0}", html)
        self.assertIn("width:297mm", html)
        self.assertIn("min-height:210mm", html)
        self.assertIn("html,body{width:297mm;margin:0;background:var(--paper);font-size:10pt}", html)
        self.assertIn(".report-page-methodology .definition-list dd{font-size:9.5pt}", html)
        self.assertIn(".report-page-methodology .report-note{font-size:9pt}", html)
        self.assertIn('id="methodology"', html)
        self.assertIn('id="evidence-boundary"', html)
        self.assertIn('<a href="#evidence-boundary">Evidence coverage</a>', html)
        self.assertIn(
            ".dashboard-metric-group>div{display:grid;grid-template-columns:repeat(4,minmax(0,1fr))",
            html,
        )
        self.assertIn("What evidence was available", html)
        self.assertIn("How to read the evidence", html)
        self.assertIn("Prototype or beyond", html)
        self.assertNotIn("Working product + substantial attributable execution", html)
        self.assertNotIn("not charted as a cohort comparison", html)
        self.assertNotIn("does not mean the community has no strong builders", html)
        self.assertIn("repository ownership alone does not qualify", html)
        self.assertIn("topic keywords alone do not qualify", html)

    def test_semantic_pages_follow_the_approved_partner_story(self):
        from community_os.partner_report import render_partner_talent_report
        from community_os.partner_semantic_projection import (
            build_protected_partner_semantic_candidate_summary,
        )
        from tests.test_partner_semantic_projection import semantic_aggregate

        summary = build_protected_partner_semantic_candidate_summary(
            semantic_aggregate(),
        )
        html = render_partner_talent_report(
            self.report, self.v3_report, semantic_summary=summary,
            semantic_context=_semantic_context(summary),
        )

        pages = {}
        for page_number in range(2, 9):
            marker = f'data-pdf-page="{page_number}">'
            start = html.index(marker) + len(marker)
            if page_number < 8:
                end = html.index(f'data-pdf-page="{page_number + 1}">', start)
            else:
                end = html.index("</main>", start)
            pages[page_number] = html[start:end]

        self.assertIn('id="journey"', pages[2])
        self.assertNotIn('id="participation-outcome"', pages[2])
        self.assertNotIn("Participation translated into submitted work", pages[2])
        self.assertNotIn("People linked to submitted teams", pages[2])
        self.assertNotIn("Selection context", pages[2])
        self.assertNotIn("Individual non-selection reasons", pages[2])
        self.assertNotIn('id="semantic-evidence"', pages[2])
        self.assertIn('id="semantic-evidence"', pages[3])
        self.assertIn('id="project-landscape"', pages[3])
        self.assertNotIn('id="domain-context"', pages[3])
        self.assertIn('id="career-context"', pages[4])
        for label in ("Student", "Senior", "Career functions"):
            self.assertIn(label, pages[4])
        self.assertIn("Top functions shown", pages[4])
        self.assertIn("founder / co-founder role", pages[4].casefold())
        self.assertIn("Reviewed founding evidence", pages[4])
        self.assertIn('id="cross-dimensional-evidence"', pages[5])
        self.assertIn("How applicant signals intersect", pages[5])
        self.assertIn('id="capability-context"', pages[6])
        self.assertIn('id="domain-context"', pages[6])
        self.assertIn(
            "<header><h3>Where the work is aimed</h3><p>Top domains shown; ",
            pages[6],
        )
        self.assertIn('id="evidence-boundary"', pages[7])
        self.assertIn("Evidence source use", pages[7])
        self.assertIn("Assessment boundary", pages[7])
        self.assertNotIn('id="methodology"', pages[7])
        self.assertIn('id="methodology"', pages[8])
        self.assertIn("Category overlap", pages[8])

    def test_semantic_report_uses_fixed_public_groups_without_repeating_unknown_panels(self):
        from community_os.partner_report import render_partner_talent_report
        from community_os.partner_semantic_projection import (
            build_protected_partner_semantic_candidate_summary,
        )
        from tests.test_partner_semantic_projection import semantic_aggregate

        summary = build_protected_partner_semantic_candidate_summary(
            semantic_aggregate(),
        )
        html = render_partner_talent_report(
            self.report, self.v3_report, semantic_summary=summary,
            semantic_context=_semantic_context(summary),
        )

        for label in (
            "Prototype or beyond", "Working or production",
            "Moderate or stronger technical", "Advanced or exceptional technical",
            "Substantial or greater execution", "Early or greater validation",
            "Meaningful or strong validation", "Differentiated or ambitious problem",
        ):
            self.assertIn(label, html)
        self.assertNotIn("Unknown or unclassified", html)
        self.assertIn("Unknown never means a negative assessment", html)

    def test_partial_team_submission_matrix_never_claims_every_team_submitted(self):
        from community_os.partner_report import _builder_evidence

        published = []
        submitted_written = False
        not_submitted_written = False
        for cell in self.v3_report.team_submission_matrix.cells:
            value = 0
            if cell.column == "submitted" and not submitted_written:
                value = 20
                submitted_written = True
            elif cell.column == "not_submitted" and not not_submitted_written:
                value = 5
                not_submitted_written = True
            published.append(replace(
                cell,
                count=replace(
                    cell.count, value=value, privacy="published", reason=None,
                ),
            ))
        event_report = replace(
            self.v3_report,
            team_submission_matrix=replace(
                self.v3_report.team_submission_matrix,
                cells=tuple(published),
            ),
        )

        html = _builder_evidence(
            self.report,
            event_report,
            include_team_submission_summary=True,
        )

        self.assertIn("20 of 25 submitted teams", html)
        self.assertIn("80% of reconciled final teams submitted a project", html)
        self.assertNotIn("Every reconciled final team submitted a project", html)

    def test_team_delivery_stays_distinct_without_public_linkage_jargon(self):
        from community_os.partner_report import render_partner_talent_report
        from community_os.report_contract import (
            BuilderSignalIntersections, CountValue, SignalIntersection,
        )
        from community_os.partner_semantic_projection import (
            build_protected_partner_semantic_candidate_summary,
        )
        from tests.test_partner_semantic_projection import semantic_aggregate

        cells = []
        for cell in self.v3_report.team_submission_matrix.cells:
            value = 10 if cell.column == "submitted" else 0
            cells.append(replace(
                cell,
                count=replace(cell.count, value=value, privacy="published", reason=None),
            ))
        attendance = next(
            stage.count.value
            for stage in self.v3_report.attendance_funnel.stages
            if stage.key in {"on_site", "checked_in"}
        )
        self.assertIsInstance(attendance, int)
        builder_intersections = BuilderSignalIntersections(
            unit="people",
            signal_keys=("submitted_team",),
            intersections=(SignalIntersection(
                signals=("submitted_team",),
                count=CountValue(
                    value=attendance - 2, privacy="published", reason=None,
                ),
            ),),
        )
        event_report = replace(
            self.v3_report,
            team_submission_matrix=replace(
                self.v3_report.team_submission_matrix, cells=tuple(cells),
            ),
            builder_signal_intersections=builder_intersections,
            composition=replace(
                self.v3_report.composition,
                categories=tuple(
                    replace(
                        item,
                        count=replace(
                            item.count,
                            value=143,
                            privacy="published",
                            reason=None,
                        ),
                    )
                    for item in self.v3_report.composition.categories
                ),
            ),
        )
        summary = build_protected_partner_semantic_candidate_summary(
            semantic_aggregate(),
        )
        html = render_partner_talent_report(
            self.report, event_report, semantic_summary=summary,
            semantic_context=_semantic_context(summary),
        )
        page_two = html.split('data-pdf-page="2">', 1)[1].split(
            'data-pdf-page="3">', 1,
        )[0]

        self.assertIn("20 of 20", page_two)
        self.assertIn("final teams submitted a project", page_two)
        self.assertIn("Applied without a pre-formed team", page_two)
        self.assertIn("Applied with a pre-formed team", page_two)
        self.assertIn("team-level completion measure", page_two)
        self.assertIn(
            "not a participant quality signal or the count of people whose reviewed evidence cited an event submission",
            page_two,
        )
        self.assertNotIn(f"{attendance - 2} of {attendance}", page_two)
        self.assertNotIn("confirmed attendees were connected to submitted teams", page_two)
        self.assertNotIn("attendees were not connected", page_two)
        self.assertNotIn("completion result is different from", page_two)
        self.assertIn("Team delivery", page_two)
        self.assertNotIn("Linkage reviewed", page_two)
        self.assertNotIn("unmatched attendance-to-team complement", page_two)
        self.assertNotIn("2 unmatched", page_two)

    def test_semantic_story_excludes_legacy_intersections_and_describes_only_page_three(self):
        from community_os.partner_report import render_partner_talent_report
        from community_os.partner_semantic_projection import (
            build_protected_partner_semantic_candidate_summary,
        )
        from tests.test_partner_semantic_projection import semantic_aggregate

        summary = build_protected_partner_semantic_candidate_summary(
            semantic_aggregate(),
        )
        html = render_partner_talent_report(
            self.report, self.v3_report, semantic_summary=summary,
            semantic_context=_semantic_context(summary),
        )
        page_two = html.split('data-pdf-page="2">', 1)[1].split(
            'data-pdf-page="3">', 1,
        )[0]
        page_three = html.split('data-pdf-page="3">', 1)[1].split(
            'data-pdf-page="4">', 1,
        )[0]

        self.assertNotIn("People linked to submitted teams", page_two)
        self.assertNotIn("Participation translated into submitted work", page_two)
        self.assertNotIn("Shared evidence", page_two)
        for intersection in self.report.intersections:
            self.assertNotIn(intersection.label, page_two)
        self.assertIn(
            "Evidence-bound project maturity, technical depth, execution ownership, "
            "external validation, and problem differentiation.",
            page_three,
        )
        self.assertNotIn("domains, methods, and demonstrated capabilities", page_three)

    def test_semantic_print_pages_use_the_landscape_canvas_instead_of_collapsing(self):
        from community_os.partner_report import render_partner_talent_report
        from community_os.partner_semantic_projection import (
            build_protected_partner_semantic_candidate_summary,
        )
        from tests.test_partner_semantic_projection import semantic_aggregate

        summary = build_protected_partner_semantic_candidate_summary(
            semantic_aggregate(),
        )
        html = render_partner_talent_report(
            self.report, self.v3_report, semantic_summary=summary,
            semantic_context=_semantic_context(summary),
        )

        self.assertIn(
            ".report-page-taxonomy .exhibit{display:grid;height:190mm;"
            "grid-template-rows:auto auto minmax(0,1fr) auto}",
            html,
        )
        self.assertIn(
            ".report-page-evidence{height:190mm;"
            "grid-template-rows:minmax(0,1fr) minmax(0,.95fr)}",
            html,
        )
        self.assertIn(
            ".report-page-evidence .exhibit{display:flex;min-height:0;flex-direction:column}",
            html,
        )
        self.assertIn(
            ".report-page-evidence .evidence-strip article:only-child{grid-column:1/-1;"
            "align-items:center;text-align:center}",
            html,
        )
        self.assertIn(
            ".report-page-journey{height:190mm}",
            html,
        )
        self.assertIn(
            ".report-page-career .exhibit{display:grid;height:190mm;"
            "grid-template-rows:auto minmax(0,1fr) auto}",
            html,
        )
        self.assertIn(
            ".report-page-career .taxonomy-grid-career{grid-template-rows:repeat(2,minmax(0,1fr))}",
            html,
        )
        self.assertIn(
            ".report-page-career .capability-career-layout{display:grid;"
            "grid-template-columns:.72fr .78fr 1.5fr}",
            html,
        )
        self.assertIn(
            ".report-page-methodology .domain-context{display:grid;"
            "grid-template-columns:42mm minmax(0,1fr)}",
            html,
        )
        self.assertIn(
            ".report-page-methodology .definition-list dt{font-size:8pt}",
            html,
        )
        self.assertIn(
            ".report-page-methodology .definition-list dd{font-size:7.5pt}",
            html,
        )
        self.assertIn(
            ".report-page-methodology .report-note{font-size:7.5pt}",
            html,
        )

    def test_semantic_report_real_pdf_is_seven_legible_landscape_pages(self):
        import shutil
        import subprocess
        import warnings
        import xml.etree.ElementTree as ET

        from community_os.partner_report import render_partner_talent_report
        from community_os.partner_semantic_projection import (
            build_protected_partner_semantic_candidate_summary,
        )
        from community_os.pdf_export import export_pdf, find_chromium
        from tests.test_partner_semantic_projection import semantic_aggregate

        browser = find_chromium()
        pdfinfo = shutil.which("pdfinfo")
        pdftocairo = shutil.which("pdftocairo")
        pdftohtml = shutil.which("pdftohtml")
        pdftotext = shutil.which("pdftotext")
        if any(
            tool is None
            for tool in (browser, pdfinfo, pdftocairo, pdftohtml, pdftotext)
        ):
            self.skipTest(
                "isolated Chromium and Poppler PDF inspection tools are required",
            )

        summary = build_protected_partner_semantic_candidate_summary(
            semantic_aggregate(),
        )
        html = render_partner_talent_report(
            self.report, self.v3_report, semantic_summary=summary,
            semantic_context=_semantic_context(summary),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "partner.html"
            output = root / "partner.pdf"
            source.write_text(html, encoding="utf-8")
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", ResourceWarning)
                export_pdf(
                    source, output,
                    stable_timestamp=self.report.metadata.generated_at,
                )

            page_two_svg = root / "page-two.svg"
            subprocess.run(
                [
                    str(pdftocairo), "-f", "2", "-l", "2", "-svg",
                    str(output), str(page_two_svg),
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            svg_root = ET.parse(page_two_svg).getroot()
            rectangle = re.compile(
                r"M ([0-9.]+) ([0-9.]+) L ([0-9.]+) [0-9.]+ "
                r"L [0-9.]+ ([0-9.]+) L [0-9.]+ [0-9.]+ Z",
            )
            funnel_widths: list[float] = []
            data_fills = {
                "rgb(0%, 0%, 17.248535%)",
                "rgb(50.19989%, 0.389099%, 12.159729%)",
                "rgb(65.879822%, 35.289001%, 43.919373%)",
            }
            for path in svg_root.iter("{http://www.w3.org/2000/svg}path"):
                if path.attrib.get("fill") not in data_fills:
                    continue
                match = rectangle.search(path.attrib.get("d", ""))
                if match is None:
                    continue
                left, top, right, bottom = (float(value) for value in match.groups())
                if 120 <= top <= 280 and 20 <= bottom - top <= 30:
                    funnel_widths.append(right - left)
            self.assertEqual(len(funnel_widths), 3)
            funnel_widths.sort(reverse=True)
            applied = next(
                stage.count.value for stage in self.report.cohort.stages
                if stage.key == "valid_applicants"
            )
            accepted = next(
                stage.count.value for stage in self.report.cohort.stages
                if stage.key == "accepted"
            )
            present = next(
                stage.count.value for stage in self.report.cohort.stages
                if stage.key == "checked_in"
            )
            self.assertGreater(funnel_widths[0], 200)
            self.assertAlmostEqual(
                funnel_widths[1] / funnel_widths[0],
                accepted / applied,
                delta=0.01,
            )
            self.assertAlmostEqual(
                funnel_widths[2] / funnel_widths[0],
                present / applied,
                delta=0.01,
            )

            info = subprocess.run(
                [pdfinfo, str(output)], check=True, capture_output=True, text=True,
            ).stdout
            self.assertRegex(info, r"(?m)^Pages:\s+7$")
            size = re.search(
                r"(?m)^Page size:\s+([0-9.]+) x ([0-9.]+) pts \(A4\)$",
                info,
            )
            self.assertIsNotNone(size)
            width, height = (float(value) for value in size.groups())
            self.assertGreater(width, height)
            self.assertAlmostEqual(width, 841.92, delta=1.0)
            self.assertAlmostEqual(height, 594.96, delta=1.0)

            xml = subprocess.run(
                [pdftohtml, "-xml", "-i", "-stdout", str(output)],
                check=True, capture_output=True, text=True,
            ).stdout
            document = ET.fromstring(xml)
            pages = document.findall("page")
            self.assertEqual(len(pages), 7)
            fonts: dict[str, int] = {}
            for page in pages:
                for font in page.findall("fontspec"):
                    fonts[str(font.attrib["id"])] = int(font.attrib["size"])

            for page_index in (2, 3):
                text_tops = sorted({
                    int(item.attrib["top"])
                    for item in pages[page_index].findall("text")
                    if 120 <= int(item.attrib["top"]) <= 760
                })
                largest_gap = max(
                    later - earlier
                    for earlier, later in zip(text_tops, text_tops[1:])
                )
                self.assertLessEqual(largest_gap, 150)

            page_four_items = pages[3].findall("text")
            overlap = next(
                item for item in page_four_items
                if "".join(item.itertext()).strip() == "Independent overlays"
            )
            overlap_top = int(overlap.attrib["top"])
            career_items = [
                item for item in page_four_items
                if int(item.attrib["left"]) >= 640
                and 180 <= int(item.attrib["top"]) < overlap_top
            ]
            self.assertTrue(career_items)
            self.assertLessEqual(
                max(
                    int(item.attrib["top"]) + int(item.attrib["height"])
                    for item in career_items
                )
                + 8,
                overlap_top,
                "slide-four career rows touch the overlap-note divider",
            )

            content_sizes = [
                fonts[str(item.attrib["font"])]
                for page in pages[1:]
                for item in page.findall("text")
            ]
            self.assertTrue(content_sizes)
            self.assertGreaterEqual(min(content_sizes), 11)
            page_six_items = pages[5].findall("text")
            page_six_text = {
                "".join(item.itertext()).strip() for item in page_six_items
            }
            self.assertIn("Assessment boundary.", page_six_text)
            self.assertNotIn("Reading note", page_six_text)
            page_six_height = int(pages[5].attrib["height"])
            self.assertLessEqual(
                max(
                    int(item.attrib["top"]) + int(item.attrib["height"])
                    for item in page_six_items
                ),
                page_six_height,
                "page-six text extends outside the PDF media box",
            )
            page_six_plain_text = subprocess.run(
                [pdftotext, "-f", "6", "-l", "6", str(output), "-"],
                check=True, capture_output=True, text=True,
            ).stdout
            self.assertIn("raw provider records.", page_six_plain_text)
            page_seven_plain_text = subprocess.run(
                [pdftotext, "-f", "7", "-l", "7", str(output), "-"],
                check=True, capture_output=True, text=True,
            ).stdout
            self.assertIn("Category overlap", page_seven_plain_text)
            self.assertNotIn("Reviewed-fact source use", page_seven_plain_text)

    def test_cohort_pdf_keeps_project_source_boundary_and_selection_note_on_page_three(self):
        import shutil
        import subprocess
        import warnings

        from community_os.partner_report import render_partner_talent_report
        from community_os.pdf_export import export_pdf, find_chromium

        browser = find_chromium()
        pdftotext = shutil.which("pdftotext")
        if browser is None or pdftotext is None:
            self.skipTest("isolated Chromium and pdftotext are required")

        cohorts = _semantic_cohort_bundle_fixture(with_all_only_signal=True)
        summary = cohorts.cohorts[0].summary
        report_values = {
            "valid_applicants": 20, "accepted": 10, "checked_in": 5,
        }
        event_values = {"applied": 15, "approved": 10, "checked_in": 5}
        report = replace(
            self.report,
            metadata=replace(self.report.metadata, event_key=summary.event_key),
            cohort=replace(
                self.report.cohort,
                denominator=replace(self.report.cohort.denominator, value=20),
                stages=tuple(
                    replace(stage, count=replace(stage.count, value=report_values[stage.key]))
                    if stage.key in report_values else stage
                    for stage in self.report.cohort.stages
                ),
            ),
        )
        event_report = replace(
            self.v3_report,
            metadata=replace(self.v3_report.metadata, event_key=summary.event_key),
            attendance_funnel=replace(
                self.v3_report.attendance_funnel,
                stages=tuple(
                    replace(stage, count=replace(stage.count, value=event_values[stage.key]))
                    if stage.key in event_values else stage
                    for stage in self.v3_report.attendance_funnel.stages
                ),
            ),
        )
        html = render_partner_talent_report(
            report,
            event_report,
            semantic_summary=summary,
            semantic_cohorts=cohorts,
            semantic_context=_semantic_context(summary),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "partner.html"
            output = root / "partner.pdf"
            source.write_text(html, encoding="utf-8")
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", ResourceWarning)
                export_pdf(
                    source, output,
                    stable_timestamp=report.metadata.generated_at,
                )
            page_three = subprocess.run(
                [pdftotext, "-f", "3", "-l", "3", "-layout", str(output), "-"],
                check=True, capture_output=True, text=True,
            ).stdout

        normalized_page_three = " ".join(page_three.split())
        self.assertIn("Public-project evidence used", normalized_page_three)
        self.assertIn(
            "non-use is not a quality judgment",
            normalized_page_three.casefold(),
        )
        self.assertNotIn("Dedicated career-provider", normalized_page_three)
        self.assertIn(
            "without treating selection as quality",
            normalized_page_three,
        )
        self.assertIn("Positive evidence available", normalized_page_three)
        self.assertIn("for the full applicant pool", normalized_page_three)
        self.assertNotIn("All applicants only", normalized_page_three)

    def test_rejects_forged_semantic_summary_before_private_text_can_render(self):
        from community_os.partner_report import render_partner_talent_report
        from community_os.partner_semantic_projection import (
            build_protected_partner_semantic_candidate_summary,
        )
        from tests.test_partner_semantic_projection import semantic_aggregate

        summary = build_protected_partner_semantic_candidate_summary(
            semantic_aggregate(),
        )
        forged = replace(
            summary,
            metrics=(
                replace(
                    summary.metrics[0],
                    label="Private Person private@example.org",
                    note="https://github.com/private/person",
                ),
                *summary.metrics[1:],
            ),
        )

        with self.assertRaisesRegex(PermissionError, "summary"):
            render_partner_talent_report(
                self.report, self.v3_report, semantic_summary=forged,
                semantic_context=_semantic_context(summary),
            )

    def test_rejects_semantic_population_that_does_not_match_report_population(self):
        from community_os.partner_report import render_partner_talent_report
        from community_os.partner_semantic_projection import (
            build_protected_partner_semantic_candidate_summary,
        )
        from tests.test_partner_semantic_projection import (
            _rebase_taxonomy_to_population,
            semantic_aggregate,
        )

        aggregate = semantic_aggregate()
        population = aggregate["population"]
        assert isinstance(population, dict)
        population.update({
            "assessed_count": 195,
            "eligible_count": 195,
            "excluded_count": 0,
            "total_count": 195,
            "unknown_count": 0,
        })
        states = population["state_counts"]
        assert isinstance(states, dict)
        states.update({
            "assessed": 195,
            "conflict": 0,
            "excluded": 0,
            "no_evidence": 0,
            "provider_unavailable": 0,
            "rejected": 0,
        })
        _rebase_taxonomy_to_population(aggregate)
        summary = build_protected_partner_semantic_candidate_summary(aggregate)

        with self.assertRaisesRegex(ValueError, "semantic population"):
            render_partner_talent_report(
                self.report, self.v3_report, semantic_summary=summary,
                semantic_context=_semantic_context(summary),
            )

    def test_rejects_semantic_summary_bound_to_a_different_event(self):
        from community_os.partner_report import render_partner_talent_report
        from community_os.partner_semantic_projection import (
            build_protected_partner_semantic_candidate_summary,
        )
        from tests.test_partner_semantic_projection import semantic_aggregate

        aggregate = semantic_aggregate()
        bindings = aggregate["bindings"]
        assert isinstance(bindings, dict)
        bindings["event_key"] = "different-event"
        summary = build_protected_partner_semantic_candidate_summary(aggregate)

        with self.assertRaisesRegex(ValueError, "semantic event"):
            render_partner_talent_report(
                self.report, self.v3_report, semantic_summary=summary,
                semantic_context=_semantic_context(summary),
            )

    def test_rejects_semantics_when_current_source_or_run_context_differs(self):
        from community_os.partner_report import render_partner_talent_report
        from community_os.partner_semantic_projection import (
            build_protected_partner_semantic_candidate_summary,
        )
        from tests.test_partner_semantic_projection import semantic_aggregate

        summary = build_protected_partner_semantic_candidate_summary(
            semantic_aggregate(),
        )
        for field in ("source_snapshot_sha256", "run_sha256"):
            context = _semantic_context(summary)
            context[field] = "f" * 64
            with self.subTest(field=field):
                with self.assertRaisesRegex(PermissionError, "context"):
                    render_partner_talent_report(
                        self.report,
                        self.v3_report,
                        semantic_summary=summary,
                        semantic_context=context,
                    )

    def test_suppressed_attendance_has_no_zero_length_or_exact_value_encoding(self):
        from community_os.partner_report import render_partner_talent_report

        stages = tuple(
            replace(
                stage,
                count=replace(
                    stage.count,
                    value=None,
                    privacy="withheld",
                    reason="Complement below publication threshold",
                ),
            ) if stage.key in {"checked_in", "on_site"} else stage
            for stage in self.v3_report.attendance_funnel.stages
        )
        intelligence_stages = tuple(
            replace(
                stage,
                count=replace(
                    stage.count,
                    value=None,
                    privacy="withheld",
                    reason="Complement below publication threshold",
                ),
            ) if stage.key in {"checked_in", "on_site"} else stage
            for stage in self.report.cohort.stages
        )
        report = replace(
            self.report,
            cohort=replace(self.report.cohort, stages=intelligence_stages),
        )
        event_report = replace(
            self.v3_report,
            attendance_funnel=replace(self.v3_report.attendance_funnel, stages=stages),
        )

        html = render_partner_talent_report(report, event_report)

        self.assertIn('data-value-state="hidden"', html)
        self.assertNotIn('--share:0', html)
        self.assertNotIn('width:0%', html)
        self.assertIn('class="privacy-marker"', html)
        self.assertIn("No value encoded", html)
        self.assertNotIn('class="hidden-band"', html)

    def test_submitted_team_singleton_stays_out_of_partner_talent_evidence(self):
        from community_os.partner_report import render_partner_talent_report

        source = self.v3_report.builder_signal_intersections.intersections[0]
        submitted_team = replace(
            source,
            signals=("submitted_team",),
            count=replace(source.count, value=76, privacy="published", reason=None),
        )
        event_report = replace(
            self.v3_report,
            builder_signal_intersections=replace(
                self.v3_report.builder_signal_intersections,
                signal_keys=("submitted_team",),
                intersections=(submitted_team,),
            ),
        )

        html = render_partner_talent_report(self.report, event_report)

        self.assertNotIn("People with reviewed team linkage", html)
        self.assertNotIn("Linked to submitted teams", html)
        self.assertNotIn("Shared evidence", html)
        self.assertIn("Shipped-product evidence", html)
        self.assertNotIn("Observed overlap", html)
        self.assertNotIn("Builder signal intersections", html)

    def test_withheld_submission_cells_do_not_render_as_zero(self):
        from community_os.partner_report import render_partner_talent_report

        cells = tuple(
            replace(
                cell,
                count=replace(
                    cell.count,
                    value=None,
                    privacy="withheld",
                    reason="Below publication threshold",
                ),
            ) if cell.column == "submitted" else cell
            for cell in self.v3_report.team_submission_matrix.cells
        )
        event_report = replace(
            self.v3_report,
            team_submission_matrix=replace(
                self.v3_report.team_submission_matrix,
                cells=cells,
            ),
        )

        html = render_partner_talent_report(self.report, event_report)

        self.assertIn("Evidence pending", html)
        self.assertNotIn("0 of 20", html)

    def test_team_submission_denominator_comes_from_the_team_matrix(self):
        from community_os.partner_report import render_partner_talent_report

        inflated_artifacts = tuple(
            replace(
                item,
                eligible=replace(item.eligible, value=99),
            )
            for item in self.v3_report.artifact_completeness.items
        )
        published_matrix = tuple(
            replace(
                cell,
                count=replace(
                    cell.count,
                    value=0,
                    privacy="published",
                    reason=None,
                ),
            ) if cell.count.value is None else cell
            for cell in self.v3_report.team_submission_matrix.cells
        )
        event_report = replace(
            self.v3_report,
            artifact_completeness=replace(
                self.v3_report.artifact_completeness,
                items=inflated_artifacts,
            ),
            team_submission_matrix=replace(
                self.v3_report.team_submission_matrix,
                cells=published_matrix,
            ),
        )
        submitted = sum(
            cell.count.value or 0
            for cell in event_report.team_submission_matrix.cells
            if cell.column == "submitted"
        )
        eligible = sum(
            cell.count.value or 0
            for cell in event_report.team_submission_matrix.cells
        )

        html = render_partner_talent_report(self.report, event_report)

        self.assertIn(f"{submitted} of {eligible}", html)
        self.assertNotIn("of 99", html)

    def test_mobile_navigation_has_full_touch_targets(self):
        from community_os.partner_report import render_partner_talent_report

        html = render_partner_talent_report(self.report, self.v3_report)

        self.assertIn(".report-nav a{min-height:44px", html)

    def test_contract_drift_fails_closed_before_rendering(self):
        from community_os.partner_report import render_partner_talent_report

        cases = (
            (
                replace(
                    self.v3_report,
                    metadata=replace(self.v3_report.metadata, event_key="different-event"),
                ),
                "metadata.event_key",
            ),
            (
                replace(
                    self.v3_report,
                    privacy=replace(self.v3_report.privacy, minimum_count=6),
                ),
                "privacy.minimum_count",
            ),
            (
                replace(
                    self.v3_report,
                    attendance_funnel=replace(
                        self.v3_report.attendance_funnel,
                        stages=(
                            replace(
                                self.v3_report.attendance_funnel.stages[0],
                                count=replace(
                                    self.v3_report.attendance_funnel.stages[0].count,
                                    value=999,
                                ),
                            ),
                            *self.v3_report.attendance_funnel.stages[1:],
                        ),
                    ),
                ),
                "shared_funnel.accepted",
            ),
        )

        for v3_report, expected in cases:
            with self.subTest(expected=expected), self.assertRaisesRegex(ValueError, expected):
                render_partner_talent_report(self.report, v3_report)

    def test_real_aggregate_stage_aliases_share_the_same_funnel(self):
        from community_os.partner_report import render_partner_talent_report

        intelligence_stages = tuple(
            replace(
                stage,
                key={"accepted": "going_accepted", "checked_in": "on_site"}.get(
                    stage.key, stage.key,
                ),
            )
            for stage in self.report.cohort.stages
        )
        event_stages = tuple(
            replace(
                stage,
                key={"approved": "going_accepted", "checked_in": "on_site"}.get(
                    stage.key, stage.key,
                ),
            )
            for stage in self.v3_report.attendance_funnel.stages
        )
        report = replace(
            self.report,
            cohort=replace(self.report.cohort, stages=intelligence_stages),
        )
        event_report = replace(
            self.v3_report,
            attendance_funnel=replace(
                self.v3_report.attendance_funnel,
                stages=event_stages,
            ),
        )

        html = render_partner_talent_report(report, event_report)

        self.assertIn('id="journey"', html)
        self.assertIn("Confirmed present at the event", html)
        self.assertNotIn("accepted participants checked in", html)


if __name__ == "__main__":
    unittest.main()
