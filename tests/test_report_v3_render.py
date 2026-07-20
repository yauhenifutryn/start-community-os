"""Behavioral contract for the partner-facing talent report v3 renderer."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import re
import unittest


class TalentReportV3RenderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        from community_os.report_contract import load_report_contract

        cls.repo = Path(__file__).resolve().parents[1]
        cls.report = load_report_contract(
            cls.repo / "config/contracts/talent-report-v3.synthetic.json"
        )

    def test_renders_every_v3_exhibit_with_semantic_fallbacks(self) -> None:
        from community_os.render import render_report

        html = render_report(self.report)

        for expected in (
            "START Warsaw Talent Data Room",
            "Synthetic evidence briefing",
            "Attendance signature",
            "Participant journey",
            "Track and submission state",
            "Builder signal intersections",
            "Track and project domain",
            "Cohort composition",
            "Artifact completeness",
            "Data readiness",
            "Methodology",
            'data-chart-key="journey"',
            'data-volume-funnel="journey"',
            'data-chart-key="signal-intersections"',
            'class="data-fallback"',
            'aria-label="Volume-adjusted participant funnel in people"',
            "Band widths encode people within each step",
            "Each dot represents one person",
            "Navy marks the observed terminal cohort",
            "Below publication threshold",
        ):
            self.assertIn(expected, html)

        self.assertIn("@media print", html)
        self.assertIn(".signature,.funnel{grid-template-columns:repeat(3,1fr)}", html)
        self.assertIn(".artifacts,.readiness-grid{grid-template-columns:repeat(2,1fr)}", html)
        self.assertIn("#evidence{font-size:8pt}", html)
        self.assertIn("@media (prefers-reduced-motion:reduce)", html)
        self.assertIn("AvenirLTNextPro", html)
        self.assertIn("#00002c", html)
        self.assertIn("#80011f", html)
        self.assertIn("data:image/svg+xml", html)
        self.assertIn('<link rel="icon" href="data:image/svg+xml,', html)
        self.assertIn("--share:", html)
        self.assertNotIn('<svg class="journey"', html)
        self.assertNotIn("min-height:280px", html)
        self.assertNotIn("Partner outcomes", html)
        self.assertNotIn("Introductions", html)
        self.assertNotIn("Investments", html)
        self.assertNotIn("<canvas", html)
        self.assertNotIn("<script src=", html)
        self.assertNotIn('src="http', html)
        self.assertNotIn('href="http', html)
        self.assertNotIn("url(http", html)

    def test_no_javascript_document_keeps_evidence_and_hides_only_enhancements(self) -> None:
        from community_os.render import render_report

        html = render_report(self.report)

        self.assertEqual(html.count("<table"), 7)
        self.assertIn("<noscript>", html)
        self.assertIn("All evidence and tables remain available without JavaScript.", html)
        self.assertNotIn("disabled", html)
        self.assertIn(".js-only{display:none}", html)
        self.assertIn(".js .js-only", html)

    def test_online_report_prioritizes_clickable_evidence(self) -> None:
        from community_os.render import render_report

        html = render_report(self.report)

        for expected in (
            "Evidence cockpit",
            "55 people shipped",
            "69% of approved people",
            "50 team-path people",
            "71% of check-ins",
            "20 submitted teams",
            "15 repositories",
            "75% of eligible projects",
            'data-evidence-target="attendance"',
            'data-inspect="attendance"',
            'data-inspect="journey"',
            'data-inspect="submissions"',
            'data-inspect="signals"',
            'data-inspect="domains"',
            'data-inspect="composition"',
            'data-inspect="artifacts"',
            'data-inspector="attendance"',
            'data-inspector="journey"',
            'aria-live="polite"',
            'data-mode-group="attendance"',
            'data-mode-value="rate"',
            'data-primary="80"',
            'data-alternate="Starting cohort"',
            '<details class="data-fallback">',
            "Open evidence table",
            "datum_inspected",
            "beforeprint",
            "afterprint",
        ):
            self.assertIn(expected, html)

        self.assertGreaterEqual(html.count('data-inspect="'), 15)
        self.assertEqual(html.count('class="person-dot terminal"'), 55)
        self.assertEqual(html.count('style="background:var(--navy)"'), 55)
        self.assertNotIn('<details class="data-fallback" open>', html)
        self.assertIn(
            ".composition-row{grid-template-columns:1fr auto;gap:8px}",
            html,
        )
        self.assertIn("details.data-fallback>summary", html)
        self.assertIn("noscript,.cockpit,.inspector,.mode-switch{display:none!important}", html)

    def test_withheld_artifact_coverage_never_renders_as_none_percent(self) -> None:
        from community_os.report_v3_renderer import render_v3_exhibits

        first, *rest = self.report.artifact_completeness.items
        withheld = replace(
            first,
            present=replace(
                first.present,
                value=None,
                privacy="withheld",
                reason="Unavailable source field",
            ),
        )
        report = replace(
            self.report,
            artifact_completeness=replace(
                self.report.artifact_completeness,
                items=(withheld, *rest),
            ),
        )

        html = render_v3_exhibits(report).html

        self.assertNotIn("None%", html)
        self.assertIn("Withheld of 20 projects · Coverage withheld", html)
        self.assertIn('data-alternate="Coverage withheld"', html)

    def test_withheld_next_stage_does_not_render_people_as_stopped(self) -> None:
        from community_os.report_v3_renderer import render_v3_exhibits

        stages = list(self.report.attendance_funnel.stages)
        stages[-1] = replace(
            stages[-1],
            count=replace(
                stages[-1].count,
                value=None,
                privacy="withheld",
                reason="Complement below publication threshold",
            ),
        )
        report = replace(
            self.report,
            attendance_funnel=replace(
                self.report.attendance_funnel,
                stages=tuple(stages),
            ),
        )

        html = render_v3_exhibits(report).html

        self.assertEqual(html.count('class="person-dot unknown"'), 70)
        self.assertIn("Hatched dots mark a protected next-stage split", html)

    def test_fully_withheld_stage_uses_non_countable_privacy_placeholder(self) -> None:
        from community_os.report_v3_renderer import render_v3_exhibits

        stages = list(self.report.attendance_funnel.stages)
        stages[-1] = replace(
            stages[-1],
            count=replace(
                stages[-1].count,
                value=None,
                privacy="withheld",
                reason="Complement below publication threshold",
            ),
        )
        report = replace(
            self.report,
            attendance_funnel=replace(
                self.report.attendance_funnel,
                stages=tuple(stages),
            ),
        )

        html = render_v3_exhibits(report).html

        self.assertIn('class="privacy-placeholder"', html)
        self.assertNotIn('class="person-dot withheld"', html)

    def test_analytics_is_inline_allowlisted_and_contains_no_sensitive_dimensions(self) -> None:
        from community_os.render import render_report

        html = render_report(
            self.report,
            posthog_key="phc_public",
            posthog_host="https://eu.i.posthog.com",
        )

        for expected in (
            "report_opened",
            "section_viewed",
            "exhibit_mode_changed",
            "methodology_opened",
            "evidence_link_followed",
            "report_completed",
            "print_requested",
            '"persistence":"memory"',
            '"autocapture":false',
            '"disable_session_recording":true',
        ):
            self.assertIn(expected, html)

        self.assertIn("https://eu.i.posthog.com", html)
        self.assertNotIn("array.js", html)
        self.assertNotIn("partner_id", html)
        self.assertNotIn("source_filename", html)
        config = re.search(r"window\.reportAnalytics=(.*?);", html)
        self.assertIsNotNone(config)
        self.assertNotIn("participant", config.group(1).lower())

    def test_embedded_exhibit_bundle_is_static_scoped_and_complete(self) -> None:
        from community_os.report_v3_renderer import V3ExhibitBundle, render_v3_exhibits

        bundle = render_v3_exhibits(self.report)

        self.assertIsInstance(bundle, V3ExhibitBundle)
        for expected in (
            "Attendance progression",
            "Application and participation funnel",
            'data-volume-funnel="journey"',
            "Track and submission state",
            "Builder signal intersections",
            "Track and project domain",
            "Cohort composition",
            "Artifact completeness",
            "Data readiness",
            'data-chart-key="journey"',
            'class="data-fallback"',
        ):
            self.assertIn(expected, bundle.html)
        self.assertEqual(bundle.html.count("<table"), 7)
        self.assertIn("#event-evidence", bundle.css)
        self.assertIn("#event-evidence .journey-bands", bundle.css)
        self.assertIn("@media(max-width:640px)", bundle.css)
        self.assertNotIn("min-height:280px", bundle.css)
        self.assertIn(
            "#event-evidence .inspector{display:grid;grid-template-columns:minmax(0,.7fr) minmax(0,.6fr) minmax(0,1.4fr)",
            bundle.css,
        )
        self.assertIn(
            "@media print{#event-evidence .event-evidence-grid{background:transparent}}",
            bundle.css,
        )
        self.assertNotIn("<script", bundle.html)
        self.assertNotIn("reportAnalytics", bundle.html + bundle.css)
        self.assertNotIn("talentBriefAnalytics", bundle.html + bundle.css)
        self.assertNotIn("Approved people showed up and shipped", bundle.html)
        self.assertNotIn("This example is synthetic", bundle.html)


if __name__ == "__main__":
    unittest.main()
