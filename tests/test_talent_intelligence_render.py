"""Behavioral contract for the VC and company talent-intelligence briefs."""

from __future__ import annotations

from pathlib import Path
import re
import unittest


class TalentIntelligenceRenderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        from community_os.talent_intelligence_contract import load_talent_intelligence_contract

        cls.repo = Path(__file__).resolve().parents[1]
        cls.report = load_talent_intelligence_contract(
            cls.repo / "config/contracts/talent-intelligence-v1.synthetic.json"
        )

    def test_requires_an_explicit_supported_audience(self) -> None:
        from community_os.render import render_report

        with self.assertRaisesRegex(ValueError, "audience is required"):
            render_report(self.report)
        with self.assertRaisesRegex(ValueError, "audience must be vc or company"):
            render_report(self.report, audience="sponsor")

    def test_vc_brief_leads_with_investor_decision_evidence(self) -> None:
        from community_os.render import render_report

        html = render_report(self.report, audience="vc")
        for expected in (
            "VC talent brief",
            "Founder access, backed by evidence",
            "48 founders or co-founders",
            "Senior technical-builder intersection pending or unknown",
            "Founder and operator composition",
            "Senior technical-builder density",
            "Employer and startup pedigree",
            "Investable domains",
            "Shipping evidence",
        ):
            self.assertIn(expected, html)
        self.assertLess(
            html.index("Founder and operator composition"),
            html.index("Employer and startup pedigree"),
        )

    def test_company_brief_leads_with_hiring_decision_evidence(self) -> None:
        from community_os.render import render_report

        html = render_report(self.report, audience="company")
        for expected in (
            "Company talent brief",
            "Experienced technical talent, mapped to hiring decisions",
            "56 senior applicants and 24 lead, staff, principal, or executive applicants",
            "118 applicants with engineering evidence",
            "Seniority and functional roles",
            "Capabilities you can recruit",
            "Employer pedigree",
            "Demonstrated builder evidence",
            "Domain experience",
        ):
            self.assertIn(expected, html)
        self.assertLess(
            html.index("Seniority and functional roles"),
            html.index("Demonstrated builder evidence"),
        )

    def test_both_reports_share_truthful_contract_evidence_and_static_fallbacks(self) -> None:
        from community_os.render import render_report

        for audience in ("vc", "company"):
            html = render_report(self.report, audience=audience)
            for expected in (
                "Illustrative synthetic data",
                "286 valid applicants",
                "Who applied, who entered, and what remains unknown",
                "Not accepted, reason unknown",
                "The current source does not prove capacity exclusion",
                "Evidence coverage",
                "Professional-profile enrichment",
                "Live enrichment remains off",
                "Named talent appendix remains disabled",
                "Methodology and privacy",
                "talent-intelligence-v1",
                "Below publication threshold",
                "<table",
                "@media print",
                "@media (prefers-reduced-motion:reduce)",
                "#methodology .readiness-grid li{padding:1.2mm 0}",
                "#methodology details.methodology p{margin:2mm 0;font-size:7.5pt;line-height:1.35}",
                'class="table-scroll"',
                ".table-scroll{max-width:100%;overflow-x:auto}",
                ".bars{break-inside:auto}",
                ".bar-row{padding:2mm 0;break-inside:avoid}",
                ".readiness-grid li{grid-template-columns:minmax(0,1fr) auto}",
                'data:image/svg+xml',
            ):
                self.assertIn(expected, html)
            self.assertNotIn('data-inspect=', html)
            self.assertNotIn('data-mode-value=', html)
            self.assertNotIn("Evidence cockpit", html)
            self.assertNotIn("datum_inspected", html)
            self.assertNotIn("<script src=", html)
            self.assertNotIn('src="http', html)
            self.assertNotIn('href="http', html)
            self.assertNotIn("Partner outcomes", html)
            self.assertNotIn("Generate appendix", html)
            self.assertNotIn('href="#appendix"', html)

    def test_applicant_funnel_and_selection_outcomes_encode_real_volume(self) -> None:
        from community_os.render import render_report

        html = render_report(self.report, audience="vc")

        self.assertIn('data-volume-funnel="cohort"', html)
        self.assertIn('aria-label="Volume-adjusted applicant funnel in people"', html)
        self.assertIn("Each square represents one applicant", html)
        self.assertIn('data-stage-key="valid_applicants"', html)
        self.assertIn('style="--stage-share:100.0%"', html)
        self.assertIn('style="--stage-share:28.0%"', html)
        self.assertEqual(html.count('class="cohort-dot'), 761)
        self.assertIn('data-outcome-split="selection"', html)
        self.assertIn('style="--outcome-share:28.0%"', html)
        self.assertIn('style="--outcome-share:58.0%"', html)
        self.assertIn('class="outcome-segment outcome-accepted"', html)
        self.assertIn('class="outcome-segment outcome-unknown"', html)
        self.assertIn("Selection outcome volume", html)
        self.assertIn(".stage-meter>i{display:block;width:var(--stage-share)", html)
        self.assertIn(".outcome-segment{display:block;width:var(--outcome-share)", html)
        self.assertIn("@media(max-width:560px)", html)
        self.assertIn(".stage-dots{width:100%}", html)
        self.assertNotIn("grid-template-columns:repeat(var(--funnel-columns),1fr)", html)
        self.assertNotIn("Participation paths", html)

    def test_mobile_tables_collapse_and_reopen_in_print(self) -> None:
        from community_os.render import render_report

        html = render_report(self.report, audience="vc")

        self.assertGreaterEqual(html.count('class="table-fallback"'), 9)
        self.assertIn("Open evidence table", html)
        self.assertIn("details.table-fallback>summary", html)
        self.assertIn(
            "details.table-fallback:not([open])>.table-scroll{display:block!important}",
            html,
        )
        self.assertNotIn(".outcome-tone-1,.outcome-tone-1::before", html)

    def test_comparison_cards_include_denominator_scaled_marks(self) -> None:
        from community_os.render import render_report

        html = render_report(self.report, audience="vc")

        self.assertIn('class="intersection-meter"', html)
        self.assertIn('style="--intersection-share:7.0%"', html)
        self.assertIn(".intersection-meter i{display:block;width:var(--intersection-share)", html)

    def test_analytics_is_inline_allowlisted_and_excludes_evidence_values(self) -> None:
        from community_os.render import render_report

        html = render_report(
            self.report,
            audience="vc",
            posthog_key="phc_public",
            posthog_host="https://eu.i.posthog.com",
        )
        for expected in (
            "report_opened",
            "section_viewed",
            "methodology_opened",
            "report_completed",
            "print_requested",
            '"persistence":"memory"',
            '"autocapture":false',
            '"disable_session_recording":true',
        ):
            self.assertIn(expected, html)
        self.assertNotIn("array.js", html)
        self.assertNotIn("participant", re.search(r"window\.talentBriefAnalytics=(.*?);", html).group(1).lower())
        self.assertNotIn("count", re.search(r"window\.talentBriefAnalytics=(.*?);", html).group(1).lower())
        self.assertNotIn("source_filename", html)
        self.assertNotIn("viewer", html)


if __name__ == "__main__":
    unittest.main()
