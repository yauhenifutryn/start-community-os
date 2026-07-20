import unittest
from pathlib import Path


class OwnedEvidenceReportTests(unittest.TestCase):
    def test_partner_outcomes_are_not_published(self) -> None:
        from community_os.report import load_report_profile
        from community_os.render import render_report

        root = Path(__file__).resolve().parents[1]
        profile = load_report_profile(
            root / "config/demo/talent-data-room.synthetic.json",
            event_key="synthetic-event",
            event_name="Synthetic Event",
            event_date="2026-07-11",
            partner_key="partner-preview",
            generated_at="2026-07-12",
        )

        html = render_report(profile)

        for forbidden in (
            "Partner outcomes",
            "data-outcome-view",
            "data-outcome-mode",
            "outcome_mode_changed",
            "Consented introductions",
            "Hires or investments",
        ):
            self.assertNotIn(forbidden, html)


if __name__ == "__main__":
    unittest.main()
