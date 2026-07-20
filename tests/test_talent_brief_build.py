"""Build-path tests for producing both briefs from one contract."""

from __future__ import annotations

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


class TalentBriefBuildTests(unittest.TestCase):
    def test_writes_both_audience_briefs_from_one_contract(self) -> None:
        from community_os.talent_briefs import build_talent_briefs

        repo = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory:
            outputs = build_talent_briefs(
                repo / "config/contracts/talent-intelligence-v1.synthetic.json",
                output_root=Path(directory),
                export_pdfs=False,
            )
            self.assertEqual(set(outputs), {"vc_html", "company_html"})
            self.assertIn("VC talent brief", outputs["vc_html"].read_text(encoding="utf-8"))
            self.assertIn("Company talent brief", outputs["company_html"].read_text(encoding="utf-8"))
            self.assertNotEqual(
                outputs["vc_html"].read_text(encoding="utf-8"),
                outputs["company_html"].read_text(encoding="utf-8"),
            )

    def test_writes_both_html_briefs_before_attempting_pdf_export(self) -> None:
        from community_os.talent_briefs import build_talent_briefs

        repo = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory:
            output_root = Path(directory)
            with patch(
                "community_os.talent_briefs.export_pdf",
                side_effect=RuntimeError("synthetic Chrome failure"),
            ):
                with self.assertRaisesRegex(RuntimeError, "synthetic Chrome failure"):
                    build_talent_briefs(
                        repo / "config/contracts/talent-intelligence-v1.synthetic.json",
                        output_root=output_root,
                        export_pdfs=True,
                    )

            self.assertTrue((output_root / "vc-brief.synthetic.html").is_file())
            self.assertTrue((output_root / "company-brief.synthetic.html").is_file())


if __name__ == "__main__":
    unittest.main()
