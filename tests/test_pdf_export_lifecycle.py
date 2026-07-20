"""Regression coverage for Chrome writing a PDF but not exiting."""

from __future__ import annotations

from pathlib import Path
import os
import signal
import tempfile
import unittest
from unittest.mock import patch


class HangingProcess:
    pid = 4242

    def __init__(self, destination: Path):
        self.destination = destination
        self.terminated = False
        destination.write_bytes(b"%PDF-1.4\n" + b"x" * 2048 + b"\n%%EOF\n")

    def poll(self):
        return None

    def terminate(self):
        self.terminated = True

    def wait(self, timeout=None):
        return -15

    def kill(self):
        self.terminated = True

    def communicate(self, timeout=None):
        return ("", "")


class EarlyExitProcess:
    """Chrome's parent may exit before its renderer finishes the PDF."""

    pid = 4343
    returncode = 0

    def poll(self):
        return self.returncode

    def communicate(self, timeout=None):
        return ("", "")


class PdfExportLifecycleTests(unittest.TestCase):
    def test_uses_only_an_explicit_executable_override_when_configured(self) -> None:
        from community_os.pdf_export import find_chromium

        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / "chrome-for-testing"
            executable.write_text("fixture", encoding="utf-8")
            executable.chmod(0o700)
            with patch.dict(
                os.environ,
                {"COMMUNITY_OS_CHROMIUM_EXECUTABLE": str(executable)},
                clear=False,
            ):
                self.assertEqual(find_chromium(), str(executable.resolve()))

    def test_rejects_invalid_override_and_never_falls_back_to_native_chrome(self) -> None:
        from community_os.pdf_export import find_chromium

        with (
            patch.dict(
                os.environ,
                {"COMMUNITY_OS_CHROMIUM_EXECUTABLE": "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"},
                clear=False,
            ),
            patch("community_os.pdf_export.shutil.which", return_value=None),
        ):
            self.assertIsNone(find_chromium())

    def test_default_discovery_never_launches_google_chrome_for_testing(self) -> None:
        from community_os.pdf_export import find_chromium

        looked_up: list[str] = []

        def lookup(name: str):
            looked_up.append(name)
            return None

        with (
            patch.dict(os.environ, {}, clear=True),
            patch("community_os.pdf_export.shutil.which", side_effect=lookup),
        ):
            self.assertIsNone(find_chromium())

        self.assertIn("chrome-headless-shell", looked_up)
        self.assertNotIn("google-chrome-for-testing", looked_up)

    def test_rejects_metadata_rewrite_that_changes_pdf_byte_offsets(self) -> None:
        from community_os.pdf_export import _normalize_pdf_metadata

        with tempfile.TemporaryDirectory() as directory:
            pdf = Path(directory) / "report.pdf"
            pdf.write_bytes(
                b"%PDF-1.4\n/CreationDate (D:20260713091933Z)\n"
                b"/ModDate (D:20260713091933Z)\n%%EOF"
            )

            with self.assertRaisesRegex(RuntimeError, "byte length"):
                _normalize_pdf_metadata(pdf, "2026-07-13T12:00:00Z")

    def test_normalizes_chromium_dates_to_stable_generation_time(self) -> None:
        from community_os.pdf_export import _normalize_pdf_metadata

        with tempfile.TemporaryDirectory() as directory:
            pdf = Path(directory) / "report.pdf"
            pdf.write_bytes(
                b"%PDF-1.4\n/CreationDate (D:20260713091933+00'00')\n"
                b"/ModDate (D:20260713091933+00'00')\n%%EOF"
            )

            _normalize_pdf_metadata(pdf, "2026-07-13T12:00:00Z")

            payload = pdf.read_bytes()
            self.assertEqual(payload.count(b"D:20260713120000+00'00'"), 2)
            self.assertNotIn(b"20260713091933", payload)

    def test_accepts_valid_stable_pdf_and_terminates_hanging_chrome(self) -> None:
        from community_os.pdf_export import export_pdf

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            html = root / "report.html"
            pdf = root / "report.pdf"
            html.write_text("<!doctype html><title>Report</title>", encoding="utf-8")
            holder = {}
            def start_process(*args, **kwargs):
                holder["process"] = HangingProcess(pdf)
                return holder["process"]
            with (
                patch("community_os.pdf_export.find_chromium", return_value="/fixture/chromium"),
                patch("community_os.pdf_export.subprocess.Popen", side_effect=start_process),
                patch("community_os.pdf_export.subprocess.run", side_effect=AssertionError("expected Popen")),
                patch("community_os.pdf_export.os.killpg") as kill_group,
            ):
                result = export_pdf(html, pdf)
            self.assertEqual(result, pdf.resolve())
            kill_group.assert_called_once_with(4242, signal.SIGTERM)
            self.assertTrue(pdf.read_bytes().startswith(b"%PDF-"))

    def test_waits_for_complete_pdf_after_clean_parent_exit(self) -> None:
        from community_os.pdf_export import export_pdf

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            html = root / "report.html"
            pdf = root / "report.pdf"
            html.write_text("<!doctype html><title>Report</title>", encoding="utf-8")

            def finish_renderer(_seconds):
                pdf.write_bytes(b"%PDF-1.4\n" + b"x" * 2048 + b"\n%%EOF\n")

            with (
                patch("community_os.pdf_export.find_chromium", return_value="/fixture/chromium"),
                patch("community_os.pdf_export.subprocess.Popen", return_value=EarlyExitProcess()),
                patch("community_os.pdf_export.time.sleep", side_effect=finish_renderer),
                patch("community_os.pdf_export.os.killpg") as kill_group,
            ):
                result = export_pdf(html, pdf)
            self.assertEqual(result, pdf.resolve())
            kill_group.assert_called_once_with(4343, signal.SIGTERM)
            self.assertTrue(pdf.read_bytes().rstrip().endswith(b"%%EOF"))

    def test_completed_renderer_tolerates_inaccessible_expired_process_group(self) -> None:
        from community_os.pdf_export import export_pdf

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            html = root / "report.html"
            pdf = root / "report.pdf"
            html.write_text("<!doctype html><title>Report</title>", encoding="utf-8")

            def finish_before_return(*_args, **_kwargs):
                pdf.write_bytes(b"%PDF-1.4\n" + b"x" * 2048 + b"\n%%EOF\n")
                return EarlyExitProcess()

            with (
                patch("community_os.pdf_export.find_chromium", return_value="/fixture/chromium"),
                patch("community_os.pdf_export.subprocess.Popen", side_effect=finish_before_return),
                patch(
                    "community_os.pdf_export.os.killpg",
                    side_effect=PermissionError("expired process group is inaccessible"),
                ),
            ):
                result = export_pdf(html, pdf)

            self.assertEqual(result, pdf.resolve())
            self.assertTrue(pdf.read_bytes().rstrip().endswith(b"%%EOF"))


if __name__ == "__main__":
    unittest.main()
