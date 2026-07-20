from __future__ import annotations

from datetime import UTC, datetime, timedelta
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


NOW = datetime(2026, 7, 13, 12, tzinfo=UTC)


def complete_artifacts(root: Path) -> tuple[Path, Path, Path, Path]:
    html = root / "talent-brief.real.html"
    pdf = root / "talent-brief.real.pdf"
    v1 = root / "talent-intelligence-v1.real.aggregate.json"
    v3 = root / "talent-report-v3.real.aggregate.json"
    html.write_text(
        '<!doctype html><a href="talent-brief.real.pdf">View PDF</a>'
        '<a href="talent-brief.real.pdf" download>Download PDF</a>',
        encoding="utf-8",
    )
    pdf.write_bytes(b"%PDF-1.4\n%%EOF")
    v1.write_text("{}", encoding="utf-8")
    v3.write_text("{}", encoding="utf-8")
    return html, pdf, v1, v3


def safe_evidence(*artifacts: Path):
    from community_os.publication import artifact_set_sha256
    from community_os.privacy_operations import (
        DataAsset, DataClass, ExclusionRegistry, PrivacyParityRecord,
        PublicationApproval, ReleaseEvidence, ReviewRecord, RightsState, UseApproval,
    )
    digest = artifact_set_sha256(artifacts)
    registry = ExclusionRegistry()
    registry.record(RightsState(
        pseudonym="psn_release", notice_version="notice_v2", notice_sent_at=NOW - timedelta(days=1),
        objection_status="none", exclusion_status="included", suppression_status="not_requested",
        deletion_status="not_requested", reconciled=True,
    ))
    asset = DataAsset(
        asset_id="partner_report", version="release_v1", pseudonym="psn_release",
        source="partner_report", purpose="partner_publication",
        accountable_owner="privacy_lead", retention_deadline=NOW + timedelta(days=30),
        allowed_uses=frozenset({"publish"}), data_class=DataClass.AGGREGATE,
        storage_scope="protected_release", resource_ref="public/talent-brief.real.html",
    )
    use = UseApproval(
        source="partner_report", purpose="partner_publication", use="publish",
        owner_code="privacy_lead", actor_code="release_owner",
        approved_at=NOW - timedelta(minutes=2), expires_at=NOW + timedelta(days=1),
    )
    members = frozenset({"psn_release"})
    return ReleaseEvidence(
        inventory=(asset,), registry=registry, approvals=(use,), cleanup_report=None,
        parity=PrivacyParityRecord(members, members, members, members),
        reviews=(ReviewRecord("release_review", True),),
        publication_approval=PublicationApproval(digest, "release_owner", NOW),
        report_hash=digest, report_generated_at=NOW - timedelta(minutes=1),
    )


class PublicationStagingTests(unittest.TestCase):
    def test_staging_emits_codex_sites_entrypoint_pdf_and_exact_byte_hash_manifest(self):
        from community_os.publication import stage_publication

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "release"
            root.mkdir()
            html, pdf, _v1, _v3 = complete_artifacts(root)
            destination = Path(directory) / "public"
            with patch("community_os.publication._pdf_text", return_value="safe PDF"):
                manifest = stage_publication(
                    root, destination,
                    allowlist=(html.name, pdf.name),
                    evidence=safe_evidence(html, pdf), now=NOW,
                )

            self.assertEqual(
                {path.name for path in destination.iterdir()},
                {"index.html", "partner-talent-brief.pdf", "publication-manifest.json"},
            )
            staged_html = (destination / "index.html").read_text(encoding="utf-8")
            self.assertIn('href="partner-talent-brief.pdf"', staged_html)
            self.assertNotIn("talent-brief.real.pdf", staged_html)
            self.assertEqual(
                (destination / "partner-talent-brief.pdf").read_bytes(), pdf.read_bytes(),
            )
            self.assertEqual(manifest["entrypoint"], "index.html")
            self.assertEqual(manifest["pdf"], "partner-talent-brief.pdf")
            self.assertEqual(
                manifest["public_transform_version"],
                "neutral-public-artifact-names-v1",
            )
            for name in ("index.html", "partner-talent-brief.pdf"):
                self.assertEqual(
                    manifest["artifact_hashes"][name],
                    hashlib.sha256((destination / name).read_bytes()).hexdigest(),
                )
            self.assertEqual(
                json.loads(
                    (destination / "publication-manifest.json").read_text(
                        encoding="utf-8",
                    )
                ),
                manifest,
            )

    def test_staging_requires_a_relative_pdf_action_that_resolves_from_index(self):
        from community_os.publication import stage_publication

        unsafe_links = (
            "<html><body>No PDF action</body></html>",
            '<a href="/talent-brief.real.pdf">Root-relative PDF</a>',
            '<base href="https://example.org/"><a href="talent-brief.real.pdf">PDF</a>',
        )
        for html_text in unsafe_links:
            with self.subTest(html_text=html_text), tempfile.TemporaryDirectory() as directory:
                root = Path(directory) / "release"
                root.mkdir()
                html, pdf, _v1, _v3 = complete_artifacts(root)
                html.write_text(html_text, encoding="utf-8")
                with (
                    patch("community_os.publication._pdf_text", return_value="safe PDF"),
                    self.assertRaisesRegex(ValueError, "relative PDF"),
                ):
                    stage_publication(
                        root, Path(directory) / "public",
                        allowlist=(html.name, pdf.name),
                        evidence=safe_evidence(html, pdf), now=NOW,
                    )

    def test_pdf_text_uses_content_stream_order_for_multicolumn_claim_parity(self):
        from community_os.publication import _pdf_text

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.pdf"
            path.write_bytes(b"%PDF-fixture")
            with patch(
                "community_os.publication.subprocess.run",
                return_value=SimpleNamespace(stdout="safe extracted text"),
            ) as runner:
                extracted = _pdf_text(path)

        self.assertIn("safe extracted text", extracted)
        self.assertEqual(
            runner.call_args.args[0],
            ["pdftotext", "-raw", str(path), "-"],
        )

    def test_staging_scans_and_hashes_copied_bytes_before_public_install(self):
        from community_os.publication import stage_publication

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "release"
            root.mkdir()
            html, pdf, v1, v3 = complete_artifacts(root)
            artifacts = (html, pdf)
            evidence = safe_evidence(*artifacts)
            destination = Path(directory) / "public"
            original_copy = shutil.copy2

            def swap_after_approval(source, target, *args, **kwargs):
                source_path = Path(source)
                if source_path.name == html.name:
                    source_path.write_text("person@example.org", encoding="utf-8")
                return original_copy(source, target, *args, **kwargs)

            with (
                patch("community_os.publication.shutil.copy2", side_effect=swap_after_approval),
                patch("community_os.publication._pdf_text", return_value="safe PDF"),
                self.assertRaisesRegex(ValueError, "forbidden personal"),
            ):
                stage_publication(
                    root, destination,
                    allowlist=tuple(path.name for path in artifacts),
                    evidence=evidence, now=NOW,
                )

            self.assertFalse((destination / html.name).exists())

    def test_publication_set_is_rolled_back_if_atomic_directory_install_fails(self):
        from community_os.publication import stage_publication

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "release"
            root.mkdir()
            artifacts = complete_artifacts(root)[:2]
            destination = Path(directory) / "public"
            destination.mkdir()
            old_files = {
                "index.html": b"old index.html",
                "partner-talent-brief.pdf": b"old partner-talent-brief.pdf",
            }
            old_files["publication-manifest.json"] = b'{"generation":"old"}\n'
            for name, body in old_files.items():
                (destination / name).write_bytes(body)
            original_replace = __import__("os").replace
            replace_calls = 0

            def fail_install(source, target):
                nonlocal replace_calls
                replace_calls += 1
                if replace_calls == 2:
                    raise OSError("injected publication install failure")
                return original_replace(source, target)

            with (
                patch("community_os.publication.os.replace", side_effect=fail_install),
                patch("community_os.publication._pdf_text", return_value="safe PDF"),
                self.assertRaisesRegex(OSError, "injected publication install failure"),
            ):
                stage_publication(
                    root, destination,
                    allowlist=tuple(path.name for path in artifacts),
                    evidence=safe_evidence(*artifacts), now=NOW,
                )

            self.assertEqual(
                {path.name: path.read_bytes() for path in destination.iterdir()},
                old_files,
            )

    def test_staging_requires_complete_html_and_pdf(self):
        from community_os.publication import stage_publication

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "release"
            root.mkdir()
            html = root / "talent-brief.real.html"
            html.write_text("safe aggregate", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "complete partner artifact set"):
                stage_publication(
                    root, Path(directory) / "public",
                    allowlist=(html.name,),
                    evidence=safe_evidence(html), now=NOW,
                )

    def test_only_explicit_public_artifacts_are_staged_and_private_files_are_rejected(self):
        from community_os.publication import stage_publication
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "release"; root.mkdir()
            html, pdf, v1, v3 = complete_artifacts(root)
            html.write_text(
                '<html><body>286 applicants '
                '<a href="talent-brief.real.pdf">View PDF</a></body></html>',
            )
            v1.write_text(json.dumps({"metadata": {"contract_version": "talent-intelligence-v1"}, "count": 286}))
            (root / "talent-brief.internal-qa.md").write_text("private")
            destination = Path(directory) / "public"
            with patch("community_os.publication._pdf_text", return_value="safe PDF"):
                result = stage_publication(
                    root, destination,
                    allowlist=tuple(path.name for path in (html, pdf)),
                    evidence=safe_evidence(html, pdf), now=NOW,
                )
            self.assertEqual(set(path.name for path in destination.iterdir()), {
                "publication-manifest.json", "index.html", "partner-talent-brief.pdf",
            })
            self.assertNotIn("internal-qa", json.dumps(result))
            self.assertFalse((destination / v1.name).exists())
            self.assertFalse((destination / v3.name).exists())

    def test_staging_fails_on_non_safe_state_pii_paths_or_unapproved_analytics(self):
        from community_os.publication import stage_publication
        from community_os.privacy_operations import ReleaseEvidence
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "release"; root.mkdir()
            html, pdf, v1, v3 = complete_artifacts(root)
            artifacts = (html, pdf)
            for content in ("person@example.org", "/Users/operator/private.csv", "linkedin.com/in/person"):
                html.write_text(content)
                with self.subTest(content=content), self.assertRaises(ValueError):
                    stage_publication(root, Path(directory) / "public", allowlist=tuple(path.name for path in artifacts), evidence=safe_evidence(*artifacts), now=NOW)
            html.write_text("safe aggregate")
            with self.assertRaises(PermissionError):
                stage_publication(root, Path(directory) / "public", allowlist=tuple(path.name for path in artifacts), evidence=ReleaseEvidence(**{**safe_evidence(*artifacts).__dict__, "publication_approval": None}), now=NOW)
            with self.assertRaises(PermissionError):
                stage_publication(root, Path(directory) / "public", allowlist=tuple(path.name for path in artifacts), evidence=safe_evidence(*artifacts), now=NOW, analytics_key="phc_public")

    def test_staging_rejects_stable_pseudonymous_identifiers(self):
        from community_os.publication import stage_publication

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "release"
            root.mkdir()
            html, pdf, v1, v3 = complete_artifacts(root)
            artifacts = (html, pdf)
            identifiers = (
                "pid:v1:" + "a" * 64,
                "pid:rotation_2026:" + "a" * 64,
                "psn_candidate_001",
                "colleague_" + "b" * 32,
                "class_" + "c" * 24,
                "person_" + "d" * 24,
                "identity_" + "e" * 16,
                "evidence:application:" + "f" * 64,
                "source:application:" + "0" * 24,
                "actor_23b1c7e9",
                "approval_7f4ab218",
                "x_pid:v1:" + "1" * 64,
                "pid:v1:" + "2" * 64 + "_x",
            )
            for identifier in identifiers:
                html.write_text(identifier, encoding="utf-8")
                with self.subTest(identifier=identifier), self.assertRaisesRegex(
                    ValueError, "forbidden personal",
                ):
                    stage_publication(
                        root, Path(directory) / "public",
                        allowlist=tuple(path.name for path in artifacts),
                        evidence=safe_evidence(*artifacts), now=NOW,
                    )

    def test_staging_rejects_coresignal_from_the_partner_artifacts(self):
        from community_os.publication import stage_publication

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "release"
            root.mkdir()
            html, pdf, _v1, _v3 = complete_artifacts(root)
            html.write_text(
                html.read_text(encoding="utf-8") + "<p>Coresignal career evidence</p>",
                encoding="utf-8",
            )
            artifacts = (html, pdf)
            with (
                patch("community_os.publication._pdf_text", return_value="safe PDF"),
                self.assertRaisesRegex(ValueError, "forbidden personal or protected"),
            ):
                stage_publication(
                    root, Path(directory) / "public",
                    allowlist=tuple(path.name for path in artifacts),
                    evidence=safe_evidence(*artifacts), now=NOW,
                )

    def test_staging_fails_closed_when_pdf_text_cannot_be_extracted_or_contains_pii(self):
        from community_os.publication import stage_publication
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "release"; root.mkdir()
            html, pdf, v1, v3 = complete_artifacts(root)
            pdf.write_bytes(b"%PDF-1.4\nperson@example.org linkedin.com/in/person\n%%EOF")
            with self.assertRaisesRegex(ValueError, "PDF"):
                stage_publication(
                    root, Path(directory) / "public",
                    allowlist=tuple(path.name for path in (html, pdf)),
                    evidence=safe_evidence(html, pdf), now=NOW,
                )


if __name__ == "__main__":
    unittest.main()
