from __future__ import annotations

from datetime import UTC, datetime, timedelta
import hashlib
import json
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import patch


NOW = datetime(2026, 7, 13, 16, 30, tzinfo=UTC)
POSTHOG_PROJECT_ID = 73155
POSTHOG_PUBLIC_KEY = "phc_public_123"
POSTHOG_PROJECT_RESPONSE = {
    "id": POSTHOG_PROJECT_ID,
    "api_token": POSTHOG_PUBLIC_KEY,
    "anonymize_ips": True,
    "name": "Partner report",
}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def canonical_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8"),
    ).hexdigest()


def posthog_responses() -> tuple[dict[str, object], ...]:
    return (POSTHOG_PROJECT_RESPONSE,)


def posthog_project_response_sha256() -> str:
    return canonical_sha256({
        "anonymize_ips": True,
        "project_id": POSTHOG_PROJECT_ID,
        "public_key_sha256": hashlib.sha256(
            POSTHOG_PUBLIC_KEY.encode("ascii"),
        ).hexdigest(),
    })


class PostHogProjectPrivacyVerificationTests(unittest.TestCase):
    def test_accepts_project_scoped_key_without_organization_access(self) -> None:
        from community_os.postpublication_analytics import (
            verify_posthog_project_privacy,
        )

        def project_only_get(*, path: str, personal_api_key: str):
            self.assertEqual(path, f"/api/projects/{POSTHOG_PROJECT_ID}/")
            self.assertEqual(personal_api_key, "phx_" + "project_scoped_key")
            return POSTHOG_PROJECT_RESPONSE

        with patch(
            "community_os.postpublication_analytics._posthog_json_get",
            side_effect=project_only_get,
        ):
            verification = verify_posthog_project_privacy(
                personal_api_key="phx_" + "project_scoped_key",
                project_id=POSTHOG_PROJECT_ID,
                public_key=POSTHOG_PUBLIC_KEY,
                now=NOW,
            )

        self.assertTrue(verification.anonymize_ips)
        self.assertEqual(verification.project_id, POSTHOG_PROJECT_ID)

    def test_verifies_ip_anonymization_and_binds_the_public_project_key(self) -> None:
        from community_os.postpublication_analytics import (
            verify_posthog_project_privacy,
        )

        responses = ({
            "id": 73155,
            "api_token": "phc_public_123",
            "anonymize_ips": True,
            "name": "Partner report",
        },)
        with patch(
            "community_os.postpublication_analytics._posthog_json_get",
            side_effect=responses,
        ) as request_json:
            verification = verify_posthog_project_privacy(
                personal_api_key="phx_" + "private_operator_key",
                project_id=73155,
                public_key="phc_public_123",
                now=NOW,
            )

        self.assertTrue(verification.anonymize_ips)
        self.assertEqual(verification.project_id, 73155)
        self.assertEqual(
            verification.public_key_sha256,
            hashlib.sha256(b"phc_public_123").hexdigest(),
        )
        self.assertRegex(verification.project_response_sha256, r"^[a-f0-9]{64}$")
        self.assertRegex(verification.sha256, r"^[a-f0-9]{64}$")
        self.assertNotIn(
            "phx_" + "private_operator_key",
            json.dumps(verification.as_dict(), sort_keys=True),
        )
        self.assertEqual(request_json.call_count, 1)

    def test_verification_fails_closed_on_project_or_privacy_mismatch(self) -> None:
        from community_os.postpublication_analytics import (
            verify_posthog_project_privacy,
        )

        invalid_projects = (
            {"id": 73155, "api_token": "phc_public_123", "anonymize_ips": False},
            {"id": 73155, "api_token": "phc_other_123", "anonymize_ips": True},
            {"id": 99999, "api_token": "phc_public_123", "anonymize_ips": True},
        )
        for project in invalid_projects:
            with self.subTest(project=project), patch(
                "community_os.postpublication_analytics._posthog_json_get",
                side_effect=(project,),
            ), self.assertRaises((PermissionError, ValueError)):
                verify_posthog_project_privacy(
                    personal_api_key="phx_" + "private_operator_key",
                    project_id=73155,
                    public_key="phc_public_123",
                    now=NOW,
                )

        with patch(
            "community_os.postpublication_analytics._posthog_json_get",
            side_effect=PermissionError(
                "PostHog personal API key requires project:read for this project",
            ),
        ), self.assertRaisesRegex(PermissionError, "project:read"):
            verify_posthog_project_privacy(
                personal_api_key="phx_" + "private_operator_key",
                project_id=73155,
                public_key="phc_public_123",
                now=NOW,
            )


class PostPublicationAnalyticsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        self.local_report = self.root / "public" / "talent-brief.real.html"
        self.local_report.parent.mkdir()
        self.local_report.write_text("<html><body>aggregate report</body></html>", encoding="utf-8")
        self.deployed_report = self.root / "downloaded-deployment.html"
        self.deployed_report.write_bytes(self.local_report.read_bytes())
        report_hash = sha256(self.local_report)
        self.manifest = self.local_report.parent / "publication-manifest.json"
        self.manifest.write_text(
            json.dumps({
                "analytics_enabled": False,
                "artifact_hashes": {"talent-brief.real.html": report_hash},
                "manifest_version": "public-partner-release-v1",
                "privacy_state": "aggregate_only",
                "release_state": "Safe to publish",
            }, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        self.receipt = {
            "receipt_version": "partner-publication-receipt-v1",
            "publication_state": "published",
            "privacy_state": "aggregate_only",
            "report_sha256": report_hash,
            "publication_manifest_sha256": sha256(self.manifest),
            "published_at": (NOW - timedelta(minutes=10)).isoformat(),
        }

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def privacy_verification(self, **changes: object):
        from community_os.postpublication_analytics import (
            PostHogPrivacyVerification,
        )

        values = {
            "receipt_version": "posthog-project-privacy-v1",
            "api_origin": "https://eu.posthog.com",
            "ingestion_origin": "https://eu.i.posthog.com",
            "project_id": POSTHOG_PROJECT_ID,
            "public_key_sha256": hashlib.sha256(
                POSTHOG_PUBLIC_KEY.encode("ascii"),
            ).hexdigest(),
            "anonymize_ips": True,
            "verified_at": NOW,
            "project_response_sha256": posthog_project_response_sha256(),
        }
        values.update(changes)
        return PostHogPrivacyVerification(**values)

    def approval(self, **changes: object):
        from community_os.postpublication_analytics import AnalyticsActivationApproval

        values = {
            "approval_code": "approval_7f4ab218",
            "actor_code": "actor_23b1c7e9",
            "scope": "privacy_limited_posthog",
            "report_sha256": self.receipt["report_sha256"],
            "publication_manifest_sha256": self.receipt["publication_manifest_sha256"],
            "posthog_privacy_receipt_sha256": self.privacy_verification().sha256,
            "approved_at": NOW - timedelta(minutes=2),
            "expires_at": NOW + timedelta(hours=1),
        }
        values.update(changes)
        return AnalyticsActivationApproval(**values)

    def activate(self, **changes: object):
        from community_os.postpublication_analytics import activate_postpublication_analytics

        values = {
            "publication_manifest_path": self.manifest,
            "local_public_report_path": self.local_report,
            "deployed_report_path": self.deployed_report,
            "publication_receipt": self.receipt,
            "approval": self.approval(),
            "public_key": POSTHOG_PUBLIC_KEY,
            "posthog_host": "https://eu.i.posthog.com",
            "personal_api_key": "phx_" + "private_operator_key",
            "posthog_project_id": POSTHOG_PROJECT_ID,
            "now": NOW,
            "artifact_path": self.root / "protected" / "analytics-activation.json",
            "posthog_privacy_artifact_path": (
                self.root / "protected" / "posthog-project-privacy.json"
            ),
        }
        values.update(changes)
        with patch(
            "community_os.postpublication_analytics._posthog_json_get",
            side_effect=posthog_responses(),
        ):
            return activate_postpublication_analytics(**values)

    def test_valid_activation_returns_and_writes_privacy_limited_offline_artifact(self) -> None:
        with patch.object(socket, "create_connection", side_effect=AssertionError("network forbidden")):
            artifact = self.activate()

        stored = json.loads((self.root / "protected" / "analytics-activation.json").read_text())
        self.assertEqual(stored, artifact)
        self.assertEqual(artifact["artifact_version"], "postpublication-analytics-v1")
        self.assertEqual(artifact["activation_receipt"]["publication_state"], "published")
        self.assertEqual(artifact["activation_receipt"]["actor_code"], "actor_23b1c7e9")
        self.assertEqual(artifact["activation_receipt"]["report_sha256"], sha256(self.local_report))
        self.assertEqual(artifact["analytics_config"], {
            "api_host": "https://eu.i.posthog.com",
            "autocapture": False,
            "capture_pageleave": False,
            "capture_pageview": False,
            "disable_session_recording": True,
            "disable_surveys": True,
            "geoip_enrichment_disabled": True,
            "identity_mode": "ephemeral_per_page_load",
            "persistence": "memory_only",
            "person_profile_processing": False,
            "transport": "direct_capture",
        })
        self.assertEqual(
            artifact["event_policy"],
            {
                "allowed_events": [
                    "cohort_selected", "metric_selected", "overlap_region_selected",
                    "pdf_downloaded", "report_opened",
                ],
                "allowed_properties": [
                    "cohort_key", "metric_key", "overlap_region", "report_version",
                ],
                "forbidden_dimensions": [
                    "email", "evidence_url", "github", "linkedin", "name",
                    "participant_id", "person_id", "profile_url", "stable_identifier",
                ],
            },
        )
        serialized = json.dumps(artifact, sort_keys=True)
        self.assertNotIn(str(self.root), serialized)
        self.assertNotIn("phc_public_123", serialized)
        self.assertNotIn("@", serialized)

    def test_requires_published_aggregate_only_receipt_and_safe_manifest(self) -> None:
        for field, invalid in (
            ("publication_state", "staged"),
            ("privacy_state", "person_level"),
            ("receipt_version", "unknown"),
        ):
            receipt = {**self.receipt, field: invalid}
            with self.subTest(field=field), self.assertRaises((PermissionError, ValueError)):
                self.activate(publication_receipt=receipt)

        manifest_payload = json.loads(self.manifest.read_text())
        manifest_payload["release_state"] = "Needs review"
        self.manifest.write_text(json.dumps(manifest_payload), encoding="utf-8")
        with self.assertRaisesRegex(PermissionError, "release state"):
            self.activate()

    def test_all_hashes_and_the_explicit_approval_must_match_and_be_current(self) -> None:
        cases = (
            {"deployed_report_path": self._different_file("deployed")},
            {"local_public_report_path": self._different_file("local")},
            {"publication_receipt": {**self.receipt, "report_sha256": "0" * 64}},
            {"approval": self.approval(report_sha256="0" * 64)},
            {"approval": self.approval(publication_manifest_sha256="0" * 64)},
            {"approval": self.approval(scope="general_analytics")},
            {"approval": self.approval(expires_at=NOW - timedelta(seconds=1))},
            {"approval": None},
        )
        for index, arguments in enumerate(cases):
            with self.subTest(index=index), self.assertRaises((PermissionError, ValueError, TypeError)):
                self.activate(**arguments)

    def test_public_key_and_https_host_are_strictly_allowlisted(self) -> None:
        for key in (None, "", "secret_private", "phc_x"):
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.activate(public_key=key)
        for host in (
            "http://eu.i.posthog.com",
            "https://evil.example",
            "https://eu.i.posthog.com.evil.example",
            "https://user@eu.i.posthog.com",
            "https://eu.i.posthog.com/capture",
        ):
            with self.subTest(host=host), self.assertRaises(ValueError):
                self.activate(posthog_host=host)

    def test_approval_audit_codes_cannot_contain_direct_identifiers_or_paths(self) -> None:
        for field, value in (
            ("actor_code", "person@example.org"),
            ("actor_code", "/Users/person"),
            ("approval_code", "Jane Smith"),
        ):
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.approval(**{field: value})

    def _different_file(self, name: str) -> Path:
        path = self.root / name
        path.write_text("different", encoding="utf-8")
        return path


class AnalyticsPublicationBundleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        self.source = self.root / "public-staging"
        self.source.mkdir()
        self.index = self.source / "index.html"
        self.index.write_text(
            '<!doctype html><html><head><meta charset="utf-8">'
            '<style>body{color:#00002c}</style></head><body>'
            '<button data-cohort-select="all">All applicants</button>'
            '<button data-dashboard-metric-select="technical_depth">Depth</button>'
            '<button data-overlap-region="both">Both signals</button>'
            '<div class="pdf-actions"><a href="partner-talent-brief.pdf" download>'
            'Download PDF</a></div>'
            '<script id="partner-dashboard-state" type="application/json">'
            '{"cohorts":[]}</script><script>'
            'document.documentElement.classList.add("js")'
            '</script></body></html>',
            encoding="utf-8",
        )
        self.pdf = self.source / "partner-talent-brief.pdf"
        self.pdf.write_bytes(b"%PDF-1.4\nfixture\n%%EOF")
        self.manifest_path = self.source / "publication-manifest.json"
        self.source_manifest = {
            "analytics_enabled": False,
            "artifact_hashes": {
                "index.html": sha256(self.index),
                "partner-talent-brief.pdf": sha256(self.pdf),
            },
            "artifact_set_sha256": "a" * 64,
            "entrypoint": "index.html",
            "manifest_version": "partner-static-bundle-v1",
            "pdf": "partner-talent-brief.pdf",
            "privacy_state": "aggregate_only",
            "public_transform_version": "neutral-public-artifact-names-v1",
            "release_state": "Safe to publish",
        }
        self.manifest_path.write_text(
            json.dumps(self.source_manifest, sort_keys=True, separators=(",", ":"))
            + "\n",
            encoding="utf-8",
        )
        self.destination = self.root / "deployment-staging"

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def privacy_verification(self, **changes: object):
        from community_os.postpublication_analytics import (
            PostHogPrivacyVerification,
        )

        values = {
            "receipt_version": "posthog-project-privacy-v1",
            "api_origin": "https://eu.posthog.com",
            "ingestion_origin": "https://eu.i.posthog.com",
            "project_id": POSTHOG_PROJECT_ID,
            "public_key_sha256": hashlib.sha256(
                POSTHOG_PUBLIC_KEY.encode("ascii"),
            ).hexdigest(),
            "anonymize_ips": True,
            "verified_at": NOW,
            "project_response_sha256": posthog_project_response_sha256(),
        }
        values.update(changes)
        return PostHogPrivacyVerification(**values)

    def approval(self, **changes: object):
        from community_os.postpublication_analytics import AnalyticsActivationApproval

        values = {
            "approval_code": "approval_7f4ab218",
            "actor_code": "actor_23b1c7e9",
            "scope": "privacy_limited_posthog",
            "report_sha256": sha256(self.index),
            "publication_manifest_sha256": sha256(self.manifest_path),
            "posthog_privacy_receipt_sha256": self.privacy_verification().sha256,
            "approved_at": NOW - timedelta(minutes=2),
            "expires_at": NOW + timedelta(hours=1),
        }
        values.update(changes)
        return AnalyticsActivationApproval(**values)

    def prepare(self, **changes: object):
        from community_os.postpublication_analytics import (
            prepare_analytics_publication_bundle,
        )

        values = {
            "source_directory": self.source,
            "destination": self.destination,
            "approval": self.approval(),
            "public_key": POSTHOG_PUBLIC_KEY,
            "posthog_host": "https://eu.i.posthog.com",
            "personal_api_key": "phx_" + "private_operator_key",
            "posthog_project_id": POSTHOG_PROJECT_ID,
            "now": NOW,
            "artifact_path": self.root / "protected" / "analytics-publication.json",
            "posthog_privacy_artifact_path": (
                self.root / "protected" / "posthog-project-privacy.json"
            ),
        }
        values.update(changes)
        with patch(
            "community_os.postpublication_analytics._posthog_json_get",
            side_effect=posthog_responses(),
        ):
            return prepare_analytics_publication_bundle(**values)

    def test_prepares_complete_hash_bound_analytics_bundle_without_network(self) -> None:
        with patch.object(
            socket, "create_connection", side_effect=AssertionError("network forbidden"),
        ):
            manifest = self.prepare()

        self.assertEqual(
            {path.name for path in self.destination.iterdir()},
            {
                "vercel.json", "index.html", "partner-talent-brief.pdf",
                "publication-manifest.json",
            },
        )
        self.assertTrue(manifest["analytics_enabled"])
        self.assertEqual(manifest["analytics_policy_version"], "posthog-minimal-v3")
        self.assertEqual(manifest["manifest_version"], "partner-static-bundle-v2")
        self.assertEqual(
            manifest["posthog_privacy_receipt_sha256"],
            self.privacy_verification().sha256,
        )
        self.assertEqual(
            manifest["source_manifest_sha256"], sha256(self.manifest_path),
        )
        for name in ("vercel.json", "index.html", "partner-talent-brief.pdf"):
            self.assertEqual(
                manifest["artifact_hashes"][name],
                sha256(self.destination / name),
            )
        self.assertEqual(
            json.loads((self.destination / "publication-manifest.json").read_text()),
            manifest,
        )

    def test_caller_forged_receipt_cannot_prepare_a_bundle_offline(self) -> None:
        from community_os.postpublication_analytics import (
            prepare_analytics_publication_bundle,
        )

        with patch.object(
            socket,
            "create_connection",
            side_effect=AssertionError("network forbidden"),
        ), self.assertRaises((AssertionError, PermissionError, TypeError)):
            prepare_analytics_publication_bundle(
                source_directory=self.source,
                destination=self.destination,
                approval=self.approval(),
                public_key="phc_public_123",
                posthog_host="https://eu.i.posthog.com",
                posthog_privacy_verification=self.privacy_verification(),
                now=NOW,
            )

    def test_capture_contract_is_cookieless_ephemeral_and_aggregate_only(self) -> None:
        self.prepare()

        html = (self.destination / "index.html").read_text(encoding="utf-8")
        for event in (
            "report_opened", "pdf_downloaded", "cohort_selected",
            "metric_selected", "overlap_region_selected",
        ):
            self.assertIn(event, html)
        for property_name in (
            "cohort_key", "metric_key", "overlap_region", "report_version",
        ):
            self.assertIn(property_name, html)
        self.assertNotIn("lens_selected", html)
        self.assertNotIn("lens_key", html)
        self.assertIn("crypto.randomUUID", html)
        self.assertNotIn("Math.random", html)
        self.assertIn("$process_person_profile:false", html)
        self.assertIn("$geoip_disable:true", html)
        self.assertNotIn("array.js", html)
        self.assertNotIn("document.cookie", html)
        self.assertNotIn("localStorage", html)
        self.assertNotIn("sessionStorage", html)
        self.assertNotIn("document.referrer", html)
        self.assertNotIn("location.href", html)
        self.assertNotIn("session_record", html)
        self.assertNotIn("sendBeacon", html)
        self.assertIn("credentials:'omit'", html)
        self.assertIn("referrerPolicy:'no-referrer'", html)
        self.assertIn("document.addEventListener('click'", html)
        self.assertIn("target.closest('[data-dashboard-metric-select]')", html)
        self.assertNotIn(
            "document.querySelectorAll('[data-dashboard-metric-select]').forEach",
            html,
        )
        self.assertIn('<meta name="referrer" content="no-referrer">', html)
        self.assertIn(
            "No participant data, names, emails, session replay, or stable viewer profiles",
            html,
        )
        artifact = json.loads(
            (self.root / "protected" / "analytics-publication.json").read_text(),
        )
        self.assertTrue(
            artifact["analytics_policy"]["ip_capture_disabled_confirmed"],
        )
        self.assertTrue(
            artifact["analytics_policy"]["geoip_enrichment_disabled"],
        )
        self.assertEqual(
            artifact["analytics_policy"]["posthog_privacy_receipt_sha256"],
            self.privacy_verification().sha256,
        )
        serialized = json.dumps(artifact, sort_keys=True).casefold()
        for forbidden in (
            "email", "github", "linkedin", "participant_id", "person_id",
            "profile_url", "referrer", "url",
        ):
            self.assertNotIn(f'"{forbidden}"', serialized)

    def test_csp_hashes_scripts_and_never_allows_inline_script_execution(self) -> None:
        self.prepare()

        config_text = (self.destination / "vercel.json").read_text(encoding="utf-8")
        config = json.loads(config_text)
        html = (self.destination / "index.html").read_text(encoding="utf-8")
        self.assertEqual(config["$schema"], "https://openapi.vercel.sh/vercel.json")
        self.assertEqual(config["framework"], None)
        self.assertEqual(config["headers"][0]["source"], "/(.*)")
        headers = {
            item["key"]: item["value"]
            for item in config["headers"][0]["headers"]
        }
        self.assertIn("script-src 'sha256-", headers["Content-Security-Policy"])
        self.assertNotIn("script-src 'unsafe-inline'", headers["Content-Security-Policy"])
        self.assertIn(
            "connect-src https://eu.i.posthog.com",
            headers["Content-Security-Policy"],
        )
        self.assertEqual(headers["X-Robots-Tag"], "noindex, nofollow, noarchive")
        self.assertIn('http-equiv="Content-Security-Policy"', html)
        self.assertLess(
            html.index('http-equiv="Content-Security-Policy"'),
            html.index("<style>"),
        )
        self.assertLess(
            html.index('http-equiv="Content-Security-Policy"'),
            html.index("<script"),
        )
        self.assertNotIn("unsafe-eval", config_text + html)

    def test_preparation_fails_closed_on_hash_scope_or_host_drift(self) -> None:
        cases = (
            {"approval": self.approval(report_sha256="0" * 64)},
            {"approval": self.approval(publication_manifest_sha256="0" * 64)},
            {"approval": self.approval(scope="general_analytics")},
            {"approval": self.approval(expires_at=NOW - timedelta(seconds=1))},
            {
                "approval": self.approval(
                    posthog_privacy_receipt_sha256="0" * 64,
                ),
            },
            {"posthog_host": "https://evil.example"},
            {"posthog_project_id": POSTHOG_PROJECT_ID + 1},
        )
        for index, changes in enumerate(cases):
            with self.subTest(index=index):
                if self.destination.exists():
                    for path in self.destination.iterdir():
                        path.unlink()
                    self.destination.rmdir()
                with self.assertRaises((PermissionError, ValueError)):
                    self.prepare(**changes)
                self.assertFalse(self.destination.exists())

    def test_preparation_rejects_a_destination_that_contains_the_source(self) -> None:
        with self.assertRaisesRegex(ValueError, "destination must be separate"):
            self.prepare(destination=self.root)

        self.assertTrue(self.source.is_dir())
        self.assertTrue(self.index.is_file())


if __name__ == "__main__":
    unittest.main()
