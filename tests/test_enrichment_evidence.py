from __future__ import annotations

from datetime import UTC, datetime, timedelta
import json
import os
from pathlib import Path
import tempfile
import unittest

from community_os.enrichment.evidence_vault import ProtectedEvidenceVault


NOW = datetime(2026, 7, 14, 9, tzinfo=UTC)
SUBJECT = "pid:v1:" + "a" * 64
EVIDENCE = "evidence:public_page:" + "b" * 64


class ProtectedEvidenceVaultTests(unittest.TestCase):
    def test_capture_is_bounded_versioned_private_and_readable_only_by_opaque_reference(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "protected" / "raw-evidence"
            vault = ProtectedEvidenceVault(root, clock=lambda: NOW)

            vault.capture(
                source="public_pages", purpose="talent_classification",
                subject_ref=SUBJECT, evidence_ref=EVIDENCE,
                provider_version="applicant-public-page-v1", content_type="text/html",
                payload=b"<html>private evidence</html>", ttl=timedelta(hours=12),
            )

            self.assertEqual(os.stat(root).st_mode & 0o777, 0o700)
            files = list((root / "records").glob("*.json"))
            self.assertEqual(len(files), 1)
            self.assertEqual(os.stat(files[0]).st_mode & 0o777, 0o600)
            envelope = json.loads(files[0].read_text(encoding="utf-8"))
            self.assertEqual(envelope["record_version"], "protected-raw-evidence-v1")
            self.assertEqual(envelope["deletion_state"], "retained")
            self.assertEqual(envelope["source"], "public_pages")
            self.assertEqual(envelope["purpose"], "talent_classification")
            self.assertEqual(envelope["captured_at"], "2026-07-14T09:00:00Z")
            self.assertEqual(envelope["expires_at"], "2026-07-14T21:00:00Z")
            self.assertEqual(
                vault.read(EVIDENCE, source="public_pages", subject_ref=SUBJECT),
                b"<html>private evidence</html>",
            )

    def test_capture_rejects_unapproved_scope_excessive_ttl_and_changed_payload(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            vault = ProtectedEvidenceVault(Path(directory) / "protected" / "raw-evidence", clock=lambda: NOW)
            common = dict(
                source="public_pages", purpose="talent_classification",
                subject_ref=SUBJECT, evidence_ref=EVIDENCE,
                provider_version="applicant-public-page-v1", content_type="text/html",
            )
            with self.assertRaises(ValueError):
                vault.capture(**{**common, "purpose": "marketing"}, payload=b"x", ttl=timedelta(hours=1))
            with self.assertRaises(ValueError):
                vault.capture(**common, payload=b"x", ttl=timedelta(hours=25))
            vault.capture(**common, payload=b"first", ttl=timedelta(hours=1))
            with self.assertRaises(PermissionError):
                vault.capture(**common, payload=b"changed", ttl=timedelta(hours=1))

    def test_reviewed_projection_deletion_is_receipted_minimized_and_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            vault = ProtectedEvidenceVault(Path(directory) / "protected" / "raw-evidence", clock=lambda: NOW)
            vault.capture(
                source="public_pages", purpose="talent_classification",
                subject_ref=SUBJECT, evidence_ref=EVIDENCE,
                provider_version="applicant-public-page-v1", content_type="text/html",
                payload=b"private evidence marker", ttl=timedelta(hours=1),
            )

            receipts = vault.delete_all(
                reason="reviewed_projection", projection_sha256="c" * 64,
            )
            repeated = vault.delete_all(
                reason="reviewed_projection", projection_sha256="c" * 64,
            )

            self.assertEqual(len(receipts), 1)
            self.assertEqual(repeated, [])
            self.assertEqual(list((vault.root / "records").glob("*")), [])
            receipt_files = list((vault.root / "receipts").glob("*.json"))
            self.assertEqual(len(receipt_files), 1)
            receipt_text = receipt_files[0].read_text(encoding="utf-8")
            receipt = json.loads(receipt_text)
            self.assertEqual(receipt["deletion_state"], "deleted")
            self.assertEqual(receipt["reason"], "reviewed_projection")
            self.assertEqual(receipt["projection_sha256"], "c" * 64)
            self.assertNotIn("private evidence marker", receipt_text)
            self.assertNotIn(SUBJECT, receipt_text)
            self.assertNotIn(EVIDENCE, receipt_text)

    def test_expiry_deletes_raw_and_fails_closed(self) -> None:
        clock = [NOW]
        with tempfile.TemporaryDirectory() as directory:
            vault = ProtectedEvidenceVault(
                Path(directory) / "protected" / "raw-evidence", clock=lambda: clock[0],
            )
            vault.capture(
                source="github", purpose="talent_classification", subject_ref=SUBJECT,
                evidence_ref="evidence:github:" + "d" * 64,
                provider_version="github-public-profile-v1", content_type="application/json",
                payload=b'{"login":"private"}', ttl=timedelta(minutes=1),
            )
            clock[0] = NOW + timedelta(minutes=2)

            with self.assertRaises(PermissionError):
                vault.read(
                    "evidence:github:" + "d" * 64,
                    source="github", subject_ref=SUBJECT,
                )

            self.assertEqual(list((vault.root / "records").glob("*")), [])
            receipt = json.loads(next((vault.root / "receipts").glob("*.json")).read_text())
            self.assertEqual(receipt["reason"], "ttl_expired")

    def test_restart_completes_pending_deletion_and_malformed_raw_is_deleted_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "protected" / "raw-evidence"
            vault = ProtectedEvidenceVault(root, clock=lambda: NOW)
            vault.capture(
                source="github", purpose="talent_classification", subject_ref=SUBJECT,
                evidence_ref="evidence:github:" + "e" * 64,
                provider_version="github-public-profile-v1", content_type="application/json",
                payload=b'{"login":"private"}', ttl=timedelta(hours=1),
            )
            record = next(vault.records.glob("*.json"))
            envelope = json.loads(record.read_text())
            pending = {
                "asset_id": envelope["asset_id"], "captured_at": envelope["captured_at"],
                "deleted_at": None, "deletion_state": "pending",
                "expires_at": envelope["expires_at"],
                "payload_sha256": envelope["payload_sha256"],
                "projection_sha256": "f" * 64,
                "provider_version": envelope["provider_version"],
                "purpose": envelope["purpose"], "reason": "reviewed_projection",
                "receipt_version": vault.RECEIPT_VERSION, "source": envelope["source"],
            }
            vault._write(vault.receipts / record.name, pending)
            record.unlink()

            reopened = ProtectedEvidenceVault(root, clock=lambda: NOW + timedelta(minutes=1))
            recovered = json.loads(next(reopened.receipts.glob("*.json")).read_text())
            self.assertEqual(recovered["deletion_state"], "deleted")
            self.assertEqual(recovered["deleted_at"], "2026-07-14T09:01:00Z")

            malformed = reopened.records / ("a" * 64 + ".json")
            malformed.write_text("private malformed evidence", encoding="utf-8")
            malformed.chmod(0o600)
            receipts = reopened.delete_all(reason="stage_failed")
            self.assertEqual(len(receipts), 1)
            self.assertFalse(malformed.exists())
            self.assertNotIn(
                "private malformed evidence",
                json.dumps(receipts, sort_keys=True),
            )

    def test_source_scoped_failure_cleanup_preserves_other_provider_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            vault = ProtectedEvidenceVault(Path(directory) / "protected" / "raw-evidence", clock=lambda: NOW)
            for source, prefix in (("github", "github"), ("public_pages", "public_page")):
                vault.capture(
                    source=source, purpose="talent_classification", subject_ref=SUBJECT,
                    evidence_ref=f"evidence:{prefix}:" + ("a" if source == "github" else "b") * 64,
                    provider_version=f"{source}-v1", content_type="application/json",
                    payload=source.encode(), ttl=timedelta(hours=1),
                )

            deleted = vault.delete_source("github", reason="github_stage_failed")

            self.assertEqual(len(deleted), 1)
            self.assertEqual(len(list(vault.records.glob("*.json"))), 1)
            self.assertEqual(
                vault.read(
                    "evidence:public_page:" + "b" * 64,
                    source="public_pages", subject_ref=SUBJECT,
                ),
                b"public_pages",
            )

    def test_source_scoped_cleanup_deletes_unattributable_interrupted_raw_write(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            vault = ProtectedEvidenceVault(
                Path(directory) / "protected" / "raw-evidence",
                clock=lambda: NOW,
            )
            temporary = vault.records / ("a" * 64 + ".json.tmp")
            temporary.write_bytes(b"interrupted raw provider evidence")
            temporary.chmod(0o600)

            vault.delete_source(
                "public_pages",
                reason="authorization_revoked",
            )

            self.assertFalse(temporary.exists())

    def test_scheduled_purge_deletes_tampered_or_unreadable_raw_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            vault = ProtectedEvidenceVault(Path(directory) / "protected" / "raw-evidence", clock=lambda: NOW)
            evidence_ref = "evidence:github:" + "f" * 64
            vault.capture(
                source="github", purpose="talent_classification", subject_ref=SUBJECT,
                evidence_ref=evidence_ref, provider_version="github-public-profile-v1",
                content_type="application/json", payload=b'{"login":"private"}',
                ttl=timedelta(hours=1),
            )
            path = next(vault.records.glob("*.json"))
            envelope = json.loads(path.read_text())
            envelope["evidence_ref"] = "evidence:github:" + "0" * 64
            path.write_text(json.dumps(envelope), encoding="utf-8")
            path.chmod(0o600)

            receipts = vault.purge_expired()

            self.assertEqual(len(receipts), 1)
            self.assertEqual(receipts[0]["reason"], "invalid_envelope")
            self.assertEqual(list(vault.records.iterdir()), [])

    def test_tampered_deletion_receipt_blocks_vault_reopen(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "protected" / "raw-evidence"
            vault = ProtectedEvidenceVault(root, clock=lambda: NOW)
            vault.capture(
                source="github", purpose="talent_classification", subject_ref=SUBJECT,
                evidence_ref="evidence:github:" + "9" * 64,
                provider_version="github-public-profile-v1", content_type="application/json",
                payload=b'{"login":"private"}', ttl=timedelta(hours=1),
            )
            vault.delete_all(reason="reviewed_projection", projection_sha256="8" * 64)
            receipt_path = next(vault.receipts.glob("*.json"))
            receipt = json.loads(receipt_path.read_text())
            receipt["direct_identifier"] = "person@example.org"
            receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
            receipt_path.chmod(0o600)

            with self.assertRaisesRegex(PermissionError, "receipt is invalid"):
                ProtectedEvidenceVault(root, clock=lambda: NOW)

    def test_deletion_receipt_cannot_predate_capture(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "protected" / "raw-evidence"
            vault = ProtectedEvidenceVault(root, clock=lambda: NOW)
            vault.capture(
                source="github", purpose="talent_classification", subject_ref=SUBJECT,
                evidence_ref="evidence:github:" + "7" * 64,
                provider_version="github-public-profile-v1", content_type="application/json",
                payload=b'{"login":"private"}', ttl=timedelta(hours=1),
            )
            vault.delete_all(reason="reviewed_projection", projection_sha256="6" * 64)
            receipt_path = next(vault.receipts.glob("*.json"))
            receipt = json.loads(receipt_path.read_text())
            receipt["deleted_at"] = "2020-01-01T00:00:00Z"
            receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
            receipt_path.chmod(0o600)

            with self.assertRaisesRegex(PermissionError, "receipt is invalid"):
                ProtectedEvidenceVault(root, clock=lambda: NOW)


if __name__ == "__main__":
    unittest.main()
