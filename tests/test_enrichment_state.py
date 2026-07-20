from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
import tempfile
import unittest

from community_os.enrichment.gates import CoresignalGate, PublicSourceGate
from community_os.enrichment.state import (
    PipelineState,
    StageStatus,
    pseudonymous_id,
    sanitize_audit_event,
)


class EnrichmentStateTests(unittest.TestCase):
    def test_github_and_public_pages_require_bound_notice_terms_and_source_gate(self) -> None:
        now = datetime(2026, 7, 13, 10, tzinfo=UTC)
        common = {
            "notice_version": "notice_v2", "notice_sent_at": "2026-07-13T08:00:00Z",
            "objections_reconciled": True, "exclusions_reconciled": True,
            "suppressions_reconciled": True, "deletions_reconciled": True,
            "source_authorization_confirmed": True, "provider_terms_version": "terms_v1",
            "purpose_code": "aggregate_talent_evidence", "accountable_owner": "privacy_lead",
            "approval_id": "approval_001", "approved_at": "2026-07-13T09:00:00Z",
        }
        with tempfile.TemporaryDirectory() as directory:
            state = PipelineState.create(Path(directory) / "state.json", {
                "github": StageStatus.LOCKED, "public_pages": StageStatus.LOCKED,
            })
            with self.assertRaises(PermissionError):
                state.unlock("github")
            github = PublicSourceGate(**{
                **common, "source_scope": "applicant_supplied_github", "retention_days": 30,
            })
            pages = PublicSourceGate(**{
                **common, "source_scope": "applicant_supplied_public_pages", "retention_days": 14,
            })
            state.unlock("github", github, now=now)
            state.unlock("public_pages", pages, now=now)
            state.start("github")
            state.start("public_pages")
            reopened = PipelineState.load(Path(directory) / "state.json")
            self.assertEqual(reopened.stage("github").status, StageStatus.RUNNING)
            self.assertIsNotNone(reopened.stage("public_pages").authorization_hash)
        future = PublicSourceGate(**{**github.to_record(), "approved_at": "2099-01-01T00:00:00Z"})
        with self.assertRaisesRegex(PermissionError, "incomplete"):
            future.authorize("github", now=now)

    def test_relocking_gated_stage_revokes_authorization_and_result(self) -> None:
        now = datetime(2026, 7, 13, 10, tzinfo=UTC)
        gate = PublicSourceGate(
            notice_version="notice_v2", notice_sent_at="2026-07-13T08:00:00Z",
            objections_reconciled=True, exclusions_reconciled=True,
            suppressions_reconciled=True, deletions_reconciled=True,
            source_authorization_confirmed=True, provider_terms_version="terms_v1",
            source_scope="applicant_supplied_github",
            purpose_code="aggregate_talent_evidence", retention_days=30,
            accountable_owner="privacy_lead", approval_id="approval_001",
            approved_at="2026-07-13T09:00:00Z",
        )
        with tempfile.TemporaryDirectory() as directory:
            state = PipelineState.create(
                Path(directory) / "state.json", {"github": StageStatus.LOCKED},
            )
            state.unlock("github", gate, now=now)
            state.start("github")
            state.complete("github", {"output_hash": "a" * 64, "record_count": 1})

            state.lock("github")

            record = state.stage("github")
            self.assertEqual(record.status, StageStatus.LOCKED)
            self.assertIsNone(record.authorization_hash)
            self.assertIsNone(record.authorization_record)
            self.assertIsNone(record.result)

    def test_state_machine_fails_closed_and_persists_canonically(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            state = PipelineState.create(path, {"local_parse": StageStatus.ALLOWED, "coresignal": StageStatus.LOCKED})
            with self.assertRaisesRegex(ValueError, "locked"):
                state.start("coresignal")
            state.start("local_parse")
            state.fail("local_parse", "upstream_unavailable")
            state.resume("local_parse")
            state.complete("local_parse", {"output_hash": "a" * 64, "record_count": 3})
            with self.assertRaisesRegex(ValueError, "complete"):
                state.start("local_parse")

            reopened = PipelineState.load(path)
            self.assertEqual(reopened.stage("local_parse").status, StageStatus.COMPLETE)
            self.assertEqual(reopened.stage("local_parse").attempts, 2)
            self.assertEqual(json.loads(path.read_text()), reopened.to_dict())
            self.assertTrue(path.read_text().endswith("\n"))
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_pseudonyms_are_keyed_and_audit_events_reject_sensitive_fields(self) -> None:
        first = pseudonymous_id("person@example.org", secret=b"secret", key_version="v1")
        second = pseudonymous_id("person@example.org", secret=b"other", key_version="v1")
        self.assertRegex(first, r"^pid:v1:[0-9a-f]{64}$")
        self.assertNotEqual(first, second)
        event = sanitize_audit_event("stage_transition", {"stage": "github", "status": "running", "attempt": 1})
        self.assertEqual(event["properties"]["stage"], "github")
        for key in ("email", "name", "token", "url", "payload"):
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "sensitive"):
                sanitize_audit_event("stage_transition", {key: "private"})
        for key in ("component", "result"):
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "allowlisted"):
                sanitize_audit_event("stage_transition", {key: "operator_private_token"})
        with self.assertRaisesRegex(ValueError, "audit property value"):
            sanitize_audit_event("stage_transition", {"stage": "Private Person"})

    def test_loading_state_revalidates_audit_events(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            state = PipelineState.create(path, {"local_parse": StageStatus.ALLOWED})
            payload = state.to_dict()
            payload["audit_events"] = [{
                "event": "stage_transition",
                "properties": {"stage": "private@example.org"},
            }]
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "audit"):
                PipelineState.load(path)

    def test_only_failed_stages_can_resume(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = PipelineState.create(
                Path(directory) / "state.json",
                {"allowed": StageStatus.ALLOWED, "locked": StageStatus.LOCKED},
            )
            with self.assertRaisesRegex(ValueError, "failed"):
                state.resume("allowed")
            with self.assertRaisesRegex(ValueError, "failed"):
                state.resume("locked")
            state.start("allowed")
            state.fail("allowed", "upstream_unavailable")
            state.resume("allowed")
            self.assertEqual(state.stage("allowed").status, StageStatus.RUNNING)
            self.assertEqual(state.stage("allowed").attempts, 2)

    def test_coresignal_gate_fails_before_transport_until_every_condition_is_recorded(self) -> None:
        now = datetime(2026, 7, 13, 11, tzinfo=UTC)
        valid = {
            "notice_version": "coresignal_transparency_v1",
            "notice_sent_at": "2026-07-13T09:00:00Z",
            "notice_scope": "linkedin_coresignal_enrichment",
            "notice_content_sha256": "d" * 64,
            "objections_reconciled": True,
            "exclusions_reconciled": True,
            "suppressions_reconciled": True,
            "deletions_reconciled": True,
            "access_verified": True,
            "provider_terms_version": "terms-2026-06",
            "source_scope": "applicant_supplied_linkedin",
            "retention_days": 30,
            "approval_id": "approval-2026-07-13-01",
            "approved_at": "2026-07-13T10:00:00Z",
        }
        invalid_values = {
            "notice_version": "", "notice_sent_at": "", "objections_reconciled": False,
            "notice_scope": "aggregate_and_github_only",
            "notice_content_sha256": "bad",
            "exclusions_reconciled": False, "suppressions_reconciled": False,
            "deletions_reconciled": False, "access_verified": False,
            "provider_terms_version": "", "source_scope": "", "retention_days": 0,
            "approval_id": "", "approved_at": "",
        }
        for field, value in invalid_values.items():
            calls: list[str] = []
            gate = CoresignalGate(**{**valid, field: value})
            with self.subTest(field=field), self.assertRaisesRegex(PermissionError, "Coresignal locked"):
                gate.call_after_authorization(lambda: calls.append("transport"), now=now)
            self.assertEqual(calls, [])

        calls = []
        result = CoresignalGate(**valid).call_after_authorization(
            lambda: calls.append("transport") or "ok", now=now,
        )
        self.assertEqual((result, calls), ("ok", ["transport"]))

    def test_coresignal_stage_cannot_be_allowed_or_started_without_bound_gate(self) -> None:
        now = datetime(2026, 7, 13, 11, tzinfo=UTC)
        values = {
            "notice_version": "coresignal_transparency_v1", "notice_sent_at": "2026-07-13T09:00:00Z",
            "notice_scope": "linkedin_coresignal_enrichment",
            "notice_content_sha256": "d" * 64,
            "objections_reconciled": True, "exclusions_reconciled": True,
            "suppressions_reconciled": True, "deletions_reconciled": True,
            "access_verified": True, "provider_terms_version": "terms-v1",
            "source_scope": "applicant_supplied_linkedin", "retention_days": 30,
            "approval_id": "approval-1", "approved_at": "2026-07-13T10:00:00Z",
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            with self.assertRaisesRegex(ValueError, "locked"):
                PipelineState.create(path, {"coresignal": StageStatus.ALLOWED})
            state = PipelineState.create(path, {"coresignal": StageStatus.LOCKED})
            with self.assertRaisesRegex(PermissionError, "authorization"):
                state.unlock("coresignal")
            with self.assertRaises(PermissionError):
                state.unlock("coresignal", CoresignalGate(**{**values, "access_verified": False}), now=now)
            state.unlock("coresignal", CoresignalGate(**values), now=now)
            self.assertRegex(state.stage("coresignal").authorization_hash or "", r"^[0-9a-f]{64}$")
            state.start("coresignal")
            self.assertEqual(state.stage("coresignal").status, StageStatus.RUNNING)

            payload = state.to_dict()
            payload["stages"]["coresignal"]["authorization_hash"] = "b" * 64
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "authorization"):
                PipelineState.load(path)

    def test_coresignal_approval_must_follow_notice_and_scope_is_exact(self) -> None:
        now = datetime(2026, 7, 13, 11, tzinfo=UTC)
        base = {
            "notice_version": "coresignal_transparency_v1", "notice_sent_at": "2026-07-13T09:00:00Z",
            "notice_scope": "linkedin_coresignal_enrichment",
            "notice_content_sha256": "d" * 64,
            "objections_reconciled": True, "exclusions_reconciled": True,
            "suppressions_reconciled": True, "deletions_reconciled": True,
            "access_verified": True, "provider_terms_version": "terms-v1",
            "source_scope": "applicant_supplied_linkedin", "retention_days": 30,
            "approval_id": "approval-1", "approved_at": "2026-07-13T10:00:00Z",
        }
        for override in (
            {"approved_at": "2026-07-13T08:00:00Z"},
            {"approved_at": "2026-07-13T09:00:00Z"},
            {"source_scope": "all_linkedin"},
            {"notice_scope": "aggregate_and_github_only"},
            {"retention_days": 31},
        ):
            calls: list[str] = []
            with self.subTest(override=override), self.assertRaises(PermissionError):
                CoresignalGate(**{**base, **override}).call_after_authorization(
                    lambda: calls.append("transport"), now=now,
                )
            self.assertEqual(calls, [])

    def test_load_rejects_semantically_impossible_stage_records(self) -> None:
        base = {
            "audit_events": [], "state_version": "enrichment-state-v1",
            "stages": {"local_stage": {
                "attempts": 0, "authorization_hash": None, "authorization_record": None,
                "reason_code": None,
                "result": None, "status": "allowed",
            }},
        }
        invalid = (
            {"attempts": -1},
            {"status": "running", "attempts": 0},
            {"status": "failed", "attempts": 1, "reason_code": None},
            {"status": "allowed", "reason_code": "wrong_state"},
            {"status": "failed", "attempts": 1, "reason_code": "failed", "result": {"output_hash": "a" * 64, "record_count": 1}},
            {"status": "complete", "attempts": 1, "result": {"record_count": 1}},
            {"status": "complete", "attempts": 1, "result": {"output_hash": "z" * 64, "record_count": 1}},
            {"status": "complete", "attempts": 1, "result": {"output_hash": "a" * 64, "record_count": -1}},
        )
        for override in invalid:
            with self.subTest(override=override), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "state.json"
                payload = json.loads(json.dumps(base))
                payload["stages"]["local_stage"].update(override)
                path.write_text(json.dumps(payload), encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "stage"):
                    PipelineState.load(path)


if __name__ == "__main__":
    unittest.main()
