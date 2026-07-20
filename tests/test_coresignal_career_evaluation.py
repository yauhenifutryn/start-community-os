from __future__ import annotations

from datetime import UTC, datetime, timedelta
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlparse

from community_os.coresignal_evaluation import EvaluationCandidate
from community_os.enrichment.transport import HttpResponse, RetryableTransportError


NOW = datetime(2026, 7, 15, 8, tzinfo=UTC)
FIELDS = [
    "active_experience_title",
    "active_experience_management_level",
    "experience",
]


def candidate(index: int = 1, *, priority: str = "checked_in") -> EvaluationCandidate:
    return EvaluationCandidate(
        subject_ref=f"pid:v1:{index:064x}",
        linkedin_url=f"https://www.linkedin.com/in/person-{index}",
        source_record_ref=f"source:application:{index:024x}",
        priority=priority,
    )


def approval_record(candidates=(candidate(),), **overrides: object) -> dict[str, object]:
    from community_os.coresignal_career_evaluation import preview_career_evaluation_plan

    sample_limit = int(overrides.get("sample_limit", 100))
    hash_limit = sample_limit if 1 <= sample_limit <= 100 else 100
    _plan, sample_hash, exclusions_hash = preview_career_evaluation_plan(
        candidates, sample_limit=hash_limit,
    )
    record: dict[str, object] = {
        "approval_id": "release-owner-coresignal-career-evaluation-20260715",
        "approved_at": NOW.isoformat().replace("+00:00", "Z"),
        "approved_by": "release_owner",
        "distribution": "internal_only",
        "evaluation_version": "coresignal-career-evaluation-v1",
        "exclusions_sha256": exclusions_hash,
        "expires_at": (NOW + timedelta(days=7)).isoformat().replace("+00:00", "Z"),
        "fields": FIELDS,
        "notice_status": "not_sent",
        "priority_order": ["checked_in", "accepted_not_checked_in", "other"],
        "projection_version": "coresignal-career-evidence-v1",
        "provider_access_verified": True,
        "provider_terms_version": "coresignal-self-service-2026-07",
        "purpose": "internal_career_semantic_evaluation",
        "retention_days": 7,
        "sample_limit": sample_limit,
        "sample_sha256": sample_hash,
        "source_scope": "applicant_supplied_linkedin",
    }
    record.update(overrides)
    return record


def bound_approval(candidates=(candidate(),), **overrides: object):
    from community_os.coresignal_career_evaluation import CoresignalCareerEvaluationApproval

    return CoresignalCareerEvaluationApproval.from_record(
        approval_record(candidates, **overrides)
    )


def career_evidence(*, description: str = "Led product delivery and operations.") -> list[dict[str, object]]:
    return [{
        "active_state": "current",
        "description_excerpt": description,
        "duration_band": "one_to_three_years",
        "evidence_refs": ["role_01:title", "role_01:description"],
        "industry_code": "software",
        "organization_size_band": "small",
        "role_code": "role_01",
        "seniority_context": "founder_executive",
        "title_excerpt": "Technical founder",
    }]


class FixtureTransport:
    def __init__(self, responses: list[HttpResponse | BaseException]) -> None:
        self.responses = list(responses)
        self.calls: list[tuple[str, str, dict[str, str]]] = []

    def request(self, method, url, *, headers, timeout, max_bytes):
        self.calls.append((method, url, dict(headers)))
        response = self.responses.pop(0)
        if isinstance(response, BaseException):
            raise response
        return response


class CoresignalCareerEvaluationTests(unittest.TestCase):
    def test_approval_is_exact_hash_bound_and_career_only(self) -> None:
        from community_os.coresignal_career_evaluation import (
            CoresignalCareerEvaluationApproval,
        )

        approval = bound_approval()
        approval.authorize(now=NOW)
        self.assertEqual(approval.to_record(), approval_record())
        self.assertEqual(len(approval.authorization_hash(now=NOW)), 64)

        for change in (
            {"distribution": "partner_report"},
            {"source_scope": "provider_discovered_linkedin"},
            {"fields": [*FIELDS, "posts"]},
            {"fields": ["experience"]},
            {"priority_order": ["other", "checked_in", "accepted_not_checked_in"]},
            {"retention_days": 8},
            {"sample_limit": 101},
            {"provider_access_verified": False},
        ):
            with self.subTest(change=change), self.assertRaises(PermissionError):
                CoresignalCareerEvaluationApproval.from_record(
                    approval_record(**change)
                ).authorize(now=NOW)

        extra = approval_record()
        extra["posts"] = False
        with self.assertRaises(PermissionError):
            CoresignalCareerEvaluationApproval.from_record(extra)

    def test_plan_reuses_evidence_backed_priority_and_caps_attempts_at_100(self) -> None:
        from community_os.coresignal_career_evaluation import (
            build_career_evaluation_plan,
        )

        candidates = tuple(
            candidate(
                index,
                priority=(
                    "checked_in" if index <= 70 else
                    "accepted_not_checked_in" if index <= 85 else "other"
                ),
            )
            for index in range(1, 121)
        )
        approval = bound_approval(candidates)
        plan = build_career_evaluation_plan(candidates, approval=approval, now=NOW)

        self.assertEqual(len(plan), 100)
        self.assertTrue(all(item.priority == "checked_in" for item in plan[:70]))
        self.assertEqual(sum(item.priority == "accepted_not_checked_in" for item in plan), 15)
        self.assertEqual(sum(item.priority == "other" for item in plan), 15)

    def test_runner_persists_only_sanitized_career_projection_and_deletion_receipt(self) -> None:
        from community_os.coresignal_career_evaluation import (
            CoresignalCareerEvaluationRunner,
            CoresignalCareerEvaluationStore,
        )

        subject = candidate()
        raw = {
            "active_experience_title": "Founder",
            "active_experience_management_level": "Founder",
            "experience": [
                {
                    "position_title": f"Role {index} for Sensitive Person",
                    "description": f"Built product {index} at Secret Company and contact x@example.com",
                    "active_experience": index == 0,
                    "date_from_year": 2025 - index,
                    "company_name": "Secret Company",
                    "company_industry": "Software Development",
                    "company_size_range": "11-50",
                }
                for index in range(8)
            ],
            "posts": [{"text": "private social post"}],
            "activity": [{"type": "comment"}],
            "recommendations": ["Sensitive endorsement"],
            "full_name": "Sensitive Person",
        }
        body = json.dumps(raw).encode("utf-8")
        transport = FixtureTransport([
            HttpResponse(200, {"Content-Type": "application/json"}, body, "https://api.coresignal.com/result"),
        ])
        identity_calls: list[str] = []
        with tempfile.TemporaryDirectory() as directory:
            release_root = Path(directory) / "release"
            release_root.mkdir()
            store = CoresignalCareerEvaluationStore(
                Path(directory) / "private" / "coresignal-career-evaluation",
                release_root=release_root,
                clock=lambda: NOW,
            )
            runner = CoresignalCareerEvaluationRunner(
                transport=transport,
                store=store,
                api_token="fixture-token",
                clock=lambda: NOW,
                source_verifier=lambda value: value == subject,
                identity_literals_resolver=lambda value: identity_calls.append(value.subject_ref) or (
                    "Sensitive Person", "person-1",
                ),
            )
            result = runner.evaluate((subject,), approval=bound_approval((subject,)))

            self.assertEqual(len(transport.calls), 1)
            self.assertEqual(identity_calls, [subject.subject_ref])
            query = parse_qs(urlparse(transport.calls[0][1]).query)
            self.assertEqual(query, {"fields": FIELDS})
            record = result["records"][0]
            self.assertEqual(record["outcome"], "observed")
            self.assertFalse(record["release_eligible"])
            self.assertEqual(record["distribution"], "internal_only")
            self.assertLessEqual(len(record["career_evidence"]), 6)
            self.assertEqual(record["audit_receipt"]["payload_sha256"], hashlib.sha256(body).hexdigest())
            self.assertTrue(record["audit_receipt"]["raw_evidence_deleted"])
            self.assertEqual(record["audit_receipt"]["deletion_state"], "deleted_after_projection")

            serialized = "\n".join(
                path.read_text(encoding="utf-8") for path in store.root.rglob("*.json")
            )
            for forbidden in (
                "Sensitive Person", "Secret Company", "x@example.com", "private social post",
                "Sensitive endorsement", "posts", "activity", "recommendations", "linkedin.com",
            ):
                self.assertNotIn(forbidden, serialized)
            self.assertEqual(os.stat(store.root).st_mode & 0o777, 0o700)
            self.assertTrue(all(
                (os.stat(path).st_mode & 0o777) == 0o600
                for path in store.root.rglob("*.json")
            ))

    def test_projection_rejection_is_definitive_unknown_and_cohort_continues(self) -> None:
        from community_os.coresignal_career_evaluation import (
            CoresignalCareerEvaluationRunner,
            CoresignalCareerEvaluationStore,
        )

        rejected = candidate(1)
        later = candidate(2)
        candidates = (rejected, later)
        rejected_body = json.dumps({
            "experience": "schema-invalid raw career data",
            "full_name": "Sensitive Person",
        }).encode("utf-8")
        later_body = b"not retained"
        transport = FixtureTransport([
            HttpResponse(
                200, {"Content-Type": "application/json"}, rejected_body,
                "https://api.coresignal.com/result",
            ),
            HttpResponse(404, {}, later_body, "https://api.coresignal.com/result"),
        ])
        with tempfile.TemporaryDirectory() as directory:
            store = CoresignalCareerEvaluationStore(
                Path(directory) / "protected" / "coresignal-career-evaluation",
                release_root=Path(directory) / "release", clock=lambda: NOW,
            )
            runner = CoresignalCareerEvaluationRunner(
                transport=transport, store=store, api_token="token", clock=lambda: NOW,
                source_verifier=lambda _value: True,
                identity_literals_resolver=lambda _value: ("Sensitive Person",),
            )

            result = runner.evaluate(candidates, approval=bound_approval(candidates))

            self.assertEqual(len(transport.calls), 2)
            self.assertEqual(len(result["records"]), 2)
            rejected_record = result["records"][0]
            self.assertEqual(rejected_record["outcome"], "projection_rejected")
            self.assertEqual(
                rejected_record["unknown_state"], "provider_payload_rejected",
            )
            self.assertEqual(rejected_record["career_evidence"], [])
            self.assertFalse(rejected_record["release_eligible"])
            self.assertEqual(rejected_record["distribution"], "internal_only")
            self.assertEqual(
                rejected_record["audit_receipt"]["payload_sha256"],
                hashlib.sha256(rejected_body).hexdigest(),
            )
            self.assertTrue(
                rejected_record["audit_receipt"]["raw_evidence_deleted"],
            )
            self.assertEqual(
                rejected_record["audit_receipt"]["deletion_state"],
                "deleted_after_projection_rejection",
            )
            self.assertEqual(
                rejected_record["audit_receipt"]["reason_code"],
                "projection_failed_after_response",
            )
            self.assertEqual(result["records"][1]["outcome"], "not_found")
            self.assertEqual(list(store.attempts.glob("*.json")), [])

            serialized = "\n".join(
                path.read_text(encoding="utf-8") for path in store.root.rglob("*.json")
            )
            self.assertNotIn("schema-invalid raw career data", serialized)
            self.assertNotIn("Sensitive Person", serialized)

    def test_operator_resolves_exact_pending_projection_failure_without_retry(self) -> None:
        from community_os.coresignal_career_evaluation import (
            CoresignalCareerEvaluationStore,
        )

        subject = candidate()
        transport = FixtureTransport([])
        with tempfile.TemporaryDirectory() as directory:
            store = CoresignalCareerEvaluationStore(
                Path(directory) / "protected" / "coresignal-career-evaluation",
                release_root=Path(directory) / "release", clock=lambda: NOW,
            )
            approval = bound_approval((subject,))
            approval_sha256 = store.write_approval(approval, now=NOW)
            store.begin_attempt(
                candidate=subject, approval_sha256=approval_sha256,
                retention_days=approval.retention_days,
            )

            record = store.resolve_pending_projection_rejection(
                candidate=subject,
                approval_sha256=approval_sha256,
                reason_code="projection_failed_after_response",
                retention_days=approval.retention_days,
            )

            self.assertEqual(transport.calls, [])
            self.assertEqual(record["outcome"], "projection_rejected")
            self.assertEqual(record["unknown_state"], "provider_payload_rejected")
            self.assertEqual(record["career_evidence"], [])
            self.assertIsNone(record["audit_receipt"]["payload_sha256"])
            self.assertEqual(
                record["audit_receipt"]["deletion_state"],
                "deleted_after_projection_rejection",
            )
            self.assertTrue(record["audit_receipt"]["raw_evidence_deleted"])
            self.assertEqual(
                record["audit_receipt"]["reason_code"],
                "projection_failed_after_response",
            )
            self.assertEqual(list(store.attempts.glob("*.json")), [])
            self.assertEqual(
                store.get(subject.subject_ref, approval_sha256=approval_sha256),
                record,
            )

            unmatched = candidate(2)
            with self.assertRaisesRegex(PermissionError, "pending attempt"):
                store.resolve_pending_projection_rejection(
                    candidate=unmatched,
                    approval_sha256=approval_sha256,
                    reason_code="projection_failed_after_response",
                    retention_days=approval.retention_days,
                )

        for mismatch in (
            "approval", "candidate_priority", "candidate_url", "candidate_source", "reason",
        ):
            with self.subTest(mismatch=mismatch), tempfile.TemporaryDirectory() as directory:
                store = CoresignalCareerEvaluationStore(
                    Path(directory) / "protected" / "coresignal-career-evaluation",
                    release_root=Path(directory) / "release", clock=lambda: NOW,
                )
                approval = bound_approval((subject,))
                approval_sha256 = store.write_approval(approval, now=NOW)
                store.begin_attempt(
                    candidate=subject, approval_sha256=approval_sha256,
                    retention_days=approval.retention_days,
                )
                candidate_overrides: dict[str, str] = {}
                if mismatch == "candidate_priority":
                    candidate_overrides["priority"] = "other"
                elif mismatch == "candidate_url":
                    candidate_overrides["linkedin_url"] = "https://www.linkedin.com/in/different"
                elif mismatch == "candidate_source":
                    candidate_overrides["source_record_ref"] = "source:application:different"
                requested_candidate = (
                    EvaluationCandidate(
                        subject_ref=subject.subject_ref,
                        linkedin_url=candidate_overrides.get(
                            "linkedin_url", subject.linkedin_url,
                        ),
                        source_record_ref=candidate_overrides.get(
                            "source_record_ref", subject.source_record_ref,
                        ),
                        priority=candidate_overrides.get("priority", subject.priority),
                    )
                    if candidate_overrides else subject
                )
                requested_hash = "f" * 64 if mismatch == "approval" else approval_sha256
                reason = "operator_override" if mismatch == "reason" else "projection_failed_after_response"

                with self.assertRaises((PermissionError, ValueError)):
                    store.resolve_pending_projection_rejection(
                        candidate=requested_candidate,
                        approval_sha256=requested_hash,
                        reason_code=reason,
                        retention_days=approval.retention_days,
                    )
                self.assertEqual(len(list(store.attempts.glob("*.json"))), 1)
                self.assertEqual(list(store.results.glob("*.json")), [])

    def test_404_is_empty_unknown_and_402_or_429_stops_without_retry(self) -> None:
        from community_os.coresignal_career_evaluation import (
            CoresignalCareerEvaluationRunner,
            CoresignalCareerEvaluationStore,
        )

        for status in (404, 402, 429):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as directory:
                subject = candidate(status)
                transport = FixtureTransport([
                    HttpResponse(status, {}, b"not stored", "https://api.coresignal.com/result"),
                    HttpResponse(200, {}, b"{}", "https://api.coresignal.com/result"),
                ])
                store = CoresignalCareerEvaluationStore(
                    Path(directory) / "protected" / "coresignal-career-evaluation",
                    release_root=Path(directory) / "release", clock=lambda: NOW,
                )
                runner = CoresignalCareerEvaluationRunner(
                    transport=transport, store=store, api_token="token", clock=lambda: NOW,
                    source_verifier=lambda _value: True,
                    identity_literals_resolver=lambda _value: ("Known Person",),
                )
                if status == 404:
                    result = runner.evaluate((subject,), approval=bound_approval((subject,)))
                    record = result["records"][0]
                    self.assertEqual(record["outcome"], "not_found")
                    self.assertEqual(record["career_evidence"], [])
                    self.assertEqual(record["unknown_state"], "provider_not_found")
                else:
                    with self.assertRaisesRegex(PermissionError, str(status)):
                        runner.evaluate((subject,), approval=bound_approval((subject,)))
                self.assertEqual(len(transport.calls), 1)

    def test_402_persists_approval_bound_exhaustion_and_blocks_later_transport(self) -> None:
        from community_os.coresignal_career_evaluation import (
            CoresignalCareerEvaluationRunner,
            CoresignalCareerEvaluationStore,
        )

        subject = candidate(402)
        approval = bound_approval((subject,), retention_days=1)
        current = [NOW]
        transport = FixtureTransport([
            HttpResponse(402, {}, b"not stored", "https://api.coresignal.com/result"),
            HttpResponse(404, {}, b"", "https://api.coresignal.com/result"),
        ])
        with tempfile.TemporaryDirectory() as directory:
            store = CoresignalCareerEvaluationStore(
                Path(directory) / "protected" / "coresignal-career-evaluation",
                release_root=Path(directory) / "release", clock=lambda: current[0],
            )
            runner = CoresignalCareerEvaluationRunner(
                transport=transport, store=store, api_token="token", clock=lambda: current[0],
                source_verifier=lambda _value: True,
                identity_literals_resolver=lambda _value: ("Known Person",),
            )

            with self.assertRaisesRegex(PermissionError, "status 402"):
                runner.evaluate((subject,), approval=approval)
            current[0] = NOW + timedelta(days=2)
            store = CoresignalCareerEvaluationStore(
                Path(directory) / "protected" / "coresignal-career-evaluation",
                release_root=Path(directory) / "release", clock=lambda: current[0],
            )
            runner = CoresignalCareerEvaluationRunner(
                transport=transport, store=store, api_token="token", clock=lambda: current[0],
                source_verifier=lambda _value: True,
                identity_literals_resolver=lambda _value: ("Known Person",),
            )
            with self.assertRaisesRegex(PermissionError, "capacity.*approval"):
                runner.evaluate((subject,), approval=approval)

            self.assertEqual(len(transport.calls), 1)
            receipts = list(store.exhaustions.glob("*.json"))
            self.assertEqual(len(receipts), 1)
            receipt = json.loads(receipts[0].read_text(encoding="utf-8"))
            self.assertEqual(
                receipt["approval_sha256"],
                approval.authorization_hash(now=NOW),
            )
            self.assertEqual(receipt["provider_status"], 402)
            self.assertEqual(receipt["state"], "provider_capacity_exhausted")
            self.assertEqual(list(store.attempts.glob("*.json")), [])
            self.assertNotIn(subject.subject_ref, receipts[0].read_text(encoding="utf-8"))

    def test_429_remains_non_terminal_and_can_be_retried_by_later_run(self) -> None:
        from community_os.coresignal_career_evaluation import (
            CoresignalCareerEvaluationRunner,
            CoresignalCareerEvaluationStore,
        )

        subject = candidate(429)
        approval = bound_approval((subject,))
        transport = FixtureTransport([
            HttpResponse(
                429, {"Retry-After": "2"}, b"not stored",
                "https://api.coresignal.com/result",
            ),
            HttpResponse(404, {}, b"", "https://api.coresignal.com/result"),
        ])
        with tempfile.TemporaryDirectory() as directory:
            store = CoresignalCareerEvaluationStore(
                Path(directory) / "protected" / "coresignal-career-evaluation",
                release_root=Path(directory) / "release", clock=lambda: NOW,
            )
            runner = CoresignalCareerEvaluationRunner(
                transport=transport, store=store, api_token="token", clock=lambda: NOW,
                source_verifier=lambda _value: True,
                identity_literals_resolver=lambda _value: ("Known Person",),
            )

            with self.assertRaisesRegex(PermissionError, "status 429"):
                runner.evaluate((subject,), approval=approval)
            result = runner.evaluate((subject,), approval=approval)

            self.assertEqual(len(transport.calls), 2)
            self.assertEqual(result["records"][0]["outcome"], "not_found")
            self.assertEqual(list(store.exhaustions.glob("*.json")), [])

    def test_interruption_leaves_fail_closed_attempt_and_cleanup_expires_it(self) -> None:
        from community_os.coresignal_career_evaluation import (
            CoresignalCareerEvaluationRunner,
            CoresignalCareerEvaluationStore,
        )

        subject = candidate()
        current = [NOW]
        transport = FixtureTransport([
            RetryableTransportError("network state unknown"),
            HttpResponse(404, {}, b"", "https://api.coresignal.com/result"),
        ])
        with tempfile.TemporaryDirectory() as directory:
            store = CoresignalCareerEvaluationStore(
                Path(directory) / "protected" / "coresignal-career-evaluation",
                release_root=Path(directory) / "release", clock=lambda: current[0],
            )
            runner = CoresignalCareerEvaluationRunner(
                transport=transport, store=store, api_token="token", clock=lambda: current[0],
                source_verifier=lambda _value: True,
                identity_literals_resolver=lambda _value: ("Known Person",),
            )
            approval = bound_approval((subject,))
            with self.assertRaisesRegex(RetryableTransportError, "unknown"):
                runner.evaluate((subject,), approval=approval)
            self.assertEqual(len(list(store.attempts.glob("*.json"))), 1)
            with self.assertRaisesRegex(PermissionError, "automatic retry is blocked"):
                runner.evaluate((subject,), approval=approval)
            self.assertEqual(len(transport.calls), 1)

            current[0] = NOW + timedelta(days=8)
            receipt = store.cleanup_expired()
            self.assertGreaterEqual(receipt["deleted_count"], 1)
            self.assertEqual(list(store.attempts.glob("*.json")), [])

    def test_runner_cleans_expired_attempt_after_store_reopen_before_transport(self) -> None:
        from community_os.coresignal_career_evaluation import (
            CoresignalCareerEvaluationRunner,
            CoresignalCareerEvaluationStore,
        )

        subject = candidate()
        approval = bound_approval((subject,))
        current = [NOW]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "protected" / "coresignal-career-evaluation"
            release_root = Path(directory) / "release"
            store = CoresignalCareerEvaluationStore(
                root, release_root=release_root, clock=lambda: current[0],
            )
            approval_sha256 = store.write_approval(approval, now=NOW)
            store.begin_attempt(
                candidate=subject, approval_sha256=approval_sha256,
                retention_days=1,
            )
            current[0] = NOW + timedelta(days=2)
            reopened = CoresignalCareerEvaluationStore(
                root, release_root=release_root, clock=lambda: current[0],
            )
            transport = FixtureTransport([
                HttpResponse(404, {}, b"", "https://api.coresignal.com/result"),
            ])
            runner = CoresignalCareerEvaluationRunner(
                transport=transport, store=reopened, api_token="token",
                clock=lambda: current[0], source_verifier=lambda _value: True,
                identity_literals_resolver=lambda _value: ("Known Person",),
            )

            result = runner.evaluate((subject,), approval=approval)

            self.assertEqual(len(transport.calls), 1)
            self.assertEqual(result["records"][0]["outcome"], "not_found")
            self.assertEqual(list(reopened.attempts.glob("*.json")), [])

    def test_identity_literals_are_required_before_projection(self) -> None:
        from community_os.coresignal_career_evaluation import (
            CoresignalCareerEvaluationRunner,
            CoresignalCareerEvaluationStore,
        )

        subject = candidate()
        body = json.dumps({"experience": []}).encode()
        transport = FixtureTransport([
            HttpResponse(200, {}, body, "https://api.coresignal.com/result"),
        ])
        with tempfile.TemporaryDirectory() as directory:
            store = CoresignalCareerEvaluationStore(
                Path(directory) / "protected" / "coresignal-career-evaluation",
                release_root=Path(directory) / "release", clock=lambda: NOW,
            )
            runner = CoresignalCareerEvaluationRunner(
                transport=transport, store=store, api_token="token", clock=lambda: NOW,
                source_verifier=lambda _value: True,
                identity_literals_resolver=lambda _value: (),
            )
            with self.assertRaisesRegex(PermissionError, "identity literals"):
                runner.evaluate((subject,), approval=bound_approval((subject,)))
            self.assertEqual(len(transport.calls), 0)

    def test_store_rejects_a_projection_that_bypasses_the_safe_career_schema(self) -> None:
        from community_os.coresignal_career_evaluation import CoresignalCareerEvaluationStore

        subject = candidate()
        unsafe = [{
            "active_state": "current",
            "description_excerpt": "Contact private.person@example.com",
            "duration_band": "unknown",
            "evidence_refs": ["role_01:description"],
            "industry_code": "software",
            "organization_size_band": "small",
            "role_code": "role_01",
            "seniority_context": "senior",
            "title_excerpt": "Senior Engineer",
        }]
        with tempfile.TemporaryDirectory() as directory:
            store = CoresignalCareerEvaluationStore(
                Path(directory) / "protected" / "coresignal-career-evaluation",
                release_root=Path(directory) / "release", clock=lambda: NOW,
            )
            bad_enum = [{**unsafe[0], "description_excerpt": "", "active_state": "published_post"}]
            for projection in (unsafe, bad_enum):
                with self.subTest(projection=projection), self.assertRaisesRegex(ValueError, "projection"):
                    store.put(
                        candidate=subject, approval_sha256="a" * 64,
                        outcome="observed", career_evidence=projection,
                        payload_sha256="b" * 64, retention_days=7,
                    )

    def test_result_validation_rejects_invalid_projected_at(self) -> None:
        from community_os.coresignal_career_evaluation import CoresignalCareerEvaluationStore

        subject = candidate()
        with tempfile.TemporaryDirectory() as directory:
            store = CoresignalCareerEvaluationStore(
                Path(directory) / "protected" / "coresignal-career-evaluation",
                release_root=Path(directory) / "release", clock=lambda: NOW,
            )
            approval_sha256 = store.write_approval(
                bound_approval((subject,)), now=NOW,
            )
            store.put(
                candidate=subject, approval_sha256=approval_sha256,
                outcome="observed", career_evidence=career_evidence(),
                payload_sha256="a" * 64, retention_days=7,
            )
            result_path = store.results / store._record_name(subject.subject_ref)
            record = json.loads(result_path.read_text(encoding="utf-8"))
            record["audit_receipt"]["projected_at"] = "not-a-timestamp"
            result_path.write_text(json.dumps(record), encoding="utf-8")
            result_path.chmod(0o600)

            with self.assertRaisesRegex(PermissionError, "unreadable|validation"):
                store.get(subject.subject_ref, approval_sha256=approval_sha256)

    def test_result_validation_rejects_future_collection_timestamp(self) -> None:
        from community_os.coresignal_career_evaluation import CoresignalCareerEvaluationStore

        subject = candidate()
        with tempfile.TemporaryDirectory() as directory:
            store = CoresignalCareerEvaluationStore(
                Path(directory) / "protected" / "coresignal-career-evaluation",
                release_root=Path(directory) / "release", clock=lambda: NOW,
            )
            approval_sha256 = store.write_approval(
                bound_approval((subject,)), now=NOW,
            )
            store.put(
                candidate=subject, approval_sha256=approval_sha256,
                outcome="observed", career_evidence=career_evidence(),
                payload_sha256="a" * 64, retention_days=7,
            )
            result_path = store.results / store._record_name(subject.subject_ref)
            record = json.loads(result_path.read_text(encoding="utf-8"))
            future = (NOW + timedelta(days=1)).isoformat().replace("+00:00", "Z")
            record["collected_at"] = future
            record["audit_receipt"]["projected_at"] = future
            record["expires_at"] = (
                NOW + timedelta(days=2)
            ).isoformat().replace("+00:00", "Z")
            result_path.write_text(json.dumps(record), encoding="utf-8")
            result_path.chmod(0o600)

            with self.assertRaisesRegex(PermissionError, "validation"):
                store.get(subject.subject_ref, approval_sha256=approval_sha256)

    def test_career_projection_requires_sequential_role_codes(self) -> None:
        from community_os.coresignal_career_evaluation import CoresignalCareerEvaluationStore

        subject = candidate()
        projection = career_evidence()
        projection[0]["role_code"] = "role_09"
        projection[0]["evidence_refs"] = [
            "role_09:title", "role_09:description",
        ]
        with tempfile.TemporaryDirectory() as directory:
            store = CoresignalCareerEvaluationStore(
                Path(directory) / "protected" / "coresignal-career-evaluation",
                release_root=Path(directory) / "release", clock=lambda: NOW,
            )
            with self.assertRaisesRegex(ValueError, "projection"):
                store.put(
                    candidate=subject, approval_sha256="a" * 64,
                    outcome="observed", career_evidence=projection,
                    payload_sha256="b" * 64, retention_days=7,
                )

    def test_coverage_snapshot_is_detached_identifier_free_deterministic_and_transport_free(self) -> None:
        from community_os.coresignal_career_evaluation import (
            CoresignalCareerEvaluationRunner,
            CoresignalCareerEvaluationStore,
        )

        requested = (candidate(2), candidate(1))
        outsider = candidate(3)
        cohort = (*requested, outsider)
        with tempfile.TemporaryDirectory() as directory:
            store = CoresignalCareerEvaluationStore(
                Path(directory) / "protected" / "coresignal-career-evaluation",
                release_root=Path(directory) / "release", clock=lambda: NOW,
            )
            approval = bound_approval(cohort)
            approval_sha256 = store.write_approval(approval, now=NOW)
            store.put(
                candidate=requested[0], approval_sha256=approval_sha256,
                outcome="observed", career_evidence=career_evidence(
                    description="Built product delivery systems.",
                ), payload_sha256="a" * 64, retention_days=7,
            )
            store.put(
                candidate=requested[1], approval_sha256=approval_sha256,
                outcome="observed", career_evidence=career_evidence(),
                payload_sha256="b" * 64, retention_days=7,
            )
            store.put(
                candidate=outsider, approval_sha256=approval_sha256,
                outcome="observed", career_evidence=career_evidence(
                    description="Researcher evidence outside requested population.",
                ), payload_sha256="c" * 64, retention_days=7,
            )

            read_paths: list[Path] = []
            original_read_text = Path.read_text

            def record_read(path: Path, *args, **kwargs):
                read_paths.append(path)
                return original_read_text(path, *args, **kwargs)

            with (
                patch.object(store, "get", wraps=store.get) as get_record,
                patch.object(Path, "read_text", record_read),
                patch.object(
                    CoresignalCareerEvaluationRunner,
                    "_fetch_and_project",
                    side_effect=AssertionError("coverage snapshot must never invoke transport"),
                ),
            ):
                snapshot = store.build_coverage_snapshot(
                    item.subject_ref for item in requested
                )

            self.assertEqual(set(snapshot), {"career_evidence", "snapshot_sha256"})
            self.assertRegex(str(snapshot["snapshot_sha256"]), r"^[0-9a-f]{64}$")
            self.assertEqual(len(snapshot["career_evidence"]), 2)
            self.assertEqual(
                [call.args[0] for call in get_record.call_args_list],
                sorted(item.subject_ref for item in requested),
            )
            outsider_path = store.results / store._record_name(outsider.subject_ref)
            self.assertNotIn(outsider_path, read_paths)
            serialized = json.dumps(snapshot, sort_keys=True)
            for forbidden in (
                *(item.subject_ref for item in cohort),
                *(item.linkedin_url for item in cohort),
                approval.approval_id,
                approval.approved_at,
                approval.provider_terms_version,
                "Researcher evidence outside requested population",
                "approval_sha256", "collected_at", "expires_at", "outcome",
                "priority", "provider", "release_eligible", "subject_ref",
            ):
                self.assertNotIn(forbidden, serialized)

            repeated = store.build_coverage_snapshot(
                item.subject_ref for item in reversed(requested)
            )
            self.assertEqual(repeated, snapshot)
            snapshot["career_evidence"][0][0]["description_excerpt"] = "mutated"
            self.assertEqual(
                store.build_coverage_snapshot(item.subject_ref for item in requested),
                repeated,
            )

    def test_internal_semantic_loader_returns_only_current_observed_subject_evidence(self) -> None:
        from community_os.coresignal_career_evaluation import (
            CoresignalCareerEvaluationStore,
        )

        observed = candidate(1)
        missing = candidate(2)
        with tempfile.TemporaryDirectory() as directory:
            store = CoresignalCareerEvaluationStore(
                Path(directory) / "protected" / "coresignal-career-evaluation",
                release_root=Path(directory) / "release", clock=lambda: NOW,
            )
            approval_sha256 = store.write_approval(
                bound_approval((observed, missing)), now=NOW,
            )
            expected = career_evidence()
            store.put(
                candidate=observed, approval_sha256=approval_sha256,
                outcome="observed", career_evidence=expected,
                payload_sha256="a" * 64, retention_days=7,
            )
            store.put(
                candidate=missing, approval_sha256=approval_sha256,
                outcome="not_found", career_evidence=[],
                payload_sha256="b" * 64, retention_days=7,
            )

            loaded = store.load_internal_semantic_evidence(
                (missing.subject_ref, observed.subject_ref),
                identity_literals=("Known Person",),
            )

            self.assertEqual(loaded, {observed.subject_ref: expected})
            loaded[observed.subject_ref][0]["description_excerpt"] = "mutated"
            self.assertEqual(
                store.load_internal_semantic_evidence(
                    (observed.subject_ref,), identity_literals=("Known Person",),
                ),
                {observed.subject_ref: expected},
            )

    def test_internal_semantic_loader_requires_identity_corpus_before_storage_access(self) -> None:
        from community_os.coresignal_career_evaluation import (
            CoresignalCareerEvaluationStore,
        )

        subject = candidate()
        with tempfile.TemporaryDirectory() as directory:
            store = CoresignalCareerEvaluationStore(
                Path(directory) / "protected" / "coresignal-career-evaluation",
                release_root=Path(directory) / "release", clock=lambda: NOW,
            )
            for identities in ((), ("x",)):
                with (
                    self.subTest(identities=identities),
                    patch.object(
                        store, "cleanup_expired",
                        side_effect=AssertionError(
                            "storage was accessed before identity validation"
                        ),
                    ),
                    self.assertRaisesRegex(PermissionError, "identity literals"),
                ):
                    store.load_internal_semantic_evidence(
                        (subject.subject_ref,), identity_literals=identities,
                    )

    def test_internal_semantic_loader_resanitizes_legacy_text_in_memory_only(self) -> None:
        from community_os.coresignal_career_evaluation import (
            CoresignalCareerEvaluationStore,
        )
        from community_os.enrichment.semantic_evidence import (
            assert_no_known_identity_literals,
        )

        subject = candidate()
        identities = ("Private Person", "Example Labs", "private@example.com")
        with tempfile.TemporaryDirectory() as directory:
            store = CoresignalCareerEvaluationStore(
                Path(directory) / "protected" / "coresignal-career-evaluation",
                release_root=Path(directory) / "release", clock=lambda: NOW,
            )
            approval_sha256 = store.write_approval(
                bound_approval((subject,)), now=NOW,
            )
            store.put(
                candidate=subject, approval_sha256=approval_sha256,
                outcome="observed", career_evidence=career_evidence(),
                payload_sha256="a" * 64, retention_days=7,
            )
            result_path = store.results / store._record_name(subject.subject_ref)
            legacy = json.loads(result_path.read_text(encoding="utf-8"))
            legacy["career_evidence"][0]["title_excerpt"] = (
                "Technical founder for Private Person"
            )
            legacy["career_evidence"][0]["description_excerpt"] = (
                "Built systems with Private Person at Example Labs; "
                "contact private@example.com."
            )
            result_path.write_text(
                json.dumps(legacy, sort_keys=True, separators=(",", ":")),
                encoding="utf-8",
            )
            result_path.chmod(0o600)
            retained_before = result_path.read_bytes()

            loaded = store.load_internal_semantic_evidence(
                (subject.subject_ref,), identity_literals=identities,
            )

            self.assertEqual(result_path.read_bytes(), retained_before)
            self.assertIn(subject.subject_ref, loaded)
            projected = loaded[subject.subject_ref]
            self.assertTrue(store._career_projection_is_valid(projected))
            assert_no_known_identity_literals(projected, identities)
            serialized = json.dumps(projected, sort_keys=True)
            for forbidden in identities:
                self.assertNotIn(forbidden.casefold(), serialized.casefold())
            self.assertEqual(
                store.load_internal_semantic_evidence(
                    (subject.subject_ref,), identity_literals=identities,
                ),
                loaded,
            )

    def test_internal_semantic_loader_never_relaxes_non_text_controls(self) -> None:
        from community_os.coresignal_career_evaluation import (
            CoresignalCareerEvaluationStore,
        )

        subject = candidate()
        identities = ("Private Person",)
        with tempfile.TemporaryDirectory() as directory:
            store = CoresignalCareerEvaluationStore(
                Path(directory) / "protected" / "coresignal-career-evaluation",
                release_root=Path(directory) / "release", clock=lambda: NOW,
            )
            approval_sha256 = store.write_approval(
                bound_approval((subject,)), now=NOW,
            )
            store.put(
                candidate=subject, approval_sha256=approval_sha256,
                outcome="observed", career_evidence=career_evidence(),
                payload_sha256="a" * 64, retention_days=7,
            )
            result_path = store.results / store._record_name(subject.subject_ref)
            baseline = json.loads(result_path.read_text(encoding="utf-8"))
            baseline["career_evidence"][0]["description_excerpt"] = (
                "Built systems with Private Person."
            )

            for failure in (
                "approval", "distribution", "release_eligible", "raw_deleted",
                "deletion_state", "enum", "ttl",
            ):
                with self.subTest(failure=failure):
                    record = json.loads(json.dumps(baseline))
                    if failure == "approval":
                        record["approval_sha256"] = "f" * 64
                    elif failure == "distribution":
                        record["distribution"] = "partner_report"
                    elif failure == "release_eligible":
                        record["release_eligible"] = True
                    elif failure == "raw_deleted":
                        record["audit_receipt"]["raw_evidence_deleted"] = False
                    elif failure == "deletion_state":
                        record["audit_receipt"]["deletion_state"] = "retained"
                    elif failure == "enum":
                        record["career_evidence"][0]["active_state"] = "published_post"
                    else:
                        record["expires_at"] = (
                            NOW + timedelta(days=8)
                        ).isoformat().replace("+00:00", "Z")
                    result_path.write_text(json.dumps(record), encoding="utf-8")
                    result_path.chmod(0o600)

                    with self.assertRaises(PermissionError):
                        store.load_internal_semantic_evidence(
                            (subject.subject_ref,), identity_literals=identities,
                        )

    def test_internal_semantic_loader_deletes_expired_records_without_returning_them(self) -> None:
        from community_os.coresignal_career_evaluation import (
            CoresignalCareerEvaluationStore,
        )

        subject = candidate()
        current = [NOW]
        with tempfile.TemporaryDirectory() as directory:
            store = CoresignalCareerEvaluationStore(
                Path(directory) / "protected" / "coresignal-career-evaluation",
                release_root=Path(directory) / "release", clock=lambda: current[0],
            )
            approval_sha256 = store.write_approval(
                bound_approval((subject,)), now=NOW,
            )
            store.put(
                candidate=subject, approval_sha256=approval_sha256,
                outcome="observed", career_evidence=career_evidence(),
                payload_sha256="a" * 64, retention_days=1,
            )
            result_path = store.results / store._record_name(subject.subject_ref)
            current[0] = NOW + timedelta(days=2)

            loaded = store.load_internal_semantic_evidence(
                (subject.subject_ref,), identity_literals=("Known Person",),
            )

            self.assertEqual(loaded, {})
            self.assertFalse(result_path.exists())

    def test_reopened_store_reads_only_scoped_subject_content_for_snapshot(self) -> None:
        from community_os.coresignal_career_evaluation import CoresignalCareerEvaluationStore

        requested = candidate(1)
        outsider = candidate(2)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "protected" / "coresignal-career-evaluation"
            release_root = Path(directory) / "release"
            store = CoresignalCareerEvaluationStore(
                root, release_root=release_root, clock=lambda: NOW,
            )
            approval_sha256 = store.write_approval(
                bound_approval((requested, outsider)), now=NOW,
            )
            for subject in (requested, outsider):
                store.put(
                    candidate=subject, approval_sha256=approval_sha256,
                    outcome="observed", career_evidence=career_evidence(),
                    payload_sha256=f"{subject.subject_ref[-1]}" * 64,
                    retention_days=7,
                )

            read_paths: list[Path] = []
            original_read_text = Path.read_text

            def record_read(path: Path, *args, **kwargs):
                read_paths.append(path)
                return original_read_text(path, *args, **kwargs)

            with patch.object(Path, "read_text", record_read):
                reopened = CoresignalCareerEvaluationStore(
                    root, release_root=release_root, clock=lambda: NOW,
                )
                reopened.build_coverage_snapshot((requested.subject_ref,))

            outsider_path = store.results / store._record_name(outsider.subject_ref)
            self.assertNotIn(outsider_path, read_paths)

    def test_coverage_snapshot_hash_binds_current_approval_and_content(self) -> None:
        from community_os.coresignal_career_evaluation import CoresignalCareerEvaluationStore

        subject = candidate()
        with tempfile.TemporaryDirectory() as directory:
            store = CoresignalCareerEvaluationStore(
                Path(directory) / "protected" / "coresignal-career-evaluation",
                release_root=Path(directory) / "release", clock=lambda: NOW,
            )
            first_approval = bound_approval((subject,))
            first_hash = store.write_approval(first_approval, now=NOW)
            store.put(
                candidate=subject, approval_sha256=first_hash,
                outcome="observed", career_evidence=career_evidence(),
                payload_sha256="a" * 64, retention_days=7,
            )
            first = store.build_coverage_snapshot((subject.subject_ref,))

            second_approval = bound_approval(
                (subject,), provider_terms_version="coresignal-self-service-2026-07-rev2",
            )
            second_hash = store.write_approval(second_approval, now=NOW)
            store.put(
                candidate=subject, approval_sha256=second_hash,
                outcome="observed", career_evidence=career_evidence(),
                payload_sha256="a" * 64, retention_days=7,
            )
            second = store.build_coverage_snapshot((subject.subject_ref,))
            self.assertEqual(first["career_evidence"], second["career_evidence"])
            self.assertNotEqual(first["snapshot_sha256"], second["snapshot_sha256"])

            store.put(
                candidate=subject, approval_sha256=second_hash,
                outcome="observed", career_evidence=career_evidence(
                    description="Built a different delivery system.",
                ), payload_sha256="b" * 64, retention_days=7,
            )
            third = store.build_coverage_snapshot((subject.subject_ref,))
            self.assertNotEqual(second["snapshot_sha256"], third["snapshot_sha256"])

    def test_coverage_snapshot_does_not_encode_subject_order_or_missing_subjects(self) -> None:
        from community_os.coresignal_career_evaluation import CoresignalCareerEvaluationStore

        first_subject = candidate(1)
        second_subject = candidate(2)
        missing_subject = candidate(3)
        cohort = (first_subject, second_subject, missing_subject)
        zulu_evidence = career_evidence(description="led zeta delivery evidence")
        alpha_evidence = career_evidence(description="led alpha delivery evidence")
        with tempfile.TemporaryDirectory() as directory:
            store = CoresignalCareerEvaluationStore(
                Path(directory) / "protected" / "coresignal-career-evaluation",
                release_root=Path(directory) / "release", clock=lambda: NOW,
            )
            approval_sha256 = store.write_approval(bound_approval(cohort), now=NOW)
            store.put(
                candidate=first_subject, approval_sha256=approval_sha256,
                outcome="observed", career_evidence=zulu_evidence,
                payload_sha256="a" * 64, retention_days=7,
            )
            store.put(
                candidate=second_subject, approval_sha256=approval_sha256,
                outcome="observed", career_evidence=alpha_evidence,
                payload_sha256="b" * 64, retention_days=7,
            )

            observed = store.build_coverage_snapshot((
                first_subject.subject_ref,
                second_subject.subject_ref,
            ))
            with_missing = store.build_coverage_snapshot((
                first_subject.subject_ref,
                second_subject.subject_ref,
                missing_subject.subject_ref,
            ))

            self.assertEqual(
                observed["career_evidence"],
                [alpha_evidence, zulu_evidence],
            )
            self.assertEqual(observed, with_missing)

    def test_coverage_snapshot_excludes_non_evidence_and_cleans_expired_records(self) -> None:
        from community_os.coresignal_career_evaluation import CoresignalCareerEvaluationStore

        subjects = tuple(candidate(index) for index in range(1, 7))
        current = [NOW]
        with tempfile.TemporaryDirectory() as directory:
            store = CoresignalCareerEvaluationStore(
                Path(directory) / "protected" / "coresignal-career-evaluation",
                release_root=Path(directory) / "release", clock=lambda: current[0],
            )
            approval = bound_approval(subjects)
            approval_sha256 = store.write_approval(approval, now=NOW)
            store.put(
                candidate=subjects[0], approval_sha256=approval_sha256,
                outcome="observed", career_evidence=career_evidence(),
                payload_sha256="a" * 64, retention_days=7,
            )
            # subjects[1] is intentionally missing.
            store.put(
                candidate=subjects[2], approval_sha256=approval_sha256,
                outcome="not_found", career_evidence=[],
                payload_sha256="b" * 64, retention_days=7,
            )
            store.put(
                candidate=subjects[3], approval_sha256=approval_sha256,
                outcome="projection_rejected", career_evidence=[],
                payload_sha256="c" * 64, retention_days=7,
            )
            store.put(
                candidate=subjects[4], approval_sha256=approval_sha256,
                outcome="observed", career_evidence=[],
                payload_sha256="d" * 64, retention_days=7,
            )
            store.put(
                candidate=subjects[5], approval_sha256=approval_sha256,
                outcome="observed", career_evidence=career_evidence(
                    description="Built delivery evidence that later expired.",
                ), payload_sha256="e" * 64, retention_days=1,
            )
            expired_path = store.results / store._record_name(subjects[5].subject_ref)
            current[0] = NOW + timedelta(days=2)

            snapshot = store.build_coverage_snapshot(
                subject.subject_ref for subject in subjects
            )

            self.assertEqual(snapshot["career_evidence"], [career_evidence()])
            self.assertFalse(expired_path.exists())

    def test_coverage_snapshot_fails_closed_for_invalid_store_state(self) -> None:
        from community_os.coresignal_career_evaluation import CoresignalCareerEvaluationStore

        subject = candidate()

        def initialized_store(directory: str):
            store = CoresignalCareerEvaluationStore(
                Path(directory) / "protected" / "coresignal-career-evaluation",
                release_root=Path(directory) / "release", clock=lambda: NOW,
            )
            approval = bound_approval((subject,))
            digest = store.write_approval(approval, now=NOW)
            store.put(
                candidate=subject, approval_sha256=digest,
                outcome="observed", career_evidence=career_evidence(),
                payload_sha256="a" * 64, retention_days=7,
            )
            return store

        for failure in (
            "missing_approval", "tampered_approval", "approval_symlink",
            "result_symlink", "duplicate_result_keys", "approval_permissions",
            "result_permissions", "directory_permissions",
        ):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                store = initialized_store(directory)
                approval_path = store.root / "approval.json"
                result_path = store.results / store._record_name(subject.subject_ref)
                if failure == "missing_approval":
                    approval_path.unlink()
                elif failure == "tampered_approval":
                    value = json.loads(approval_path.read_text(encoding="utf-8"))
                    value["purpose"] = "partner_profile_ranking"
                    approval_path.write_text(json.dumps(value), encoding="utf-8")
                    approval_path.chmod(0o600)
                elif failure == "approval_symlink":
                    target = store.root / "approval-target.json"
                    approval_path.replace(target)
                    approval_path.symlink_to(target)
                elif failure == "result_symlink":
                    target = store.root / "result-target.json"
                    result_path.replace(target)
                    result_path.symlink_to(target)
                elif failure == "duplicate_result_keys":
                    serialized = result_path.read_text(encoding="utf-8")
                    result_path.write_text(
                        serialized.replace(
                            '"outcome":"observed"',
                            '"outcome":"not_found","outcome":"observed"',
                            1,
                        ),
                        encoding="utf-8",
                    )
                    result_path.chmod(0o600)
                elif failure == "approval_permissions":
                    approval_path.chmod(0o644)
                elif failure == "result_permissions":
                    result_path.chmod(0o644)
                else:
                    store.results.chmod(0o755)

                read_paths: list[Path] = []
                original_read_text = Path.read_text

                def record_read(path: Path, *args, **kwargs):
                    read_paths.append(path)
                    return original_read_text(path, *args, **kwargs)

                with (
                    patch.object(Path, "read_text", record_read),
                    self.assertRaises(PermissionError),
                ):
                    store.build_coverage_snapshot((subject.subject_ref,))
                if failure == "approval_permissions":
                    self.assertNotIn(approval_path, read_paths)
                if failure in {"result_permissions", "directory_permissions"}:
                    self.assertNotIn(result_path, read_paths)

    def test_store_rejects_symlink_or_preexisting_unsafe_root(self) -> None:
        from community_os.coresignal_career_evaluation import CoresignalCareerEvaluationStore

        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            target = base / "target" / "coresignal-career-evaluation"
            target.mkdir(parents=True, mode=0o700)
            alias = base / "alias" / "coresignal-career-evaluation"
            alias.parent.mkdir()
            alias.symlink_to(target, target_is_directory=True)
            with self.assertRaises((PermissionError, ValueError)):
                CoresignalCareerEvaluationStore(
                    alias, release_root=base / "release", clock=lambda: NOW,
                )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "coresignal-career-evaluation"
            root.mkdir(mode=0o755)
            with self.assertRaises(PermissionError):
                CoresignalCareerEvaluationStore(
                    root, release_root=Path(directory) / "release", clock=lambda: NOW,
                )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "protected" / "coresignal-career-evaluation"
            release_root = Path(directory) / "release"
            store = CoresignalCareerEvaluationStore(
                root, release_root=release_root, clock=lambda: NOW,
            )
            approval_path = store.root / "approval.json"
            store.write_approval(bound_approval(), now=NOW)
            approval_path.chmod(0o644)
            with self.assertRaises(PermissionError):
                CoresignalCareerEvaluationStore(
                    root, release_root=release_root, clock=lambda: NOW,
                )

    def test_coverage_snapshot_rejects_invalid_or_duplicate_requested_subjects(self) -> None:
        from community_os.coresignal_career_evaluation import CoresignalCareerEvaluationStore

        subject = candidate()
        with tempfile.TemporaryDirectory() as directory:
            store = CoresignalCareerEvaluationStore(
                Path(directory) / "protected" / "coresignal-career-evaluation",
                release_root=Path(directory) / "release", clock=lambda: NOW,
            )
            store.write_approval(bound_approval((subject,)), now=NOW)
            for requested in (
                (), (subject.subject_ref, subject.subject_ref), ("case:v1:" + "a" * 64,),
                (["not-a-subject"],),
            ):
                with self.subTest(requested=requested), self.assertRaises(ValueError):
                    store.build_coverage_snapshot(requested)

            def oversized_subjects():
                for index in range(100_001):
                    yield f"pid:v1:{index:064x}"
                raise AssertionError("coverage loader consumed beyond its input bound")

            with self.assertRaises(ValueError):
                store.build_coverage_snapshot(oversized_subjects())


if __name__ == "__main__":
    unittest.main()
