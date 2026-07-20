from __future__ import annotations

from datetime import UTC, datetime, timedelta
import json
import os
from pathlib import Path
import tempfile
import unittest

from community_os.enrichment.transport import HttpResponse
from community_os.enrichment.transport import RetryableTransportError


NOW = datetime(2026, 7, 15, 1, tzinfo=UTC)


def approval_record(**overrides: object) -> dict[str, object]:
    record: dict[str, object] = {
        "evaluation_version": "coresignal-evaluation-v1",
        "notice_status": "not_sent",
        "purpose": "internal_provider_evaluation",
        "distribution": "internal_only",
        "source_scope": "applicant_supplied_linkedin",
        "sample_sha256": "a" * 64,
        "exclusions_sha256": "b" * 64,
        "sample_limit": 100,
        "provider_access_verified": True,
        "provider_terms_version": "coresignal-self-service-2026-07",
        "approved_by": "release_owner",
        "approval_id": "coresignal_eval_20260715",
        "approved_at": NOW.isoformat().replace("+00:00", "Z"),
        "expires_at": (NOW + timedelta(days=7)).isoformat().replace("+00:00", "Z"),
        "retention_days": 7,
    }
    record.update(overrides)
    return record


def bound_approval(candidates, **overrides: object):
    from community_os.coresignal_evaluation import (
        CoresignalEvaluationApproval, preview_evaluation_plan,
    )

    limit = int(overrides.get("sample_limit", 100))
    _plan, sample_sha256, exclusions_sha256 = preview_evaluation_plan(
        candidates, sample_limit=limit,
    )
    return CoresignalEvaluationApproval.from_record(approval_record(
        sample_sha256=sample_sha256,
        exclusions_sha256=exclusions_sha256,
        **overrides,
    ))


class CoresignalEvaluationTests(unittest.TestCase):
    def test_approval_is_exact_internal_only_and_short_lived(self) -> None:
        from community_os.coresignal_evaluation import CoresignalEvaluationApproval

        approval = CoresignalEvaluationApproval.from_record(approval_record())
        approval.authorize(now=NOW)
        self.assertEqual(approval.to_record(), approval_record())
        self.assertEqual(len(approval.authorization_hash(now=NOW)), 64)

        for change in (
            {"notice_status": "sent"}, {"distribution": "partner_report"},
            {"sample_limit": 101}, {"retention_days": 8},
            {"provider_access_verified": False},
            {"expires_at": (NOW + timedelta(days=8)).isoformat().replace("+00:00", "Z")},
        ):
            with self.subTest(change=change), self.assertRaises(PermissionError):
                CoresignalEvaluationApproval.from_record(
                    approval_record(**change)
                ).authorize(now=NOW)

        extra = approval_record()
        extra["participant_notice_version"] = "invented"
        with self.assertRaises(PermissionError):
            CoresignalEvaluationApproval.from_record(extra)

    def test_plan_uses_only_evidence_backed_priority_deduplicates_and_caps(self) -> None:
        from community_os.coresignal_evaluation import (
            CoresignalEvaluationApproval, EvaluationCandidate, build_evaluation_plan,
        )

        candidates = [
            EvaluationCandidate(
                subject_ref=f"pid:v1:{index:064x}",
                linkedin_url=f"https://www.linkedin.com/in/person-{index}",
                source_record_ref=f"source_application_{index}",
                priority=(
                    "checked_in" if index < 72 else
                    "accepted_not_checked_in" if index < 82 else "other"
                ),
            )
            for index in range(120)
        ]
        candidates.append(EvaluationCandidate(
            subject_ref="pid:v1:" + "f" * 64,
            linkedin_url="https://linkedin.com/in/person-90",
            source_record_ref="source_application_duplicate",
            priority="checked_in",
        ))
        approval = bound_approval(candidates)

        plan = build_evaluation_plan(candidates, approval=approval, now=NOW)

        self.assertEqual(len(plan), 100)
        self.assertEqual(plan[0].priority, "checked_in")
        self.assertEqual(sum(item.priority == "checked_in" for item in plan), 73)
        self.assertEqual(sum(item.priority == "accepted_not_checked_in" for item in plan), 10)
        self.assertEqual(sum(item.priority == "other" for item in plan), 17)
        self.assertEqual(len({item.linkedin_url for item in plan}), len(plan))
        with self.assertRaises(ValueError):
            EvaluationCandidate(
                subject_ref="pid:v1:" + "c" * 64,
                linkedin_url="https://linkedin.com/in/not-evidence-backed",
                source_record_ref="source_application_bad",
                priority="aggregate_only",
            )

    def test_store_is_isolated_and_runner_persists_only_minimized_facts(self) -> None:
        from community_os.coresignal_evaluation import (
            CoresignalEvaluationApproval, CoresignalEvaluationRunner,
            CoresignalEvaluationStore, EvaluationCandidate,
        )

        class FixtureTransport:
            def __init__(self) -> None:
                self.calls = 0

            def request(self, method, url, *, headers, timeout, max_bytes):
                self.calls += 1
                body = json.dumps({
                    "active_experience_title": "Senior Engineer at Secret Company",
                    "active_experience_management_level": "Senior",
                    "company_type": "Privately Held Startup",
                    "company_size_range": "11-50 employees",
                    "company_industry": "Software Development",
                    "experience": [{
                        "position_title": "Founder of Private Product",
                        "management_level": "Founder",
                        "active_experience": False,
                    }],
                    "full_name": "Sensitive Person",
                }).encode()
                return HttpResponse(200, {"Content-Type": "application/json"}, body, url)

        candidate = EvaluationCandidate(
            subject_ref="pid:v1:" + "c" * 64,
            linkedin_url="https://linkedin.com/in/sensitive-person",
            source_record_ref="source:application:001",
            priority="checked_in",
        )
        transport = FixtureTransport()
        with tempfile.TemporaryDirectory() as directory:
            release_root = Path(directory) / "release"
            release_root.mkdir()
            with self.assertRaises(ValueError):
                CoresignalEvaluationStore(
                    release_root / "coresignal-evaluation",
                    release_root=release_root, clock=lambda: NOW,
                )
            store = CoresignalEvaluationStore(
                Path(directory) / "protected" / "coresignal-evaluation",
                release_root=release_root, clock=lambda: NOW,
            )
            approval = bound_approval((candidate,), sample_limit=1)
            runner = CoresignalEvaluationRunner(
                transport=transport, store=store, pseudonym_secret=b"evaluation-secret",
                api_token="fixture-token", clock=lambda: NOW,
                source_verifier=lambda value: value == candidate,
            )
            report = runner.evaluate((candidate,), approval=approval)
            report_again = runner.evaluate((candidate,), approval=approval)

            self.assertEqual(transport.calls, 1)
            self.assertEqual(report, report_again)
            self.assertEqual(report["attempted"], 1)
            self.assertEqual(report["observed"], 1)
            self.assertEqual(report["coverage"]["seniority_known"], 1)
            self.assertEqual(report["coverage"]["founder_history"], 1)
            serialized = "\n".join(
                path.read_text(encoding="utf-8")
                for path in store.root.rglob("*.json")
            )
            for forbidden in (
                "sensitive-person", "Sensitive Person", "Secret Company",
                "Private Product", "linkedin.com", "full_name",
            ):
                self.assertNotIn(forbidden, serialized)
            self.assertEqual(os.stat(store.root).st_mode & 0o777, 0o700)
            for path in store.root.rglob("*.json"):
                self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)

    def test_runner_fails_closed_before_transport_and_handles_not_found(self) -> None:
        from community_os.coresignal_evaluation import (
            CoresignalEvaluationApproval, CoresignalEvaluationRunner,
            CoresignalEvaluationStore, EvaluationCandidate,
        )

        class NotFoundTransport:
            def __init__(self) -> None:
                self.calls = 0

            def request(self, method, url, *, headers, timeout, max_bytes):
                self.calls += 1
                return HttpResponse(404, {}, b'{"message":"not found"}', url)

        candidate = EvaluationCandidate(
            subject_ref="pid:v1:" + "d" * 64,
            linkedin_url="https://linkedin.com/in/not-found-person",
            source_record_ref="source:application:002",
            priority="accepted_not_checked_in",
        )
        with tempfile.TemporaryDirectory() as directory:
            store = CoresignalEvaluationStore(
                Path(directory) / "protected" / "coresignal-evaluation",
                release_root=Path(directory) / "release", clock=lambda: NOW,
            )
            transport = NotFoundTransport()
            runner = CoresignalEvaluationRunner(
                transport=transport, store=store, pseudonym_secret=b"evaluation-secret",
                api_token="fixture-token", clock=lambda: NOW,
                source_verifier=lambda value: value == candidate,
            )
            expired = CoresignalEvaluationApproval.from_record(approval_record(
                sample_limit=1,
                approved_at=(NOW - timedelta(days=8)).isoformat().replace("+00:00", "Z"),
                expires_at=(NOW - timedelta(days=1)).isoformat().replace("+00:00", "Z"),
            ))
            with self.assertRaises(PermissionError):
                runner.evaluate((candidate,), approval=expired)
            self.assertEqual(transport.calls, 0)

            wrong_sample = CoresignalEvaluationApproval.from_record(approval_record(sample_limit=1))
            with self.assertRaises(PermissionError):
                runner.evaluate((candidate,), approval=wrong_sample)
            self.assertEqual(transport.calls, 0)

            valid = bound_approval((candidate,), sample_limit=1)
            report = runner.evaluate((candidate,), approval=valid)
            self.assertEqual(transport.calls, 1)
            self.assertEqual(report["not_found"], 1)
            self.assertNotIn(candidate.subject_ref, json.dumps(report))

    def test_store_enforces_minimized_values_and_physically_deletes_expired_data(self) -> None:
        from community_os.coresignal_evaluation import (
            CoresignalEvaluationStore, EvaluationCandidate,
        )

        current = [NOW]
        candidate = EvaluationCandidate(
            subject_ref="pid:v1:" + "e" * 64,
            linkedin_url="https://linkedin.com/in/retention-person",
            source_record_ref="source:application:003",
            priority="other",
        )
        safe_facts = {
            "company_category": "startup", "founder_history": True,
            "seniority": "senior", "title_category": "software_engineering",
        }
        with tempfile.TemporaryDirectory() as directory:
            store = CoresignalEvaluationStore(
                Path(directory) / "protected" / "coresignal-evaluation",
                release_root=Path(directory) / "release", clock=lambda: current[0],
            )
            record = store.put(
                candidate=candidate, approval_sha256="a" * 64,
                outcome="observed", evidence_ref="evidence:coresignal:" + "b" * 64,
                facts=safe_facts, retention_days=7,
            )
            with self.assertRaises(ValueError):
                store.put(
                    candidate=candidate, approval_sha256="a" * 64,
                    outcome="observed", evidence_ref="evidence:coresignal:" + "b" * 64,
                    facts={**safe_facts, "company_category": "https://linkedin.com/in/leak"},
                    retention_days=365,
                )
            with self.assertRaises(ValueError):
                store.write_report({"leaked_url": "https://linkedin.com/in/leak"})

            report = {
                "approval_sha256": "a" * 64, "attempted": 1,
                "coverage": {
                    "company_category_known": 1, "founder_history": 1,
                    "seniority_known": 1, "software_engineering_title": 1,
                },
                "evaluation_version": "coresignal-evaluation-v1",
                "expires_at": record["expires_at"], "generated_at": record["collected_at"],
                "not_found": 0, "observed": 1,
                "priority": {"checked_in": 0, "accepted_not_checked_in": 0, "other": 1},
                "report_version": store.REPORT_VERSION,
            }
            store.write_report(report)
            current[0] = NOW + timedelta(days=8)
            store = CoresignalEvaluationStore(
                Path(directory) / "protected" / "coresignal-evaluation",
                release_root=Path(directory) / "release", clock=lambda: current[0],
            )
            receipt = json.loads(
                (store.root / "cleanup-receipt.json").read_text(encoding="utf-8")
            )

            self.assertEqual(receipt["deleted_count"], 2)
            self.assertFalse(any(store.results.glob("*.json")))
            self.assertFalse((store.root / "quality-report.json").exists())
            receipt_text = (store.root / "cleanup-receipt.json").read_text(encoding="utf-8")
            self.assertNotIn(candidate.subject_ref, receipt_text)
            self.assertNotIn("retention-person", receipt_text)
            self.assertEqual(set(receipt), {
                "assets_sha256", "cleanup_version", "deleted_at", "deleted_count",
            })

    def test_tampered_read_cannot_extend_retention_or_inject_evidence_text(self) -> None:
        from community_os.coresignal_evaluation import (
            CoresignalEvaluationStore, EvaluationCandidate,
        )

        candidate = EvaluationCandidate(
            subject_ref="pid:v1:" + "9" * 64,
            linkedin_url="https://linkedin.com/in/tamper-person",
            source_record_ref="source:application:005",
            priority="other",
        )
        with tempfile.TemporaryDirectory() as directory:
            store = CoresignalEvaluationStore(
                Path(directory) / "protected" / "coresignal-evaluation",
                release_root=Path(directory) / "release", clock=lambda: NOW,
            )
            store.put(
                candidate=candidate, approval_sha256="a" * 64,
                outcome="observed", evidence_ref="evidence:coresignal:" + "b" * 64,
                facts={
                    "company_category": "startup", "founder_history": False,
                    "seniority": "senior", "title_category": "software_engineering",
                }, retention_days=7,
            )
            path = next(store.results.glob("*.json"))
            record = json.loads(path.read_text(encoding="utf-8"))
            record["evidence_ref"] = "https://linkedin.com/in/leak"
            record["expires_at"] = (NOW + timedelta(days=365)).isoformat().replace("+00:00", "Z")
            path.write_text(json.dumps(record), encoding="utf-8")

            with self.assertRaises(PermissionError):
                store.get(candidate.subject_ref, approval_sha256="a" * 64)

    def test_uncertain_paid_attempt_is_not_retried_and_provenance_is_reverified(self) -> None:
        from community_os.coresignal_evaluation import (
            CoresignalEvaluationRunner, CoresignalEvaluationStore, EvaluationCandidate,
        )

        class FixtureTransport:
            def __init__(self) -> None:
                self.calls = 0

            def request(self, method, url, *, headers, timeout, max_bytes):
                self.calls += 1
                return HttpResponse(200, {}, json.dumps({
                    "active_experience_title": "Engineer", "experience": [],
                }).encode(), url)

        candidate = EvaluationCandidate(
            subject_ref="pid:v1:" + "f" * 64,
            linkedin_url="https://linkedin.com/in/uncertain-person",
            source_record_ref="source:application:004",
            priority="checked_in",
        )
        approval = bound_approval((candidate,), sample_limit=1)
        with tempfile.TemporaryDirectory() as directory:
            store = CoresignalEvaluationStore(
                Path(directory) / "protected" / "coresignal-evaluation",
                release_root=Path(directory) / "release", clock=lambda: NOW,
            )
            transport = FixtureTransport()
            denied = CoresignalEvaluationRunner(
                transport=transport, store=store, pseudonym_secret=b"evaluation-secret",
                api_token="fixture-token", clock=lambda: NOW,
                source_verifier=lambda _value: False,
            )
            with self.assertRaises(PermissionError):
                denied.evaluate((candidate,), approval=approval)
            self.assertEqual(transport.calls, 0)

            runner = CoresignalEvaluationRunner(
                transport=transport, store=store, pseudonym_secret=b"evaluation-secret",
                api_token="fixture-token", clock=lambda: NOW,
                source_verifier=lambda value: value == candidate,
            )
            original_put = store.put
            store.put = lambda **_kwargs: (_ for _ in ()).throw(OSError("disk failed"))
            with self.assertRaises(OSError):
                runner.evaluate((candidate,), approval=approval)
            store.put = original_put
            self.assertEqual(transport.calls, 1)
            with self.assertRaises(PermissionError):
                runner.evaluate((candidate,), approval=approval)
            self.assertEqual(transport.calls, 1)

    def test_approval_is_rechecked_before_each_transport(self) -> None:
        from community_os.coresignal_evaluation import (
            CoresignalEvaluationRunner, CoresignalEvaluationStore, EvaluationCandidate,
        )

        current = [NOW]
        candidates = tuple(EvaluationCandidate(
            subject_ref=f"pid:v1:{index + 10:064x}",
            linkedin_url=f"https://linkedin.com/in/expiry-{index}",
            source_record_ref=f"source:application:expiry_{index}",
            priority="checked_in",
        ) for index in range(2))

        class AdvancingTransport:
            def __init__(self) -> None:
                self.calls = 0

            def request(self, method, url, *, headers, timeout, max_bytes):
                self.calls += 1
                current[0] = NOW + timedelta(minutes=2)
                return HttpResponse(200, {}, json.dumps({
                    "active_experience_title": "Engineer", "experience": [],
                }).encode(), url)

        approval = bound_approval(
            candidates, sample_limit=2,
            expires_at=(NOW + timedelta(minutes=1)).isoformat().replace("+00:00", "Z"),
        )
        with tempfile.TemporaryDirectory() as directory:
            transport = AdvancingTransport()
            store = CoresignalEvaluationStore(
                Path(directory) / "protected" / "coresignal-evaluation",
                release_root=Path(directory) / "release", clock=lambda: current[0],
            )
            runner = CoresignalEvaluationRunner(
                transport=transport, store=store, pseudonym_secret=b"evaluation-secret",
                api_token="fixture-token", clock=lambda: current[0],
                source_verifier=lambda value: value in candidates,
            )
            with self.assertRaises(PermissionError):
                runner.evaluate(candidates, approval=approval)
            self.assertEqual(transport.calls, 1)

    def test_ambiguous_transport_failure_is_never_automatically_retried(self) -> None:
        from community_os.coresignal_evaluation import (
            CoresignalEvaluationRunner, CoresignalEvaluationStore, EvaluationCandidate,
        )

        class AmbiguousTransport:
            def __init__(self) -> None:
                self.calls = 0

            def request(self, method, url, *, headers, timeout, max_bytes):
                self.calls += 1
                if self.calls == 1:
                    raise RetryableTransportError("response lost after request")
                return HttpResponse(200, {}, json.dumps({
                    "active_experience_title": "Engineer", "experience": [],
                }).encode(), url)

        candidate = EvaluationCandidate(
            subject_ref="pid:v1:" + "8" * 64,
            linkedin_url="https://linkedin.com/in/no-retry-person",
            source_record_ref="source:application:006",
            priority="checked_in",
        )
        approval = bound_approval((candidate,), sample_limit=1)
        with tempfile.TemporaryDirectory() as directory:
            transport = AmbiguousTransport()
            store = CoresignalEvaluationStore(
                Path(directory) / "protected" / "coresignal-evaluation",
                release_root=Path(directory) / "release", clock=lambda: NOW,
            )
            runner = CoresignalEvaluationRunner(
                transport=transport, store=store, pseudonym_secret=b"evaluation-secret",
                api_token="fixture-token", clock=lambda: NOW,
                source_verifier=lambda value: value == candidate,
            )
            with self.assertRaises(RetryableTransportError):
                runner.evaluate((candidate,), approval=approval)
            self.assertEqual(transport.calls, 1)
            with self.assertRaises(PermissionError):
                runner.evaluate((candidate,), approval=approval)
            self.assertEqual(transport.calls, 1)

    def test_bounded_canary_resumes_without_repeating_completed_records(self) -> None:
        from community_os.coresignal_evaluation import (
            CoresignalEvaluationRunner, CoresignalEvaluationStore, EvaluationCandidate,
        )

        class NotFoundTransport:
            def __init__(self) -> None:
                self.calls = 0

            def request(self, method, url, *, headers, timeout, max_bytes):
                self.calls += 1
                return HttpResponse(404, {}, b"{}", url)

        candidates = tuple(EvaluationCandidate(
            subject_ref=f"pid:v1:{index + 20:064x}",
            linkedin_url=f"https://linkedin.com/in/canary-{index}",
            source_record_ref=f"source:application:canary_{index}",
            priority="checked_in",
        ) for index in range(2))
        approval = bound_approval(candidates, sample_limit=2)
        with tempfile.TemporaryDirectory() as directory:
            transport = NotFoundTransport()
            store = CoresignalEvaluationStore(
                Path(directory) / "protected" / "coresignal-evaluation",
                release_root=Path(directory) / "release", clock=lambda: NOW,
            )
            runner = CoresignalEvaluationRunner(
                transport=transport, store=store, pseudonym_secret=b"evaluation-secret",
                api_token="fixture-token", clock=lambda: NOW,
                source_verifier=lambda value: value in candidates,
            )
            canary = runner.evaluate(candidates, approval=approval, max_new_records=1)
            complete = runner.evaluate(candidates, approval=approval)

        self.assertEqual(canary["attempted"], 1)
        self.assertEqual(complete["attempted"], 2)
        self.assertEqual(transport.calls, 2)

    def test_definitive_4xx_clears_attempt_and_reports_only_status(self) -> None:
        from community_os.coresignal_evaluation import (
            CoresignalEvaluationRunner, CoresignalEvaluationStore, EvaluationCandidate,
        )

        class UnauthorizedTransport:
            def __init__(self) -> None:
                self.calls = 0

            def request(self, method, url, *, headers, timeout, max_bytes):
                self.calls += 1
                return HttpResponse(401, {}, b'{"private":"do not expose"}', url)

        candidate = EvaluationCandidate(
            subject_ref="pid:v1:" + "7" * 64,
            linkedin_url="https://linkedin.com/in/unauthorized-person",
            source_record_ref="source:application:007",
            priority="checked_in",
        )
        approval = bound_approval((candidate,), sample_limit=1)
        with tempfile.TemporaryDirectory() as directory:
            transport = UnauthorizedTransport()
            store = CoresignalEvaluationStore(
                Path(directory) / "protected" / "coresignal-evaluation",
                release_root=Path(directory) / "release", clock=lambda: NOW,
            )
            runner = CoresignalEvaluationRunner(
                transport=transport, store=store, pseudonym_secret=b"evaluation-secret",
                api_token="fixture-token", clock=lambda: NOW,
                source_verifier=lambda value: value == candidate,
            )
            for _attempt in range(2):
                with self.assertRaisesRegex(PermissionError, "status 401") as caught:
                    runner.evaluate((candidate,), approval=approval)
                self.assertNotIn("private", str(caught.exception))

        self.assertEqual(transport.calls, 2)

    def test_internal_aggregate_is_group_safe_and_contains_no_subjects(self) -> None:
        from community_os.coresignal_evaluation import (
            CoresignalEvaluationStore, build_internal_evaluation_aggregate,
        )

        records = []
        for index in range(10):
            observed = index < 8
            records.append({
                "subject_ref": f"pid:v1:{index:064x}",
                "priority": "accepted_not_checked_in",
                "outcome": "observed" if observed else "not_found",
                "facts": {
                    "company_category": "enterprise" if index < 5 else "unknown",
                    "founder_history": index < 5,
                    "seniority": "founder" if index < 5 else "unknown",
                    "title_category": "software_engineering" if index < 5 else "unknown",
                },
            })

        aggregate = build_internal_evaluation_aggregate(records, minimum_group_size=5)

        serialized = json.dumps(aggregate, sort_keys=True)
        self.assertNotIn("pid:v1", serialized)
        self.assertNotIn("subject_ref", serialized)
        cohort = aggregate["cohorts"]["accepted_not_checked_in"]
        self.assertIsNone(cohort["observed"]["value"])
        self.assertIsNone(cohort["not_found"]["value"])
        company = aggregate["dimensions"]["company_context"]
        self.assertEqual(company["enterprise"]["value"], 5)
        self.assertEqual(company["unknown_or_other"]["value"], 5)

        with tempfile.TemporaryDirectory() as directory:
            store = CoresignalEvaluationStore(
                Path(directory) / "protected" / "coresignal-evaluation",
                release_root=Path(directory) / "release", clock=lambda: NOW,
            )
            stored = store.write_internal_aggregate(records, minimum_group_size=5)
            path = store.root / "internal-aggregate.json"
            self.assertEqual(stored, aggregate)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(json.loads(path.read_text(encoding="utf-8")), aggregate)

    def test_event_candidates_use_exact_attendance_evidence_and_no_aggregate_correction(self) -> None:
        from community_os.coresignal_evaluation import build_event_evaluation_candidates

        applications = [
            {
                "external_id": f"guest-{index}",
                "email": f"person-{index}@example.org",
                "linkedin": (
                    "" if index == 4 else
                    "https://linkedin.com/company/not-a-person" if index == 6 else
                    f"https://linkedin.com/in/person-{index}"
                ),
            }
            for index in range(7)
        ]
        attendance = [
            {"email": "person-0@example.org", "accepted": True, "checked_in": True},
            {"email": "person-1@example.org", "accepted": True, "checked_in": True},
            {"email": "person-2@example.org", "accepted": True, "checked_in": False},
            {"email": "not-an-applicant@example.org", "accepted": True, "checked_in": False},
        ]
        candidates = build_event_evaluation_candidates(
            applications, attendance, pseudonym_secret=b"candidate-secret",
        )

        self.assertEqual(len(candidates), 5)
        self.assertEqual(sum(item.priority == "checked_in" for item in candidates), 2)
        self.assertEqual(sum(item.priority == "accepted_not_checked_in" for item in candidates), 1)
        self.assertEqual(sum(item.priority == "other" for item in candidates), 2)
        self.assertTrue(all(item.source_record_ref.startswith("source:application:") for item in candidates))
        self.assertNotIn("person-4", json.dumps([item.linkedin_url for item in candidates]))

        with self.assertRaises(ValueError):
            build_event_evaluation_candidates(
                applications,
                attendance + [{
                    "email": "person-3@example.org", "accepted": False, "checked_in": True,
                }],
                pseudonym_secret=b"candidate-secret",
            )


if __name__ == "__main__":
    unittest.main()
