from __future__ import annotations

from datetime import UTC, datetime, timedelta
import json
from pathlib import Path
import tempfile
import unittest

from community_os.enrichment.github_assessment import (
    ASSESSMENT_FIELDS,
    GitHubProjectAssessor,
    MODEL,
    PROJECT_FIELDS,
    PROMPT_VERSION,
)
from community_os.enrichment.cache import CanonicalJsonCache
from community_os.github_evaluation import (
    GitHubSemanticEvaluationTransport,
    GitHubSemanticEvaluationApproval,
    GitHubSemanticEvaluationStore,
    cleanup_expired_github_evaluation,
    build_internal_github_aggregate,
)
from community_os.enrichment.transport import HttpResponse


NOW = datetime(2026, 7, 15, 12, tzinfo=UTC)
HASH_A = "a" * 64
HASH_B = "b" * 64
HASH_C = "c" * 64


def approval_record(**overrides: object) -> dict[str, object]:
    record: dict[str, object] = {
        "evaluation_version": "github-semantic-evaluation-v1",
        "distribution": "internal_only_pending_human_review",
        "source_scope": "applicant_supplied_public_github",
        "model": MODEL,
        "prompt_version": PROMPT_VERSION,
        "cache_identity": GitHubProjectAssessor.cache_identity,
        "project_vector_fields": sorted(PROJECT_FIELDS),
        "assessment_fields": sorted(ASSESSMENT_FIELDS),
        "processing_region": "global",
        "retention_mode": "default_abuse_monitoring_30d",
        "store": False,
        "reasoning_effort": "none",
        "source_file_sha256": HASH_A,
        "candidate_set_sha256": HASH_B,
        "github_authorization_sha256": HASH_C,
        "approved_by": "release_owner",
        "approval_id": "release-owner-github-semantic-evaluation-20260715",
        "approved_at": NOW.isoformat(),
        "expires_at": (NOW + timedelta(days=6)).isoformat(),
        "retention_days": 6,
        "canary_size": 5,
        "max_provider_attempts": 597,
    }
    record.update(overrides)
    return record


def semantic_result(**overrides: object) -> dict[str, object]:
    result: dict[str, object] = {
        "evidence_strength": "moderate",
        "maintenance": "active",
        "external_validation": "limited",
        "productization": "moderate",
        "categories": ["backend", "data_ai"],
        "reason_codes": ["multiple_projects", "recent_activity"],
        "confidence_state": "medium",
        "review_state": "human_review_required",
    }
    result.update(overrides)
    return result


def github_result(**overrides: object) -> dict[str, object]:
    result: dict[str, object] = {
        "account_age_days": 1200,
        "evidence_ref": "evidence:github:" + "d" * 64,
        "forks_received": 7,
        "last_public_update": "2026-07-01",
        "owned_public_repos_sampled": 8,
        "project_assessment": semantic_result(),
        "public_repos": 10,
        "recently_active_repos": 4,
        "state": "observed",
        "stars_received": 30,
        "technology_codes": ["javascript_typescript", "python"],
    }
    result.update(overrides)
    return result


def write_approval(path: Path, **overrides: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(approval_record(**overrides)), encoding="utf-8")
    path.chmod(0o600)


class GitHubSemanticEvaluationApprovalTests(unittest.TestCase):
    def test_loads_only_preexisting_exact_approval_and_returns_stable_hash(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "approval.json"
            path.write_text(json.dumps(approval_record()), encoding="utf-8")

            approval, first_hash = GitHubSemanticEvaluationApproval.load(path, now=NOW)
            loaded_again, second_hash = GitHubSemanticEvaluationApproval.load(path, now=NOW)

        self.assertEqual(approval.to_record(), approval_record())
        self.assertEqual(loaded_again, approval)
        self.assertEqual(first_hash, second_hash)
        self.assertEqual(len(first_hash), 64)

    def test_rejects_missing_extra_or_mismatched_approval_fields(self) -> None:
        invalid = [
            {key: value for key, value in approval_record().items() if key != "model"},
            {**approval_record(), "unexpected": True},
            approval_record(model="gpt-5.6-terra"),
            approval_record(project_vector_fields=[*sorted(PROJECT_FIELDS), "name"]),
            approval_record(assessment_fields=[*sorted(ASSESSMENT_FIELDS), "summary"]),
            approval_record(processing_region="eu"),
            approval_record(retention_mode="zero_data_retention"),
            approval_record(store=True),
            approval_record(reasoning_effort="low"),
            approval_record(source_file_sha256="short"),
            approval_record(canary_size=4),
            approval_record(max_provider_attempts=598),
            approval_record(retention_days=0),
            approval_record(approved_by="codex"),
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "approval.json"
            for value in invalid:
                path.write_text(json.dumps(value), encoding="utf-8")
                with self.assertRaises(PermissionError):
                    GitHubSemanticEvaluationApproval.load(path, now=NOW)


class GitHubSemanticEvaluationStoreTests(unittest.TestCase):
    def _store(
        self, directory: str, *, clock=lambda: NOW,
    ) -> GitHubSemanticEvaluationStore:
        root = Path(directory) / "github-semantic-evaluation"
        approval_path = root / "approval.json"
        write_approval(approval_path)
        return GitHubSemanticEvaluationStore(
            root, release_root=Path(directory) / "protected-release",
            approval_path=approval_path, clock=clock,
            source_file_sha256=HASH_A, candidate_set_sha256=HASH_B,
            github_authorization_sha256=HASH_C,
        )

    def test_requires_dedicated_isolated_root_and_restrictive_modes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "github-semantic-evaluation"
            write_approval(root / "approval.json")
            with self.assertRaises(ValueError):
                GitHubSemanticEvaluationStore(
                    Path(directory) / "wrong-name",
                    release_root=Path(directory) / "release",
                    approval_path=root / "approval.json", clock=lambda: NOW,
                    source_file_sha256=HASH_A, candidate_set_sha256=HASH_B,
                    github_authorization_sha256=HASH_C,
                )
            with self.assertRaises(ValueError):
                GitHubSemanticEvaluationStore(
                    root, release_root=root / "release",
                    approval_path=root / "approval.json", clock=lambda: NOW,
                    source_file_sha256=HASH_A, candidate_set_sha256=HASH_B,
                    github_authorization_sha256=HASH_C,
                )

            with self.assertRaises(PermissionError):
                GitHubSemanticEvaluationStore(
                    root, release_root=Path(directory) / "release",
                    approval_path=root / "approval.json", clock=lambda: NOW,
                    source_file_sha256="f" * 64, candidate_set_sha256=HASH_B,
                    github_authorization_sha256=HASH_C,
                )

            store = self._store(directory)

            self.assertEqual(store.root.stat().st_mode & 0o777, 0o700)
            self.assertEqual(store.results.stat().st_mode & 0o777, 0o700)
            self.assertEqual(store.attempts.stat().st_mode & 0o777, 0o700)
            self.assertEqual((store.root / "cache").stat().st_mode & 0o777, 0o700)

    def test_writes_exact_validated_envelope_and_update_never_extends_expiry(self) -> None:
        current = [NOW]
        subject = "pid:v1:" + "1" * 64
        with tempfile.TemporaryDirectory() as directory:
            store = self._store(directory, clock=lambda: current[0])
            first = store.put(subject_ref=subject, github_result=github_result())
            current[0] = NOW + timedelta(days=1)
            updated = store.put(
                subject_ref=subject,
                github_result=github_result(stars_received=31),
            )
            loaded = store.get(subject)

            path = next(store.results.glob("*.json"))
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

        self.assertEqual(set(first), {
            "approval_sha256", "created_at", "expires_at", "github_result",
            "record_version", "subject_ref", "updated_at",
        })
        self.assertEqual(updated["created_at"], first["created_at"])
        self.assertEqual(updated["expires_at"], first["expires_at"])
        self.assertNotEqual(updated["updated_at"], first["updated_at"])
        self.assertEqual(loaded, updated)
        self.assertEqual(loaded["github_result"]["stars_received"], 31)

    def test_rejects_direct_identifiers_urls_text_and_unreviewed_assessment(self) -> None:
        unsafe_results = [
            github_result(username="jane"),
            github_result(profile_url="https://github.com/jane"),
            github_result(summary="Jane built a medical product"),
            github_result(technology_codes=["https://example.com/person"]),
            github_result(project_assessment=semantic_result(review_state="ready")),
            github_result(project_assessment=semantic_result(summary="named project")),
        ]
        with tempfile.TemporaryDirectory() as directory:
            store = self._store(directory)
            for index, result in enumerate(unsafe_results):
                with self.assertRaises(ValueError):
                    store.put(
                        subject_ref="pid:v1:" + f"{index + 1:064x}",
                        github_result=result,
                    )
            self.assertEqual(list(store.results.glob("*.json")), [])

    def test_accepts_strict_unknown_result_without_assessment(self) -> None:
        subject = "pid:v1:" + "2" * 64
        with tempfile.TemporaryDirectory() as directory:
            store = self._store(directory)
            record = store.put(subject_ref=subject, github_result={
                "reason_code": "profile_not_found", "state": "unknown",
            })
        self.assertEqual(record["github_result"]["state"], "unknown")

    def test_internal_aggregate_is_group_safe_pending_and_identifier_free(self) -> None:
        records = []
        for index in range(10):
            assessment = semantic_result(
                evidence_strength=("strong" if index < 2 else "moderate" if index < 5 else "limited"),
                maintenance="active",
                external_validation="limited",
                productization="moderate",
                confidence_state="medium",
            )
            records.append({
                "subject_ref": "pid:v1:" + f"{index + 1:064x}",
                "github_result": github_result(project_assessment=assessment),
            })

        aggregate = build_internal_github_aggregate(records, minimum_group_size=5)

        serialized = json.dumps(aggregate, sort_keys=True)
        self.assertNotIn("pid:v1", serialized)
        self.assertNotIn("subject_ref", serialized)
        self.assertFalse(aggregate["release_eligible"])
        evidence = aggregate["dimensions"]["evidence_strength"]
        self.assertEqual(evidence["moderate_or_strong"]["value"], 5)
        self.assertEqual(evidence["limited"]["value"], 5)

    def test_sixth_record_requires_current_five_record_canary_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = self._store(directory)
            for index in range(5):
                store.put(
                    subject_ref="pid:v1:" + f"{index + 1:064x}",
                    github_result=github_result(),
                )
            with self.assertRaises(PermissionError):
                store.put(
                    subject_ref="pid:v1:" + f"{6:064x}",
                    github_result=github_result(),
                )

            receipt = store.write_canary_receipt(
                reviewed_by="codex_proof_for_me", quality_decision="accepted",
            )
            sixth = store.put(
                subject_ref="pid:v1:" + f"{6:064x}",
                github_result=github_result(),
            )

        self.assertEqual(receipt["record_count"], 5)
        self.assertEqual(sixth["subject_ref"], "pid:v1:" + f"{6:064x}")

    def test_changed_canary_invalidates_receipt_before_expansion(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = self._store(directory)
            for index in range(5):
                store.put(
                    subject_ref="pid:v1:" + f"{index + 1:064x}",
                    github_result=github_result(),
                )
            store.write_canary_receipt(
                reviewed_by="codex_proof_for_me", quality_decision="accepted",
            )
            store.put(
                subject_ref="pid:v1:" + f"{1:064x}",
                github_result=github_result(stars_received=99),
            )

            with self.assertRaises(PermissionError):
                store.put(
                    subject_ref="pid:v1:" + f"{6:064x}",
                    github_result=github_result(),
                )

    def test_record_expiry_is_exact_and_expired_record_cannot_be_updated(self) -> None:
        current = [NOW]
        subject = "pid:v1:" + "e" * 64
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "github-semantic-evaluation"
            write_approval(
                root / "approval.json",
                expires_at=(NOW + timedelta(days=7)).isoformat(), retention_days=1,
            )
            store = GitHubSemanticEvaluationStore(
                root, release_root=Path(directory) / "release",
                approval_path=root / "approval.json", clock=lambda: current[0],
                source_file_sha256=HASH_A, candidate_set_sha256=HASH_B,
                github_authorization_sha256=HASH_C,
            )
            record = store.put(subject_ref=subject, github_result=github_result())
            self.assertEqual(
                record["expires_at"],
                (NOW + timedelta(days=1)).isoformat().replace("+00:00", "Z"),
            )
            current[0] = NOW + timedelta(days=1, seconds=1)
            with self.assertRaises(PermissionError):
                store.put(subject_ref=subject, github_result=github_result(stars_received=31))

    def test_attempt_ledger_is_durable_pretransport_and_enforces_ceiling(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "github-semantic-evaluation"
            write_approval(root / "approval.json", max_provider_attempts=2)
            store = GitHubSemanticEvaluationStore(
                root, release_root=Path(directory) / "release",
                approval_path=root / "approval.json", clock=lambda: NOW,
                source_file_sha256=HASH_A, candidate_set_sha256=HASH_B,
                github_authorization_sha256=HASH_C,
            )

            self.assertEqual(store.begin_provider_attempt(), 1)
            self.assertEqual(store.begin_provider_attempt(), 2)
            with self.assertRaises(PermissionError):
                store.begin_provider_attempt()

            entries = sorted(store.attempts.glob("*.json"))
            self.assertEqual(len(entries), 2)
            self.assertTrue(all(path.stat().st_mode & 0o777 == 0o600 for path in entries))
            self.assertEqual(
                [json.loads(path.read_text())["attempt_number"] for path in entries],
                [1, 2],
            )

    def test_transport_reserves_durable_attempt_before_every_openai_request(self) -> None:
        observed_attempt_counts: list[int] = []

        class UnderlyingTransport:
            def request(
                self, *, headers: dict[str, str], body: bytes, timeout: float,
                max_bytes: int,
            ) -> HttpResponse:
                del headers, body, timeout, max_bytes
                observed_attempt_counts.append(len(list(store.attempts.glob("*.json"))))
                return HttpResponse(200, {}, b"{}", "https://api.openai.com/v1/responses")

        with tempfile.TemporaryDirectory() as directory:
            store = self._store(directory)
            transport = GitHubSemanticEvaluationTransport(
                store=store, transport=UnderlyingTransport(),
            )
            transport.request(headers={}, body=b"{}", timeout=1.0, max_bytes=100)
            transport.request(headers={}, body=b"{}", timeout=1.0, max_bytes=100)

        self.assertEqual(observed_attempt_counts, [1, 2])

    def test_attempt_ledger_persists_for_full_approval_window_not_result_retention(self) -> None:
        current = [NOW]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "github-semantic-evaluation"
            write_approval(
                root / "approval.json", max_provider_attempts=1,
                retention_days=1, expires_at=(NOW + timedelta(days=7)).isoformat(),
            )
            store = GitHubSemanticEvaluationStore(
                root, release_root=Path(directory) / "release",
                approval_path=root / "approval.json", clock=lambda: current[0],
                source_file_sha256=HASH_A, candidate_set_sha256=HASH_B,
                github_authorization_sha256=HASH_C,
            )
            store.begin_provider_attempt()
            current[0] = NOW + timedelta(days=2)

            store.cleanup_expired()

            self.assertEqual(len(list(store.attempts.glob("*.json"))), 1)
            with self.assertRaises(PermissionError):
                store.begin_provider_attempt()

    def test_malformed_attempt_cannot_reset_the_durable_budget(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = self._store(directory)
            store.begin_provider_attempt()
            attempt = next(store.attempts.glob("*.json"))
            attempt.write_text("{}", encoding="utf-8")

            with self.assertRaises(PermissionError):
                store.cleanup_expired()

            self.assertTrue(attempt.exists())

    def test_scheduled_cleanup_works_after_approval_expiry_and_removes_caches(self) -> None:
        current = [NOW]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "github-semantic-evaluation"
            release = Path(directory) / "release"
            write_approval(
                root / "approval.json",
                expires_at=(NOW + timedelta(days=1)).isoformat(), retention_days=1,
            )
            store = GitHubSemanticEvaluationStore(
                root, release_root=release, approval_path=root / "approval.json",
                clock=lambda: current[0], source_file_sha256=HASH_A,
                candidate_set_sha256=HASH_B, github_authorization_sha256=HASH_C,
            )
            store.put(
                subject_ref="pid:v1:" + "d" * 64,
                github_result=github_result(),
            )
            cache = root / "cache" / "github"
            cache.mkdir(parents=True)
            (cache / "transient.json").write_text("{}", encoding="utf-8")
            current[0] = NOW + timedelta(days=1, seconds=1)

            receipt = cleanup_expired_github_evaluation(
                root, release_root=release, now=current[0],
            )

            self.assertEqual(list(store.results.glob("*.json")), [])
            self.assertFalse((cache / "transient.json").exists())
            self.assertGreaterEqual(receipt["deleted_count"], 2)

    def test_scheduled_cleanup_deletes_data_when_approval_is_corrupt(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "github-semantic-evaluation"
            release = Path(directory) / "release"
            root.mkdir(parents=True)
            approval_path = root / "approval.json"
            approval_path.write_text("not-json", encoding="utf-8")
            results = root / "results"
            cache = root / "cache" / "github-assessment"
            results.mkdir(parents=True)
            cache.mkdir(parents=True)
            (results / "person.json").write_text("{}", encoding="utf-8")
            (cache / "transient.json").write_text("{}", encoding="utf-8")

            receipt = cleanup_expired_github_evaluation(
                root, release_root=release, now=NOW,
            )

            self.assertTrue(approval_path.exists())
            self.assertFalse((results / "person.json").exists())
            self.assertFalse((cache / "transient.json").exists())
            self.assertEqual(receipt["deleted_count"], 2)

    def test_scheduled_cleanup_deletes_data_when_approval_scope_is_invalid(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "github-semantic-evaluation"
            release = Path(directory) / "release"
            approval_path = root / "approval.json"
            write_approval(
                approval_path,
                expires_at=(NOW + timedelta(days=7)).isoformat(),
            )
            approval = json.loads(approval_path.read_text(encoding="utf-8"))
            approval["distribution"] = "corrupt_scope"
            approval_path.write_text(json.dumps(approval), encoding="utf-8")
            results = root / "results"
            results.mkdir(parents=True)
            result_path = results / "person.json"
            result_path.write_text("{}", encoding="utf-8")

            receipt = cleanup_expired_github_evaluation(
                root, release_root=release, now=NOW,
            )

            self.assertFalse(result_path.exists())
            self.assertEqual(receipt["deleted_count"], 1)

    def test_normal_cleanup_deletes_cache_at_short_result_retention(self) -> None:
        current = [NOW]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "github-semantic-evaluation"
            write_approval(
                root / "approval.json", retention_days=1,
                expires_at=(NOW + timedelta(days=7)).isoformat(),
            )
            store = GitHubSemanticEvaluationStore(
                root, release_root=Path(directory) / "release",
                approval_path=root / "approval.json", clock=lambda: current[0],
                source_file_sha256=HASH_A, candidate_set_sha256=HASH_B,
                github_authorization_sha256=HASH_C,
            )
            cache = CanonicalJsonCache(root / "cache" / "github-assessment", clock=lambda: current[0])
            key = cache.key("github_assessment", "v1", {"projects": []})
            cache.set(key, semantic_result(), expires_at=NOW + timedelta(days=1))
            current[0] = NOW + timedelta(days=2)

            receipt = store.cleanup_expired()

            self.assertEqual(list(cache.root.glob("*.json")), [])
            self.assertGreaterEqual(receipt["deleted_count"], 1)

    def test_cleanup_deletes_expired_records_attempts_and_receipt(self) -> None:
        current = [NOW]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "github-semantic-evaluation"
            write_approval(
                root / "approval.json",
                expires_at=(NOW + timedelta(days=1)).isoformat(), retention_days=1,
            )
            store = GitHubSemanticEvaluationStore(
                root, release_root=Path(directory) / "release",
                approval_path=root / "approval.json", clock=lambda: current[0],
                source_file_sha256=HASH_A, candidate_set_sha256=HASH_B,
                github_authorization_sha256=HASH_C,
            )
            for index in range(5):
                store.put(
                    subject_ref="pid:v1:" + f"{index + 1:064x}",
                    github_result=github_result(),
                )
            store.write_canary_receipt(
                reviewed_by="codex_proof_for_me", quality_decision="accepted",
            )
            store.begin_provider_attempt()
            current[0] = NOW + timedelta(days=1, seconds=1)

            receipt = store.cleanup_expired()

            self.assertEqual(list(store.results.glob("*.json")), [])
            self.assertEqual(list(store.attempts.glob("*.json")), [])
            self.assertFalse((store.root / "canary-receipt.json").exists())
            self.assertGreaterEqual(receipt["deleted_count"], 7)

    def test_rejects_missing_expired_future_or_overlong_approval(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "approval.json"
            with self.assertRaises(PermissionError):
                GitHubSemanticEvaluationApproval.load(path, now=NOW)

            for value in (
                approval_record(expires_at=NOW.isoformat()),
                approval_record(approved_at=(NOW + timedelta(seconds=1)).isoformat()),
                approval_record(expires_at=(NOW + timedelta(days=7, seconds=1)).isoformat()),
            ):
                path.write_text(json.dumps(value), encoding="utf-8")
                with self.assertRaises(PermissionError):
                    GitHubSemanticEvaluationApproval.load(path, now=NOW)


if __name__ == "__main__":
    unittest.main()
