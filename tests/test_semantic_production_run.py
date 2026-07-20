"""Bounded production-run behavior for rich semantic proposals."""

from __future__ import annotations

from datetime import UTC, datetime
import json
from pathlib import Path
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest import mock

from community_os.enrichment.cache import CanonicalJsonCache


NOW = datetime(2026, 7, 17, 2, tzinfo=UTC)


class _MetadataProvider:
    model = "gpt-5.6-sol"
    reasoning_effort = "medium"

    def __init__(self, *, fail_at: int | None = None) -> None:
        self.calls: list[dict[str, object]] = []
        self.fail_at = fail_at

    def assess_with_metadata(self, evidence, *, max_transport_attempts):
        from tests.test_rich_semantic_assessment import assessment

        self.calls.append(evidence)
        if max_transport_attempts != 1:
            raise AssertionError("production run must make one transport attempt")
        if self.fail_at == len(self.calls):
            raise RuntimeError("simulated interruption")
        references = sorted({
            reference
            for packets in evidence.values()
            for packet in packets
            for reference in packet["evidence_refs"]
        })
        return {
            "assessment": assessment(evidence_refs=references[:4]),
            "model_version": self.model,
            "normalizations": [],
            "usage": {"input_tokens": 100, "output_tokens": 10},
        }


class _KnownFailedMetadataProvider(_MetadataProvider):
    def assess_with_metadata(self, evidence, *, max_transport_attempts):
        from community_os.enrichment.openai_rich_semantic_assessment import (
            RetryableRichSemanticOutputError,
        )

        self.calls.append(evidence)
        if max_transport_attempts != 1:
            raise AssertionError("production run must make one transport attempt")
        raise RetryableRichSemanticOutputError(
            "simulated bounded output failure",
            failure_code="output_token_limit",
            model_version=self.model,
            usage={"input_tokens": 100, "output_tokens": 4_000},
        )


class _IdentityLeakingMetadataProvider(_MetadataProvider):
    def assess_with_metadata(self, evidence, *, max_transport_attempts):
        from tests.test_rich_semantic_assessment import assessment

        self.calls.append(evidence)
        if max_transport_attempts != 1:
            raise AssertionError("production run must make one transport attempt")
        references = sorted({
            reference
            for packets in evidence.values()
            for packet in packets
            for reference in packet["evidence_refs"]
        })
        return {
            "assessment": assessment(
                evidence_refs=references[:4],
                project_summary=(
                    "quendria built a working operational product with deployment "
                    "and testing evidence."
                ),
            ),
            "model_version": self.model,
            "normalizations": [],
            "usage": {"input_tokens": 100, "output_tokens": 10},
        }


class _ParallelTracker:
    def __init__(self, expected_parallelism: int) -> None:
        self.expected_parallelism = expected_parallelism
        self.lock = threading.Lock()
        self.ready = threading.Event()
        self.active = 0
        self.max_active = 0
        self.calls = 0

    def enter(self) -> None:
        with self.lock:
            self.active += 1
            self.calls += 1
            self.max_active = max(self.max_active, self.active)
            if self.active >= self.expected_parallelism:
                self.ready.set()

    def leave(self) -> None:
        with self.lock:
            self.active -= 1


class _ParallelMetadataProvider(_MetadataProvider):
    def __init__(self, tracker: _ParallelTracker, *, fail: bool = False) -> None:
        super().__init__()
        self.tracker = tracker
        self.fail = fail

    def assess_with_metadata(self, evidence, *, max_transport_attempts):
        self.tracker.enter()
        try:
            self.tracker.ready.wait(timeout=0.5)
            if self.fail:
                raise RuntimeError("simulated parallel interruption")
            return super().assess_with_metadata(
                evidence, max_transport_attempts=max_transport_attempts,
            )
        finally:
            self.tracker.leave()


class SemanticProductionRunTests(unittest.TestCase):
    def _fixture(self, root: Path, *, count: int = 7):
        from community_os.enrichment.state import pseudonymous_id
        from community_os.release_operator import ReleaseOperatorState
        from tests.test_release_operations import (
            _current_event_definition, _review_bindings_payload,
            rich_semantic_processor_approval,
        )
        from tests.test_release_operator import source_gate
        from tests.test_rich_semantic_assessment import project_packet

        secret = b"fixture-pseudonym-secret"
        applications = tuple({
            "external_id": f"app-{ordinal:02d}",
            "name": f"Private Person {ordinal}",
            "email": f"private-{ordinal}@example.org",
            "experience": f"Built durable automation system number {ordinal}.",
            "impressive_thing": (
                "Designed, implemented, and shipped the same workflow "
                f"end to end, version {ordinal}."
            ),
        } for ordinal in range(1, count + 1))
        state = ReleaseOperatorState(
            root, operator_code="privacy_lead",
            event_definition=_current_event_definition(), clock=lambda: NOW,
        )
        state.record_public_source_authorization(
            "github", source_gate("applicant_supplied_github", 30), now=NOW,
        )
        records = [{
            "subject_ref": pseudonymous_id(
                str(application["external_id"]), secret=secret, key_version="v1",
            ),
            "state": "observed",
            "rich_project_evidence": [project_packet()],
        } for application in applications]
        stages = root / "protected" / "stages"
        stages.mkdir(parents=True)
        (stages / "github.json").write_text(json.dumps({
            "created_at": NOW.isoformat(),
            "expires_at": "2099-08-12T12:00:00Z",
            "records": records, "stage": "github",
            "stage_output_version": "protected-stage-output-v1",
        }), encoding="utf-8")
        state.pipeline.start("github")
        state.pipeline.complete(
            "github", {"output_hash": "a" * 64, "record_count": len(records)},
        )
        state.record_semantic_processor_authorization(
            rich_semantic_processor_approval(), now=NOW,
        )
        (root / "protected" / "review-bindings.json").write_text(
            json.dumps(_review_bindings_payload(
                state, {"exact_person_links": {}, "identity_subjects": {}},
            )),
            encoding="utf-8",
        )
        return state, secret, applications

    @staticmethod
    def _service(
        state, secret, applications, provider, *, mode: str,
        base_calls: list[str] | None = None,
        attendance_records: tuple[object, ...] | None = None,
        provider_factory=None,
        max_concurrency: int | None = None,
    ):
        from community_os.release_operations import (
            ReconciliationInputs, build_rich_semantic_proposal_service,
        )

        calls = base_calls if base_calls is not None else []
        attendance = attendance_records if attendance_records is not None else tuple(
            SimpleNamespace(
                applicant_identity=application["email"],
                payload={
                    "approval_status": "approved",
                    "checked_in_at": "2026-07-11T09:00:00Z",
                },
            )
            for application in applications
        )
        options = {}
        if max_concurrency is not None:
            options["run_max_concurrency"] = max_concurrency
        return build_rich_semantic_proposal_service(
            state,
            base_classification=lambda: calls.append("called") or [{"legacy": True}],
            pseudonym_secret=secret,
            provider_factory=(
                provider_factory
                if provider_factory is not None
                else lambda _corpus: provider
            ),
            cache=CanonicalJsonCache(
                Path(state.root) / "protected" / "cache" / "rich",
                clock=lambda: NOW,
            ),
            clock=lambda: NOW,
            application_loader=lambda _state: applications,
            reconciliation_loader=lambda _state: ReconciliationInputs(
                applications=applications, preference_records=(), submission_records=(),
                preferences={}, projects={},
            ),
            attendance_loader=lambda _state: attendance,
            run_mode=mode,
            run_model="gpt-5.6-sol",
            run_reasoning_effort="medium",
            input_cost_per_million_usd_micros=5_000_000,
            output_cost_per_million_usd_micros=30_000_000,
            **options,
        )

    def test_canary_prioritizes_present_then_accepted_then_remaining_applicants(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state, secret, applications = self._fixture(Path(directory))
            provider = _MetadataProvider()
            attendance = (
                SimpleNamespace(
                    applicant_identity="private-7@example.org",
                    payload={
                        "approval_status": "approved",
                        "checked_in_at": "2026-07-11T09:00:00Z",
                    },
                ),
                SimpleNamespace(
                    applicant_identity="private-6@example.org",
                    payload={
                        "approval_status": "approved",
                        "checked_in_at": "",
                    },
                ),
            )
            canary = self._service(
                state, secret, applications, provider, mode="canary",
                attendance_records=attendance,
            )

            canary()

        excerpts = [
            call["application"][0]["experience_excerpt"]
            for call in provider.calls
        ]
        self.assertEqual(len(excerpts), 5)
        self.assertIn("number 7", excerpts[0])
        self.assertIn("number 6", excerpts[1])
        self.assertIn("number 1", excerpts[2])
        self.assertIn("number 2", excerpts[3])
        self.assertIn("number 3", excerpts[4])

    def test_cohort_membership_is_independently_derived_from_exact_event_rows(self) -> None:
        from community_os.release_operations import (
            derive_semantic_application_cohort_membership,
        )

        with tempfile.TemporaryDirectory() as directory:
            state, _secret, applications = self._fixture(Path(directory))
            attendance = (
                SimpleNamespace(
                    applicant_identity="private-7@example.org",
                    payload={
                        "approval_status": "approved",
                        "checked_in_at": "2026-07-11T09:00:00Z",
                    },
                ),
                SimpleNamespace(
                    applicant_identity="private-6@example.org",
                    payload={
                        "approval_status": "approved",
                        "checked_in_at": "",
                    },
                ),
            )

            membership = derive_semantic_application_cohort_membership(
                state,
                applications,
                attendance_loader=lambda _state: attendance,
            )

        self.assertEqual(tuple(membership), tuple(
            application["external_id"] for application in applications
        ))
        self.assertEqual(
            membership["app-07"],
            {"applied": True, "accepted": True, "present": True},
        )
        self.assertEqual(
            membership["app-06"],
            {"applied": True, "accepted": True, "present": False},
        )
        self.assertEqual(
            membership["app-01"],
            {"applied": True, "accepted": False, "present": False},
        )
        self.assertEqual(
            {
                key: sum(row[key] for row in membership.values())
                for key in ("applied", "accepted", "present")
            },
            {"applied": 7, "accepted": 2, "present": 1},
        )

    def test_default_cohort_membership_parser_receives_exact_attendance_source(self) -> None:
        from community_os.release_operations import (
            derive_semantic_application_cohort_membership,
        )

        with tempfile.TemporaryDirectory() as directory:
            state, _secret, applications = self._fixture(Path(directory))
            attendance = (
                SimpleNamespace(
                    applicant_identity="private-7@example.org",
                    payload={
                        "email": "private-7@example.org",
                        "approval_status": "approved",
                        "checked_in_at": "2026-07-11T09:00:00Z",
                    },
                ),
            )
            with (
                mock.patch.object(
                    state,
                    "snapshot",
                    return_value={
                        "source_slots": {
                            "attendance": {"path": "attendance.csv"},
                        },
                    },
                ),
                mock.patch(
                    "community_os.operator_pipeline.records_from_source",
                    return_value=attendance,
                ) as parser,
            ):
                derive_semantic_application_cohort_membership(
                    state,
                    applications,
                    attendance_loader=None,
                )

        self.assertEqual(parser.call_count, 1)
        self.assertIs(
            parser.call_args.kwargs["source"],
            state.event_definition.source("attendance"),
        )

    def test_production_concurrency_accepts_measured_72_worker_ceiling_and_rejects_73(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state, secret, applications = self._fixture(Path(directory))
            provider = _MetadataProvider()

            service = self._service(
                state, secret, applications, provider, mode="full",
                max_concurrency=72,
            )
            self.assertTrue(callable(service))

            with self.assertRaisesRegex(
                ValueError, "semantic production run binding is incomplete",
            ):
                self._service(
                    state, secret, applications, provider, mode="full",
                    max_concurrency=73,
                )

    def test_canary_rejects_present_without_event_accepted_state_before_provider(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state, secret, applications = self._fixture(Path(directory))
            provider = _MetadataProvider()
            canary = self._service(
                state, secret, applications, provider, mode="canary",
                attendance_records=(
                    SimpleNamespace(
                        applicant_identity="private-7@example.org",
                        payload={
                            "approval_status": "rejected",
                            "checked_in_at": "2026-07-11T09:00:00Z",
                        },
                    ),
                ),
            )

            with self.assertRaisesRegex(
                PermissionError, "present applicant is not accepted",
            ):
                canary()

        self.assertEqual(provider.calls, [])

    def test_full_rejects_attendance_priority_drift_from_exact_canary_population(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state, secret, applications = self._fixture(Path(directory))
            canary_provider = _MetadataProvider()
            initial_attendance = (
                SimpleNamespace(
                    applicant_identity="private-7@example.org",
                    payload={
                        "approval_status": "approved",
                        "checked_in_at": "2026-07-11T09:00:00Z",
                    },
                ),
                SimpleNamespace(
                    applicant_identity="private-6@example.org",
                    payload={"approval_status": "approved", "checked_in_at": ""},
                ),
            )
            self._service(
                state, secret, applications, canary_provider, mode="canary",
                attendance_records=initial_attendance,
            )()
            changed_attendance = (
                SimpleNamespace(
                    applicant_identity="private-6@example.org",
                    payload={
                        "approval_status": "approved",
                        "checked_in_at": "2026-07-11T09:00:00Z",
                    },
                ),
                SimpleNamespace(
                    applicant_identity="private-7@example.org",
                    payload={"approval_status": "approved", "checked_in_at": ""},
                ),
            )
            full_provider = _MetadataProvider()
            full = self._service(
                state, secret, applications, full_provider, mode="full",
                attendance_records=changed_attendance,
            )

            with self.assertRaisesRegex(PermissionError, "population drift"):
                full()

        self.assertEqual(full_provider.calls, [])

    def test_full_fails_before_base_or_provider_until_exact_canary_exists(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state, secret, applications = self._fixture(Path(directory))
            provider = _MetadataProvider()
            base_calls: list[str] = []
            service = self._service(
                state, secret, applications, provider,
                mode="full", base_calls=base_calls,
            )

            with self.assertRaisesRegex(PermissionError, "canary receipt"):
                service()

        self.assertEqual(base_calls, [])
        self.assertEqual(provider.calls, [])

    def test_canary_then_full_calls_each_unchanged_subject_once_and_skips_open_proposals(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state, secret, applications = self._fixture(Path(directory))
            canary_provider = _MetadataProvider()
            canary = self._service(
                state, secret, applications, canary_provider, mode="canary",
            )

            canary_result = canary()

            self.assertEqual(len(canary_provider.calls), 5)
            self.assertEqual(canary_result, [{
                "canary_subject_count": 5,
                "interrupted_subject_count": 0,
                "state": "complete",
            }])
            full_provider = _MetadataProvider()
            base_calls: list[str] = []
            full = self._service(
                state, secret, applications, full_provider,
                mode="full", base_calls=base_calls,
            )

            full_result = full()
            full_again = full()

            self.assertEqual(full_result, [{"legacy": True}])
            self.assertEqual(full_again, [{"legacy": True}])
            self.assertEqual(base_calls, ["called", "called"])
            self.assertEqual(len(full_provider.calls), 2)
            cases = [
                case for case in state.review_repository.list(kind="classification")
                if case.version == "rich_semantic_review_v1"
            ]
            self.assertEqual(len(cases), 7)

    def test_full_bounds_parallel_provider_calls_and_serially_commits_every_result(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state, secret, applications = self._fixture(root, count=9)
            self._service(
                state, secret, applications, _MetadataProvider(), mode="canary",
            )()
            tracker = _ParallelTracker(expected_parallelism=4)
            full = self._service(
                state, secret, applications, _MetadataProvider(), mode="full",
                max_concurrency=4,
                provider_factory=lambda _corpus: _ParallelMetadataProvider(tracker),
            )

            full()

            receipts = [
                json.loads(path.read_text(encoding="utf-8"))
                for path in (root / "protected/rich-semantic-run/subjects").glob("*.json")
            ]
            rich_cases = [
                case for case in state.review_repository.list(kind="classification")
                if case.version == "rich_semantic_review_v1"
            ]

        self.assertEqual(tracker.calls, 4)
        self.assertEqual(tracker.max_active, 4)
        self.assertEqual(len(receipts), 9)
        self.assertTrue(all(receipt["state"] == "completed" for receipt in receipts))
        self.assertEqual(len(rich_cases), 9)

    def test_parallel_batch_commits_successes_and_leaves_only_failed_call_reserved(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state, secret, applications = self._fixture(root, count=9)
            self._service(
                state, secret, applications, _MetadataProvider(), mode="canary",
            )()
            tracker = _ParallelTracker(expected_parallelism=4)
            provider_ordinal = 0
            provider_lock = threading.Lock()

            def provider_factory(_corpus):
                nonlocal provider_ordinal
                with provider_lock:
                    provider_ordinal += 1
                    ordinal = provider_ordinal
                return _ParallelMetadataProvider(tracker, fail=ordinal == 2)

            full = self._service(
                state, secret, applications, _MetadataProvider(), mode="full",
                max_concurrency=4, provider_factory=provider_factory,
            )

            with self.assertRaisesRegex(
                RuntimeError, "simulated parallel interruption",
            ):
                full()

            receipts = [
                json.loads(path.read_text(encoding="utf-8"))
                for path in (root / "protected/rich-semantic-run/subjects").glob("*.json")
            ]
            states = [receipt["state"] for receipt in receipts]
            rich_cases = [
                case for case in state.review_repository.list(kind="classification")
                if case.version == "rich_semantic_review_v1"
            ]

        self.assertEqual(tracker.calls, 4)
        self.assertEqual(tracker.max_active, 4)
        self.assertEqual(states.count("completed"), 8)
        self.assertEqual(states.count("reserved"), 1)
        self.assertEqual(len(rich_cases), 8)

    def test_interrupted_reservation_blocks_all_new_calls_until_explicit_recovery(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state, secret, applications = self._fixture(root)
            interrupted_provider = _MetadataProvider(fail_at=3)
            canary = self._service(
                state, secret, applications, interrupted_provider, mode="canary",
            )

            with self.assertRaisesRegex(RuntimeError, "simulated interruption"):
                canary()
            self.assertEqual(len(interrupted_provider.calls), 3)

            resumed_provider = _MetadataProvider()
            resumed = self._service(
                state, secret, applications, resumed_provider, mode="canary",
            )
            with self.assertRaisesRegex(PermissionError, "interrupted"):
                resumed()

            self.assertEqual(len(resumed_provider.calls), 0)
            ledger_files = "\n".join(
                path.read_text(encoding="utf-8")
                for path in (root / "protected" / "rich-semantic-run").rglob("*.json")
            )

        for private_value in (
            "Private Person", "@example.org", "Built durable automation systems",
        ):
            self.assertNotIn(private_value, ledger_files)

    def test_retry_recovers_paid_usage_when_proposal_preceded_ledger_completion(self) -> None:
        from community_os.enrichment.rich_semantic_assessment import (
            PROMPT_VERSION, SEMANTIC_NORMALIZATION_VERSION,
        )
        from community_os.enrichment.semantic_run_ledger import (
            ProtectedSemanticRunLedger, SemanticRunBinding,
        )
        from community_os.release_operations import (
            _canonical_hash, rich_semantic_subject_ref,
        )
        from community_os.enrichment.openai_rich_semantic_assessment import (
            rich_semantic_schema_sha256,
        )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state, secret, applications = self._fixture(root)
            provider = _MetadataProvider()
            service = self._service(
                state, secret, applications, provider, mode="canary",
            )
            original_complete = ProtectedSemanticRunLedger.complete
            completion_calls = 0

            def interrupt_first_completion(ledger, *args, **kwargs):
                nonlocal completion_calls
                completion_calls += 1
                if completion_calls == 1:
                    raise RuntimeError("simulated post-proposal interruption")
                return original_complete(ledger, *args, **kwargs)

            with mock.patch.object(
                ProtectedSemanticRunLedger, "complete",
                new=interrupt_first_completion,
            ):
                with self.assertRaisesRegex(
                    RuntimeError, "post-proposal interruption",
                ):
                    service()

            ordered_subjects = tuple(
                rich_semantic_subject_ref(
                    str(application["external_id"]), secret=secret,
                )
                for application in applications
            )
            ledger = ProtectedSemanticRunLedger(
                root / "protected" / "rich-semantic-run",
                binding=SemanticRunBinding(
                    approval_sha256=str(
                        state.pipeline.stage("classification").authorization_hash,
                    ),
                    event_context_sha256=_canonical_hash(dict(
                        state.rich_semantic_reviews.review_context_hashes,
                    )),
                    input_cost_per_million_usd_micros=5_000_000,
                    model="gpt-5.6-sol",
                    normalization_version=SEMANTIC_NORMALIZATION_VERSION,
                    output_cost_per_million_usd_micros=30_000_000,
                    prompt_version=PROMPT_VERSION,
                    reasoning_effort="medium",
                    schema_sha256=rich_semantic_schema_sha256(),
                ),
                ordered_subject_refs=ordered_subjects,
                clock=lambda: NOW,
            )
            interrupted = ledger.interrupted_subjects()
            self.assertEqual(len(interrupted), 1)
            ledger.retry_once(interrupted[0], expected_state="reserved")

            resumed_provider = _MetadataProvider()
            resumed = self._service(
                state, secret, applications, resumed_provider, mode="canary",
            )
            resumed()
            recovered = ledger._load_subject(interrupted[0])

        self.assertEqual(len(resumed_provider.calls), 4)
        self.assertEqual(recovered["state"], "completed")
        self.assertEqual(recovered["cache_status"], "miss")
        self.assertEqual(recovered["input_tokens"], 100)
        self.assertEqual(recovered["output_tokens"], 10)

    def test_known_provider_failure_accounts_usage_and_is_not_retried(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state, secret, applications = self._fixture(root)
            failed_provider = _KnownFailedMetadataProvider()
            canary = self._service(
                state, secret, applications, failed_provider, mode="canary",
            )

            with self.assertRaisesRegex(
                RuntimeError, "simulated bounded output failure",
            ):
                canary()
            self.assertEqual(len(failed_provider.calls), 1)

            resumed_provider = _MetadataProvider()
            resumed = self._service(
                state, secret, applications, resumed_provider, mode="canary",
            )
            with self.assertRaisesRegex(PermissionError, "failed subjects"):
                resumed()

            self.assertEqual(len(resumed_provider.calls), 4)
            receipts = [
                json.loads(path.read_text(encoding="utf-8"))
                for path in (root / "protected" / "rich-semantic-run" / "subjects").glob("*.json")
            ]
            failed = [receipt for receipt in receipts if receipt.get("state") == "failed"]

        self.assertEqual(len(failed), 1)
        self.assertEqual(failed[0]["failure_code"], "output_token_limit")
        self.assertEqual(failed[0]["input_tokens"], 100)
        self.assertEqual(failed[0]["output_tokens"], 4_000)
        self.assertEqual(failed[0]["cost_usd_micros"], 120_500)

    def test_subject_identity_fragments_reach_model_output_sanitization(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state, secret, applications = self._fixture(Path(directory))
            applications[0]["name"] = "Quendria Vale"
            applications[0]["github"] = "quendria-labs"
            provider = _MetadataProvider()
            sanitizer_corpora: list[tuple[str, ...]] = []

            service = self._service(
                state, secret, applications, provider, mode="canary",
                provider_factory=lambda corpus: (
                    sanitizer_corpora.append(corpus) or provider
                ),
            )
            service()

        normalized_corpora = [
            {literal.casefold() for literal in corpus}
            for corpus in sanitizer_corpora
        ]
        self.assertTrue(
            any(
                {"quendria", "quendria-labs"}.issubset(corpus)
                for corpus in normalized_corpora
            ),
            "the current subject's name fragment and handle must be bound into "
            "the model-output sanitizer",
        )

    def test_subject_name_fragment_cannot_enter_durable_review_proposal(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state, secret, applications = self._fixture(Path(directory))
            applications[0]["name"] = "Quendria Vale"
            provider = _IdentityLeakingMetadataProvider()
            service = self._service(
                state, secret, applications, provider, mode="canary",
            )

            with self.assertRaisesRegex(
                ValueError, "known identity literal",
            ):
                service()


if __name__ == "__main__":
    unittest.main()
