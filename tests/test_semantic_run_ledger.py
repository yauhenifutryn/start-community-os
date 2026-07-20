"""Content-free, approval-bound production semantic-run ledger tests."""

from __future__ import annotations

from datetime import UTC, datetime
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


NOW = datetime(2026, 7, 17, 2, tzinfo=UTC)


def _binding(**overrides: object):
    from community_os.enrichment.semantic_run_ledger import SemanticRunBinding

    values = {
        "approval_sha256": "a" * 64,
        "event_context_sha256": "b" * 64,
        "input_cost_per_million_usd_micros": 5_000_000,
        "model": "gpt-5.6-sol",
        "normalization_version": "rich-semantic-normalization-v14",
        "output_cost_per_million_usd_micros": 30_000_000,
        "prompt_version": "rich-professional-evidence-a-v20",
        "reasoning_effort": "medium",
        "schema_sha256": "c" * 64,
    }
    values.update(overrides)
    return SemanticRunBinding(**values)


def _subjects(count: int = 7) -> tuple[str, ...]:
    return tuple(f"case:v1:{ordinal:064x}" for ordinal in range(1, count + 1))


class ProtectedSemanticRunLedgerTests(unittest.TestCase):
    def _ledger(self, root: Path, **binding_overrides: object):
        from community_os.enrichment.semantic_run_ledger import (
            ProtectedSemanticRunLedger,
        )

        return ProtectedSemanticRunLedger(
            root,
            binding=_binding(**binding_overrides),
            ordered_subject_refs=_subjects(),
            clock=lambda: NOW,
        )

    def test_binding_and_subject_population_drift_fail_closed(self) -> None:
        from community_os.enrichment.semantic_run_ledger import (
            ProtectedSemanticRunLedger,
        )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "rich-semantic-run"
            self._ledger(root)

            with self.assertRaisesRegex(PermissionError, "binding drift"):
                self._ledger(root, approval_sha256="d" * 64)
            with self.assertRaisesRegex(PermissionError, "population drift"):
                ProtectedSemanticRunLedger(
                    root,
                    binding=_binding(),
                    ordered_subject_refs=tuple(reversed(_subjects())),
                    clock=lambda: NOW,
                )
            self.assertEqual(root.stat().st_mode & 0o777, 0o700)

    def test_canary_is_exactly_five_and_full_requires_matching_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            ledger = self._ledger(Path(directory) / "rich-semantic-run")

            self.assertEqual(ledger.subjects_for_mode("canary"), _subjects()[:5])
            with self.assertRaisesRegex(PermissionError, "canary receipt"):
                ledger.subjects_for_mode("full")

            for subject_ref in _subjects()[:5]:
                ledger.record_existing(subject_ref)
            receipt = ledger.complete_canary()

            self.assertEqual(receipt["canary_subject_count"], 5)
            self.assertEqual(ledger.subjects_for_mode("full"), _subjects())

    def test_reserved_subject_is_never_returned_for_retry_after_interruption(self) -> None:
        request = b'{"application":[],"career":[],"devpost":[],"projects":[]}'
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "rich-semantic-run"
            ledger = self._ledger(root)
            first = _subjects()[0]
            ledger.reserve(
                first,
                request_sha256=hashlib.sha256(request).hexdigest(),
                request_byte_count=len(request),
                source_family_counts={
                    "application": 0, "career": 0, "devpost": 0, "projects": 0,
                },
            )

            resumed = self._ledger(root)

            self.assertEqual(resumed.subject_state(first), "reserved")
            self.assertEqual(
                resumed.unprocessed_subjects("canary"), _subjects()[1:5],
            )
            self.assertEqual(resumed.interrupted_subjects(), (first,))
            with self.assertRaisesRegex(PermissionError, "interrupted"):
                resumed.complete_canary()

    def test_completed_receipt_binds_usage_cost_and_contains_no_evidence(self) -> None:
        private_text = "private evidence about jane@example.org"
        request = private_text.encode("utf-8")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "rich-semantic-run"
            ledger = self._ledger(root)
            subject = _subjects()[0]
            request_sha256 = hashlib.sha256(request).hexdigest()
            ledger.reserve(
                subject,
                request_sha256=request_sha256,
                request_byte_count=len(request),
                source_family_counts={
                    "application": 1, "career": 0, "devpost": 1, "projects": 2,
                },
            )

            receipt = ledger.complete(
                subject,
                cache_status="miss",
                input_tokens=1_000,
                model_version="gpt-5.6-sol",
                output_tokens=100,
            )

            self.assertEqual(receipt["cost_usd_micros"], 8_000)
            self.assertEqual(receipt["request_sha256"], request_sha256)
            self.assertEqual(receipt["request_byte_count"], len(request))
            self.assertEqual(receipt["source_family_counts"]["projects"], 2)
            serialized = "\n".join(
                path.read_text(encoding="utf-8")
                for path in root.rglob("*.json")
            )

        self.assertNotIn(private_text, serialized)
        self.assertNotIn("jane@example.org", serialized)
        self.assertEqual(set(receipt), {
            "binding_sha256", "cache_status", "completed_at",
            "cost_usd_micros", "input_tokens", "model", "model_version",
            "normalization_version", "output_tokens", "prompt_version",
            "reasoning_effort", "record_version", "request_byte_count",
            "request_sha256", "source_family_counts", "state", "subject_ref",
        })

    def test_known_provider_failure_records_cost_but_never_completes_canary(self) -> None:
        request = b'{"application":[{"redacted":"private"}]}'
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "rich-semantic-run"
            ledger = self._ledger(root)
            subject = _subjects()[0]
            ledger.reserve(
                subject,
                request_sha256=hashlib.sha256(request).hexdigest(),
                request_byte_count=len(request),
                source_family_counts={
                    "application": 1, "career": 0, "devpost": 0, "projects": 0,
                },
            )

            receipt = ledger.record_failed(
                subject,
                failure_code="output_token_limit",
                input_tokens=100,
                model_version="gpt-5.6-sol",
                output_tokens=4_000,
            )

            self.assertEqual(receipt["state"], "failed")
            self.assertEqual(receipt["failure_code"], "output_token_limit")
            self.assertEqual(receipt["cost_usd_micros"], 120_500)
            self.assertEqual(ledger.failed_subjects(), (subject,))
            self.assertEqual(
                ledger.unprocessed_subjects("canary"), _subjects()[1:5],
            )
            with self.assertRaisesRegex(PermissionError, "incomplete"):
                ledger.complete_canary()
            serialized = "\n".join(
                path.read_text(encoding="utf-8")
                for path in root.rglob("*.json")
            )

        self.assertNotIn("redacted", serialized)
        self.assertNotIn("private", serialized)

    def test_failed_subject_can_retry_once_with_prior_cost_and_hash_preserved(self) -> None:
        request = b'{"application":[],"career":[],"devpost":[],"projects":[]}'
        counts = {
            "application": 0, "career": 0, "devpost": 0, "projects": 0,
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "rich-semantic-run"
            ledger = self._ledger(root)
            subject = _subjects()[0]
            request_sha256 = hashlib.sha256(request).hexdigest()
            ledger.reserve(
                subject, request_sha256=request_sha256,
                request_byte_count=len(request), source_family_counts=counts,
            )
            failed = ledger.record_failed(
                subject,
                failure_code="semantic_output_invalid_validation",
                input_tokens=100,
                model_version="gpt-5.6-sol",
                output_tokens=50,
            )
            prior_record = json.loads(
                next((root / "subjects").glob("*.json")).read_text(
                    encoding="utf-8",
                ),
            )

            self.assertTrue(
                hasattr(ledger, "retry_once"),
                "the atomic one-time semantic-run recovery API is missing",
            )
            self.assertTrue(
                hasattr(ledger, "recovery_receipt"),
                "the append-only semantic-run recovery receipt API is missing",
            )
            recovery = ledger.retry_once(subject, expected_state="failed")

            self.assertEqual(recovery["state"], "retry_authorized")
            self.assertEqual(recovery["previous_state"], "failed")
            self.assertEqual(
                recovery["previous_record_sha256"],
                prior_record["record_sha256"],
            )
            self.assertEqual(
                recovery["cumulative_prior_cost_usd_micros"],
                failed["cost_usd_micros"],
            )
            self.assertEqual(recovery["request_sha256"], request_sha256)
            self.assertIsNone(ledger.subject_state(subject))
            with self.assertRaisesRegex(PermissionError, "request binding drift"):
                ledger.reserve(
                    subject, request_sha256="d" * 64,
                    request_byte_count=len(request), source_family_counts=counts,
                )
            self.assertEqual(
                ledger.reserve(
                    subject, request_sha256=request_sha256,
                    request_byte_count=len(request), source_family_counts=counts,
                ),
                "reserved",
            )
            ledger.record_failed(
                subject,
                failure_code="semantic_output_invalid_validation",
                input_tokens=10,
                model_version="gpt-5.6-sol",
                output_tokens=5,
            )

            restarted = self._ledger(root)
            self.assertEqual(restarted.recovery_receipt(subject), recovery)
            with self.assertRaisesRegex(PermissionError, "one-time|already used"):
                restarted.retry_once(subject, expected_state="failed")

    def test_interrupted_reservation_can_restart_once_without_deleting_history(self) -> None:
        request = b'{"application":[],"career":[],"devpost":[],"projects":[]}'
        counts = {
            "application": 0, "career": 0, "devpost": 0, "projects": 0,
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "rich-semantic-run"
            ledger = self._ledger(root)
            subject = _subjects()[0]
            request_sha256 = hashlib.sha256(request).hexdigest()
            ledger.reserve(
                subject, request_sha256=request_sha256,
                request_byte_count=len(request), source_family_counts=counts,
            )
            prior_record = json.loads(
                next((root / "subjects").glob("*.json")).read_text(
                    encoding="utf-8",
                ),
            )

            self.assertTrue(
                hasattr(ledger, "retry_once"),
                "the atomic one-time semantic-run recovery API is missing",
            )
            self.assertTrue(
                hasattr(ledger, "recovery_receipt"),
                "the append-only semantic-run recovery receipt API is missing",
            )
            recovery = ledger.retry_once(subject, expected_state="reserved")

            self.assertEqual(recovery["state"], "retry_authorized")
            self.assertEqual(recovery["previous_state"], "reserved")
            self.assertEqual(
                recovery["previous_record_sha256"],
                prior_record["record_sha256"],
            )
            self.assertEqual(recovery["cumulative_prior_cost_usd_micros"], 0)
            self.assertIsNone(ledger.subject_state(subject))

            restarted = self._ledger(root)
            self.assertEqual(restarted.recovery_receipt(subject), recovery)
            with self.assertRaisesRegex(PermissionError, "request binding drift"):
                restarted.reserve(
                    subject, request_sha256="e" * 64,
                    request_byte_count=len(request), source_family_counts=counts,
                )
            self.assertEqual(
                restarted.reserve(
                    subject, request_sha256=request_sha256,
                    request_byte_count=len(request), source_family_counts=counts,
                ),
                "reserved",
            )
            with self.assertRaisesRegex(PermissionError, "one-time|already used"):
                restarted.retry_once(subject, expected_state="reserved")
            restarted.record_empty(
                subject, request_sha256=request_sha256,
                request_byte_count=len(request), source_family_counts=counts,
            )

            finalized = self._ledger(root)
            self.assertEqual(finalized.recovery_receipt(subject), recovery)
            self.assertEqual(finalized.subject_state(subject), "empty")

    def test_completed_subject_can_restart_once_after_privacy_invalidation(self) -> None:
        request = b'{"application":[],"career":[],"devpost":[],"projects":[]}'
        counts = {
            "application": 0, "career": 0, "devpost": 0, "projects": 0,
        }
        with tempfile.TemporaryDirectory() as directory:
            ledger = self._ledger(Path(directory) / "rich-semantic-run")
            subject = _subjects()[0]
            request_sha256 = hashlib.sha256(request).hexdigest()
            ledger.reserve(
                subject, request_sha256=request_sha256,
                request_byte_count=len(request), source_family_counts=counts,
            )
            completed = ledger.complete(
                subject, cache_status="miss", input_tokens=100,
                model_version="gpt-5.6-sol", output_tokens=50,
            )

            replacement_sha256 = "e" * 64
            recovery = ledger.retry_once(
                subject, expected_state="completed",
                replacement_request_sha256=replacement_sha256,
                replacement_request_byte_count=len(request) - 1,
                replacement_source_family_counts={
                    **counts, "projects": 1,
                },
            )

            self.assertEqual(recovery["previous_state"], "completed")
            self.assertEqual(
                recovery["cumulative_prior_cost_usd_micros"],
                completed["cost_usd_micros"],
            )
            self.assertIsNone(ledger.subject_state(subject))
            with self.assertRaisesRegex(PermissionError, "request binding drift"):
                ledger.reserve(
                    subject, request_sha256=request_sha256,
                    request_byte_count=len(request), source_family_counts=counts,
                )
            self.assertEqual(
                ledger.reserve(
                    subject, request_sha256=replacement_sha256,
                    request_byte_count=len(request) - 1,
                    source_family_counts={**counts, "projects": 1},
                ),
                "reserved",
            )

    def test_retrying_completed_canary_subject_requires_rebuilt_canary(self) -> None:
        request = b'{"application":[],"career":[],"devpost":[],"projects":[]}'
        counts = {
            "application": 0, "career": 0, "devpost": 0, "projects": 0,
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "rich-semantic-run"
            ledger = self._ledger(root)
            subject = _subjects()[0]
            request_sha256 = hashlib.sha256(request).hexdigest()
            ledger.reserve(
                subject, request_sha256=request_sha256,
                request_byte_count=len(request), source_family_counts=counts,
            )
            ledger.complete(
                subject, cache_status="miss", input_tokens=100,
                model_version="gpt-5.6-sol", output_tokens=50,
            )
            for canary_subject in _subjects()[1:5]:
                ledger.record_existing(canary_subject)
            ledger.complete_canary()

            ledger.retry_once(
                subject, expected_state="completed",
                replacement_request_sha256="e" * 64,
                replacement_request_byte_count=len(request) - 1,
                replacement_source_family_counts={**counts, "projects": 1},
            )

            self.assertFalse(ledger.canary_path.exists())
            restarted = self._ledger(root)
            with self.assertRaisesRegex(PermissionError, "canary receipt"):
                restarted.subjects_for_mode("full")
            self.assertEqual(
                restarted.unprocessed_subjects("canary"), (subject,),
            )
            restarted.reserve(
                subject, request_sha256="e" * 64,
                request_byte_count=len(request) - 1,
                source_family_counts={**counts, "projects": 1},
            )
            restarted.complete(
                subject, cache_status="miss", input_tokens=10,
                model_version="gpt-5.6-sol", output_tokens=5,
            )
            restarted.complete_canary()
            self.assertEqual(restarted.subjects_for_mode("full"), _subjects())

    def test_completed_canary_retry_recovers_after_subject_removal_crash(self) -> None:
        request = b'{"application":[],"career":[],"devpost":[],"projects":[]}'
        counts = {
            "application": 0, "career": 0, "devpost": 0, "projects": 0,
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "rich-semantic-run"
            ledger = self._ledger(root)
            subject = _subjects()[0]
            request_sha256 = hashlib.sha256(request).hexdigest()
            ledger.reserve(
                subject, request_sha256=request_sha256,
                request_byte_count=len(request), source_family_counts=counts,
            )
            ledger.complete(
                subject, cache_status="miss", input_tokens=100,
                model_version="gpt-5.6-sol", output_tokens=50,
            )
            for canary_subject in _subjects()[1:5]:
                ledger.record_existing(canary_subject)
            ledger.complete_canary()
            subject_path = (
                root / "subjects"
                / f"{hashlib.sha256(subject.encode('ascii')).hexdigest()}.json"
            )
            original_unlink = Path.unlink

            def interrupt_subject_removal(
                path: Path, *args: object, **kwargs: object,
            ) -> None:
                if path == subject_path:
                    raise OSError("simulated interruption after recovery receipt")
                original_unlink(path, *args, **kwargs)

            with patch(
                "pathlib.Path.unlink", autospec=True,
                side_effect=interrupt_subject_removal,
            ):
                with self.assertRaisesRegex(OSError, "simulated interruption"):
                    ledger.retry_once(
                        subject, expected_state="completed",
                        replacement_request_sha256="e" * 64,
                        replacement_request_byte_count=len(request) - 1,
                        replacement_source_family_counts={**counts, "projects": 1},
                    )

            self.assertFalse(ledger.canary_path.exists())
            restarted = self._ledger(root)
            recovery = restarted.retry_once(subject, expected_state="completed")
            self.assertEqual(recovery["state"], "retry_authorized")
            self.assertIsNone(restarted.subject_state(subject))
            restarted.reserve(
                subject, request_sha256="e" * 64,
                request_byte_count=len(request) - 1,
                source_family_counts={**counts, "projects": 1},
            )
            with self.assertRaisesRegex(PermissionError, "one-time|already used"):
                restarted.retry_once(subject, expected_state="reserved")

    def test_reserved_empty_subject_can_be_finalized_once_without_retrying(self) -> None:
        request = b'{"application":[],"career":[],"devpost":[],"projects":[]}'
        counts = {
            "application": 0, "career": 0, "devpost": 0, "projects": 0,
        }
        with tempfile.TemporaryDirectory() as directory:
            ledger = self._ledger(Path(directory) / "rich-semantic-run")
            subject = _subjects()[0]
            request_sha256 = hashlib.sha256(request).hexdigest()
            ledger.reserve(
                subject, request_sha256=request_sha256,
                request_byte_count=len(request), source_family_counts=counts,
            )

            first = ledger.record_empty(
                subject, request_sha256=request_sha256,
                request_byte_count=len(request), source_family_counts=counts,
            )
            second = ledger.record_empty(
                subject, request_sha256=request_sha256,
                request_byte_count=len(request), source_family_counts=counts,
            )

        self.assertEqual(first["state"], "empty")
        self.assertEqual(second, first)

    def test_changed_request_for_reserved_subject_is_binding_drift(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            ledger = self._ledger(Path(directory) / "rich-semantic-run")
            subject = _subjects()[0]
            counts = {
                "application": 1, "career": 0, "devpost": 0, "projects": 0,
            }
            ledger.reserve(
                subject, request_sha256="d" * 64, request_byte_count=42,
                source_family_counts=counts,
            )

            with self.assertRaisesRegex(PermissionError, "request binding drift"):
                ledger.reserve(
                    subject, request_sha256="e" * 64, request_byte_count=42,
                    source_family_counts=counts,
                )

    def test_existing_case_cannot_overwrite_an_ambiguous_reservation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            ledger = self._ledger(Path(directory) / "rich-semantic-run")
            subject = _subjects()[0]
            ledger.reserve(
                subject, request_sha256="d" * 64, request_byte_count=42,
                source_family_counts={
                    "application": 1, "career": 0, "devpost": 0, "projects": 0,
                },
            )

            with self.assertRaisesRegex(PermissionError, "non-final"):
                ledger.record_existing(subject)

            self.assertEqual(ledger.subject_state(subject), "reserved")

    def test_tampered_subject_receipt_is_not_treated_as_processed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "rich-semantic-run"
            ledger = self._ledger(root)
            subject = _subjects()[0]
            ledger.record_existing(subject)
            record_path = next((root / "subjects").glob("*.json"))
            record = json.loads(record_path.read_text(encoding="utf-8"))
            record["state"] = "completed"
            record_path.write_text(json.dumps(record), encoding="utf-8")

            with self.assertRaisesRegex(PermissionError, "receipt.*tampered"):
                self._ledger(root)


if __name__ == "__main__":
    unittest.main()
