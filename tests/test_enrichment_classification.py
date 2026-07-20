from __future__ import annotations

from datetime import UTC, datetime
import json
from pathlib import Path
import tempfile
import unittest

from community_os.enrichment.cache import CanonicalJsonCache
from community_os.enrichment.classification import ClassificationInput, ProcessorApproval, SemanticClassifier


def approval(provider: str = "approved_processor") -> ProcessorApproval:
    return ProcessorApproval(
        provider=provider, purpose="talent_classification", dpa_version="dpa-v1",
        terms_version="terms-v1", retention_mode="zero_retention", region="eu",
        security_profile="approved-v1",
        field_allowlist=frozenset({"subject_ref", "signals", "evidence_refs"}),
        approved_by="start_privacy_owner", approved_at="2026-07-13T09:00:00Z",
    )


class EnrichmentClassificationTests(unittest.TestCase):
    @staticmethod
    def _observed_dimensions() -> dict[str, object]:
        labels = {
            "professional_identity": "startup_operator", "seniority": "senior",
            "functional_role": "engineering", "employer_pedigree": "academia_research",
            "builder_evidence": "shipped_product", "capabilities": "backend",
            "domains": "applied_ai",
        }
        return {
            key: {
                "labels": [label], "confidence": 0.99,
                "evidence_refs": ["evidence:application:abc"],
            }
            for key, label in labels.items()
        }

    def test_ai_input_is_structured_pseudonymous_and_minimum_necessary(self) -> None:
        observed: list[dict[str, object]] = []

        def provider(value: dict[str, object]) -> dict[str, object]:
            observed.append(value)
            return {
                "dimensions": {
                    "professional_identity": {"labels": ["startup_operator"], "confidence": 0.86, "evidence_refs": ["evidence:application:abc"]},
                    "seniority": {"labels": ["senior"], "confidence": 0.91, "evidence_refs": ["evidence:application:abc"]},
                    "functional_role": {"labels": ["engineering"], "confidence": 0.88, "evidence_refs": ["evidence:application:abc"]},
                    "employer_pedigree": {"labels": ["unknown"], "confidence": 0.0, "evidence_refs": []},
                    "builder_evidence": {"labels": ["shipped_product"], "confidence": 0.89, "evidence_refs": ["evidence:application:abc"]},
                    "capabilities": {"labels": ["backend"], "confidence": 0.87, "evidence_refs": ["evidence:application:abc"]},
                    "domains": {"labels": ["applied_ai"], "confidence": 0.82, "evidence_refs": ["evidence:application:abc"]},
                }
            }

        now = datetime(2026, 7, 13, 10, tzinfo=UTC)
        with tempfile.TemporaryDirectory() as directory:
            classifier = SemanticClassifier(
                provider=provider,
                cache=CanonicalJsonCache(Path(directory), clock=lambda: now),
                clock=lambda: now,
                approval=approval(),
                model="fixture-model",
                prompt_version="talent-structured-v1",
                taxonomy_version="talent-taxonomy-v1",
                classifier_version="semantic-v1",
            )
            source = ClassificationInput(
                subject_ref="pid:v1:" + "a" * 64,
                signals={"occupation_codes": ["role_engineering"], "experience_band": "senior", "builder_codes": ["builder_shipped_product"]},
                evidence_refs=("evidence:application:abc",),
            )
            result = classifier.classify(source)
            cached = classifier.classify(source)
        self.assertEqual(result, cached)
        self.assertEqual(len(observed), 1)
        sent = json.dumps(observed[0], sort_keys=True)
        self.assertNotIn("email", sent.casefold())
        self.assertNotIn("name", sent.casefold())
        self.assertNotIn("http", sent.casefold())
        self.assertEqual(result["review_state"], "pending")
        self.assertEqual(result["dimensions"]["seniority"]["state"], "observed")

    def test_rich_approval_cannot_authorize_legacy_classification_payload(self) -> None:
        from community_os.enrichment.github_content_evidence import RICH_PROJECT_FIELDS
        from community_os.enrichment.rich_semantic_assessment import (
            PROFILE_ALLOWED_KEYS, PROMPT_VERSION,
        )

        now = datetime(2026, 7, 13, 10, tzinfo=UTC)
        rich_approval = ProcessorApproval(
            provider="openai_responses", purpose="rich_semantic_assessment",
            dpa_version="dpa-v1", terms_version="terms-v1",
            retention_mode="zero_retention", region="eu",
            security_profile="approved-v1",
            field_allowlist=PROFILE_ALLOWED_KEYS.union(RICH_PROJECT_FIELDS),
            approved_by="start_privacy_owner", approved_at="2026-07-13T09:00:00Z",
            payload_version=PROMPT_VERSION,
        )
        provider_calls: list[dict[str, object]] = []
        with tempfile.TemporaryDirectory() as directory:
            classifier = SemanticClassifier(
                provider=lambda value: provider_calls.append(value) or {
                    "dimensions": self._observed_dimensions(),
                },
                cache=CanonicalJsonCache(Path(directory), clock=lambda: now),
                clock=lambda: now, approval=rich_approval, model="fixture-model",
                prompt_version="talent-structured-v1",
                taxonomy_version="talent-taxonomy-v1", classifier_version="semantic-v1",
            )
            with self.assertRaisesRegex(PermissionError, "payload contract"):
                classifier.classify(ClassificationInput(
                    subject_ref="pid:v1:" + "8" * 64,
                    signals={
                        "occupation_codes": ["role_engineering"],
                        "experience_band": "senior",
                        "builder_codes": ["builder_shipped_product"],
                    },
                    evidence_refs=("evidence:application:abc",),
                ))

        self.assertEqual(provider_calls, [])

    def test_global_project_posture_requires_explicit_default_abuse_monitoring_retention(self) -> None:
        now = datetime(2026, 7, 14, 18, tzinfo=UTC)
        approved = ProcessorApproval(**{
            **approval().__dict__,
            "region": "global",
            "retention_mode": "default_abuse_monitoring_30d",
            "security_profile": "project_scoped_store_false_minimized_v1",
            "approved_at": "2026-07-14T17:00:00Z",
        })

        approved.authorize(now=now)

        wrong_profile = ProcessorApproval(**{
            **approved.__dict__, "security_profile": "generic_profile",
        })
        with self.assertRaisesRegex(PermissionError, "security profile"):
            wrong_profile.authorize(now=now)

        for region, retention_mode in (
            ("global", "zero_retention"),
            ("global", "no_training"),
            ("eu", "default_abuse_monitoring_30d"),
        ):
            mismatched = ProcessorApproval(**{
                **approved.__dict__,
                "region": region,
                "retention_mode": retention_mode,
            })
            with self.subTest(region=region, retention_mode=retention_mode):
                with self.assertRaisesRegex(PermissionError, "retention.*region|region.*retention"):
                    mismatched.authorize(now=now)

    def test_unknown_and_low_confidence_outputs_enter_human_review_queue(self) -> None:
        def provider(_value: dict[str, object]) -> dict[str, object]:
            return {"dimensions": {
                "seniority": {"labels": ["unknown"], "confidence": 0.0, "evidence_refs": []},
                "professional_identity": {"labels": ["founder_cofounder"], "confidence": 0.61, "evidence_refs": ["evidence:application:abc"]},
            }}

        now = datetime(2026, 7, 13, 10, tzinfo=UTC)
        with tempfile.TemporaryDirectory() as directory:
            classifier = SemanticClassifier(
                provider=provider, cache=CanonicalJsonCache(Path(directory), clock=lambda: now),
                clock=lambda: now, approval=approval(), model="fixture-model",
                prompt_version="talent-structured-v1", taxonomy_version="talent-taxonomy-v1",
                classifier_version="semantic-v1",
            )
            result = classifier.classify(ClassificationInput(
                subject_ref="pid:v1:" + "b" * 64,
                signals={"occupation_codes": ["unknown"], "experience_band": "unknown", "builder_codes": []},
                evidence_refs=("evidence:application:abc",),
            ))
        self.assertEqual(result["review_state"], "pending")
        self.assertEqual(set(result["review_reasons"]), {"low_confidence", "consequential_claim", "unknown_state", "incomplete_provider_output"})
        self.assertEqual(set(result["dimensions"]), {
            "professional_identity", "seniority", "functional_role", "employer_pedigree",
            "builder_evidence", "capabilities", "domains",
        })

    def test_empty_provider_dimensions_become_explicit_unknowns_and_require_review(self) -> None:
        now = datetime(2026, 7, 13, 10, tzinfo=UTC)
        with tempfile.TemporaryDirectory() as directory:
            classifier = SemanticClassifier(
                provider=lambda _value: {"dimensions": {}},
                cache=CanonicalJsonCache(Path(directory), clock=lambda: now),
                clock=lambda: now, approval=approval(), model="fixture-model",
                prompt_version="talent-structured-v1", taxonomy_version="talent-taxonomy-v1",
                classifier_version="semantic-v1",
            )
            result = classifier.classify(ClassificationInput(
                subject_ref="pid:v1:" + "e" * 64,
                signals={"occupation_codes": ["unknown"], "experience_band": "unknown", "builder_codes": []},
                evidence_refs=("evidence:application:abc",),
            ))
        self.assertEqual(result["review_state"], "pending")
        self.assertEqual(
            set(result["review_reasons"]),
            {"incomplete_provider_output", "low_confidence", "unknown_state"},
        )
        self.assertEqual(
            {key: item["labels"] for key, item in result["dimensions"].items()},
            {
                "professional_identity": ["insufficient_evidence"],
                "seniority": ["unknown"], "functional_role": ["unknown"],
                "employer_pedigree": ["unknown"],
                "builder_evidence": ["insufficient_evidence"],
                "capabilities": ["unknown"], "domains": ["unknown"],
            },
        )

    def test_direct_identifiers_urls_raw_fields_and_unapproved_processor_fail_before_provider(self) -> None:
        calls: list[object] = []
        now = datetime(2026, 7, 13, 10, tzinfo=UTC)
        with tempfile.TemporaryDirectory() as directory:
            cache = CanonicalJsonCache(Path(directory), clock=lambda: now)
            for signals in (
                {"email": "person@example.org"}, {"profile_url": "https://example.org"},
                {"raw_payload": "text"}, {"occupation_codes": ["person@example.org"]},
            ):
                with self.subTest(signals=signals), self.assertRaises(ValueError):
                    ClassificationInput(
                        subject_ref="pid:v1:" + "c" * 64,
                        signals=signals,
                        evidence_refs=("evidence:application:abc",),
                    )
            classifier = SemanticClassifier(
                provider=lambda value: calls.append(value) or {}, cache=cache, clock=lambda: now,
                approval=approval(""), model="fixture", prompt_version="v1",
                taxonomy_version="v1", classifier_version="v1",
            )
            with self.assertRaises(PermissionError):
                classifier.classify(ClassificationInput(
                    subject_ref="pid:v1:" + "d" * 64,
                    signals={"occupation_codes": ["unknown"], "experience_band": "unknown", "builder_codes": []},
                    evidence_refs=("evidence:application:abc",),
                ))
        self.assertEqual(calls, [])

    def test_processor_approval_cannot_be_future_dated_and_is_bound_to_cache_provenance(self) -> None:
        calls: list[str] = []
        now = datetime(2026, 7, 13, 10, tzinfo=UTC)
        source = ClassificationInput(
            subject_ref="pid:v1:" + "f" * 64,
            signals={"occupation_codes": ["unknown"], "experience_band": "unknown", "builder_codes": []},
            evidence_refs=("evidence:application:abc",),
        )
        dimensions = {
            key: {"labels": [label], "confidence": 0.0, "evidence_refs": []}
            for key, label in {
                "professional_identity": "insufficient_evidence", "seniority": "unknown",
                "functional_role": "unknown", "employer_pedigree": "unknown",
                "builder_evidence": "insufficient_evidence", "capabilities": "unknown",
                "domains": "unknown",
            }.items()
        }
        with tempfile.TemporaryDirectory() as directory:
            cache = CanonicalJsonCache(Path(directory), clock=lambda: now)
            future = ProcessorApproval(**{
                **approval().__dict__, "approved_at": "2099-01-01T00:00:00Z",
            })
            blocked = SemanticClassifier(
                provider=lambda _value: calls.append("future") or {"dimensions": dimensions},
                cache=cache, clock=lambda: now, approval=future, model="fixture",
                prompt_version="v1", taxonomy_version="v1", classifier_version="v1",
            )
            with self.assertRaisesRegex(PermissionError, "future"):
                blocked.classify(source)
            first = SemanticClassifier(
                provider=lambda _value: calls.append("terms_v1") or {"dimensions": dimensions},
                cache=cache, clock=lambda: now, approval=approval(), model="fixture",
                prompt_version="v1", taxonomy_version="v1", classifier_version="v1",
            ).classify(source)
            changed = ProcessorApproval(**{**approval().__dict__, "terms_version": "terms-v2"})
            second = SemanticClassifier(
                provider=lambda _value: calls.append("terms_v2") or {"dimensions": dimensions},
                cache=cache, clock=lambda: now, approval=changed, model="fixture",
                prompt_version="v1", taxonomy_version="v1", classifier_version="v1",
            ).classify(source)
        self.assertEqual(calls, ["terms_v1", "terms_v2"])
        self.assertNotEqual(first["processor_approval_hash"], second["processor_approval_hash"])

    def test_provider_labels_must_belong_to_the_versioned_dimension_taxonomy(self) -> None:
        now = datetime(2026, 7, 13, 10, tzinfo=UTC)
        with tempfile.TemporaryDirectory() as directory:
            classifier = SemanticClassifier(
                provider=lambda _value: {"dimensions": {
                    "seniority": {
                        "labels": ["superstar"], "confidence": 0.99,
                        "evidence_refs": ["evidence:application:abc"],
                    },
                }},
                cache=CanonicalJsonCache(Path(directory), clock=lambda: now),
                clock=lambda: now, approval=approval(), model="fixture-model",
                prompt_version="talent-structured-v1",
                taxonomy_version="talent-taxonomy-v1", classifier_version="semantic-v1",
            )
            with self.assertRaisesRegex(ValueError, "taxonomy"):
                classifier.classify(ClassificationInput(
                    subject_ref="pid:v1:" + "f" * 64,
                    signals={"occupation_codes": ["unknown"], "experience_band": "unknown", "builder_codes": []},
                    evidence_refs=("evidence:application:abc",),
                ))

    def test_observed_semantic_dimensions_require_bound_evidence(self) -> None:
        now = datetime(2026, 7, 13, 10, tzinfo=UTC)
        dimensions = self._observed_dimensions()
        dimensions["functional_role"] = {
            "labels": ["engineering"], "confidence": 0.99, "evidence_refs": [],
        }
        with tempfile.TemporaryDirectory() as directory:
            classifier = SemanticClassifier(
                provider=lambda _value: {"dimensions": dimensions},
                cache=CanonicalJsonCache(Path(directory), clock=lambda: now),
                clock=lambda: now, approval=approval(), model="fixture-model",
                prompt_version="talent-structured-v1",
                taxonomy_version="talent-taxonomy-v1", classifier_version="semantic-v1",
            )
            with self.assertRaisesRegex(ValueError, "evidence"):
                classifier.classify(ClassificationInput(
                    subject_ref="pid:v1:" + "9" * 64,
                    signals={"occupation_codes": ["role_engineering"], "experience_band": "senior", "builder_codes": ["builder_shipped_product"]},
                    evidence_refs=("evidence:application:abc",),
                ))

    def test_consequential_seniority_requires_human_review_at_high_confidence(self) -> None:
        now = datetime(2026, 7, 13, 10, tzinfo=UTC)
        dimensions = self._observed_dimensions()
        dimensions["seniority"] = {
            "labels": ["founder"], "confidence": 0.99,
            "evidence_refs": ["evidence:application:abc"],
        }
        with tempfile.TemporaryDirectory() as directory:
            result = SemanticClassifier(
                provider=lambda _value: {"dimensions": dimensions},
                cache=CanonicalJsonCache(Path(directory), clock=lambda: now),
                clock=lambda: now, approval=approval(), model="fixture-model",
                prompt_version="talent-structured-v1",
                taxonomy_version="talent-taxonomy-v1", classifier_version="semantic-v1",
            ).classify(ClassificationInput(
                subject_ref="pid:v1:" + "8" * 64,
                signals={"occupation_codes": ["identity_founder_cofounder"], "experience_band": "founder", "builder_codes": ["builder_founded_company"]},
                evidence_refs=("evidence:application:abc",),
            ))
        self.assertEqual(result["review_state"], "pending")
        self.assertIn("consequential_claim", result["review_reasons"])

    def test_mixed_unknown_and_observed_labels_require_human_review(self) -> None:
        now = datetime(2026, 7, 13, 10, tzinfo=UTC)
        dimensions = self._observed_dimensions()
        dimensions["seniority"] = {
            "labels": ["unknown", "senior"], "confidence": 0.99,
            "evidence_refs": ["evidence:application:abc"],
        }
        with tempfile.TemporaryDirectory() as directory:
            result = SemanticClassifier(
                provider=lambda _value: {"dimensions": dimensions},
                cache=CanonicalJsonCache(Path(directory), clock=lambda: now),
                clock=lambda: now, approval=approval(), model="fixture-model",
                prompt_version="talent-structured-v1",
                taxonomy_version="talent-taxonomy-v1", classifier_version="semantic-v1",
            ).classify(ClassificationInput(
                subject_ref="pid:v1:" + "7" * 64,
                signals={"occupation_codes": ["role_engineering"], "experience_band": "senior", "builder_codes": []},
                evidence_refs=("evidence:application:abc",),
            ))

        self.assertEqual(result["review_state"], "pending")
        self.assertEqual(result["dimensions"]["seniority"]["state"], "unknown")
        self.assertIn("contradictory_labels", result["review_reasons"])
        self.assertIn("unknown_state", result["review_reasons"])

    def test_multiple_mutually_exclusive_labels_require_human_review(self) -> None:
        now = datetime(2026, 7, 13, 10, tzinfo=UTC)
        dimensions = self._observed_dimensions()
        dimensions["employer_pedigree"] = {
            "labels": ["academia_research", "student_no_employer"],
            "confidence": 0.99, "evidence_refs": ["evidence:application:abc"],
        }
        with tempfile.TemporaryDirectory() as directory:
            result = SemanticClassifier(
                provider=lambda _value: {"dimensions": dimensions},
                cache=CanonicalJsonCache(Path(directory), clock=lambda: now),
                clock=lambda: now, approval=approval(), model="fixture-model",
                prompt_version="talent-structured-v1",
                taxonomy_version="talent-taxonomy-v1", classifier_version="semantic-v1",
            ).classify(ClassificationInput(
                subject_ref="pid:v1:" + "6" * 64,
                signals={"occupation_codes": ["employer_academia_research"], "experience_band": "senior", "builder_codes": []},
                evidence_refs=("evidence:application:abc",),
            ))

        self.assertEqual(result["review_state"], "pending")
        self.assertIn("contradictory_labels", result["review_reasons"])

    def test_semantic_input_rejects_code_shaped_values_outside_local_allowlists(self) -> None:
        for signals in (
            {"occupation_codes": ["identity_jane_smith"], "experience_band": "senior", "builder_codes": []},
            {"occupation_codes": ["role_engineering"], "experience_band": "senior", "builder_codes": ["coresignal_company_jane_smith"]},
        ):
            with self.subTest(signals=signals), self.assertRaisesRegex(ValueError, "allowlist"):
                ClassificationInput(
                    subject_ref="pid:v1:" + "7" * 64, signals=signals,
                    evidence_refs=("evidence:application:abc",),
                )


if __name__ == "__main__":
    unittest.main()
