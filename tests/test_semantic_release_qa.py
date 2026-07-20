from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest


def population() -> dict[str, object]:
    return {
        "assessed_count": 195,
        "eligible_count": 286,
        "excluded_count": 0,
        "population_key": "all_applicants",
        "snapshot_sha256": "6" * 64,
        "state_counts": {
            "assessed": 195,
            "conflict": 0,
            "excluded": 0,
            "no_evidence": 87,
            "provider_unavailable": 0,
            "rejected": 4,
        },
        "total_count": 286,
        "unknown_count": 91,
    }


def context() -> dict[str, object]:
    from community_os.semantic_release_qa import build_semantic_release_qa_context

    return build_semantic_release_qa_context(
        event_approval_sha256="1" * 64,
        event_definition_sha256="2" * 64,
        event_key="start-warsaw-2026-07",
        source_snapshot_sha256="3" * 64,
        population=population(),
        run_sha256="4" * 64,
        taxonomy_version="talent-taxonomy-v1",
        aggregate_sha256="5" * 64,
        html_candidate_sha256="7" * 64,
        pdf_candidate_sha256="8" * 64,
        positive_claim_count=24,
        required_review_case_count=9,
        review_evidence_sha256="9" * 64,
    )


def checks() -> dict[str, dict[str, object]]:
    return {
        "aggregate_rederived": {
            "passed": True, "evidence_count": 7, "expected_count": 7,
        },
        "artifact_privacy_parity": {
            "passed": True, "evidence_count": 4, "expected_count": 4,
        },
        "dashboard_state_parity": {
            "passed": True, "evidence_count": 4, "expected_count": 4,
        },
        "html_pdf_text_parity": {
            "passed": True, "evidence_count": 5, "expected_count": 5,
        },
        "pdf_layout": {
            "passed": True, "evidence_count": 5, "expected_count": 5,
        },
        "required_review_cases_resolved": {
            "passed": True, "evidence_count": 9, "expected_count": 9,
        },
        "positive_claim_sample_bound_to_final_reviewed_facts": {
            "passed": True, "evidence_count": 10, "expected_count": 10,
        },
    }


class SemanticReleaseQAReceiptTests(unittest.TestCase):
    def test_receipt_schema_names_final_fact_binding_honestly(self) -> None:
        from community_os.semantic_release_qa import CHECK_KEYS, RECEIPT_VERSION

        self.assertEqual(RECEIPT_VERSION, "semantic-release-qa-v3")
        self.assertIn(
            "positive_claim_sample_bound_to_final_reviewed_facts", CHECK_KEYS,
        )
        self.assertIn("dashboard_state_parity", CHECK_KEYS)
        self.assertNotIn("positive_claim_sample_reviewed", CHECK_KEYS)

    def test_builder_is_canonical_deterministic_and_derives_taxonomy_hash(self) -> None:
        from community_os.semantic_metrics import semantic_taxonomy_sha256
        from community_os.semantic_release_qa import (
            build_semantic_release_qa_context,
            build_semantic_release_qa_receipt,
        )

        first_context = context()
        reversed_population = population()
        reversed_population["state_counts"] = dict(reversed(
            list(reversed_population["state_counts"].items()),
        ))
        second_context = build_semantic_release_qa_context(
            event_approval_sha256="1" * 64,
            event_definition_sha256="2" * 64,
            event_key="start-warsaw-2026-07",
            source_snapshot_sha256="3" * 64,
            population=dict(reversed(list(reversed_population.items()))),
            run_sha256="4" * 64,
            taxonomy_version="talent-taxonomy-v1",
            aggregate_sha256="5" * 64,
            html_candidate_sha256="7" * 64,
            pdf_candidate_sha256="8" * 64,
            positive_claim_count=24,
            required_review_case_count=9,
            review_evidence_sha256="9" * 64,
        )
        first = build_semantic_release_qa_receipt(
            context=first_context, checks=checks(),
        )
        second = build_semantic_release_qa_receipt(
            context=second_context,
            checks=dict(reversed(list(checks().items()))),
        )

        self.assertEqual(first.canonical_bytes(), second.canonical_bytes())
        self.assertEqual(first.sha256, second.sha256)
        self.assertEqual(
            first.sha256, hashlib.sha256(first.canonical_bytes()).hexdigest(),
        )
        record = first.to_record()
        self.assertEqual(record["version"], "semantic-release-qa-v3")
        self.assertIn(
            "positive_claim_sample_bound_to_final_reviewed_facts",
            record["checks"],
        )
        self.assertNotIn("positive_claim_sample_reviewed", record["checks"])
        self.assertEqual(
            record["context"]["taxonomy_sha256"],
            semantic_taxonomy_sha256("talent-taxonomy-v1"),
        )
        self.assertEqual(
            first.canonical_json(),
            json.dumps(
                record, ensure_ascii=True, sort_keys=True,
                separators=(",", ":"), allow_nan=False,
            ),
        )

    def test_validator_rejects_missing_false_malformed_or_prose_checks(self) -> None:
        from community_os.semantic_release_qa import (
            SemanticReleaseQAError,
            build_semantic_release_qa_receipt,
            validate_semantic_release_qa_receipt,
        )

        receipt = build_semantic_release_qa_receipt(
            context=context(), checks=checks(),
        ).to_record()
        cases: list[tuple[str, dict[str, object]]] = []

        missing = deepcopy(receipt)
        del missing["checks"]["pdf_layout"]
        cases.append(("missing", missing))

        false_check = deepcopy(receipt)
        false_check["checks"]["pdf_layout"]["passed"] = False
        cases.append(("false", false_check))

        truthy_integer = deepcopy(receipt)
        truthy_integer["checks"]["pdf_layout"]["passed"] = 1
        cases.append(("truthy_integer", truthy_integer))

        mismatched_counter = deepcopy(receipt)
        mismatched_counter["checks"]["pdf_layout"]["evidence_count"] = 4
        cases.append(("mismatched_counter", mismatched_counter))

        negative_counter = deepcopy(receipt)
        negative_counter["checks"]["pdf_layout"]["expected_count"] = -1
        cases.append(("negative_counter", negative_counter))

        prose = deepcopy(receipt)
        prose["checks"]["pdf_layout"]["note"] = "Looks good to me"
        cases.append(("free_prose", prose))

        extra_check = deepcopy(receipt)
        extra_check["checks"]["manual_opinion"] = {
            "passed": True, "evidence_count": 1, "expected_count": 1,
        }
        cases.append(("extra_check", extra_check))

        extra_top_level = deepcopy(receipt)
        extra_top_level["participant_name"] = "Private Person"
        cases.append(("pii_field", extra_top_level))

        for label, value in cases:
            with self.subTest(case=label):
                with self.assertRaises(SemanticReleaseQAError):
                    validate_semantic_release_qa_receipt(
                        value, expected_context=context(),
                    )

    def test_positive_claims_cannot_pass_with_an_empty_final_fact_binding_sample(self) -> None:
        from community_os.semantic_release_qa import (
            SemanticReleaseQAError,
            build_semantic_release_qa_receipt,
        )

        empty_review = checks()
        empty_review["positive_claim_sample_bound_to_final_reviewed_facts"] = {
            "passed": True, "evidence_count": 0, "expected_count": 0,
        }

        with self.assertRaisesRegex(SemanticReleaseQAError, "positive_claim"):
            build_semantic_release_qa_receipt(
                context=context(), checks=empty_review,
            )

    def test_legacy_reviewed_sample_claim_is_rejected(self) -> None:
        from community_os.semantic_release_qa import (
            SemanticReleaseQAError,
            build_semantic_release_qa_receipt,
            validate_semantic_release_qa_receipt,
        )

        release_context = context()
        record = build_semantic_release_qa_receipt(
            context=release_context, checks=checks(),
        ).to_record()
        record["version"] = "semantic-release-qa-v2"
        record["checks"]["positive_claim_sample_reviewed"] = record[
            "checks"
        ].pop("positive_claim_sample_bound_to_final_reviewed_facts")

        with self.assertRaises(SemanticReleaseQAError):
            validate_semantic_release_qa_receipt(
                record, expected_context=release_context,
            )

    def test_context_and_population_must_match_exact_reconciled_release_state(self) -> None:
        from community_os.semantic_metrics import semantic_taxonomy_sha256
        from community_os.semantic_release_qa import (
            SemanticReleaseQAError,
            build_semantic_release_qa_context,
            build_semantic_release_qa_receipt,
            validate_semantic_release_qa_receipt,
        )

        release_context = context()
        record = build_semantic_release_qa_receipt(
            context=release_context, checks=checks(),
        ).to_record()
        direct_fields = (
            "event_approval_sha256", "event_definition_sha256", "event_key",
            "source_snapshot_sha256", "run_sha256", "taxonomy_version",
            "taxonomy_sha256", "aggregate_sha256", "html_candidate_sha256",
            "pdf_candidate_sha256", "positive_claim_count",
            "required_review_case_count", "review_evidence_sha256",
        )
        for field in direct_fields:
            expected = deepcopy(release_context)
            if field == "event_key":
                expected[field] = "different-event"
            elif field == "taxonomy_version":
                expected[field] = "talent-taxonomy-v2"
                expected["taxonomy_sha256"] = semantic_taxonomy_sha256(
                    "talent-taxonomy-v2",
                )
            elif field == "taxonomy_sha256":
                expected["taxonomy_version"] = "talent-taxonomy-v2"
                expected[field] = semantic_taxonomy_sha256("talent-taxonomy-v2")
            elif field in {"positive_claim_count", "required_review_case_count"}:
                expected[field] = int(expected[field]) + 1
            else:
                expected[field] = "f" * 64
            with self.subTest(context_field=field):
                with self.assertRaisesRegex(SemanticReleaseQAError, "context"):
                    validate_semantic_release_qa_receipt(
                        record, expected_context=expected,
                    )

        expected = deepcopy(release_context)
        expected["population"]["snapshot_sha256"] = "f" * 64
        with self.assertRaisesRegex(SemanticReleaseQAError, "context"):
            validate_semantic_release_qa_receipt(record, expected_context=expected)

        extra_population_field = population()
        extra_population_field["participant_email"] = "private@example.org"
        with self.assertRaises(SemanticReleaseQAError):
            build_semantic_release_qa_context(
                event_approval_sha256="1" * 64,
                event_definition_sha256="2" * 64,
                event_key="start-warsaw-2026-07",
                source_snapshot_sha256="3" * 64,
                population=extra_population_field,
                run_sha256="4" * 64,
                taxonomy_version="talent-taxonomy-v1",
                aggregate_sha256="5" * 64,
                html_candidate_sha256="7" * 64,
                pdf_candidate_sha256="8" * 64,
                positive_claim_count=24,
                required_review_case_count=9,
                review_evidence_sha256="9" * 64,
            )

        unreconciled = population()
        unreconciled["unknown_count"] = 90
        with self.assertRaisesRegex(SemanticReleaseQAError, "population"):
            build_semantic_release_qa_context(
                event_approval_sha256="1" * 64,
                event_definition_sha256="2" * 64,
                event_key="start-warsaw-2026-07",
                source_snapshot_sha256="3" * 64,
                population=unreconciled,
                run_sha256="4" * 64,
                taxonomy_version="talent-taxonomy-v1",
                aggregate_sha256="5" * 64,
                html_candidate_sha256="7" * 64,
                pdf_candidate_sha256="8" * 64,
                positive_claim_count=24,
                required_review_case_count=9,
                review_evidence_sha256="9" * 64,
            )

    def test_loader_requires_regular_0600_strict_json_and_context_match(self) -> None:
        from community_os.semantic_release_qa import (
            SemanticReleaseQAError,
            build_semantic_release_qa_receipt,
            load_semantic_release_qa_receipt,
        )

        release_context = context()
        receipt = build_semantic_release_qa_receipt(
            context=release_context, checks=checks(),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "semantic-release-qa.json"
            path.write_text(receipt.canonical_json() + "\n", encoding="utf-8")
            path.chmod(0o644)
            with self.assertRaisesRegex(SemanticReleaseQAError, "0600"):
                load_semantic_release_qa_receipt(
                    path, expected_context=release_context,
                )

            path.chmod(0o600)
            loaded = load_semantic_release_qa_receipt(
                path, expected_context=release_context,
            )
            self.assertEqual(loaded.sha256, receipt.sha256)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

            symlink = root / "qa-link.json"
            symlink.symlink_to(path)
            with self.assertRaisesRegex(SemanticReleaseQAError, "unsafe"):
                load_semantic_release_qa_receipt(
                    symlink, expected_context=release_context,
                )

            duplicate = root / "duplicate.json"
            duplicate.write_text(
                '{"version":"semantic-release-qa-v3",'
                '"version":"semantic-release-qa-v3"}',
                encoding="utf-8",
            )
            duplicate.chmod(0o600)
            with self.assertRaisesRegex(SemanticReleaseQAError, "duplicate"):
                load_semantic_release_qa_receipt(
                    duplicate, expected_context=release_context,
                )

            nonfinite = root / "nonfinite.json"
            nonfinite.write_text('{"version":NaN}', encoding="utf-8")
            nonfinite.chmod(0o600)
            with self.assertRaisesRegex(SemanticReleaseQAError, "non-finite"):
                load_semantic_release_qa_receipt(
                    nonfinite, expected_context=release_context,
                )


if __name__ == "__main__":
    unittest.main()
