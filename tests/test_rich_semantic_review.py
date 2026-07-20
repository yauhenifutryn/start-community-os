from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone
import hashlib
import inspect
import json
from pathlib import Path
import tempfile
import unittest

from community_os.enrichment.openai_rich_semantic_assessment import (
    OpenAIRichSemanticAssessmentProvider,
    rich_semantic_schema_sha256,
)
from community_os.enrichment.rich_semantic_assessment import PROMPT_VERSION
from community_os.release_operations import ReviewDecision, ReviewRepository
from community_os.semantic_metrics import semantic_taxonomy_sha256
from tests.test_rich_semantic_assessment import (
    FakeResponsesTransport,
    semantic_taxonomy_for_assessment,
)


NOW = datetime(2026, 7, 15, 14, tzinfo=UTC)
AUTHENTICATED_ACTOR = "colleague_" + "a" * 32
REVIEW_SIGNING_SECRET = b"rich-semantic-review-test-secret"
KNOWN_IDENTITY_LITERALS = (
    "Person Example", "person_handle", "person@example.org",
)


def _sha256(value: object) -> str:
    return hashlib.sha256(json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")).hexdigest()


def evidence() -> dict[str, object]:
    return {
        "projects": [{
            "activity_recency": "active_90d",
            "age_band": "established",
            "deployment_signal": "deployment_observed",
            "description_excerpt": "Product workflow with durable jobs and audit receipts.",
            "evidence_refs": [
                "project_01:ownership",
                "project_01:description", "project_01:readme",
                "project_01:release", "project_01:deployment",
            ],
            "forks_band": "none",
            "issues_band": "some",
            "language_code": "python",
            "productization_codes": ["issues_enabled", "license_present"],
            "project_code": "project_01",
            "readme_excerpt": "Runs background work, retries failures, and records decisions.",
            "repository_relationship": "profile_owned_nonfork",
            "release_signal": "release_observed",
            "size_band": "medium",
            "stars_band": "none",
            "topic_codes": ["developer_tools"],
        }],
        "application": [{
            "evidence_code": "application_01",
            "experience_excerpt": "Built production systems end to end.",
            "achievement_excerpt": "Shipped a product used by customers.",
            "evidence_refs": [
                "application_01:experience", "application_01:achievement",
            ],
        }],
        "devpost": [],
        "career": [],
    }


def assessment(**overrides: object) -> dict[str, object]:
    value: dict[str, object] = {
        "builder_level": "substantial",
        "career_summary": "",
        "cross_source_confidence": "medium",
        "evidence_refs": [
            "project_01:description", "project_01:deployment",
            "application_01:experience", "application_01:achievement",
        ],
        "execution_scope": "substantial_contributor",
        "external_validation": "none",
        "originality": "ordinary",
        "product_maturity": "working_product",
        "project_summary": "A working product with explicit operational evidence.",
        "rationale": "The supplied project evidence supports the bounded classification.",
        "reason_codes": ["end_to_end_delivery", "shipped_working_product"],
        "review_state": "human_review_required",
        "technical_depth": "advanced",
    }
    value.update(overrides)
    if "semantic_taxonomy" not in overrides:
        value["semantic_taxonomy"] = semantic_taxonomy_for_assessment(value)
    return value


def proposal(ordinal: int, **overrides: object) -> dict[str, object]:
    bound_evidence = evidence()
    model = "gpt-5.6-luna"
    value: dict[str, object] = {
        "approval_sha256": "a" * 64,
        "assessment": assessment(),
        "created_at": NOW.isoformat().replace("+00:00", "Z"),
        "evidence": bound_evidence,
        "evidence_sha256": _sha256(bound_evidence),
        "expires_at": (NOW + timedelta(days=3)).isoformat().replace("+00:00", "Z"),
        "model": model,
        "model_sha256": _sha256(model),
        "prompt_sha256": _sha256(PROMPT_VERSION),
        "prompt_version": PROMPT_VERSION,
        "schema_sha256": rich_semantic_schema_sha256(),
        "source_coverage": ["application", "projects"],
        "subject_ref": f"case:v1:{ordinal:064x}",
    }
    value.update(overrides)
    return value


def population_context() -> dict[str, str]:
    return {
        "event_approval_sha256": "1" * 64,
        "event_definition_sha256": "2" * 64,
        "event_key": "test-hackathon-2026",
        "run_sha256": "3" * 64,
        "source_snapshot_sha256": "4" * 64,
        "taxonomy_sha256": semantic_taxonomy_sha256("semantic-taxonomy-v1"),
        "taxonomy_version": "semantic-taxonomy-v1",
    }


def decision_manifest_row(
    packet: dict[str, object], *, action: str = "approved",
    actor_code: str = "proof_for_me_agent",
) -> dict[str, str]:
    return {
        "action": action,
        "actor_code": actor_code,
        "case_code": str(packet["case_code"]),
        "case_hash": str(packet["case_hash"]),
        "proposal_sha256": str(packet["proposal_sha256"]),
    }


def decision_manifest(*rows: dict[str, str]) -> dict[str, object]:
    return {
        "decisions": list(rows),
        "manifest_version": "rich-semantic-decision-manifest-v1",
    }


def insufficient_proposal(ordinal: int) -> dict[str, object]:
    empty_evidence = {
        "application": [], "career": [], "devpost": [], "projects": [],
    }
    empty_assessment = assessment(
        builder_level="insufficient",
        career_summary="",
        cross_source_confidence="low",
        evidence_refs=[],
        execution_scope="unknown",
        external_validation="none",
        originality="unknown",
        product_maturity="unknown",
        project_summary="",
        rationale="insufficient evidence.",
        reason_codes=["insufficient_evidence"],
        technical_depth="unknown",
    )
    empty_assessment["semantic_taxonomy"]["project"][
        "external_validation"
    ] = "unknown"
    return proposal(
        ordinal,
        evidence=empty_evidence,
        evidence_sha256=_sha256(empty_evidence),
        source_coverage=[],
        assessment=empty_assessment,
    )


def career_only_proposal(ordinal: int) -> dict[str, object]:
    career_evidence = {
        "application": [],
        "career": [{
            "active_state": "current",
            "description_excerpt": (
                "Led product delivery and production operations."
            ),
            "duration_band": "one_to_three_years",
            "evidence_refs": ["role_01:title", "role_01:description"],
            "industry_code": "software",
            "organization_size_band": "small",
            "role_code": "role_01",
            "seniority_context": "founder_executive",
            "title_excerpt": "Technical founder",
        }],
        "devpost": [],
        "projects": [],
    }
    career_assessment = assessment(
        builder_level="insufficient",
        career_summary=(
            "Repeated delivery responsibility spans products and operations."
        ),
        cross_source_confidence="medium",
        evidence_refs=["role_01:title", "role_01:description"],
        execution_scope="unknown",
        external_validation="none",
        originality="unknown",
        product_maturity="unknown",
        project_summary="",
        rationale="career evidence is available without project evidence.",
        reason_codes=["career_progression"],
        technical_depth="unknown",
    )
    career_assessment["semantic_taxonomy"]["project"][
        "external_validation"
    ] = "unknown"
    return proposal(
        ordinal,
        evidence=career_evidence,
        evidence_sha256=_sha256(career_evidence),
        source_coverage=["career"],
        assessment=career_assessment,
    )


class RichSemanticReviewTests(unittest.TestCase):
    def create_store(
        self, directory: str, *, clock=lambda: NOW, failpoint=None,
        approved_authorizations=frozenset({"a" * 64, "b" * 64}),
        review_context_hashes=None,
        decision_signing_secret=REVIEW_SIGNING_SECRET,
        known_identity_literals=KNOWN_IDENTITY_LITERALS,
    ):
        from community_os.rich_semantic_review import RichSemanticReviewStore

        root = Path(directory) / "rich-semantic-review"
        repository = ReviewRepository(Path(directory) / "operator" / "reviews.json")
        store = RichSemanticReviewStore(
            root,
            release_root=Path(directory) / "release",
            review_repository=repository,
            clock=clock,
            failpoint=failpoint,
            approval_verifier=lambda digest: digest in approved_authorizations,
            decision_signing_secret=decision_signing_secret,
            review_context_hashes=(
                review_context_hashes or {
                    "event_approval": "c" * 64,
                    "event_definition": "d" * 64,
                    "event_key": "e" * 64,
                }
            ),
            known_identity_literals=known_identity_literals,
        )
        return store, repository

    def test_approved_fact_retains_only_safe_bounded_reviewed_narrative(self) -> None:
        safe_project_summary = (
            "A durable developer workflow coordinates background jobs, retries "
            "failures, and records auditable outcomes."
        )
        candidate = proposal(1, assessment=assessment(
            project_summary=safe_project_summary,
        ))
        with tempfile.TemporaryDirectory() as directory:
            store, _ = self.create_store(directory)
            case = store.submit(candidate)

            record = store.decide(
                case.case_code, action="approved",
                actor_code=AUTHENTICATED_ACTOR, decided_at=NOW,
            )

        fact = record["fact"]
        narrative = fact["reviewed_narrative"]
        self.assertEqual(fact["fact_version"], "rich-semantic-reviewed-fact-v4")
        self.assertEqual(
            narrative["narrative_version"],
            "rich-semantic-reviewed-narrative-v1",
        )
        self.assertRegex(
            str(narrative["identity_corpus_sha256"]), r"^[0-9a-f]{64}$",
        )
        self.assertEqual(narrative["project"]["state"], "reviewed")
        self.assertEqual(narrative["project"]["text"], safe_project_summary)
        self.assertEqual(narrative["project"]["confidence"], "medium")
        self.assertEqual(
            narrative["project"]["evidence_refs"],
            [
                "application_01:achievement", "application_01:experience",
                "project_01:deployment", "project_01:description",
            ],
        )
        self.assertEqual(narrative["career"], {
            "confidence": "medium", "evidence_refs": [],
            "state": "unknown", "text": "",
        })
        self.assertEqual(
            record["audit_receipt"]["fact_sha256"], _sha256(fact),
        )

    def test_unsafe_or_identifying_narrative_becomes_unknown_without_leakage(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store, _ = self.create_store(directory)
            case = store.submit(proposal(
                1,
                assessment=assessment(
                    project_summary="built an audited workflow with person-example.",
                ),
            ))

            record = store.decide(
                case.case_code, action="approved",
                actor_code=AUTHENTICATED_ACTOR, decided_at=NOW,
            )

            project = record["fact"]["reviewed_narrative"]["project"]
            self.assertEqual(project, {
                "confidence": "medium", "evidence_refs": [],
                "state": "unknown", "text": "",
            })
            serialized = json.dumps(record, sort_keys=True).casefold()
            self.assertNotIn("person example", serialized.replace("-", " "))

        for ordinal, unsafe_summary in enumerate((
            "A deployed workflow is documented at https://profile.example.org.",
            "contact person@example.org about the deployed workflow.",
        ), start=2):
            with self.subTest(summary=unsafe_summary), tempfile.TemporaryDirectory() as directory:
                store, _ = self.create_store(directory)
                with self.assertRaisesRegex(ValueError, "direct identifier"):
                    store.submit(proposal(
                        ordinal,
                        assessment=assessment(project_summary=unsafe_summary),
                    ))
                self.assertFalse(any(store.reviewed.glob("*.json")))

    def test_reviewed_narrative_tampering_invalidates_fact_and_signed_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store, _ = self.create_store(directory)
            case = store.submit(proposal(1))
            store.decide(
                case.case_code, action="approved",
                actor_code=AUTHENTICATED_ACTOR, decided_at=NOW,
            )
            record_path = next(store.reviewed.glob("*.json"))
            record = json.loads(record_path.read_text(encoding="utf-8"))
            record["fact"]["reviewed_narrative"]["project"]["text"] = (
                "A different reviewed claim."
            )
            record["audit_receipt"]["fact_sha256"] = _sha256(record["fact"])
            record_path.write_text(
                json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(
                PermissionError, "decision proof|final receipt|tampered",
            ):
                store.semantic_release_qa_evidence()

    def test_reviewed_project_narrative_requires_identity_corpus_binding(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store, _ = self.create_store(directory)
            case = store.submit(proposal(1))
            record = store.decide(
                case.case_code, action="approved",
                actor_code=AUTHENTICATED_ACTOR, decided_at=NOW,
            )
            fact = record["fact"]
            fact["reviewed_narrative"]["identity_corpus_sha256"] = None

            with self.assertRaisesRegex(
                PermissionError, "lacks identity binding",
            ):
                store._validate_fact(fact)

    def test_submit_removes_known_identity_from_private_proposal_before_disk_write(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store, _ = self.create_store(directory)
            case = store.submit(proposal(
                1,
                assessment=assessment(
                    project_summary="built an audited workflow with person-example.",
                ),
            ))

            serialized = "\n".join(
                path.read_text(encoding="utf-8")
                for path in store.root.rglob("*.json")
            ).casefold().replace("-", " ")
            packet = store.load_review_packet(case.case_code)

        self.assertNotIn("person example", serialized)
        self.assertEqual(packet["proposal"]["project_summary"], "")

    def test_safe_narrative_survives_restart_without_persisting_identity_corpus(self) -> None:
        safe_summary = (
            "A durable workflow coordinates background jobs, retries failures, "
            "and records auditable outcomes."
        )
        with tempfile.TemporaryDirectory() as directory:
            store, _ = self.create_store(directory)
            case = store.submit(proposal(
                1,
                assessment=assessment(project_summary=safe_summary),
            ))
            before_restart = "\n".join(
                path.read_text(encoding="utf-8")
                for path in store.root.rglob("*.json")
            ).casefold()
            self.assertNotIn("person example", before_restart)
            self.assertNotIn("person_handle", before_restart)
            self.assertNotIn("person@example.org", before_restart)

            restarted, _ = self.create_store(
                directory, known_identity_literals=(),
            )
            record = restarted.decide(
                case.case_code, action="approved",
                actor_code=AUTHENTICATED_ACTOR, decided_at=NOW,
            )

        project = record["fact"]["reviewed_narrative"]["project"]
        self.assertEqual(project["state"], "reviewed")
        self.assertEqual(project["text"], safe_summary)
        self.assertRegex(
            record["fact"]["reviewed_narrative"]["identity_corpus_sha256"],
            r"^[0-9a-f]{64}$",
        )

    def test_open_case_returns_detached_identity_safe_evidence_visible_review_packet(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store, _ = self.create_store(directory)
            case = store.submit(proposal(1))

            packet = store.load_review_packet(case.case_code)

            self.assertEqual(
                set(packet),
                {
                    "case_code", "case_hash", "evidence_items", "packet_version",
                    "proposal", "proposal_sha256", "source_coverage",
                },
            )
            self.assertEqual(packet["packet_version"], "rich-semantic-review-packet-v1")
            self.assertEqual(packet["case_code"], case.case_code)
            self.assertEqual(packet["case_hash"], case.case_hash)
            self.assertEqual(
                packet["proposal"]["classification"],
                {
                    "builder_level": "substantial",
                    "execution_scope": "substantial_contributor",
                    "external_validation": "none",
                    "originality": "ordinary",
                    "product_maturity": "working_product",
                    "technical_depth": "advanced",
                },
            )
            self.assertEqual(packet["proposal"]["confidence"], "medium")
            self.assertEqual(
                packet["proposal"]["reason_codes"],
                ["end_to_end_delivery", "shipped_working_product"],
            )
            self.assertEqual(
                packet["proposal"]["rationale"],
                "The supplied project evidence supports the bounded classification.",
            )
            self.assertEqual(
                packet["proposal"]["semantic_taxonomy"]["project"]
                ["technical_depth"],
                "advanced",
            )
            self.assertEqual(
                packet["source_coverage"],
                {
                    "application": {"available": 1, "shown": 1},
                    "career": {"available": 0, "shown": 0},
                    "devpost": {"available": 0, "shown": 0},
                    "projects": {"available": 1, "shown": 1},
                },
            )
            excerpts = [
                excerpt["text"]
                for item in packet["evidence_items"]
                for excerpt in item["excerpts"]
            ]
            self.assertIn(
                "Product workflow with durable jobs and audit receipts.", excerpts,
            )
            self.assertIn(
                "Runs background work, retries failures, and records decisions.",
                excerpts,
            )
            project_item = next(
                item for item in packet["evidence_items"]
                if item["source_family"] == "projects"
            )
            self.assertEqual(
                project_item["signals"]["deployment_signal"],
                "deployment_observed",
            )

            serialized = json.dumps(packet, sort_keys=True)
            for forbidden in (
                "subject_ref", "case:v1:", "profile_url", "email", "phone",
                "raw_payload",
            ):
                self.assertNotIn(forbidden, serialized)

            packet["proposal"]["rationale"] = "mutated by caller"
            self.assertEqual(
                store.load_review_packet(case.case_code)["proposal"]["rationale"],
                "The supplied project evidence supports the bounded classification.",
            )

    def test_review_packet_fails_closed_if_stored_evidence_contains_identity_leakage(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store, _ = self.create_store(directory)
            case = store.submit(proposal(1))
            proposal_path = next(store.proposals.glob("*.json"))
            envelope = json.loads(proposal_path.read_text(encoding="utf-8"))
            envelope["proposal"]["evidence"]["projects"][0][
                "description_excerpt"
            ] = "See https://participant.example/profile for the named owner."
            proposal_path.write_text(
                json.dumps(envelope, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(
                PermissionError, "identity leakage|unsafe content",
            ):
                store.load_review_packet(case.case_code)

    def test_review_packet_rejects_stale_approval(self) -> None:
        approved = {"a" * 64}
        with tempfile.TemporaryDirectory() as directory:
            store, _ = self.create_store(
                directory, approved_authorizations=approved,
            )
            case = store.submit(proposal(1))
            approved.clear()

            with self.assertRaisesRegex(PermissionError, "authoritative approval"):
                store.load_review_packet(case.case_code)

    def test_review_packet_rejects_stale_case_binding(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store, repository = self.create_store(directory)
            case = store.submit(proposal(1))
            repository.replace_for_kinds(("classification",), (
                type(case)(
                    case_code=case.case_code,
                    case_hash="f" * 64,
                    kind=case.kind,
                    subject_code=case.subject_code,
                    reason_codes=case.reason_codes,
                    candidate_codes=case.candidate_codes,
                    version=case.version,
                ),
            ))
            with self.assertRaisesRegex(PermissionError, "stale"):
                store.load_review_packet(case.case_code)

    def test_review_packet_rejects_transient_evidence_binding_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store, _ = self.create_store(directory)
            case = store.submit(proposal(1))
            transient_path = next(store.transient.glob("*.json"))
            transient = json.loads(transient_path.read_text(encoding="utf-8"))
            transient["evidence_sha256"] = "f" * 64
            transient_path.write_text(
                json.dumps(transient, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(PermissionError, "tampered"):
                store.load_review_packet(case.case_code)

    def test_review_packet_excerpts_and_total_payload_are_bounded(self) -> None:
        bound_evidence = evidence()
        project = bound_evidence["projects"][0]
        application = bound_evidence["application"][0]
        project["description_excerpt"] = ("Built production workflow. " * 40)[:800]
        project["readme_excerpt"] = ("Runs durable background workflow. " * 80)[:2_000]
        application["achievement_excerpt"] = ("Shipped working product. " * 70)[:1_500]
        application["experience_excerpt"] = ("Built production systems. " * 90)[:2_000]
        candidate = proposal(
            1,
            evidence=bound_evidence,
            evidence_sha256=_sha256(bound_evidence),
        )

        with tempfile.TemporaryDirectory() as directory:
            store, _ = self.create_store(directory)
            case = store.submit(candidate)
            packet = store.load_review_packet(case.case_code)

        excerpts = [
            excerpt["text"]
            for item in packet["evidence_items"]
            for excerpt in item["excerpts"]
        ]
        self.assertTrue(excerpts)
        self.assertTrue(all(len(value) <= 500 for value in excerpts))
        self.assertLessEqual(len(packet["evidence_items"]), 11)
        self.assertLess(len(json.dumps(packet, sort_keys=True)), 24_000)

    def test_proof_for_me_manifest_applies_only_explicit_packet_bound_rows_and_replays_idempotently(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store, repository = self.create_store(directory)
            self.assertTrue(
                hasattr(store, "apply_decision_manifest"),
                "the explicit decision-manifest importer is missing",
            )
            selected = store.submit(proposal(
                1, assessment=assessment(cross_source_confidence="high"),
            ))
            omitted = store.submit(proposal(2))
            packet = store.load_review_packet(selected.case_code)
            manifest = decision_manifest(decision_manifest_row(packet))

            first = store.apply_decision_manifest(manifest, decided_at=NOW)
            second = store.apply_decision_manifest(manifest, decided_at=NOW)

            self.assertEqual(first["applied_count"], 1)
            self.assertEqual(first["already_applied_count"], 0)
            self.assertEqual(second["applied_count"], 0)
            self.assertEqual(second["already_applied_count"], 1)
            self.assertEqual(first["manifest_sha256"], second["manifest_sha256"])
            self.assertRegex(str(first["manifest_sha256"]), r"^[0-9a-f]{64}$")
            cases = {case.case_code: case for case in repository.list(kind="classification")}
            self.assertEqual(cases[selected.case_code].status, "resolved")
            self.assertEqual(cases[omitted.case_code].status, "open")
            record = json.loads(next(store.reviewed.glob("*.json")).read_text())
            self.assertEqual(
                record["audit_receipt"]["actor_code"], "proof_for_me_agent",
            )
            self.assertFalse(any(store.attempts.glob("*.json")))

    def test_decision_manifest_preflights_every_binding_before_applying_any_row(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store, repository = self.create_store(directory)
            first = store.submit(proposal(1))
            second = store.submit(proposal(2))
            first_row = decision_manifest_row(store.load_review_packet(first.case_code))
            second_row = decision_manifest_row(store.load_review_packet(second.case_code))
            second_row["proposal_sha256"] = "f" * 64

            with self.assertRaisesRegex(PermissionError, "drift|binding"):
                store.apply_decision_manifest(
                    decision_manifest(first_row, second_row), decided_at=NOW,
                )

            self.assertTrue(all(
                case.status == "open"
                for case in repository.list(kind="classification")
                if case.case_code in {first.case_code, second.case_code}
            ))
            self.assertFalse(any(store.reviewed.glob("*.json")))
            self.assertFalse(any(store.receipts.glob("*.json")))

    def test_decision_manifest_requires_versioned_exact_key_envelopes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store, repository = self.create_store(directory)
            candidate = store.submit(proposal(1))
            packet = store.load_review_packet(candidate.case_code)
            extra_row = decision_manifest_row(packet)
            extra_row["confidence"] = "medium"
            extra_envelope = decision_manifest(decision_manifest_row(packet))
            extra_envelope["approve_all"] = True

            for malformed in (
                decision_manifest(extra_row),
                extra_envelope,
                {
                    "decisions": [decision_manifest_row(packet)],
                    "manifest_version": "rich-semantic-decision-manifest-v0",
                },
            ):
                with self.subTest(keys=sorted(malformed)):
                    with self.assertRaisesRegex(ValueError, "manifest"):
                        store.apply_decision_manifest(malformed, decided_at=NOW)

            self.assertEqual(
                repository.list(kind="classification")[0].status, "open",
            )

    def test_proof_for_me_manifest_rejects_low_confidence_without_a_decision(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store, repository = self.create_store(directory)
            candidate = store.submit(proposal(
                1, assessment=assessment(cross_source_confidence="low"),
            ))
            row = decision_manifest_row(store.load_review_packet(candidate.case_code))

            with self.assertRaisesRegex(PermissionError, "medium or high"):
                store.apply_decision_manifest(decision_manifest(row), decided_at=NOW)

            self.assertEqual(
                repository.list(kind="classification")[0].status, "open",
            )

    def test_proof_for_me_manifest_rejects_non_approval_actions_and_other_actors(self) -> None:
        rejected_inputs = (
            ("rejected", "proof_for_me_agent", "individual authenticated review"),
            ("corrected", "proof_for_me_agent", "individual authenticated review"),
            ("approved", AUTHENTICATED_ACTOR, "Proof-for-Me"),
        )
        for action, actor_code, message in rejected_inputs:
            with self.subTest(action=action, actor_code=actor_code):
                with tempfile.TemporaryDirectory() as directory:
                    store, repository = self.create_store(directory)
                    candidate = store.submit(proposal(1))
                    packet = store.load_review_packet(candidate.case_code)
                    row = decision_manifest_row(
                        packet, action=action, actor_code=actor_code,
                    )

                    with self.assertRaisesRegex(PermissionError, message):
                        store.apply_decision_manifest(
                            decision_manifest(row), decided_at=NOW,
                        )

                    self.assertEqual(
                        repository.list(kind="classification")[0].status, "open",
                    )

    def test_decision_manifest_resumes_an_interrupted_row_before_applying_the_rest(self) -> None:
        interrupted = {"value": False}

        def failpoint(stage: str) -> None:
            if stage == "after_intent_before_review" and not interrupted["value"]:
                interrupted["value"] = True
                raise RuntimeError("synthetic manifest interruption")

        with tempfile.TemporaryDirectory() as directory:
            store, repository = self.create_store(directory, failpoint=failpoint)
            first = store.submit(proposal(1))
            second = store.submit(proposal(2))
            manifest = decision_manifest(
                decision_manifest_row(store.load_review_packet(first.case_code)),
                decision_manifest_row(store.load_review_packet(second.case_code)),
            )
            with self.assertRaisesRegex(RuntimeError, "manifest interruption"):
                store.apply_decision_manifest(manifest, decided_at=NOW)

            resumed = store.apply_decision_manifest(manifest, decided_at=NOW)

            self.assertEqual(resumed["already_applied_count"], 1)
            self.assertEqual(resumed["applied_count"], 1)
            self.assertTrue(all(
                case.status == "resolved"
                for case in repository.list(kind="classification")
                if case.case_code in {first.case_code, second.case_code}
            ))
            self.assertEqual(store.finalized_case_codes(), {
                first.case_code, second.case_code,
            })
            self.assertFalse(any(store.attempts.glob("*.json")))

    def test_public_decide_signature_exposes_no_manifest_authority_parameters(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store, _ = self.create_store(directory)

            parameters = set(inspect.signature(store.decide).parameters)

            self.assertEqual(parameters, {
                "action", "actor_code", "case_code", "corrected_assessment",
                "decided_at",
            })
            self.assertFalse(any(
                "manifest" in parameter or "capability" in parameter
                for parameter in parameters
            ))

    def test_recovered_store_values_cannot_authorize_public_proof_for_me_decide(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store, repository = self.create_store(directory)
            candidate = store.submit(proposal(
                1, assessment=assessment(cross_source_confidence="low"),
            ))
            recovered = [
                value for key, value in vars(store).items()
                if "capability" in key
            ]
            forged = recovered[0] if recovered else object()

            with self.assertRaises(TypeError):
                store.decide(
                    candidate.case_code, action="approved",
                    actor_code="proof_for_me_agent", decided_at=NOW,
                    _manifest_capability=forged,
                    _decision_manifest_sha256="f" * 64,
                    _decision_manifest_version=(
                        "rich-semantic-decision-manifest-v1"
                    ),
                )

            self.assertFalse(recovered)
            current = repository.list(kind="classification")[0]
            self.assertEqual(current.status, "open")
            self.assertFalse(any(store.attempts.glob("*.json")))
            self.assertFalse(any(store.reviewed.glob("*.json")))
            self.assertFalse(any(store.receipts.glob("*.json")))

    def test_proof_for_me_actor_cannot_bypass_manifest_with_direct_decide(self) -> None:
        for confidence in ("medium", "low"):
            with self.subTest(confidence=confidence):
                with tempfile.TemporaryDirectory() as directory:
                    store, repository = self.create_store(directory)
                    candidate = store.submit(proposal(
                        1,
                        assessment=assessment(
                            cross_source_confidence=confidence,
                        ),
                    ))

                    with self.assertRaisesRegex(
                        PermissionError, "decision manifest",
                    ):
                        store.decide(
                            candidate.case_code, action="approved",
                            actor_code="proof_for_me_agent", decided_at=NOW,
                        )

                    current = repository.list(kind="classification")[0]
                    self.assertEqual(current.status, "open")
                    self.assertFalse(any(store.attempts.glob("*.json")))
                    self.assertFalse(any(store.reviewed.glob("*.json")))
                    self.assertFalse(any(store.receipts.glob("*.json")))

    def test_manifest_decision_receipt_binds_exact_manifest_version_and_hash(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store, _ = self.create_store(directory)
            candidate = store.submit(proposal(1))
            packet = store.load_review_packet(candidate.case_code)
            manifest = decision_manifest(decision_manifest_row(packet))

            record = store.apply_decision_manifest(manifest, decided_at=NOW)
            reviewed = json.loads(next(store.reviewed.glob("*.json")).read_text())
            receipt = reviewed["audit_receipt"]

            self.assertEqual(record["manifest_sha256"], _sha256(manifest))
            self.assertEqual(
                receipt.get("decision_manifest_version"),
                "rich-semantic-decision-manifest-v1",
            )
            self.assertEqual(
                receipt.get("decision_manifest_sha256"), _sha256(manifest),
            )

    def test_manifest_hash_tampering_invalidates_the_durable_review_proof(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store, _ = self.create_store(directory)
            candidate = store.submit(proposal(1))
            packet = store.load_review_packet(candidate.case_code)
            store.apply_decision_manifest(
                decision_manifest(decision_manifest_row(packet)), decided_at=NOW,
            )
            record_path = next(store.reviewed.glob("*.json"))
            record = json.loads(record_path.read_text(encoding="utf-8"))
            record["audit_receipt"]["decision_manifest_sha256"] = "f" * 64
            record_path.write_text(
                json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(PermissionError, "final receipt"):
                store.semantic_release_qa_evidence()

    def test_external_proof_resolution_cannot_manufacture_a_store_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store, repository = self.create_store(directory)
            candidate = store.submit(proposal(1))
            repository.decide(
                ReviewDecision(
                    case_code=candidate.case_code,
                    case_hash=candidate.case_hash,
                    action="approved",
                ),
                actor_code="proof_for_me_agent", decided_at=NOW,
            )

            with self.assertRaisesRegex(PermissionError, "persisted attempt"):
                store.decide(
                    candidate.case_code, action="approved",
                    actor_code=AUTHENTICATED_ACTOR, decided_at=NOW,
                )

            self.assertTrue(any(store.proposals.glob("*.json")))
            self.assertTrue(any(store.transient.glob("*.json")))
            self.assertFalse(any(store.attempts.glob("*.json")))
            self.assertFalse(any(store.reviewed.glob("*.json")))
            self.assertFalse(any(store.receipts.glob("*.json")))
            with self.assertRaisesRegex(PermissionError, "outcome is incomplete"):
                store.semantic_release_qa_evidence()

    def test_external_human_resolution_cannot_manufacture_a_store_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store, repository = self.create_store(directory)
            candidate = store.submit(proposal(1))
            repository.decide(
                ReviewDecision(
                    case_code=candidate.case_code,
                    case_hash=candidate.case_hash,
                    action="approved",
                ),
                actor_code=AUTHENTICATED_ACTOR, decided_at=NOW,
            )

            with self.assertRaisesRegex(PermissionError, "persisted attempt"):
                store.decide(
                    candidate.case_code, action="approved",
                    actor_code=AUTHENTICATED_ACTOR, decided_at=NOW,
                )

            self.assertTrue(any(store.proposals.glob("*.json")))
            self.assertTrue(any(store.transient.glob("*.json")))
            self.assertFalse(any(store.attempts.glob("*.json")))
            self.assertFalse(any(store.reviewed.glob("*.json")))
            self.assertFalse(any(store.receipts.glob("*.json")))

    def test_decision_requires_configured_signing_authority(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store, _ = self.create_store(
                directory, decision_signing_secret=None,
            )
            case = store.submit(proposal(1))

            with self.assertRaisesRegex(PermissionError, "signing authority"):
                store.decide(
                    case.case_code, action="approved",
                    actor_code=AUTHENTICATED_ACTOR, decided_at=NOW,
                )

    def test_literal_owner_code_cannot_authenticate_uncertain_human_review(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store, _ = self.create_store(directory)
            low = proposal(1, assessment=assessment(cross_source_confidence="low"))
            case = store.submit(low)
            store.decide(
                case.case_code, action="approved",
                actor_code="release_owner", decided_at=NOW,
            )

            aggregate = store.build_population_aggregate(
                expected_subject_refs=[str(low["subject_ref"])],
                binding_context=population_context(), generated_at=NOW,
                minimum_group_size=5,
            )

            self.assertEqual(aggregate["population"]["assessed_count"], 0)
            self.assertEqual(aggregate["population"]["state_counts"]["conflict"], 1)

    def test_signed_authenticated_actor_can_resolve_uncertain_review(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store, _ = self.create_store(directory)
            low = proposal(1, assessment=assessment(cross_source_confidence="low"))
            case = store.submit(low)
            store.decide(
                case.case_code, action="approved",
                actor_code=AUTHENTICATED_ACTOR, decided_at=NOW,
            )

            aggregate = store.build_population_aggregate(
                expected_subject_refs=[str(low["subject_ref"])],
                binding_context=population_context(), generated_at=NOW,
                minimum_group_size=5,
            )

            self.assertEqual(aggregate["population"]["assessed_count"], 1)

    def test_career_only_legacy_none_normalizes_before_population_aggregation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store, _ = self.create_store(directory)
            candidate = career_only_proposal(1)
            case = store.submit(candidate)
            record = store.decide(
                case.case_code, action="approved",
                actor_code=AUTHENTICATED_ACTOR, decided_at=NOW,
            )

            aggregate = store.build_population_aggregate(
                expected_subject_refs=[str(candidate["subject_ref"])],
                binding_context=population_context(), generated_at=NOW,
                minimum_group_size=5,
            )

        self.assertEqual(
            record["fact"]["semantic_fact"]["external_validation"],
            "unknown",
        )
        self.assertEqual(aggregate["population"]["assessed_count"], 1)
        self.assertEqual(
            aggregate["taxonomy_dimensions"]["external_validation"][
                "unknown_count"
            ],
            1,
        )

    def test_provider_clears_evidence_free_validation_narratives_before_reviewed_fact(self) -> None:
        candidate = career_only_proposal(1)
        model_assessment = candidate["assessment"]
        model_assessment["project_summary"] = (
            "a product claim is not supported by reviewed project evidence."
        )
        provider = OpenAIRichSemanticAssessmentProvider(
            api_key="fixture-key-not-secret",
            transport=FakeResponsesTransport(model_assessment),
            sleeper=lambda _seconds: None,
            known_identity_literals=KNOWN_IDENTITY_LITERALS,
        )

        provider_result = provider.assess_with_metadata(candidate["evidence"])
        candidate["assessment"] = provider_result["assessment"]
        with tempfile.TemporaryDirectory() as directory:
            store, _ = self.create_store(directory)
            case = store.submit(candidate)
            record = store.decide(
                case.case_code, action="approved",
                actor_code=AUTHENTICATED_ACTOR, decided_at=NOW,
            )

        self.assertEqual(
            provider_result["assessment"]["external_validation"], "unknown",
        )
        self.assertEqual(provider_result["assessment"]["project_summary"], "")
        self.assertEqual(provider_result["assessment"]["career_summary"], "")
        self.assertIn(
            "unsupported_external_validation_downgraded",
            provider_result["normalizations"],
        )
        self.assertIn(
            "narrative_removed_after_semantic_downgrade",
            provider_result["normalizations"],
        )
        narrative = record["fact"]["reviewed_narrative"]
        self.assertEqual(narrative["project"]["state"], "unknown")
        self.assertEqual(narrative["career"]["state"], "unknown")

    def test_release_qa_evidence_derives_positive_claims_and_required_human_reviews(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store, _ = self.create_store(directory)

            approved = store.submit(proposal(1))
            store.decide(
                approved.case_code, action="approved",
                actor_code=AUTHENTICATED_ACTOR, decided_at=NOW,
            )

            uncertain = store.submit(proposal(
                2, assessment=assessment(cross_source_confidence="low"),
            ))
            store.decide(
                uncertain.case_code, action="approved",
                actor_code="release_owner", decided_at=NOW,
            )

            corrected = store.submit(proposal(3))
            store.decide(
                corrected.case_code, action="corrected",
                actor_code=AUTHENTICATED_ACTOR, decided_at=NOW,
                corrected_assessment=assessment(),
            )

            evidence = store.semantic_release_qa_evidence(sample_limit=10)

            # Release QA reconciles only claim codes the partner report can
            # display. Internal diagnostic taxonomy states are not public claims.
            self.assertEqual(evidence["positive_claim_count"], 22)
            self.assertEqual(evidence["positive_claim_sample_count"], 10)
            self.assertEqual(evidence["required_review_case_count"], 2)
            self.assertEqual(evidence["required_review_cases_resolved"], 1)
            self.assertRegex(str(evidence["positive_claims_sha256"]), r"^[0-9a-f]{64}$")
            self.assertRegex(str(evidence["review_evidence_sha256"]), r"^[0-9a-f]{64}$")
            self.assertNotIn("case:v1:", json.dumps(evidence, sort_keys=True))

    def test_authenticated_batch_attestation_promotes_existing_low_confidence_review(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store, _ = self.create_store(directory)
            candidate = store.submit(proposal(
                1, assessment=assessment(cross_source_confidence="low"),
            ))
            store.decide(
                candidate.case_code,
                action="approved",
                actor_code="proof_for_me_reviewer",
                decided_at=NOW,
            )

            before = store.semantic_release_qa_evidence()
            self.assertEqual(before["required_review_case_count"], 1)
            self.assertEqual(before["required_review_cases_resolved"], 0)
            preview = store.preview_required_human_attestation()
            self.assertEqual(preview["required_review_case_count"], 1)
            self.assertRegex(
                str(preview["required_review_set_sha256"]), r"^[0-9a-f]{64}$",
            )

            receipt = store.attest_required_human_reviews(
                expected_review_set_sha256=str(
                    preview["required_review_set_sha256"],
                ),
                actor_code=AUTHENTICATED_ACTOR,
                attested_at=NOW,
            )

            self.assertEqual(receipt["attested_review_case_count"], 1)
            after = store.semantic_release_qa_evidence()
            self.assertEqual(after["required_review_cases_resolved"], 1)
            aggregate = store.build_population_aggregate(
                expected_subject_refs=[str(proposal(1)["subject_ref"])],
                binding_context=population_context(),
                generated_at=NOW,
                minimum_group_size=5,
            )
            self.assertEqual(aggregate["population"]["assessed_count"], 1)
            reloaded, _ = self.create_store(directory)
            self.assertEqual(
                reloaded.semantic_release_qa_evidence()[
                    "required_review_cases_resolved"
                ],
                1,
            )

    def test_batch_attestation_rejects_non_human_actor_and_stale_review_set(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store, _ = self.create_store(directory)
            candidate = store.submit(proposal(
                1, assessment=assessment(cross_source_confidence="low"),
            ))
            store.decide(
                candidate.case_code,
                action="approved",
                actor_code="proof_for_me_reviewer",
                decided_at=NOW,
            )
            preview = store.preview_required_human_attestation()
            digest = str(preview["required_review_set_sha256"])

            with self.assertRaisesRegex(PermissionError, "authenticated human"):
                store.attest_required_human_reviews(
                    expected_review_set_sha256=digest,
                    actor_code="proof_for_me_agent",
                    attested_at=NOW,
                )
            with self.assertRaisesRegex(PermissionError, "review set"):
                store.attest_required_human_reviews(
                    expected_review_set_sha256="0" * 64,
                    actor_code=AUTHENTICATED_ACTOR,
                    attested_at=NOW,
                )

    def test_tampered_batch_attestation_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store, _ = self.create_store(directory)
            candidate = store.submit(proposal(
                1, assessment=assessment(cross_source_confidence="low"),
            ))
            store.decide(
                candidate.case_code,
                action="approved",
                actor_code="proof_for_me_reviewer",
                decided_at=NOW,
            )
            preview = store.preview_required_human_attestation()
            store.attest_required_human_reviews(
                expected_review_set_sha256=str(
                    preview["required_review_set_sha256"],
                ),
                actor_code=AUTHENTICATED_ACTOR,
                attested_at=NOW,
            )
            attestation = json.loads(store.human_attestation.read_text())
            attestation["actor_code"] = "colleague_" + "b" * 32
            store.human_attestation.write_text(
                json.dumps(attestation, sort_keys=True, separators=(",", ":"))
                + "\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(PermissionError, "attestation"):
                store.semantic_release_qa_evidence()

    def test_tampered_decision_proof_is_rejected_before_aggregation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store, _ = self.create_store(directory)
            case = store.submit(proposal(1))
            store.decide(
                case.case_code, action="approved",
                actor_code=AUTHENTICATED_ACTOR, decided_at=NOW,
            )
            record_path = next(store.reviewed.glob("*.json"))
            record = json.loads(record_path.read_text(encoding="utf-8"))
            record["audit_receipt"]["decision_hmac_sha256"] = "0" * 64
            record_path.write_text(
                json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(PermissionError, "decision proof|final receipt"):
                store.build_population_aggregate(
                    expected_subject_refs=[str(proposal(1)["subject_ref"])],
                    binding_context=population_context(), generated_at=NOW,
                    minimum_group_size=5,
                )

    def test_case_hash_is_bound_to_event_and_event_approval_context(self) -> None:
        with tempfile.TemporaryDirectory() as first_directory, tempfile.TemporaryDirectory() as second_directory:
            first, _ = self.create_store(
                first_directory,
                review_context_hashes={
                    "event_approval": "a" * 64,
                    "event_definition": "b" * 64,
                    "event_key": "c" * 64,
                },
            )
            second, _ = self.create_store(
                second_directory,
                review_context_hashes={
                    "event_approval": "d" * 64,
                    "event_definition": "e" * 64,
                    "event_key": "f" * 64,
                },
            )

            self.assertNotEqual(
                first.submit(proposal(1)).case_hash,
                second.submit(proposal(1)).case_hash,
            )

    def test_submit_requires_authoritative_approval_verifier_match(self) -> None:
        from community_os.rich_semantic_review import RichSemanticReviewStore

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            unconfigured = RichSemanticReviewStore(
                root / "rich-semantic-review",
                release_root=root / "release",
                review_repository=ReviewRepository(root / "operator" / "reviews.json"),
                clock=lambda: NOW,
                review_context_hashes={
                    "event_approval": "a" * 64,
                    "event_definition": "b" * 64,
                    "event_key": "c" * 64,
                },
            )
            with self.assertRaisesRegex(PermissionError, "authoritative"):
                unconfigured.submit(proposal(1))

            store, _ = self.create_store(
                directory, approved_authorizations=frozenset({"b" * 64}),
            )
            with self.assertRaisesRegex(PermissionError, "authoritative"):
                store.submit(proposal(2))
            case = store.submit(proposal(3, approval_sha256="b" * 64))
            self.assertEqual(case.status, "open")

    def test_submit_validates_all_bindings_and_creates_open_hash_bound_case(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store, repository = self.create_store(directory)
            case = store.submit(proposal(1))

            self.assertEqual(case.kind, "classification")
            self.assertEqual(case.status, "open")
            self.assertEqual(repository.list(kind="classification"), (case,))
            self.assertEqual(store.root.stat().st_mode & 0o777, 0o700)
            self.assertEqual(store.proposals.stat().st_mode & 0o777, 0o700)
            proposal_path = next(store.proposals.glob("*.json"))
            self.assertEqual(proposal_path.stat().st_mode & 0o777, 0o600)
            serialized = proposal_path.read_text(encoding="utf-8")
            self.assertNotIn("http", serialized)
            self.assertNotIn("@", serialized)

    def test_changed_hash_source_coverage_ttl_or_direct_identifier_fails_closed(self) -> None:
        invalid = (
            proposal(1, evidence_sha256="b" * 64),
            proposal(2, source_coverage=["career"]),
            proposal(3, expires_at=(NOW + timedelta(days=8)).isoformat()),
            proposal(4, subject_ref="jane@example.org"),
            proposal(5, model_sha256="c" * 64),
            proposal(6, prompt_sha256="d" * 64),
        )
        for item in invalid:
            with self.subTest(subject=item["subject_ref"]), tempfile.TemporaryDirectory() as directory:
                store, _ = self.create_store(directory)
                with self.assertRaises((ValueError, PermissionError)):
                    store.submit(item)

    def test_approved_projection_deletes_evidence_and_retains_only_minimized_fact_and_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store, repository = self.create_store(directory)
            case = store.submit(proposal(1))
            transient = next(store.transient.glob("*.json"))

            record = store.decide(
                case.case_code, action="approved", actor_code="release_owner",
                decided_at=NOW,
            )

            self.assertEqual(repository.list(kind="classification")[0].status, "resolved")
            self.assertFalse(any(store.proposals.glob("*.json")))
            self.assertFalse(transient.exists())
            self.assertFalse(any(store.attempts.glob("*.json")))
            self.assertEqual(record["audit_receipt"]["deletion_state"], "deleted_after_review")
            self.assertTrue(record["audit_receipt"]["minimized_evidence_deleted"])
            self.assertTrue(record["audit_receipt"]["transient_cache_deleted"])
            serialized = json.dumps(record, sort_keys=True)
            for forbidden in (
                "description_excerpt", "readme_excerpt", "project_summary",
                "career_summary", "rationale", "http", "@",
            ):
                self.assertNotIn(forbidden, serialized)
            self.assertEqual(record["fact"]["semantic_fact"]["builder_level"], "substantial")
            self.assertEqual(
                record["fact"]["semantic_taxonomy"]["project"]["technical_depth"],
                "advanced",
            )
            self.assertEqual(
                record["fact"]["semantic_taxonomy"]["evidence_by_dimension"]
                ["technical_depth"],
                [
                    "application_01:achievement", "application_01:experience",
                    "project_01:description",
                ],
            )
            self.assertEqual(
                record["fact"]["fact_version"],
                "rich-semantic-reviewed-fact-v4",
            )
            self.assertEqual(record["fact"]["confidence"], "medium")
            self.assertEqual(record["fact"]["unknown_state"], [])

    def test_reason_codes_are_controlled_and_survive_minimized_projection(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store, _ = self.create_store(directory)
            invalid = proposal(1, assessment=assessment(
                reason_codes=["free-form opinion about this person"],
            ))
            with self.assertRaisesRegex(ValueError, "reasons"):
                store.submit(invalid)

            case = store.submit(proposal(2))
            record = store.decide(
                case.case_code, action="approved",
                actor_code="release_owner", decided_at=NOW,
            )

            self.assertEqual(
                record["fact"].get("reason_codes"),
                ["end_to_end_delivery", "shipped_working_product"],
            )

    def test_correction_is_schema_validated_against_bound_evidence_and_repository_decision(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store, repository = self.create_store(directory)
            case = store.submit(proposal(1))
            invalid = assessment(evidence_refs=["project_99:description"])
            with self.assertRaisesRegex(ValueError, "references"):
                store.decide(
                    case.case_code, action="corrected", actor_code="release_owner",
                    decided_at=NOW, corrected_assessment=invalid,
                )
            self.assertEqual(repository.list(kind="classification")[0].status, "open")

            corrected = assessment(
                builder_level="exploratory", product_maturity="prototype",
                technical_depth="moderate", execution_scope="contributor",
                evidence_refs=[
                    "project_01:description", "application_01:experience",
                ],
                reason_codes=["prototype_only"],
            )
            record = store.decide(
                case.case_code, action="corrected", actor_code="release_owner",
                decided_at=NOW, corrected_assessment=corrected,
            )
            decision = repository.list(kind="classification")[0].decision
            self.assertEqual(decision.action, "corrected")
            self.assertIsNotNone(decision.corrected_output)
            self.assertEqual(record["fact"]["semantic_fact"]["builder_level"], "exploratory")
            self.assertEqual(record["audit_receipt"]["review_action"], "corrected")

    def test_decision_time_is_canonicalized_before_intent_and_repository_write(self) -> None:
        local_time = datetime(2026, 7, 15, 16, tzinfo=timezone(timedelta(hours=2)))
        with tempfile.TemporaryDirectory() as directory:
            store, repository = self.create_store(directory)
            case = store.submit(proposal(1))

            record = store.decide(
                case.case_code, action="approved",
                actor_code="release_owner", decided_at=local_time,
            )

            expected = "2026-07-15T14:00:00Z"
            self.assertEqual(record["audit_receipt"]["decided_at"], expected)
            self.assertEqual(
                repository.list(kind="classification")[0].decision.decided_at,
                expected,
            )

    def test_open_rejected_expired_and_tampered_records_cannot_aggregate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store, _ = self.create_store(directory)
            open_case = store.submit(proposal(1))
            rejected_case = store.submit(proposal(2))
            store.decide(
                rejected_case.case_code, action="rejected",
                actor_code="release_owner", decided_at=NOW,
            )
            aggregate = store.build_aggregate(minimum_group_size=5)
            self.assertEqual(aggregate["reviewed_denominator"], 0)
            self.assertEqual(open_case.status, "open")
            self.assertFalse(any(store.reviewed.glob("*.json")))

            expired = proposal(
                3,
                created_at=(NOW - timedelta(days=2)).isoformat(),
                expires_at=(NOW - timedelta(days=1)).isoformat(),
            )
            with self.assertRaisesRegex(PermissionError, "expired"):
                store.submit(expired)

            case = store.submit(proposal(4))
            store.decide(
                case.case_code, action="approved",
                actor_code="release_owner", decided_at=NOW,
            )
            reviewed_path = next(store.reviewed.glob("*.json"))
            payload = json.loads(reviewed_path.read_text(encoding="utf-8"))
            payload["fact"]["semantic_fact"]["builder_level"] = "standout"
            reviewed_path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(PermissionError, "tampered"):
                store.build_aggregate(minimum_group_size=5)

    def test_copied_reviewed_record_cannot_inflate_aggregate_denominator(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store, _ = self.create_store(directory)
            case = store.submit(proposal(1))
            store.decide(
                case.case_code, action="approved",
                actor_code="release_owner", decided_at=NOW,
            )
            reviewed_path = next(store.reviewed.glob("*.json"))
            copied = store.reviewed / "classification_copied_record.json"
            copied.write_bytes(reviewed_path.read_bytes())
            copied.chmod(0o600)

            with self.assertRaisesRegex(PermissionError, "filename"):
                store.build_aggregate(minimum_group_size=5)

    def test_aggregate_has_denominators_source_coverage_and_no_event_count_duplication(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store, _ = self.create_store(directory)
            for ordinal in range(1, 7):
                case = store.submit(proposal(ordinal))
                store.decide(
                    case.case_code, action="approved",
                    actor_code="release_owner", decided_at=NOW,
                )

            aggregate = store.build_aggregate(minimum_group_size=5)

            self.assertNotIn("event_counts", aggregate)
            self.assertEqual(
                aggregate["source_coverage"],
                {"application": 6, "career": 0, "devpost": 0, "projects": 6},
            )
            self.assertEqual(aggregate["reviewed_denominator"], 6)
            self.assertTrue(aggregate["internal_only"])
            self.assertFalse(aggregate["release_eligible"])
            self.assertEqual(aggregate["minimum_group_size"], 5)
            self.assertEqual(
                aggregate["aggregate_version"],
                "rich-semantic-internal-aggregate-v4",
            )
            builder = aggregate["dimensions"]["builder_level"]
            self.assertEqual(builder["denominator"], 6)
            self.assertEqual(builder["unknown_cell"], {"count": None, "state": "withheld"})
            self.assertEqual(builder["cells"]["substantial"], {"count": 6, "state": "reported"})
            self.assertEqual(builder["cells"]["standout"], {"count": None, "state": "withheld"})
            impressive = aggregate["dimensions"]["impressive_band"]
            self.assertEqual(impressive["denominator"], 6)
            self.assertEqual(
                impressive["cells"]["impressive"],
                {"count": 6, "state": "reported"},
            )
            self.assertEqual(
                impressive["cells"]["not_impressive"],
                {"count": None, "state": "withheld"},
            )
            self.assertEqual(
                impressive["unknown_cell"],
                {"count": None, "state": "withheld"},
            )
            serialized = json.dumps(aggregate, sort_keys=True)
            self.assertNotIn("case:v1", serialized)
            self.assertNotIn("evidence_refs", serialized)

    def test_aggregate_complementary_suppression_hides_small_remainder(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store, _ = self.create_store(directory)
            for ordinal in range(1, 7):
                item = proposal(ordinal)
                if ordinal == 6:
                    item = proposal(ordinal, assessment=assessment(
                        builder_level="exploratory",
                        product_maturity="prototype",
                        technical_depth="moderate",
                        execution_scope="contributor",
                        evidence_refs=[
                            "project_01:description", "application_01:experience",
                        ],
                        reason_codes=["prototype_only"],
                    ))
                case = store.submit(item)
                store.decide(
                    case.case_code, action="approved",
                    actor_code="release_owner", decided_at=NOW,
                )

            aggregate = store.build_aggregate(minimum_group_size=5)

            builder = aggregate["dimensions"]["builder_level"]["cells"]
            self.assertEqual(builder["exploratory"], {"count": None, "state": "withheld"})
            self.assertEqual(builder["substantial"], {"count": None, "state": "withheld"})
            impressive = aggregate["dimensions"]["impressive_band"]["cells"]
            self.assertEqual(impressive["not_impressive"], {"count": None, "state": "withheld"})
            self.assertEqual(impressive["impressive"], {"count": None, "state": "withheld"})

    def test_aggregate_suppresses_all_cells_when_multiple_large_cells_expose_remainder(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store, _ = self.create_store(directory)
            for ordinal in range(1, 12):
                builder_level = (
                    "substantial" if ordinal <= 5
                    else "standout" if ordinal <= 10
                    else "exploratory"
                )
                overrides: dict[str, object] = {"builder_level": builder_level}
                if builder_level == "exploratory":
                    overrides.update({
                        "product_maturity": "prototype",
                        "technical_depth": "moderate",
                        "execution_scope": "contributor",
                        "reason_codes": ["prototype_only"],
                    })
                if builder_level == "standout":
                    overrides.update({
                        "evidence_refs": [
                            "project_01:description", "project_01:deployment",
                            "project_01:ownership", "application_01:achievement",
                        ],
                        "execution_scope": "primary_builder",
                        "external_validation": "meaningful",
                        "originality": "differentiated",
                        "reason_codes": [
                            "differentiated_problem", "external_adoption",
                            "shipped_working_product", "technically_substantial",
                        ],
                    })
                item = proposal(ordinal, assessment=assessment(**overrides))
                case = store.submit(item)
                store.decide(
                    case.case_code, action="approved",
                    actor_code="release_owner", decided_at=NOW,
                )

            builder = store.build_aggregate(
                minimum_group_size=5,
            )["dimensions"]["builder_level"]["cells"]

            self.assertFalse(any(
                cell["state"] == "reported" for cell in builder.values()
            ))

    def test_population_aggregate_reconciles_every_authoritative_subject(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store, _ = self.create_store(directory)
            expected = [str(proposal(ordinal)["subject_ref"]) for ordinal in range(1, 7)]
            for ordinal in range(1, 6):
                case = store.submit(proposal(ordinal))
                store.decide(
                    case.case_code, action="approved",
                    actor_code="release_owner", decided_at=NOW,
                )
            insufficient = store.submit(insufficient_proposal(6))
            store.decide(
                insufficient.case_code, action="approved",
                actor_code="release_owner", decided_at=NOW,
            )

            aggregate = store.build_population_aggregate(
                expected_subject_refs=expected,
                binding_context=population_context(),
                generated_at=NOW,
                minimum_group_size=5,
            )

            self.assertEqual(
                aggregate["aggregate_version"], "population-semantic-aggregate-v2",
            )
            self.assertEqual(aggregate["population"]["total_count"], 6)
            self.assertEqual(aggregate["population"]["assessed_count"], 5)
            self.assertEqual(aggregate["population"]["unknown_count"], 1)
            self.assertEqual(aggregate["population"]["state_counts"]["no_evidence"], 1)
            self.assertEqual(aggregate["source_coverage"]["public_projects"], 5)
            self.assertEqual(aggregate["metrics"]["advanced_technical_evidence"], 5)
            self.assertEqual(
                aggregate["taxonomy_dimensions"]["technical_depth"]["cells"]
                ["advanced"],
                5,
            )
            self.assertEqual(
                aggregate["taxonomy_dimensions"]["technical_depth"]
                ["unknown_count"],
                1,
            )
            self.assertEqual(
                aggregate["taxonomy_dimensions"]["technical_methods"]["cells"],
                {
                    "applied_ai_ml": 5,
                    "automation_orchestration": 0,
                    "blockchain_web3": 0,
                    "cloud_infrastructure": 0,
                    "computer_vision": 0,
                    "cybersecurity": 0,
                    "data_engineering": 0,
                    "distributed_systems": 0,
                    "hardware_iot": 0,
                    "mobile_native": 0,
                    "natural_language_processing": 0,
                    "realtime_systems": 0,
                    "spatial_computing": 0,
                    "web_full_stack": 5,
                },
            )

    def test_population_aggregate_projects_real_membership_when_supplied(self) -> None:
        from community_os.rich_semantic_review import RichSemanticReviewStore

        self.assertIn(
            "membership_by_subject",
            inspect.signature(
                RichSemanticReviewStore.build_population_aggregate,
            ).parameters,
        )
        with tempfile.TemporaryDirectory() as directory:
            store, _ = self.create_store(directory)
            expected = [
                str(proposal(ordinal)["subject_ref"])
                for ordinal in range(1, 7)
            ]
            for ordinal in range(1, 7):
                case = store.submit(proposal(ordinal))
                store.decide(
                    case.case_code, action="approved",
                    actor_code="release_owner", decided_at=NOW,
                )

            legacy = store.build_population_aggregate(
                expected_subject_refs=expected,
                binding_context=population_context(),
                generated_at=NOW,
                minimum_group_size=5,
            )
            membership = {
                subject: {
                    "applied": "member",
                    "accepted": "member" if index < 5 else "not_member",
                    "present": "member" if index < 5 else "not_member",
                }
                for index, subject in enumerate(expected)
            }
            bundle = store.build_population_aggregate(
                expected_subject_refs=expected,
                binding_context=population_context(),
                generated_at=NOW,
                minimum_group_size=5,
                membership_by_subject=membership,
            )

            self.assertEqual(
                legacy["population"]["population_key"], "all_applicants",
            )
            self.assertEqual(tuple(bundle), ("all", "accepted", "attended"))
            self.assertEqual(
                {
                    key: aggregate["population"]["total_count"]
                    for key, aggregate in bundle.items()
                },
                {"all": 6, "accepted": 5, "attended": 5},
            )
            self.assertNotEqual(
                bundle["all"]["bindings"]["population_sha256"],
                bundle["accepted"]["bindings"]["population_sha256"],
            )

            with self.assertRaisesRegex(ValueError, "membership.*subjects"):
                store.build_population_aggregate(
                    expected_subject_refs=expected,
                    binding_context=population_context(),
                    generated_at=NOW,
                    minimum_group_size=5,
                    membership_by_subject={
                        subject: membership[subject] for subject in expected[:-1]
                    },
                )

    def test_population_aggregate_blocks_missing_or_unmapped_terminal_cases(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store, _ = self.create_store(directory)
            case = store.submit(proposal(1))
            store.decide(
                case.case_code, action="approved",
                actor_code="release_owner", decided_at=NOW,
            )

            with self.assertRaisesRegex(PermissionError, "population|case"):
                store.build_population_aggregate(
                    expected_subject_refs=[
                        str(proposal(1)["subject_ref"]),
                        str(proposal(2)["subject_ref"]),
                    ],
                    binding_context=population_context(),
                    generated_at=NOW,
                    minimum_group_size=5,
                )

    def test_population_aggregate_maps_rejection_to_its_exact_subject(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store, _ = self.create_store(directory)
            case = store.submit(proposal(1))
            store.decide(
                case.case_code, action="rejected",
                actor_code=AUTHENTICATED_ACTOR, decided_at=NOW,
            )

            aggregate = store.build_population_aggregate(
                expected_subject_refs=[str(proposal(1)["subject_ref"])],
                binding_context=population_context(),
                generated_at=NOW,
                minimum_group_size=5,
            )

            self.assertEqual(aggregate["population"]["state_counts"]["rejected"], 1)
            self.assertEqual(aggregate["population"]["assessed_count"], 0)

    def test_legacy_v1_fact_is_retained_as_conflict_not_positive_semantics(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store, _ = self.create_store(directory)
            case = store.submit(proposal(1))
            store.decide(
                case.case_code, action="approved",
                actor_code="release_owner", decided_at=NOW,
            )
            record_path = next(store.reviewed.glob("*.json"))
            record = json.loads(record_path.read_text(encoding="utf-8"))
            fact = record["fact"]
            fact["fact_version"] = "rich-semantic-reviewed-fact-v1"
            fact.pop("reason_codes")
            fact.pop("reviewed_narrative")
            fact.pop("semantic_taxonomy")
            receipt = record["audit_receipt"]
            receipt["fact_sha256"] = _sha256(fact)
            receipt["receipt_version"] = "rich-semantic-deletion-receipt-v1"
            receipt.pop("decision_hmac_sha256")
            record_path.write_text(
                json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )

            aggregate = store.build_population_aggregate(
                expected_subject_refs=[str(proposal(1)["subject_ref"])],
                binding_context=population_context(),
                generated_at=NOW,
                minimum_group_size=5,
            )

            self.assertEqual(aggregate["population"]["assessed_count"], 0)
            self.assertEqual(aggregate["population"]["state_counts"]["conflict"], 1)
            self.assertTrue(all(value == 0 for value in aggregate["metrics"].values()))

    def test_legacy_receipt_cannot_downgrade_a_positive_v3_fact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store, _ = self.create_store(directory)
            case = store.submit(proposal(1))
            store.decide(
                case.case_code, action="approved",
                actor_code=AUTHENTICATED_ACTOR, decided_at=NOW,
            )
            record_path = next(store.reviewed.glob("*.json"))
            record = json.loads(record_path.read_text(encoding="utf-8"))
            receipt = record["audit_receipt"]
            receipt["receipt_version"] = "rich-semantic-deletion-receipt-v1"
            receipt.pop("decision_hmac_sha256")
            record_path.write_text(
                json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(PermissionError, "legacy|final receipt"):
                store.build_population_aggregate(
                    expected_subject_refs=[str(proposal(1)["subject_ref"])],
                    binding_context=population_context(), generated_at=NOW,
                    minimum_group_size=5,
                )

    def test_interrupted_projection_recovers_without_retaining_evidence_or_duplicate_decision(self) -> None:
        tripped = {"value": False}

        def failpoint(stage: str) -> None:
            if stage == "after_cleanup_before_commit" and not tripped["value"]:
                tripped["value"] = True
                raise RuntimeError("synthetic interruption")

        with tempfile.TemporaryDirectory() as directory:
            store, repository = self.create_store(directory, failpoint=failpoint)
            case = store.submit(proposal(1))
            with self.assertRaisesRegex(RuntimeError, "synthetic interruption"):
                store.decide(
                    case.case_code, action="approved",
                    actor_code="release_owner", decided_at=NOW,
                )
            self.assertFalse(any(store.proposals.glob("*.json")))
            self.assertTrue(any(store.attempts.glob("*.json")))
            self.assertEqual(repository.list(kind="classification")[0].status, "resolved")
            pending = json.loads(next(store.attempts.glob("*.json")).read_text())
            pending_fact_bytes = json.dumps(
                pending["fact"], sort_keys=True, separators=(",", ":"),
            ).encode("utf-8")

            recovered = store.recover_interrupted()
            self.assertEqual(recovered["recovered_count"], 1)
            self.assertFalse(any(store.attempts.glob("*.json")))
            self.assertTrue(any(store.reviewed.glob("*.json")))
            finalized = json.loads(next(store.reviewed.glob("*.json")).read_text())
            finalized_fact_bytes = json.dumps(
                finalized["fact"], sort_keys=True, separators=(",", ":"),
            ).encode("utf-8")
            self.assertEqual(finalized_fact_bytes, pending_fact_bytes)
            self.assertEqual(store.build_aggregate(minimum_group_size=5)["reviewed_denominator"], 1)

    def test_interruption_before_cleanup_rechecks_deletion_before_commit(self) -> None:
        tripped = {"value": False}

        def failpoint(stage: str) -> None:
            if stage == "after_attempt_before_cleanup" and not tripped["value"]:
                tripped["value"] = True
                raise RuntimeError("synthetic pre-cleanup interruption")

        with tempfile.TemporaryDirectory() as directory:
            store, _ = self.create_store(directory, failpoint=failpoint)
            case = store.submit(proposal(1))
            relevant_cache_file = store.transient_cache_root / f"{case.case_code}.json"
            relevant_cache_file.write_text("transient", encoding="utf-8")
            peer_cache_file = store.transient_cache_root / "interrupted-peer.json"
            peer_cache_file.write_text("transient", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "pre-cleanup"):
                store.decide(
                    case.case_code, action="approved",
                    actor_code="release_owner", decided_at=NOW,
                )
            self.assertTrue(any(store.proposals.glob("*.json")))
            self.assertTrue(any(store.transient.glob("*.json")))
            self.assertTrue(relevant_cache_file.exists())
            self.assertTrue(peer_cache_file.exists())

            recovered = store.recover_interrupted()

            self.assertEqual(recovered["recovered_count"], 1)
            self.assertFalse(any(store.proposals.glob("*.json")))
            self.assertFalse(any(store.transient.glob("*.json")))
            self.assertFalse(relevant_cache_file.exists())
            self.assertTrue(peer_cache_file.exists())
            record = json.loads(next(store.reviewed.glob("*.json")).read_text())
            self.assertTrue(record["audit_receipt"]["minimized_evidence_deleted"])
            self.assertTrue(record["audit_receipt"]["transient_cache_deleted"])

    def test_review_cleanup_deletes_only_the_exact_semantic_cache_entry(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store, _ = self.create_store(directory)
            case = store.submit(proposal(1))
            reviewed_cache_file = store.transient_cache_root / f"{case.case_code}.json"
            reviewed_cache_file.write_text("transient", encoding="utf-8")
            peer_cache_file = store.transient_cache_root / "interrupted-peer.json"
            peer_cache_file.write_text("transient", encoding="utf-8")
            classification_cache_file = (
                Path(directory) / "protected" / "cache" / "classification"
                / "unrelated.json"
            )
            classification_cache_file.parent.mkdir(parents=True, mode=0o700)
            classification_cache_file.write_text("{}\n", encoding="utf-8")
            github_cache_file = (
                Path(directory) / "protected" / "cache" / "github" / "unrelated.json"
            )
            github_cache_file.parent.mkdir(parents=True, mode=0o700)
            github_cache_file.write_text("{}\n", encoding="utf-8")

            store.decide(
                case.case_code, action="approved",
                actor_code=AUTHENTICATED_ACTOR, decided_at=NOW,
            )

            self.assertFalse(reviewed_cache_file.exists())
            self.assertTrue(peer_cache_file.exists())
            self.assertTrue(classification_cache_file.exists())
            self.assertTrue(github_cache_file.exists())

    def test_interruption_after_intent_before_review_recovers_exact_correction(self) -> None:
        tripped = {"value": False}

        def failpoint(stage: str) -> None:
            if stage == "after_intent_before_review" and not tripped["value"]:
                tripped["value"] = True
                raise RuntimeError("synthetic pre-review interruption")

        corrected = assessment(
            builder_level="exploratory", product_maturity="prototype",
            technical_depth="moderate", execution_scope="contributor",
            evidence_refs=[
                "project_01:description", "application_01:experience",
            ],
            reason_codes=["prototype_only"],
        )
        with tempfile.TemporaryDirectory() as directory:
            store, repository = self.create_store(directory, failpoint=failpoint)
            case = store.submit(proposal(1))
            with self.assertRaisesRegex(RuntimeError, "pre-review"):
                store.decide(
                    case.case_code, action="corrected",
                    actor_code="release_owner", decided_at=NOW,
                    corrected_assessment=corrected,
                )
            self.assertEqual(repository.list(kind="classification")[0].status, "open")
            attempt_path = next(store.attempts.glob("*.json"))
            self.assertEqual(store.attempts.stat().st_mode & 0o777, 0o700)
            self.assertEqual(attempt_path.stat().st_mode & 0o777, 0o600)

            restarted, restarted_repository = self.create_store(directory)
            recovered = restarted.recover_interrupted()

            # Construction recovers persisted intents before TTL cleanup; an
            # explicit retry is therefore idempotent.
            self.assertEqual(recovered["recovered_count"], 0)
            resolved = restarted_repository.list(kind="classification")[0]
            self.assertEqual(resolved.status, "resolved")
            self.assertEqual(resolved.decision.action, "corrected")
            self.assertEqual(resolved.decision.actor_code, "release_owner")
            self.assertEqual(
                resolved.decision.decided_at,
                NOW.isoformat().replace("+00:00", "Z"),
            )
            self.assertFalse(any(restarted.proposals.glob("*.json")))
            self.assertFalse(any(restarted.transient.glob("*.json")))
            self.assertFalse(any(restarted.attempts.glob("*.json")))
            record = json.loads(next(restarted.reviewed.glob("*.json")).read_text())
            self.assertEqual(record["fact"]["review_action"], "corrected")
            self.assertEqual(
                record["fact"]["semantic_fact"]["builder_level"], "exploratory",
            )
            self.assertEqual(
                record["audit_receipt"]["actor_code"], "release_owner",
            )
            self.assertEqual(
                record["audit_receipt"]["decided_at"],
                NOW.isoformat().replace("+00:00", "Z"),
            )

    def test_unsigned_restart_cannot_apply_or_delete_a_signed_review_intent(self) -> None:
        tripped = {"value": False}

        def failpoint(stage: str) -> None:
            if stage == "after_intent_before_review" and not tripped["value"]:
                tripped["value"] = True
                raise RuntimeError("synthetic signed-intent interruption")

        with tempfile.TemporaryDirectory() as directory:
            store, repository = self.create_store(directory, failpoint=failpoint)
            case = store.submit(proposal(1))
            with self.assertRaisesRegex(RuntimeError, "signed-intent interruption"):
                store.decide(
                    case.case_code, action="approved",
                    actor_code=AUTHENTICATED_ACTOR, decided_at=NOW,
                )

            attempt_path = next(store.attempts.glob("*.json"))
            attempt = json.loads(attempt_path.read_text(encoding="utf-8"))
            attempt["audit_receipt"]["decision_hmac_sha256"] = "0" * 64
            attempt_path.write_text(
                json.dumps(attempt, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )

            unsigned, restarted_repository = self.create_store(
                directory, decision_signing_secret=None,
            )

            self.assertEqual(
                restarted_repository.list(kind="classification")[0].status,
                "open",
            )
            self.assertTrue(any(unsigned.proposals.glob("*.json")))
            self.assertTrue(any(unsigned.transient.glob("*.json")))
            self.assertTrue(any(unsigned.attempts.glob("*.json")))
            self.assertFalse(any(unsigned.reviewed.glob("*.json")))
            with self.assertRaisesRegex(PermissionError, "signing authority"):
                unsigned.recover_interrupted()
            with self.assertRaisesRegex(PermissionError, "tampered"):
                unsigned.configure_decision_authority(REVIEW_SIGNING_SECRET)

            self.assertEqual(repository.list(kind="classification")[0].status, "open")
            self.assertTrue(any(unsigned.proposals.glob("*.json")))
            self.assertTrue(any(unsigned.transient.glob("*.json")))
            self.assertTrue(any(unsigned.attempts.glob("*.json")))
            self.assertFalse(any(unsigned.reviewed.glob("*.json")))

    def test_restart_recovers_review_intent_before_expired_proposal_cleanup(self) -> None:
        clock = {"now": NOW}

        def failpoint(stage: str) -> None:
            if stage == "after_intent_before_review":
                raise RuntimeError("synthetic pre-review interruption")

        with tempfile.TemporaryDirectory() as directory:
            store, _ = self.create_store(
                directory, clock=lambda: clock["now"], failpoint=failpoint,
            )
            case = store.submit(proposal(
                1, expires_at=(NOW + timedelta(hours=1)).isoformat(),
            ))
            with self.assertRaisesRegex(RuntimeError, "pre-review"):
                store.decide(
                    case.case_code, action="approved",
                    actor_code="release_owner", decided_at=NOW,
                )
            clock["now"] = NOW + timedelta(hours=2)

            restarted, repository = self.create_store(
                directory, clock=lambda: clock["now"],
            )

            self.assertFalse(any(restarted.attempts.glob("*.json")))
            self.assertFalse(any(restarted.proposals.glob("*.json")))
            self.assertFalse(any(restarted.transient.glob("*.json")))
            self.assertEqual(
                repository.list(kind="classification")[0].status, "resolved",
            )
            self.assertEqual(
                restarted.build_aggregate(minimum_group_size=5)["reviewed_denominator"],
                1,
            )

    def test_replacing_pending_subject_deletes_superseded_private_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store, repository = self.create_store(directory)
            first = store.submit(proposal(1))
            replacement = store.submit(proposal(1, approval_sha256="b" * 64))

            self.assertNotEqual(first.case_code, replacement.case_code)
            self.assertEqual(
                [item.case_code for item in repository.list(kind="classification")],
                [replacement.case_code],
            )
            self.assertEqual(
                [path.stem for path in store.proposals.glob("*.json")],
                [replacement.case_code],
            )
            self.assertEqual(
                [path.stem for path in store.transient.glob("*.json")],
                [replacement.case_code],
            )

    def test_cleanup_deletes_orphaned_pending_evidence_without_current_case(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store, repository = self.create_store(directory)
            case = store.submit(proposal(1))
            repository.replace_for_kinds(("classification",), ())

            receipt = store.cleanup_expired()

            self.assertEqual(receipt["deleted_count"], 1)
            self.assertFalse((store.proposals / f"{case.case_code}.json").exists())
            self.assertFalse((store.transient / f"{case.case_code}.json").exists())

    def test_resolved_retry_without_persisted_attempt_fails_closed(self) -> None:
        tripped = {"value": False}

        def failpoint(stage: str) -> None:
            if stage == "after_review_before_attempt" and not tripped["value"]:
                tripped["value"] = True
                raise RuntimeError("synthetic pre-attempt interruption")

        with tempfile.TemporaryDirectory() as directory:
            store, _ = self.create_store(directory, failpoint=failpoint)
            case = store.submit(proposal(1))
            with self.assertRaisesRegex(RuntimeError, "pre-attempt"):
                store.decide(
                    case.case_code, action="approved",
                    actor_code="release_owner", decided_at=NOW,
                )
            next(store.attempts.glob("*.json")).unlink()

            with self.assertRaisesRegex(PermissionError, "persisted attempt"):
                store.decide(
                    case.case_code, action="approved",
                    actor_code="different_operator",
                    decided_at=NOW + timedelta(hours=1),
                )

            self.assertTrue(any(store.proposals.glob("*.json")))
            self.assertTrue(any(store.transient.glob("*.json")))
            self.assertFalse(any(store.attempts.glob("*.json")))
            self.assertFalse(any(store.reviewed.glob("*.json")))
            self.assertFalse(any(store.receipts.glob("*.json")))

    def test_expired_pending_evidence_cleanup_deletes_both_copies_and_records_receipt(self) -> None:
        clock = {"now": NOW}
        with tempfile.TemporaryDirectory() as directory:
            store, repository = self.create_store(directory, clock=lambda: clock["now"])
            case = store.submit(proposal(
                1, expires_at=(NOW + timedelta(hours=1)).isoformat(),
            ))
            clock["now"] = NOW + timedelta(hours=2)

            receipt = store.cleanup_expired()

            self.assertEqual(receipt["deleted_count"], 1)
            self.assertFalse(any(store.proposals.glob("*.json")))
            self.assertFalse(any(store.transient.glob("*.json")))
            self.assertFalse(any(store.reviewed.glob("*.json")))
            self.assertNotIn(case.case_code, {
                item.case_code for item in repository.list(kind="classification")
            })
            cleanup = json.loads(
                (store.root / "cleanup-receipt.json").read_text(encoding="utf-8")
            )
            self.assertEqual(cleanup["deletion_state"], "pending_evidence_deleted")
            self.assertEqual(cleanup["deleted_count"], 1)

    def test_store_startup_recovers_interrupted_expiry_cleanup_and_records_it(self) -> None:
        clock = {"now": NOW}
        with tempfile.TemporaryDirectory() as directory:
            store, _ = self.create_store(directory, clock=lambda: clock["now"])
            case = store.submit(proposal(
                1, expires_at=(NOW + timedelta(hours=1)).isoformat(),
            ))
            clock["now"] = NOW + timedelta(hours=2)

            def failpoint(stage: str) -> None:
                if stage == "after_cleanup_case_removal":
                    raise RuntimeError("synthetic cleanup interruption")

            with self.assertRaisesRegex(RuntimeError, "cleanup interruption"):
                self.create_store(
                    directory, clock=lambda: clock["now"], failpoint=failpoint,
                )

            restarted, repository = self.create_store(
                directory, clock=lambda: clock["now"],
            )

            self.assertFalse(any(restarted.proposals.glob("*.json")))
            self.assertFalse(any(restarted.transient.glob("*.json")))
            self.assertNotIn(case.case_code, {
                item.case_code for item in repository.list(kind="classification")
            })
            self.assertFalse((restarted.root / "cleanup-attempt.json").exists())
            cleanup = json.loads(
                (restarted.root / "cleanup-receipt.json").read_text(encoding="utf-8")
            )
            self.assertEqual(cleanup["deletion_state"], "pending_evidence_deleted")
            self.assertEqual(cleanup["deleted_count"], 1)
            self.assertTrue(cleanup["recovered_interruption"])

    def test_store_must_be_isolated_from_release_root(self) -> None:
        from community_os.rich_semantic_review import RichSemanticReviewStore

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "release" / "rich-semantic-review"
            with self.assertRaisesRegex(ValueError, "isolated"):
                RichSemanticReviewStore(
                    root, release_root=Path(directory) / "release",
                    review_repository=ReviewRepository(Path(directory) / "reviews.json"),
                    clock=lambda: NOW,
                    review_context_hashes={
                        "event_approval": "a" * 64,
                        "event_definition": "b" * 64,
                        "event_key": "c" * 64,
                    },
                )


if __name__ == "__main__":
    unittest.main()
