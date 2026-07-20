from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime, timedelta
import hashlib
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import ANY, patch


NOW = datetime(2026, 7, 13, 12, tzinfo=UTC)
ROOT = Path(__file__).resolve().parents[1]

_SEMANTIC_REPORT_DIMENSION_LIMITS: dict[str, int | None] = {
    "product_maturity": 0,
    "technical_depth": 0,
    "execution_scope": 0,
    "external_validation": 0,
    "problem_differentiation": 0,
    "technical_methods": 6,
    "demonstrated_capabilities": 6,
    "career_stage": None,
    "founder_state": 5,
    "leadership_state": 5,
    "career_functions": 5,
    "career_delivery": 5,
    "market_domains": 6,
}


def _claim_count_line(value: int, denominator: int) -> str:
    percentage = round(value / denominator * 100) if denominator else 0
    return f"{value} of {denominator} ({percentage}%)"


def _expected_funnel_claims(
    headline_counts: dict[str, int | None],
) -> list[tuple[str, str]]:
    applied = headline_counts["applied"]
    accepted = headline_counts["going_accepted"]
    attendance = headline_counts["on_site"]
    assert isinstance(applied, int)
    assert isinstance(accepted, int)
    claims = [
        ("Applied", f"{applied} people"),
        ("Accepted by organizers", f"{accepted} people"),
        (
            "of applicants",
            f"{round(accepted / applied * 100) if applied else 0}%",
        ),
        (
            "applicants were not in the accepted group",
            str(applied - accepted),
        ),
    ]
    if attendance is None:
        claims.append((
            "Confirmed present at the event", "Attendance count hidden",
        ))
    else:
        claims.extend((
            ("Confirmed present at the event", f"{attendance} people"),
            (
                "accepted participants were confirmed present",
                f"{attendance} of {accepted}",
            ),
            (
                "were not in the reviewed attendance count",
                str(accepted - attendance),
            ),
        ))
    return claims


def _expected_semantic_report_claims(
    summary: object,
    headline_counts: dict[str, int | None],
) -> list[tuple[str, str]]:
    claims = _expected_funnel_claims(headline_counts)

    metrics = tuple(getattr(summary, "metrics"))
    for metric in metrics:
        count = getattr(metric, "count")
        denominator = getattr(metric, "denominator")
        if count is None or count == 0:
            continue
        display = str(count) if denominator is None else f"{count} of {denominator}"
        claims.append((str(getattr(metric, "label")), display))

    public_groups = tuple(getattr(summary, "public_groups"))
    assert len(public_groups) == 8
    for group in public_groups:
        count = getattr(group, "count")
        denominator = getattr(group, "denominator")
        if getattr(group, "state") != "reported" or count is None or count == 0:
            continue
        assert isinstance(denominator, int)
        claims.append((
            str(getattr(group, "label")),
            _claim_count_line(count, denominator),
        ))

    dimensions = tuple(getattr(summary, "dimensions"))
    assert {str(getattr(item, "key")) for item in dimensions} == set(
        _SEMANTIC_REPORT_DIMENSION_LIMITS,
    )
    for dimension in dimensions:
        key = str(getattr(dimension, "key"))
        denominator = getattr(dimension, "denominator")
        visible = sorted(
            (
                cell for cell in getattr(dimension, "cells")
                if getattr(cell, "state") == "reported"
                and isinstance(getattr(cell, "count"), int)
                and getattr(cell, "count") > 0
            ),
            key=lambda cell: (
                -int(getattr(cell, "count")), str(getattr(cell, "label")),
            ),
        )
        limit = _SEMANTIC_REPORT_DIMENSION_LIMITS[key]
        if limit is not None:
            visible = visible[:limit]
        for cell in visible:
            count = int(getattr(cell, "count"))
            display = (
                _claim_count_line(count, denominator)
                if isinstance(denominator, int) else f"{count} people"
            )
            claims.append((str(getattr(cell, "label")), display))

    return claims


def _event_definition():
    from community_os.event_definition import load_event_definition

    return load_event_definition(ROOT / "config/events/openai-hackathon-2026.json")


def _public_gate(scope: str, retention_days: int) -> dict[str, object]:
    return {
        "notice_version": "notice_v2", "notice_sent_at": "2026-07-13T08:00:00Z",
        "objections_reconciled": True, "exclusions_reconciled": True,
        "suppressions_reconciled": True, "deletions_reconciled": True,
        "source_authorization_confirmed": True, "provider_terms_version": "terms_v1",
        "source_scope": scope, "purpose_code": "aggregate_talent_evidence",
        "retention_days": retention_days, "accountable_owner": "privacy_lead",
        "approval_id": "approval_001", "approved_at": "2026-07-13T09:00:00Z",
    }


def _privacy_operations() -> dict[str, object]:
    return {
        "accountable_owner": "privacy_lead",
        "approval": {
            "actor_code": "release_owner",
            "approved_at": "2026-07-13T10:00:00Z",
            "expires_at": "2026-08-12T10:00:00Z",
        },
        "allowed_uses": {
            "applications": ["aggregate"],
            "attendance": ["aggregate"],
            "preferences": ["aggregate"],
            "submissions": ["aggregate"],
            "github": ["classify"],
            "public_pages": ["classify"],
            "coresignal": ["classify"],
            "classification": ["aggregate"],
            "partner_report": ["publish"],
        },
        "excluded_subject_refs": [],
        "notice_sent_at": "2026-07-13T08:00:00Z",
        "notice_version": "notice_v2",
        "retention_deadline": "2026-10-11T12:00:00Z",
        "rights": {
            "deletion_status": "not_requested",
            "exclusion_status": "included",
            "objection_status": "none",
            "reconciled": True,
            "suppression_status": "not_requested",
        },
    }


def _source_hashes() -> dict[str, str]:
    return {
        source: hashlib.sha256(source.encode()).hexdigest()
        for source in ("applications", "attendance", "preferences", "submissions")
    }


def _write_semantic_release_qa(
    protected: Path,
    aggregate: dict[str, object],
    public_paths: tuple[Path, ...],
):
    from community_os.semantic_metrics import semantic_aggregate_sha256
    from community_os.semantic_release_qa import (
        build_semantic_release_qa_context,
        build_semantic_release_qa_receipt,
    )

    bindings = aggregate["bindings"]
    population = aggregate["population"]
    assert isinstance(bindings, dict)
    assert isinstance(population, dict)
    release_context = {
        "event_approval_sha256": bindings["event_approval_sha256"],
        "event_definition_sha256": bindings["event_definition_sha256"],
        "event_key": bindings["event_key"],
        "population_sha256": bindings["population_sha256"],
        "run_sha256": bindings["run_sha256"],
        "source_snapshot_sha256": bindings["source_snapshot_sha256"],
        "taxonomy_sha256": bindings["taxonomy_sha256"],
        "taxonomy_version": bindings["taxonomy_version"],
        "total_population": population["total_count"],
    }
    context_path = protected / "semantic-release-context.json"
    context_path.write_text(
        json.dumps(release_context, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    context_path.chmod(0o600)
    qa_context = build_semantic_release_qa_context(
        event_approval_sha256=str(bindings["event_approval_sha256"]),
        event_definition_sha256=str(bindings["event_definition_sha256"]),
        event_key=str(bindings["event_key"]),
        source_snapshot_sha256=str(bindings["source_snapshot_sha256"]),
        population=population,
        run_sha256=str(bindings["run_sha256"]),
        taxonomy_version=str(bindings["taxonomy_version"]),
        aggregate_sha256=semantic_aggregate_sha256(aggregate),
        html_candidate_sha256=hashlib.sha256(public_paths[0].read_bytes()).hexdigest(),
        pdf_candidate_sha256=hashlib.sha256(public_paths[1].read_bytes()).hexdigest(),
        positive_claim_count=1,
        required_review_case_count=1,
        review_evidence_sha256="9" * 64,
    )
    checks = {
        key: {"passed": True, "evidence_count": count, "expected_count": count}
        for key, count in {
            "aggregate_rederived": 7,
            "artifact_privacy_parity": 4,
            "dashboard_state_parity": 4,
            "html_pdf_text_parity": 5,
            "pdf_layout": 5,
            "positive_claim_sample_bound_to_final_reviewed_facts": 1,
            "required_review_cases_resolved": 1,
        }.items()
    }
    receipt = build_semantic_release_qa_receipt(
        context=qa_context, checks=checks,
    )
    qa_path = protected / "semantic-release-qa.json"
    qa_path.write_text(receipt.canonical_json() + "\n", encoding="utf-8")
    qa_path.chmod(0o600)
    return receipt


def _semantic_authoritative_context(
    aggregate: dict[str, object],
) -> dict[str, object]:
    bindings = aggregate["bindings"]
    population = aggregate["population"]
    assert isinstance(bindings, dict)
    assert isinstance(population, dict)
    return {
        "event_approval_sha256": bindings["event_approval_sha256"],
        "event_definition_sha256": bindings["event_definition_sha256"],
        "event_key": bindings["event_key"],
        "source_snapshot_sha256": bindings["source_snapshot_sha256"],
        "taxonomy_sha256": bindings["taxonomy_sha256"],
        "taxonomy_version": bindings["taxonomy_version"],
        "total_population": population["total_count"],
    }


def _bundle(publication_approval: object = None) -> dict[str, object]:
    definition = _event_definition()
    source_hashes = _source_hashes()
    return {
        "bundle_version": "controlled-release-v2",
        "event_approval": {
            "version": "event-approval-v2",
            "event_key": definition.event_key,
            "event_definition_sha256": definition.sha256,
            "policy_profile": definition.privacy.policy_profile,
            "taxonomy_version": definition.semantic.taxonomy_version,
            "metric_registry_version": definition.semantic.metric_registry_version,
            "sources": {
                source.role: {
                    "adapter_id": source.adapter_id,
                    "mapping_sha256": source.mapping_sha256,
                    "source_sha256": source_hashes[source.role],
                }
                for source in definition.sources
            },
            "excluded_subject_refs": [],
            "actor_code": "release_owner",
            "approved_at": "2026-07-13T10:00:00Z",
        },
        "generated_at": "2026-07-13T12:00:00Z",
        "public_sources": {
            "github": _public_gate("applicant_supplied_github", 30),
            "public_pages": _public_gate("applicant_supplied_public_pages", 14),
        },
        "coresignal": None,
        "privacy_operations": _privacy_operations(),
        "publication_approval": publication_approval,
        "semantic_processor": None,
    }


def _coresignal_gate() -> dict[str, object]:
    return {
        "notice_version": "coresignal_transparency_v1", "notice_sent_at": "2026-07-13T10:00:00Z",
        "notice_scope": "linkedin_coresignal_enrichment",
        "notice_content_sha256": "d" * 64,
        "objections_reconciled": True, "exclusions_reconciled": True,
        "suppressions_reconciled": True, "deletions_reconciled": True,
        "access_verified": True, "provider_terms_version": "terms_v1",
        "source_scope": "applicant_supplied_linkedin", "retention_days": 14,
        "approval_id": "release_approval_001",
        "approved_at": "2026-07-13T11:00:00Z",
    }


def _semantic_processor() -> dict[str, object]:
    return {
        "provider": "openai_responses", "purpose": "talent_classification",
        "dpa_version": "dpa-v1", "terms_version": "terms-v1",
        "retention_mode": "zero_retention", "region": "eu",
        "security_profile": "approved-v1",
        "field_allowlist": ["evidence_refs", "signals", "subject_ref"],
        "approved_by": "start_privacy_owner",
        "approved_at": "2026-07-13T11:00:00Z",
    }


class ControlledReleaseTests(unittest.TestCase):
    def test_runtime_requires_an_explicit_event_definition(self) -> None:
        from community_os.controlled_release import ControlledReleaseRuntime

        with self.assertRaisesRegex(ValueError, "event definition is required"):
            ControlledReleaseRuntime(
                approval_bundle=Path("approval.json"),
                pseudonym_secret=b"fixture-pseudonym-secret",
            )

    def test_scheduled_cleanup_requires_an_explicit_event_definition(self) -> None:
        import inspect

        from community_os.controlled_release import run_scheduled_privacy_cleanup

        parameter = inspect.signature(
            run_scheduled_privacy_cleanup,
        ).parameters["event_definition"]

        self.assertIs(parameter.default, inspect.Parameter.empty)

    def test_semantic_candidate_promotion_requires_every_immutable_binding(self) -> None:
        from community_os.controlled_release import _is_semantic_binding_promotion
        from community_os.partner_semantic_projection import (
            build_partner_semantic_summary,
            build_protected_partner_semantic_candidate_summary,
            semantic_summary_manifest_binding,
        )
        from tests.test_partner_semantic_projection import (
            APPROVAL_SECRET,
            NOW,
            approved_release,
            semantic_aggregate,
        )

        candidate = semantic_summary_manifest_binding(
            build_protected_partner_semantic_candidate_summary(semantic_aggregate()),
        )
        approved = semantic_summary_manifest_binding(
            build_partner_semantic_summary(
                approved_release(), now=NOW, approval_secret=APPROVAL_SECRET,
            ),
        )
        self.assertTrue(_is_semantic_binding_promotion(candidate, approved))

        drifted = dict(approved)
        drifted["source_snapshot_sha256"] = "f" * 64
        self.assertFalse(_is_semantic_binding_promotion(candidate, drifted))

    def test_event_approval_must_fall_inside_current_privacy_approval_window(self) -> None:
        from community_os.controlled_release import (
            ControlledReleaseRuntime, build_controlled_release_factory,
        )

        for approved_at in ("2020-01-01T00:00:00Z", "2099-01-01T00:00:00Z"):
            with self.subTest(approved_at=approved_at), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                state = self._state_with_sources(root)
                bundle = _bundle()
                bundle["event_approval"]["approved_at"] = approved_at
                path = root / "approval.json"
                path.write_text(json.dumps(bundle), encoding="utf-8")

                with self.assertRaisesRegex(
                    PermissionError, "event approval is not currently valid",
                ):
                    build_controlled_release_factory(ControlledReleaseRuntime(
                        approval_bundle=path,
                        pseudonym_secret=b"fixture-pseudonym-secret",
                        event_definition=_event_definition(),
                        clock=lambda: NOW,
                    ))(state)

                self.assertIsNone(state.snapshot()["event_approval"])

    def test_v1_or_duplicate_event_approval_fails_before_any_transport_is_created(self) -> None:
        from community_os.controlled_release import (
            ControlledReleaseRuntime,
            build_controlled_release_factory,
        )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = self._state_with_sources(root)
            path = root / "approval.json"
            legacy = _bundle()
            legacy["bundle_version"] = "controlled-release-v1"
            path.write_text(json.dumps(legacy), encoding="utf-8")
            calls: list[str] = []
            runtime = ControlledReleaseRuntime(
                approval_bundle=path,
                pseudonym_secret=b"fixture-pseudonym-secret",
                event_definition=_event_definition(),
                transport_factory=lambda: calls.append("transport") or object(),
                clock=lambda: NOW,
            )

            with self.assertRaisesRegex(PermissionError, "version is unsupported"):
                build_controlled_release_factory(runtime)(state)

            raw = json.dumps(_bundle(), separators=(",", ":"))
            event_key = _event_definition().event_key
            raw = raw.replace(
                f'"event_key":"{event_key}"',
                f'"event_key":"{event_key}","event_key":"{event_key}"',
                1,
            )
            path.write_text(raw, encoding="utf-8")
            with self.assertRaisesRegex(PermissionError, "duplicate key: event_key"):
                build_controlled_release_factory(runtime)(state)
            self.assertEqual(calls, [])

    def test_optional_event_sources_are_explicit_null_and_do_not_block_factory(self) -> None:
        from community_os.controlled_release import (
            ControlledReleaseRuntime,
            build_controlled_release_factory,
        )
        from community_os.event_definition import load_event_definition
        from community_os.release_operator import ReleaseOperatorState

        definition = load_event_definition(
            ROOT / "tests/fixtures/events/second-hackathon.synthetic.json",
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = ReleaseOperatorState(
                root / "operator",
                operator_code="privacy_lead",
                event_definition=definition,
            )
            source_hashes: dict[str, str | None] = {
                source.role: None for source in definition.sources
            }
            for role in ("applications", "attendance"):
                body = role.encode("utf-8")
                destination = state.record_source(
                    role,
                    sha256=hashlib.sha256(body).hexdigest(),
                    row_count=1,
                    filename=f"{role}.xlsx",
                )
                destination.write_bytes(body)
                source_hashes[role] = hashlib.sha256(body).hexdigest()
            privacy = _privacy_operations()
            privacy["allowed_uses"] = {
                **{
                    source.role: ["aggregate"]
                    for source in definition.sources
                },
                "github": ["classify"],
                "public_pages": ["classify"],
                "coresignal": ["classify"],
                "classification": ["aggregate"],
                "partner_report": ["publish"],
            }
            bundle = _bundle()
            bundle["privacy_operations"] = privacy
            bundle["event_approval"] = {
                "version": "event-approval-v2",
                "event_key": definition.event_key,
                "event_definition_sha256": definition.sha256,
                "policy_profile": definition.privacy.policy_profile,
                "taxonomy_version": definition.semantic.taxonomy_version,
                "metric_registry_version": definition.semantic.metric_registry_version,
                "sources": {
                    source.role: {
                        "adapter_id": source.adapter_id,
                        "mapping_sha256": source.mapping_sha256,
                        "source_sha256": source_hashes[source.role],
                    }
                    for source in definition.sources
                },
                "excluded_subject_refs": [],
                "actor_code": "release_owner",
                "approved_at": "2026-07-13T10:00:00Z",
            }
            path = root / "approval.json"
            path.write_text(json.dumps(bundle), encoding="utf-8")

            operations = build_controlled_release_factory(ControlledReleaseRuntime(
                approval_bundle=path,
                pseudonym_secret=b"fixture-pseudonym-secret",
                event_definition=definition,
                clock=lambda: NOW,
            ))(state)

            self.assertIn("reconcile", operations)
            self.assertIsNotNone(state.snapshot()["event_approval"])
            privacy_plan = json.loads(
                (state.root / "protected/privacy-operations.json").read_text(
                    encoding="utf-8",
                )
            )
            inventory_sources = {item["source"] for item in privacy_plan["inventory"]}
            self.assertIn("applications", inventory_sources)
            self.assertIn("attendance", inventory_sources)
            self.assertNotIn("teams", inventory_sources)
            self.assertNotIn("submissions", inventory_sources)

    def test_enrichment_coverage_counts_only_observed_records(self) -> None:
        from community_os.controlled_release import _observed_record_count

        records = [
            {"state": "observed"},
            {"state": "unknown", "reason_code": "profile_not_found"},
            {"state": "observed"},
        ]

        self.assertEqual(_observed_record_count(records, stage="github"), 2)

    def test_openai_transport_uses_only_the_approved_processor_region(self) -> None:
        from community_os.controlled_release import _openai_transport

        global_route = _openai_transport(region="global")

        self.assertEqual(global_route.host, "api.openai.com")
        with self.assertRaises(TypeError):
            _openai_transport(lambda: object(), region="global")

    def test_runtime_repr_redacts_all_secrets_and_github_credential_is_loaded_transiently(self) -> None:
        from community_os.controlled_release import (
            ControlledReleaseRuntime, load_transient_github_token,
            resolve_github_token,
        )

        runtime = ControlledReleaseRuntime(
            approval_bundle=Path("approval.json"),
            pseudonym_secret=b"pseudonym-secret-marker",
            event_definition=_event_definition(),
            github_token="github-secret-marker",
            coresignal_token="coresignal-secret-marker",
            openai_api_key="openai-secret-marker",
        )
        rendered = repr(runtime)
        for secret in (
            "pseudonym-secret-marker", "github-secret-marker",
            "coresignal-secret-marker", "openai-secret-marker",
        ):
            self.assertNotIn(secret, rendered)

        calls: list[object] = []

        def runner(command, **options):
            calls.append((command, options))
            return SimpleNamespace(returncode=0, stdout="transient-gh-secret\n", stderr="")

        token = load_transient_github_token(runner=runner)
        self.assertEqual(token, "transient-gh-secret")
        self.assertEqual(calls[0][0], ["gh", "auth", "token"])
        self.assertTrue(calls[0][1]["capture_output"])
        supplier_calls: list[str] = []
        self.assertEqual(
            resolve_github_token(
                "managed-token", lambda: supplier_calls.append("unexpected") or None,
            ),
            "managed-token",
        )
        self.assertEqual(supplier_calls, [])
        self.assertEqual(
            resolve_github_token(
                None, lambda: supplier_calls.append("gh") or "transient-token",
            ),
            "transient-token",
        )
        with self.assertRaisesRegex(PermissionError, "authenticated gh credential"):
            resolve_github_token(None, lambda: None)

    def test_reviewed_projection_finalization_deletes_raw_and_all_transient_caches(self) -> None:
        from community_os.controlled_release import finalize_reviewed_evidence
        from community_os.enrichment.cache import CanonicalJsonCache
        from community_os.enrichment.evidence_vault import ProtectedEvidenceVault

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            vault = ProtectedEvidenceVault(
                root / "protected" / "raw-evidence", clock=lambda: NOW,
            )
            subject = "pid:v1:" + "a" * 64
            evidence = "evidence:github:" + "b" * 64
            vault.capture(
                source="github", purpose="talent_classification", subject_ref=subject,
                evidence_ref=evidence, provider_version="github-public-profile-v1",
                content_type="application/json", payload=b'{"login":"private"}',
                ttl=timedelta(hours=1),
            )
            cache = CanonicalJsonCache(root / "protected" / "cache" / "github", clock=lambda: NOW)
            key = cache.key("github", "v1", {"subject_ref": subject})
            cache.set(key, {"state": "observed"}, expires_at=NOW + timedelta(days=1))

            result = finalize_reviewed_evidence(
                vault=vault, caches=(cache,), projection={"app-1": {"seniority": {"unknown"}}},
                semantic_projection={
                    "aggregate_version": "population-semantic-aggregate-v2",
                    "bindings": {"run_sha256": "c" * 64},
                    "population": {"total": 1},
                },
            )

            self.assertEqual(result["raw_evidence_deleted"], 1)
            self.assertEqual(result["transient_cache_deleted"], 1)
            self.assertRegex(result["projection_sha256"], r"^[0-9a-f]{64}$")
            self.assertRegex(result["semantic_projection_sha256"], r"^[0-9a-f]{64}$")
            receipt = json.loads(next(vault.receipts.iterdir()).read_text(encoding="utf-8"))
            self.assertEqual(
                receipt["projection_sha256"], result["projection_sha256"],
            )
            self.assertEqual(list(vault.records.iterdir()), [])
            self.assertEqual(list(cache.root.iterdir()), [])

    def test_rich_semantic_aggregate_supersedes_the_legacy_person_projection(self) -> None:
        from community_os.controlled_release import (
            _authoritative_person_projection,
        )

        state = SimpleNamespace()
        with patch(
            "community_os.release_operations.load_reviewed_classification_projection",
        ) as load_legacy:
            projection = _authoritative_person_projection(
                state,
                semantic_aggregate={
                    "aggregate_version": "population-semantic-aggregate-v2",
                },
                pseudonym_secret=b"fixture-pseudonym-secret",
                application_loader=lambda _state: (),
            )

        self.assertIsNone(projection)
        load_legacy.assert_not_called()

    def test_source_approval_hashes_block_wrong_population_before_enrichment_unlocks(self) -> None:
        from community_os.controlled_release import (
            ControlledReleaseRuntime, build_controlled_release_factory,
        )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = self._state_with_sources(root)
            bundle = _bundle()
            bundle["event_approval"]["sources"]["applications"]["source_sha256"] = "f" * 64
            bundle_path = root / "approval.json"
            bundle_path.write_text(json.dumps(bundle), encoding="utf-8")

            with self.assertRaisesRegex(PermissionError, "source for applications"):
                build_controlled_release_factory(ControlledReleaseRuntime(
                    approval_bundle=bundle_path,
                    pseudonym_secret=b"fixture-pseudonym-secret",
                    event_definition=_event_definition(), clock=lambda: NOW,
                ))(state)

    def test_successful_controlled_cleanup_updates_operator_privacy_status(self) -> None:
        from community_os.controlled_release import ControlledReleaseRuntime, build_controlled_release_factory

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = self._state_with_sources(root)
            bundle_path = root / "approval.json"
            bundle_path.write_text(json.dumps(_bundle()), encoding="utf-8")
            operations = build_controlled_release_factory(ControlledReleaseRuntime(
                approval_bundle=bundle_path,
                pseudonym_secret=b"fixture-pseudonym-secret",
                event_definition=_event_definition(), clock=lambda: NOW,
            ))(state)

            operations["privacy_cleanup"]()

            self.assertEqual(
                state.snapshot()["privacy_operations"]["retention_cleanup"], "complete",
            )

    def test_semantic_stage_stays_locked_without_processor_approval_or_api_key(self) -> None:
        from community_os.controlled_release import ControlledReleaseRuntime, build_controlled_release_factory
        from community_os.enrichment.state import StageStatus

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = self._state_with_sources(root)
            bundle_path = root / "approval.json"
            bundle_path.write_text(json.dumps(_bundle()), encoding="utf-8")

            operations = build_controlled_release_factory(ControlledReleaseRuntime(
                approval_bundle=bundle_path,
                pseudonym_secret=b"fixture-pseudonym-secret",
                event_definition=_event_definition(), clock=lambda: NOW,
            ))(state)

            self.assertIn("classification", operations)
            self.assertEqual(state.pipeline.stage("classification").status, StageStatus.LOCKED)

    def test_semantic_stage_unlocks_only_with_bound_processor_approval_and_managed_api_key(self) -> None:
        from community_os.controlled_release import ControlledReleaseRuntime, build_controlled_release_factory
        from community_os.enrichment.state import StageStatus

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = self._state_with_sources(root)
            bundle = _bundle()
            bundle["semantic_processor"] = _semantic_processor()
            bundle_path = root / "approval.json"
            bundle_path.write_text(json.dumps(bundle), encoding="utf-8")

            build_controlled_release_factory(ControlledReleaseRuntime(
                approval_bundle=bundle_path,
                pseudonym_secret=b"fixture-pseudonym-secret",
                event_definition=_event_definition(),
                openai_api_key="fixture-key-not-secret", clock=lambda: NOW,
            ))(state)

            self.assertEqual(state.pipeline.stage("classification").status, StageStatus.ALLOWED)

    def test_semantic_stage_accepts_sol_low_or_medium_with_explicit_global_default_retention_approval(self) -> None:
        from community_os.controlled_release import ControlledReleaseRuntime, build_controlled_release_factory
        from community_os.enrichment.state import StageStatus

        for effort in ("low", "medium"):
            with self.subTest(effort=effort), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                state = self._state_with_sources(root)
                bundle = _bundle()
                processor = _semantic_processor()
                processor.update({
                    "region": "global",
                    "retention_mode": "default_abuse_monitoring_30d",
                    "security_profile": "project_scoped_store_false_minimized_v1",
                })
                bundle["semantic_processor"] = processor
                bundle_path = root / "approval.json"
                bundle_path.write_text(json.dumps(bundle), encoding="utf-8")

                build_controlled_release_factory(ControlledReleaseRuntime(
                    approval_bundle=bundle_path,
                    pseudonym_secret=b"fixture-pseudonym-secret",
                    event_definition=_event_definition(),
                    openai_api_key="fixture-key-not-secret", clock=lambda: NOW,
                    openai_model="gpt-5.6-sol", openai_reasoning_effort=effort,
                    openai_input_cost_per_million_usd_micros=5_000_000,
                    openai_output_cost_per_million_usd_micros=30_000_000,
                ))(state)

                self.assertEqual(
                    state.pipeline.stage("classification").status,
                    StageStatus.ALLOWED,
                )

    def test_global_rich_runtime_requires_sol_low_or_medium_and_explicit_pricing(self) -> None:
        from community_os.controlled_release import (
            ControlledReleaseRuntime, build_controlled_release_factory,
        )

        cases = (
            ({
                "openai_model": "gpt-5.6-sol",
                "openai_reasoning_effort": "medium",
            }, "pricing"),
            ({
                "openai_model": "gpt-5.6-terra",
                "openai_reasoning_effort": "medium",
                "openai_input_cost_per_million_usd_micros": 5_000_000,
                "openai_output_cost_per_million_usd_micros": 30_000_000,
            }, "gpt-5.6-sol.*low or medium"),
            ({
                "openai_model": "gpt-5.6-sol",
                "openai_reasoning_effort": "none",
                "openai_input_cost_per_million_usd_micros": 5_000_000,
                "openai_output_cost_per_million_usd_micros": 30_000_000,
            }, "gpt-5.6-sol.*low or medium"),
            ({
                "openai_model": "gpt-5.6-sol",
                "openai_reasoning_effort": "high",
                "openai_input_cost_per_million_usd_micros": 5_000_000,
                "openai_output_cost_per_million_usd_micros": 30_000_000,
            }, "gpt-5.6-sol.*low or medium"),
        )
        for runtime_overrides, message in cases:
            with self.subTest(message=message), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                state = self._state_with_sources(root)
                bundle = _bundle()
                processor = _semantic_processor()
                processor.update({
                    "region": "global",
                    "retention_mode": "default_abuse_monitoring_30d",
                    "security_profile": "project_scoped_store_false_minimized_v1",
                })
                bundle["semantic_processor"] = processor
                bundle_path = root / "approval.json"
                bundle_path.write_text(json.dumps(bundle), encoding="utf-8")

                with self.assertRaisesRegex(PermissionError, message):
                    build_controlled_release_factory(ControlledReleaseRuntime(
                        approval_bundle=bundle_path,
                        pseudonym_secret=b"fixture-pseudonym-secret",
                        event_definition=_event_definition(),
                        openai_api_key="fixture-key-not-secret", clock=lambda: NOW,
                        **runtime_overrides,
                    ))(state)
                self.assertNotEqual(
                    state.pipeline.stage("classification").status.value,
                    "allowed",
                )

    def test_rich_provider_uses_pinned_runtime_model_effort_global_and_store_false(self) -> None:
        from community_os.controlled_release import (
            ControlledReleaseRuntime, _build_rich_semantic_provider,
        )

        captured: dict[str, object] = {}

        def provider_stub(**kwargs):
            captured.update(kwargs)
            return SimpleNamespace(
                model=kwargs["model"], reasoning_effort=kwargs["reasoning_effort"],
                region=kwargs["region"], store=False,
            )

        runtime = ControlledReleaseRuntime(
            approval_bundle=Path("approval.json"),
            pseudonym_secret=b"fixture-pseudonym-secret",
            event_definition=_event_definition(),
            openai_api_key="fixture-key-not-secret", clock=lambda: NOW,
            openai_model="gpt-5.6-sol", openai_reasoning_effort="high",
        )
        with patch(
            "community_os.controlled_release.OpenAIRichSemanticAssessmentProvider",
            side_effect=provider_stub,
        ):
            provider = _build_rich_semantic_provider(runtime, ("Private Person",))

        self.assertEqual(provider.model, "gpt-5.6-sol")
        self.assertEqual(provider.reasoning_effort, "high")
        self.assertEqual(provider.region, "global")
        self.assertFalse(provider.store)
        self.assertEqual(captured["known_identity_literals"], ("Private Person",))
        self.assertEqual(captured["transport"].host, "api.openai.com")

    def test_global_factory_wraps_legacy_classification_and_collects_rich_github_evidence(self) -> None:
        from community_os.controlled_release import (
            ControlledReleaseRuntime, build_controlled_release_factory,
        )
        from community_os.release_operations import ReconciliationInputs

        captured: dict[str, object] = {"adapters": {}, "rich": {}}
        legacy = lambda: [{"legacy": True}]
        rich = lambda: [{"legacy": True}]
        canary = lambda: [{"canary_subject_count": 5, "state": "complete"}]

        def adapter_builder(*_args, **kwargs):
            captured["adapters"][kwargs["stage"]] = kwargs["adapter_factory"]
            return lambda: []

        def rich_builder(*_args, **kwargs):
            captured["rich"][kwargs["run_mode"]] = kwargs
            return canary if kwargs["run_mode"] == "canary" else rich

        class RegistryStub:
            def __init__(self, services):
                self.services = services

            def callbacks(self):
                return dict(self.services)

            def nonpersisting_callback(self, stage, service):
                if stage != "classification":
                    raise AssertionError("canary must use classification barriers")
                return service

        application = {
            "external_id": "app-1", "name": "Private Person",
            "email": "private@example.org", "github": "private-handle",
        }
        reconciliation = ReconciliationInputs(
            applications=(application,), preference_records=(), submission_records=(),
            preferences={}, projects={},
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            career_root = root / "coresignal-career-evaluation"
            career_loader = lambda _subjects: {}
            state = self._state_with_sources(root)
            bundle = _bundle()
            processor = _semantic_processor()
            processor.update({
                "region": "global",
                "retention_mode": "default_abuse_monitoring_30d",
                "security_profile": "project_scoped_store_false_minimized_v1",
            })
            bundle["semantic_processor"] = processor
            bundle_path = root / "approval.json"
            bundle_path.write_text(json.dumps(bundle), encoding="utf-8")
            with (
                patch(
                    "community_os.controlled_release.build_local_classification_service",
                    return_value=legacy,
                ) as local_builder,
                patch(
                    "community_os.controlled_release.build_rich_semantic_proposal_service",
                    side_effect=rich_builder,
                ),
                patch(
                    "community_os.controlled_release.build_adapter_service",
                    side_effect=adapter_builder,
                ),
                patch(
                    "community_os.controlled_release.ProductionOperationRegistry.from_operator_state",
                    side_effect=lambda _state, **kwargs: RegistryStub(kwargs["services"]),
                ),
                patch(
                    "community_os.release_operations._load_applications",
                    return_value=(application,),
                ),
                patch(
                    "community_os.release_operations._load_reconciliation_inputs",
                    return_value=reconciliation,
                ),
                patch(
                    "community_os.controlled_release.CoresignalCareerEvaluationStore",
                    return_value=SimpleNamespace(
                        load_internal_semantic_evidence=career_loader,
                    ),
                ) as career_store,
            ):
                operations = build_controlled_release_factory(ControlledReleaseRuntime(
                    approval_bundle=bundle_path,
                    pseudonym_secret=b"fixture-pseudonym-secret",
                    event_definition=_event_definition(),
                    github_token="fixture-github-token",
                    openai_api_key="fixture-key-not-secret", clock=lambda: NOW,
                    openai_model="gpt-5.6-sol",
                    openai_reasoning_effort="medium",
                    openai_input_cost_per_million_usd_micros=5_000_000,
                    openai_output_cost_per_million_usd_micros=30_000_000,
                    transport_factory=lambda: object(),
                    coresignal_career_evaluation_root=career_root,
                ))(state)
                github_adapter = captured["adapters"]["github"](lambda _value: True)

                disabled_root = root / "disabled"
                disabled_state = self._state_with_sources(disabled_root)
                disabled_bundle = _bundle()
                disabled_bundle["semantic_processor"] = None
                disabled_bundle_path = disabled_root / "approval.json"
                disabled_bundle_path.write_text(
                    json.dumps(disabled_bundle), encoding="utf-8",
                )
                build_controlled_release_factory(ControlledReleaseRuntime(
                    approval_bundle=disabled_bundle_path,
                    pseudonym_secret=b"fixture-pseudonym-secret",
                    event_definition=_event_definition(),
                    github_token="fixture-github-token", clock=lambda: NOW,
                    transport_factory=lambda: object(),
                ))(disabled_state)
                disabled_github_adapter = captured["adapters"]["github"](
                    lambda _value: True,
                )

            self.assertIs(operations["classification"], rich)
            self.assertIs(operations["classification_canary"], canary)
            full = captured["rich"]["full"]
            bounded_canary = captured["rich"]["canary"]
            self.assertIs(full["base_classification"], legacy)
            self.assertIs(full["career_evidence_loader"], career_loader)
            self.assertEqual(bounded_canary["run_model"], "gpt-5.6-sol")
            self.assertEqual(bounded_canary["run_reasoning_effort"], "medium")
            self.assertEqual(bounded_canary["run_max_concurrency"], 72)
            self.assertEqual(full["run_max_concurrency"], 72)
            self.assertEqual(
                bounded_canary["input_cost_per_million_usd_micros"], 5_000_000,
            )
            self.assertEqual(
                full["output_cost_per_million_usd_micros"], 30_000_000,
            )
            career_store.assert_called_once_with(
                career_root,
                release_root=state.root / "protected" / "release",
                clock=ANY,
            )
            self.assertIsNone(local_builder.call_args.kwargs["semantic_classifier"])
            self.assertTrue(github_adapter.collect_rich_evidence)
            self.assertFalse(disabled_github_adapter.collect_rich_evidence)
            self.assertIn("Private Person", github_adapter.identity_literals)
            self.assertIn("private@example.org", github_adapter.identity_literals)
            from community_os.enrichment.state import pseudonymous_id

            github_subject = pseudonymous_id(
                "app-1", secret=b"fixture-pseudonym-secret", key_version="v1",
            )
            self.assertEqual(
                set(github_adapter.subject_identity_literals),
                {github_subject},
            )
            self.assertIn(
                "private-handle",
                github_adapter.subject_identity_literals[github_subject],
            )
            self.assertIn(
                "private",
                tuple(
                    value.casefold()
                    for value in github_adapter.subject_identity_literals[
                        github_subject
                    ]
                ),
            )

            identity_corpus = ("Private Person", "private@example.org")
            provider_events: list[str] = []
            provider_sentinel = object()
            with (
                patch.object(
                    state.rich_semantic_reviews,
                    "configure_identity_corpus",
                    side_effect=lambda _corpus: provider_events.append("configure"),
                ) as configure_corpus,
                patch(
                    "community_os.controlled_release._build_rich_semantic_provider",
                    side_effect=lambda _runtime, _corpus: (
                        provider_events.append("provider") or provider_sentinel
                    ),
                ) as build_provider,
            ):
                provider = full["provider_factory"](identity_corpus)

            self.assertIs(provider, provider_sentinel)
            self.assertEqual(provider_events, ["provider"])
            configure_corpus.assert_not_called()
            self.assertEqual(build_provider.call_args.args[1], identity_corpus)

    def test_internal_rich_aggregate_is_private_and_only_written_after_all_reviews_resolve(self) -> None:
        from community_os.controlled_release import persist_internal_rich_semantic_aggregate
        from tests.test_partner_semantic_projection import population_aggregate
        from tests.test_rich_semantic_review import population_context

        aggregate = population_aggregate()
        expected_subjects = tuple(
            f"case:v1:{ordinal:064x}" for ordinal in range(1, 7)
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            open_case = SimpleNamespace(
                version="rich_semantic_review_v1", status="open", case_code="case_open",
            )
            state = SimpleNamespace(
                root=root,
                review_repository=SimpleNamespace(list=lambda **_kwargs: (open_case,)),
                rich_semantic_reviews=SimpleNamespace(
                    finalized_case_codes=lambda: frozenset(),
                    build_population_aggregate=lambda **_kwargs: aggregate,
                ),
            )
            with self.assertRaisesRegex(PermissionError, "review remains open"):
                persist_internal_rich_semantic_aggregate(
                    state,
                    expected_subject_refs=expected_subjects,
                    binding_context=population_context(),
                    generated_at=NOW,
                )
            path = root / "protected" / "rich-semantic-internal.aggregate.json"
            self.assertFalse(path.exists())

            resolved = SimpleNamespace(
                version="rich_semantic_review_v1", status="resolved", case_code="case_done",
            )
            state.review_repository = SimpleNamespace(list=lambda **_kwargs: (resolved,))
            state.rich_semantic_reviews = SimpleNamespace(
                finalized_case_codes=lambda: frozenset({"case_done"}),
                build_population_aggregate=lambda **kwargs: (
                    setattr(state, "aggregate_arguments", kwargs) or aggregate
                ),
            )
            result = persist_internal_rich_semantic_aggregate(
                state,
                expected_subject_refs=expected_subjects,
                binding_context=population_context(),
                generated_at=NOW,
                minimum_group_size=7,
            )

            self.assertEqual(result, aggregate)
            self.assertEqual(result["aggregate_version"], "population-semantic-aggregate-v2")
            self.assertEqual(state.aggregate_arguments["minimum_group_size"], 7)
            self.assertEqual(json.loads(path.read_text()), aggregate)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_internal_cohort_bundle_is_separate_private_and_keeps_approved_all_aggregate(self) -> None:
        from copy import deepcopy
        from community_os.controlled_release import (
            persist_internal_rich_semantic_aggregate,
        )
        from tests.test_partner_semantic_projection import population_aggregate
        from tests.test_rich_semantic_review import population_context

        legacy = population_aggregate()
        accepted = deepcopy(legacy)
        attended = deepcopy(legacy)
        for aggregate, key, total in (
            (accepted, "accepted_participants", 83),
            (attended, "confirmed_attendees", 78),
        ):
            aggregate["bindings"]["population_key"] = key
            aggregate["population"]["population_key"] = key
            aggregate["population"]["total_count"] = total
        generated_bundle = {
            "all": deepcopy(legacy),
            "accepted": accepted,
            "attended": attended,
        }
        expected_subjects = tuple(
            f"case:v1:{ordinal:064x}" for ordinal in range(1, 7)
        )
        membership = {
            subject: {
                "applied": "member",
                "accepted": "member",
                "present": "member",
            }
            for subject in expected_subjects
        }

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            resolved = SimpleNamespace(
                version="rich_semantic_review_v1",
                status="resolved",
                case_code="case_done",
            )
            calls = []

            def build_population_aggregate(**kwargs):
                calls.append(kwargs)
                return generated_bundle if "membership_by_subject" in kwargs else legacy

            state = SimpleNamespace(
                root=root,
                review_repository=SimpleNamespace(list=lambda **_kwargs: (resolved,)),
                rich_semantic_reviews=SimpleNamespace(
                    finalized_case_codes=lambda: frozenset({"case_done"}),
                    build_population_aggregate=build_population_aggregate,
                ),
            )

            result = persist_internal_rich_semantic_aggregate(
                state,
                expected_subject_refs=expected_subjects,
                binding_context=population_context(),
                generated_at=NOW,
                membership_by_subject=membership,
            )

            cohort_path = (
                root / "protected" /
                "rich-semantic-internal.cohorts.aggregate.json"
            )
            stored = json.loads(cohort_path.read_text(encoding="utf-8"))
            cohort_mode = cohort_path.stat().st_mode & 0o777

        self.assertEqual(result, legacy)
        self.assertEqual(len(calls), 2)
        self.assertNotIn("membership_by_subject", calls[0])
        self.assertEqual(calls[1]["membership_by_subject"], membership)
        self.assertEqual(stored["all"], legacy)
        self.assertEqual(stored["accepted"]["population"]["total_count"], 83)
        self.assertEqual(stored["attended"]["population"]["total_count"], 78)
        self.assertEqual(cohort_mode, 0o600)

    def test_internal_rich_aggregate_removes_stale_projection_when_no_current_cases_exist(self) -> None:
        from community_os.controlled_release import persist_internal_rich_semantic_aggregate

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "protected" / "rich-semantic-internal.aggregate.json"
            path.parent.mkdir(parents=True)
            path.write_text('{"stale":true}', encoding="utf-8")
            state = SimpleNamespace(
                root=root,
                review_repository=SimpleNamespace(list=lambda **_kwargs: ()),
            )

            result = persist_internal_rich_semantic_aggregate(state)

            self.assertIsNone(result)
            self.assertFalse(path.exists())

    def test_privacy_plan_reports_the_enforced_stage_retention_deadlines(self) -> None:
        from community_os.controlled_release import ControlledReleaseRuntime, build_controlled_release_factory

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = self._state_with_sources(root)
            bundle_path = root / "approval.json"
            bundle_path.write_text(json.dumps(_bundle()), encoding="utf-8")

            build_controlled_release_factory(ControlledReleaseRuntime(
                approval_bundle=bundle_path,
                pseudonym_secret=b"fixture-pseudonym-secret",
                event_definition=_event_definition(), clock=lambda: NOW,
            ))(state)

            privacy = json.loads(
                (state.root / "protected" / "privacy-operations.json").read_text(
                    encoding="utf-8",
                )
            )
            deadlines = {
                item["source"]: item["retention_deadline"]
                for item in privacy["inventory"]
            }
            self.assertEqual(
                deadlines["github"], (NOW + timedelta(days=30)).isoformat(),
            )
            self.assertEqual(
                deadlines["public_pages"], (NOW + timedelta(days=14)).isoformat(),
            )
            self.assertEqual(
                deadlines["classification"], (NOW + timedelta(days=30)).isoformat(),
            )

    def test_completed_stage_replaces_planned_retention_with_persisted_expiry(self) -> None:
        from community_os.controlled_release import ControlledReleaseRuntime, build_controlled_release_factory

        captured: dict[str, object] = {}

        class RegistryStub:
            def callbacks(self):
                return {
                    stage: (lambda: [])
                    for stage in (
                        "privacy_cleanup", "reconcile", "github", "public_pages",
                        "coresignal", "classification", "aggregate", "report", "publish",
                    )
                }

        def capture_registry(*args, **kwargs):
            captured.update(kwargs)
            return RegistryStub()

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = self._state_with_sources(root)
            bundle_path = root / "approval.json"
            bundle_path.write_text(json.dumps(_bundle()), encoding="utf-8")
            with patch(
                "community_os.controlled_release.ProductionOperationRegistry.from_operator_state",
                side_effect=capture_registry,
            ):
                build_controlled_release_factory(ControlledReleaseRuntime(
                    approval_bundle=bundle_path,
                    pseudonym_secret=b"fixture-pseudonym-secret",
                    event_definition=_event_definition(), clock=lambda: NOW,
                ))(state)

            actual_expiry = NOW + timedelta(days=19)
            persister = captured["retention_persister"]
            self.assertTrue(callable(persister))
            persister("public_pages", actual_expiry)  # type: ignore[operator]

            privacy = json.loads(
                (state.root / "protected" / "privacy-operations.json").read_text(
                    encoding="utf-8",
                )
            )
            deadline = next(
                item["retention_deadline"] for item in privacy["inventory"]
                if item["source"] == "public_pages"
            )
            self.assertEqual(deadline, actual_expiry.isoformat())

    @staticmethod
    def _state_with_sources(root: Path):
        from community_os.release_operator import ReleaseOperatorState, ReleaseSourceSlot

        state = ReleaseOperatorState(root / "operator", operator_code="privacy_lead", event_definition=_event_definition())
        for slot in ReleaseSourceSlot:
            suffix = ".csv" if slot.value in {"applications", "attendance"} else ".xlsx"
            path = state.protected_uploads / (slot.value + suffix)
            path.write_bytes(slot.value.encode())
            state.record_source(
                slot, sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                row_count=1, filename=path.name,
            )
        return state

    def test_lazy_factory_builds_all_callbacks_records_public_gates_and_makes_no_calls(self) -> None:
        from community_os.controlled_release import ControlledReleaseRuntime, build_controlled_release_factory
        from community_os.enrichment.state import StageStatus
        from community_os.release_operator import ReleaseOperatorState, ReleaseSourceSlot

        calls: list[object] = []
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle_path = root / "approval.json"
            bundle_path.write_text(json.dumps(_bundle()), encoding="utf-8")
            state = ReleaseOperatorState(root / "operator", operator_code="privacy_lead", event_definition=_event_definition())
            for slot in ReleaseSourceSlot:
                path = state.protected_uploads / (slot.value + (".csv" if slot.value in {"applications", "attendance"} else ".xlsx"))
                path.write_bytes(slot.value.encode())
                state.record_source(
                    slot, sha256=__import__("hashlib").sha256(path.read_bytes()).hexdigest(),
                    row_count=1, filename=path.name,
                )
            factory = build_controlled_release_factory(ControlledReleaseRuntime(
                approval_bundle=bundle_path,
                pseudonym_secret=b"fixture-pseudonym-secret",
                event_definition=_event_definition(),
                transport_factory=lambda: calls.append("transport") or object(),
                clock=lambda: NOW,
                sleeper=lambda _seconds: calls.append("sleep"),
            ))
            operations = factory(state)
        self.assertEqual(set(operations), {
            "privacy_cleanup", "reconcile", "github", "public_pages", "coresignal",
            "classification", "aggregate", "report", "publish", "withdraw_publication",
        })
        self.assertEqual(calls, [])
        self.assertEqual(state.pipeline.stage("github").status, StageStatus.ALLOWED)
        self.assertEqual(state.pipeline.stage("public_pages").status, StageStatus.ALLOWED)
        self.assertEqual(state.pipeline.stage("coresignal").status, StageStatus.LOCKED)

    def test_public_pages_can_be_explicitly_disabled_without_creating_a_transport(self) -> None:
        from community_os.controlled_release import (
            ControlledReleaseRuntime,
            build_controlled_release_factory,
        )
        from community_os.enrichment.state import StageStatus

        calls: list[str] = []
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = self._state_with_sources(root)
            bundle = _bundle()
            bundle["public_sources"]["public_pages"] = None
            bundle_path = root / "approval.json"
            bundle_path.write_text(json.dumps(bundle), encoding="utf-8")
            factory = build_controlled_release_factory(ControlledReleaseRuntime(
                approval_bundle=bundle_path,
                pseudonym_secret=b"fixture-pseudonym-secret",
                event_definition=_event_definition(),
                transport_factory=lambda: calls.append("transport") or object(),
                clock=lambda: NOW,
            ))

            operations = factory(state)

            self.assertEqual(factory.disabled_optional_stages, ("public_pages",))
            self.assertEqual(calls, [])
            self.assertEqual(state.pipeline.stage("github").status, StageStatus.ALLOWED)
            self.assertEqual(
                state.pipeline.stage("public_pages").status, StageStatus.LOCKED,
            )
            with self.assertRaisesRegex(
                PermissionError, "public-page enrichment is disabled",
            ):
                operations["public_pages"]()
            self.assertEqual(calls, [])

    def test_disabled_public_pages_privacy_inventory_has_no_processing_resource(self) -> None:
        from community_os.controlled_release import (
            ControlledReleaseRuntime,
            build_controlled_release_factory,
        )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = self._state_with_sources(root)
            bundle = _bundle()
            bundle["public_sources"]["public_pages"] = None
            bundle_path = root / "approval.json"
            bundle_path.write_text(json.dumps(bundle), encoding="utf-8")

            build_controlled_release_factory(ControlledReleaseRuntime(
                approval_bundle=bundle_path,
                pseudonym_secret=b"fixture-pseudonym-secret",
                event_definition=_event_definition(),
                clock=lambda: NOW,
            ))(state)

            privacy = json.loads(
                (state.root / "protected" / "privacy-operations.json").read_text(
                    encoding="utf-8",
                )
            )
            public_pages = next(
                item for item in privacy["inventory"]
                if item["source"] == "public_pages"
            )
            self.assertEqual(public_pages.get("state"), "disabled")
            self.assertEqual(public_pages["allowed_uses"], [])
            self.assertIsNone(public_pages["resource_ref"])
            self.assertIsNone(public_pages["retention_deadline"])
            self.assertEqual(public_pages["storage_scope"], "none")

    def test_optional_stage_policy_and_operations_use_one_approval_bundle_snapshot(self) -> None:
        from community_os.controlled_release import (
            ControlledReleaseRuntime,
            build_controlled_release_factory,
        )
        from community_os.enrichment.state import StageStatus

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = self._state_with_sources(root)
            enabled = _bundle()
            disabled = json.loads(json.dumps(enabled))
            disabled["public_sources"]["public_pages"] = None
            factory = build_controlled_release_factory(ControlledReleaseRuntime(
                approval_bundle=root / "approval.json",
                pseudonym_secret=b"fixture-pseudonym-secret",
                event_definition=_event_definition(),
                clock=lambda: NOW,
            ))

            with patch(
                "community_os.controlled_release._load_bundle",
                side_effect=(enabled, disabled),
            ) as load_bundle:
                factory(state)

            self.assertEqual(load_bundle.call_count, 1)
            self.assertEqual(factory.disabled_optional_stages, ())
            self.assertEqual(
                state.pipeline.stage("public_pages").status,
                StageStatus.ALLOWED,
            )

    def test_optional_stage_policy_is_explicitly_unbound_before_validation(self) -> None:
        from community_os.controlled_release import (
            ControlledReleaseRuntime,
            build_controlled_release_factory,
        )

        with tempfile.TemporaryDirectory() as directory:
            factory = build_controlled_release_factory(ControlledReleaseRuntime(
                approval_bundle=Path(directory) / "missing-approval.json",
                pseudonym_secret=b"fixture-pseudonym-secret",
                event_definition=_event_definition(),
                clock=lambda: NOW,
            ))

            self.assertIsNone(factory.disabled_optional_stages)

    def test_invalid_bundle_cannot_bind_optional_stage_policy(self) -> None:
        from community_os.controlled_release import (
            ControlledReleaseRuntime,
            build_controlled_release_factory,
        )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = self._state_with_sources(root)
            bundle_path = root / "approval.json"
            invalid = _bundle()
            invalid["public_sources"]["public_pages"] = None
            invalid["privacy_operations"]["rights"]["objection_status"] = "requested"
            bundle_path.write_text(json.dumps(invalid), encoding="utf-8")
            factory = build_controlled_release_factory(ControlledReleaseRuntime(
                approval_bundle=bundle_path,
                pseudonym_secret=b"fixture-pseudonym-secret",
                event_definition=_event_definition(),
                clock=lambda: NOW,
            ))

            with self.assertRaisesRegex(PermissionError, "rights are unresolved"):
                factory(state)
            self.assertIsNone(factory.disabled_optional_stages)

            bundle_path.write_text(json.dumps(_bundle()), encoding="utf-8")
            factory(state)

            self.assertEqual(factory.disabled_optional_stages, ())

    def test_github_public_source_gate_cannot_be_disabled(self) -> None:
        from community_os.controlled_release import (
            ControlledReleaseRuntime,
            build_controlled_release_factory,
        )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = self._state_with_sources(root)
            bundle = _bundle()
            bundle["public_sources"]["github"] = None
            bundle_path = root / "approval.json"
            bundle_path.write_text(json.dumps(bundle), encoding="utf-8")

            with self.assertRaisesRegex(
                PermissionError, "GitHub public-source approval is required",
            ):
                build_controlled_release_factory(ControlledReleaseRuntime(
                    approval_bundle=bundle_path,
                    pseudonym_secret=b"fixture-pseudonym-secret",
                    event_definition=_event_definition(),
                    clock=lambda: NOW,
                ))(state)

    def test_current_report_bundle_replaces_stale_html_and_pdf_from_aggregates(self) -> None:
        from community_os.controlled_release import render_current_report_bundle
        from tests.test_partner_semantic_projection import semantic_aggregate

        with tempfile.TemporaryDirectory() as directory:
            release = Path(directory)
            (release / "talent-intelligence-v1.real.aggregate.json").write_text(
                "{}", encoding="utf-8",
            )
            (release / "talent-report-v3.real.aggregate.json").write_text(
                "{}", encoding="utf-8",
            )
            html = release / "talent-brief.real.html"
            pdf = release / "talent-brief.real.pdf"
            html.write_text("stale-html", encoding="utf-8")
            pdf.write_text("stale-pdf", encoding="utf-8")
            expected = (
                html,
                pdf,
                release / "talent-intelligence-v1.real.aggregate.json",
                release / "talent-report-v3.real.aggregate.json",
            )
            manifest_path = release / "talent-report-v3.real.manifest.json"
            stale_code_provenance = {
                "version": "code-provenance-v1",
                "git_sha": "a" * 40,
                "python_source_sha256": "b" * 64,
                "python_file_count": 1,
            }
            fresh_code_provenance = {
                "version": "code-provenance-v1",
                "git_sha": "c" * 40,
                "python_source_sha256": "d" * 64,
                "python_file_count": 73,
            }
            manifest_path.write_text(json.dumps({
                "aggregates": {"applied": 286, "going_accepted": 83, "on_site": 78},
                "release_context": {"code_provenance": stale_code_provenance},
                "output_hashes": {
                    path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                    for path in expected
                },
            }), encoding="utf-8")
            report = SimpleNamespace(
                metadata=SimpleNamespace(generated_at="2026-07-14T00:00:00Z"),
            )
            semantic_path = release / "rich-semantic-internal.aggregate.json"
            semantic_path.write_text(
                json.dumps(semantic_aggregate(), sort_keys=True), encoding="utf-8",
            )
            from community_os.partner_report_presentation import (
                build_default_partner_report_presentation,
                write_partner_report_presentation,
            )
            from community_os.partner_semantic_projection import (
                build_protected_partner_semantic_candidate_summary,
            )

            stale_aggregate = semantic_aggregate()
            stale_aggregate["metrics"]["standout_builder"] = 6
            stale_summary = build_protected_partner_semantic_candidate_summary(
                stale_aggregate,
            )
            stale_presentation = build_default_partner_report_presentation(
                stale_summary,
            )
            write_partner_report_presentation(
                release / "partner-report-presentation.json",
                stale_presentation,
                semantic_summary=stale_summary,
            )

            def write_pdf(_html, target, *, stable_timestamp):
                self.assertEqual(stable_timestamp, "2026-07-14T00:00:00Z")
                Path(target).write_bytes(b"%PDF-fresh\n%%EOF")

            with (
                patch(
                    "community_os.talent_intelligence_contract.load_talent_intelligence_contract",
                    return_value=report,
                ),
                patch(
                    "community_os.report_contract.load_report_contract",
                    return_value=object(),
                ),
                patch(
                    "community_os.partner_report.render_partner_talent_report",
                    return_value="<html>fresh-report</html>",
                ) as render,
                patch(
                    "community_os.real_report._code_provenance",
                    return_value=fresh_code_provenance,
                ),
                patch("community_os.pdf_export.export_pdf", side_effect=write_pdf),
                patch(
                    "community_os.publication._pdf_text",
                    return_value="fresh report aggregate only",
                ),
            ):
                records = render_current_report_bundle(
                    release, semantic_aggregate_path=semantic_path,
                )

            self.assertEqual(html.read_text(encoding="utf-8"), "<html>fresh-report</html>")
            self.assertEqual(pdf.read_bytes(), b"%PDF-fresh\n%%EOF")
            self.assertEqual(records[0]["state"], "complete")
            summary = render.call_args.kwargs["semantic_summary"]
            presentation = render.call_args.kwargs["presentation"]
            self.assertEqual(summary.reviewed_denominator, 195)
            self.assertEqual(presentation.aggregate_sha256, summary.aggregate_sha256)
            presentation_path = release / "partner-report-presentation.json"
            self.assertTrue(presentation_path.is_file())
            self.assertEqual(presentation_path.stat().st_mode & 0o777, 0o600)
            guide = release / "reproduce-real-report.md"
            self.assertIn(
                '--semantic-aggregate "$SEMANTIC_AGGREGATE"',
                guide.read_text(encoding="utf-8"),
            )
            self.assertEqual(
                set(records[0]["artifact_hashes"]),
                {
                    "talent-brief.real.html", "talent-brief.real.pdf",
                    "talent-intelligence-v1.real.aggregate.json",
                    "talent-report-v3.real.aggregate.json",
                },
            )
            share = release / "partner-share"
            self.assertFalse(
                share.exists(),
                "an unapproved semantic candidate must remain preview-only",
            )
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            self.assertEqual(
                manifest["output_hashes"],
                {
                    path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                    for path in (*expected, guide)
                },
            )
            from community_os.partner_semantic_projection import (
                semantic_summary_manifest_binding,
            )

            self.assertEqual(
                manifest["semantic_enrichment"],
                semantic_summary_manifest_binding(summary),
            )
            from community_os.partner_report_presentation import (
                partner_report_presentation_sha256,
            )

            self.assertEqual(
                manifest["partner_presentation"],
                {
                    "aggregate_sha256": summary.aggregate_sha256,
                    "presentation_sha256": partner_report_presentation_sha256(
                        presentation,
                    ),
                    "version": "partner-report-presentation-v1",
                },
            )
            self.assertEqual(
                manifest["release_context"]["code_provenance"],
                fresh_code_provenance,
            )

    def test_current_report_without_semantic_approval_remains_local_preview_only(self) -> None:
        from community_os.controlled_release import render_current_report_bundle

        with tempfile.TemporaryDirectory() as directory:
            release = Path(directory)
            v1 = release / "talent-intelligence-v1.real.aggregate.json"
            v3 = release / "talent-report-v3.real.aggregate.json"
            v1.write_text("{}", encoding="utf-8")
            v3.write_text("{}", encoding="utf-8")
            (release / "talent-report-v3.real.manifest.json").write_text(
                json.dumps({"output_hashes": {}}), encoding="utf-8",
            )
            report = SimpleNamespace(
                metadata=SimpleNamespace(generated_at="2026-07-14T00:00:00Z"),
            )

            def write_pdf(_html, target, *, stable_timestamp):
                self.assertEqual(stable_timestamp, "2026-07-14T00:00:00Z")
                Path(target).write_bytes(b"%PDF-preview\n%%EOF")

            with (
                patch(
                    "community_os.talent_intelligence_contract.load_talent_intelligence_contract",
                    return_value=report,
                ),
                patch(
                    "community_os.report_contract.load_report_contract",
                    return_value=object(),
                ),
                patch(
                    "community_os.partner_report.render_partner_talent_report",
                    return_value="<html>count-only preview</html>",
                ),
                patch("community_os.pdf_export.export_pdf", side_effect=write_pdf),
                patch(
                    "community_os.publication._pdf_text",
                    return_value="count-only preview",
                ),
                patch(
                    "community_os.controlled_release.materialize_local_partner_share",
                ) as materialize,
            ):
                records = render_current_report_bundle(release)

            materialize.assert_not_called()
            self.assertIsNone(records[0]["partner_share_directory"])
            self.assertFalse((release / "partner-share").exists())

    def test_current_report_bundle_rejects_symlink_root_before_withdrawing_share(self) -> None:
        from community_os.controlled_release import render_current_report_bundle

        with tempfile.TemporaryDirectory() as directory:
            real_root = Path(directory) / "real-release"
            share = real_root / "partner-share"
            share.mkdir(parents=True)
            marker = share / "marker.txt"
            marker.write_text("must survive", encoding="utf-8")
            linked_root = Path(directory) / "linked-release"
            linked_root.symlink_to(real_root, target_is_directory=True)

            with self.assertRaisesRegex(PermissionError, "release root.*unsafe"):
                render_current_report_bundle(linked_root)

            self.assertEqual(marker.read_text(encoding="utf-8"), "must survive")

    def test_current_report_bundle_rejects_symlink_target_before_rendering(self) -> None:
        from community_os.controlled_release import render_current_report_bundle

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            release = root / "release"
            release.mkdir()
            v1 = release / "talent-intelligence-v1.real.aggregate.json"
            v3 = release / "talent-report-v3.real.aggregate.json"
            v1.write_text("{}", encoding="utf-8")
            v3.write_text("{}", encoding="utf-8")
            external = root / "external.html"
            external.write_text("external must survive", encoding="utf-8")
            (release / "talent-brief.real.html").symlink_to(external)
            (release / "talent-brief.real.pdf").write_bytes(b"%PDF-old\n%%EOF")
            (release / "talent-report-v3.real.manifest.json").write_text(
                json.dumps({"output_hashes": {}}), encoding="utf-8",
            )

            with (
                patch(
                    "community_os.talent_intelligence_contract.load_talent_intelligence_contract",
                    return_value=SimpleNamespace(
                        metadata=SimpleNamespace(generated_at="2026-07-14T00:00:00Z"),
                    ),
                ),
                patch(
                    "community_os.report_contract.load_report_contract",
                    return_value=object(),
                ),
                patch(
                    "community_os.partner_report.render_partner_talent_report",
                ) as render,
                patch("community_os.pdf_export.export_pdf") as export,
            ):
                with self.assertRaisesRegex(PermissionError, "report target.*unsafe"):
                    render_current_report_bundle(release)

            render.assert_not_called()
            export.assert_not_called()
            self.assertEqual(
                external.read_text(encoding="utf-8"), "external must survive",
            )

    def test_approved_report_regeneration_reconciles_share_and_aggregate_hashes(self) -> None:
        from community_os.controlled_release import render_current_report_bundle
        from community_os.partner_semantic_projection import (
            build_protected_partner_semantic_candidate_summary,
            semantic_summary_manifest_binding,
        )
        from community_os.publication import artifact_set_sha256
        from community_os.semantic_release_approval import (
            build_semantic_release_candidate,
            issue_semantic_release_approval,
        )
        from tests.test_partner_semantic_projection import semantic_aggregate

        approval_secret = b"controlled-report-approval-secret"
        approval_time = datetime(2026, 7, 15, 12, tzinfo=UTC)
        expected_artifacts = {
            "talent-brief.real.html": b"<html>approved-candidate</html>",
            "talent-brief.real.pdf": b"%PDF-approved\n%%EOF",
            "talent-intelligence-v1.real.aggregate.json": b"{}",
            "talent-report-v3.real.aggregate.json": b"{}",
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            release = root / "release"
            release.mkdir()
            aggregate = semantic_aggregate()
            semantic_path = root / "rich-semantic-internal.aggregate.json"
            semantic_path.write_text(json.dumps(aggregate), encoding="utf-8")
            for name in (
                "talent-intelligence-v1.real.aggregate.json",
                "talent-report-v3.real.aggregate.json",
            ):
                (release / name).write_bytes(expected_artifacts[name])

            candidate_dir = root / "candidate"
            candidate_dir.mkdir()
            candidate_paths = []
            for name, contents in expected_artifacts.items():
                path = candidate_dir / name
                path.write_bytes(contents)
                candidate_paths.append(path)
            qa_receipt = _write_semantic_release_qa(
                root, aggregate, tuple(candidate_paths),
            )
            semantic_candidate = build_semantic_release_candidate(
                aggregate,
                qa_sha256=qa_receipt.sha256,
                report_candidate_sha256=artifact_set_sha256(tuple(candidate_paths)),
                html_sha256=hashlib.sha256(
                    expected_artifacts["talent-brief.real.html"],
                ).hexdigest(),
                pdf_sha256=hashlib.sha256(
                    expected_artifacts["talent-brief.real.pdf"],
                ).hexdigest(),
            )
            approval = issue_semantic_release_approval(
                semantic_candidate,
                actor_code="colleague_0123456789abcdef0123456789abcdef",
                approved_at=approval_time,
                expires_at=approval_time + timedelta(days=1),
                signing_secret=approval_secret,
            )
            approval_path = root / "semantic-release-approval.json"
            approval_path.write_text(json.dumps(approval), encoding="utf-8")
            (release / "talent-report-v3.real.manifest.json").write_text(
                json.dumps({
                    "output_hashes": {},
                    "semantic_enrichment": semantic_summary_manifest_binding(
                        build_protected_partner_semantic_candidate_summary(aggregate),
                    ),
                }),
                encoding="utf-8",
            )

            def write_pdf(_html, target, *, stable_timestamp):
                self.assertEqual(stable_timestamp, "2026-07-14T00:00:00Z")
                Path(target).write_bytes(
                    expected_artifacts["talent-brief.real.pdf"],
                )

            with (
                patch(
                    "community_os.talent_intelligence_contract.load_talent_intelligence_contract",
                    return_value=SimpleNamespace(
                        metadata=SimpleNamespace(
                            generated_at="2026-07-14T00:00:00Z",
                        ),
                    ),
                ),
                patch(
                    "community_os.report_contract.load_report_contract",
                    return_value=object(),
                ),
                patch(
                    "community_os.partner_report.render_partner_talent_report",
                    return_value=expected_artifacts[
                        "talent-brief.real.html"
                    ].decode("utf-8"),
                ),
                patch(
                    "community_os.pdf_export.export_pdf",
                    side_effect=write_pdf,
                ),
                patch(
                    "community_os.publication._pdf_text",
                    return_value="approved report aggregate only",
                ),
            ):
                records = render_current_report_bundle(
                    release,
                    semantic_aggregate_path=semantic_path,
                    semantic_approval_path=approval_path,
                    semantic_approval_secret=approval_secret,
                    semantic_authoritative_context=(
                        _semantic_authoritative_context(aggregate)
                    ),
                    now=approval_time,
                )

            expected_hashes = {
                name: hashlib.sha256(contents).hexdigest()
                for name, contents in expected_artifacts.items()
            }
            self.assertEqual(records[0]["artifact_hashes"], expected_hashes)
            share = release / "partner-share"
            self.assertEqual(
                {
                    path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                    for path in share.iterdir()
                },
                {
                    name: expected_hashes[name]
                    for name in (
                        "talent-brief.real.html", "talent-brief.real.pdf",
                    )
                },
            )

    def test_approved_report_hash_drift_fails_before_replacing_existing_bundle(self) -> None:
        from community_os.controlled_release import render_current_report_bundle
        from community_os.partner_semantic_projection import (
            build_protected_partner_semantic_candidate_summary,
            semantic_summary_manifest_binding,
        )
        from community_os.publication import artifact_set_sha256
        from community_os.semantic_release_approval import (
            build_semantic_release_candidate,
            issue_semantic_release_approval,
        )
        from tests.test_partner_semantic_projection import semantic_aggregate

        approval_secret = b"controlled-report-approval-secret"
        approval_time = datetime(2026, 7, 15, 12, tzinfo=UTC)
        expected_html = b"<html>approved-candidate</html>"
        expected_pdf = b"%PDF-approved\n%%EOF"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            release = root / "release"
            release.mkdir()
            aggregate = semantic_aggregate()
            semantic_path = root / "rich-semantic-internal.aggregate.json"
            semantic_path.write_text(json.dumps(aggregate), encoding="utf-8")
            v1 = release / "talent-intelligence-v1.real.aggregate.json"
            v3 = release / "talent-report-v3.real.aggregate.json"
            v1.write_text("{}", encoding="utf-8")
            v3.write_text("{}", encoding="utf-8")
            html = release / "talent-brief.real.html"
            pdf = release / "talent-brief.real.pdf"
            html.write_text("existing-html", encoding="utf-8")
            pdf.write_text("existing-pdf", encoding="utf-8")
            candidate_dir = root / "candidate"
            candidate_dir.mkdir()
            candidate_paths = []
            for name, contents in (
                (v1.name, v1.read_bytes()),
                (v3.name, v3.read_bytes()),
                (html.name, expected_html),
                (pdf.name, expected_pdf),
            ):
                path = candidate_dir / name
                path.write_bytes(contents)
                candidate_paths.append(path)
            qa_receipt = _write_semantic_release_qa(
                root, aggregate, tuple(candidate_paths),
            )
            semantic_candidate = build_semantic_release_candidate(
                aggregate,
                qa_sha256=qa_receipt.sha256,
                report_candidate_sha256=artifact_set_sha256(tuple(candidate_paths)),
                html_sha256=hashlib.sha256(expected_html).hexdigest(),
                pdf_sha256=hashlib.sha256(expected_pdf).hexdigest(),
            )
            approval = issue_semantic_release_approval(
                semantic_candidate,
                actor_code="colleague_0123456789abcdef0123456789abcdef",
                approved_at=approval_time,
                expires_at=approval_time + timedelta(days=1),
                signing_secret=approval_secret,
            )
            approval_path = root / "semantic-release-approval.json"
            approval_path.write_text(json.dumps(approval), encoding="utf-8")
            manifest_path = release / "talent-report-v3.real.manifest.json"
            manifest = {
                "aggregates": {"applied": 286, "going_accepted": 83, "on_site": 78},
                "output_hashes": {},
                "semantic_enrichment": semantic_summary_manifest_binding(
                    build_protected_partner_semantic_candidate_summary(aggregate),
                ),
            }
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            before = {
                path: path.read_bytes() for path in (html, pdf, manifest_path)
            }
            report = SimpleNamespace(
                metadata=SimpleNamespace(generated_at="2026-07-14T00:00:00Z"),
            )

            def write_drifted_pdf(_html, target, *, stable_timestamp):
                self.assertEqual(stable_timestamp, "2026-07-14T00:00:00Z")
                Path(target).write_bytes(b"%PDF-drifted\n%%EOF")

            with (
                patch(
                    "community_os.talent_intelligence_contract.load_talent_intelligence_contract",
                    return_value=report,
                ),
                patch(
                    "community_os.report_contract.load_report_contract",
                    return_value=object(),
                ),
                patch(
                    "community_os.partner_report.render_partner_talent_report",
                    return_value=expected_html.decode("utf-8"),
                ),
                patch(
                    "community_os.pdf_export.export_pdf",
                    side_effect=write_drifted_pdf,
                ),
                patch(
                    "community_os.publication._pdf_text",
                    return_value="approved report aggregate only",
                ),
            ):
                with self.assertRaisesRegex(PermissionError, "artifact|candidate"):
                    render_current_report_bundle(
                        release,
                        semantic_aggregate_path=semantic_path,
                        semantic_approval_path=approval_path,
                        semantic_approval_secret=approval_secret,
                        semantic_authoritative_context=(
                            _semantic_authoritative_context(aggregate)
                        ),
                        now=approval_time,
                    )

            self.assertEqual(
                {path: path.read_bytes() for path in before},
                before,
            )

    def test_authenticated_operator_issues_hash_bound_semantic_approval_file(self) -> None:
        from community_os.controlled_release import (
            issue_current_semantic_release_approval,
        )
        from community_os.partner_semantic_projection import (
            build_protected_partner_semantic_candidate_summary,
            semantic_summary_manifest_binding,
        )
        from community_os.semantic_release_approval import (
            build_semantic_release_candidate,
            load_semantic_release_approval,
        )
        from community_os.publication import artifact_set_sha256
        from tests.test_partner_semantic_projection import semantic_aggregate

        secret = b"operator-issued-semantic-secret"
        approved_at = datetime(2026, 7, 15, 12, tzinfo=UTC)
        with tempfile.TemporaryDirectory() as directory:
            protected = Path(directory) / "protected"
            release = protected / "release"
            release.mkdir(parents=True)
            aggregate = semantic_aggregate()
            aggregate_path = protected / "rich-semantic-internal.aggregate.json"
            aggregate_path.write_text(json.dumps(aggregate), encoding="utf-8")
            paths = tuple(
                release / name
                for name in (
                    "talent-brief.real.html",
                    "talent-brief.real.pdf",
                    "talent-intelligence-v1.real.aggregate.json",
                    "talent-report-v3.real.aggregate.json",
                )
            )
            for index, path in enumerate(paths):
                path.write_bytes(f"artifact-{index}".encode("ascii"))
            qa_receipt = _write_semantic_release_qa(
                protected, aggregate, paths,
            )
            manifest = {
                "semantic_enrichment": semantic_summary_manifest_binding(
                    build_protected_partner_semantic_candidate_summary(aggregate),
                ),
            }
            (release / "talent-report-v3.real.manifest.json").write_text(
                json.dumps(manifest), encoding="utf-8",
            )

            with patch(
                "community_os.controlled_release."
                "regenerate_current_semantic_release_qa_for_approval",
                return_value=qa_receipt,
            ):
                result = issue_current_semantic_release_approval(
                    release,
                    state=SimpleNamespace(root=Path(directory)),
                    actor_code="colleague_0123456789abcdef0123456789abcdef",
                    signing_secret=secret,
                    now=approved_at,
                    authoritative_context=_semantic_authoritative_context(aggregate),
                )

            approval_path = protected / "semantic-release-approval.json"
            self.assertEqual(approval_path.stat().st_mode & 0o777, 0o600)
            candidate = build_semantic_release_candidate(
                aggregate,
                qa_sha256=qa_receipt.sha256,
                report_candidate_sha256=artifact_set_sha256(paths),
                html_sha256=hashlib.sha256(paths[0].read_bytes()).hexdigest(),
                pdf_sha256=hashlib.sha256(paths[1].read_bytes()).hexdigest(),
            )
            approved = load_semantic_release_approval(
                approval_path,
                candidate=candidate,
                now=approved_at,
                signing_secret=secret,
            )
            self.assertEqual(approved.approval["actor_code"], (
                "colleague_0123456789abcdef0123456789abcdef"
            ))
            self.assertEqual(result["approval_sha256"], approved.sha256)

    def test_authenticated_owner_writes_exact_hash_publication_approval_atomically(self) -> None:
        from community_os.controlled_release import (
            issue_current_publication_approval,
        )
        from community_os.publication import artifact_set_sha256

        secret = b"publication-approval-secret"
        actor = "colleague_0123456789abcdef0123456789abcdef"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            protected = root / "protected"
            release = protected / "release"
            release.mkdir(parents=True)
            html = release / "talent-brief.real.html"
            pdf = release / "talent-brief.real.pdf"
            html.write_text(
                '<a href="talent-brief.real.pdf">View PDF</a>',
                encoding="utf-8",
            )
            pdf.write_bytes(b"%PDF-publication-candidate\n%%EOF")
            bundle_path = protected / "controlled-release-approval.json"
            bundle_path.write_text(
                json.dumps(_bundle(), sort_keys=True, separators=(",", ":"))
                + "\n",
                encoding="utf-8",
            )
            bundle_path.chmod(0o600)
            victim = root / "victim.txt"
            victim.write_text("must-not-change", encoding="utf-8")
            predictable_temporary = bundle_path.with_name(bundle_path.name + ".tmp")
            predictable_temporary.symlink_to(victim)
            event_approval_sha256 = "e" * 64
            state = SimpleNamespace(
                root=root,
                snapshot=lambda: {
                    "event_approval": {"sha256": event_approval_sha256},
                },
            )

            with patch(
                "community_os.controlled_release._verified_release_artifacts",
                return_value={"applied": 286, "going_accepted": 83, "on_site": 78},
            ) as verify:
                result = issue_current_publication_approval(
                    release,
                    state=state,
                    actor_code=actor,
                    approval_bundle=bundle_path,
                    now=NOW,
                    semantic_approval_secret=secret,
                )

            stored = json.loads(bundle_path.read_text(encoding="utf-8"))
            approval = stored["publication_approval"]
            self.assertFalse(bundle_path.is_symlink())
            self.assertEqual(victim.read_text(encoding="utf-8"), "must-not-change")
            self.assertTrue(predictable_temporary.is_symlink())
            self.assertEqual(bundle_path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(approval, {
                "actor_code": actor,
                "approved_at": "2026-07-13T12:00:00Z",
                "artifact_set_sha256": artifact_set_sha256((html, pdf)),
                "event_approval_sha256": event_approval_sha256,
                "report_sha256": hashlib.sha256(html.read_bytes()).hexdigest(),
            })
            self.assertEqual(result, {
                **approval,
                "state": "complete",
            })
            verify.assert_called_once_with(
                release,
                now=NOW,
                semantic_approval_secret=secret,
                semantic_authoritative_context=None,
            )

    def test_publication_approval_validation_failure_preserves_existing_bundle(self) -> None:
        from community_os.controlled_release import (
            issue_current_publication_approval,
        )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            protected = root / "protected"
            release = protected / "release"
            release.mkdir(parents=True)
            (release / "talent-brief.real.html").write_text(
                '<a href="talent-brief.real.pdf">View PDF</a>',
                encoding="utf-8",
            )
            (release / "talent-brief.real.pdf").write_bytes(
                b"%PDF-publication-candidate\n%%EOF",
            )
            bundle_path = protected / "controlled-release-approval.json"
            original = json.dumps(
                _bundle(), sort_keys=True, separators=(",", ":"),
            ) + "\n"
            bundle_path.write_text(original, encoding="utf-8")
            bundle_path.chmod(0o600)
            state = SimpleNamespace(
                root=root,
                snapshot=lambda: {"event_approval": {"sha256": "e" * 64}},
            )

            with (
                patch(
                    "community_os.controlled_release._verified_release_artifacts",
                    side_effect=PermissionError("semantic approval is stale"),
                ),
                self.assertRaisesRegex(PermissionError, "semantic approval is stale"),
            ):
                issue_current_publication_approval(
                    release,
                    state=state,
                    actor_code="colleague_0123456789abcdef0123456789abcdef",
                    approval_bundle=bundle_path,
                    now=NOW,
                    semantic_approval_secret=b"publication-approval-secret",
                )

            self.assertEqual(bundle_path.read_text(encoding="utf-8"), original)

    def test_release_evidence_uses_authoritative_rich_reviews_not_superseded_legacy_queue(self) -> None:
        from community_os.controlled_release import _authoritative_release_reviews
        from community_os.release_operations import (
            ReviewCase, ReviewDecision, ReviewRepository,
        )

        with tempfile.TemporaryDirectory() as directory:
            repository = ReviewRepository(Path(directory) / "reviews.json")
            legacy = ReviewCase.create(
                kind="classification",
                subject_code="legacy_subject",
                reason_codes=("low_confidence",),
                candidate_codes=(),
                source_hashes={"applications": "a" * 64},
                version="deterministic_rules_v1",
            )
            rich = ReviewCase.create(
                kind="classification",
                subject_code="rich_subject",
                reason_codes=("human_review_required",),
                candidate_codes=(),
                source_hashes={"evidence": "b" * 64},
                version="rich_semantic_review_v1",
            )
            repository.replace((legacy, rich))
            repository.decide(
                ReviewDecision(
                    case_code=rich.case_code,
                    case_hash=rich.case_hash,
                    action="approved",
                ),
                actor_code="colleague_0123456789abcdef0123456789abcdef",
                decided_at=NOW,
            )

            reviews = _authoritative_release_reviews(
                SimpleNamespace(review_repository=repository),
            )

            self.assertEqual(len(reviews), 1)
            self.assertTrue(reviews[0].resolved)

    def test_dashboard_state_parser_rejects_private_or_duplicated_payloads(self) -> None:
        from community_os.controlled_release import (
            _partner_dashboard_state_from_html,
        )

        valid = (
            '<script id="partner-dashboard-state" type="application/json">'
            '{"cohorts":[],"version":"partner-dashboard-v2"}</script>'
        )
        self.assertEqual(
            _partner_dashboard_state_from_html(valid)["version"],
            "partner-dashboard-v2",
        )
        private = valid.replace(
            '"cohorts":[]',
            '"cohorts":[],"subject_ref":"case:v1:' + "a" * 64 + '"',
        )
        with self.assertRaisesRegex(PermissionError, "private data"):
            _partner_dashboard_state_from_html(private)
        with self.assertRaisesRegex(PermissionError, "missing or duplicated"):
            _partner_dashboard_state_from_html(valid + valid)

    def test_dashboard_pdf_claim_parity_requires_each_cohort_metric_and_source_value(self) -> None:
        from community_os.controlled_release import (
            _assert_partner_dashboard_pdf_claims,
        )

        dashboard = {
            "version": "partner-dashboard-v2",
            "cohorts": [
                {
                    "key": "all",
                    "label": "All applicants",
                    "denominator": 15,
                    "metrics": [{
                        "key": "technical",
                        "label": "Technical evidence",
                        "count": 10,
                    }],
                    "source_coverage": [{
                        "key": "application", "label": "Application", "count": 15,
                    }],
                },
                {
                    "key": "accepted",
                    "label": "Accepted participants",
                    "denominator": 10,
                    "metrics": [{
                        "key": "technical",
                        "label": "Technical evidence",
                        "count": 7,
                    }],
                    "source_coverage": [{
                        "key": "application", "label": "Application", "count": 10,
                    }],
                },
                {
                    "key": "attended",
                    "label": "Confirmed attendees",
                    "denominator": 5,
                    "metrics": [{
                        "key": "technical",
                        "label": "Technical evidence",
                        "count": None,
                    }],
                    "source_coverage": [{
                        "key": "application", "label": "Application", "count": 5,
                    }],
                },
            ],
        }
        full_pdf_text = (
            "Technical evidence 10 of 15 All applicants "
            "7 of 10 Accepted participants Count withheld Confirmed attendees "
            "Application 15 of 15 All applicants "
            "10 of 10 Accepted participants 5 of 5 Confirmed attendees"
        )

        self.assertEqual(
            _assert_partner_dashboard_pdf_claims(dashboard, full_pdf_text),
            6,
        )
        with self.assertRaisesRegex(PermissionError, "cohort claim parity"):
            _assert_partner_dashboard_pdf_claims(
                dashboard,
                full_pdf_text.replace("7 of 10 Accepted participants", ""),
            )
        with self.assertRaisesRegex(PermissionError, "cohort claim parity"):
            _assert_partner_dashboard_pdf_claims(
                dashboard,
                full_pdf_text.replace("Technical evidence ", ""),
            )
        with self.assertRaisesRegex(PermissionError, "cohort claim parity"):
            _assert_partner_dashboard_pdf_claims(
                dashboard,
                full_pdf_text.replace("Application ", ""),
            )

    def test_pdf_heading_contract_ignores_screen_only_dashboard_headings(self) -> None:
        from community_os.controlled_release import _pdf_page_headings

        html = (
            '<main><section class="partner-dashboard"><h2>Screen only</h2></section>'
            '<section data-pdf-page="1"><h1>Printed cover</h1>'
            '<div><h2>Printed question</h2></div></section></main>'
        )
        self.assertEqual(
            _pdf_page_headings(html),
            ("printed cover", "printed question"),
        )

    def test_production_qa_is_derived_from_current_aggregate_reviews_and_artifacts(self) -> None:
        from community_os.controlled_release import (
            generate_current_semantic_release_qa,
        )
        from tests.test_partner_semantic_projection import semantic_aggregate

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            protected = root / "protected"
            release = protected / "release"
            release.mkdir(parents=True)
            aggregate = semantic_aggregate()
            (protected / "rich-semantic-internal.aggregate.json").write_text(
                json.dumps(aggregate), encoding="utf-8",
            )
            for name, payload in (
                ("talent-brief.real.html", b"<h1>Current report</h1>"),
                ("talent-brief.real.pdf", b"%PDF-current\n%%EOF"),
                ("talent-intelligence-v1.real.aggregate.json", b"{}"),
                ("talent-report-v3.real.aggregate.json", b"{}"),
            ):
                (release / name).write_bytes(payload)

            class DerivedStore:
                def build_population_aggregate(self, **kwargs):
                    self.rederive_arguments = kwargs
                    return aggregate

                def semantic_release_qa_evidence(self):
                    return {
                        "positive_claim_count": 2787,
                        "positive_claim_sample_count": 10,
                        "required_review_case_count": 9,
                        "required_review_cases_resolved": 9,
                        "positive_claims_sha256": "8" * 64,
                        "review_evidence_sha256": "9" * 64,
                    }

            store = DerivedStore()
            state = SimpleNamespace(root=root, rich_semantic_reviews=store)
            artifact_checks = {
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
            }

            with patch(
                "community_os.controlled_release._semantic_release_artifact_checks",
                return_value=artifact_checks,
            ):
                receipt = generate_current_semantic_release_qa(
                    state,
                    expected_subject_refs=("case:v1:" + "a" * 64,),
                    binding_context={
                        key: str(aggregate["bindings"][key])
                        for key in (
                            "event_approval_sha256", "event_definition_sha256",
                            "event_key", "run_sha256", "source_snapshot_sha256",
                            "taxonomy_sha256", "taxonomy_version",
                        )
                    },
                )

            qa_path = protected / "semantic-release-qa.json"
            self.assertEqual(qa_path.stat().st_mode & 0o777, 0o600)
            record = receipt.to_record()
            self.assertEqual(record["context"]["positive_claim_count"], 2787)
            self.assertEqual(
                record["checks"][
                    "positive_claim_sample_bound_to_final_reviewed_facts"
                ],
                {"passed": True, "evidence_count": 10, "expected_count": 10},
            )
            self.assertEqual(
                record["checks"]["required_review_cases_resolved"],
                {"passed": True, "evidence_count": 9, "expected_count": 9},
            )
            self.assertEqual(
                store.rederive_arguments["generated_at"],
                datetime(2026, 7, 15, 11, tzinfo=UTC),
            )

    def test_postapproval_qa_validator_has_no_caller_counter_input(self) -> None:
        import inspect

        from community_os.controlled_release import validate_current_semantic_release_qa

        self.assertNotIn(
            "review_evidence",
            inspect.signature(validate_current_semantic_release_qa).parameters,
        )

    def test_semantic_metric_claims_match_the_compact_project_landscape_copy(self) -> None:
        from community_os.controlled_release import _public_semantic_claims
        from community_os.partner_semantic_projection import (
            build_protected_partner_semantic_candidate_summary,
        )
        from tests.test_partner_semantic_projection import population_aggregate

        summary = build_protected_partner_semantic_candidate_summary(
            population_aggregate(),
        )
        claims = _public_semantic_claims(summary)

        expected_metrics = tuple(
            metric for metric in summary.metrics
            if metric.count is not None and metric.count > 0
        )
        for index, metric in enumerate(expected_metrics):
            expected = (
                str(metric.count) if metric.denominator is None
                else f"{metric.count} of {metric.denominator}"
            )
            self.assertEqual(claims[index], (metric.label, expected))

    def test_semantic_claims_exclude_nonpublic_metrics_and_empty_dimensions(self) -> None:
        from dataclasses import replace
        from community_os.controlled_release import _public_semantic_claims
        from community_os.partner_semantic_projection import (
            build_protected_partner_semantic_candidate_summary,
        )
        from tests.test_partner_semantic_projection import population_aggregate

        summary = build_protected_partner_semantic_candidate_summary(
            population_aggregate(),
        )
        empty_key = "product_maturity"
        summary = replace(
            summary,
            metrics=(
                replace(summary.metrics[0], count=None),
                replace(summary.metrics[1], count=0),
                *summary.metrics[2:],
            ),
            dimensions=tuple(
                replace(dimension, cells=())
                if dimension.key == empty_key else dimension
                for dimension in summary.dimensions
            ),
        )

        claims = _public_semantic_claims(summary)

        self.assertNotIn(summary.metrics[0].label, {label for label, _ in claims})
        self.assertNotIn(summary.metrics[1].label, {label for label, _ in claims})
        self.assertNotIn(
            next(item.label for item in summary.dimensions if item.key == empty_key),
            {label for label, _ in claims},
        )

    def test_pdf_claim_matching_allows_repeated_displays_with_distinct_labels(self) -> None:
        from collections import Counter
        from community_os.controlled_release import _surface_has_all_bound_claims

        claims = Counter({
            ("Primary execution evidence", "17 of 286"): 1,
            ("Meaningful external validation", "17 of 286"): 1,
        })
        self.assertTrue(_surface_has_all_bound_claims(
            "17 of 286 primary execution evidence 17 of 286 "
            "meaningful external validation",
            claims,
        ))
        self.assertFalse(_surface_has_all_bound_claims(
            "17 of 286 primary execution evidence meaningful external validation",
            claims,
        ))

    def test_pdf_heading_matching_tolerates_extractor_ligature_spacing(self) -> None:
        from community_os.controlled_release import _surface_contains_heading

        self.assertTrue(_surface_contains_heading(
            "Capabilitiesandcareercontext",
            "Capabilities and career context",
        ))
        self.assertFalse(_surface_contains_heading(
            "Capabilities and project context",
            "Capabilities and career context",
        ))

    def test_partner_surface_parity_requires_every_summary_derived_claim_on_both_surfaces(
        self,
    ) -> None:
        from community_os.controlled_release import (
            _assert_partner_surface_claim_parity,
        )
        from community_os.partner_semantic_projection import (
            build_protected_partner_semantic_candidate_summary,
        )
        from tests.test_partner_semantic_projection import population_aggregate

        summary = build_protected_partner_semantic_candidate_summary(
            population_aggregate(),
        )
        headline_counts = {
            "applied": 286, "going_accepted": 82, "on_site": 78,
        }
        claims = _expected_semantic_report_claims(summary, headline_counts)
        complete_surface = " | ".join(
            f"{label} {display}" for label, display in claims
        )

        self.assertEqual(
            _assert_partner_surface_claim_parity(
                html_text=complete_surface,
                pdf_text=complete_surface,
                headline_counts=headline_counts,
                semantic_summary=summary,
            ),
            len(claims),
        )
        for surface_name in ("HTML", "PDF"):
            for index, (label, display) in enumerate(claims):
                missing_one_claim = complete_surface.replace(
                    f"{label} {display}", "", 1,
                )
                arguments = {
                    "html_text": (
                        missing_one_claim
                        if surface_name == "HTML" else complete_surface
                    ),
                    "pdf_text": (
                        missing_one_claim
                        if surface_name == "PDF" else complete_surface
                    ),
                    "headline_counts": headline_counts,
                    "semantic_summary": summary,
                }
                with self.subTest(
                    surface=surface_name, claim_index=index,
                    label=label, display=display,
                ):
                    with self.assertRaisesRegex(
                        PermissionError, "text parity",
                    ):
                        _assert_partner_surface_claim_parity(**arguments)

    def test_partner_surface_parity_rejects_an_incomplete_metric_set(self) -> None:
        from community_os.controlled_release import (
            _assert_partner_surface_claim_parity,
        )
        from community_os.partner_semantic_projection import (
            build_protected_partner_semantic_candidate_summary,
        )
        from tests.test_partner_semantic_projection import population_aggregate

        summary = build_protected_partner_semantic_candidate_summary(
            population_aggregate(),
        )
        degraded = SimpleNamespace(
            metrics=summary.metrics[:-1], dimensions=summary.dimensions,
        )
        headline_counts = {
            "applied": 286, "going_accepted": 82, "on_site": 78,
        }
        complete_surface = " | ".join(
            f"{label} {display}"
            for label, display in _expected_semantic_report_claims(
                summary, headline_counts,
            )
        )

        with self.assertRaisesRegex(PermissionError, "claim is invalid"):
            _assert_partner_surface_claim_parity(
                html_text=complete_surface,
                pdf_text=complete_surface,
                headline_counts=headline_counts,
                semantic_summary=degraded,
            )

    def test_cohort_dashboard_parity_excludes_legacy_public_group_claims(self) -> None:
        from community_os.controlled_release import (
            _semantic_public_group_parity_required,
        )

        with tempfile.TemporaryDirectory() as directory:
            protected = Path(directory)
            self.assertTrue(
                _semantic_public_group_parity_required(protected),
            )
            (protected / "rich-semantic-internal.cohorts.aggregate.json").write_text(
                "{}\n",
                encoding="utf-8",
            )
            self.assertFalse(
                _semantic_public_group_parity_required(protected),
            )

    def test_partner_surface_parity_ignores_nonrendered_html_claims(self) -> None:
        from community_os.controlled_release import (
            _assert_partner_surface_claim_parity,
        )
        from community_os.partner_semantic_projection import (
            build_protected_partner_semantic_candidate_summary,
        )
        from tests.test_partner_semantic_projection import population_aggregate

        summary = build_protected_partner_semantic_candidate_summary(
            population_aggregate(),
        )
        headline_counts = {
            "applied": 286, "going_accepted": 82, "on_site": 78,
        }
        claims = _expected_semantic_report_claims(summary, headline_counts)
        claim = next(
            pair for pair, count in Counter(claims).items() if count == 1
        )
        segment = f"{claim[0]} {claim[1]}"
        complete_surface = " | ".join(
            f"{label} {display}" for label, display in claims
        )
        visible_without_claim = complete_surface.replace(segment, "", 1)

        for hidden_claim in (
            f"<span hidden>{segment}</span>",
            f"<span aria-hidden=\"true\">{segment}</span>",
            f"<template>{segment}</template>",
            f"<style>{segment}</style>",
        ):
            with self.subTest(hidden_claim=hidden_claim.split(">", 1)[0]):
                with self.assertRaisesRegex(PermissionError, "text parity"):
                    _assert_partner_surface_claim_parity(
                        html_text=visible_without_claim + hidden_claim,
                        pdf_text=complete_surface,
                        headline_counts=headline_counts,
                        semantic_summary=summary,
                    )

    def test_artifact_qa_requires_event_privacy_threshold_and_exact_page_sequence(self) -> None:
        from community_os.controlled_release import _semantic_release_artifact_checks
        from community_os.partner_semantic_projection import (
            build_protected_partner_semantic_candidate_summary,
        )
        from tests.test_partner_semantic_projection import population_aggregate

        with tempfile.TemporaryDirectory() as directory:
            protected = Path(directory) / "protected"
            release = protected / "release"
            release.mkdir(parents=True)
            html = release / "report.html"
            pdf = release / "report.pdf"
            v1 = release / "v1.json"
            v3 = release / "v3.json"
            aggregate = population_aggregate()
            aggregate["minimum_group_size"] = 7
            (protected / "rich-semantic-internal.aggregate.json").write_text(
                json.dumps(aggregate), encoding="utf-8",
            )
            summary = build_protected_partner_semantic_candidate_summary(aggregate)
            claim_text = " | ".join(
                f"{label} {display}"
                for label, display in _expected_semantic_report_claims(
                    summary,
                    {"applied": 286, "going_accepted": 82, "on_site": 78},
                )
            )
            html.write_text(
                '<section data-pdf-page="1"><h1>Current report</h1>'
                + claim_text + '</section>'
                + ''.join('<section data-pdf-page="1"></section>' for _ in range(4)),
                encoding="utf-8",
            )
            pdf.write_bytes(b"%PDF-fixture")
            privacy = {
                "minimum_count": 7, "mode": "aggregate_only",
                "pii_included": False, "state": "withheld_cells",
            }
            v1.write_text(json.dumps({
                "privacy": privacy,
                "cohort": {"stages": [
                    {"key": "valid_applicants", "count": {"value": 286}},
                    {"key": "going_accepted", "count": {"value": 82}},
                    {"key": "on_site", "count": {"value": 78}},
                ]},
            }), encoding="utf-8")
            v3.write_text(json.dumps({
                "privacy": privacy,
                "attendance_funnel": {"stages": [
                    {"key": "applied", "count": {"value": 286}},
                    {"key": "going_accepted", "count": {"value": 82}},
                    {"key": "on_site", "count": {"value": 78}},
                ]},
            }), encoding="utf-8")
            info = SimpleNamespace(
                returncode=0,
                stdout="Pages:          6\nPage size:      841.89 x 595.28 pts\n",
            )

            with (
                patch(
                    "community_os.publication._pdf_text",
                    return_value="Current report " + claim_text,
                ),
                patch("community_os.controlled_release.subprocess.run", return_value=info),
            ):
                with self.assertRaisesRegex(PermissionError, "PDF layout"):
                    _semantic_release_artifact_checks(
                        html_path=html, pdf_path=pdf,
                        aggregate_paths=(v1, v3), minimum_group_size=7,
                    )

                html.write_text(
                    '<section data-pdf-page="1"><h1>Current report</h1>'
                    + claim_text + '</section>'
                    + ''.join(
                        f'<section data-pdf-page="{number}"></section>'
                        for number in range(2, 7)
                    ),
                    encoding="utf-8",
                )
                checks = _semantic_release_artifact_checks(
                    html_path=html, pdf_path=pdf,
                    aggregate_paths=(v1, v3), minimum_group_size=7,
                )

            self.assertTrue(checks["pdf_layout"]["passed"])

    def test_artifact_qa_rejects_heading_only_html_pdf_parity(self) -> None:
        from community_os.controlled_release import _semantic_release_artifact_checks
        from tests.test_partner_semantic_projection import population_aggregate

        with tempfile.TemporaryDirectory() as directory:
            protected = Path(directory) / "protected"
            release = protected / "release"
            release.mkdir(parents=True)
            html = release / "report.html"
            pdf = release / "report.pdf"
            v1 = release / "v1.json"
            v3 = release / "v3.json"
            html.write_text(
                '<h1>Current report</h1>'
                + ''.join(
                    f'<section data-pdf-page="{number}"></section>'
                    for number in range(1, 6)
                ),
                encoding="utf-8",
            )
            pdf.write_bytes(b"%PDF-fixture")
            privacy = {
                "minimum_count": 5, "mode": "aggregate_only",
                "pii_included": False, "state": "withheld_cells",
            }
            v1.write_text(json.dumps({
                "privacy": privacy,
                "cohort": {"stages": [
                    {"key": "valid_applicants", "count": {"value": 286}},
                    {"key": "going_accepted", "count": {"value": 82}},
                    {"key": "on_site", "count": {"value": 78}},
                ]},
            }), encoding="utf-8")
            v3.write_text(json.dumps({
                "privacy": privacy,
                "attendance_funnel": {"stages": [
                    {"key": "applied", "count": {"value": 286}},
                    {"key": "going_accepted", "count": {"value": 82}},
                    {"key": "on_site", "count": {"value": 78}},
                ]},
            }), encoding="utf-8")
            (protected / "rich-semantic-internal.aggregate.json").write_text(
                json.dumps(population_aggregate()), encoding="utf-8",
            )
            info = SimpleNamespace(
                returncode=0,
                stdout="Pages:          6\nPage size:      841.89 x 595.28 pts\n",
            )

            with (
                patch(
                    "community_os.publication._pdf_text",
                    return_value="Current report",
                ) as pdf_text,
                patch(
                    "community_os.controlled_release.subprocess.run",
                    return_value=info,
                ),
            ):
                with self.assertRaisesRegex(PermissionError, "text parity"):
                    _semantic_release_artifact_checks(
                        html_path=html, pdf_path=pdf,
                        aggregate_paths=(v1, v3), minimum_group_size=5,
                    )

                headline_text = (
                    "Current report Applied 286 Accepted by organizers 82 "
                    "Confirmed present at the event 78"
                )
                html.write_text(
                    '<h1>Current report</h1>' + headline_text
                    + ''.join(
                        f'<section data-pdf-page="{number}"></section>'
                        for number in range(1, 7)
                    ),
                    encoding="utf-8",
                )
                pdf_text.return_value = headline_text
                with self.assertRaisesRegex(PermissionError, "text parity"):
                    _semantic_release_artifact_checks(
                        html_path=html, pdf_path=pdf,
                        aggregate_paths=(v1, v3), minimum_group_size=5,
                    )

    def test_verified_partner_release_requires_approved_semantic_enrichment(self) -> None:
        from community_os.controlled_release import _verified_release_artifacts

        with tempfile.TemporaryDirectory() as directory:
            release = Path(directory) / "protected" / "release"
            release.mkdir(parents=True)
            surface_text = " | ".join(
                f"{label} {display}"
                for label, display in _expected_funnel_claims({
                    "applied": 100,
                    "going_accepted": 20,
                    "on_site": None,
                })
            )
            html = release / "talent-brief.real.html"
            pdf = release / "talent-brief.real.pdf"
            html.write_text(surface_text, encoding="utf-8")
            pdf.write_bytes(b"%PDF-fixture")
            privacy = {
                "minimum_count": 7, "mode": "aggregate_only",
                "pii_included": False, "state": "withheld_cells",
            }
            v1 = release / "talent-intelligence-v1.real.aggregate.json"
            v3 = release / "talent-report-v3.real.aggregate.json"
            v1.write_text(json.dumps({
                "privacy": privacy,
                "cohort": {"stages": [
                    {"key": "valid_applicants", "count": {"value": 100}},
                    {"key": "going_accepted", "count": {"value": 20}},
                    {"key": "on_site", "count": {"value": None}},
                ]},
            }), encoding="utf-8")
            v3.write_text(json.dumps({
                "privacy": privacy,
                "attendance_funnel": {"stages": [
                    {"key": "applied", "count": {"value": 100}},
                    {"key": "going_accepted", "count": {"value": 20}},
                    {"key": "on_site", "count": {"value": None}},
                ]},
            }), encoding="utf-8")
            artifacts = (html, pdf, v1, v3)
            (release / "talent-report-v3.real.manifest.json").write_text(
                json.dumps({
                    "aggregates": {
                        "applied": 100, "going_accepted": 20, "on_site": 14,
                    },
                    "output_hashes": {
                        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                        for path in artifacts
                    },
                }),
                encoding="utf-8",
            )

            with (
                patch(
                    "community_os.publication._pdf_text",
                    return_value=surface_text,
                ),
                self.assertRaisesRegex(
                    PermissionError, "approved semantic enrichment is required",
                ),
            ):
                _verified_release_artifacts(
                    release, now=NOW,
                    semantic_approval_secret=b"unused-without-semantic-data",
                    semantic_authoritative_context=None,
                    minimum_group_size=7,
                )

    def test_semantic_approval_rejects_opaque_qa_or_stale_release_context(self) -> None:
        from community_os.controlled_release import (
            issue_current_semantic_release_approval,
        )
        from community_os.partner_semantic_projection import (
            build_protected_partner_semantic_candidate_summary,
            semantic_summary_manifest_binding,
        )
        from tests.test_partner_semantic_projection import semantic_aggregate

        with tempfile.TemporaryDirectory() as directory:
            protected = Path(directory) / "protected"
            release = protected / "release"
            release.mkdir(parents=True)
            aggregate = semantic_aggregate()
            (protected / "rich-semantic-internal.aggregate.json").write_text(
                json.dumps(aggregate), encoding="utf-8",
            )
            paths = tuple(
                release / name
                for name in (
                    "talent-brief.real.html", "talent-brief.real.pdf",
                    "talent-intelligence-v1.real.aggregate.json",
                    "talent-report-v3.real.aggregate.json",
                )
            )
            for index, path in enumerate(paths):
                path.write_bytes(f"artifact-{index}".encode("ascii"))
            manifest = {
                "semantic_enrichment": semantic_summary_manifest_binding(
                    build_protected_partner_semantic_candidate_summary(aggregate),
                ),
            }
            (release / "talent-report-v3.real.manifest.json").write_text(
                json.dumps(manifest), encoding="utf-8",
            )
            _write_semantic_release_qa(protected, aggregate, paths)
            qa_path = protected / "semantic-release-qa.json"
            qa_path.write_text('{"state":"complete"}', encoding="utf-8")
            qa_path.chmod(0o600)

            with self.assertRaisesRegex(PermissionError, "QA|receipt"):
                issue_current_semantic_release_approval(
                    release,
                    state=SimpleNamespace(root=Path(directory)),
                    actor_code="colleague_0123456789abcdef0123456789abcdef",
                    signing_secret=b"operator-issued-semantic-secret",
                    now=datetime(2026, 7, 15, 12, tzinfo=UTC),
                    authoritative_context=_semantic_authoritative_context(aggregate),
                )

            _write_semantic_release_qa(protected, aggregate, paths)
            context_path = protected / "semantic-release-context.json"
            stale_context = json.loads(context_path.read_text(encoding="utf-8"))
            stale_context["run_sha256"] = "f" * 64
            context_path.write_text(json.dumps(stale_context), encoding="utf-8")
            context_path.chmod(0o600)

            with self.assertRaisesRegex(PermissionError, "context"):
                issue_current_semantic_release_approval(
                    release,
                    state=SimpleNamespace(root=Path(directory)),
                    actor_code="colleague_0123456789abcdef0123456789abcdef",
                    signing_secret=b"operator-issued-semantic-secret",
                    now=datetime(2026, 7, 15, 12, tzinfo=UTC),
                    authoritative_context=_semantic_authoritative_context(aggregate),
                )

    def test_current_report_bundle_fails_before_overwrite_when_bound_semantic_source_is_missing(self) -> None:
        from community_os.controlled_release import render_current_report_bundle

        with tempfile.TemporaryDirectory() as directory:
            release = Path(directory)
            (release / "talent-intelligence-v1.real.aggregate.json").write_text(
                "{}", encoding="utf-8",
            )
            (release / "talent-report-v3.real.aggregate.json").write_text(
                "{}", encoding="utf-8",
            )
            html = release / "talent-brief.real.html"
            pdf = release / "talent-brief.real.pdf"
            html.write_text("existing-html", encoding="utf-8")
            pdf.write_text("existing-pdf", encoding="utf-8")
            (release / "talent-report-v3.real.manifest.json").write_text(
                json.dumps({
                    "output_hashes": {},
                    "semantic_enrichment": {
                        "aggregate_sha256": "a" * 64,
                        "projection_version": "partner-semantic-summary-v1",
                        "reviewed_denominator": 195,
                    },
                }),
                encoding="utf-8",
            )
            report = SimpleNamespace(
                metadata=SimpleNamespace(generated_at="2026-07-14T00:00:00Z"),
            )

            with (
                patch(
                    "community_os.talent_intelligence_contract.load_talent_intelligence_contract",
                    return_value=report,
                ),
                patch(
                    "community_os.report_contract.load_report_contract",
                    return_value=object(),
                ),
                patch("community_os.partner_report.render_partner_talent_report") as render,
                patch("community_os.pdf_export.export_pdf") as export,
            ):
                with self.assertRaisesRegex(PermissionError, "semantic enrichment source is missing"):
                    render_current_report_bundle(release)

            render.assert_not_called()
            export.assert_not_called()
            self.assertEqual(html.read_text(encoding="utf-8"), "existing-html")
            self.assertEqual(pdf.read_text(encoding="utf-8"), "existing-pdf")

    def test_current_report_bundle_fails_before_overwrite_on_semantic_source_hash_drift(self) -> None:
        from community_os.controlled_release import render_current_report_bundle
        from tests.test_partner_semantic_projection import semantic_aggregate

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            release = root / "release"
            release.mkdir()
            (release / "talent-intelligence-v1.real.aggregate.json").write_text(
                "{}", encoding="utf-8",
            )
            (release / "talent-report-v3.real.aggregate.json").write_text(
                "{}", encoding="utf-8",
            )
            html = release / "talent-brief.real.html"
            pdf = release / "talent-brief.real.pdf"
            html.write_text("existing-html", encoding="utf-8")
            pdf.write_text("existing-pdf", encoding="utf-8")
            (root / "rich-semantic-internal.aggregate.json").write_text(
                json.dumps(semantic_aggregate(), sort_keys=True), encoding="utf-8",
            )
            (release / "talent-report-v3.real.manifest.json").write_text(
                json.dumps({
                    "output_hashes": {},
                    "semantic_enrichment": {
                        "aggregate_sha256": "a" * 64,
                        "projection_version": "partner-semantic-summary-v1",
                        "reviewed_denominator": 195,
                    },
                }),
                encoding="utf-8",
            )
            report = SimpleNamespace(
                metadata=SimpleNamespace(generated_at="2026-07-14T00:00:00Z"),
            )

            with (
                patch(
                    "community_os.talent_intelligence_contract.load_talent_intelligence_contract",
                    return_value=report,
                ),
                patch(
                    "community_os.report_contract.load_report_contract",
                    return_value=object(),
                ),
                patch("community_os.partner_report.render_partner_talent_report") as render,
                patch("community_os.pdf_export.export_pdf") as export,
            ):
                with self.assertRaisesRegex(PermissionError, "semantic enrichment hash drift"):
                    render_current_report_bundle(release)

            render.assert_not_called()
            export.assert_not_called()
            self.assertEqual(html.read_text(encoding="utf-8"), "existing-html")
            self.assertEqual(pdf.read_text(encoding="utf-8"), "existing-pdf")

    def test_invalid_or_missing_approval_bundle_fails_closed_before_registry(self) -> None:
        from community_os.controlled_release import ControlledReleaseRuntime, build_controlled_release_factory
        from community_os.release_operator import ReleaseOperatorState

        with tempfile.TemporaryDirectory() as directory:
            state = ReleaseOperatorState(Path(directory) / "operator", operator_code="privacy_lead", event_definition=_event_definition())
            missing = Path(directory) / "missing.json"
            factory = build_controlled_release_factory(ControlledReleaseRuntime(
                approval_bundle=missing, pseudonym_secret=b"fixture-pseudonym-secret",
                event_definition=_event_definition(),
                clock=lambda: NOW,
            ))
            with self.assertRaisesRegex(PermissionError, "approval bundle"):
                factory(state)

    def test_removing_coresignal_approval_relocks_prior_authorization_and_clears_staging(self) -> None:
        from community_os.controlled_release import ControlledReleaseRuntime, build_controlled_release_factory
        from community_os.enrichment.state import StageStatus

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = self._state_with_sources(root)
            bundle_path = root / "approval.json"
            approved = _bundle()
            approved["coresignal"] = _coresignal_gate()
            bundle_path.write_text(json.dumps(approved), encoding="utf-8")
            runtime = ControlledReleaseRuntime(
                approval_bundle=bundle_path,
                pseudonym_secret=b"fixture-pseudonym-secret",
                event_definition=_event_definition(),
                coresignal_token="fixture-coresignal-token", clock=lambda: NOW,
            )
            build_controlled_release_factory(runtime)(state)
            self.assertEqual(state.pipeline.stage("coresignal").status, StageStatus.ALLOWED)
            protected_payload = state.root / "protected" / "stages" / "coresignal.json"
            protected_payload.parent.mkdir(parents=True, exist_ok=True)
            protected_payload.write_text(
                json.dumps({"expires_at": "2026-07-20T12:00:00Z", "records": []}),
                encoding="utf-8",
            )
            protected_temporary = protected_payload.with_name(protected_payload.name + ".tmp")
            protected_temporary.write_text("raw personal enrichment", encoding="utf-8")
            cache_root = state.root / "protected" / "cache" / "coresignal"
            cache_root.mkdir(parents=True, exist_ok=True)
            (cache_root / "entry.json").write_text("{}", encoding="utf-8")
            (cache_root / "entry.tmp").write_text("raw personal cache", encoding="utf-8")
            staged = state.root / "public-staging" / "index.html"
            staged.parent.mkdir(parents=True)
            staged.write_text("stale", encoding="utf-8")
            public_pdf = staged.parent / "partner-talent-brief.pdf"
            public_pdf.write_text("stale", encoding="utf-8")
            deployment = state.root / "deployment-staging"
            deployment.mkdir()
            for name in (
                "vercel.json", "index.html", "partner-talent-brief.pdf",
                "publication-manifest.json",
            ):
                (deployment / name).write_text("stale", encoding="utf-8")
            analytics_audit = state.root / "protected" / "analytics-publication.json"
            analytics_audit.write_text("stale", encoding="utf-8")

            bundle_path.write_text(json.dumps(_bundle()), encoding="utf-8")
            build_controlled_release_factory(runtime)(state)

            self.assertEqual(state.pipeline.stage("coresignal").status, StageStatus.LOCKED)
            self.assertFalse(protected_payload.exists())
            self.assertFalse(protected_temporary.exists())
            self.assertEqual(list(cache_root.iterdir()), [])
            self.assertFalse(staged.exists())
            self.assertFalse(public_pdf.exists())
            self.assertFalse(deployment.exists())
            self.assertFalse(analytics_audit.exists())
            self.assertEqual(state.snapshot()["release_state"], "Blocked")

    def test_coresignal_stays_locked_until_notice_gate_and_provider_token_are_both_present(self) -> None:
        from community_os.controlled_release import ControlledReleaseRuntime, build_controlled_release_factory
        from community_os.enrichment.state import StageStatus

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = self._state_with_sources(root)
            bundle = _bundle()
            bundle["coresignal"] = _coresignal_gate()
            bundle_path = root / "approval.json"
            bundle_path.write_text(json.dumps(bundle), encoding="utf-8")

            build_controlled_release_factory(ControlledReleaseRuntime(
                approval_bundle=bundle_path,
                pseudonym_secret=b"fixture-pseudonym-secret",
                event_definition=_event_definition(), clock=lambda: NOW,
            ))(state)
            self.assertEqual(state.pipeline.stage("coresignal").status, StageStatus.LOCKED)

            build_controlled_release_factory(ControlledReleaseRuntime(
                approval_bundle=bundle_path,
                pseudonym_secret=b"fixture-pseudonym-secret",
                event_definition=_event_definition(),
                coresignal_token="fixture-coresignal-token", clock=lambda: NOW,
            ))(state)
            self.assertEqual(state.pipeline.stage("coresignal").status, StageStatus.ALLOWED)

    def test_current_aggregate_and_github_notice_cannot_unlock_coresignal(self) -> None:
        from community_os.controlled_release import ControlledReleaseRuntime, build_controlled_release_factory

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = self._state_with_sources(root)
            bundle = _bundle()
            current_notice = _coresignal_gate()
            current_notice["notice_version"] = bundle["privacy_operations"]["notice_version"]
            current_notice["notice_sent_at"] = bundle["privacy_operations"]["notice_sent_at"]
            bundle["coresignal"] = current_notice
            bundle_path = root / "approval.json"
            bundle_path.write_text(json.dumps(bundle), encoding="utf-8")

            with self.assertRaisesRegex(PermissionError, "distinct Coresignal transparency notice"):
                build_controlled_release_factory(ControlledReleaseRuntime(
                    approval_bundle=bundle_path,
                    pseudonym_secret=b"fixture-pseudonym-secret",
                    event_definition=_event_definition(),
                    coresignal_token="fixture-coresignal-token", clock=lambda: NOW,
                ))(state)

    def test_invalid_rights_record_revokes_gates_and_clears_prior_staging(self) -> None:
        from community_os.controlled_release import ControlledReleaseRuntime, build_controlled_release_factory
        from community_os.enrichment.state import StageStatus

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = self._state_with_sources(root)
            bundle_path = root / "approval.json"
            bundle_path.write_text(json.dumps(_bundle()), encoding="utf-8")
            runtime = ControlledReleaseRuntime(
                approval_bundle=bundle_path,
                pseudonym_secret=b"fixture-pseudonym-secret",
                event_definition=_event_definition(), clock=lambda: NOW,
            )
            build_controlled_release_factory(runtime)(state)
            staged = state.root / "public-staging" / "talent-brief.real.html"
            staged.parent.mkdir(parents=True)
            staged.write_text("stale", encoding="utf-8")
            invalid = _bundle()
            invalid["privacy_operations"]["rights"]["objection_status"] = "requested"
            bundle_path.write_text(json.dumps(invalid), encoding="utf-8")

            with self.assertRaisesRegex(PermissionError, "rights are unresolved"):
                build_controlled_release_factory(runtime)(state)

            for stage in ("github", "public_pages", "coresignal"):
                self.assertEqual(state.pipeline.stage(stage).status, StageStatus.LOCKED)
            self.assertFalse(staged.exists())
            self.assertEqual(state.snapshot()["release_state"], "Blocked")

    def test_publication_requires_hash_bound_approval_then_stages_only_public_allowlist(self) -> None:
        from community_os.controlled_release import ControlledReleaseRuntime, build_controlled_release_factory
        from community_os.publication import artifact_set_sha256
        from community_os.release_operations import ReviewCase, ReviewDecision
        from community_os.release_operator import ReleaseOperatorState, ReleaseSourceSlot

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle_path = root / "approval.json"
            initial_bundle = _bundle()
            initial_bundle["semantic_processor"] = _semantic_processor()
            bundle_path.write_text(json.dumps(initial_bundle), encoding="utf-8")
            state = ReleaseOperatorState(root / "operator", operator_code="privacy_lead", event_definition=_event_definition())
            for slot in ReleaseSourceSlot:
                suffix = ".csv" if slot.value in {"applications", "attendance"} else ".xlsx"
                path = state.protected_uploads / (slot.value + suffix)
                path.write_bytes(slot.value.encode())
                state.record_source(
                    slot, sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                    row_count=1, filename=path.name,
                )
            runtime = ControlledReleaseRuntime(
                approval_bundle=bundle_path,
                pseudonym_secret=b"fixture-pseudonym-secret",
                event_definition=_event_definition(),
                openai_api_key="fixture-key-not-secret", clock=lambda: NOW,
            )
            build_controlled_release_factory(runtime)(state)
            release = state.root / "protected" / "release"
            release.mkdir(parents=True)
            html = release / "talent-brief.real.html"
            surface_text = " | ".join(
                f"{label} {display}"
                for label, display in _expected_funnel_claims({
                    "applied": 286,
                    "going_accepted": 83,
                    "on_site": 78,
                })
            )
            surface_text += " | aggregate only"
            html.write_text(
                f'<html><body>{surface_text}'
                '<a href="talent-brief.real.pdf">View PDF</a></body></html>',
                encoding="utf-8",
            )
            pdf = release / "talent-brief.real.pdf"
            pdf.write_bytes(b"%PDF-1.4\nfixture\n%%EOF")
            privacy = {
                "minimum_count": 5, "mode": "aggregate_only",
                "pii_included": False, "state": "withheld_cells",
            }
            v1 = {
                "privacy": privacy,
                "cohort": {"stages": [
                    {"key": "valid_applicants", "count": {"value": 286}},
                    {"key": "going_accepted", "count": {"value": 83}},
                    {"key": "on_site", "count": {"value": 78}},
                ]},
            }
            v3 = {
                "privacy": privacy,
                "attendance_funnel": {"stages": [
                    {"key": "applied", "count": {"value": 286}},
                    {"key": "going_accepted", "count": {"value": 83}},
                    {"key": "on_site", "count": {"value": 78}},
                ]},
            }
            v1_path = release / "talent-intelligence-v1.real.aggregate.json"
            v3_path = release / "talent-report-v3.real.aggregate.json"
            v1_path.write_text(json.dumps(v1), encoding="utf-8")
            v3_path.write_text(json.dumps(v3), encoding="utf-8")
            artifacts = (html, pdf, v1_path, v3_path)
            (release / "talent-report-v3.real.manifest.json").write_text(json.dumps({
                "aggregates": {"applied": 286, "going_accepted": 83, "on_site": 78},
                "output_hashes": {
                    path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                    for path in artifacts
                },
            }), encoding="utf-8")
            classification_expiry = NOW + timedelta(days=30)
            stages = state.root / "protected" / "stages"
            stages.mkdir(parents=True)
            (stages / "classification.json").write_text(json.dumps({
                "expires_at": classification_expiry.isoformat(), "records": [],
            }), encoding="utf-8")
            review = ReviewCase.create(
                kind="classification", subject_code="candidate_001",
                reason_codes=("low_confidence",), candidate_codes=(),
                source_hashes={"applications": "a" * 64}, version="rules_v1",
            )
            state.review_repository.replace((review,))
            state.review_repository.decide(
                ReviewDecision(
                    case_code=review.case_code, case_hash=review.case_hash,
                    action="approved",
                ),
                actor_code="privacy_lead", decided_at=NOW,
            )

            operations = build_controlled_release_factory(runtime)(state)

            def verify_semantic_artifact_gate(release_root, **_kwargs):
                manifest = json.loads(
                    (release_root / "talent-report-v3.real.manifest.json").read_text(
                        encoding="utf-8",
                    )
                )
                for name, expected_hash in manifest["output_hashes"].items():
                    path = release_root / name
                    if path.is_file() and hashlib.sha256(path.read_bytes()).hexdigest() != expected_hash:
                        raise PermissionError("protected release artifact hash drift")
                return {"applied": 286, "going_accepted": 83, "on_site": 78}

            semantic_artifact_gate = patch(
                "community_os.controlled_release._verified_release_artifacts",
                side_effect=verify_semantic_artifact_gate,
            )
            semantic_artifact_gate.start()
            self.addCleanup(semantic_artifact_gate.stop)
            with patch("community_os.publication._pdf_text", return_value=surface_text):
                with self.assertRaisesRegex(PermissionError, "Needs review"):
                    operations["publish"]()
            self.assertEqual(state.snapshot()["release_state"], "Needs review")

            event_approval_sha256 = state.snapshot()["event_approval"]["sha256"]
            approval_record = {
                "actor_code": "release_owner",
                "approved_at": "2026-07-13T12:00:00Z",
                "artifact_set_sha256": artifact_set_sha256((html, pdf)),
                "event_approval_sha256": "f" * 64,
                "report_sha256": hashlib.sha256(html.read_bytes()).hexdigest(),
            }
            wrong_event_approval = _bundle(approval_record)
            wrong_event_approval["semantic_processor"] = _semantic_processor()
            bundle_path.write_text(json.dumps(wrong_event_approval), encoding="utf-8")
            operations = build_controlled_release_factory(runtime)(state)
            with patch("community_os.publication._pdf_text", return_value=surface_text):
                with self.assertRaisesRegex(
                    PermissionError, "publication approval event approval hash does not match",
                ):
                    operations["publish"]()

            approval_record["event_approval_sha256"] = event_approval_sha256
            approved = _bundle(approval_record)
            approved["semantic_processor"] = _semantic_processor()
            bundle_path.write_text(json.dumps(approved), encoding="utf-8")
            operations = build_controlled_release_factory(runtime)(state)
            original_pdf = pdf.read_bytes()
            pdf.write_bytes(original_pdf + b"tampered")
            with patch("community_os.publication._pdf_text", return_value=surface_text):
                with self.assertRaisesRegex(PermissionError, "artifact hash drift"):
                    operations["publish"]()
            pdf.write_bytes(original_pdf)
            with patch("community_os.publication._pdf_text", return_value=surface_text):
                records = operations["publish"]()

            self.assertEqual(state.snapshot()["release_state"], "Safe to publish")
            self.assertEqual(records[0]["release_state"], "Safe to publish")
            public = state.root / "public-staging"
            self.assertEqual(
                {path.name for path in public.iterdir()},
                {
                    "publication-manifest.json", "index.html",
                    "partner-talent-brief.pdf",
                },
            )
            privacy = json.loads(
                (state.root / "protected" / "privacy-operations.json").read_text(encoding="utf-8")
            )
            self.assertEqual(privacy["release_state"], "Safe to publish")
            self.assertEqual(privacy["accountable_owner"], "privacy_lead")
            self.assertEqual(
                {item["source"] for item in privacy["inventory"]},
                {
                    "applications", "attendance", "preferences", "submissions",
                    "classification", "partner_report",
                },
            )
            classification_asset = next(
                item for item in privacy["inventory"]
                if item["source"] == "classification"
            )
            self.assertEqual(
                classification_asset["retention_deadline"],
                classification_expiry.isoformat(),
            )

    def test_scheduled_cleanup_physically_deletes_expired_cache_and_raw_enrichment(self) -> None:
        from community_os.controlled_release import run_scheduled_privacy_cleanup
        from community_os.enrichment.cache import CanonicalJsonCache
        from community_os.enrichment.evidence_vault import ProtectedEvidenceVault

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            earlier = NOW - timedelta(days=2)
            vault = ProtectedEvidenceVault(
                root / "protected" / "raw-evidence", clock=lambda: earlier,
            )
            vault.capture(
                source="github", purpose="talent_classification",
                subject_ref="pid:v1:" + "a" * 64,
                evidence_ref="evidence:github:" + "b" * 64,
                provider_version="github-public-profile-v1",
                content_type="application/json", payload=b'{"login":"private"}',
                ttl=timedelta(hours=1),
            )
            cache = CanonicalJsonCache(
                root / "protected" / "cache" / "github", clock=lambda: earlier,
            )
            key = cache.key("github", "v1", {"subject_ref": "psn_fixture"})
            cache.set(key, {"state": "cached"}, expires_at=NOW - timedelta(days=1))
            (cache.root / "orphan.tmp").write_text("raw personal cache", encoding="utf-8")
            classification_cache = CanonicalJsonCache(
                root / "protected" / "cache" / "classification", clock=lambda: earlier,
            )
            classification_key = classification_cache.key(
                "classification", "semantic-v1", {"subject_ref": "psn_fixture"},
            )
            classification_cache.set(
                classification_key, {"dimensions": {}}, expires_at=NOW - timedelta(days=1),
            )
            (classification_cache.root / "orphan.tmp").write_text(
                "derived personal cache", encoding="utf-8",
            )
            stages = root / "protected" / "stages"
            stages.mkdir(parents=True)
            raw = stages / "github.json"
            raw.write_text(json.dumps({
                "expires_at": "2026-07-12T12:00:00Z", "records": [],
            }), encoding="utf-8")
            raw_temporary = stages / "public_pages.json.tmp"
            raw_temporary.write_text("raw personal enrichment", encoding="utf-8")
            classification_raw = stages / "classification.json"
            classification_raw.write_text(json.dumps({
                "expires_at": "2026-07-12T12:00:00Z", "records": [],
            }), encoding="utf-8")
            classification_temporary = stages / "classification.json.tmp"
            classification_temporary.write_text("derived personal data", encoding="utf-8")

            result = run_scheduled_privacy_cleanup(
                root, clock=lambda: NOW, event_definition=_event_definition(),
            )

            self.assertEqual(result["cache_entries_deleted"], 4)
            self.assertEqual(result["raw_enrichment_deleted"], 4)
            self.assertEqual(result["temporary_raw_evidence_deleted"], 1)
            self.assertEqual(list(vault.records.iterdir()), [])
            self.assertEqual(len(list(vault.receipts.glob("*.json"))), 1)
            self.assertFalse(raw.exists())
            self.assertFalse(raw_temporary.exists())
            self.assertFalse(classification_raw.exists())
            self.assertFalse(classification_temporary.exists())
            self.assertEqual(list(cache.root.glob("*.json")), [])
            self.assertEqual(list(cache.root.glob("*.tmp")), [])
            self.assertEqual(list(classification_cache.root.glob("*.json")), [])
            self.assertEqual(list(classification_cache.root.glob("*.tmp")), [])
            audit = root / "protected" / "privacy-cleanup-audit.jsonl"
            self.assertTrue(audit.is_file())
            self.assertNotIn("psn_fixture", audit.read_text(encoding="utf-8"))

    def test_scheduled_cleanup_deletes_orphan_review_binding_temporary_file(self) -> None:
        from community_os.controlled_release import run_scheduled_privacy_cleanup

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            temporary = root / "protected" / "review-bindings.json.tmp"
            temporary.parent.mkdir(parents=True)
            temporary.write_text("interrupted private binding", encoding="utf-8")

            result = run_scheduled_privacy_cleanup(
                root, clock=lambda: NOW, event_definition=_event_definition(),
            )

            self.assertFalse(temporary.exists())
            self.assertEqual(result["derived_files_deleted"], 1)

    def test_scheduled_cleanup_deletes_expired_raw_exports_and_clears_source_state(self) -> None:
        from community_os.controlled_release import run_scheduled_privacy_cleanup
        from community_os.enrichment.evidence_vault import ProtectedEvidenceVault

        with tempfile.TemporaryDirectory() as directory:
            state = self._state_with_sources(Path(directory))
            applications = state.protected_uploads / str(
                state.snapshot()["source_slots"]["applications"]["path"]
            )
            privacy = state.root / "protected" / "privacy-operations.json"
            privacy.write_text(json.dumps({
                "inventory": [
                    {
                        "data_class": "raw_source",
                        "resource_ref": state.snapshot()["source_slots"][role]["path"],
                        "retention_deadline": (
                            "2026-07-12T12:00:00Z" if role == "applications"
                            else "2026-08-12T12:00:00Z"
                        ),
                        "source": role,
                        "storage_scope": "protected_uploads",
                    }
                    for role in state.source_slots
                ],
            }), encoding="utf-8")
            staged = state.root / "public-staging" / "talent-brief.real.html"
            staged.parent.mkdir(parents=True)
            staged.write_text("stale", encoding="utf-8")
            derived = state.root / "protected" / "release" / "private" / "operator-state.real.json"
            derived.parent.mkdir(parents=True)
            derived.write_text("personal derivative", encoding="utf-8")
            stage_output = state.root / "protected" / "stages" / "classification.json"
            stage_output.parent.mkdir(parents=True)
            stage_output.write_text("personal derivative", encoding="utf-8")
            review_bindings_temporary = (
                state.root / "protected" / "review-bindings.json.tmp"
            )
            review_bindings_temporary.write_text(
                "interrupted personal binding", encoding="utf-8",
            )
            vault = ProtectedEvidenceVault(
                state.root / "protected" / "raw-evidence", clock=lambda: NOW,
            )
            vault.capture(
                source="github", purpose="talent_classification",
                subject_ref="pid:v1:" + "a" * 64,
                evidence_ref="evidence:github:" + "b" * 64,
                provider_version="github-public-profile-v1",
                content_type="application/json", payload=b'{"login":"private"}',
                ttl=timedelta(hours=1),
            )

            result = run_scheduled_privacy_cleanup(
                state.root, clock=lambda: NOW,
                event_definition=_event_definition(),
            )

            self.assertEqual(result["raw_sources_deleted"], 1)
            self.assertFalse(applications.exists())
            self.assertNotIn(
                "applications", state.__class__(
                    state.root, operator_code="privacy_lead",
                    event_definition=_event_definition(),
                ).snapshot()["source_slots"],
            )
            self.assertFalse(staged.exists())
            self.assertFalse(derived.exists())
            self.assertFalse(stage_output.exists())
            self.assertFalse(review_bindings_temporary.exists())
            self.assertEqual(list(vault.records.iterdir()), [])

    def test_scheduled_cleanup_validates_event_binding_before_deleting_sources(self) -> None:
        from community_os.controlled_release import run_scheduled_privacy_cleanup
        from community_os.event_definition import load_event_definition

        with tempfile.TemporaryDirectory() as directory:
            state = self._state_with_sources(Path(directory))
            applications = state.protected_uploads / str(
                state.snapshot()["source_slots"]["applications"]["path"]
            )
            privacy = state.root / "protected" / "privacy-operations.json"
            privacy.write_text(json.dumps({
                "inventory": [{
                    "data_class": "raw_source",
                    "resource_ref": applications.name,
                    "retention_deadline": "2026-07-12T12:00:00Z",
                    "source": "applications",
                    "storage_scope": "protected_uploads",
                }],
            }), encoding="utf-8")
            wrong_definition = load_event_definition(
                ROOT / "tests/fixtures/events/second-hackathon.synthetic.json",
            )
            public = state.root / "public-staging"
            public.mkdir()
            for name in (
                "index.html", "partner-talent-brief.pdf",
                "publication-manifest.json",
            ):
                (public / name).write_text("stale", encoding="utf-8")
            deployment = state.root / "deployment-staging"
            deployment.mkdir()
            for name in (
                "vercel.json", "index.html", "partner-talent-brief.pdf",
                "publication-manifest.json",
            ):
                (deployment / name).write_text("stale", encoding="utf-8")

            with self.assertRaisesRegex(PermissionError, "different event"):
                run_scheduled_privacy_cleanup(
                    state.root, clock=lambda: NOW,
                    event_definition=wrong_definition,
                )

            self.assertTrue(applications.is_file())
            self.assertFalse(public.exists())
            self.assertFalse(deployment.exists())

    def test_scheduled_cleanup_rejects_relabelled_or_missing_raw_source_inventory(self) -> None:
        from community_os.controlled_release import run_scheduled_privacy_cleanup

        for mutation in ("relabelled", "missing", "duplicate", "redirected"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                state = self._state_with_sources(Path(directory))
                slots = state.snapshot()["source_slots"]
                inventory = [
                    {
                        "data_class": "raw_source",
                        "resource_ref": slots[role]["path"],
                        "retention_deadline": "2026-08-12T12:00:00Z",
                        "source": role,
                        "storage_scope": "protected_uploads",
                    }
                    for role in state.source_slots
                ]
                applications = state.protected_uploads / str(
                    slots["applications"]["path"]
                )
                if mutation == "relabelled":
                    inventory[0]["data_class"] = "derived"
                elif mutation == "missing":
                    inventory = [
                        item for item in inventory
                        if item["source"] != "applications"
                    ]
                elif mutation == "duplicate":
                    inventory.append(dict(inventory[0]))
                else:
                    inventory[0]["resource_ref"] = slots["attendance"]["path"]
                privacy = state.root / "protected" / "privacy-operations.json"
                privacy.write_text(json.dumps({"inventory": inventory}), encoding="utf-8")

                with self.assertRaisesRegex(
                    PermissionError, "raw source privacy inventory is invalid",
                ):
                    run_scheduled_privacy_cleanup(
                        state.root, clock=lambda: NOW,
                        event_definition=_event_definition(),
                    )

                self.assertTrue(applications.is_file())

    def test_scheduled_cleanup_invalidates_outputs_derived_from_expired_enrichment(self) -> None:
        from community_os.controlled_release import ControlledReleaseRuntime, build_controlled_release_factory, run_scheduled_privacy_cleanup
        from community_os.enrichment.state import PipelineState, StageStatus

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = self._state_with_sources(root)
            bundle_path = root / "approval.json"
            bundle = _bundle()
            bundle["semantic_processor"] = _semantic_processor()
            bundle_path.write_text(json.dumps(bundle), encoding="utf-8")
            build_controlled_release_factory(ControlledReleaseRuntime(
                approval_bundle=bundle_path,
                pseudonym_secret=b"fixture-pseudonym-secret",
                event_definition=_event_definition(),
                openai_api_key="fixture-key-not-secret", clock=lambda: NOW,
            ))(state)
            for stage in ("github", "classification", "aggregate", "report", "publish"):
                state.pipeline.start(stage)
                state.pipeline.complete(stage, {
                    "output_hash": hashlib.sha256(stage.encode()).hexdigest(),
                    "record_count": 1,
                })
            stages = state.root / "protected" / "stages"
            stages.mkdir(parents=True, exist_ok=True)
            (stages / "github.json").write_text(json.dumps({
                "expires_at": "2026-07-12T12:00:00Z", "records": [],
            }), encoding="utf-8")
            staged = state.root / "public-staging" / "talent-brief.real.html"
            staged.parent.mkdir(parents=True)
            staged.write_text("stale", encoding="utf-8")

            run_scheduled_privacy_cleanup(
                state.root, clock=lambda: NOW,
                event_definition=_event_definition(),
            )

            reopened = PipelineState.load(state.pipeline_path)
            for stage in ("github", "classification", "aggregate", "report", "publish"):
                self.assertEqual(reopened.stage(stage).status, StageStatus.ALLOWED)
            self.assertFalse(staged.exists())

    def test_scheduled_cleanup_withdraws_public_staging_before_failed_state_repair(self) -> None:
        from community_os.controlled_release import run_scheduled_privacy_cleanup

        with tempfile.TemporaryDirectory() as directory:
            state = self._state_with_sources(Path(directory))
            stages = state.root / "protected" / "stages"
            stages.mkdir(parents=True, exist_ok=True)
            (stages / "github.json").write_text(json.dumps({
                "expires_at": "2026-07-12T12:00:00Z", "records": [],
            }), encoding="utf-8")
            public = state.root / "public-staging"
            public.mkdir(parents=True)
            staged = public / "talent-brief.real.html"
            staged.write_text("stale aggregate report", encoding="utf-8")
            slots = state.snapshot()["source_slots"]
            (state.root / "protected" / "privacy-operations.json").write_text(
                json.dumps({
                    "inventory": [
                        {
                            "data_class": "raw_source",
                            "resource_ref": slots[role]["path"],
                            "retention_deadline": "2026-08-12T12:00:00Z",
                            "source": role,
                            "storage_scope": "protected_uploads",
                        }
                        for role in state.source_slots
                    ],
                }),
                encoding="utf-8",
            )
            state.pipeline_path.write_text("{corrupt", encoding="utf-8")

            with self.assertRaisesRegex(PermissionError, "invalidation failed"):
                run_scheduled_privacy_cleanup(
                    state.root, clock=lambda: NOW,
                    event_definition=_event_definition(),
                )

            self.assertFalse(staged.exists())
            self.assertFalse((stages / "github.json").exists())

    def test_scheduled_cleanup_preflights_raw_inventory_and_withdraws_public_on_failure(self) -> None:
        from community_os.controlled_release import run_scheduled_privacy_cleanup

        with tempfile.TemporaryDirectory() as directory:
            state = self._state_with_sources(Path(directory))
            stages = state.root / "protected" / "stages"
            stages.mkdir(parents=True, exist_ok=True)
            expired = stages / "github.json"
            expired.write_text(json.dumps({
                "expires_at": "2026-07-12T12:00:00Z", "records": [],
            }), encoding="utf-8")
            privacy = state.root / "protected" / "privacy-operations.json"
            privacy.write_text(json.dumps({
                "inventory": [{"data_class": "raw_source"}],
            }), encoding="utf-8")
            staged = state.root / "public-staging" / "talent-brief.real.html"
            staged.parent.mkdir(parents=True)
            staged.write_text("stale aggregate report", encoding="utf-8")

            with self.assertRaisesRegex(PermissionError, "raw source privacy inventory"):
                run_scheduled_privacy_cleanup(
                    state.root, clock=lambda: NOW,
                    event_definition=_event_definition(),
                )

            self.assertTrue(expired.exists(), "preflight failure must not partially delete stages")
            self.assertFalse(staged.exists(), "invalid privacy inventory must withdraw publication")

    def test_scheduled_cleanup_withdraws_public_and_audits_if_mid_deletion_fails(self) -> None:
        from community_os.controlled_release import run_scheduled_privacy_cleanup

        with tempfile.TemporaryDirectory() as directory:
            state = self._state_with_sources(Path(directory))
            slots = state.snapshot()["source_slots"]
            applications = state.protected_uploads / str(slots["applications"]["path"])
            attendance = (
                state.protected_uploads / str(slots["attendance"]["path"])
            ).resolve()
            privacy = state.root / "protected" / "privacy-operations.json"
            privacy.write_text(json.dumps({
                "inventory": [
                    {
                        "data_class": "raw_source", "resource_ref": applications.name,
                        "retention_deadline": "2026-07-12T12:00:00Z",
                        "source": "applications", "storage_scope": "protected_uploads",
                    },
                    {
                        "data_class": "raw_source", "resource_ref": attendance.name,
                        "retention_deadline": "2026-07-12T12:00:00Z",
                        "source": "attendance", "storage_scope": "protected_uploads",
                    },
                    *[
                        {
                            "data_class": "raw_source",
                            "resource_ref": slots[role]["path"],
                            "retention_deadline": "2026-08-12T12:00:00Z",
                            "source": role,
                            "storage_scope": "protected_uploads",
                        }
                        for role in ("preferences", "submissions")
                    ],
                ],
            }), encoding="utf-8")
            staged = state.root / "public-staging" / "talent-brief.real.html"
            staged.parent.mkdir(parents=True)
            staged.write_text("stale aggregate report", encoding="utf-8")
            original_unlink = Path.unlink

            def fail_attendance(path, *args, **kwargs):
                if path == attendance:
                    raise OSError("fixture storage deletion failed")
                return original_unlink(path, *args, **kwargs)

            with patch("pathlib.Path.unlink", autospec=True, side_effect=fail_attendance):
                with self.assertRaisesRegex(OSError, "storage deletion failed"):
                    run_scheduled_privacy_cleanup(
                        state.root, clock=lambda: NOW,
                        event_definition=_event_definition(),
                    )

            self.assertFalse(staged.exists())
            audit = state.root / "protected" / "privacy-cleanup-audit.jsonl"
            self.assertTrue(audit.is_file())
            event = json.loads(audit.read_text(encoding="utf-8").splitlines()[-1])
            self.assertEqual(event["state"], "failed")
            self.assertEqual(event["audit_reason_code"], "scheduled_retention_expiry")
            self.assertNotIn("applications", json.dumps(event))

    def test_scheduled_cleanup_refuses_to_overlap_an_operator_mutation(self) -> None:
        from community_os.controlled_release import run_scheduled_privacy_cleanup
        from community_os.release_operator import protected_mutation_lock

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with protected_mutation_lock(root):
                with self.assertRaises(BlockingIOError):
                    run_scheduled_privacy_cleanup(
                        root, clock=lambda: NOW,
                        event_definition=_event_definition(),
                    )

    def test_local_partner_share_contains_only_scanned_public_artifacts(self) -> None:
        from community_os.controlled_release import materialize_local_partner_share

        with tempfile.TemporaryDirectory() as directory:
            release = Path(directory) / "release"
            release.mkdir()
            public = {
                "talent-brief.real.html": b"<html>Aggregate partner brief</html>",
                "talent-brief.real.pdf": b"%PDF-1.4\nfixture\n%%EOF",
            }
            for name, contents in public.items():
                (release / name).write_bytes(contents)
            for name in (
                "talent-intelligence-v1.real.aggregate.json",
                "talent-report-v3.real.aggregate.json",
            ):
                (release / name).write_text(
                    '{"evidence_coverage":{"github":199}}', encoding="utf-8",
                )
            (release / "talent-brief.internal-qa.md").write_text(
                "internal operator evidence", encoding="utf-8",
            )
            private = release / "private"
            private.mkdir()
            (private / "operator-state.real.json").write_text(
                '{"private":true}', encoding="utf-8",
            )

            with patch(
                "community_os.publication._pdf_text",
                return_value="Aggregate partner brief",
            ):
                result = materialize_local_partner_share(release)

            share = release / "partner-share"
            self.assertEqual(
                {path.name for path in share.iterdir()}, set(public),
            )
            self.assertEqual(
                {name: (share / name).read_bytes() for name in public}, public,
            )
            self.assertEqual(set(result["artifact_hashes"]), set(public))
            self.assertEqual(share.stat().st_mode & 0o777, 0o700)
            self.assertTrue(all(
                path.stat().st_mode & 0o777 == 0o600
                for path in share.iterdir()
            ))
            self.assertFalse((share / "talent-brief.internal-qa.md").exists())
            self.assertFalse((share / "private").exists())
            self.assertFalse(
                (share / "talent-intelligence-v1.real.aggregate.json").exists(),
            )
            self.assertFalse(
                (share / "talent-report-v3.real.aggregate.json").exists(),
            )

    def test_local_partner_share_fails_closed_before_copying_forbidden_text(self) -> None:
        from community_os.controlled_release import materialize_local_partner_share

        with tempfile.TemporaryDirectory() as directory:
            release = Path(directory) / "release"
            release.mkdir()
            for name, contents in {
                "talent-brief.real.html": b"contact person@example.com",
                "talent-brief.real.pdf": b"%PDF-1.4\nfixture\n%%EOF",
                "talent-intelligence-v1.real.aggregate.json": b"{}",
                "talent-report-v3.real.aggregate.json": b"{}",
            }.items():
                (release / name).write_bytes(contents)
            stale = release / "partner-share"
            stale.mkdir()
            (stale / "talent-brief.real.html").write_text(
                "previous share", encoding="utf-8",
            )

            with patch(
                "community_os.publication._pdf_text", return_value="Aggregate brief",
            ):
                with self.assertRaisesRegex(
                    PermissionError, "forbidden personal or protected data",
                ):
                    materialize_local_partner_share(release)

            self.assertFalse(stale.exists())

    def test_withdraw_local_partner_share_is_a_noop_before_release_exists(self) -> None:
        from community_os.controlled_release import withdraw_local_partner_share

        with tempfile.TemporaryDirectory() as directory:
            release = Path(directory) / "release"

            withdraw_local_partner_share(release)

            self.assertFalse(release.exists())


if __name__ == "__main__":
    unittest.main()
