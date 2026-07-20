from __future__ import annotations

from datetime import UTC, datetime, timedelta
import hashlib
import hmac
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch


NOW = datetime(2026, 7, 13, 12, tzinfo=UTC)


def _current_event_definition():
    from community_os.event_definition import load_event_definition

    return load_event_definition(
        Path(__file__).parents[1]
        / "config/events/openai-hackathon-2026.json",
    )


def _review_bindings_payload(
    state: object, bindings: dict[str, object],
) -> dict[str, object]:
    snapshot = state.snapshot()
    slots = snapshot["source_slots"]
    return {
        "bindings": bindings,
        "bindings_version": "release-review-bindings-v2",
        "event_approval_sha256": (
            snapshot["event_approval"]["sha256"]
            if snapshot["event_approval"] is not None else None
        ),
        "event_definition_sha256": state.event_definition_sha256,
        "event_key": state.event_key,
        "source_hashes": {
            role: slots[role]["sha256"] if role in slots else None
            for role in state.source_slots
        },
    }


def semantic_processor_approval():
    from community_os.enrichment.classification import ProcessorApproval

    return ProcessorApproval(
        provider="openai_responses", purpose="talent_classification",
        dpa_version="dpa-v1", terms_version="terms-v1",
        retention_mode="zero_retention", region="eu",
        security_profile="approved-v1",
        field_allowlist=frozenset({"subject_ref", "signals", "evidence_refs"}),
        approved_by="start_privacy_owner", approved_at="2026-07-13T09:00:00Z",
    )


def rich_semantic_processor_approval():
    from community_os.enrichment.classification import ProcessorApproval
    from community_os.enrichment.github_content_evidence import RICH_PROJECT_FIELDS
    from community_os.enrichment.rich_semantic_assessment import (
        PROFILE_ALLOWED_KEYS, PROMPT_VERSION,
    )

    return ProcessorApproval(
        provider="openai_responses", purpose="rich_semantic_assessment",
        dpa_version="dpa-v1", terms_version="terms-v1",
        retention_mode="zero_retention", region="eu",
        security_profile="approved-v1",
        field_allowlist=PROFILE_ALLOWED_KEYS.union(RICH_PROJECT_FIELDS),
        approved_by="start_privacy_owner", approved_at="2026-07-13T09:00:00Z",
        payload_version=PROMPT_VERSION,
    )


class ReviewRepositoryTests(unittest.TestCase):
    def test_application_loader_passes_the_operator_event_definition(self) -> None:
        from community_os.event_definition import load_event_definition
        from community_os.release_operations import _load_applications

        definition = load_event_definition(
            Path(__file__).parent / "fixtures/events/second-hackathon.synthetic.json",
        )
        root = Path("/protected-operator")
        state = SimpleNamespace(
            event_definition=definition,
            protected_uploads=root / "protected" / "uploads",
            snapshot=lambda: {
                "source_slots": {"applications": {"path": "applications.csv"}},
            },
        )
        observed: list[object] = []

        def application_rows(path: Path, *, event_definition: object):
            observed.extend((path, event_definition))
            return [{"external_id": "second-applicant"}]

        with patch(
            "community_os.real_report._application_rows",
            side_effect=application_rows,
        ):
            records = _load_applications(state)

        self.assertEqual(records, ({"external_id": "second-applicant"},))
        self.assertEqual(observed, [
            root / "protected" / "uploads" / "applications.csv",
            definition,
        ])

    def test_reconciliation_loader_passes_the_operator_event_definition(self) -> None:
        from community_os.event_definition import load_event_definition
        from community_os.release_operations import _load_reconciliation_inputs

        definition = load_event_definition(
            Path(__file__).parent / "fixtures/events/second-hackathon.synthetic.json",
        )
        root = Path("/protected-operator")
        state = SimpleNamespace(
            event_definition=definition,
            protected_uploads=root / "protected" / "uploads",
            snapshot=lambda: {"source_slots": {
                "applications": {"path": "applications.csv"},
                "preferences": {"path": "preferences.xlsx"},
                "submissions": {"path": "submissions.xlsx"},
            }},
        )
        observed: list[object] = []

        def application_rows(path: Path, *, event_definition: object):
            observed.extend((path, event_definition))
            return [{"external_id": "second-applicant"}]

        with (
            patch(
                "community_os.real_report._application_rows",
                side_effect=application_rows,
            ),
            patch(
                "community_os.real_report._group_final_sources",
                return_value=((), (), {}, {}),
            ) as group_sources,
        ):
            inputs = _load_reconciliation_inputs(state)

        self.assertEqual(inputs.applications, ({"external_id": "second-applicant"},))
        self.assertEqual(observed, [
            root / "protected" / "uploads" / "applications.csv",
            definition,
        ])
        group_sources.assert_called_once_with(
            root / "protected" / "uploads" / "preferences.xlsx",
            root / "protected" / "uploads" / "submissions.xlsx",
            event_definition=definition,
        )

    def test_review_case_hash_includes_event_and_approval_context(self) -> None:
        from community_os.release_operations import (
            ReviewCase, _review_case_source_hashes,
        )

        base = {"applications": "a" * 64}
        state_a = SimpleNamespace(
            event_key="event-a", event_definition_sha256="b" * 64,
            snapshot=lambda: {"event_approval": {"sha256": "c" * 64}},
        )
        state_b = SimpleNamespace(
            event_key="event-b", event_definition_sha256="d" * 64,
            snapshot=lambda: {"event_approval": {"sha256": "e" * 64}},
        )
        case_a = ReviewCase.create(
            kind="identity", subject_code="candidate_001",
            reason_codes=("ambiguous_match",), candidate_codes=("person_001",),
            source_hashes=_review_case_source_hashes(state_a, base),
            version="identity_rules_v1",
        )
        case_b = ReviewCase.create(
            kind="identity", subject_code="candidate_001",
            reason_codes=("ambiguous_match",), candidate_codes=("person_001",),
            source_hashes=_review_case_source_hashes(state_b, base),
            version="identity_rules_v1",
        )

        self.assertNotEqual(case_a.case_hash, case_b.case_hash)

    def test_only_current_persisted_cases_can_be_decided(self) -> None:
        from community_os.release_operations import ReviewCase, ReviewDecision, ReviewRepository

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "protected" / "review-cases.json"
            repository = ReviewRepository(path)
            case = ReviewCase.create(
                kind="identity",
                subject_code="candidate_001",
                reason_codes=("email_mismatch",),
                candidate_codes=("person_001",),
                source_hashes={"applications": "a" * 64},
                version="identity_rules_v1",
            )
            repository.replace((case,))

            with self.assertRaisesRegex(ValueError, "unknown review case"):
                repository.decide(
                    ReviewDecision(
                        case_code="identity_missing",
                        case_hash="b" * 64,
                        action="quarantine",
                    ),
                    actor_code="privacy_lead",
                    decided_at=NOW,
                )
            with self.assertRaisesRegex(ValueError, "stale review case"):
                repository.decide(
                    ReviewDecision(
                        case_code=case.case_code,
                        case_hash="b" * 64,
                        action="approve",
                        selected_code="person_001",
                    ),
                    actor_code="privacy_lead",
                    decided_at=NOW,
                )

            repository.decide(
                ReviewDecision(
                    case_code=case.case_code,
                    case_hash=case.case_hash,
                    action="approve",
                    selected_code="person_001",
                ),
                actor_code="privacy_lead",
                decided_at=NOW,
            )
            reopened = ReviewRepository(path)
            resolved = reopened.list(kind="identity")[0]
            self.assertEqual(resolved.status, "resolved")
            self.assertEqual(resolved.decision.action, "approve")
            self.assertEqual(path.parent.stat().st_mode & 0o777, 0o700)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertNotIn("@", path.read_text(encoding="utf-8"))

    def test_refresh_invalidates_decisions_when_case_evidence_changes(self) -> None:
        from community_os.release_operations import ReviewCase, ReviewDecision, ReviewRepository

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "review-cases.json"
            repository = ReviewRepository(path)
            first = ReviewCase.create(
                kind="team",
                subject_code="team_001",
                reason_codes=("ambiguous_match",),
                candidate_codes=("project_001",),
                source_hashes={"preferences": "a" * 64, "submissions": "b" * 64},
                version="team_rules_v1",
            )
            repository.replace((first,))
            repository.decide(
                ReviewDecision(
                    case_code=first.case_code,
                    case_hash=first.case_hash,
                    action="link",
                    selected_code="project_001",
                ),
                actor_code="privacy_lead",
                decided_at=NOW,
            )
            changed = ReviewCase.create(
                kind="team",
                subject_code="team_001",
                reason_codes=("ambiguous_match",),
                candidate_codes=("project_001",),
                source_hashes={"preferences": "c" * 64, "submissions": "b" * 64},
                version="team_rules_v1",
            )
            repository.replace((changed,))

            refreshed = repository.list(kind="team")[0]
            self.assertEqual(refreshed.status, "open")
            self.assertIsNone(refreshed.decision)
            self.assertNotEqual(refreshed.case_hash, first.case_hash)

    def test_unresolved_queue_is_a_hard_barrier(self) -> None:
        from community_os.release_operations import ReviewCase, ReviewRepository

        with tempfile.TemporaryDirectory() as directory:
            repository = ReviewRepository(Path(directory) / "reviews.json")
            repository.replace((ReviewCase.create(
                kind="classification",
                subject_code="case_001",
                reason_codes=("low_confidence",),
                candidate_codes=(),
                source_hashes={"applications": "a" * 64},
                version="semantic_v1",
            ),))
            with self.assertRaisesRegex(PermissionError, "classification review remains open"):
                repository.assert_resolved("identity", "team", "classification")

    def test_resolved_rich_semantic_path_supersedes_open_legacy_classification_queue(self) -> None:
        from community_os.release_operations import (
            ReviewCase, ReviewDecision, ReviewRepository,
        )

        with tempfile.TemporaryDirectory() as directory:
            repository = ReviewRepository(Path(directory) / "reviews.json")
            legacy = ReviewCase.create(
                kind="classification", subject_code="class_001",
                reason_codes=("low_confidence",), candidate_codes=(),
                source_hashes={"applications": "a" * 64},
                version="deterministic_rules_v1",
            )
            rich = ReviewCase.create(
                kind="classification", subject_code="semantic_001",
                reason_codes=("human_review_required",), candidate_codes=(),
                source_hashes={"evidence": "b" * 64},
                version="rich_semantic_review_v1",
            )
            repository.replace((legacy, rich))
            with self.assertRaisesRegex(PermissionError, "classification review remains open"):
                repository.assert_authoritative_classification_resolved()

            repository.decide(
                ReviewDecision(
                    case_code=rich.case_code, case_hash=rich.case_hash,
                    action="approved",
                ),
                actor_code="privacy_lead", decided_at=NOW,
            )

            repository.assert_authoritative_classification_resolved()
            self.assertEqual(
                tuple(
                    case.version
                    for case in repository.authoritative_classification_cases()
                ),
                ("rich_semantic_review_v1",),
            )
            self.assertEqual(
                next(
                    case for case in repository.list(kind="classification")
                    if case.version == "deterministic_rules_v1"
                ).status,
                "open",
            )


class ProductionOperationRegistryTests(unittest.TestCase):
    def _operator_state(self, directory: str):
        from community_os.release_operator import ReleaseOperatorState, ReleaseSourceSlot

        state = ReleaseOperatorState(
            Path(directory), operator_code="privacy_lead",
            event_definition=_current_event_definition(),
        )
        for index, slot in enumerate(ReleaseSourceSlot, start=1):
            body = f"fixture-{slot.value}".encode()
            digest = __import__("hashlib").sha256(body).hexdigest()
            destination = state.record_source(
                slot, sha256=digest, row_count=index, filename=(
                    f"{slot.value}.csv"
                    if slot.value in {"applications", "attendance"}
                    else f"{slot.value}.xlsx"
                ),
            )
            destination.write_bytes(body)
            destination.chmod(0o600)
        return state

    @staticmethod
    def _canonical_sha256(value: object) -> str:
        return hashlib.sha256(json.dumps(
            value, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")).hexdigest()

    @staticmethod
    def _canonical_json_bytes(value: object) -> bytes:
        return json.dumps(
            value, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")

    def _rich_github_import_fixture(
        self, directory: str, *, now: datetime = NOW,
        github_profile: str | None = None,
        first_email_local: str | None = None,
        first_name: tuple[str, str, str] | None = None,
        second_github_profile: str | None = None,
    ) -> tuple[object, Path, bytes, dict[str, object]]:
        from community_os.enrichment.state import (
            PipelineState, StageStatus, pseudonymous_id,
        )
        from community_os.release_operations import _load_applications
        from community_os.release_operator import ReleaseSourceSlot
        from tests.test_release_operator import source_gate
        from tests.test_rich_semantic_assessment import project_packet

        root = Path(directory)
        destination_root = root / "destination"
        source_root = root / "source"
        secret = b"fixture-pseudonym-secret"
        state = self._operator_state(str(destination_root))
        application_bytes = (
            Path(__file__).parent / "fixtures/luma_guests_synthetic.csv"
        ).read_bytes()
        if first_name is not None:
            full, given, family = first_name
            marker = b"Ada Example,Ada,Example"
            replacement = f"{full},{given},{family}".encode("utf-8")
            if application_bytes.count(marker) != 1:
                raise AssertionError("synthetic name fixture marker drifted")
            application_bytes = application_bytes.replace(marker, replacement)
        if first_email_local is not None:
            replacement = f"{first_email_local}@example.org".encode("utf-8")
            if application_bytes.count(b"ada@example.org") != 1:
                raise AssertionError("synthetic email fixture marker drifted")
            application_bytes = application_bytes.replace(
                b"ada@example.org", replacement,
            )
        if github_profile is not None:
            marker = b",ada-example,https://example.org"
            replacement = f",{github_profile},https://example.org".encode("utf-8")
            if application_bytes.count(marker) != 1:
                raise AssertionError("synthetic GitHub fixture marker drifted")
            application_bytes = application_bytes.replace(marker, replacement)
        if second_github_profile is not None:
            identity_marker = b"gst_synthetic_002,Missing Email,Missing,Email,,,,pending"
            identity_replacement = (
                b"gst_synthetic_002,Bob Other,Bob,Other,bob@example.org,,"
                b"2026-07-01T10:00:00Z,pending"
            )
            profile_marker = b"Yes,,missing-email,,,,Friend"
            profile_replacement = (
                "Yes,https://linkedin.com/in/bob-other,"
                f"{second_github_profile},,,,Friend"
            ).encode("utf-8")
            if (
                application_bytes.count(identity_marker) != 1
                or application_bytes.count(profile_marker) != 1
            ):
                raise AssertionError("synthetic second applicant fixture marker drifted")
            application_bytes = application_bytes.replace(
                identity_marker, identity_replacement,
            ).replace(profile_marker, profile_replacement)
        application_path = state.record_source(
            ReleaseSourceSlot.APPLICATIONS,
            sha256=hashlib.sha256(application_bytes).hexdigest(),
            row_count=1, filename="applications.csv",
        )
        application_path.write_bytes(application_bytes)
        application_path.chmod(0o600)
        applications = _load_applications(state)
        gate = source_gate("applicant_supplied_github", 30)
        state.record_public_source_authorization("github", gate, now=now)
        state.pipeline.start("github")
        state.pipeline.complete("github", {
            "output_hash": "d" * 64, "record_count": len(applications),
        })
        destination_stage = destination_root / "protected" / "stages" / "github.json"
        destination_stage.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        (destination_root / "protected").chmod(0o700)
        destination_stage.parent.chmod(0o700)
        destination_stage.write_bytes(b'{"prior":true}\n')
        destination_stage.chmod(0o600)
        state.record_semantic_processor_authorization(
            semantic_processor_approval(), now=now,
        )
        for index, stage in enumerate(
            ("classification", "aggregate", "report", "publish", "analytics"),
            start=1,
        ):
            state.pipeline.start(stage)
            state.pipeline.complete(stage, {
                "output_hash": f"{index:x}" * 64, "record_count": index,
            })

        candidates = []
        subjects = []
        for application in applications:
            external_id = str(application["external_id"])
            profile = str(application["github"])
            subject = pseudonymous_id(external_id, secret=secret, key_version="v1")
            subjects.append(subject)
            candidates.append({
                "profile_sha256": hashlib.sha256(profile.encode("utf-8")).hexdigest(),
                "source_record_ref": "source:application:" + hmac.new(
                    secret, external_id.encode("utf-8"), hashlib.sha256,
                ).hexdigest()[:24],
                "subject_ref": subject,
            })
        candidates.sort(key=lambda item: item["subject_ref"])
        application_sha256 = state.snapshot()["source_slots"]["applications"]["sha256"]
        approval = {
            "approval_id": "rich_github_fixture_001",
            "approval_version": "rich-github-collection-approval-v1",
            "approved_at": (now - timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
            "approved_by": "release_owner",
            "candidate_set_sha256": self._canonical_sha256(candidates),
            "distribution": "internal_only_pending_review",
            "event_definition_sha256": state.event_definition_sha256,
            "event_key": state.event_key,
            "expires_at": (now + timedelta(days=2)).isoformat().replace("+00:00", "Z"),
            "github_authorization_sha256": state.pipeline.stage("github").authorization_hash,
            "max_physical_requests": len(candidates) * 11,
            "max_profiles": len(candidates),
            "purpose": "rich_semantic_project_evidence",
            "release_eligible": False,
            "source_file_sha256": application_sha256,
            "source_scope": "applicant_supplied_public_github",
            "ttl_days": 3,
        }
        approval_sha256 = self._canonical_sha256(approval)
        records = [
            {
                "account_age_days": 1200,
                "evidence_ref": "evidence:github:" + f"{index + 1:x}" * 64,
                "forks_received": 2,
                "last_public_update": "2026-07-01",
                "owned_public_repos_sampled": 4,
                "public_repos": 5,
                "recently_active_repos": 3,
                "rich_project_evidence": [project_packet()],
                "stars_received": 12,
                "state": "observed",
                "subject_ref": subject,
                "technology_codes": ["python"],
            }
            for index, subject in enumerate(subjects)
        ]
        source_pipeline = PipelineState.create(
            source_root / "pipeline-state.json", {"github": StageStatus.LOCKED},
        )
        source_pipeline.unlock("github", gate, now=now)
        source_pipeline.start("github")
        source_pipeline.complete("github", {
            "output_hash": self._canonical_sha256(records),
            "record_count": len(records),
        })
        protected = source_root / "protected"
        stages = protected / "stages"
        for private_directory in (source_root, protected, stages):
            private_directory.mkdir(parents=True, exist_ok=True, mode=0o700)
            private_directory.chmod(0o700)
        approval_path = source_root / "collection-approval.json"
        approval_path.write_text(json.dumps(approval), encoding="utf-8")
        approval_path.chmod(0o600)
        stage_path = stages / "github.json"
        stage_payload = {
            "approval_sha256": approval_sha256,
            "created_at": now.isoformat().replace("+00:00", "Z"),
            "expires_at": approval["expires_at"],
            "records": records,
            "stage": "github",
            "stage_output_version": "protected-stage-output-v1",
        }
        stage_path.write_text(json.dumps(stage_payload), encoding="utf-8")
        stage_path.chmod(0o600)
        return state, source_root, secret, stage_payload

    def _rewrite_rich_github_source_records(
        self, source_root: Path, records: list[dict[str, object]],
    ) -> bytes:
        stage_path = source_root / "protected" / "stages" / "github.json"
        stage_payload = json.loads(stage_path.read_text(encoding="utf-8"))
        stage_payload["records"] = records
        stage_path.write_text(json.dumps(stage_payload), encoding="utf-8")
        stage_path.chmod(0o600)
        source_pipeline = source_root / "pipeline-state.json"
        pipeline_payload = json.loads(source_pipeline.read_text(encoding="utf-8"))
        pipeline_payload["stages"]["github"]["result"] = {
            "output_hash": self._canonical_sha256(records),
            "record_count": len(records),
        }
        source_pipeline.write_text(json.dumps(pipeline_payload), encoding="utf-8")
        source_pipeline.chmod(0o600)
        return stage_path.read_bytes()

    def _write_legacy_rich_github_file_chain_receipt(
        self, source_root: Path,
    ) -> Path:
        stage_path = source_root / "protected" / "stages" / "github.json"
        stage_payload = json.loads(stage_path.read_text(encoding="utf-8"))
        records = sorted(
            stage_payload["records"],
            key=lambda record: hashlib.sha256(
                str(record["subject_ref"]).encode("utf-8"),
            ).hexdigest(),
        )
        stage_payload["records"] = records
        stage_path.write_bytes(self._canonical_json_bytes(stage_payload) + b"\n")
        stage_path.chmod(0o600)

        records_dir = source_root / "records"
        records_dir.mkdir(mode=0o700)
        records_dir.chmod(0o700)
        record_file_hashes: list[str] = []
        for record in records:
            filename = hashlib.sha256(
                str(record["subject_ref"]).encode("utf-8"),
            ).hexdigest() + ".json"
            payload = self._canonical_json_bytes(record) + b"\n"
            path = records_dir / filename
            path.write_bytes(payload)
            path.chmod(0o600)
            record_file_hashes.append(hashlib.sha256(payload).hexdigest())

        source_pipeline = source_root / "pipeline-state.json"
        pipeline_payload = json.loads(source_pipeline.read_text(encoding="utf-8"))
        pipeline_payload["stages"]["github"]["result"] = {
            "output_hash": self._canonical_sha256(record_file_hashes),
            "record_count": len(records),
        }
        source_pipeline.write_bytes(self._canonical_json_bytes(pipeline_payload) + b"\n")
        source_pipeline.chmod(0o600)
        return records_dir

    def test_imports_approval_bound_rich_github_stage_without_refetching(self) -> None:
        from community_os.release_operations import import_protected_rich_github_stage

        with tempfile.TemporaryDirectory() as directory:
            state, source_root, secret, stage_payload = (
                self._rich_github_import_fixture(directory)
            )
            source = source_root / "protected" / "stages" / "github.json"
            destination = state.root / "protected" / "stages" / "github.json"

            receipt = import_protected_rich_github_stage(
                state, source_root=source_root, pseudonym_secret=secret,
                clock=lambda: NOW,
            )

            self.assertEqual(
                json.loads(destination.read_text(encoding="utf-8")),
                json.loads(source.read_text(encoding="utf-8")),
            )
            self.assertNotEqual(destination.read_bytes(), source.read_bytes())
            self.assertEqual(destination.stat().st_mode & 0o777, 0o600)
            self.assertEqual(source.stat().st_mode & 0o777, 0o600)
            self.assertEqual(
                (source_root / "collection-approval.json").stat().st_mode & 0o777,
                0o600,
            )
            self.assertEqual(source.parent.stat().st_mode & 0o777, 0o700)
            self.assertFalse(list(destination.parent.glob("github.json.*.tmp")))
            installed = destination.read_text(encoding="utf-8").casefold()
            for forbidden in ("ada example", "ada-example", "github.com", "https://"):
                self.assertNotIn(forbidden, installed)
            source_sha256 = hashlib.sha256(source.read_bytes()).hexdigest()
            destination_sha256 = hashlib.sha256(destination.read_bytes()).hexdigest()
            output_hash = self._canonical_sha256(stage_payload["records"])
            self.assertEqual(receipt, {
                "destination_output_hash": output_hash,
                "destination_stage_sha256": destination_sha256,
                "normalization_count": 0,
                "record_count": 1,
                "receipt_version": "protected-rich-github-stage-import-v2",
                "redaction_count": 0,
                "rich_subject_count": 1,
                "source_output_hash": output_hash,
                "source_receipt_scheme": "canonical-record-array-v1",
                "source_stage_sha256": source_sha256,
            })
            github = state.pipeline.stage("github")
            self.assertEqual(github.status.value, "complete")
            self.assertEqual(github.result, {
                "output_hash": self._canonical_sha256(stage_payload["records"]),
                "record_count": 1,
            })
            self.assertEqual(state.snapshot()["release_state"], "Blocked")
            for stage in (
                "classification", "aggregate", "report", "publish", "analytics",
            ):
                self.assertEqual(state.pipeline.stage(stage).status.value, "allowed")

    def test_imports_exact_legacy_rich_github_file_chain_receipt(self) -> None:
        from community_os.release_operations import import_protected_rich_github_stage

        with tempfile.TemporaryDirectory() as directory:
            state, source_root, secret, _stage_payload = (
                self._rich_github_import_fixture(
                    directory, second_github_profile="other-builder",
                )
            )
            self._write_legacy_rich_github_file_chain_receipt(source_root)
            source = source_root / "protected" / "stages" / "github.json"
            source_before = source.read_bytes()

            receipt = import_protected_rich_github_stage(
                state, source_root=source_root, pseudonym_secret=secret,
                clock=lambda: NOW,
            )

            stage_records = json.loads(source_before)["records"]
            pipeline = json.loads(
                (source_root / "pipeline-state.json").read_text(encoding="utf-8"),
            )
            legacy_output_hash = pipeline["stages"]["github"]["result"]["output_hash"]
            self.assertNotEqual(
                legacy_output_hash, self._canonical_sha256(stage_records),
            )
            self.assertEqual(
                receipt["source_output_hash"], legacy_output_hash,
            )
            self.assertEqual(
                receipt["source_receipt_scheme"],
                "legacy-record-file-sha256-chain-v1",
            )
            self.assertEqual(source.read_bytes(), source_before)

    def test_legacy_rich_github_receipt_rejects_record_contract_violations(self) -> None:
        from community_os.release_operations import import_protected_rich_github_stage

        mutations = {
            "extra_entry": "legacy rich GitHub records",
            "wrong_filename": "legacy rich GitHub records",
            "noncanonical_json": "legacy rich GitHub record",
            "nonprivate_file": "legacy rich GitHub record",
            "nonprivate_directory": "legacy rich GitHub records",
            "symlink_file": "legacy rich GitHub record",
            "symlink_directory": "legacy rich GitHub records",
            "hardlink_file": "legacy rich GitHub record",
            "directory_instead_of_file": "legacy rich GitHub record",
            "record_content_mismatch": "do not exactly match the stage",
            "pipeline_hash": "legacy rich GitHub file-chain receipt",
            "approval_version": "collection approval scope",
            "approval_purpose": "collection approval scope",
        }
        for mutation, message in mutations.items():
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                state, source_root, secret, _stage_payload = (
                    self._rich_github_import_fixture(directory)
                )
                records_dir = self._write_legacy_rich_github_file_chain_receipt(
                    source_root,
                )
                record_path = next(records_dir.glob("*.json"))
                if mutation == "extra_entry":
                    extra = records_dir / "unexpected.tmp"
                    extra.write_bytes(b"unexpected")
                    extra.chmod(0o600)
                elif mutation == "wrong_filename":
                    record_path.rename(records_dir / ("f" * 64 + ".json"))
                elif mutation == "noncanonical_json":
                    record = json.loads(record_path.read_text(encoding="utf-8"))
                    record_path.write_text(json.dumps(record), encoding="utf-8")
                    record_path.chmod(0o600)
                elif mutation == "nonprivate_file":
                    record_path.chmod(0o644)
                elif mutation == "nonprivate_directory":
                    records_dir.chmod(0o755)
                elif mutation == "symlink_file":
                    target = source_root / "legacy-record-target.json"
                    record_path.rename(target)
                    record_path.symlink_to(Path("..") / target.name)
                elif mutation == "symlink_directory":
                    target = source_root / "legacy-records-target"
                    records_dir.rename(target)
                    records_dir.symlink_to(target.name, target_is_directory=True)
                elif mutation == "hardlink_file":
                    target = source_root / "legacy-record-target.json"
                    target.write_bytes(record_path.read_bytes())
                    target.chmod(0o600)
                    record_path.unlink()
                    os.link(target, record_path)
                elif mutation == "directory_instead_of_file":
                    target = source_root / "legacy-record-target.json"
                    record_path.rename(target)
                    record_path.mkdir(mode=0o700)
                elif mutation == "record_content_mismatch":
                    record = json.loads(record_path.read_text(encoding="utf-8"))
                    record["stars_received"] += 1
                    payload = self._canonical_json_bytes(record) + b"\n"
                    record_path.write_bytes(payload)
                    record_path.chmod(0o600)
                    pipeline_path = source_root / "pipeline-state.json"
                    pipeline = json.loads(pipeline_path.read_text(encoding="utf-8"))
                    pipeline["stages"]["github"]["result"]["output_hash"] = (
                        self._canonical_sha256([hashlib.sha256(payload).hexdigest()])
                    )
                    pipeline_path.write_bytes(self._canonical_json_bytes(pipeline) + b"\n")
                    pipeline_path.chmod(0o600)
                elif mutation == "pipeline_hash":
                    pipeline_path = source_root / "pipeline-state.json"
                    pipeline = json.loads(pipeline_path.read_text(encoding="utf-8"))
                    pipeline["stages"]["github"]["result"]["output_hash"] = "f" * 64
                    pipeline_path.write_bytes(self._canonical_json_bytes(pipeline) + b"\n")
                    pipeline_path.chmod(0o600)
                else:
                    approval_path = source_root / "collection-approval.json"
                    approval = json.loads(approval_path.read_text(encoding="utf-8"))
                    approval[
                        "approval_version" if mutation == "approval_version" else "purpose"
                    ] = "unsupported"
                    approval_path.write_bytes(self._canonical_json_bytes(approval) + b"\n")
                    approval_path.chmod(0o600)
                destination = state.root / "protected" / "stages" / "github.json"
                destination_before = destination.read_bytes()

                with self.assertRaisesRegex((PermissionError, ValueError), message):
                    import_protected_rich_github_stage(
                        state, source_root=source_root, pseudonym_secret=secret,
                        clock=lambda: NOW,
                    )

                self.assertEqual(destination.read_bytes(), destination_before)

    def test_legacy_rich_github_receipt_rejects_stage_order_not_bound_to_sorted_files(self) -> None:
        from community_os.release_operations import import_protected_rich_github_stage

        with tempfile.TemporaryDirectory() as directory:
            state, source_root, secret, _stage_payload = (
                self._rich_github_import_fixture(
                    directory, second_github_profile="other-builder",
                )
            )
            self._write_legacy_rich_github_file_chain_receipt(source_root)
            stage_path = source_root / "protected" / "stages" / "github.json"
            stage = json.loads(stage_path.read_text(encoding="utf-8"))
            stage["records"].reverse()
            stage_path.write_bytes(self._canonical_json_bytes(stage) + b"\n")
            stage_path.chmod(0o600)
            destination = state.root / "protected" / "stages" / "github.json"
            destination_before = destination.read_bytes()

            with self.assertRaisesRegex(
                PermissionError, "sorted stage subjects",
            ):
                import_protected_rich_github_stage(
                    state, source_root=source_root, pseudonym_secret=secret,
                    clock=lambda: NOW,
                )

            self.assertEqual(destination.read_bytes(), destination_before)

    def test_legacy_rich_github_receipt_detects_all_record_races_and_rolls_back(self) -> None:
        from community_os.release_operations import import_protected_rich_github_stage

        for mutation in ("replace", "in_place", "add", "delete", "replace_directory"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                state, source_root, secret, _stage_payload = (
                    self._rich_github_import_fixture(directory)
                )
                records_dir = self._write_legacy_rich_github_file_chain_receipt(
                    source_root,
                )
                record_path = next(records_dir.glob("*.json"))
                destination = state.root / "protected" / "stages" / "github.json"
                destination_before = destination.read_bytes()
                original_install = state.install_imported_github_stage

                def mutate_between_guards(**kwargs: object) -> None:
                    source_guard = kwargs["source_guard"]
                    guard_calls = 0

                    def guarded_source() -> None:
                        nonlocal guard_calls
                        source_guard()
                        guard_calls += 1
                        if guard_calls != 1:
                            return
                        original = record_path.read_bytes()
                        if mutation == "replace":
                            replacement = record_path.with_name(
                                record_path.name + ".replacement",
                            )
                            replacement.write_bytes(original)
                            replacement.chmod(0o600)
                            os.replace(replacement, record_path)
                        elif mutation == "in_place":
                            record_path.write_bytes(original + b"\n")
                            record_path.chmod(0o600)
                        elif mutation == "add":
                            added = records_dir / ("f" * 64 + ".json")
                            added.write_bytes(original)
                            added.chmod(0o600)
                        elif mutation == "delete":
                            record_path.unlink()
                        else:
                            original_dir = records_dir.with_name("records-original")
                            records_dir.rename(original_dir)
                            records_dir.mkdir(mode=0o700)
                            copied = records_dir / record_path.name
                            copied.write_bytes(
                                (original_dir / record_path.name).read_bytes(),
                            )
                            copied.chmod(0o600)

                    kwargs["source_guard"] = guarded_source
                    original_install(**kwargs)

                with (
                    patch.object(
                        state, "install_imported_github_stage",
                        side_effect=mutate_between_guards,
                    ),
                    self.assertRaisesRegex(
                        PermissionError, "changed during protected import",
                    ),
                ):
                    import_protected_rich_github_stage(
                        state, source_root=source_root, pseudonym_secret=secret,
                        clock=lambda: NOW,
                    )

                self.assertEqual(destination.read_bytes(), destination_before)
                self.assertEqual(state.pipeline.stage("github").status.value, "failed")

    def test_rich_github_import_projects_only_own_derived_identifiers(self) -> None:
        from community_os.release_operations import import_protected_rich_github_stage

        with tempfile.TemporaryDirectory() as directory:
            state, source_root, secret, stage_payload = (
                self._rich_github_import_fixture(
                    directory,
                    github_profile="commonword",
                    first_email_local="ownmail",
                    second_github_profile="other-builder",
                )
            )
            first_project = stage_payload["records"][0]["rich_project_evidence"][0]
            second_project = stage_payload["records"][1]["rich_project_evidence"][0]
            first_project["description_excerpt"] = (
                "built ownmail commonword ada-example workflow"
            )
            second_project["description_excerpt"] = (
                "built commonword workflow with ada example"
            )
            source_bytes = self._rewrite_rich_github_source_records(
                source_root, stage_payload["records"],
            )
            source_path = source_root / "protected" / "stages" / "github.json"

            receipt = import_protected_rich_github_stage(
                state, source_root=source_root, pseudonym_secret=secret,
                clock=lambda: NOW,
            )

            self.assertEqual(source_path.read_bytes(), source_bytes)
            destination_path = state.root / "protected" / "stages" / "github.json"
            destination_bytes = destination_path.read_bytes()
            destination = json.loads(destination_bytes)
            first_text = json.dumps(
                destination["records"][0]["rich_project_evidence"],
            ).casefold()
            second_text = json.dumps(
                destination["records"][1]["rich_project_evidence"],
            ).casefold()
            for own_literal in ("ownmail", "commonword", "ada-example"):
                self.assertNotIn(own_literal, first_text)
            self.assertIn("commonword", second_text)
            self.assertNotIn("ada example", second_text)
            self.assertEqual(
                receipt["source_stage_sha256"],
                hashlib.sha256(source_bytes).hexdigest(),
            )
            self.assertEqual(
                receipt["destination_stage_sha256"],
                hashlib.sha256(destination_bytes).hexdigest(),
            )
            self.assertNotEqual(
                receipt["source_stage_sha256"],
                receipt["destination_stage_sha256"],
            )
            self.assertGreaterEqual(receipt["redaction_count"], 2)
            self.assertGreaterEqual(receipt["normalization_count"], 0)
            self.assertEqual(
                state.pipeline.stage("github").result,
                {
                    "output_hash": self._canonical_sha256(destination["records"]),
                    "record_count": 2,
                },
            )
            serialized_receipt = json.dumps(receipt).casefold()
            for forbidden in (
                "ownmail", "commonword", "ada-example", "ada example",
                "bob other", "other-builder",
            ):
                self.assertNotIn(forbidden, serialized_receipt)

    def test_rich_github_import_redacts_email_local_inside_snake_case_prose(self) -> None:
        from community_os.release_operations import import_protected_rich_github_stage

        with tempfile.TemporaryDirectory() as directory:
            state, source_root, secret, stage_payload = (
                self._rich_github_import_fixture(
                    directory, first_email_local="ownmail",
                )
            )
            project = stage_payload["records"][0]["rich_project_evidence"][0]
            project["readme_excerpt"] = "uses ownmail_cache for workflow state"
            self._rewrite_rich_github_source_records(
                source_root, stage_payload["records"],
            )

            receipt = import_protected_rich_github_stage(
                state, source_root=source_root, pseudonym_secret=secret,
                clock=lambda: NOW,
            )

            destination = json.loads((
                state.root / "protected" / "stages" / "github.json"
            ).read_text(encoding="utf-8"))
            readme = destination["records"][0]["rich_project_evidence"][0][
                "readme_excerpt"
            ]
            self.assertNotIn("ownmail", readme.casefold())
            self.assertGreaterEqual(receipt["redaction_count"], 1)

    def test_rich_github_import_resanitizes_repository_shorthand(self) -> None:
        from community_os.release_operations import import_protected_rich_github_stage

        with tempfile.TemporaryDirectory() as directory:
            state, source_root, secret, stage_payload = (
                self._rich_github_import_fixture(directory)
            )
            project = stage_payload["records"][0]["rich_project_evidence"][0]
            project["readme_excerpt"] = (
                "repo: /sample-owner/sample-project and built a working product."
            )
            self._rewrite_rich_github_source_records(
                source_root, stage_payload["records"],
            )

            receipt = import_protected_rich_github_stage(
                state, source_root=source_root, pseudonym_secret=secret,
                clock=lambda: NOW,
            )

            destination = json.loads((
                state.root / "protected" / "stages" / "github.json"
            ).read_text(encoding="utf-8"))
            readme = destination["records"][0]["rich_project_evidence"][0][
                "readme_excerpt"
            ]
            self.assertNotIn("sample-owner", readme)
            self.assertNotIn("sample-project", readme)
            self.assertIn("built a working product", readme)
            self.assertGreaterEqual(receipt["redaction_count"], 1)

    def test_rich_github_import_resanitizes_structural_identifier_variants(self) -> None:
        from community_os.release_operations import import_protected_rich_github_stage

        with tempfile.TemporaryDirectory() as directory:
            state, source_root, secret, stage_payload = (
                self._rich_github_import_fixture(directory)
            )
            project = stage_payload["records"][0]["rich_project_evidence"][0]
            project["readme_excerpt"] = (
                "compared owner/repository. demo example .com. "
                "built a working product."
            )
            self._rewrite_rich_github_source_records(
                source_root, stage_payload["records"],
            )

            receipt = import_protected_rich_github_stage(
                state, source_root=source_root, pseudonym_secret=secret,
                clock=lambda: NOW,
            )

            destination = json.loads((
                state.root / "protected" / "stages" / "github.json"
            ).read_text(encoding="utf-8"))
            readme = destination["records"][0]["rich_project_evidence"][0][
                "readme_excerpt"
            ]
            self.assertNotIn("owner/repository", readme)
            self.assertNotIn("example .com", readme)
            self.assertIn("working product", readme.casefold())
            self.assertGreaterEqual(receipt["redaction_count"], 1)

    def test_rich_github_import_resanitizes_all_current_identifier_markers(self) -> None:
        from community_os.release_operations import import_protected_rich_github_stage

        with tempfile.TemporaryDirectory() as directory:
            state, source_root, secret, stage_payload = (
                self._rich_github_import_fixture(directory)
            )
            project = stage_payload["records"][0]["rich_project_evidence"][0]
            project["readme_excerpt"] = (
                "deployed in warsaw. demo privateproduct .us. "
                "contact john[at]example[dot]com. built a working product."
            )
            self._rewrite_rich_github_source_records(
                source_root, stage_payload["records"],
            )

            receipt = import_protected_rich_github_stage(
                state, source_root=source_root, pseudonym_secret=secret,
                clock=lambda: NOW,
            )

            destination = json.loads((
                state.root / "protected" / "stages" / "github.json"
            ).read_text(encoding="utf-8"))
            readme = destination["records"][0]["rich_project_evidence"][0][
                "readme_excerpt"
            ]
            for forbidden in (
                "warsaw", "privateproduct", "john", "example",
            ):
                self.assertNotIn(forbidden, readme.casefold())
            self.assertIn("working product", readme.casefold())
            self.assertGreaterEqual(receipt["redaction_count"], 1)

    def test_rich_github_import_identity_corpus_includes_submission_context(self) -> None:
        from community_os.release_operations import (
            ReconciliationInputs,
            _rich_github_import_identity_corpus,
        )

        applications = ({
            "external_id": "app-1",
            "name": "Application Identity",
            "email": "application@example.org",
        },)
        submission = SimpleNamespace(
            external_id="submission-1",
            name="Submission Identity",
            email="submission@example.org",
            team_name="Private Team",
            submission_title="Private Project",
        )
        state = SimpleNamespace(snapshot=lambda: {
            "event_approval": {},
            "source_slots": {
                "applications": {},
                "attendance": {},
                "preferences": {},
                "submissions": {},
            },
        })
        inputs = ReconciliationInputs(
            applications=applications,
            preference_records=(),
            submission_records=(submission,),
            preferences={},
            projects={},
        )

        with patch(
            "community_os.release_operations._load_reconciliation_inputs",
            return_value=inputs,
        ):
            corpus = _rich_github_import_identity_corpus(state, applications)

        self.assertIn("Application Identity", corpus)
        self.assertIn("Submission Identity", corpus)
        self.assertIn("Private Team", corpus)
        self.assertIn("Private Project", corpus)

    def test_rich_github_import_redacts_own_two_character_name_only(self) -> None:
        from community_os.release_operations import import_protected_rich_github_stage

        with tempfile.TemporaryDirectory() as directory:
            state, source_root, secret, stage_payload = (
                self._rich_github_import_fixture(
                    directory,
                    first_name=("Li Wei", "Li", "Wei"),
                    second_github_profile="other-builder",
                )
            )
            first_project = stage_payload["records"][0]["rich_project_evidence"][0]
            second_project = stage_payload["records"][1]["rich_project_evidence"][0]
            first_project["description_excerpt"] = "Built by Li. I designed data tooling."
            second_project["description_excerpt"] = "Built li tooling for data workflows."
            self._rewrite_rich_github_source_records(
                source_root, stage_payload["records"],
            )

            import_protected_rich_github_stage(
                state, source_root=source_root, pseudonym_secret=secret,
                clock=lambda: NOW,
            )

            destination = json.loads(
                (state.root / "protected" / "stages" / "github.json").read_text(
                    encoding="utf-8",
                )
            )
            first_text = destination["records"][0]["rich_project_evidence"][0][
                "description_excerpt"
            ]
            second_text = destination["records"][1]["rich_project_evidence"][0][
                "description_excerpt"
            ]
            self.assertNotRegex(first_text.casefold(), r"\bli\b")
            self.assertIn("I designed data tooling", first_text)
            self.assertRegex(second_text.casefold(), r"\bli\b")

    def test_rich_github_import_redacts_own_byline_initial_without_erasing_prose(self) -> None:
        from community_os.release_operations import import_protected_rich_github_stage

        with tempfile.TemporaryDirectory() as directory:
            state, source_root, secret, stage_payload = (
                self._rich_github_import_fixture(
                    directory, first_name=("X Wei", "X", "Wei"),
                )
            )
            project = stage_payload["records"][0]["rich_project_evidence"][0]
            project["description_excerpt"] = (
                "I built x ray tooling. Built by X."
            )
            self._rewrite_rich_github_source_records(
                source_root, stage_payload["records"],
            )

            import_protected_rich_github_stage(
                state, source_root=source_root, pseudonym_secret=secret,
                clock=lambda: NOW,
            )

            destination = json.loads(
                (state.root / "protected" / "stages" / "github.json").read_text(
                    encoding="utf-8",
                )
            )
            text = destination["records"][0]["rich_project_evidence"][0][
                "description_excerpt"
            ]
            self.assertIn("I built x ray tooling", text)
            self.assertNotRegex(text, r"(?i)\bby\s+x\b")

    def test_rich_github_import_fails_closed_if_own_byline_initial_survives(self) -> None:
        from community_os.release_operations import import_protected_rich_github_stage

        with tempfile.TemporaryDirectory() as directory:
            state, source_root, secret, stage_payload = (
                self._rich_github_import_fixture(
                    directory, first_name=("X Wei", "X", "Wei"),
                )
            )
            stage_payload["records"][0]["rich_project_evidence"][0][
                "description_excerpt"
            ] = "Built by X."
            self._rewrite_rich_github_source_records(
                source_root, stage_payload["records"],
            )
            destination = state.root / "protected" / "stages" / "github.json"
            before = destination.read_bytes()

            with (
                patch(
                    "community_os.enrichment.semantic_evidence.sanitize_professional_text",
                    side_effect=lambda value, **_kwargs: value,
                ),
                self.assertRaisesRegex(ValueError, "known identity literal"),
            ):
                import_protected_rich_github_stage(
                    state, source_root=source_root, pseudonym_secret=secret,
                    clock=lambda: NOW,
                )

            self.assertEqual(destination.read_bytes(), before)

    def test_rich_github_import_of_clean_stage_is_deterministic(self) -> None:
        from community_os.release_operations import import_protected_rich_github_stage

        with tempfile.TemporaryDirectory() as directory:
            state, source_root, secret, _stage_payload = (
                self._rich_github_import_fixture(directory)
            )
            source_path = source_root / "protected" / "stages" / "github.json"
            source_before = source_path.read_bytes()

            first = import_protected_rich_github_stage(
                state, source_root=source_root, pseudonym_secret=secret,
                clock=lambda: NOW,
            )
            destination = state.root / "protected" / "stages" / "github.json"
            destination_first = destination.read_bytes()
            second = import_protected_rich_github_stage(
                state, source_root=source_root, pseudonym_secret=secret,
                clock=lambda: NOW,
            )

            self.assertEqual(source_path.read_bytes(), source_before)
            self.assertEqual(destination.read_bytes(), destination_first)
            self.assertEqual(
                first["destination_stage_sha256"],
                second["destination_stage_sha256"],
            )
            self.assertEqual(first["redaction_count"], 0)
            self.assertEqual(second["redaction_count"], 0)

    def test_rich_github_import_validates_source_receipt_before_projection(self) -> None:
        from community_os.release_operations import import_protected_rich_github_stage

        with tempfile.TemporaryDirectory() as directory:
            state, source_root, secret, _stage_payload = (
                self._rich_github_import_fixture(
                    directory, first_email_local="ownmail",
                )
            )
            source_stage = source_root / "protected" / "stages" / "github.json"
            payload = json.loads(source_stage.read_text(encoding="utf-8"))
            payload["records"][0]["rich_project_evidence"][0][
                "description_excerpt"
            ] = "built ownmail workflow"
            source_stage.write_text(json.dumps(payload), encoding="utf-8")
            source_stage.chmod(0o600)
            destination = state.root / "protected" / "stages" / "github.json"
            destination_before = destination.read_bytes()

            with self.assertRaisesRegex(PermissionError, "pipeline receipt"):
                import_protected_rich_github_stage(
                    state, source_root=source_root, pseudonym_secret=secret,
                    clock=lambda: NOW,
                )

            self.assertEqual(destination.read_bytes(), destination_before)

    def test_rich_github_import_rejects_duplicate_or_unbound_stage_subjects(self) -> None:
        from community_os.release_operations import import_protected_rich_github_stage

        for mutation, message in (
            ("duplicate", "duplicated"),
            ("unbound", "do not match"),
        ):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                state, source_root, secret, stage_payload = (
                    self._rich_github_import_fixture(
                        directory,
                        second_github_profile=(
                            "other-builder" if mutation == "duplicate" else None
                        ),
                    )
                )
                records = stage_payload["records"]
                if mutation == "duplicate":
                    records[1]["subject_ref"] = records[0]["subject_ref"]
                else:
                    records[0]["subject_ref"] = "pid:v1:" + "f" * 64
                self._rewrite_rich_github_source_records(source_root, records)
                destination = state.root / "protected" / "stages" / "github.json"
                destination_before = destination.read_bytes()

                with self.assertRaisesRegex((ValueError, PermissionError), message):
                    import_protected_rich_github_stage(
                        state, source_root=source_root,
                        pseudonym_secret=secret, clock=lambda: NOW,
                    )

                self.assertEqual(destination.read_bytes(), destination_before)

    def test_rich_github_projection_fails_closed_if_redaction_leaves_identity(self) -> None:
        from community_os.release_operations import import_protected_rich_github_stage

        with tempfile.TemporaryDirectory() as directory:
            state, source_root, secret, stage_payload = (
                self._rich_github_import_fixture(
                    directory, first_email_local="ownmail",
                )
            )
            stage_payload["records"][0]["rich_project_evidence"][0][
                "description_excerpt"
            ] = "built ownmail workflow"
            self._rewrite_rich_github_source_records(
                source_root, stage_payload["records"],
            )
            destination = state.root / "protected" / "stages" / "github.json"
            destination_before = destination.read_bytes()

            with (
                patch(
                    "community_os.enrichment.semantic_evidence.sanitize_professional_text",
                    side_effect=lambda value, **_kwargs: value,
                ),
                self.assertRaisesRegex(ValueError, "known identity literal"),
            ):
                import_protected_rich_github_stage(
                    state, source_root=source_root, pseudonym_secret=secret,
                    clock=lambda: NOW,
                )

            self.assertEqual(destination.read_bytes(), destination_before)

    def test_subject_identity_mapping_rejects_duplicate_applications(self) -> None:
        from community_os.release_operations import (
            _application_subject_identity_literals,
        )

        application = {
            "external_id": "app-1", "name": "Private Person",
            "email": "private@example.org", "github": "private-handle",
        }
        with self.assertRaisesRegex(ValueError, "unique identifiers"):
            _application_subject_identity_literals(
                (application, dict(application)),
                pseudonym_secret=b"fixture-pseudonym-secret",
            )

    def test_subject_identity_mapping_marks_name_initials_contextually(self) -> None:
        from community_os.release_operations import (
            _application_subject_identity_literals,
        )

        mapping = _application_subject_identity_literals(
            ({
                "external_id": "app-1", "name": "X Wei",
                "email": "private@example.org", "github": "private-handle",
            },),
            pseudonym_secret=b"fixture-pseudonym-secret",
        )

        literals = next(iter(mapping.values()))
        self.assertIn("subject-initial:X", literals)
        self.assertNotIn("X", literals)

    def test_rich_github_import_has_no_application_loader_injection_surface(self) -> None:
        import inspect
        from community_os.release_operations import import_protected_rich_github_stage

        self.assertNotIn(
            "application_loader",
            inspect.signature(import_protected_rich_github_stage).parameters,
        )

    def test_rich_github_import_rejects_source_drift_and_preserves_destination(self) -> None:
        from community_os.release_operations import import_protected_rich_github_stage

        with tempfile.TemporaryDirectory() as directory:
            state, source_root, secret, _stage_payload = (
                self._rich_github_import_fixture(directory)
            )
            destination = state.root / "protected" / "stages" / "github.json"
            before = destination.read_bytes()
            application_path = state.protected_uploads / "applications.csv"
            application_path.write_bytes(b"drifted-applications")
            application_path.chmod(0o600)

            with self.assertRaisesRegex(PermissionError, "application source hash drifted"):
                import_protected_rich_github_stage(
                    state, source_root=source_root, pseudonym_secret=secret,
                    clock=lambda: NOW,
                )

            self.assertEqual(destination.read_bytes(), before)

    def test_rich_github_import_rejects_nonprivate_approval_and_preserves_destination(self) -> None:
        from community_os.release_operations import import_protected_rich_github_stage

        with tempfile.TemporaryDirectory() as directory:
            state, source_root, secret, _stage_payload = (
                self._rich_github_import_fixture(directory)
            )
            destination = state.root / "protected" / "stages" / "github.json"
            before = destination.read_bytes()
            (source_root / "collection-approval.json").chmod(0o644)

            with self.assertRaisesRegex(PermissionError, "0600"):
                import_protected_rich_github_stage(
                    state, source_root=source_root, pseudonym_secret=secret,
                    clock=lambda: NOW,
                )

            self.assertEqual(destination.read_bytes(), before)

    def test_rich_github_import_rejects_symlinked_source_root_and_preserves_destination(self) -> None:
        from community_os.release_operations import import_protected_rich_github_stage

        with tempfile.TemporaryDirectory() as directory:
            state, source_root, secret, _stage_payload = (
                self._rich_github_import_fixture(directory)
            )
            destination = state.root / "protected" / "stages" / "github.json"
            before = destination.read_bytes()
            symlink = Path(directory) / "source-link"
            symlink.symlink_to(source_root, target_is_directory=True)

            with self.assertRaisesRegex(PermissionError, "non-symlink directory"):
                import_protected_rich_github_stage(
                    state, source_root=symlink, pseudonym_secret=secret,
                    clock=lambda: NOW,
                )

            self.assertEqual(destination.read_bytes(), before)

    def test_rich_github_import_rejects_symlinked_source_ancestor(self) -> None:
        from community_os.release_operations import import_protected_rich_github_stage

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            real_parent = root / "real-parent"
            real_parent.mkdir(mode=0o700)
            state, source_root, secret, _stage_payload = (
                self._rich_github_import_fixture(str(real_parent / "fixture"))
            )
            alias_parent = root / "alias-parent"
            alias_parent.symlink_to(real_parent, target_is_directory=True)
            aliased_source = alias_parent / "fixture" / "source"
            destination = state.root / "protected" / "stages" / "github.json"
            before = destination.read_bytes()
            pipeline_before = state.pipeline.to_dict()

            with self.assertRaisesRegex(PermissionError, "symlink ancestor"):
                import_protected_rich_github_stage(
                    state, source_root=aliased_source, pseudonym_secret=secret,
                    clock=lambda: NOW,
                )

            self.assertEqual(destination.read_bytes(), before)
            self.assertEqual(state.pipeline.to_dict(), pipeline_before)

    def test_rich_github_import_rejects_protected_input_swap_during_safe_open(self) -> None:
        from community_os.release_operations import import_protected_rich_github_stage

        targets = (
            ("approval", "source", ("collection-approval.json",)),
            ("source_pipeline", "source", ("pipeline-state.json",)),
            ("source_stage", "source", ("protected", "stages", "github.json")),
            ("destination_pipeline", "destination", ("pipeline-state.json",)),
            ("destination_stage", "destination", ("protected", "stages", "github.json")),
            ("application", "destination", ("protected", "uploads", "applications.csv")),
        )
        for target_code, owner, relative in targets:
            with self.subTest(target=target_code), tempfile.TemporaryDirectory() as directory:
                state, source_root, secret, _stage_payload = (
                    self._rich_github_import_fixture(directory)
                )
                destination = state.root / "protected" / "stages" / "github.json"
                before = destination.read_bytes()
                pipeline_before = state.pipeline.to_dict()
                base = source_root if owner == "source" else state.root
                target = base.joinpath(*relative)
                backup = target.with_name(target.name + ".original")
                parent_metadata = target.parent.stat()
                real_open = os.open
                swapped = False

                def swap_before_open(
                    path: object, flags: int, mode: int = 0o777,
                    *, dir_fd: int | None = None,
                ) -> int:
                    nonlocal swapped
                    if (
                        path == target.name
                        and dir_fd is not None
                        and not swapped
                        and (os.fstat(dir_fd).st_dev, os.fstat(dir_fd).st_ino)
                        == (parent_metadata.st_dev, parent_metadata.st_ino)
                    ):
                        target.rename(backup)
                        target.symlink_to(backup.name)
                        swapped = True
                    return real_open(path, flags, mode, dir_fd=dir_fd)

                with (
                    patch(
                        "community_os.release_operations.os.open",
                        side_effect=swap_before_open,
                    ),
                    self.assertRaisesRegex(PermissionError, "unsafe protected file"),
                ):
                    import_protected_rich_github_stage(
                        state, source_root=source_root, pseudonym_secret=secret,
                        clock=lambda: NOW,
                    )

                self.assertTrue(swapped)
                self.assertEqual(destination.read_bytes(), before)
                self.assertEqual(state.pipeline.to_dict(), pipeline_before)

    def test_rich_github_import_fails_closed_on_source_drift_before_commit(self) -> None:
        from community_os.release_operations import import_protected_rich_github_stage

        targets = (
            ("approval", ("collection-approval.json",)),
            ("source_pipeline", ("pipeline-state.json",)),
            ("source_stage", ("protected", "stages", "github.json")),
        )
        for target_code, relative in targets:
            for mutation in ("replace", "in_place"):
                with (
                    self.subTest(target=target_code, mutation=mutation),
                    tempfile.TemporaryDirectory() as directory,
                ):
                    state, source_root, secret, _stage_payload = (
                        self._rich_github_import_fixture(directory)
                    )
                    destination = state.root / "protected" / "stages" / "github.json"
                    destination_before = destination.read_bytes()
                    target = source_root.joinpath(*relative)
                    original_install = state.install_imported_github_stage
                    mutated = False

                    def mutate_before_install(**kwargs: object) -> None:
                        nonlocal mutated
                        original = target.read_bytes()
                        if mutation == "replace":
                            replacement = target.with_name(target.name + ".replacement")
                            replacement.write_bytes(original)
                            replacement.chmod(0o600)
                            os.replace(replacement, target)
                        else:
                            target.write_bytes(original + b"\n")
                            target.chmod(0o600)
                        mutated = True
                        original_install(**kwargs)

                    with (
                        patch.object(
                            state, "install_imported_github_stage",
                            side_effect=mutate_before_install,
                        ),
                        self.assertRaisesRegex(
                            PermissionError, "changed during protected import",
                        ),
                    ):
                        import_protected_rich_github_stage(
                            state, source_root=source_root,
                            pseudonym_secret=secret, clock=lambda: NOW,
                        )

                    self.assertTrue(mutated)
                    self.assertEqual(destination.read_bytes(), destination_before)
                    self.assertEqual(
                        state.pipeline.stage("github").status.value, "failed",
                    )
                    for stage in (
                        "classification", "aggregate", "report", "publish", "analytics",
                    ):
                        self.assertNotEqual(
                            state.pipeline.stage(stage).status.value, "complete",
                        )

    def test_rich_github_import_rejects_wrong_secret_and_preserves_destination(self) -> None:
        from community_os.release_operations import import_protected_rich_github_stage

        with tempfile.TemporaryDirectory() as directory:
            state, source_root, _secret, _stage_payload = (
                self._rich_github_import_fixture(directory)
            )
            destination = state.root / "protected" / "stages" / "github.json"
            before = destination.read_bytes()
            pipeline_before = state.pipeline.to_dict()
            release_before = state.snapshot()["release_state"]

            with self.assertRaisesRegex(PermissionError, "candidate set"):
                import_protected_rich_github_stage(
                    state, source_root=source_root,
                    pseudonym_secret=b"different-fixture-pseudonym-secret",
                    clock=lambda: NOW,
                )

            self.assertEqual(destination.read_bytes(), before)
            self.assertEqual(state.pipeline.to_dict(), pipeline_before)
            self.assertEqual(state.snapshot()["release_state"], release_before)

    def test_rich_github_import_commit_failure_never_leaves_stale_ready_state(self) -> None:
        from community_os.release_operations import import_protected_rich_github_stage

        with tempfile.TemporaryDirectory() as directory:
            state, source_root, secret, _stage_payload = (
                self._rich_github_import_fixture(directory)
            )
            destination = state.root / "protected" / "stages" / "github.json"
            destination_before = destination.read_bytes()
            source = source_root / "protected" / "stages" / "github.json"
            source_before = source.read_bytes()

            with (
                patch.object(
                    state.pipeline, "complete",
                    side_effect=RuntimeError("fixture commit failure"),
                ),
                self.assertRaisesRegex(RuntimeError, "fixture commit failure"),
            ):
                import_protected_rich_github_stage(
                    state, source_root=source_root, pseudonym_secret=secret,
                    clock=lambda: NOW,
                )

            self.assertEqual(state.snapshot()["release_state"], "Blocked")
            self.assertEqual(state.pipeline.stage("github").status.value, "failed")
            self.assertEqual(destination.read_bytes(), destination_before)
            self.assertEqual(source.read_bytes(), source_before)
            for stage in (
                "classification", "aggregate", "report", "publish", "analytics",
            ):
                self.assertNotEqual(state.pipeline.stage(stage).status.value, "complete")

    def test_rich_github_import_preflights_running_downstream_without_partial_mutation(self) -> None:
        from community_os.release_operations import import_protected_rich_github_stage

        with tempfile.TemporaryDirectory() as directory:
            state, source_root, secret, _stage_payload = (
                self._rich_github_import_fixture(directory)
            )
            state.pipeline.invalidate(["aggregate"])
            state.pipeline.start("aggregate")
            destination = state.root / "protected" / "stages" / "github.json"
            destination_before = destination.read_bytes()
            pipeline_before = state.pipeline_path.read_bytes()
            operator_before = state.path.read_bytes()
            in_memory_before = state.pipeline.to_dict()
            release_before = state.snapshot()["release_state"]

            with self.assertRaises(RuntimeError):
                import_protected_rich_github_stage(
                    state, source_root=source_root, pseudonym_secret=secret,
                    clock=lambda: NOW,
                )

            self.assertEqual(destination.read_bytes(), destination_before)
            self.assertEqual(state.pipeline_path.read_bytes(), pipeline_before)
            self.assertEqual(state.path.read_bytes(), operator_before)
            self.assertEqual(state.pipeline.to_dict(), in_memory_before)
            self.assertEqual(state.snapshot()["release_state"], release_before)

    def test_rich_github_import_rejects_destination_root_swap_before_commit(self) -> None:
        from community_os.release_operations import import_protected_rich_github_stage

        with tempfile.TemporaryDirectory() as directory:
            state, source_root, secret, _stage_payload = (
                self._rich_github_import_fixture(directory)
            )
            live_root = state.root
            moved_root = live_root.with_name("destination-moved")
            destination = live_root / "protected" / "stages" / "github.json"
            destination_before = destination.read_bytes()
            pipeline_before = state.pipeline.to_dict()
            original_install = state.install_imported_github_stage

            def swap_root_before_install(**kwargs: object) -> None:
                live_root.rename(moved_root)
                live_root.mkdir(mode=0o700)
                live_root.chmod(0o700)
                original_install(**kwargs)

            with (
                patch.object(
                    state, "install_imported_github_stage",
                    side_effect=swap_root_before_install,
                ),
                self.assertRaisesRegex(PermissionError, "destination root changed"),
            ):
                import_protected_rich_github_stage(
                    state, source_root=source_root, pseudonym_secret=secret,
                    clock=lambda: NOW,
                )

            self.assertFalse(
                (live_root / "protected" / "stages" / "github.json").exists(),
            )
            self.assertEqual(
                (moved_root / "protected" / "stages" / "github.json").read_bytes(),
                destination_before,
            )
            self.assertEqual(state.pipeline.to_dict(), pipeline_before)

    def test_rich_github_import_respects_existing_operator_mutation_lock(self) -> None:
        from community_os.release_operations import import_protected_rich_github_stage
        from community_os.release_operator import protected_mutation_lock

        with tempfile.TemporaryDirectory() as directory:
            state, source_root, secret, _stage_payload = (
                self._rich_github_import_fixture(directory)
            )
            destination = state.root / "protected" / "stages" / "github.json"
            destination_before = destination.read_bytes()
            pipeline_before = state.pipeline.to_dict()

            with protected_mutation_lock(state.root):
                with self.assertRaises(BlockingIOError):
                    import_protected_rich_github_stage(
                        state, source_root=source_root, pseudonym_secret=secret,
                        clock=lambda: NOW,
                    )

            self.assertEqual(destination.read_bytes(), destination_before)
            self.assertEqual(state.pipeline.to_dict(), pipeline_before)

    def test_rich_github_import_refreshes_authoritative_state_and_preserves_concurrent_correction(self) -> None:
        from community_os.release_operations import import_protected_rich_github_stage
        from community_os.release_operator import ReleaseOperatorState

        with tempfile.TemporaryDirectory() as directory:
            state, source_root, secret, _stage_payload = (
                self._rich_github_import_fixture(directory)
            )
            concurrent = ReleaseOperatorState(
                state.root, operator_code="privacy_lead",
                event_definition=_current_event_definition(),
            )
            concurrent.apply_correction(
                "going_accepted", 82, reason_code="attendance_deduplicated",
            )

            receipt = import_protected_rich_github_stage(
                state, source_root=source_root, pseudonym_secret=secret,
                clock=lambda: NOW,
            )

            self.assertEqual(receipt["record_count"], 1)
            self.assertEqual(state.snapshot()["corrections"]["going_accepted"], {
                "reason_code": "attendance_deduplicated", "value": 82,
            })
            reopened = ReleaseOperatorState(
                state.root, operator_code="privacy_lead",
                event_definition=_current_event_definition(),
            )
            self.assertEqual(reopened.snapshot()["corrections"]["going_accepted"], {
                "reason_code": "attendance_deduplicated", "value": 82,
            })

    def test_rich_github_import_rejects_destination_swap_during_authoritative_refresh(self) -> None:
        from community_os.release_operations import import_protected_rich_github_stage

        with tempfile.TemporaryDirectory() as directory:
            state, source_root, secret, _stage_payload = (
                self._rich_github_import_fixture(directory)
            )
            live_root = state.root
            moved_root = live_root.with_name("destination-moved-during-refresh")
            destination_before = (
                live_root / "protected" / "stages" / "github.json"
            ).read_bytes()
            original_refresh = state.refresh_import_authority

            def refresh_then_swap() -> None:
                original_refresh()
                live_root.rename(moved_root)
                live_root.mkdir(mode=0o700)
                live_root.chmod(0o700)

            with (
                patch.object(
                    state, "refresh_import_authority",
                    side_effect=refresh_then_swap,
                ),
                self.assertRaisesRegex(PermissionError, "destination root changed"),
            ):
                import_protected_rich_github_stage(
                    state, source_root=source_root, pseudonym_secret=secret,
                    clock=lambda: NOW,
                )

            self.assertEqual(
                (moved_root / "protected" / "stages" / "github.json").read_bytes(),
                destination_before,
            )
            self.assertFalse(
                (live_root / "protected" / "stages" / "github.json").exists(),
            )

    def test_rich_github_import_rejects_named_source_root_swap_before_transaction(self) -> None:
        from community_os.release_operations import import_protected_rich_github_stage

        with tempfile.TemporaryDirectory() as directory:
            state, source_root, secret, _stage_payload = (
                self._rich_github_import_fixture(directory)
            )
            moved_source = source_root.with_name("source-moved-before-transaction")
            destination = state.root / "protected" / "stages" / "github.json"
            destination_before = destination.read_bytes()
            original_install = state.install_imported_github_stage

            def swap_source_before_transaction(**kwargs: object) -> None:
                source_root.rename(moved_source)
                source_root.mkdir(mode=0o700)
                source_root.chmod(0o700)
                original_install(**kwargs)

            with (
                patch.object(
                    state, "install_imported_github_stage",
                    side_effect=swap_source_before_transaction,
                ),
                self.assertRaisesRegex(PermissionError, "source root changed"),
            ):
                import_protected_rich_github_stage(
                    state, source_root=source_root, pseudonym_secret=secret,
                    clock=lambda: NOW,
                )

            self.assertEqual(destination.read_bytes(), destination_before)
            self.assertFalse(
                (state.root / "protected" / ".rich-github-import-transaction.json").exists(),
            )

    def test_rich_github_import_restart_recovers_hard_exit_after_transaction_marker(self) -> None:
        from community_os.release_operator import ReleaseOperatorState

        with tempfile.TemporaryDirectory() as directory:
            state, source_root, _secret, _stage_payload = (
                self._rich_github_import_fixture(directory)
            )
            state._data["release_state"] = "Safe to publish"
            state._persist()
            partner_share = state.root / "protected" / "release" / "partner-share"
            partner_share.mkdir(parents=True, mode=0o700)
            (partner_share / "stale.html").write_text("stale", encoding="utf-8")
            public_staging = state.root / "public-staging"
            public_staging.mkdir(mode=0o700)
            (public_staging / "talent-brief.real.html").write_text(
                "stale", encoding="utf-8",
            )
            script = "\n".join((
                "import os, sys",
                "from pathlib import Path",
                "from community_os.release_operations import import_protected_rich_github_stage",
                "from community_os.release_operator import ReleaseOperatorState",
                "from tests.test_release_operations import NOW, _current_event_definition",
                "state = ReleaseOperatorState(Path(sys.argv[1]), operator_code='privacy_lead', event_definition=_current_event_definition())",
                "state._invalidate_release = lambda *args, **kwargs: os._exit(73)",
                "import_protected_rich_github_stage(state, source_root=Path(sys.argv[2]), pseudonym_secret=b'fixture-pseudonym-secret', clock=lambda: NOW)",
            ))

            crashed = subprocess.run(
                [sys.executable, "-c", script, str(state.root), str(source_root)],
                cwd=Path(__file__).resolve().parents[1], check=False,
                capture_output=True, text=True,
            )

            self.assertEqual(crashed.returncode, 73, crashed.stderr)
            marker = (
                state.root / "protected" / ".rich-github-import-transaction.json"
            )
            self.assertTrue(marker.is_file())
            self.assertEqual(marker.stat().st_mode & 0o777, 0o600)
            self.assertEqual(json.loads(marker.read_text(encoding="utf-8")), {
                "stage": "github", "state": "installing",
                "version": "rich-github-import-transaction-v1",
            })
            self.assertTrue(partner_share.exists())

            reopened = ReleaseOperatorState(
                state.root, operator_code="privacy_lead",
                event_definition=_current_event_definition(),
            )

            self.assertFalse(marker.exists())
            self.assertEqual(reopened.snapshot()["release_state"], "Blocked")
            self.assertFalse(partner_share.exists())
            self.assertFalse(
                (public_staging / "talent-brief.real.html").exists(),
            )
            for stage in (
                "github", "classification", "aggregate", "report", "publish",
                "analytics",
            ):
                self.assertNotEqual(
                    reopened.pipeline.stage(stage).status.value, "complete",
                )

    def test_rich_github_import_refresh_recovers_existing_transaction_marker(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state, _source_root, _secret, _stage_payload = (
                self._rich_github_import_fixture(directory)
            )
            state._data["release_state"] = "Safe to publish"
            state._persist()
            marker = (
                state.root / "protected" / ".rich-github-import-transaction.json"
            )
            marker.write_text(json.dumps({
                "stage": "github", "state": "installing",
                "version": "rich-github-import-transaction-v1",
            }), encoding="utf-8")
            marker.chmod(0o600)
            partner_share = state.root / "protected" / "release" / "partner-share"
            partner_share.mkdir(parents=True, mode=0o700)
            (partner_share / "stale.html").write_text("stale", encoding="utf-8")

            state.refresh()

            self.assertFalse(marker.exists())
            self.assertEqual(state.snapshot()["release_state"], "Blocked")
            self.assertFalse(partner_share.exists())
            for stage in (
                "github", "classification", "aggregate", "report", "publish",
                "analytics",
            ):
                self.assertNotEqual(state.pipeline.stage(stage).status.value, "complete")

    def test_rich_github_import_refresh_recovers_when_caller_owns_mutation_lock(self) -> None:
        from community_os.release_operator import protected_mutation_lock

        with tempfile.TemporaryDirectory() as directory:
            state, _source_root, _secret, _stage_payload = (
                self._rich_github_import_fixture(directory)
            )
            state._data["release_state"] = "Safe to publish"
            state._persist()
            marker = (
                state.root / "protected" / ".rich-github-import-transaction.json"
            )
            marker.write_text(json.dumps({
                "stage": "github", "state": "installing",
                "version": "rich-github-import-transaction-v1",
            }), encoding="utf-8")
            marker.chmod(0o600)
            partner_share = state.root / "protected" / "release" / "partner-share"
            partner_share.mkdir(parents=True, mode=0o700)
            (partner_share / "stale.html").write_text("stale", encoding="utf-8")

            with protected_mutation_lock(state.root):
                state.refresh(mutation_lock_held=True)

            self.assertFalse(marker.exists())
            self.assertEqual(state.snapshot()["release_state"], "Blocked")
            self.assertFalse(partner_share.exists())
            for stage in (
                "github", "classification", "aggregate", "report", "publish",
                "analytics",
            ):
                self.assertNotEqual(state.pipeline.stage(stage).status.value, "complete")

    def test_second_operator_does_not_recover_a_live_rich_github_import_marker(self) -> None:
        from community_os.release_operations import import_protected_rich_github_stage
        from community_os.release_operator import ReleaseOperatorState

        with tempfile.TemporaryDirectory() as directory:
            state, source_root, secret, _stage_payload = (
                self._rich_github_import_fixture(directory)
            )
            marker = (
                state.root / "protected" / ".rich-github-import-transaction.json"
            )
            marker_ready = threading.Event()
            resume_import = threading.Event()
            import_errors: list[BaseException] = []
            original_invalidate = state._invalidate_release

            def pause_after_marker(
                stages: object, *, reason_code: str,
            ) -> None:
                if reason_code == "rich_github_stage_import":
                    marker_ready.set()
                    if not resume_import.wait(timeout=5):
                        raise RuntimeError("fixture import pause timed out")
                original_invalidate(stages, reason_code=reason_code)

            def run_import() -> None:
                try:
                    import_protected_rich_github_stage(
                        state, source_root=source_root,
                        pseudonym_secret=secret, clock=lambda: NOW,
                    )
                except BaseException as error:
                    import_errors.append(error)

            with patch.object(
                state, "_invalidate_release", side_effect=pause_after_marker,
            ):
                worker = threading.Thread(target=run_import, daemon=True)
                worker.start()
                try:
                    self.assertTrue(marker_ready.wait(timeout=5))
                    self.assertTrue(marker.is_file())
                    marker_before = marker.read_bytes()
                    pipeline_before = state.pipeline_path.read_bytes()

                    second = ReleaseOperatorState(
                        state.root, operator_code="privacy_lead",
                        event_definition=_current_event_definition(),
                    )
                    second.refresh()

                    self.assertEqual(marker.read_bytes(), marker_before)
                    self.assertEqual(state.pipeline_path.read_bytes(), pipeline_before)
                finally:
                    resume_import.set()
                    worker.join(timeout=5)

            self.assertFalse(worker.is_alive())
            self.assertEqual(import_errors, [])
            self.assertFalse(marker.exists())

    def test_rich_github_import_rejects_expired_approval_and_preserves_destination(self) -> None:
        from community_os.release_operations import import_protected_rich_github_stage

        with tempfile.TemporaryDirectory() as directory:
            state, source_root, secret, _stage_payload = (
                self._rich_github_import_fixture(directory)
            )
            destination = state.root / "protected" / "stages" / "github.json"
            before = destination.read_bytes()
            approval_path = source_root / "collection-approval.json"
            approval = json.loads(approval_path.read_text(encoding="utf-8"))
            approval["expires_at"] = NOW.isoformat().replace("+00:00", "Z")
            approval_path.write_text(json.dumps(approval), encoding="utf-8")
            approval_path.chmod(0o600)

            with self.assertRaisesRegex(PermissionError, "expired or overlong"):
                import_protected_rich_github_stage(
                    state, source_root=source_root, pseudonym_secret=secret,
                    clock=lambda: NOW,
                )

            self.assertEqual(destination.read_bytes(), before)

    def test_rich_github_import_rejects_authorization_mismatch_and_preserves_destination(self) -> None:
        from dataclasses import replace
        from community_os.enrichment.state import PipelineState, StageStatus
        from community_os.release_operations import import_protected_rich_github_stage
        from tests.test_release_operator import source_gate

        with tempfile.TemporaryDirectory() as directory:
            state, source_root, secret, stage_payload = (
                self._rich_github_import_fixture(directory)
            )
            destination = state.root / "protected" / "stages" / "github.json"
            before = destination.read_bytes()
            source_pipeline = PipelineState.create(
                source_root / "pipeline-state.json", {"github": StageStatus.LOCKED},
            )
            mismatched_gate = replace(
                source_gate("applicant_supplied_github", 30),
                approval_id="approval_002",
            )
            source_pipeline.unlock("github", mismatched_gate, now=NOW)
            source_pipeline.start("github")
            source_pipeline.complete("github", {
                "output_hash": self._canonical_sha256(stage_payload["records"]),
                "record_count": len(stage_payload["records"]),
            })

            with self.assertRaisesRegex(PermissionError, "authorization does not match"):
                import_protected_rich_github_stage(
                    state, source_root=source_root, pseudonym_secret=secret,
                    clock=lambda: NOW,
                )

            self.assertEqual(destination.read_bytes(), before)

    def test_rich_github_import_rejects_malformed_rich_packet_and_preserves_destination(self) -> None:
        from community_os.release_operations import import_protected_rich_github_stage

        with tempfile.TemporaryDirectory() as directory:
            state, source_root, secret, _stage_payload = (
                self._rich_github_import_fixture(directory)
            )
            destination = state.root / "protected" / "stages" / "github.json"
            before = destination.read_bytes()
            source_stage = source_root / "protected" / "stages" / "github.json"
            payload = json.loads(source_stage.read_text(encoding="utf-8"))
            payload["records"][0]["rich_project_evidence"][0][
                "description_excerpt"
            ] = "https://github.com/direct-identifier"
            source_stage.write_text(json.dumps(payload), encoding="utf-8")
            source_stage.chmod(0o600)

            with self.assertRaisesRegex(ValueError, "direct identifier"):
                import_protected_rich_github_stage(
                    state, source_root=source_root, pseudonym_secret=secret,
                    clock=lambda: NOW,
                )

            self.assertEqual(destination.read_bytes(), before)

    def test_rich_github_import_rejects_stable_pseudonym_in_excerpt(self) -> None:
        from community_os.release_operations import import_protected_rich_github_stage

        with tempfile.TemporaryDirectory() as directory:
            state, source_root, secret, _stage_payload = (
                self._rich_github_import_fixture(directory)
            )
            destination = state.root / "protected" / "stages" / "github.json"
            before = destination.read_bytes()
            source_stage = source_root / "protected" / "stages" / "github.json"
            payload = json.loads(source_stage.read_text(encoding="utf-8"))
            payload["records"][0]["rich_project_evidence"][0][
                "readme_excerpt"
            ] = "Built by pid:v1:" + "f" * 64
            source_stage.write_text(json.dumps(payload), encoding="utf-8")
            source_stage.chmod(0o600)

            with self.assertRaisesRegex(ValueError, "direct identifier"):
                import_protected_rich_github_stage(
                    state, source_root=source_root, pseudonym_secret=secret,
                    clock=lambda: NOW,
                )

            self.assertEqual(destination.read_bytes(), before)

    def test_rich_github_import_redacts_applicant_handle_in_destination_projection(self) -> None:
        from community_os.release_operations import import_protected_rich_github_stage

        with tempfile.TemporaryDirectory() as directory:
            state, source_root, secret, _stage_payload = (
                self._rich_github_import_fixture(directory)
            )
            destination = state.root / "protected" / "stages" / "github.json"
            source_stage = source_root / "protected" / "stages" / "github.json"
            payload = json.loads(source_stage.read_text(encoding="utf-8"))
            payload["records"][0]["rich_project_evidence"][0][
                "description_excerpt"
            ] = "built by ada-example"
            source_stage.write_text(json.dumps(payload), encoding="utf-8")
            source_stage.chmod(0o600)
            source_pipeline = source_root / "pipeline-state.json"
            pipeline_payload = json.loads(source_pipeline.read_text(encoding="utf-8"))
            pipeline_payload["stages"]["github"]["result"]["output_hash"] = (
                self._canonical_sha256(payload["records"])
            )
            source_pipeline.write_text(json.dumps(pipeline_payload), encoding="utf-8")
            source_pipeline.chmod(0o600)

            source_before = source_stage.read_bytes()
            receipt = import_protected_rich_github_stage(
                state, source_root=source_root, pseudonym_secret=secret,
                clock=lambda: NOW,
            )

            self.assertEqual(source_stage.read_bytes(), source_before)
            self.assertNotIn(
                "ada-example",
                destination.read_text(encoding="utf-8").casefold(),
            )
            self.assertGreaterEqual(receipt["redaction_count"], 1)

    def test_rich_github_import_redacts_three_character_handle_as_exact_token(self) -> None:
        from community_os.release_operations import import_protected_rich_github_stage

        with tempfile.TemporaryDirectory() as directory:
            state, source_root, secret, _stage_payload = (
                self._rich_github_import_fixture(directory, github_profile="abc")
            )
            source_stage = source_root / "protected" / "stages" / "github.json"
            payload = json.loads(source_stage.read_text(encoding="utf-8"))
            payload["records"][0]["rich_project_evidence"][0][
                "description_excerpt"
            ] = "built by abc"
            source_stage.write_text(json.dumps(payload), encoding="utf-8")
            source_stage.chmod(0o600)
            source_pipeline = source_root / "pipeline-state.json"
            pipeline_payload = json.loads(source_pipeline.read_text(encoding="utf-8"))
            pipeline_payload["stages"]["github"]["result"]["output_hash"] = (
                self._canonical_sha256(payload["records"])
            )
            source_pipeline.write_text(json.dumps(pipeline_payload), encoding="utf-8")
            source_pipeline.chmod(0o600)

            receipt = import_protected_rich_github_stage(
                state, source_root=source_root, pseudonym_secret=secret,
                clock=lambda: NOW,
            )

            destination = json.loads((
                state.root / "protected" / "stages" / "github.json"
            ).read_text(encoding="utf-8"))
            description = destination["records"][0]["rich_project_evidence"][0][
                "description_excerpt"
            ]
            self.assertNotIn("abc", description.casefold())
            self.assertGreaterEqual(receipt["redaction_count"], 1)

    def test_rich_github_import_redacts_one_and_two_character_handles_as_exact_tokens(self) -> None:
        from community_os.release_operations import import_protected_rich_github_stage

        for handle in ("a", "ai"):
            with self.subTest(handle=handle), tempfile.TemporaryDirectory() as directory:
                state, source_root, secret, _stage_payload = (
                    self._rich_github_import_fixture(
                        directory, github_profile=handle,
                    )
                )
                source_stage = source_root / "protected" / "stages" / "github.json"
                payload = json.loads(source_stage.read_text(encoding="utf-8"))
                payload["records"][0]["rich_project_evidence"][0][
                    "description_excerpt"
                ] = f"built by {handle}"
                source_stage.write_text(json.dumps(payload), encoding="utf-8")
                source_stage.chmod(0o600)
                source_pipeline = source_root / "pipeline-state.json"
                pipeline_payload = json.loads(
                    source_pipeline.read_text(encoding="utf-8"),
                )
                pipeline_payload["stages"]["github"]["result"]["output_hash"] = (
                    self._canonical_sha256(payload["records"])
                )
                source_pipeline.write_text(
                    json.dumps(pipeline_payload), encoding="utf-8",
                )
                source_pipeline.chmod(0o600)

                receipt = import_protected_rich_github_stage(
                    state, source_root=source_root, pseudonym_secret=secret,
                    clock=lambda: NOW,
                )

                destination = json.loads((
                    state.root / "protected" / "stages" / "github.json"
                ).read_text(encoding="utf-8"))
                description = destination["records"][0][
                    "rich_project_evidence"
                ][0]["description_excerpt"]
                self.assertNotIn(f" {handle} ", f" {description.casefold()} ")
                self.assertGreaterEqual(receipt["redaction_count"], 1)

    def test_rich_github_import_redacts_schemeless_short_profile_handles(self) -> None:
        from community_os.release_operations import import_protected_rich_github_stage

        profiles = (
            ("github.com/ai", "ai"),
            ("www.github.com/abc/", "abc"),
        )
        for profile, handle in profiles:
            with self.subTest(profile=profile), tempfile.TemporaryDirectory() as directory:
                state, source_root, secret, _stage_payload = (
                    self._rich_github_import_fixture(
                        directory, github_profile=profile,
                    )
                )
                source_stage = source_root / "protected" / "stages" / "github.json"
                payload = json.loads(source_stage.read_text(encoding="utf-8"))
                payload["records"][0]["rich_project_evidence"][0][
                    "description_excerpt"
                ] = f"built by {handle}"
                source_stage.write_text(json.dumps(payload), encoding="utf-8")
                source_stage.chmod(0o600)
                source_pipeline = source_root / "pipeline-state.json"
                pipeline_payload = json.loads(
                    source_pipeline.read_text(encoding="utf-8"),
                )
                pipeline_payload["stages"]["github"]["result"]["output_hash"] = (
                    self._canonical_sha256(payload["records"])
                )
                source_pipeline.write_text(
                    json.dumps(pipeline_payload), encoding="utf-8",
                )
                source_pipeline.chmod(0o600)

                receipt = import_protected_rich_github_stage(
                    state, source_root=source_root, pseudonym_secret=secret,
                    clock=lambda: NOW,
                )

                destination = json.loads((
                    state.root / "protected" / "stages" / "github.json"
                ).read_text(encoding="utf-8"))
                description = destination["records"][0][
                    "rich_project_evidence"
                ][0]["description_excerpt"]
                self.assertNotIn(f" {handle} ", f" {description.casefold()} ")
                self.assertGreaterEqual(receipt["redaction_count"], 1)

    def test_schemeless_github_identity_extraction_does_not_accept_other_hosts(self) -> None:
        from community_os.release_operations import import_protected_rich_github_stage

        controls = (
            ("notgithub.com/ai", "ai"),
            ("github.com.example/abc", "abc"),
        )
        for profile, handle in controls:
            with self.subTest(profile=profile), tempfile.TemporaryDirectory() as directory:
                state, source_root, secret, _stage_payload = (
                    self._rich_github_import_fixture(
                        directory, github_profile=profile,
                    )
                )
                source_stage = source_root / "protected" / "stages" / "github.json"
                payload = json.loads(source_stage.read_text(encoding="utf-8"))
                payload["records"][0]["rich_project_evidence"][0][
                    "description_excerpt"
                ] = f"built by {handle}"
                source_stage.write_text(json.dumps(payload), encoding="utf-8")
                source_stage.chmod(0o600)
                source_pipeline = source_root / "pipeline-state.json"
                pipeline_payload = json.loads(
                    source_pipeline.read_text(encoding="utf-8"),
                )
                pipeline_payload["stages"]["github"]["result"]["output_hash"] = (
                    self._canonical_sha256(payload["records"])
                )
                source_pipeline.write_text(
                    json.dumps(pipeline_payload), encoding="utf-8",
                )
                source_pipeline.chmod(0o600)

                receipt = import_protected_rich_github_stage(
                    state, source_root=source_root, pseudonym_secret=secret,
                    clock=lambda: NOW,
                )

                self.assertEqual(receipt["record_count"], 1)

    def test_short_github_handle_matching_preserves_hyphens_and_actual_length(self) -> None:
        from community_os.release_operations import import_protected_rich_github_stage

        controls = (
            ("a-b", "built a b workflow"),
            ("a-b-c", "built a b c workflow"),
        )
        for handle, excerpt in controls:
            with self.subTest(handle=handle), tempfile.TemporaryDirectory() as directory:
                state, source_root, secret, _stage_payload = (
                    self._rich_github_import_fixture(
                        directory, github_profile=handle,
                    )
                )
                source_stage = source_root / "protected" / "stages" / "github.json"
                payload = json.loads(source_stage.read_text(encoding="utf-8"))
                payload["records"][0]["rich_project_evidence"][0][
                    "description_excerpt"
                ] = excerpt
                source_stage.write_text(json.dumps(payload), encoding="utf-8")
                source_stage.chmod(0o600)
                source_pipeline = source_root / "pipeline-state.json"
                pipeline_payload = json.loads(
                    source_pipeline.read_text(encoding="utf-8"),
                )
                pipeline_payload["stages"]["github"]["result"]["output_hash"] = (
                    self._canonical_sha256(payload["records"])
                )
                source_pipeline.write_text(
                    json.dumps(pipeline_payload), encoding="utf-8",
                )
                source_pipeline.chmod(0o600)

                receipt = import_protected_rich_github_stage(
                    state, source_root=source_root, pseudonym_secret=secret,
                    clock=lambda: NOW,
                )

                self.assertEqual(receipt["record_count"], 1)

    def test_short_hyphenated_github_handle_is_redacted_only_as_exact_token(self) -> None:
        from community_os.release_operations import import_protected_rich_github_stage

        with tempfile.TemporaryDirectory() as directory:
            state, source_root, secret, _stage_payload = (
                self._rich_github_import_fixture(
                    directory, github_profile="a-b",
                )
            )
            source_stage = source_root / "protected" / "stages" / "github.json"
            payload = json.loads(source_stage.read_text(encoding="utf-8"))
            payload["records"][0]["rich_project_evidence"][0][
                "description_excerpt"
            ] = "built by a-b"
            source_stage.write_text(json.dumps(payload), encoding="utf-8")
            source_stage.chmod(0o600)
            source_pipeline = source_root / "pipeline-state.json"
            pipeline_payload = json.loads(
                source_pipeline.read_text(encoding="utf-8"),
            )
            pipeline_payload["stages"]["github"]["result"]["output_hash"] = (
                self._canonical_sha256(payload["records"])
            )
            source_pipeline.write_text(
                json.dumps(pipeline_payload), encoding="utf-8",
            )
            source_pipeline.chmod(0o600)

            receipt = import_protected_rich_github_stage(
                state, source_root=source_root, pseudonym_secret=secret,
                clock=lambda: NOW,
            )

            destination = json.loads((
                state.root / "protected" / "stages" / "github.json"
            ).read_text(encoding="utf-8"))
            description = destination["records"][0]["rich_project_evidence"][0][
                "description_excerpt"
            ]
            self.assertNotIn("a-b", description.casefold())
            self.assertGreaterEqual(receipt["redaction_count"], 1)

    def test_rich_github_import_short_identity_scan_uses_exact_token_boundaries(self) -> None:
        from community_os.release_operations import import_protected_rich_github_stage

        controls = (
            ("a", "built data tooling"),
            ("ai", "built chair tooling"),
            ("abc", "built xabc tooling and abcd workflows"),
        )
        for handle, excerpt in controls:
            with self.subTest(handle=handle), tempfile.TemporaryDirectory() as directory:
                state, source_root, secret, _stage_payload = (
                    self._rich_github_import_fixture(
                        directory, github_profile=handle,
                    )
                )
                source_stage = source_root / "protected" / "stages" / "github.json"
                payload = json.loads(source_stage.read_text(encoding="utf-8"))
                payload["records"][0]["rich_project_evidence"][0][
                    "description_excerpt"
                ] = excerpt
                source_stage.write_text(json.dumps(payload), encoding="utf-8")
                source_stage.chmod(0o600)
                source_pipeline = source_root / "pipeline-state.json"
                pipeline_payload = json.loads(
                    source_pipeline.read_text(encoding="utf-8"),
                )
                pipeline_payload["stages"]["github"]["result"]["output_hash"] = (
                    self._canonical_sha256(payload["records"])
                )
                source_pipeline.write_text(
                    json.dumps(pipeline_payload), encoding="utf-8",
                )
                source_pipeline.chmod(0o600)

                receipt = import_protected_rich_github_stage(
                    state, source_root=source_root, pseudonym_secret=secret,
                    clock=lambda: NOW,
                )

                self.assertEqual(receipt["record_count"], 1)

    def test_fixture_only_controlled_action_runs_and_persists_complete_prepublication_chain(self) -> None:
        from community_os.enrichment.release_pipeline import ReleasePipeline
        from community_os.release_operations import ProductionOperationRegistry
        from community_os.release_operator import run_approved_release
        from tests.test_release_operator import processor_approval, source_gate

        calls: list[str] = []
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = self._operator_state(directory)
            state.configure_optional_stage_policy(())
            state.record_public_source_authorization(
                "github", source_gate("applicant_supplied_github", 30), now=NOW,
            )
            state.record_public_source_authorization(
                "public_pages", source_gate("applicant_supplied_public_pages", 14), now=NOW,
            )
            state.record_semantic_processor_authorization(
                processor_approval(), now=NOW,
            )
            services = {
                stage: (
                    lambda stage=stage: calls.append(stage)
                    or [{"fixture": True, "stage": stage, "state": "complete"}]
                )
                for stage in (
                    "privacy_cleanup", "reconcile", "github", "public_pages",
                    "coresignal", "classification", "aggregate", "report", "publish",
                )
            }
            callbacks = ProductionOperationRegistry.from_operator_state(
                state, services=services, caches=(), clock=lambda: NOW,
            ).callbacks()
            callbacks["withdraw_publication"] = lambda: []
            pipeline = ReleasePipeline(
                state.pipeline,
                manifest_path=root / "protected" / "enrichment-manifest.json",
                config={
                    "disabled_optional_stages": list(
                        state.disabled_optional_stages,
                    ),
                    "optional_stage_policy_bound": (
                        state.optional_stage_policy_bound
                    ),
                },
                prerequisites={
                    "github": ("reconcile",), "public_pages": ("reconcile",),
                    "coresignal": ("reconcile",),
                    "classification": ("github", "public_pages"),
                    "aggregate": ("classification",), "report": ("aggregate",),
                    "publish": ("report",), "analytics": ("publish",),
                },
            )

            run_approved_release(pipeline, callbacks, include_coresignal=False)

            expected = (
                "privacy_cleanup", "reconcile", "github", "public_pages",
                "classification", "aggregate", "report", "publish",
            )
            self.assertEqual(calls, list(expected))
            for stage in expected:
                payload = json.loads(
                    (root / "protected" / "stages" / f"{stage}.json").read_text(
                        encoding="utf-8",
                    )
                )
                self.assertIn(
                    stage,
                    {str(record.get("stage")) for record in payload["records"]},
                )
            manifest = json.loads(
                (root / "protected" / "enrichment-manifest.json").read_text(
                    encoding="utf-8",
                )
            )
            self.assertEqual(manifest["stages"]["publish"]["status"], "complete")
            self.assertEqual(manifest["stages"]["coresignal"]["status"], "locked")
            self.assertEqual(manifest["stages"]["analytics"]["status"], "allowed")

            run_approved_release(pipeline, callbacks, include_coresignal=False)
            self.assertEqual(calls.count("privacy_cleanup"), 2)
            self.assertEqual(calls[1:].count("reconcile"), 1)

    def test_registry_has_complete_prepublication_callbacks_and_persists_protected_outputs(self) -> None:
        from community_os.release_operations import ProductionOperationRegistry

        calls: list[str] = []
        with tempfile.TemporaryDirectory() as directory:
            state = self._operator_state(directory)
            services = {
                stage: (lambda stage=stage: calls.append(stage) or [{"stage": stage, "state": "complete"}])
                for stage in (
                    "privacy_cleanup", "reconcile", "github", "public_pages", "coresignal",
                    "classification", "aggregate", "report", "publish",
                )
            }
            registry = ProductionOperationRegistry.from_operator_state(
                state, services=services, caches=(),
            )
            callbacks = registry.callbacks()
            self.assertEqual(set(callbacks), set(services))
            records = callbacks["reconcile"]()
            self.assertEqual(records, [{"stage": "reconcile", "state": "complete"}])
            output = Path(directory) / "protected" / "stages" / "reconcile.json"
            self.assertTrue(output.is_file())
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            self.assertEqual(calls, ["reconcile"])

    def test_registry_can_run_a_classification_canary_without_persisting_stage_output(self) -> None:
        from community_os.release_operations import ProductionOperationRegistry

        with tempfile.TemporaryDirectory() as directory:
            state = self._operator_state(directory)
            services = {
                stage: (lambda: [])
                for stage in (
                    "privacy_cleanup", "reconcile", "github", "public_pages",
                    "coresignal", "classification", "aggregate", "report", "publish",
                )
            }
            registry = ProductionOperationRegistry.from_operator_state(
                state, services=services, caches=(), clock=lambda: NOW,
            )
            canary = lambda: [{"canary_subject_count": 5, "state": "complete"}]

            with patch.object(registry.reviews, "assert_resolved") as resolved:
                records = registry.nonpersisting_callback("classification", canary)()

            self.assertEqual(records, [{"canary_subject_count": 5, "state": "complete"}])
            resolved.assert_called_once_with("identity", "team")
            self.assertFalse(
                (Path(directory) / "protected" / "stages" / "classification.json").exists(),
            )

    def test_registry_reports_the_exact_persisted_retention_deadline(self) -> None:
        from datetime import timedelta
        from community_os.release_operations import ProductionOperationRegistry

        observed: list[tuple[str, datetime]] = []
        execution_time = NOW + timedelta(days=5)
        with tempfile.TemporaryDirectory() as directory:
            state = self._operator_state(directory)
            services = {
                stage: (lambda: [])
                for stage in (
                    "privacy_cleanup", "reconcile", "github", "public_pages",
                    "coresignal", "classification", "aggregate", "report", "publish",
                )
            }
            registry = ProductionOperationRegistry.from_operator_state(
                state, services=services, caches=(), clock=lambda: execution_time,
                retention_days={"public_pages": 14},
                retention_persister=lambda stage, deadline: observed.append(
                    (stage, deadline)
                ),
            )

            registry.callbacks()["public_pages"]()

            output = Path(directory) / "protected" / "stages" / "public_pages.json"
            payload = json.loads(output.read_text(encoding="utf-8"))
            persisted = datetime.fromisoformat(payload["expires_at"].replace("Z", "+00:00"))
            self.assertEqual(observed, [("public_pages", persisted)])
            self.assertEqual(persisted, execution_time + timedelta(days=14))

    def test_incremental_classification_keeps_the_earlier_base_expiry(self) -> None:
        from community_os.release_operations import ProductionOperationRegistry

        with tempfile.TemporaryDirectory() as directory:
            state = self._operator_state(directory)
            stage_root = Path(directory) / "protected" / "stages"
            stage_root.mkdir(parents=True, exist_ok=True)
            classification = stage_root / "classification.json"
            classification.write_text(json.dumps({
                "created_at": "2026-07-13T12:00:00Z",
                "expires_at": "2026-07-20T12:00:00Z",
                "records": [{"base": True}], "stage": "classification",
                "stage_output_version": "protected-stage-output-v1",
            }), encoding="utf-8")
            services = {
                stage: (lambda: [])
                for stage in (
                    "privacy_cleanup", "reconcile", "github", "public_pages",
                    "coresignal", "classification", "aggregate", "report", "publish",
                )
            }
            services["classification"] = lambda: [{"merged": True}]
            registry = ProductionOperationRegistry.from_operator_state(
                state, services=services, caches=(), clock=lambda: NOW,
                retention_days={"classification": 30},
                retention_invalidator=lambda _stages: None,
            )
            registry.callbacks()["classification"]()
            persisted = json.loads(classification.read_text(encoding="utf-8"))

        self.assertEqual(persisted["expires_at"], "2026-07-20T12:00:00Z")

    def test_protected_stage_expiry_uses_injected_registry_clock(self) -> None:
        from community_os.release_operations import (
            ProductionOperationRegistry, _protected_stage_records,
        )

        runtime_now = datetime(2100, 1, 1, tzinfo=UTC)
        with tempfile.TemporaryDirectory() as directory:
            state = self._operator_state(directory)
            state.record_semantic_processor_authorization(
                semantic_processor_approval(), now=NOW,
            )
            state.pipeline.start("classification")
            state.pipeline.complete("classification", {
                "output_hash": "a" * 64, "record_count": 1,
            })
            stage_root = Path(directory) / "protected" / "stages"
            stage_root.mkdir(parents=True, exist_ok=True)
            (stage_root / "classification.json").write_text(json.dumps({
                "created_at": "2098-01-01T00:00:00Z",
                "expires_at": "2099-01-01T00:00:00Z",
                "records": [{"subject_ref": "psn_fixture"}],
                "stage": "classification",
                "stage_output_version": "protected-stage-output-v1",
            }), encoding="utf-8")
            services = {
                stage: (lambda: [])
                for stage in (
                    "privacy_cleanup", "reconcile", "github", "public_pages", "coresignal",
                    "classification", "aggregate", "report", "publish",
                )
            }
            ProductionOperationRegistry.from_operator_state(
                state, services=services, caches=(), clock=lambda: runtime_now,
            )

            with self.assertRaisesRegex(PermissionError, "classification output is expired"):
                _protected_stage_records(state, "classification")

    def test_every_operation_rehashes_consumed_sources_before_service_call(self) -> None:
        from community_os.release_operations import ProductionOperationRegistry

        calls: list[str] = []
        with tempfile.TemporaryDirectory() as directory:
            state = self._operator_state(directory)
            services = {
                stage: (lambda stage=stage: calls.append(stage) or [])
                for stage in (
                    "privacy_cleanup", "reconcile", "github", "public_pages", "coresignal",
                    "classification", "aggregate", "report", "publish",
                )
            }
            registry = ProductionOperationRegistry.from_operator_state(
                state, services=services, caches=(),
            )
            applications = state.protected_uploads / "applications.csv"
            applications.write_bytes(b"tampered")
            with self.assertRaisesRegex(PermissionError, "protected source hash drift"):
                registry.callbacks()["github"]()
            self.assertEqual(calls, [])

    def test_cleanup_physically_deletes_expired_cache_before_service(self) -> None:
        from community_os.enrichment.cache import CanonicalJsonCache
        from community_os.release_operations import ProductionOperationRegistry
        from datetime import timedelta

        calls: list[str] = []
        with tempfile.TemporaryDirectory() as directory:
            state = self._operator_state(directory)
            cache = CanonicalJsonCache(Path(directory) / "protected" / "cache", clock=lambda: NOW)
            key = cache.key("github", "v1", {"fixture": True})
            cache.set(key, {"state": "observed"}, expires_at=NOW + timedelta(seconds=1))
            expired_cache = CanonicalJsonCache(cache.root, clock=lambda: NOW + timedelta(seconds=2))
            services = {
                stage: (lambda stage=stage: calls.append(stage) or [])
                for stage in (
                    "privacy_cleanup", "reconcile", "github", "public_pages", "coresignal",
                    "classification", "aggregate", "report", "publish",
                )
            }
            registry = ProductionOperationRegistry.from_operator_state(
                state, services=services, caches=(expired_cache,),
            )
            records = registry.callbacks()["privacy_cleanup"]()
            self.assertFalse(any(cache.root.glob("*.json")))
            self.assertEqual(records[0], {"cache_entries_deleted": 1, "state": "complete"})
            self.assertEqual(calls, ["privacy_cleanup"])

    def test_cleanup_physically_deletes_expired_raw_enrichment_output(self) -> None:
        from community_os.release_operations import ProductionOperationRegistry
        from datetime import timedelta

        with tempfile.TemporaryDirectory() as directory:
            state = self._operator_state(directory)
            invalidated: list[tuple[str, ...]] = []
            services = {
                stage: (lambda stage=stage: [{"stage": stage, "state": "complete"}])
                for stage in (
                    "privacy_cleanup", "reconcile", "github", "public_pages", "coresignal",
                    "classification", "aggregate", "report", "publish",
                )
            }
            registry = ProductionOperationRegistry.from_operator_state(
                state, services=services, caches=(), clock=lambda: NOW,
                retention_days={"public_pages": 1},
            )
            registry.callbacks()["public_pages"]()
            output = Path(directory) / "protected" / "stages" / "public_pages.json"
            self.assertTrue(output.is_file())
            temporary = output.with_name(output.name + ".tmp")
            temporary.write_text("raw personal enrichment", encoding="utf-8")
            cleanup_registry = ProductionOperationRegistry.from_operator_state(
                state, services=services, caches=(), clock=lambda: NOW + timedelta(days=2),
                retention_days={"public_pages": 1},
                retention_invalidator=lambda stages: invalidated.append(tuple(stages)),
            )
            records = cleanup_registry.callbacks()["privacy_cleanup"]()
            self.assertFalse(output.exists())
            self.assertFalse(temporary.exists())
            self.assertEqual(records[0]["raw_enrichment_deleted"], 2)
            self.assertEqual(invalidated, [("public_pages",)])

    def test_classification_output_has_enforced_retention_and_invalidation(self) -> None:
        from community_os.release_operations import ProductionOperationRegistry
        from datetime import timedelta

        with tempfile.TemporaryDirectory() as directory:
            state = self._operator_state(directory)
            invalidated: list[tuple[str, ...]] = []
            services = {
                stage: (lambda stage=stage: [{"stage": stage, "state": "complete"}])
                for stage in (
                    "privacy_cleanup", "reconcile", "github", "public_pages", "coresignal",
                    "classification", "aggregate", "report", "publish",
                )
            }
            registry = ProductionOperationRegistry.from_operator_state(
                state, services=services, caches=(), clock=lambda: NOW,
                retention_days={"classification": 30},
                retention_invalidator=lambda stages: invalidated.append(tuple(stages)),
            )
            registry.callbacks()["classification"]()
            output = Path(directory) / "protected" / "stages" / "classification.json"
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(payload["expires_at"], "2026-08-12T12:00:00Z")

            expired = ProductionOperationRegistry.from_operator_state(
                state, services=services, caches=(), clock=lambda: NOW + timedelta(days=31),
                retention_days={"classification": 30},
                retention_invalidator=lambda stages: invalidated.append(tuple(stages)),
            )
            records = expired.callbacks()["privacy_cleanup"]()
            self.assertFalse(output.exists())
            self.assertEqual(records[0]["raw_enrichment_deleted"], 1)
            self.assertEqual(invalidated, [("classification",)])


class ReviewPlanningTests(unittest.TestCase):
    def test_review_cases_accept_the_event_source_role_grammar(self) -> None:
        from community_os.release_operations import ReviewCase

        case = ReviewCase.create(
            kind="identity",
            subject_code="candidate_001",
            reason_codes=("email_mismatch",),
            candidate_codes=(),
            source_hashes={"x": "a" * 64},
            version="identity_rules_v1",
        )

        self.assertRegex(case.case_hash, r"^[0-9a-f]{64}$")

    def test_real_source_planner_auto_links_exact_evidence_and_queues_only_ambiguous_cases(self) -> None:
        from community_os.operator_store import FinalRecord
        from community_os.release_operations import plan_source_reviews

        applications = [
            {"external_id": "app-1", "email": "one@example.org", "name": "Ada One"},
            {"external_id": "app-2", "email": "two@example.org", "name": "Bob Two"},
        ]
        preference_records = [
            FinalRecord("pref-1", {}, "one@example.org", "Ada One", team_name="Exact Team", track="boski"),
            FinalRecord("pref-2", {}, "changed@example.org", "Bob Two", team_name="Needs Review", track="boski"),
        ]
        preferences = {
            "Exact Team": {"track": "boski"},
            "Needs Review": {"track": "boski"},
        }
        projects = {
            "Exact Team": {"track": "boski"},
            "Candidate Project": {"track": "boski"},
        }
        plan = plan_source_reviews(
            applications=applications,
            preference_records=preference_records,
            submission_records=(),
            preferences=preferences,
            projects=projects,
            source_hashes={
                "applications": "a" * 64, "attendance": "b" * 64,
                "preferences": "c" * 64, "submissions": "d" * 64,
            },
            pseudonym_secret=b"fixture-pseudonym-secret",
        )
        self.assertEqual({case.kind for case in plan.cases}, {"identity", "team"})
        identity = next(case for case in plan.cases if case.kind == "identity")
        team = next(case for case in plan.cases if case.kind == "team")
        self.assertEqual(len(identity.candidate_codes), 1)
        self.assertEqual(len(team.candidate_codes), 1)
        self.assertEqual(plan.bindings["exact_person_links"], {"pref-1": "app-1"})
        self.assertEqual(plan.bindings["exact_team_links"], {"Exact Team": "Exact Team"})
        self.assertNotIn("one@example.org", str(plan.cases))
        self.assertNotIn("Bob Two", str(plan.cases))

    def test_review_repository_refreshes_selected_kinds_without_deleting_other_queues(self) -> None:
        from community_os.release_operations import ReviewCase, ReviewRepository

        with tempfile.TemporaryDirectory() as directory:
            repository = ReviewRepository(Path(directory) / "reviews.json")
            classification = ReviewCase.create(
                kind="classification", subject_code="case_001",
                reason_codes=("low_confidence",), candidate_codes=(),
                source_hashes={"applications": "a" * 64}, version="semantic_v1",
            )
            identity = ReviewCase.create(
                kind="identity", subject_code="candidate_001",
                reason_codes=("email_mismatch",), candidate_codes=(),
                source_hashes={"applications": "a" * 64}, version="identity_rules_v1",
            )
            repository.replace((classification, identity))
            repository.replace_for_kinds(("identity", "team"), ())
            self.assertEqual(repository.list(), (classification,))

    def test_reconcile_service_populates_real_queues_and_protected_bindings(self) -> None:
        from community_os.operator_store import FinalRecord
        from community_os.release_operator import ReleaseOperatorState, ReleaseSourceSlot
        from community_os.release_operations import (
            ReconciliationInputs, build_reconcile_service,
        )
        import hashlib

        with tempfile.TemporaryDirectory() as directory:
            state = ReleaseOperatorState(
                Path(directory), operator_code="privacy_lead",
                event_definition=_current_event_definition(),
            )
            for slot in ReleaseSourceSlot:
                body = slot.value.encode()
                destination = state.record_source(
                    slot, sha256=hashlib.sha256(body).hexdigest(), row_count=1,
                    filename=f"{slot.value}{'.csv' if slot.value in {'applications', 'attendance'} else '.xlsx'}",
                )
                destination.write_bytes(body)
                destination.chmod(0o600)
            inputs = ReconciliationInputs(
                applications=(
                    {"external_id": "app-1", "email": "one@example.org", "name": "Ada One"},
                    {"external_id": "app-2", "email": "two@example.org", "name": "Bob Two"},
                ),
                preference_records=(
                    FinalRecord("pref-1", {}, "changed@example.org", "Bob Two", team_name="Review Team", track="boski"),
                ),
                submission_records=(),
                preferences={"Review Team": {"track": "boski"}},
                projects={"Submitted Team": {"track": "boski"}},
            )
            service = build_reconcile_service(
                state, pseudonym_secret=b"fixture-pseudonym-secret",
                source_loader=lambda _state: inputs,
            )
            summary = service()
            self.assertEqual(summary, [{
                "identity_cases": 1, "state": "needs_review", "team_cases": 1,
            }])
            self.assertEqual(
                {case.kind for case in state.review_repository.list()},
                {"identity", "team"},
            )
            bindings = Path(directory) / "protected" / "review-bindings.json"
            self.assertTrue(bindings.is_file())
            self.assertEqual(bindings.stat().st_mode & 0o777, 0o600)
            payload = json.loads(bindings.read_text(encoding="utf-8"))
            self.assertEqual(
                set(payload),
                {
                    "bindings", "bindings_version", "event_definition_sha256",
                    "event_approval_sha256", "event_key", "source_hashes",
                },
            )
            self.assertEqual(payload["bindings_version"], "release-review-bindings-v2")
            self.assertIsNone(payload["event_approval_sha256"])
            self.assertEqual(payload["event_key"], state.event_key)
            self.assertEqual(
                payload["event_definition_sha256"], state.event_definition_sha256,
            )
            self.assertEqual(
                payload["source_hashes"],
                {
                    role: state.snapshot()["source_slots"][role]["sha256"]
                    for role in state.source_slots
                },
            )

    def test_review_bindings_reject_event_definition_and_source_drift(self) -> None:
        from community_os.release_operator import ReleaseOperatorState
        from community_os.release_operations import _load_review_bindings

        with tempfile.TemporaryDirectory() as directory:
            state = ReleaseOperatorState(
                Path(directory), operator_code="privacy_lead",
                event_definition=_current_event_definition(),
            )
            path = state.root / "protected" / "review-bindings.json"
            baseline = _review_bindings_payload(state, {"marker": "bound"})

            legacy = dict(baseline)
            legacy["bindings_version"] = "release-review-bindings-v1"
            path.write_text(json.dumps(legacy), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "invalid"):
                _load_review_bindings(state)

            cases = (
                (
                    {**baseline, "event_key": "different-event"},
                    "event key",
                ),
                (
                    {**baseline, "event_definition_sha256": "f" * 64},
                    "event definition",
                ),
                (
                    {**baseline, "event_approval_sha256": "f" * 64},
                    "event approval",
                ),
                (
                    {
                        **baseline,
                        "source_hashes": {
                            **baseline["source_hashes"],
                            "applications": "e" * 64,
                        },
                    },
                    "source hashes",
                ),
                (
                    {
                        **baseline,
                        "source_hashes": {
                            key: value
                            for key, value in baseline["source_hashes"].items()
                            if key != "applications"
                        },
                    },
                    "source hashes",
                ),
                (
                    {
                        **baseline,
                        "source_hashes": {
                            **baseline["source_hashes"],
                            "unexpected": None,
                        },
                    },
                    "source hashes",
                ),
            )
            for payload, message in cases:
                with self.subTest(message=message):
                    path.write_text(json.dumps(payload), encoding="utf-8")
                    with self.assertRaisesRegex(PermissionError, message):
                        _load_review_bindings(state)

    def test_review_binding_envelope_records_missing_optional_sources_as_null(self) -> None:
        from community_os.event_definition import load_event_definition
        from community_os.release_operator import ReleaseOperatorState
        from community_os.release_operations import _persist_review_bindings

        definition = load_event_definition(
            Path(__file__).parent / "fixtures/events/second-hackathon.synthetic.json",
        )
        with tempfile.TemporaryDirectory() as directory:
            state = ReleaseOperatorState(
                Path(directory), operator_code="privacy_lead",
                event_definition=definition,
            )
            for role in ("applications", "attendance"):
                body = role.encode("utf-8")
                destination = state.record_source(
                    role,
                    sha256=hashlib.sha256(body).hexdigest(),
                    row_count=1,
                    filename=f"{role}.xlsx",
                )
                destination.write_bytes(body)

            _persist_review_bindings(state, {"marker": "second_event"})

            payload = json.loads(
                (state.root / "protected/review-bindings.json").read_text(
                    encoding="utf-8",
                ),
            )
            self.assertRegex(payload["source_hashes"]["applications"], r"^[0-9a-f]{64}$")
            self.assertRegex(payload["source_hashes"]["attendance"], r"^[0-9a-f]{64}$")
            self.assertIsNone(payload["source_hashes"]["teams"])
            self.assertIsNone(payload["source_hashes"]["submissions"])

    def test_review_binding_metadata_uses_event_key_grammar_and_requires_strings(self) -> None:
        from community_os.release_operations import (
            _load_review_bindings, _persist_review_bindings,
        )

        with tempfile.TemporaryDirectory() as directory:
            state = SimpleNamespace(
                root=Path(directory),
                event_key="1",
                event_definition_sha256="1" * 64,
                source_slots=(),
                snapshot=lambda: {"source_slots": {}},
            )
            _persist_review_bindings(state, {"marker": "typed"})
            path = Path(directory) / "protected/review-bindings.json"
            payload = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(payload["event_key"], "1")

            payload["event_key"] = 1
            payload["event_definition_sha256"] = int("1" * 64)
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(PermissionError, "event key"):
                _load_review_bindings(state)


class AdapterServiceTests(unittest.TestCase):
    def test_adapter_service_uses_verified_applicant_source_and_pseudonymous_subjects(self) -> None:
        from community_os.release_operator import ReleaseOperatorState
        from community_os.release_operations import build_adapter_service

        observed: list[object] = []

        class FakeAdapter:
            def __init__(self, verifier):
                self.verifier = verifier

            def enrich(self, reference, *, state, authorization, subject_ref):
                self_test.assertTrue(self.verifier(reference))
                observed.append((
                    reference, state.stage("github").status,
                    authorization.source_scope, subject_ref,
                ))
                return {"evidence_ref": "evidence:github:" + "e" * 64, "state": "observed"}

        self_test = self
        with tempfile.TemporaryDirectory() as directory:
            state = ReleaseOperatorState(
                Path(directory), operator_code="privacy_lead",
                event_definition=_current_event_definition(),
            )
            gate = __import__("tests.test_release_operator", fromlist=["source_gate"]).source_gate(
                "applicant_supplied_github", 30,
            )
            state.pipeline.unlock("github", gate, now=NOW)
            state.pipeline.start("github")
            service = build_adapter_service(
                state, stage="github", field="github",
                pseudonym_secret=b"fixture-pseudonym-secret",
                adapter_factory=FakeAdapter,
                application_loader=lambda _state: ({
                    "external_id": "app-1", "github": "https://github.com/example-user",
                },),
            )
            records = service()
        self.assertEqual(len(observed), 1)
        self.assertRegex(records[0]["subject_ref"], r"^pid:v1:[0-9a-f]{64}$")
        self.assertNotIn("example-user", str(records))
        self.assertEqual(records[0]["evidence_ref"], "evidence:github:" + "e" * 64)


class ClassificationServiceTests(unittest.TestCase):
    def test_stale_review_bindings_block_before_semantic_provider_or_queue_mutation(self) -> None:
        from community_os.release_operator import ReleaseOperatorState
        from community_os.release_operations import build_local_classification_service

        class ExplodingClassifier:
            calls = 0

            def classify(self, _source):
                self.calls += 1
                raise AssertionError("stale bindings must block before the provider")

        with tempfile.TemporaryDirectory() as directory:
            state = ReleaseOperatorState(
                Path(directory), operator_code="privacy_lead",
                event_definition=_current_event_definition(),
            )
            payload = _review_bindings_payload(state, {"marker": "stale"})
            payload["source_hashes"]["applications"] = "f" * 64
            path = state.root / "protected/review-bindings.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            classifier = ExplodingClassifier()
            service = build_local_classification_service(
                state,
                pseudonym_secret=b"fixture-pseudonym-secret",
                semantic_classifier=classifier,
                application_loader=lambda _state: ({"external_id": "app-1"},),
            )

            with self.assertRaisesRegex(PermissionError, "source hashes"):
                service()

            self.assertEqual(classifier.calls, 0)
            self.assertEqual(state.review_repository.list(kind="classification"), ())

    def test_classification_overlay_preserves_event_and_source_binding_metadata(self) -> None:
        from community_os.release_operator import ReleaseOperatorState
        from community_os.release_operations import build_local_classification_service

        with tempfile.TemporaryDirectory() as directory:
            state = ReleaseOperatorState(
                Path(directory), operator_code="privacy_lead",
                event_definition=_current_event_definition(),
            )
            path = state.root / "protected" / "review-bindings.json"
            baseline = _review_bindings_payload(
                state,
                {
                    "exact_person_links": {},
                    "identity_subjects": {},
                    "marker": "preserve",
                },
            )
            path.write_text(json.dumps(baseline), encoding="utf-8")

            build_local_classification_service(
                state,
                pseudonym_secret=b"fixture-pseudonym-secret",
                application_loader=lambda _state: ({"external_id": "app-1"},),
            )()

            persisted = json.loads(path.read_text(encoding="utf-8"))
            for key in (
                "bindings_version", "event_approval_sha256",
                "event_definition_sha256", "event_key", "source_hashes",
            ):
                self.assertEqual(persisted[key], baseline[key])
            self.assertEqual(persisted["bindings"]["marker"], "preserve")
            self.assertIn("classification_subjects", persisted["bindings"])

    def test_github_activity_adds_observed_builder_and_technology_signals(self) -> None:
        from community_os.enrichment.state import pseudonymous_id
        from community_os.release_operator import ReleaseOperatorState
        from community_os.release_operations import build_local_classification_service
        from tests.test_release_operator import source_gate

        secret = b"fixture-pseudonym-secret"
        subject = pseudonymous_id("app-1", secret=secret, key_version="v1")
        with tempfile.TemporaryDirectory() as directory:
            state = ReleaseOperatorState(
                Path(directory), operator_code="privacy_lead",
                event_definition=_current_event_definition(),
            )
            state.record_public_source_authorization(
                "github", source_gate("applicant_supplied_github", 30), now=NOW,
            )
            stage_root = Path(directory) / "protected" / "stages"
            stage_root.mkdir(parents=True)
            (stage_root / "github.json").write_text(json.dumps({
                "created_at": "2026-07-13T12:00:00Z",
                "expires_at": "2026-08-12T12:00:00Z",
                "records": [{
                    "subject_ref": subject, "state": "observed",
                    "account_age_days": 1200, "last_public_update": "2026-06-01",
                    "public_repos": 8, "owned_public_repos_sampled": 6,
                    "recently_active_repos": 2, "stars_received": 12,
                    "forks_received": 3,
                    "technology_codes": ["javascript_typescript", "python"],
                    "evidence_ref": "evidence:github:" + "a" * 64,
                }, {
                    "subject_ref": pseudonymous_id(
                        "app-2", secret=secret, key_version="v1",
                    ),
                    "reason_code": "profile_not_found", "state": "unknown",
                }], "stage": "github",
                "stage_output_version": "protected-stage-output-v1",
            }), encoding="utf-8")
            state.pipeline.start("github")
            state.pipeline.complete("github", {
                "output_hash": "a" * 64, "record_count": 2,
            })
            records = build_local_classification_service(
                state, pseudonym_secret=secret,
                application_loader=lambda _state: (
                    {"external_id": "app-1"},
                    {"external_id": "app-2", "github": "deleted-profile"},
                ),
            )()

        dimensions = records[0]["dimensions"]
        self.assertIn("active_github", dimensions["builder_evidence"]["labels"])
        self.assertIn("github_supplied", dimensions["builder_evidence"]["labels"])
        self.assertIn("frontend", dimensions["capabilities"]["labels"])
        self.assertIn("backend", dimensions["capabilities"]["labels"])
        self.assertIn(
            "evidence:github:" + "a" * 64,
            dimensions["capabilities"]["evidence_refs"],
        )
        self.assertIn(
            "github_supplied", records[1]["dimensions"]["builder_evidence"]["labels"],
        )

    def test_local_classification_reads_public_page_only_from_temporary_evidence_vault(self) -> None:
        from community_os.enrichment.evidence_vault import ProtectedEvidenceVault
        from community_os.enrichment.state import pseudonymous_id
        from community_os.release_operator import ReleaseOperatorState
        from community_os.release_operations import build_local_classification_service
        from tests.test_release_operator import source_gate

        secret = b"fixture-pseudonym-secret"
        subject = pseudonymous_id("app-1", secret=secret, key_version="v1")
        evidence_ref = "evidence:public_page:" + "a" * 64
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = ReleaseOperatorState(
                root, operator_code="privacy_lead",
                event_definition=_current_event_definition(),
                clock=lambda: NOW,
            )
            gate = source_gate("applicant_supplied_public_pages", 14)
            state.record_public_source_authorization("public_pages", gate, now=NOW)
            stage_root = root / "protected" / "stages"
            stage_root.mkdir(parents=True)
            (stage_root / "public_pages.json").write_text(json.dumps({
                "created_at": "2026-07-13T12:00:00Z",
                "expires_at": "2099-07-27T12:00:00Z",
                "records": [{
                    "subject_ref": subject, "state": "observed",
                    "evidence_ref": evidence_ref,
                    "text": "Legacy raw founder profile must not bypass the vault",
                }],
                "stage": "public_pages", "stage_output_version": "protected-stage-output-v1",
            }), encoding="utf-8")
            state.pipeline.start("public_pages")
            state.pipeline.complete(
                "public_pages", {"output_hash": "a" * 64, "record_count": 1},
            )
            vault = ProtectedEvidenceVault(
                root / "protected" / "raw-evidence", clock=lambda: NOW,
            )
            vault.capture(
                source="public_pages", purpose="talent_classification",
                subject_ref=subject, evidence_ref=evidence_ref,
                provider_version="applicant-public-page-v1", content_type="text/html",
                payload=b"<main>Engineer who built production systems</main>",
                ttl=timedelta(hours=1),
            )

            records = build_local_classification_service(
                state, pseudonym_secret=secret, evidence_vault=vault,
                application_loader=lambda _state: ({"external_id": "app-1"},),
            )()

        self.assertNotIn(
            "founder_cofounder",
            records[0]["dimensions"]["professional_identity"]["labels"],
        )

    def test_semantic_classification_receives_only_minimized_codes_and_drives_review_records(self) -> None:
        from community_os.enrichment.cache import CanonicalJsonCache
        from community_os.enrichment.classification import ProcessorApproval, SemanticClassifier
        from community_os.release_operator import ReleaseOperatorState
        from community_os.release_operations import build_local_classification_service

        observed: list[dict[str, object]] = []
        now = NOW
        with tempfile.TemporaryDirectory() as directory:
            state = ReleaseOperatorState(
                Path(directory), operator_code="privacy_lead",
                event_definition=_current_event_definition(),
            )
            processor = SemanticClassifier(
                provider=lambda value: observed.append(value) or {"dimensions": {
                    "professional_identity": {"labels": ["founder_cofounder"], "confidence": 0.93, "evidence_refs": value["evidence_refs"]},
                    "seniority": {"labels": ["founder"], "confidence": 0.91, "evidence_refs": value["evidence_refs"]},
                    "functional_role": {"labels": ["engineering"], "confidence": 0.88, "evidence_refs": value["evidence_refs"]},
                    "employer_pedigree": {"labels": ["self_employed_founder"], "confidence": 0.84, "evidence_refs": value["evidence_refs"]},
                    "builder_evidence": {"labels": ["shipped_product"], "confidence": 0.89, "evidence_refs": value["evidence_refs"]},
                    "capabilities": {"labels": ["backend"], "confidence": 0.87, "evidence_refs": value["evidence_refs"]},
                    "domains": {"labels": ["applied_ai"], "confidence": 0.82, "evidence_refs": value["evidence_refs"]},
                }},
                cache=CanonicalJsonCache(Path(directory) / "cache", clock=lambda: now),
                clock=lambda: now,
                approval=ProcessorApproval(
                    provider="openai_responses", purpose="talent_classification",
                    dpa_version="dpa-v1", terms_version="terms-v1",
                    retention_mode="zero_retention", region="eu",
                    security_profile="approved-v1",
                    field_allowlist=frozenset({"subject_ref", "signals", "evidence_refs"}),
                    approved_by="start_privacy_owner", approved_at="2026-07-13T09:00:00Z",
                ),
                model="gpt-5.6-terra", prompt_version="talent-structured-v1",
                taxonomy_version="talent-taxonomy-v1", classifier_version="semantic-v1",
            )
            records = build_local_classification_service(
                state, pseudonym_secret=b"fixture-pseudonym-secret",
                semantic_classifier=processor,
                application_loader=lambda _state: ({
                    "external_id": "app-1", "email": "person@example.org",
                    "name": "Jane Smith", "occupation": "Senior AI engineer and founder",
                    "experience": "Built and shipped a product",
                    "github": "https://github.com/private-handle",
                    "linkedin": "https://linkedin.com/in/private-handle",
                    "portfolio": "https://portfolio.example/private",
                },),
            )()

        self.assertEqual(len(observed), 1)
        serialized = json.dumps(observed[0], sort_keys=True).casefold()
        for forbidden in (
            "person@example.org", "jane smith", "private-handle",
            "github.com", "linkedin.com", "portfolio.example",
        ):
            self.assertNotIn(forbidden, serialized)
        self.assertIn("role_engineering", observed[0]["signals"]["occupation_codes"])
        self.assertEqual(records[0]["classifier_version"], "semantic-v1")
        self.assertEqual(records[0]["model"], "gpt-5.6-terra")
        self.assertEqual(records[0]["review_state"], "pending")
        self.assertEqual(len(state.review_repository.list(kind="classification")), 1)

    def test_local_classification_ignores_provider_envelope_until_stage_is_complete(self) -> None:
        from community_os.enrichment.state import pseudonymous_id
        from community_os.release_operator import ReleaseOperatorState
        from community_os.release_operations import build_local_classification_service
        from tests.test_release_operator import source_gate

        secret = b"fixture-pseudonym-secret"
        subject = pseudonymous_id("app-1", secret=secret, key_version="v1")
        with tempfile.TemporaryDirectory() as directory:
            state = ReleaseOperatorState(
                Path(directory), operator_code="privacy_lead",
                event_definition=_current_event_definition(),
            )
            state.record_public_source_authorization(
                "public_pages", source_gate("applicant_supplied_public_pages", 14), now=NOW,
            )
            stage_root = Path(directory) / "protected" / "stages"
            stage_root.mkdir(parents=True)
            (stage_root / "public_pages.json").write_text(json.dumps({
                "created_at": "2026-07-13T12:00:00Z",
                "expires_at": "2099-07-27T12:00:00Z",
                "records": [{
                    "subject_ref": subject, "state": "observed",
                    "text": "Founder who launched a production AI platform",
                    "evidence_ref": "evidence:public_page:" + "a" * 64,
                }],
                "stage": "public_pages", "stage_output_version": "protected-stage-output-v1",
            }), encoding="utf-8")

            records = build_local_classification_service(
                state, pseudonym_secret=secret,
                application_loader=lambda _state: ({"external_id": "app-1"},),
            )()

        self.assertNotIn("founder_cofounder", records[0]["dimensions"]["professional_identity"]["labels"])

    def test_local_classification_rejects_expired_enrichment_envelopes(self) -> None:
        from community_os.enrichment.state import pseudonymous_id
        from community_os.release_operator import ReleaseOperatorState
        from community_os.release_operations import build_local_classification_service

        secret = b"fixture-pseudonym-secret"
        subject = pseudonymous_id("app-1", secret=secret, key_version="v1")
        with tempfile.TemporaryDirectory() as directory:
            state = ReleaseOperatorState(
                Path(directory), operator_code="privacy_lead",
                event_definition=_current_event_definition(),
            )
            from tests.test_release_operator import source_gate
            state.record_public_source_authorization(
                "public_pages", source_gate("applicant_supplied_public_pages", 14), now=NOW,
            )
            stage_root = Path(directory) / "protected" / "stages"
            stage_root.mkdir(parents=True)
            (stage_root / "public_pages.json").write_text(json.dumps({
                "created_at": "2026-07-10T12:00:00Z",
                "expires_at": "2026-07-12T12:00:00Z",
                "records": [{
                    "subject_ref": subject, "state": "observed", "text": "stale",
                    "evidence_ref": "evidence:public_page:" + "a" * 64,
                }],
                "stage": "public_pages", "stage_output_version": "protected-stage-output-v1",
            }), encoding="utf-8")
            state.pipeline.start("public_pages")
            state.pipeline.complete(
                "public_pages", {"output_hash": "a" * 64, "record_count": 1},
            )

            service = build_local_classification_service(
                state, pseudonym_secret=secret,
                application_loader=lambda _state: ({"external_id": "app-1"},),
            )
            with self.assertRaisesRegex(PermissionError, "expired"):
                service()

    def test_local_versioned_classification_creates_case_bound_review_queue(self) -> None:
        from community_os.release_operator import ReleaseOperatorState
        from community_os.release_operations import build_local_classification_service

        with tempfile.TemporaryDirectory() as directory:
            state = ReleaseOperatorState(
                Path(directory), operator_code="privacy_lead",
                event_definition=_current_event_definition(),
            )
            service = build_local_classification_service(
                state,
                pseudonym_secret=b"fixture-pseudonym-secret",
                application_loader=lambda _state: (
                    {
                        "external_id": "app-1", "occupation": "Senior ML Engineer and co-founder",
                        "experience": "Built and deployed a product", "github": "builder",
                    },
                    {"external_id": "app-2", "occupation": "", "experience": ""},
                ),
            )
            records = service()
            cases = state.review_repository.list(kind="classification")
        self.assertEqual(len(records), 2)
        self.assertEqual(len(cases), 2)
        self.assertTrue(all(record["classifier_version"] == "deterministic-rules-v1" for record in records))
        self.assertTrue(all(record["review_state"] == "pending" for record in records))
        self.assertTrue(all(set(record["dimensions"]) == {
            "professional_identity", "seniority", "functional_role", "employer_pedigree",
            "builder_evidence", "capabilities", "domains",
        } for record in records))
        self.assertNotIn("app-1", str(records))
        self.assertNotIn("Senior ML Engineer", str(records))

    def test_corrected_classification_requires_complete_structured_dimensions(self) -> None:
        from community_os.release_operations import ReviewCase, ReviewDecision, ReviewRepository

        with tempfile.TemporaryDirectory() as directory:
            repository = ReviewRepository(Path(directory) / "reviews.json")
            case = ReviewCase.create(
                kind="classification", subject_code="case_001",
                reason_codes=("low_confidence",), candidate_codes=(),
                source_hashes={"applications": "a" * 64}, version="semantic_v1",
            )
            repository.replace((case,))
            with self.assertRaisesRegex(ValueError, "classification dimensions"):
                repository.decide(
                    ReviewDecision(
                        case_code=case.case_code, case_hash=case.case_hash,
                        action="corrected", corrected_output={"seniority": {"labels": ["senior"]}},
                    ),
                    actor_code="privacy_lead", decided_at=NOW,
                )

    def test_local_classification_joins_protected_enrichment_by_pseudonym(self) -> None:
        from community_os.enrichment.gates import CoresignalGate, PublicSourceGate
        from community_os.enrichment.state import pseudonymous_id
        from community_os.release_operator import ReleaseOperatorState
        from community_os.release_operations import build_local_classification_service

        secret = b"fixture-pseudonym-secret"
        subject = pseudonymous_id("app-1", secret=secret, key_version="v1")
        with tempfile.TemporaryDirectory() as directory:
            state = ReleaseOperatorState(
                Path(directory), operator_code="privacy_lead",
                event_definition=_current_event_definition(),
            )
            public_gate = PublicSourceGate(
                notice_version="notice_v2", notice_sent_at="2026-07-13T08:00:00Z",
                objections_reconciled=True, exclusions_reconciled=True,
                suppressions_reconciled=True, deletions_reconciled=True,
                source_authorization_confirmed=True, provider_terms_version="terms_v1",
                source_scope="applicant_supplied_public_pages",
                purpose_code="aggregate_talent_evidence", retention_days=14,
                accountable_owner="privacy_lead", approval_id="approval_001",
                approved_at="2026-07-13T09:00:00Z",
            )
            coresignal_gate = CoresignalGate(
                notice_version="coresignal_transparency_v1", notice_sent_at="2026-07-13T10:00:00Z",
                notice_scope="linkedin_coresignal_enrichment",
                notice_content_sha256="d" * 64,
                objections_reconciled=True, exclusions_reconciled=True,
                suppressions_reconciled=True, deletions_reconciled=True,
                access_verified=True, provider_terms_version="terms_v1",
                source_scope="applicant_supplied_linkedin", retention_days=14,
                approval_id="release_approval_001",
                approved_at="2026-07-13T11:00:00Z",
            )
            state.record_public_source_authorization("public_pages", public_gate, now=NOW)
            state.record_coresignal_authorization(coresignal_gate, now=NOW)
            stage_root = Path(directory) / "protected" / "stages"
            stage_root.mkdir(parents=True)
            fixtures = {
                "public_pages": {
                    "subject_ref": subject, "state": "observed",
                    "text": "Founder who launched a production AI platform",
                    "evidence_ref": "evidence:public_page:" + "a" * 64,
                },
                "coresignal": {
                    "subject_ref": subject, "state": "observed", "founder_history": True,
                    "company_category": "startup", "seniority": "founder",
                    "title_category": "software_engineering",
                    "evidence_ref": "evidence:coresignal:" + "b" * 64,
                },
            }
            for stage, record in fixtures.items():
                (stage_root / f"{stage}.json").write_text(json.dumps({
                    "created_at": "2026-07-13T12:00:00Z", "expires_at": "2026-07-27T12:00:00Z",
                    "records": [record], "stage": stage,
                    "stage_output_version": "protected-stage-output-v1",
                }), encoding="utf-8")
                state.pipeline.start(stage)
                state.pipeline.complete(stage, {"output_hash": "a" * 64, "record_count": 1})
            records = build_local_classification_service(
                state, pseudonym_secret=secret,
                application_loader=lambda _state: ({"external_id": "app-1"},),
            )()

        dimensions = records[0]["dimensions"]
        self.assertEqual(dimensions["seniority"]["labels"], ["founder"])
        self.assertIn("founder_cofounder", dimensions["professional_identity"]["labels"])
        self.assertIn("engineering", dimensions["functional_role"]["labels"])
        self.assertIn(
            "evidence:coresignal:" + "b" * 64,
            dimensions["professional_identity"]["evidence_refs"],
        )

    def test_late_coresignal_overlay_merges_structured_facts_without_model_rerun(self) -> None:
        from community_os.enrichment.gates import CoresignalGate
        from community_os.enrichment.state import pseudonymous_id
        from community_os.release_operator import ReleaseOperatorState
        from community_os.release_operations import build_local_classification_service

        class ExplodingSemanticClassifier:
            calls = 0

            def classify(self, _source):
                self.calls += 1
                raise AssertionError("late structured Coresignal overlay must not rerun the model")

        secret = b"fixture-pseudonym-secret"
        applications = ({
            "external_id": "app-1", "occupation": "Senior software engineer",
            "experience": "Built and deployed production systems",
        },)
        subject = pseudonymous_id("app-1", secret=secret, key_version="v1")
        with tempfile.TemporaryDirectory() as directory:
            state = ReleaseOperatorState(
                Path(directory), operator_code="privacy_lead",
                event_definition=_current_event_definition(),
            )
            base_records = build_local_classification_service(
                state, pseudonym_secret=secret,
                application_loader=lambda _state: applications,
            )()
            binding_path = state.root / "protected" / "review-bindings.json"
            binding_before = json.loads(binding_path.read_text(encoding="utf-8"))
            state.record_semantic_processor_authorization(
                semantic_processor_approval(), now=NOW,
            )
            state.pipeline.start("classification")
            state.pipeline.complete("classification", {
                "output_hash": "a" * 64, "record_count": len(base_records),
            })
            stage_root = Path(directory) / "protected" / "stages"
            stage_root.mkdir(parents=True, exist_ok=True)
            classification_path = stage_root / "classification.json"
            classification_path.write_text(json.dumps({
                "created_at": "2026-07-13T12:00:00Z",
                "expires_at": "2026-08-12T12:00:00Z",
                "records": base_records, "stage": "classification",
                "stage_output_version": "protected-stage-output-v1",
            }), encoding="utf-8")
            corrected_dimensions = json.loads(json.dumps(base_records[0]["dimensions"]))
            corrected_dimensions["domains"]["labels"] = ["enterprise"]
            corrected_dimensions["domains"]["state"] = "observed"
            for case in state.review_repository.list(kind="classification"):
                state.review_classification(
                    case.case_code, case.case_hash, "corrected",
                    corrected_output=corrected_dimensions,
                )

            gate = CoresignalGate(
                notice_version="coresignal_transparency_v1",
                notice_sent_at="2026-07-13T08:00:00Z",
                notice_scope="linkedin_coresignal_enrichment",
                notice_content_sha256="d" * 64,
                objections_reconciled=True, exclusions_reconciled=True,
                suppressions_reconciled=True, deletions_reconciled=True,
                access_verified=True, provider_terms_version="terms_v1",
                source_scope="applicant_supplied_linkedin", retention_days=14,
                approval_id="release_approval_001",
                approved_at="2026-07-13T09:00:00Z",
            )
            state.record_coresignal_authorization(gate, now=NOW)
            state.pipeline.start("coresignal")
            state.pipeline.complete("coresignal", {
                "output_hash": "b" * 64, "record_count": 1,
            })
            (stage_root / "coresignal.json").write_text(json.dumps({
                "created_at": "2026-07-14T10:00:00Z",
                "expires_at": "2026-07-28T10:00:00Z",
                "records": [{
                    "subject_ref": subject, "state": "observed",
                    "founder_history": False, "company_category": "startup",
                    "seniority": "senior", "title_category": "software_engineering",
                    "evidence_ref": "evidence:coresignal:" + "b" * 64,
                }],
                "stage": "coresignal", "stage_output_version": "protected-stage-output-v1",
            }), encoding="utf-8")
            classifier = ExplodingSemanticClassifier()
            merged = build_local_classification_service(
                state, pseudonym_secret=secret, semantic_classifier=classifier,
                application_loader=lambda _state: applications,
            )()
            refreshed_cases = state.review_repository.list(kind="classification")
            binding_after = json.loads(binding_path.read_text(encoding="utf-8"))

        self.assertEqual(classifier.calls, 0)
        self.assertEqual(len(merged), 1)
        self.assertIn(
            "startup_operator",
            merged[0]["dimensions"]["professional_identity"]["labels"],
        )
        self.assertIn(
            "evidence:coresignal:" + "b" * 64,
            merged[0]["dimensions"]["professional_identity"]["evidence_refs"],
        )
        self.assertIn("enterprise", merged[0]["dimensions"]["domains"]["labels"])
        self.assertEqual(
            merged[0]["incremental_overlay"]["provider"], "coresignal",
        )
        self.assertEqual(refreshed_cases[0].status, "open")
        self.assertIn("prior_human_correction", refreshed_cases[0].reason_codes)
        for key in (
            "bindings_version", "event_approval_sha256",
            "event_definition_sha256", "event_key", "source_hashes",
        ):
            self.assertEqual(binding_after[key], binding_before[key])

    def test_aggregate_projection_loads_only_resolved_case_bound_classifications(self) -> None:
        from community_os.release_operator import ReleaseOperatorState
        from community_os.release_operations import (
            build_local_classification_service, load_reviewed_classification_projection,
        )

        secret = b"fixture-pseudonym-secret"
        applications = ({
            "external_id": "app-1", "occupation": "Senior ML Engineer and co-founder",
            "experience": "Built and deployed a product",
        },)
        with tempfile.TemporaryDirectory() as directory:
            state = ReleaseOperatorState(
                Path(directory), operator_code="privacy_lead",
                event_definition=_current_event_definition(),
            )
            records = build_local_classification_service(
                state, pseudonym_secret=secret,
                application_loader=lambda _state: applications,
            )()
            state.record_semantic_processor_authorization(
                semantic_processor_approval(), now=NOW,
            )
            state.pipeline.start("classification")
            state.pipeline.complete("classification", {
                "output_hash": "a" * 64, "record_count": len(records),
            })
            stage_root = Path(directory) / "protected" / "stages"
            stage_root.mkdir(parents=True, exist_ok=True)
            (stage_root / "classification.json").write_text(json.dumps({
                "created_at": "2026-07-13T12:00:00Z", "expires_at": "2099-07-13T12:00:00Z",
                "records": records, "stage": "classification",
                "stage_output_version": "protected-stage-output-v1",
            }), encoding="utf-8")
            with self.assertRaisesRegex(PermissionError, "review remains open"):
                load_reviewed_classification_projection(
                    state, pseudonym_secret=secret,
                    application_loader=lambda _state: applications,
                )
            case = state.review_repository.list(kind="classification")[0]
            state.review_classification(case.case_code, case.case_hash, "approved")
            projection = load_reviewed_classification_projection(
                state, pseudonym_secret=secret,
                application_loader=lambda _state: applications,
            )

        self.assertEqual(projection["app-1"]["seniority"], {"founder"})
        self.assertIn("founder_cofounder", projection["app-1"]["professional_identity"])

    def test_aggregate_projection_rejects_expired_classification_output(self) -> None:
        from community_os.release_operator import ReleaseOperatorState
        from community_os.release_operations import (
            build_local_classification_service, load_reviewed_classification_projection,
        )

        secret = b"fixture-pseudonym-secret"
        applications = ({"external_id": "app-1", "occupation": "Engineer"},)
        with tempfile.TemporaryDirectory() as directory:
            state = ReleaseOperatorState(
                Path(directory), operator_code="privacy_lead",
                event_definition=_current_event_definition(),
            )
            records = build_local_classification_service(
                state, pseudonym_secret=secret,
                application_loader=lambda _state: applications,
            )()
            state.record_semantic_processor_authorization(
                semantic_processor_approval(), now=NOW,
            )
            state.pipeline.start("classification")
            state.pipeline.complete("classification", {
                "output_hash": "a" * 64, "record_count": len(records),
            })
            stage_root = Path(directory) / "protected" / "stages"
            stage_root.mkdir(parents=True, exist_ok=True)
            (stage_root / "classification.json").write_text(json.dumps({
                "created_at": "2020-01-01T00:00:00Z",
                "expires_at": "2020-01-02T00:00:00Z",
                "records": records, "stage": "classification",
                "stage_output_version": "protected-stage-output-v1",
            }), encoding="utf-8")

            with self.assertRaisesRegex(PermissionError, "classification output is expired"):
                load_reviewed_classification_projection(
                    state, pseudonym_secret=secret,
                    application_loader=lambda _state: applications,
                )


class RichSemanticProposalServiceTests(unittest.TestCase):
    def test_legacy_machine_approval_cannot_authorize_rich_payload(self) -> None:
        from community_os.enrichment.semantic_taxonomy import empty_semantic_taxonomy
        from community_os.release_operations import (
            ReconciliationInputs, build_rich_semantic_proposal_service,
        )

        application = {
            "external_id": "app-1", "name": "Private Person",
            "email": "private@example.org", "experience": "Built systems",
            "impressive_thing": "",
        }
        legacy_approval = semantic_processor_approval()
        base_calls: list[str] = []
        provider_calls: list[dict[str, object]] = []

        def base_classification():
            base_calls.append("called")
            return []

        class FakeProvider:
            model = "gpt-5.6-sol"
            reasoning_effort = "high"

            def __call__(self, evidence):
                provider_calls.append(evidence)
                return {
                    "builder_level": "insufficient",
                    "career_summary": "",
                    "cross_source_confidence": "low",
                    "evidence_refs": [],
                    "execution_scope": "unknown",
                    "external_validation": "none",
                    "originality": "unknown",
                    "product_maturity": "unknown",
                    "project_summary": "",
                    "rationale": "insufficient evidence.",
                    "reason_codes": ["insufficient_evidence"],
                    "review_state": "human_review_required",
                    "semantic_taxonomy": empty_semantic_taxonomy(),
                    "technical_depth": "unknown",
                }

        stage = SimpleNamespace(
            authorization_hash=legacy_approval.authorization_hash(now=NOW),
            authorization_record=legacy_approval.to_record(),
        )
        state = SimpleNamespace(
            pipeline=SimpleNamespace(stage=lambda _stage: stage),
            rich_semantic_reviews=SimpleNamespace(submit=lambda _proposal: None),
            review_repository=SimpleNamespace(list=lambda **_kwargs: ()),
        )
        inputs = ReconciliationInputs(
            applications=(application,), preference_records=(), submission_records=(),
            preferences={}, projects={},
        )
        with (
            tempfile.TemporaryDirectory() as directory,
            patch(
                "community_os.release_operations._protected_stage_records",
                return_value=(),
            ),
            patch(
                "community_os.release_operations._resolved_person_links",
                return_value=({}, frozenset()),
            ),
        ):
            service = build_rich_semantic_proposal_service(
                state, base_classification=base_classification,
                pseudonym_secret=b"fixture-pseudonym-secret",
                provider_factory=lambda _corpus: FakeProvider(),
                cache=__import__(
                    "community_os.enrichment.cache", fromlist=["CanonicalJsonCache"],
                ).CanonicalJsonCache(Path(directory), clock=lambda: NOW),
                clock=lambda: NOW,
                application_loader=lambda _state: (application,),
                reconciliation_loader=lambda _state: inputs,
            )

            with self.assertRaisesRegex(
                PermissionError, "rich semantic processor approval",
            ):
                service()

        self.assertEqual(base_calls, [])
        self.assertEqual(provider_calls, [])

    def test_rich_subject_reference_is_shared_by_proposal_and_population_paths(self) -> None:
        from community_os.release_operations import rich_semantic_subject_ref

        secret = b"fixture-pseudonym-secret"
        expected = "case:v1:" + hmac.new(
            secret, b"rich:app-1", hashlib.sha256,
        ).hexdigest()

        self.assertEqual(rich_semantic_subject_ref("app-1", secret=secret), expected)
        with self.assertRaisesRegex(ValueError, "identifier|secret"):
            rich_semantic_subject_ref("", secret=secret)

    def test_empty_eligible_profile_creates_reviewable_unknown_instead_of_skipping_gate(self) -> None:
        from community_os.enrichment.state import pseudonymous_id
        from community_os.release_operations import (
            ReconciliationInputs, build_rich_semantic_proposal_service,
        )

        secret = b"fixture-pseudonym-secret"
        application = {
            "external_id": "app-1", "name": "Private Person",
            "email": "private@example.org", "experience": "",
            "impressive_thing": "",
        }
        subject = pseudonymous_id("app-1", secret=secret, key_version="v1")
        submitted: list[dict[str, object]] = []

        class FakeProvider:
            model = "gpt-5.6-sol"
            reasoning_effort = "high"

            def __call__(self, _evidence):
                raise AssertionError("empty evidence must not spend model tokens")

        approval = rich_semantic_processor_approval()
        state = SimpleNamespace(
            pipeline=SimpleNamespace(stage=lambda _stage: SimpleNamespace(
                authorization_hash=approval.authorization_hash(now=NOW),
                authorization_record=approval.to_record(),
            )),
            rich_semantic_reviews=SimpleNamespace(
                submit=lambda value, **_kwargs: submitted.append(value),
            ),
            review_repository=SimpleNamespace(list=lambda **_kwargs: ()),
        )
        inputs = ReconciliationInputs(
            applications=(application,), preference_records=(), submission_records=(),
            preferences={}, projects={},
        )
        with (
            patch(
                "community_os.release_operations._protected_stage_records",
                return_value=({
                    "subject_ref": subject, "state": "observed",
                    "rich_project_evidence": [],
                },),
            ),
            patch(
                "community_os.release_operations._resolved_person_links",
                return_value=({}, frozenset()),
            ),
        ):
            service = build_rich_semantic_proposal_service(
                state, base_classification=lambda: [], pseudonym_secret=secret,
                provider_factory=lambda _corpus: FakeProvider(),
                cache=SimpleNamespace(), clock=lambda: NOW,
                application_loader=lambda _state: (application,),
                reconciliation_loader=lambda _state: inputs,
            )
            service()

        self.assertEqual(len(submitted), 1)
        self.assertEqual(
            submitted[0]["assessment"]["builder_level"], "insufficient",
        )
        self.assertEqual(submitted[0]["assessment"]["reason_codes"], ["insufficient_evidence"])

    def test_final_outbound_scan_rejects_current_subject_derived_identity(self) -> None:
        from community_os.enrichment.cache import CanonicalJsonCache
        from community_os.enrichment.state import pseudonymous_id
        from community_os.release_operations import (
            ReconciliationInputs, build_rich_semantic_proposal_service,
        )
        from tests.test_rich_semantic_assessment import project_packet

        secret = b"fixture-pseudonym-secret"
        application = {
            "external_id": "app-1", "name": "Private Person",
            "email": "ownmail@example.org", "github": "other-handle",
            "linkedin": "https://linkedin.com/in/own-linkedin",
            "experience": "Built systems", "impressive_thing": "",
        }
        subject = pseudonymous_id("app-1", secret=secret, key_version="v1")
        project = project_packet()
        project["description_excerpt"] = "built ownmail workflow"
        approval = rich_semantic_processor_approval()

        class FakeProvider:
            model = "gpt-5.6-sol"
            reasoning_effort = "high"

            def __call__(self, _evidence):
                raise AssertionError("identity scan must run before provider transport")

        state = SimpleNamespace(
            pipeline=SimpleNamespace(stage=lambda _stage: SimpleNamespace(
                authorization_hash=approval.authorization_hash(now=NOW),
                authorization_record=approval.to_record(),
            )),
            rich_semantic_reviews=SimpleNamespace(submit=lambda _proposal: None),
            review_repository=SimpleNamespace(list=lambda **_kwargs: ()),
        )
        inputs = ReconciliationInputs(
            applications=(application,), preference_records=(), submission_records=(),
            preferences={}, projects={},
        )
        with (
            tempfile.TemporaryDirectory() as directory,
            patch(
                "community_os.release_operations._protected_stage_records",
                return_value=({
                    "subject_ref": subject, "state": "observed",
                    "rich_project_evidence": [project],
                },),
            ),
            patch(
                "community_os.release_operations._resolved_person_links",
                return_value=({}, frozenset()),
            ),
        ):
            service = build_rich_semantic_proposal_service(
                state, base_classification=lambda: [], pseudonym_secret=secret,
                provider_factory=lambda _corpus: FakeProvider(),
                cache=CanonicalJsonCache(Path(directory), clock=lambda: NOW),
                clock=lambda: NOW,
                application_loader=lambda _state: (application,),
                reconciliation_loader=lambda _state: inputs,
            )
            with self.assertRaisesRegex(ValueError, "known identity literal"):
                service()

    def test_reuses_rich_github_application_and_resolved_devpost_without_changing_legacy_records(self) -> None:
        from community_os.enrichment.state import pseudonymous_id
        from community_os.release_operator import ReleaseOperatorState
        from community_os.release_operations import (
            ReconciliationInputs, build_rich_semantic_proposal_service,
        )
        from tests.test_release_operator import source_gate
        from tests.test_rich_semantic_assessment import assessment, project_packet

        secret = b"fixture-pseudonym-secret"
        legacy_records = [{"classifier_version": "deterministic-rules-v1", "sentinel": True}]
        application = {
            "external_id": "app-1", "name": "Jane Private", "email": "jane@example.org",
            "github": "https://github.com/jane-private",
            "experience": "Jane Private built production automation end to end.",
            "impressive_thing": (
                "Designed, implemented, and shipped the same workflow end to end "
                "for 20 schools."
            ),
        }
        submission = SimpleNamespace(
            external_id="submission-1", email="jane@example.org", name="Jane Private",
            submission_title="Private Project Name", demo_present=True,
            payload={
                "About The Project": "A working event platform with deployment evidence.",
                "Built With": "Python, OpenAI, React", "Project Submitted At": "2026-07-01",
            },
        )
        inputs = ReconciliationInputs(
            applications=(application,), preference_records=(),
            submission_records=(submission,), preferences={}, projects={},
        )
        captured: dict[str, object] = {}

        class FakeProvider:
            model = "gpt-5.6-sol"
            reasoning_effort = "high"

            def __call__(self, evidence):
                captured["evidence"] = evidence
                references = sorted({
                    reference
                    for family in evidence.values()
                    for packet in family
                    for reference in packet["evidence_refs"]
                })
                return assessment(evidence_refs=references[:4])

        def provider_factory(corpus):
            captured["corpus"] = corpus
            return FakeProvider()

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = ReleaseOperatorState(
                root, operator_code="privacy_lead",
                event_definition=_current_event_definition(),
                clock=lambda: NOW,
            )
            state.record_public_source_authorization(
                "github", source_gate("applicant_supplied_github", 30), now=NOW,
            )
            subject_ref = pseudonymous_id("app-1", secret=secret, key_version="v1")
            stages = root / "protected" / "stages"
            stages.mkdir(parents=True)
            (stages / "github.json").write_text(json.dumps({
                "created_at": NOW.isoformat(),
                "expires_at": "2099-08-12T12:00:00Z",
                "records": [{
                    "subject_ref": subject_ref, "state": "observed",
                    "rich_project_evidence": [project_packet()],
                }],
                "stage": "github", "stage_output_version": "protected-stage-output-v1",
            }), encoding="utf-8")
            state.pipeline.start("github")
            state.pipeline.complete("github", {"output_hash": "a" * 64, "record_count": 1})
            state.record_semantic_processor_authorization(
                rich_semantic_processor_approval(), now=NOW,
            )
            bindings = root / "protected" / "review-bindings.json"
            bindings.write_text(json.dumps(_review_bindings_payload(
                state,
                {
                    "exact_person_links": {"submission-1": "app-1"},
                    "identity_subjects": {}, "exact_team_links": {}, "team_subjects": {},
                },
            )), encoding="utf-8")
            service = build_rich_semantic_proposal_service(
                state, base_classification=lambda: legacy_records,
                pseudonym_secret=secret, provider_factory=provider_factory,
                cache=__import__(
                    "community_os.enrichment.cache", fromlist=["CanonicalJsonCache"],
                ).CanonicalJsonCache(root / "protected" / "cache" / "rich", clock=lambda: NOW),
                clock=lambda: NOW, application_loader=lambda _state: (application,),
                reconciliation_loader=lambda _state: inputs,
            )

            with patch(
                "community_os.enrichment.semantic_evidence.assert_no_known_identity_literals",
                wraps=__import__(
                    "community_os.enrichment.semantic_evidence",
                    fromlist=["assert_no_known_identity_literals"],
                ).assert_no_known_identity_literals,
            ) as final_identity_scan:
                returned = service()

            self.assertEqual(returned, legacy_records)
            self.assertGreaterEqual(final_identity_scan.call_count, 1)
            self.assertEqual(captured["evidence"]["projects"], [project_packet()])
            self.assertEqual(len(captured["evidence"]["application"]), 1)
            self.assertEqual(len(captured["evidence"]["devpost"]), 1)
            self.assertEqual(captured["evidence"]["career"], [])
            self.assertIn("Jane Private", captured["corpus"])
            self.assertIn("jane@example.org", captured["corpus"])
            cases = [
                case for case in state.review_repository.list(kind="classification")
                if case.version == "rich_semantic_review_v1"
            ]
            self.assertEqual(len(cases), 1)
            self.assertEqual(cases[0].status, "open")
            serialized = next(state.rich_semantic_reviews.proposals.glob("*.json")).read_text()
            stored_proposal = json.loads(serialized)["proposal"]
            self.assertEqual(stored_proposal["model"], "gpt-5.6-sol")
            for private_value in (
                "Jane Private", "jane@example.org", "jane-private", "Private Project Name",
            ):
                self.assertNotIn(private_value, serialized)
            approval = state.pipeline.stage("classification").authorization_hash
            self.assertIn(str(approval), serialized)

    def test_optional_career_loader_is_additive_and_never_required(self) -> None:
        from community_os.enrichment.state import pseudonymous_id
        from community_os.release_operator import ReleaseOperatorState
        from community_os.release_operations import (
            ReconciliationInputs, build_rich_semantic_proposal_service,
        )
        from tests.test_release_operator import source_gate
        from tests.test_rich_semantic_assessment import assessment, project_packet

        secret = b"fixture-pseudonym-secret"
        application = {
            "external_id": "app-1", "name": "Private Person", "email": "private@example.org",
            "experience": "Built products",
            "impressive_thing": (
                "Designed, implemented, and shipped the same system end to end."
            ),
        }
        captured: dict[str, object] = {}
        career = [{
            "role_code": "role_01", "title_excerpt": "Technical founder",
            "description_excerpt": "Led product delivery and operations.",
            "active_state": "current", "duration_band": "one_to_three_years",
            "seniority_context": "founder_executive", "industry_code": "software",
            "organization_size_band": "small",
            "evidence_refs": ["role_01:title", "role_01:description"],
        }]

        class FakeProvider:
            model = "gpt-5.6-luna"
            reasoning_effort = "medium"

            def __call__(self, evidence):
                captured["evidence"] = evidence
                references = sorted({
                    reference
                    for family in evidence.values()
                    for packet in family
                    for reference in packet["evidence_refs"]
                })
                return assessment(evidence_refs=references)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = ReleaseOperatorState(
                root, operator_code="privacy_lead",
                event_definition=_current_event_definition(),
                clock=lambda: NOW,
            )
            state.record_public_source_authorization(
                "github", source_gate("applicant_supplied_github", 30), now=NOW,
            )
            subject = pseudonymous_id("app-1", secret=secret, key_version="v1")
            stages = root / "protected" / "stages"
            stages.mkdir(parents=True)
            (stages / "github.json").write_text(json.dumps({
                "created_at": NOW.isoformat(), "expires_at": "2099-08-12T12:00:00Z",
                "records": [{"subject_ref": subject, "state": "observed",
                             "rich_project_evidence": [project_packet()]}],
                "stage": "github", "stage_output_version": "protected-stage-output-v1",
            }), encoding="utf-8")
            state.pipeline.start("github")
            state.pipeline.complete("github", {"output_hash": "a" * 64, "record_count": 1})
            state.record_semantic_processor_authorization(
                rich_semantic_processor_approval(), now=NOW,
            )
            (root / "protected" / "review-bindings.json").write_text(json.dumps(
                _review_bindings_payload(
                    state, {"exact_person_links": {}, "identity_subjects": {}},
                ),
            ), encoding="utf-8")
            loader_calls: list[tuple[frozenset[str], tuple[str, ...]]] = []

            def career_loader(
                subjects: frozenset[str], *, identity_literals: tuple[str, ...],
            ):
                loader_calls.append((subjects, identity_literals))
                return {subject: career}

            service = build_rich_semantic_proposal_service(
                state, base_classification=lambda: [], pseudonym_secret=secret,
                provider_factory=lambda _corpus: FakeProvider(),
                cache=__import__(
                    "community_os.enrichment.cache", fromlist=["CanonicalJsonCache"],
                ).CanonicalJsonCache(root / "protected" / "cache" / "rich", clock=lambda: NOW),
                clock=lambda: NOW, application_loader=lambda _state: (application,),
                reconciliation_loader=lambda _state: ReconciliationInputs(
                    applications=(application,), preference_records=(), submission_records=(),
                    preferences={}, projects={},
                ),
                career_evidence_loader=career_loader,
            )

            service()

        self.assertEqual(len(loader_calls), 1)
        self.assertEqual(loader_calls[0][0], frozenset({subject}))
        self.assertIn("Private Person", loader_calls[0][1])
        self.assertIn("private@example.org", loader_calls[0][1])
        self.assertEqual(captured["evidence"]["career"], career)


class ReviewedOverrideTests(unittest.TestCase):
    def test_observed_attendance_parses_the_registered_second_event_workbook(self) -> None:
        from community_os.config import load_mapping
        from community_os.event_definition import load_event_definition
        from community_os.release_operator import ReleaseOperatorState
        from community_os.release_operations import _load_observed_attendance
        from tests.test_mapped_workbook_ingest import _write_workbook

        definition = load_event_definition(
            Path(__file__).parent / "fixtures/events/second-hackathon.synthetic.json",
        )
        source = definition.source("attendance")
        mapping = load_mapping(source.mapping_path)

        def attendance_row(
            email: str, approval_status: str, checked_in_at: str,
        ) -> list[str]:
            row = {header: "" for header in mapping.expected_headers}
            for canonical, value in {
                "name": email.split("@", 1)[0],
                "email": email,
                "approval_status": approval_status,
                "checked_in_at": checked_in_at,
            }.items():
                row[mapping.field_map[canonical]] = value
            return [row[header] for header in mapping.expected_headers]

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            workbook = root / "attendance.xlsx"
            _write_workbook(workbook, {
                "Door scans": [
                    list(mapping.expected_headers),
                    attendance_row(
                        "present@example.test", "accepted",
                        "2027-02-20T09:00:00Z",
                    ),
                    attendance_row("accepted@example.test", "confirmed", ""),
                    attendance_row("waitlisted@example.test", "waitlisted", ""),
                ],
            })
            state = ReleaseOperatorState(
                root / "operator",
                operator_code="privacy_lead",
                event_definition=definition,
            )
            state.store_upload(
                "attendance",
                workbook.read_bytes(),
                filename="attendance.xlsx",
            )
            observed = _load_observed_attendance(
                state,
                application_loader=lambda _state: ({}, {}, {}),
            )

        self.assertEqual(observed, {
            "applied": 3,
            "going_accepted": 2,
            "on_site_builders": 1,
        })

    def test_observed_attendance_uses_the_event_funnel_values(self) -> None:
        from community_os.event_definition import load_event_definition
        from community_os.release_operator import ReleaseOperatorState
        from community_os.release_operations import _load_observed_attendance

        definition = load_event_definition(
            Path(__file__).parent / "fixtures/events/second-hackathon.synthetic.json",
        )
        records = (
            SimpleNamespace(
                payload={"approval_status": "accepted"},
                checked_in_at="2027-02-20T09:00:00Z",
            ),
            SimpleNamespace(
                payload={"approval_status": "confirmed"},
                checked_in_at=None,
            ),
            SimpleNamespace(
                payload={"approval_status": "approved"},
                checked_in_at="2027-02-20T09:05:00Z",
            ),
        )
        with tempfile.TemporaryDirectory() as directory:
            state = ReleaseOperatorState(
                Path(directory), operator_code="privacy_lead",
                event_definition=definition,
            )
            observed = _load_observed_attendance(
                state,
                application_loader=lambda _state: ({}, {}, {}, {}),
                attendance_loader=lambda _state: records,
            )

        self.assertEqual(observed, {
            "applied": 4,
            "going_accepted": 2,
            "on_site_builders": 2,
        })

    def test_override_is_derived_only_from_bound_decisions_and_attributable_corrections(self) -> None:
        from community_os.release_operator import ReleaseOperatorState
        from community_os.release_operations import (
            ReconciliationInputs, ReviewCase, ReviewDecision, build_reviewed_override,
        )

        with tempfile.TemporaryDirectory() as directory:
            state = ReleaseOperatorState(
                Path(directory), operator_code="privacy_lead",
                event_definition=_current_event_definition(),
            )
            identity = ReviewCase.create(
                kind="identity", subject_code="member_001",
                reason_codes=("email_mismatch",), candidate_codes=("person_001",),
                source_hashes={"applications": "a" * 64}, version="identity_rules_v1",
            )
            team = ReviewCase.create(
                kind="team", subject_code="team_001",
                reason_codes=("ambiguous_match",), candidate_codes=("project_001",),
                source_hashes={"preferences": "b" * 64}, version="team_rules_v1",
            )
            classification = ReviewCase.create(
                kind="classification", subject_code="class_001",
                reason_codes=("low_confidence",), candidate_codes=(),
                source_hashes={"applications": "a" * 64}, version="semantic_v1",
            )
            rejected_rich = ReviewCase.create(
                kind="classification", subject_code="semantic_001",
                reason_codes=("human_review_required",), candidate_codes=(),
                source_hashes={"evidence": "d" * 64}, version="rich_semantic_review_v1",
            )
            state.replace_review_cases((identity, team, classification, rejected_rich))
            state.decide_identity(identity.case_code, identity.case_hash, "approve", selected_code="person_001")
            state.decide_team(team.case_code, team.case_hash, "project_001")
            state.review_classification(classification.case_code, classification.case_hash, "approved")
            state.review_repository.decide(
                ReviewDecision(
                    case_code=rejected_rich.case_code,
                    case_hash=rejected_rich.case_hash,
                    action="rejected",
                ),
                actor_code="privacy_lead", decided_at=NOW,
            )
            state.record_reviewed_value(
                "going_accepted", source_value=83, reviewed_value=83,
                reason_code="owner_reviewed",
            )
            state.record_reviewed_value(
                "on_site_builders", source_value=72, reviewed_value=78,
                reason_code="owner_corrected",
            )
            state.record_operational_fact(
                "mid_event_departures", value=5, unit="people",
                funnel_stage=False, reason_code="owner_reviewed",
            )
            bindings = _review_bindings_payload(state, {
                    "exact_person_links": {"source_exact": "app_exact"},
                    "exact_team_links": {},
                    "identity_subjects": {
                        "member_001": {
                            "candidate_map": {"person_001": "app_reviewed"},
                            "source_ref": "source_reviewed", "source_kind": "submission",
                        },
                    },
                    "team_subjects": {
                        "team_001": {
                            "candidate_map": {"project_001": "Project B"},
                            "preference_team": "Preference B", "track": "track_b",
                        },
                    },
            })
            path = Path(directory) / "protected" / "review-bindings.json"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(bindings), encoding="utf-8")
            stage_path = Path(directory) / "protected" / "stages" / "classification.json"
            stage_path.parent.mkdir(parents=True, exist_ok=True)
            stage_path.write_text(json.dumps({
                "created_at": "2026-07-13T12:00:00Z", "expires_at": "2099-07-13T12:00:00Z",
                "stage": "classification", "stage_output_version": "protected-stage-output-v1",
                "records": [{
                    "classifier_version": "semantic-v1", "model": "gpt-5.6-terra",
                    "prompt_version": "talent-structured-v1",
                    "processor_approval_hash": "c" * 64,
                }],
            }), encoding="utf-8")
            inputs = ReconciliationInputs(
                applications=(), preference_records=(), submission_records=(),
                preferences={"Exact A": {"track": "track_a"}, "Preference B": {"track": "track_b"}},
                projects={"Exact A": {"track": "track_a"}, "Project B": {"track": "track_b"}},
            )
            override = build_reviewed_override(
                state, generated_at="2026-07-13T12:00:00Z", inputs=inputs,
                observed_attendance={"applied": 286, "going_accepted": 83, "on_site_builders": 72},
            )
        self.assertEqual(override["person_links"], {"source_exact": "app_exact", "source_reviewed": "app_reviewed"})
        self.assertEqual(override["team_links"], {"Exact A": "Exact A", "Preference B": "Project B"})
        self.assertEqual([item["corrected_value"] for item in override["corrections"]], [78])
        self.assertEqual(override["reviewed_values"][0]["decision"], "approved")
        self.assertEqual(override["reviewed_values"][0]["reviewed_value"], 83)
        self.assertEqual(override["operational_facts"][0]["value"], 5)
        self.assertEqual(override["classification_review"]["status"], "approved")
        self.assertEqual(override["classification_review"]["classifier_version"], "semantic-v1")
        self.assertEqual(override["classification_review"]["model"], "gpt-5.6-terra")
        self.assertEqual(
            override["classification_review"]["processor_approval_hash"], "c" * 64,
        )


if __name__ == "__main__":
    unittest.main()
