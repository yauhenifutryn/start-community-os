from __future__ import annotations

from contextlib import contextmanager
import csv
from datetime import UTC, datetime, timedelta
import hashlib
from http.server import ThreadingHTTPServer
import io
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


NOW = datetime(2026, 7, 13, 10, tzinfo=UTC)
SEMANTIC_SIGNING_SECRET = b"release-operator-semantic-test-secret"


def _event_definition():
    from community_os.event_definition import load_event_definition

    return load_event_definition(
        Path(__file__).resolve().parents[1]
        / "config/events/openai-hackathon-2026.json"
    )


def source_gate(scope: str, retention_days: int):
    from community_os.enrichment.gates import PublicSourceGate
    return PublicSourceGate(
        notice_version="notice_v2", notice_sent_at="2026-07-13T08:00:00Z",
        objections_reconciled=True, exclusions_reconciled=True,
        suppressions_reconciled=True, deletions_reconciled=True,
        source_authorization_confirmed=True, provider_terms_version="terms_v1",
        source_scope=scope, purpose_code="aggregate_talent_evidence",
        retention_days=retention_days, accountable_owner="privacy_lead",
        approval_id="approval_001", approved_at="2026-07-13T09:00:00Z",
    )


def processor_approval():
    from community_os.enrichment.classification import ProcessorApproval
    return ProcessorApproval(
        provider="openai_responses", purpose="talent_classification",
        dpa_version="dpa-v1", terms_version="terms-v1",
        retention_mode="zero_retention", region="eu",
        security_profile="approved-v1",
        field_allowlist=frozenset({"subject_ref", "signals", "evidence_refs"}),
        approved_by="start_privacy_owner", approved_at="2026-07-13T09:00:00Z",
    )


def authorize_operator_rich_semantics(state, *, now: datetime) -> str:
    state.record_semantic_processor_authorization(processor_approval(), now=now)
    digest = state.pipeline.stage("classification").authorization_hash
    if not isinstance(digest, str):
        raise AssertionError("classification authorization hash was not persisted")
    return digest


def _seed_validated_operator_sources(root: Path) -> None:
    from community_os.release_operator import ReleaseOperatorState

    state = ReleaseOperatorState(
        root, operator_code="privacy_lead",
        event_definition=_event_definition(),
    )
    with patch(
        "community_os.release_operator._validate_configured_release_source",
        return_value=1,
    ):
        for role, suffix in (
            ("applications", ".csv"),
            ("attendance", ".csv"),
            ("preferences", ".xlsx"),
            ("submissions", ".xlsx"),
        ):
            state.store_upload(
                role, f"synthetic-{role}".encode(), filename=role + suffix,
            )


def _seed_staged_public_bundle(root: Path):
    from community_os.enrichment.release_pipeline import canonical_hash
    from community_os.publication import artifact_set_sha256, _public_html_bytes
    from community_os.release_operator import ReleaseOperatorState

    state = ReleaseOperatorState(
        root,
        operator_code="privacy_lead",
        event_definition=_event_definition(),
    )
    release = root / "protected" / "release"
    release.mkdir(parents=True)
    source_html = release / "talent-brief.real.html"
    source_pdf = release / "talent-brief.real.pdf"
    source_html.write_text(
        '<html><head><style>body{color:#00002c}</style></head><body>'
        '<button data-cohort-select="all" aria-pressed="true">All</button>'
        '<button data-dashboard-metric-select="technical_depth">Depth</button>'
        '<button data-overlap-region="both">Both signals</button>'
        '<div class="pdf-actions"><a href="talent-brief.real.pdf" download>'
        'Download PDF</a></div>'
        '<script>document.documentElement.classList.add("js")</script>'
        '</body></html>',
        encoding="utf-8",
    )
    source_pdf.write_bytes(b"%PDF-sites-bundle\n%%EOF")
    public = root / "public-staging"
    public.mkdir()
    index = public / "index.html"
    pdf = public / "partner-talent-brief.pdf"
    index.write_bytes(_public_html_bytes(source_html.read_bytes()))
    pdf.write_bytes(source_pdf.read_bytes())
    manifest_path = public / "publication-manifest.json"
    manifest = {
        "analytics_enabled": False,
        "artifact_set_sha256": artifact_set_sha256((source_html, source_pdf)),
        "artifact_hashes": {
            "index.html": hashlib.sha256(index.read_bytes()).hexdigest(),
            "partner-talent-brief.pdf": hashlib.sha256(pdf.read_bytes()).hexdigest(),
        },
        "entrypoint": "index.html",
        "manifest_version": "partner-static-bundle-v1",
        "pdf": "partner-talent-brief.pdf",
        "privacy_state": "aggregate_only",
        "public_transform_version": "neutral-public-artifact-names-v1",
        "release_state": "Safe to publish",
    }
    manifest_path.write_text(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    state.pipeline.start("publish")
    state.pipeline.complete("publish", {
        "output_hash": canonical_hash([{
            "artifact_count": 2,
            "manifest_hash": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
            "release_state": "Safe to publish",
        }]),
        "record_count": 1,
    })
    return state


@contextmanager
def _running_release_operator(
    root: Path,
    *,
    stage_operation_factory,
    release_owner: bool = False,
):
    from community_os.release_operator import (
        OperatorAccessPolicy,
        run_release_operator,
    )

    stage_operation_factory.disabled_optional_stages = ()
    created = threading.Event()
    server_box: dict[str, ThreadingHTTPServer] = {}
    errors: list[BaseException] = []

    def server_factory(address, handler):
        server = ThreadingHTTPServer(address, handler)
        server_box["server"] = server
        created.set()
        return server

    def serve() -> None:
        try:
            with patch(
                "community_os.release_operator.ThreadingHTTPServer",
                side_effect=server_factory,
            ):
                run_release_operator(
                    root=root,
                    access_policy=OperatorAccessPolicy(
                        allowed_emails=frozenset({"reviewer@example.org"}),
                        proxy_secret="fixture-proxy-secret",
                        release_owner_emails=(
                            frozenset({"reviewer@example.org"})
                            if release_owner else frozenset()
                        ),
                    ),
                    operator_code="privacy_lead",
                    pseudonym_secret=b"fixture-pseudonym-secret",
                    event_definition=_event_definition(),
                    port=0,
                    stage_operation_factory=stage_operation_factory,
                )
        except BaseException as error:  # pragma: no cover - surfaced below
            errors.append(error)
            created.set()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    if not created.wait(timeout=3):
        raise RuntimeError("test release operator did not start")
    if errors:
        raise errors[0]
    server = server_box["server"]
    try:
        yield (
            f"http://127.0.0.1:{server.server_port}",
            {
                "X-Operator-Email": "reviewer@example.org",
                "X-Operator-Proxy-Secret": "fixture-proxy-secret",
            },
        )
    finally:
        server.shutdown()
        thread.join(timeout=3)
        if thread.is_alive():
            raise RuntimeError("test release operator did not stop")
        if errors:
            raise errors[0]


def _http_result(request: Request) -> tuple[int, bytes]:
    try:
        with urlopen(request, timeout=3) as response:
            return response.status, response.read()
    except HTTPError as error:
        try:
            return error.code, error.read()
        finally:
            error.close()


class ReleaseOperatorTests(unittest.TestCase):
    def test_state_requires_event_definition_before_creating_storage(self) -> None:
        from community_os.release_operator import ReleaseOperatorState

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "operator"

            with self.assertRaises(TypeError):
                ReleaseOperatorState(root, operator_code="privacy_lead")

            self.assertFalse(root.exists())

    def test_server_entry_point_requires_event_definition_before_creating_storage(self) -> None:
        from community_os.release_operator import (
            OperatorAccessPolicy,
            run_release_operator,
        )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "operator"
            policy = OperatorAccessPolicy(
                allowed_emails=frozenset({"operator@example.test"}),
                proxy_secret="operator-proxy-secret",
            )

            with self.assertRaises(TypeError):
                run_release_operator(
                    root=root,
                    access_policy=policy,
                    operator_code="privacy_lead",
                    pseudonym_secret=b"operator-pseudonym-secret",
                )

            self.assertFalse(root.exists())

    def test_current_source_verification_rejects_uploaded_byte_drift(self) -> None:
        from community_os.release_operator import ReleaseOperatorState

        with tempfile.TemporaryDirectory() as directory:
            state = ReleaseOperatorState(
                Path(directory), operator_code="privacy_lead",
            event_definition=_event_definition(),
            )
            with patch(
                "community_os.release_operator._validate_configured_release_source",
                return_value=1,
            ):
                state.store_upload(
                    "applications", b"validated-source",
                    filename="applications.csv",
                )

            state.verify_current_source_files()
            source = state.protected_uploads / "applications.csv"
            source.write_bytes(b"tampered-source")

            with self.assertRaisesRegex(PermissionError, "source file hash drift"):
                state.verify_current_source_files()

    def test_changed_event_approval_discards_prior_review_decisions_and_bindings(self):
        from community_os.release_operations import (
            ReviewCase, ReviewDecision, _persist_review_bindings,
        )
        from community_os.release_operator import ReleaseOperatorState

        with tempfile.TemporaryDirectory() as directory:
            state = ReleaseOperatorState(
                Path(directory), operator_code="privacy_lead",
            event_definition=_event_definition(),
            )
            first = SimpleNamespace(
                event_key=state.event_key,
                event_definition_sha256=state.event_definition_sha256,
                sha256="a" * 64,
                actor_code="release_owner",
                approved_at=NOW,
            )
            state.record_event_approval(first)
            review_case = ReviewCase.create(
                kind="identity", subject_code="candidate_001",
                reason_codes=("ambiguous_match",),
                candidate_codes=("person_001",),
                source_hashes={"applications": "b" * 64},
                version="identity_rules_v1",
            )
            state.review_repository.replace((review_case,))
            state.decide_identity(
                review_case.case_code, review_case.case_hash,
                "approve", selected_code="person_001",
            )
            _persist_review_bindings(state, {"marker": "first_approval"})
            bindings = state.root / "protected" / "review-bindings.json"
            self.assertEqual(state.review_repository.list()[0].status, "resolved")
            self.assertTrue(bindings.is_file())

            changed = SimpleNamespace(
                event_key=state.event_key,
                event_definition_sha256=state.event_definition_sha256,
                sha256="c" * 64,
                actor_code="release_owner",
                approved_at=NOW + timedelta(minutes=1),
            )
            state.record_event_approval(changed)

            self.assertEqual(state.review_repository.list(), ())
            self.assertFalse(bindings.exists())
            self.assertEqual(state.snapshot()["identity_reviews"], {})
            self.assertEqual(state.snapshot()["team_reviews"], {})
            self.assertEqual(state.snapshot()["classification_reviews"], {})

    def test_operator_state_and_page_are_bound_to_the_configured_event(self):
        from community_os.event_definition import load_event_definition
        from community_os.release_operator import (
            ReleaseOperatorState,
            render_release_operator_page,
        )

        repository = Path(__file__).resolve().parents[1]
        source_payload = json.loads(
            (repository / "tests/fixtures/events/second-hackathon.synthetic.json").read_text(
                encoding="utf-8",
            )
        )
        source_payload["sources"] = source_payload["sources"][:2]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_path = root / "event.json"
            config_path.write_text(json.dumps(source_payload), encoding="utf-8")
            definition = load_event_definition(config_path)

            state = ReleaseOperatorState(
                root / "operator",
                operator_code="privacy_lead",
                event_definition=definition,
            )
            state.record_event_summary(
                applied=17,
                accepted=11,
                present=9,
                tracks=("Build", "Health"),
                reason_code="reviewed_source_values",
            )
            snapshot = state.snapshot()
            html = render_release_operator_page(state)

            self.assertEqual(snapshot["event"]["key"], "second-hackathon-synthetic")
            self.assertEqual(snapshot["event"]["name"], "START Krakow Synthetic Hackathon")
            self.assertEqual(snapshot["event"]["definition_sha256"], definition.sha256)
            self.assertEqual(snapshot["event"]["source_total"], 2)
            self.assertEqual(snapshot["event_counts"], {
                "applied": 17, "accepted": 11, "present": 9,
            })
            self.assertEqual(snapshot["event_tracks"], ["Build", "Health"])
            self.assertEqual(state.source_slots, ("applications", "attendance"))
            self.assertIn("START Krakow Synthetic Hackathon", html)
            self.assertIn("11 accepted / 9 present", html)
            self.assertIn("Tracks: Build, Health", html)
            self.assertIn("0 / 2", html)
            self.assertIn("Upload 2 protected exports", html)
            self.assertNotIn("START Warsaw", html)
            self.assertNotIn("83 accepted / 78 present", html)
            self.assertNotIn("Track preferences", html)
            self.assertNotIn("Submissions", html)
            self.assertTrue(snapshot["audit_events"])
            self.assertTrue(all(
                event["event_key"] == definition.event_key
                and event["event_definition_sha256"] == definition.sha256
                for event in snapshot["audit_events"]
            ))

    def test_operator_rejects_reopening_state_with_a_different_event_definition(self):
        from community_os.event_definition import load_event_definition
        from community_os.release_operator import ReleaseOperatorState

        repository = Path(__file__).resolve().parents[1]
        current = load_event_definition(
            repository / "config/events/openai-hackathon-2026.json",
        )
        second = load_event_definition(
            repository / "tests/fixtures/events/second-hackathon.synthetic.json",
        )
        with tempfile.TemporaryDirectory() as directory:
            ReleaseOperatorState(
                directory,
                operator_code="privacy_lead",
                event_definition=current,
            )
            with self.assertRaisesRegex(PermissionError, "different event"):
                ReleaseOperatorState(
                    directory,
                    operator_code="privacy_lead",
                    event_definition=second,
                )

    def test_operator_rejects_same_event_key_with_a_changed_definition_hash(self):
        from community_os.event_definition import load_event_definition
        from community_os.release_operator import ReleaseOperatorState

        repository = Path(__file__).resolve().parents[1]
        current_path = repository / "config/events/openai-hackathon-2026.json"
        current = load_event_definition(current_path)
        payload = json.loads(current_path.read_text(encoding="utf-8"))
        payload["event"]["name"] = "Changed Name"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            changed_path = root / "changed.json"
            changed_path.write_text(json.dumps(payload), encoding="utf-8")
            changed = load_event_definition(changed_path)
            ReleaseOperatorState(
                root / "operator",
                operator_code="privacy_lead",
                event_definition=current,
            )

            self.assertEqual(changed.event_key, current.event_key)
            self.assertNotEqual(changed.sha256, current.sha256)
            with self.assertRaisesRegex(PermissionError, "different event"):
                ReleaseOperatorState(
                    root / "operator",
                    operator_code="privacy_lead",
                    event_definition=changed,
                )

    def test_operator_refresh_rejects_tampered_persisted_event_binding(self):
        from community_os.event_definition import load_event_definition
        from community_os.release_operator import ReleaseOperatorState

        repository = Path(__file__).resolve().parents[1]
        definition = load_event_definition(
            repository / "config/events/openai-hackathon-2026.json",
        )
        with tempfile.TemporaryDirectory() as directory:
            state = ReleaseOperatorState(
                directory,
                operator_code="privacy_lead",
                event_definition=definition,
            )
            payload = json.loads(state.path.read_text(encoding="utf-8"))
            payload["event"]["name"] = "Tampered Event"
            state.path.write_text(json.dumps(payload), encoding="utf-8")

            with self.assertRaisesRegex(PermissionError, "different event"):
                state.refresh()

    def test_event_summary_becomes_unknown_when_its_source_snapshot_changes(self):
        from community_os.release_operator import ReleaseOperatorState

        with tempfile.TemporaryDirectory() as directory:
            state = ReleaseOperatorState(directory, operator_code="privacy_lead", event_definition=_event_definition())
            state.record_event_summary(
                applied=20,
                accepted=12,
                present=10,
                tracks=("Build",),
                reason_code="reviewed_source_values",
            )
            self.assertEqual(state.snapshot()["event_counts"]["accepted"], 12)

            state.record_source(
                "applications",
                sha256="a" * 64,
                row_count=20,
                filename="applications.csv",
            )

            self.assertEqual(state.snapshot()["event_counts"], {
                "applied": None, "accepted": None, "present": None,
            })
            self.assertEqual(state.snapshot()["event_tracks"], [])

    def test_optional_event_sources_render_but_do_not_block_the_operator(self):
        from community_os.event_definition import load_event_definition
        from community_os.release_operator import (
            ReleaseOperatorState,
            render_release_operator_page,
        )

        repository = Path(__file__).resolve().parents[1]
        definition = load_event_definition(
            repository / "tests/fixtures/events/second-hackathon.synthetic.json",
        )
        with tempfile.TemporaryDirectory() as directory:
            state = ReleaseOperatorState(
                directory,
                operator_code="privacy_lead",
                event_definition=definition,
            )
            html = render_release_operator_page(state)

        blockers = html.split('<ul class="blockers">', 1)[1].split("</ul>", 1)[0]
        self.assertIn("Applications", blockers)
        self.assertIn("Attendance", blockers)
        self.assertNotIn("Teams", blockers)
        self.assertNotIn("Submissions", blockers)
        self.assertIn('data-source="teams" accept=".json"', html)
        self.assertIn('data-source="submissions" accept=".json"', html)
        self.assertIn("optional", html)

    def test_event_media_contract_drives_xlsx_and_json_upload_validation(self):
        from community_os.event_definition import load_event_definition
        from community_os.release_operator import ReleaseOperatorState
        from tests.test_mapped_workbook_ingest import _write_workbook

        repository = Path(__file__).resolve().parents[1]
        definition = load_event_definition(
            repository / "tests/fixtures/events/second-hackathon.synthetic.json",
        )
        application_mapping = json.loads(
            definition.source("applications").mapping_path.read_text(encoding="utf-8"),
        )
        team_mapping = json.loads(
            definition.source("teams").mapping_path.read_text(encoding="utf-8"),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            workbook = root / "applications.xlsx"
            _write_workbook(workbook, {
                "Applications 2027": [
                    list(application_mapping["expected_headers"]),
                    ["fixture" for _ in application_mapping["expected_headers"]],
                ],
            })
            state = ReleaseOperatorState(
                root / "operator",
                operator_code="privacy_lead",
                event_definition=definition,
            )

            applications = state.store_upload(
                "applications",
                workbook.read_bytes(),
                filename="applications.xlsx",
            )
            teams = state.store_upload(
                "teams",
                json.dumps([{
                    header: "fixture"
                    for header in team_mapping["expected_headers"]
                }]).encode("utf-8"),
                filename="teams.json",
            )

            self.assertEqual(applications["row_count"], 1)
            self.assertEqual(teams["row_count"], 1)
            self.assertEqual(
                set(state.snapshot()["source_slots"]),
                {"applications", "teams"},
            )

    def test_current_event_csv_upload_uses_its_registered_mapping(self):
        from community_os.config import load_mapping
        from community_os.release_operator import ReleaseOperatorState

        definition = _event_definition()
        mapping = load_mapping(definition.source("applications").mapping_path)
        stream = io.StringIO(newline="")
        writer = csv.writer(stream)
        writer.writerow(mapping.expected_headers)
        writer.writerow(["fixture" for _ in mapping.expected_headers])
        csv_body = stream.getvalue().encode("utf-8")

        with tempfile.TemporaryDirectory() as directory:
            state = ReleaseOperatorState(
                Path(directory),
                operator_code="privacy_lead",
                event_definition=definition,
            )
            stored = state.store_upload(
                "applications",
                csv_body,
                filename="applications.csv",
            )

        self.assertEqual(stored["row_count"], 1)

    def test_current_event_workbook_upload_uses_configured_sheets_and_mapping(self):
        from community_os.release_operator import ReleaseOperatorState
        from tests.test_mapped_workbook_ingest import _write_workbook

        definition = _event_definition()
        source = definition.source("preferences")
        mapping = json.loads(source.mapping_path.read_text(encoding="utf-8"))
        expected_headers = tuple(mapping["expected_headers"])

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            workbook = root / "preferences.xlsx"
            _write_workbook(workbook, {
                source.sheets[0]: [
                    list(expected_headers),
                    ["fixture" for _ in expected_headers],
                ],
                "Not configured": [["unexpected"], ["ignored"]],
            })
            state = ReleaseOperatorState(
                root / "operator",
                operator_code="privacy_lead",
                event_definition=definition,
            )
            stored = state.store_upload(
                "preferences",
                workbook.read_bytes(),
                filename="preferences.xlsx",
            )

        self.assertEqual(stored["row_count"], 1)

    def test_current_submission_upload_accepts_registered_shared_header_workbook(self):
        from community_os.operator_pipeline import DEVPOST_HEADERS
        from community_os.release_operator import ReleaseOperatorState
        from tests.test_mapped_workbook_ingest import _write_workbook

        definition = _event_definition()
        first = {header: "" for header in DEVPOST_HEADERS}
        first.update({
            "Project Title": "Header owner",
            "Submission Url": "https://devpost.com/software/header-owner",
            "Submitter Email": "first@example.test",
        })
        second = dict(first)
        second.update({
            "Project Title": "Shared header",
            "Submission Url": "https://devpost.com/software/shared-header",
            "Submitter Email": "second@example.test",
        })

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            workbook = root / "submissions.xlsx"
            _write_workbook(workbook, {
                "solidgate": [
                    list(DEVPOST_HEADERS),
                    [first[header] for header in DEVPOST_HEADERS],
                ],
                "boski": [[second[header] for header in DEVPOST_HEADERS]],
            })
            state = ReleaseOperatorState(
                root / "operator",
                operator_code="privacy_lead",
                event_definition=definition,
            )
            stored = state.store_upload(
                "submissions",
                workbook.read_bytes(),
                filename="submissions.xlsx",
            )

        self.assertEqual(stored["row_count"], 2)

    def test_json_upload_rejects_records_outside_registered_mapping(self):
        from community_os.event_definition import load_event_definition
        from community_os.release_operator import ReleaseOperatorState

        repository = Path(__file__).resolve().parents[1]
        definition = load_event_definition(
            repository / "tests/fixtures/events/second-hackathon.synthetic.json",
        )
        with tempfile.TemporaryDirectory() as directory:
            state = ReleaseOperatorState(
                Path(directory),
                operator_code="privacy_lead",
                event_definition=definition,
            )
            with self.assertRaisesRegex(ValueError, "missing headers"):
                state.store_upload(
                    "teams",
                    b'[{"id":"team-1"}]',
                    filename="teams.json",
                )

    def test_legacy_operator_state_never_infers_an_event_binding(self):
        from community_os.event_definition import load_event_definition
        from community_os.release_operator import ReleaseOperatorState

        repository = Path(__file__).resolve().parents[1]
        current = load_event_definition(
            repository / "config/events/openai-hackathon-2026.json",
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = ReleaseOperatorState(
                root,
                operator_code="privacy_lead",
                event_definition=current,
            )
            payload = json.loads(state.path.read_text(encoding="utf-8"))
            payload["state_version"] = "release-operator-v1"
            payload.pop("event")
            payload.pop("event_summary")
            payload.pop("reviewed_values")
            payload.pop("operational_facts")
            state.path.write_text(json.dumps(payload), encoding="utf-8")
            state_before = state.path.read_bytes()
            pipeline_before = state.pipeline_path.read_bytes()

            with self.assertRaisesRegex(
                PermissionError, "legacy operator state requires explicit offline migration",
            ):
                ReleaseOperatorState(
                    root,
                    operator_code="privacy_lead",
                    event_definition=current,
                )
            self.assertEqual(state.path.read_bytes(), state_before)
            self.assertEqual(state.pipeline_path.read_bytes(), pipeline_before)

    def test_legacy_operator_rejection_preserves_state_pipeline_and_staging(self):
        from community_os.event_definition import load_event_definition
        from community_os.release_operator import ReleaseOperatorState

        repository = Path(__file__).resolve().parents[1]
        current = load_event_definition(
            repository / "config/events/openai-hackathon-2026.json",
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = ReleaseOperatorState(
                root,
                operator_code="privacy_lead",
                event_definition=current,
            )
            state.pipeline.start("aggregate")
            state.pipeline.complete("aggregate", {
                "output_hash": "a" * 64, "record_count": 1,
            })
            staged = root / "public-staging" / "talent-brief.real.html"
            staged.parent.mkdir(parents=True)
            staged.write_text("stale but rollback-protected", encoding="utf-8")
            payload = json.loads(state.path.read_text(encoding="utf-8"))
            payload["state_version"] = "release-operator-v1"
            for key in ("event", "event_summary", "reviewed_values", "operational_facts"):
                payload.pop(key)
            state.path.write_text(json.dumps(payload), encoding="utf-8")
            before_state = state.path.read_bytes()
            before_pipeline = state.pipeline_path.read_bytes()

            with self.assertRaisesRegex(
                PermissionError, "legacy operator state requires explicit offline migration",
            ):
                ReleaseOperatorState(
                    root,
                    operator_code="privacy_lead",
                    event_definition=current,
                )

            self.assertEqual(state.path.read_bytes(), before_state)
            self.assertEqual(state.pipeline_path.read_bytes(), before_pipeline)
            self.assertEqual(
                staged.read_text(encoding="utf-8"),
                "stale but rollback-protected",
            )

    def test_failed_atomic_upload_install_never_persists_a_validated_source_slot(self):
        from community_os.release_operator import ReleaseOperatorState, ReleaseSourceSlot

        with tempfile.TemporaryDirectory() as directory:
            state = ReleaseOperatorState(
                Path(directory), operator_code="privacy_lead",
            event_definition=_event_definition(),
            )
            original_replace = Path.replace

            def replace(path, target):
                if path.name.endswith(".pending"):
                    raise OSError("fixture replace failure")
                return original_replace(path, target)

            with (
                patch("community_os.release_operator._validate_configured_release_source", return_value=1),
                patch("pathlib.Path.replace", autospec=True, side_effect=replace),
            ):
                with self.assertRaisesRegex(OSError, "replace failure"):
                    state.store_upload(
                        ReleaseSourceSlot.APPLICATIONS, b"fixture", filename="applications.csv",
                    )

            reopened = ReleaseOperatorState(
                Path(directory), operator_code="privacy_lead",
            event_definition=_event_definition(),
            )
            self.assertNotIn("applications", reopened.snapshot()["source_slots"])

    def test_upload_state_failure_restores_prior_bytes_pipeline_and_public_release(self):
        from community_os.release_operator import (
            ReleaseOperatorState, ReleaseSourceSlot, release_export_ready,
        )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = ReleaseOperatorState(root, operator_code="privacy_lead", event_definition=_event_definition())
            with patch("community_os.release_operator._validate_configured_release_source", return_value=1):
                state.store_upload(
                    ReleaseSourceSlot.APPLICATIONS, b"approved bytes",
                    filename="applications.csv",
                )
            for stage in ("aggregate", "report"):
                state.pipeline.start(stage)
                state.pipeline.complete(stage, {
                    "output_hash": "a" * 64, "record_count": 1,
                })
            protected_report = root / "protected" / "release" / "talent-brief.real.html"
            protected_report.parent.mkdir(parents=True)
            protected_report.write_text("approved protected report", encoding="utf-8")
            public = root / "public-staging" / "talent-brief.real.html"
            public.parent.mkdir(parents=True)
            public.write_text("approved public report", encoding="utf-8")
            original = state.snapshot()["source_slots"]["applications"]

            with (
                patch("community_os.release_operator._validate_configured_release_source", return_value=2),
                patch.object(state, "_persist", side_effect=OSError("state persistence failed")),
            ):
                with self.assertRaisesRegex(OSError, "state persistence failed"):
                    state.store_upload(
                        ReleaseSourceSlot.APPLICATIONS, b"replacement bytes",
                        filename="applications.csv",
                    )

            reopened = ReleaseOperatorState(root, operator_code="privacy_lead", event_definition=_event_definition())
            self.assertEqual(
                (root / "protected" / "uploads" / "applications.csv").read_bytes(),
                b"approved bytes",
            )
            self.assertEqual(reopened.snapshot()["source_slots"]["applications"], original)
            self.assertEqual(public.read_text(encoding="utf-8"), "approved public report")
            self.assertTrue(release_export_ready(reopened, "html"))

    def test_restart_recovers_crash_during_upload_install_before_any_export_is_trusted(self):
        from community_os.release_operator import (
            ReleaseOperatorState, ReleaseSourceSlot, release_export_ready,
        )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = ReleaseOperatorState(root, operator_code="privacy_lead", event_definition=_event_definition())
            with patch("community_os.release_operator._validate_configured_release_source", return_value=1):
                state.store_upload(
                    ReleaseSourceSlot.APPLICATIONS, b"approved bytes",
                    filename="applications.csv",
                )
            for stage in ("aggregate", "report"):
                state.pipeline.start(stage)
                state.pipeline.complete(stage, {
                    "output_hash": "a" * 64, "record_count": 1,
                })
            staged = root / "public-staging" / "talent-brief.real.html"
            staged.parent.mkdir(parents=True)
            staged.write_text("stale public report", encoding="utf-8")
            marker = (
                root / "protected" / "uploads"
                / ".applications.upload-transaction.json"
            )
            marker.write_text(json.dumps({
                "slot": "applications", "state": "installing",
                "version": "upload-transaction-v1",
            }), encoding="utf-8")
            (root / "protected" / "uploads" / "applications.csv").write_bytes(
                b"uncommitted replacement bytes",
            )

            reopened = ReleaseOperatorState(root, operator_code="privacy_lead", event_definition=_event_definition())

            self.assertNotIn("applications", reopened.snapshot()["source_slots"])
            self.assertFalse((root / "protected" / "uploads" / "applications.csv").exists())
            self.assertFalse(marker.exists())
            self.assertFalse(staged.exists())
            self.assertFalse(release_export_ready(reopened, "html"))

    def test_changed_subject_exclusion_plan_withdraws_staging_and_audits_only_set_hash(self):
        from community_os.enrichment.evidence_vault import ProtectedEvidenceVault
        from community_os.release_operations import ReviewCase
        from community_os.release_operator import ReleaseOperatorState

        with tempfile.TemporaryDirectory() as directory:
            state = ReleaseOperatorState(
                Path(directory), operator_code="privacy_lead",
            event_definition=_event_definition(),
            )
            staged = state.root / "public-staging" / "talent-brief.real.html"
            staged.parent.mkdir(parents=True)
            staged.write_text("stale", encoding="utf-8")
            derivatives = (
                state.root / "protected" / "stages" / "github.json",
                state.root / "protected" / "cache" / "github" / "entry.json",
                state.root / "protected" / "release" / "private" / "operator-state.real.json",
                state.root / "protected" / "review-bindings.json",
                state.root / "protected" / "review-bindings.json.tmp",
                state.root / "protected" / "rich-semantic-internal.aggregate.json",
                state.root / "protected" / "rich-semantic-review" / "reviewed" / "stale.json",
                state.root / "protected" / "rich-semantic-review" / "receipts" / "stale.json",
            )
            for derivative in derivatives:
                derivative.parent.mkdir(parents=True, exist_ok=True)
                derivative.write_text("stale personal derivative", encoding="utf-8")
            pending_case = ReviewCase.create(
                kind="classification", subject_code="semantic_stale",
                reason_codes=("human_review_required",), candidate_codes=(),
                source_hashes={"proposal": "a" * 64},
                version="rich_semantic_review_v1",
            )
            state.review_repository.replace_for_kinds(
                ("classification",), (pending_case,),
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

            state.invalidate_for_subject_exclusions("a" * 64, excluded_count=2)

            self.assertFalse(staged.exists())
            self.assertTrue(all(not derivative.exists() for derivative in derivatives))
            self.assertEqual(list(vault.records.iterdir()), [])
            self.assertEqual(len(list(vault.receipts.glob("*.json"))), 1)
            self.assertEqual(state.snapshot()["release_state"], "Blocked")
            self.assertEqual(
                state.rich_semantic_reviews.build_aggregate(
                    minimum_group_size=5,
                )["reviewed_denominator"],
                0,
            )
            self.assertEqual(
                state.review_repository.list(kind="classification"), (),
            )
            event = state.snapshot()["audit_events"][-1]
            self.assertEqual(event["action"], "subject_exclusions_changed")
            self.assertEqual(event["subject_code"], "exclusions_aaaaaaaaaaaaaaaa")
            self.assertEqual(event["reason_code"], "rights_request_2")
            self.assertNotIn("pid:", json.dumps(event))

    def test_correction_endpoint_rejects_json_boolean_value(self):
        from community_os.release_operator import ReleaseOperatorState

        with tempfile.TemporaryDirectory() as directory:
            with socket.socket() as listener:
                listener.bind(("127.0.0.1", 0))
                port = listener.getsockname()[1]
            environment = {
                **os.environ,
                "OPERATOR_ALLOWED_EMAILS": "reviewer@example.org",
                "OPERATOR_PROXY_SECRET": "fixture-proxy-secret",
                "OPERATOR_PSEUDONYM_SECRET": "fixture-pseudonym-secret",
            }
            process = subprocess.Popen(
                [
                    sys.executable, "-m", "community_os", "release-operator",
                    "--root", directory, "--port", str(port),
                    "--allow-ephemeral-root",
                    "--event-config", "config/events/openai-hackathon-2026.json",
                ],
                cwd=Path(__file__).resolve().parents[1], env=environment,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            headers = {
                "X-Operator-Email": "reviewer@example.org",
                "X-Operator-Proxy-Secret": "fixture-proxy-secret",
            }
            try:
                page = ""
                startup_deadline = time.monotonic() + 10
                while time.monotonic() < startup_deadline:
                    try:
                        with urlopen(Request(f"http://127.0.0.1:{port}/", headers=headers), timeout=1) as response:
                            page = response.read().decode("utf-8")
                        break
                    except URLError:
                        if process.poll() is not None:
                            self.fail(process.stderr.read())
                        time.sleep(0.02)
                else:
                    self.fail("release operator did not start within 10 seconds")
                csrf = re.search(r'name="operator-csrf" content="([^"]+)"', page)
                self.assertIsNotNone(csrf)
                request = Request(
                    f"http://127.0.0.1:{port}/correction",
                    data=json.dumps({
                        "field": "going_accepted", "source_value": 83,
                        "reviewed_value": True,
                        "reason_code": "owner_correction",
                    }).encode("utf-8"),
                    headers={**headers, "Content-Type": "application/json", "X-Operator-CSRF": csrf.group(1)},
                    method="POST",
                )

                with self.assertRaises(HTTPError) as rejected:
                    urlopen(request, timeout=2)
                self.assertEqual(rejected.exception.code, 400)
                rejected.exception.close()
                state = ReleaseOperatorState(Path(directory), operator_code="privacy_lead", event_definition=_event_definition())
                self.assertEqual(state.snapshot()["corrections"], {})
            finally:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)
                if process.stdout is not None:
                    process.stdout.close()
                if process.stderr is not None:
                    process.stderr.close()

    def test_live_operator_refresh_observes_external_cleanup_invalidation(self):
        from community_os.release_operator import ReleaseOperatorState, release_export_ready

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            live = ReleaseOperatorState(root, operator_code="privacy_lead", event_definition=_event_definition())
            for stage in ("aggregate", "report"):
                live.pipeline.start(stage)
                live.pipeline.complete(stage, {"output_hash": "a" * 64, "record_count": 1})
            protected_report = root / "protected" / "release" / "talent-brief.real.html"
            protected_report.parent.mkdir(parents=True)
            protected_report.write_text("current protected report", encoding="utf-8")
            self.assertTrue(release_export_ready(live, "html"))

            cleanup_process = ReleaseOperatorState(root, operator_code="privacy_lead", event_definition=_event_definition())
            cleanup_process.invalidate_for_retention_expiry(["github"])
            self.assertTrue(release_export_ready(live, "html"))

            live.refresh()

            self.assertFalse(release_export_ready(live, "html"))

    def test_live_operator_refresh_observes_external_rich_review_cases(self):
        from community_os.release_operator import ReleaseOperatorState
        from community_os.release_operations import ReviewCase, ReviewRepository

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            live = ReleaseOperatorState(root, operator_code="privacy_lead", event_definition=_event_definition())
            case = ReviewCase.create(
                kind="classification", subject_code="semantic_external",
                reason_codes=("human_review_required",), candidate_codes=(),
                source_hashes={"proposal": "a" * 64},
                version="rich_semantic_review_v1",
            )
            external = ReviewRepository(root / "protected" / "review-cases.json")
            external.replace_for_kinds(("classification",), (case,))

            self.assertEqual(live.snapshot()["rich_semantic_status"]["pending"], 0)
            live.refresh()

            self.assertEqual(live.snapshot()["rich_semantic_status"]["pending"], 1)

    def test_operator_rich_review_projects_fact_and_deletes_private_evidence(self):
        from community_os.release_operator import ReleaseOperatorState
        from community_os.rich_semantic_review import RichSemanticReviewStore
        from tests.test_rich_semantic_review import NOW, proposal

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            now = datetime.now(UTC)
            state = ReleaseOperatorState(root, operator_code="privacy_lead", event_definition=_event_definition())
            state.configure_semantic_release_authority(SEMANTIC_SIGNING_SECRET)
            approval_sha256 = authorize_operator_rich_semantics(state, now=now)
            store = RichSemanticReviewStore(
                root / "protected" / "rich-semantic-review",
                release_root=root / "protected" / "release",
                review_repository=state.review_repository,
                clock=lambda: now,
                approval_verifier=lambda digest: digest == approval_sha256,
                review_context_hashes=state.rich_semantic_reviews.review_context_hashes,
            )
            candidate = proposal(
                1,
                approval_sha256=approval_sha256,
                created_at=(now - timedelta(minutes=1)).isoformat(),
                expires_at=(now + timedelta(days=1)).isoformat(),
            )
            case = store.submit(candidate)
            review_cache = state.rich_semantic_reviews.transient_cache_root
            reviewed_cache_file = review_cache / f"{case.case_code}.json"
            reviewed_cache_file.write_text("transient", encoding="utf-8")
            peer_cache_file = review_cache / "interrupted-peer.json"
            peer_cache_file.write_text("transient", encoding="utf-8")
            deterministic_cache_file = (
                root / "protected" / "cache" / "classification" / "peer.json"
            )
            deterministic_cache_file.parent.mkdir(parents=True, mode=0o700)
            deterministic_cache_file.write_text("{}\n", encoding="utf-8")
            github_cache_file = root / "protected" / "cache" / "github" / "peer.json"
            github_cache_file.parent.mkdir(parents=True, mode=0o700)
            github_cache_file.write_text("{}\n", encoding="utf-8")
            coresignal_cache_file = (
                root / "protected" / "cache" / "coresignal" / "peer.json"
            )
            coresignal_cache_file.parent.mkdir(parents=True, mode=0o700)
            coresignal_cache_file.write_text("{}\n", encoding="utf-8")

            state.review_classification(
                case.case_code, case.case_hash, "approved",
            )

            self.assertFalse(any(store.proposals.glob("*.json")))
            self.assertFalse(any(store.transient.glob("*.json")))
            self.assertTrue(any(store.reviewed.glob("*.json")))
            self.assertFalse(reviewed_cache_file.exists())
            self.assertTrue(peer_cache_file.exists())
            self.assertTrue(deterministic_cache_file.exists())
            self.assertTrue(github_cache_file.exists())
            self.assertTrue(coresignal_cache_file.exists())
            status = state.snapshot()["rich_semantic_status"]
            self.assertEqual(status["pending"], 0)
            self.assertEqual(status["reviewed"], 1)

    def test_resolved_case_without_rich_projection_is_not_counted_as_reviewed(self):
        from community_os.release_operator import ReleaseOperatorState
        from community_os.release_operations import ReviewDecision
        from community_os.rich_semantic_review import RichSemanticReviewStore
        from tests.test_rich_semantic_review import NOW, proposal

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = ReleaseOperatorState(root, operator_code="privacy_lead", event_definition=_event_definition())
            store = RichSemanticReviewStore(
                root / "protected" / "rich-semantic-review",
                release_root=root / "protected" / "release",
                review_repository=state.review_repository,
                clock=lambda: NOW,
                approval_verifier=lambda digest: digest == "a" * 64,
                review_context_hashes=state.rich_semantic_reviews.review_context_hashes,
            )
            case = store.submit(proposal(1))
            state.review_repository.decide(
                ReviewDecision(
                    case_code=case.case_code, case_hash=case.case_hash,
                    action="approved", corrected_output=None,
                ),
                actor_code="privacy_lead", decided_at=NOW,
            )

            status = state.snapshot()["rich_semantic_status"]

            self.assertEqual(status["reviewed"], 0)
            self.assertEqual(status["projection_incomplete"], 1)

    def test_authenticated_colleagues_receive_distinct_pseudonymous_actor_codes(self):
        from community_os.release_operator import OperatorAccessPolicy

        policy = OperatorAccessPolicy(
            allowed_emails=frozenset({"one@example.org", "two@example.org"}),
            proxy_secret="proxy-secret",
        )
        one_headers = {
            "X-Operator-Email": "one@example.org",
            "X-Operator-Proxy-Secret": "proxy-secret",
        }
        two_headers = {
            "X-Operator-Email": "two@example.org",
            "X-Operator-Proxy-Secret": "proxy-secret",
        }

        one = policy.pseudonymous_actor(one_headers, secret=b"fixture-pseudonym-secret")
        two = policy.pseudonymous_actor(two_headers, secret=b"fixture-pseudonym-secret")

        self.assertRegex(one, r"^colleague_[0-9a-f]{32}$")
        self.assertNotEqual(one, two)
        self.assertNotIn("@", one + two)

    def test_only_explicit_authenticated_release_owner_can_issue_final_approval(self):
        from community_os.release_operator import OperatorAccessPolicy

        policy = OperatorAccessPolicy(
            allowed_emails=frozenset({"owner@example.org", "reviewer@example.org"}),
            proxy_secret="proxy-secret",
            release_owner_emails=frozenset({"owner@example.org"}),
        )
        owner = {
            "X-Operator-Email": "owner@example.org",
            "X-Operator-Proxy-Secret": "proxy-secret",
        }
        reviewer = {
            "X-Operator-Email": "reviewer@example.org",
            "X-Operator-Proxy-Secret": "proxy-secret",
        }
        self.assertTrue(policy.authorize_release_owner(owner))
        self.assertFalse(policy.authorize_release_owner(reviewer))
        self.assertFalse(policy.authorize_release_owner({
            **owner, "X-Operator-Proxy-Secret": "wrong-secret",
        }))
        with self.assertRaisesRegex(ValueError, "allowlisted"):
            OperatorAccessPolicy(
                allowed_emails=frozenset({"reviewer@example.org"}),
                proxy_secret="proxy-secret",
                release_owner_emails=frozenset({"owner@example.org"}),
            )

    def test_state_audit_can_attribute_a_mutation_to_request_actor(self):
        from community_os.release_operator import ReleaseOperatorState

        with tempfile.TemporaryDirectory() as directory:
            state = ReleaseOperatorState(Path(directory), operator_code="privacy_lead", event_definition=_event_definition())
            with state.acting_as("colleague_" + "a" * 32):
                state.apply_correction("going_accepted", 82, reason_code="owner_correction")

            event = next(
                item for item in reversed(state.snapshot()["audit_events"])
                if item["action"] == "correction_applied"
            )
            self.assertEqual(event["actor_code"], "colleague_" + "a" * 32)

    def test_access_audit_is_append_only_pseudonymous_and_restrictive(self):
        from community_os.release_operator import (
            ReleaseOperatorState,
            append_operator_access_audit,
        )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = ReleaseOperatorState(root, operator_code="privacy_lead", event_definition=_event_definition())
            append_operator_access_audit(
                root, action="artifact_exported", actor_code="colleague_" + "a" * 32,
                subject_code="pdf", reason_code="authenticated_request",
            )
            append_operator_access_audit(
                root, action="stage_requested", actor_code="colleague_" + "b" * 32,
                subject_code="report", reason_code="operator_requested",
            )
            path = root / "protected" / "operator-access-audit.jsonl"
            events = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]

            self.assertEqual(len(events), 2)
            self.assertEqual(events[0]["action"], "artifact_exported")
            self.assertTrue(all(
                event["event_key"] == state.event_key
                and event["event_definition_sha256"] == state.event_definition_sha256
                for event in events
            ))
            self.assertNotIn("@", str(events))
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_restart_recovers_interrupted_stage_as_resumable_failure(self):
        from community_os.enrichment.state import StageStatus
        from community_os.release_operator import ReleaseOperatorState

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = ReleaseOperatorState(root, operator_code="release_owner", event_definition=_event_definition())
            state.pipeline.start("reconcile")

            reopened = ReleaseOperatorState(root, operator_code="release_owner", event_definition=_event_definition())

            record = reopened.pipeline.stage("reconcile")
            self.assertEqual(record.status, StageStatus.FAILED)
            self.assertEqual(record.reason_code, "interrupted")

    def test_invalidated_release_cannot_be_previewed_or_exported(self):
        from community_os.release_operator import ReleaseOperatorState, release_export_ready

        with tempfile.TemporaryDirectory() as directory:
            state = ReleaseOperatorState(Path(directory), operator_code="release_owner", event_definition=_event_definition())
            for stage in ("aggregate", "report"):
                state.pipeline.start(stage)
                state.pipeline.complete(stage, {
                    "output_hash": "a" * 64, "record_count": 1,
                })
            release = state.root / "protected" / "release"
            release.mkdir(parents=True)
            (release / "talent-brief.real.html").write_text("current report", encoding="utf-8")
            (release / "talent-intelligence-v1.real.aggregate.json").write_text("{}", encoding="utf-8")
            (release / "talent-report-v3.real.aggregate.json").write_text("{}", encoding="utf-8")
            self.assertTrue(release_export_ready(state, "html"))
            self.assertTrue(release_export_ready(state, "aggregates"))

            state.block_for_invalid_approval(reason_code="approval_record_invalid")

            self.assertFalse(release_export_ready(state, "html"))
            self.assertFalse(release_export_ready(state, "aggregates"))

    def test_semantic_candidate_can_be_previewed_but_not_exported_before_signed_approval(self):
        from community_os.release_operator import (
            ReleaseOperatorState,
            release_export_ready,
        )

        with tempfile.TemporaryDirectory() as directory:
            state = ReleaseOperatorState(
                Path(directory), operator_code="privacy_lead",
            event_definition=_event_definition(),
            )
            for stage in ("aggregate", "report"):
                state.pipeline.start(stage)
                state.pipeline.complete(stage, {
                    "output_hash": "a" * 64, "record_count": 1,
                })
            protected = state.root / "protected"
            release = protected / "release"
            release.mkdir(parents=True)
            (protected / "rich-semantic-internal.aggregate.json").write_text(
                "{}", encoding="utf-8",
            )
            (release / "talent-brief.real.html").write_text(
                "candidate", encoding="utf-8",
            )

            self.assertTrue(release_export_ready(
                state, "html", allow_candidate_preview=True,
            ))
            self.assertFalse(release_export_ready(state, "html"))

    def test_signed_semantic_candidate_for_different_event_is_never_export_ready(self):
        from community_os.partner_semantic_projection import (
            build_partner_semantic_summary,
            semantic_summary_manifest_binding,
        )
        from community_os.publication import artifact_set_sha256
        from community_os.release_operator import (
            ReleaseOperatorState,
            release_export_ready,
        )
        from community_os.semantic_metrics import semantic_aggregate_sha256
        from community_os.semantic_release_approval import (
            build_semantic_release_candidate,
            issue_semantic_release_approval,
            validate_semantic_release_approval_record,
        )
        from tests.test_partner_semantic_projection import semantic_aggregate

        with tempfile.TemporaryDirectory() as directory:
            state = ReleaseOperatorState(
                Path(directory), operator_code="privacy_lead",
            event_definition=_event_definition(),
            )
            secret = b"wrong-event-semantic-approval-secret"
            state.configure_semantic_release_authority(secret)
            for stage in ("aggregate", "report"):
                state.pipeline.start(stage)
                state.pipeline.complete(stage, {
                    "output_hash": "a" * 64, "record_count": 1,
                })
            protected = state.root / "protected"
            release = protected / "release"
            release.mkdir(parents=True)
            aggregate = semantic_aggregate()
            aggregate["bindings"]["event_key"] = "different-event"
            aggregate_path = protected / "rich-semantic-internal.aggregate.json"
            aggregate_path.write_text(json.dumps(aggregate), encoding="utf-8")
            public_paths = tuple(
                release / name for name in (
                    "talent-brief.real.html", "talent-brief.real.pdf",
                    "talent-intelligence-v1.real.aggregate.json",
                    "talent-report-v3.real.aggregate.json",
                )
            )
            for index, path in enumerate(public_paths):
                path.write_bytes(f"artifact-{index}".encode("ascii"))
            qa_path = protected / "semantic-release-qa.json"
            qa_path.write_text('{"state":"complete"}', encoding="utf-8")
            candidate = build_semantic_release_candidate(
                aggregate,
                qa_sha256=hashlib.sha256(qa_path.read_bytes()).hexdigest(),
                report_candidate_sha256=artifact_set_sha256(public_paths),
                html_sha256=hashlib.sha256(public_paths[0].read_bytes()).hexdigest(),
                pdf_sha256=hashlib.sha256(public_paths[1].read_bytes()).hexdigest(),
            )
            approval_time = datetime(2026, 7, 15, 12, tzinfo=UTC)
            record = issue_semantic_release_approval(
                candidate,
                actor_code="colleague_0123456789abcdef0123456789abcdef",
                approved_at=approval_time,
                expires_at=approval_time + timedelta(days=1),
                signing_secret=secret,
            )
            approval_path = protected / "semantic-release-approval.json"
            approval_path.write_text(json.dumps(record), encoding="utf-8")
            approved = validate_semantic_release_approval_record(
                record, candidate=candidate, now=approval_time,
                signing_secret=secret,
            )
            summary = build_partner_semantic_summary(
                approved, approval_secret=secret, now=approval_time,
            )
            (release / "talent-report-v3.real.manifest.json").write_text(
                json.dumps({
                    "semantic_enrichment": semantic_summary_manifest_binding(summary),
                }),
                encoding="utf-8",
            )

            self.assertRegex(semantic_aggregate_sha256(aggregate), r"^[0-9a-f]{64}$")
            for artifact in ("html", "pdf", "aggregates", "manifest"):
                with self.subTest(artifact=artifact):
                    self.assertFalse(release_export_ready(state, artifact))

    def test_pending_rich_proposal_revokes_stale_release_until_review_and_fresh_render(self):
        from community_os.release_operator import ReleaseOperatorState, release_export_ready
        from tests.test_rich_semantic_review import proposal

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            now = datetime.now(UTC)
            state = ReleaseOperatorState(root, operator_code="release_owner", event_definition=_event_definition())
            state.configure_semantic_release_authority(SEMANTIC_SIGNING_SECRET)
            approval_sha256 = authorize_operator_rich_semantics(state, now=now)
            for stage in ("aggregate", "report"):
                state.pipeline.start(stage)
                state.pipeline.complete(stage, {
                    "output_hash": "a" * 64, "record_count": 1,
                })
            release = root / "protected" / "release"
            release.mkdir(parents=True)
            (release / "talent-brief.real.html").write_text(
                "previous approved report", encoding="utf-8",
            )
            staged = root / "public-staging" / "talent-brief.real.html"
            staged.parent.mkdir(parents=True)
            staged.write_text("previous public staging", encoding="utf-8")
            qa = root / "protected" / "semantic-release-qa.json"
            approval = root / "protected" / "semantic-release-approval.json"
            qa.write_text("{}", encoding="utf-8")
            approval.write_text("{}", encoding="utf-8")
            self.assertTrue(release_export_ready(state, "html"))

            case = state.rich_semantic_reviews.submit(proposal(
                1,
                approval_sha256=approval_sha256,
                created_at=(now - timedelta(minutes=1)).isoformat(),
                expires_at=(now + timedelta(days=1)).isoformat(),
            ))

            snapshot = state.snapshot()
            self.assertEqual(snapshot["release_state"], "Blocked")
            self.assertFalse(staged.exists())
            self.assertFalse(qa.exists())
            self.assertFalse(approval.exists())
            self.assertEqual(
                snapshot["rich_semantic_status"]["next_action"],
                "Review 1 pending rich semantic proposal.",
            )
            self.assertFalse(release_export_ready(state, "html"))

            for stage in ("aggregate", "report"):
                state.pipeline.start(stage)
                state.pipeline.complete(stage, {
                    "output_hash": "b" * 64, "record_count": 1,
                })
            self.assertFalse(release_export_ready(state, "html"))

            state.review_classification(
                case.case_code, case.case_hash, "approved",
            )
            for stage in ("aggregate", "report"):
                state.pipeline.start(stage)
                state.pipeline.complete(stage, {
                    "output_hash": "c" * 64, "record_count": 1,
                })

            self.assertTrue(release_export_ready(state, "html"))

    def test_completed_stage_without_artifact_file_is_not_export_ready(self):
        from community_os.release_operator import ReleaseOperatorState, release_export_ready

        with tempfile.TemporaryDirectory() as directory:
            state = ReleaseOperatorState(Path(directory), operator_code="release_owner", event_definition=_event_definition())
            for stage in ("aggregate", "report"):
                state.pipeline.start(stage)
                state.pipeline.complete(stage, {
                    "output_hash": "a" * 64, "record_count": 1,
                })

            self.assertFalse(release_export_ready(state, "html"))
            self.assertFalse(release_export_ready(state, "pdf"))
            self.assertFalse(release_export_ready(state, "aggregates"))
            release = state.root / "protected" / "release"
            release.mkdir(parents=True)
            (release / "talent-intelligence-v1.real.aggregate.json").write_text(
                "{}", encoding="utf-8",
            )
            self.assertFalse(release_export_ready(state, "aggregates"))

    def test_manifest_export_requires_current_pipeline_state(self):
        from community_os.enrichment.release_pipeline import ReleasePipeline
        from community_os.release_operator import ReleaseOperatorState, release_export_ready

        with tempfile.TemporaryDirectory() as directory:
            state = ReleaseOperatorState(Path(directory), operator_code="privacy_lead", event_definition=_event_definition())
            pipeline = ReleasePipeline(
                state.pipeline, manifest_path=state.root / "protected" / "enrichment-manifest.json",
            )
            pipeline.write_manifest()
            for stage in ("aggregate", "report"):
                state.pipeline.start(stage)
                state.pipeline.complete(stage, {"output_hash": "a" * 64, "record_count": 1})

            self.assertFalse(release_export_ready(state, "manifest"))

            pipeline.write_manifest()

            self.assertTrue(release_export_ready(state, "manifest"))

    def test_authorization_records_unlock_only_the_bound_provider_stages(self):
        from community_os.enrichment.gates import CoresignalGate
        from community_os.enrichment.state import StageStatus
        from community_os.release_operator import ReleaseOperatorState

        with tempfile.TemporaryDirectory() as directory:
            state = ReleaseOperatorState(Path(directory), operator_code="privacy_lead", event_definition=_event_definition())
            self.assertEqual(state.pipeline.stage("classification").status, StageStatus.LOCKED)
            state.record_public_source_authorization(
                "github", source_gate("applicant_supplied_github", 30), now=NOW,
            )
            self.assertEqual(state.pipeline.stage("github").status, StageStatus.ALLOWED)
            self.assertEqual(state.pipeline.stage("public_pages").status, StageStatus.LOCKED)
            self.assertEqual(state.pipeline.stage("coresignal").status, StageStatus.LOCKED)
            gate = CoresignalGate(
                notice_version="coresignal_transparency_v1", notice_sent_at="2026-07-13T08:00:00Z",
                notice_scope="linkedin_coresignal_enrichment",
                notice_content_sha256="d" * 64,
                objections_reconciled=True, exclusions_reconciled=True,
                suppressions_reconciled=True, deletions_reconciled=True,
                access_verified=True, provider_terms_version="coresignal_terms_v1",
                source_scope="applicant_supplied_linkedin", retention_days=14,
                approval_id="release_approval_001",
                approved_at="2026-07-13T09:00:00Z",
            )
            state.record_coresignal_authorization(gate, now=NOW)
            self.assertEqual(state.pipeline.stage("coresignal").status, StageStatus.ALLOWED)
            state.record_semantic_processor_authorization(processor_approval(), now=NOW)
            self.assertEqual(state.pipeline.stage("classification").status, StageStatus.ALLOWED)
            self.assertEqual(state.snapshot()["privacy_operations"]["notice"], "recorded")
            self.assertTrue(all(
                "@" not in str(event) and "token" not in str(event).casefold()
                for event in state.snapshot()["audit_events"]
            ))

    def test_revoking_provider_authorization_deletes_its_raw_evidence(self):
        from community_os.enrichment.evidence_vault import ProtectedEvidenceVault
        from community_os.release_operator import ReleaseOperatorState

        with tempfile.TemporaryDirectory() as directory:
            state = ReleaseOperatorState(Path(directory), operator_code="privacy_lead", event_definition=_event_definition())
            state.record_public_source_authorization(
                "github", source_gate("applicant_supplied_github", 30), now=NOW,
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

            state.revoke_stage_authorization("github", reason_code="owner_revoked")

            self.assertEqual(list(vault.records.iterdir()), [])
            self.assertEqual(len(list(vault.receipts.glob("*.json"))), 1)

    def test_access_policy_requires_proxy_secret_and_allowlisted_colleague(self):
        from community_os.release_operator import OperatorAccessPolicy
        policy = OperatorAccessPolicy(
            allowed_emails=frozenset({"colleague@example.org"}), proxy_secret="proxy-secret"
        )
        self.assertTrue(policy.authorize({
            "X-Operator-Email": "colleague@example.org",
            "X-Operator-Proxy-Secret": "proxy-secret",
        }))
        self.assertFalse(policy.authorize({"X-Operator-Email": "other@example.org", "X-Operator-Proxy-Secret": "proxy-secret"}))
        self.assertFalse(policy.authorize({"X-Operator-Email": "colleague@example.org", "X-Operator-Proxy-Secret": "wrong"}))

    def test_state_has_four_sources_durable_reviews_stages_and_protected_paths(self):
        from community_os.release_operator import ReleaseOperatorState, ReleaseSourceSlot
        from community_os.release_operations import ReviewCase
        with tempfile.TemporaryDirectory() as directory:
            state = ReleaseOperatorState(Path(directory), operator_code="release_owner", event_definition=_event_definition())
            self.assertEqual(set(state.source_slots), {
                "applications", "attendance", "preferences", "submissions",
            })
            identity = ReviewCase.create(
                kind="identity", subject_code="candidate_001",
                reason_codes=("email_mismatch",), candidate_codes=("person_001",),
                source_hashes={"applications": "a" * 64}, version="identity_rules_v1",
            )
            team = ReviewCase.create(
                kind="team", subject_code="team_001",
                reason_codes=("ambiguous_match",), candidate_codes=("project_001",),
                source_hashes={"preferences": "b" * 64}, version="team_rules_v1",
            )
            classification = ReviewCase.create(
                kind="classification", subject_code="case_001",
                reason_codes=("low_confidence",), candidate_codes=(),
                source_hashes={"applications": "a" * 64}, version="semantic_v1",
            )
            state.replace_review_cases((identity, team, classification))
            state.apply_correction("going_accepted", 82, reason_code="owner_correction")
            state.apply_correction("going_accepted", 81, reason_code="second_review")
            state.decide_identity(identity.case_code, identity.case_hash, "quarantine")
            state.decide_team(team.case_code, team.case_hash, "project_001")
            state.review_classification(classification.case_code, classification.case_hash, "approved")
            snapshot = state.snapshot()
            self.assertEqual(snapshot["corrections"]["going_accepted"]["value"], 81)
            self.assertEqual(snapshot["identity_reviews"][identity.case_code], "quarantine")
            self.assertEqual(snapshot["team_reviews"][team.case_code], "project_001")
            self.assertEqual(snapshot["classification_reviews"][classification.case_code], "approved")
            self.assertTrue(all(item["status"] == "resolved" for item in snapshot["review_cases"]))
            self.assertEqual(snapshot["stages"]["reconcile"]["status"], "allowed")
            self.assertEqual(snapshot["stages"]["coresignal"]["status"], "locked")
            self.assertEqual(snapshot["stages"]["github"]["status"], "locked")
            self.assertEqual(snapshot["stages"]["public_pages"]["status"], "locked")
            self.assertEqual(snapshot["release_state"], "Blocked")
            actions = [event["action"] for event in snapshot["audit_events"]]
            self.assertEqual(actions.count("correction_applied"), 2)
            self.assertEqual(actions.count("release_invalidated"), 5)
            self.assertNotIn("@", str(snapshot["audit_events"]))
            self.assertEqual(oct((Path(directory).stat().st_mode & 0o777)), "0o700")

    def test_equal_reviewed_value_is_an_approval_and_operational_fact_is_separate(self):
        from community_os.release_operator import ReleaseOperatorState

        with tempfile.TemporaryDirectory() as directory:
            state = ReleaseOperatorState(directory, operator_code="privacy_lead", event_definition=_event_definition())
            state.record_reviewed_value(
                "going_accepted",
                source_value=83,
                reviewed_value=83,
                reason_code="owner_reviewed",
            )
            state.record_reviewed_value(
                "on_site_builders",
                source_value=72,
                reviewed_value=78,
                reason_code="owner_corrected",
            )
            state.record_operational_fact(
                "mid_event_departures",
                value=5,
                unit="people",
                funnel_stage=False,
                reason_code="owner_reviewed",
            )

            snapshot = state.snapshot()

        self.assertEqual(
            snapshot["reviewed_values"]["going_accepted"]["decision"],
            "approved",
        )
        self.assertEqual(
            snapshot["reviewed_values"]["on_site_builders"]["decision"],
            "corrected",
        )
        self.assertNotIn("going_accepted", snapshot["corrections"])
        self.assertEqual(snapshot["corrections"]["on_site_builders"], {
            "reason_code": "owner_corrected", "value": 78,
        })
        self.assertEqual(snapshot["operational_facts"]["mid_event_departures"], {
            "funnel_stage": False,
            "reason_code": "owner_reviewed",
            "source_snapshot_sha256": state.source_snapshot_sha256(),
            "unit": "people",
            "value": 5,
        })
        self.assertEqual(
            [
                event["action"] for event in snapshot["audit_events"]
                if event["subject_code"] in {
                    "going_accepted", "on_site_builders", "mid_event_departures",
                }
            ],
            ["source_value_approved", "source_value_corrected", "operational_fact_recorded"],
        )

    def test_operator_rejects_invented_review_codes(self):
        from community_os.release_operator import ReleaseOperatorState
        with tempfile.TemporaryDirectory() as directory:
            state = ReleaseOperatorState(Path(directory), operator_code="release_owner", event_definition=_event_definition())
            with self.assertRaisesRegex(ValueError, "unknown review case"):
                state.decide_identity("identity_missing", "a" * 64, "quarantine")

    def test_page_exposes_complete_operator_workflow_without_public_person_search(self):
        from community_os.release_operator import ReleaseOperatorState, render_release_operator_page
        from community_os.release_operations import ReviewCase
        with tempfile.TemporaryDirectory() as directory:
            state = ReleaseOperatorState(Path(directory), operator_code="release_owner", event_definition=_event_definition())
            case = ReviewCase.create(
                kind="identity", subject_code="candidate_001",
                reason_codes=("email_mismatch",), candidate_codes=("person_001",),
                source_hashes={"applications": "a" * 64}, version="identity_rules_v1",
            )
            classification_case = ReviewCase.create(
                kind="classification", subject_code="candidate_001",
                reason_codes=("low_confidence",), candidate_codes=(),
                source_hashes={"applications": "a" * 64}, version="classification_rules_v1",
            )
            state.replace_review_cases((case, classification_case))
            html = render_release_operator_page(state)
        required_sources = ("applications", "attendance", "preferences", "submissions")
        self.assertEqual(html.count('type="file"'), 4)
        for source in required_sources:
            self.assertEqual(html.count(f'data-source="{source}"'), 1)
        self.assertEqual(html.count(">Blocked<"), 1)
        for expected in (
            "Upload 4 protected exports", "Applications", "Attendance", "Track preferences", "Submissions",
            "Schema &amp; hash validation", "Reviewed source values", "Identity resolution", "Team linking",
            "Privacy Operations", "Semantic review", "Preview partner report",
            "Export partner HTML", "Export partner PDF", "Export publication manifest",
            "Export aggregates", "Export pipeline manifest", "Export QA report",
            "Generate current HTML and PDF", "Does not enrich or share",
            "Run approved release",
            "Release overview", "Action required", "Pipeline sequence",
            'data-summary="sources"', 'data-summary="reviews"',
            'aria-label="Release sequence"', "What blocks sharing",
            "Blocked", "Needs review", "Approved for sharing", 'aria-live="polite"', "dragover",
            "'/correction'", "'/identity-review'", "'/team-review'",
            "'/classification-review'",
            "Optional internal-only Coresignal evaluation", "data-corrected-output",
            "not covered by the participant notice",
            "retained records never enter partner output",
            "reviewed aggregate semantic facts require exact release approval",
            "GitHub semantic assessment", "Required for release",
            'data-review-action="corrected"', "JSON.parse",
            "1. Upload", "2. Review", "3. Run", "4. Preview", "5. Approve",
            "6. Export", "Waiting for approval", "Ready to run",
            "Approval becomes available after current aggregate QA is generated",
            'class="skip" href="#operator-main"', 'id="operator-main"',
            "@media(max-width:420px)", "@media (prefers-reduced-motion:reduce)",
            "min-height:44px", "overflow-wrap:anywhere", 'target="_blank"',
            ".partner-presentation-editor select{width:100%;min-width:0;max-width:100%}",
            "setBusy", "aria-busy",
            "data-render-report", "'/render-report'", "'/approve-publication'",
        ):
            self.assertIn(expected, html)
        self.assertIn(case.case_code, html)
        self.assertIn(case.case_hash, html)
        self.assertIn(classification_case.case_code, html)
        self.assertIn('data-review-queue="classification"', html)
        self.assertIn("Semantic review queue · 1 open", html)
        self.assertNotIn(
            '<div class="queue"><h3>Semantic review</h3><p>Approve, correct, or reject',
            html,
        )
        self.assertNotIn("prompt(", html)
        self.assertNotIn("'/stage'", html)
        self.assertNotIn("data-run-stage", html)
        self.assertNotIn("data-resume-stage", html)
        self.assertNotIn("Search participants", html)
        self.assertNotIn("person search", html.casefold())
        self.assertIn("repeat(6,minmax(0,1fr))", html)
        self.assertEqual(html.count('class="workflow-nav-link"'), 6)
        self.assertIn("text-transform:none", html)
        self.assertEqual(html.count('data-top-level-action="'), 6)
        self.assertIn('<details class="operator-ledger" data-ledger="qa">', html)
        self.assertIn('<details class="operator-ledger" data-ledger="provider">', html)
        self.assertIn('<details class="operator-ledger" data-ledger="privacy">', html)
        self.assertIn("<summary>QA evidence ledger</summary>", html)
        self.assertIn("<summary>Provider controls and stage ledger</summary>", html)
        self.assertIn("<summary>Privacy and retention ledger</summary>", html)
        self.assertNotIn('open data-ledger=', html)

    def test_page_places_the_five_person_canary_before_full_semantic_enrichment(self):
        from community_os.release_operator import (
            ReleaseOperatorState,
            render_release_operator_page,
        )

        with tempfile.TemporaryDirectory() as directory:
            state = ReleaseOperatorState(
                Path(directory), operator_code="release_owner",
                event_definition=_event_definition(),
            )
            html = render_release_operator_page(state)

        self.assertIn("Run five-person semantic canary", html)
        self.assertIn("data-run-canary", html)
        self.assertIn("'/classification-canary'", html)
        self.assertIn(
            "The service prioritizes accepted and present participants",
            html,
        )
        self.assertIn(
            "Full enrichment remains blocked until the five proposals are reviewed",
            html,
        )
        self.assertLess(
            html.index("data-run-canary"), html.index("data-run-approved"),
        )

    def test_classification_canary_endpoint_is_authenticated_csrf_protected_and_nonpersisting(self):
        from community_os.release_operator import ReleaseOperatorState

        marker = "PRIVATE_PROVIDER_CONTENT_MUST_NOT_ESCAPE"
        calls: list[str] = []
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _seed_validated_operator_sources(root)
            stage_path = root / "protected" / "stages" / "classification.json"
            stage_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            stage_path.write_bytes(b'{"sentinel":"classification-stage"}')
            stage_path.chmod(0o600)
            before = ReleaseOperatorState(
                root, operator_code="privacy_lead",
                event_definition=_event_definition(),
            ).pipeline.to_dict()["stages"]["classification"]

            def full_classification():
                calls.append("full_classification")
                return []

            def factory(_state):
                calls.append("sync")

                def canary():
                    calls.append("canary")
                    return [{
                        "canary_subject_count": 5,
                        "interrupted_subject_count": 0,
                        "state": "complete",
                        "provider_output": marker,
                        "subject_ref": "subject_private",
                    }]

                return {
                    "classification": full_classification,
                    "classification_canary": canary,
                }

            with _running_release_operator(
                root, stage_operation_factory=factory,
            ) as (base_url, auth_headers):
                status, _body = _http_result(Request(
                    base_url + "/classification-canary",
                    data=b"{}", method="POST",
                    headers={"Content-Type": "application/json"},
                ))
                self.assertEqual(status, 403)
                self.assertEqual(calls, [])

                status, page = _http_result(Request(
                    base_url + "/", headers=auth_headers,
                ))
                self.assertEqual(status, 200)
                csrf = re.search(
                    rb'name="operator-csrf" content="([^"]+)"', page,
                )
                self.assertIsNotNone(csrf)

                status, _body = _http_result(Request(
                    base_url + "/classification-canary",
                    data=b"{}", method="POST",
                    headers={
                        **auth_headers, "Content-Type": "application/json",
                    },
                ))
                self.assertEqual(status, 403)
                self.assertEqual(calls, [])

                status, body = _http_result(Request(
                    base_url + "/classification-canary",
                    data=b"{}", method="POST",
                    headers={
                        **auth_headers,
                        "Content-Type": "application/json",
                        "X-Operator-CSRF": csrf.group(1).decode(),
                    },
                ))

            self.assertEqual(status, 200)
            self.assertEqual(calls, ["sync", "canary"])
            self.assertEqual(json.loads(body), {
                "canary_subject_count": 5,
                "full_enrichment": "blocked_pending_canary_review",
                "interrupted_subject_count": 0,
                "state": "complete",
            })
            self.assertNotIn(marker.encode(), body)
            self.assertNotIn(b"subject_private", body)
            after_state = ReleaseOperatorState(
                root, operator_code="privacy_lead",
                event_definition=_event_definition(),
            )
            self.assertEqual(
                after_state.pipeline.to_dict()["stages"]["classification"],
                before,
            )
            self.assertEqual(
                stage_path.read_bytes(),
                b'{"sentinel":"classification-stage"}',
            )
            self.assertTrue(all(
                marker.encode() not in path.read_bytes()
                for path in root.rglob("*") if path.is_file()
            ))

    def test_classification_canary_endpoint_fails_closed_for_missing_or_failed_operation(self):
        from community_os.release_operator import ReleaseOperatorState

        safe_error = {
            "error": (
                "semantic canary is unavailable; full enrichment remains blocked"
            ),
        }
        for case in ("missing", "failed"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                _seed_validated_operator_sources(root)
                calls: list[str] = []

                def factory(_state):
                    calls.append("sync")
                    if case == "missing":
                        return {}

                    def failed_canary():
                        calls.append("canary")
                        raise RuntimeError(
                            "PRIVATE_PROVIDER_FAILURE_MUST_NOT_ESCAPE",
                        )

                    return {"classification_canary": failed_canary}

                before = ReleaseOperatorState(
                    root, operator_code="privacy_lead",
                    event_definition=_event_definition(),
                ).pipeline.to_dict()["stages"]["classification"]
                with _running_release_operator(
                    root, stage_operation_factory=factory,
                ) as (base_url, auth_headers):
                    status, page = _http_result(Request(
                        base_url + "/", headers=auth_headers,
                    ))
                    self.assertEqual(status, 200)
                    csrf = re.search(
                        rb'name="operator-csrf" content="([^"]+)"', page,
                    )
                    self.assertIsNotNone(csrf)
                    status, body = _http_result(Request(
                        base_url + "/classification-canary",
                        data=b"{}", method="POST",
                        headers={
                            **auth_headers,
                            "Content-Type": "application/json",
                            "X-Operator-CSRF": csrf.group(1).decode(),
                        },
                    ))

                self.assertEqual(status, 400)
                self.assertEqual(json.loads(body), safe_error)
                self.assertNotIn(b"PRIVATE_PROVIDER_FAILURE", body)
                self.assertEqual(
                    calls, ["sync"] if case == "missing" else ["sync", "canary"],
                )
                after = ReleaseOperatorState(
                    root, operator_code="privacy_lead",
                    event_definition=_event_definition(),
                ).pipeline.to_dict()["stages"]["classification"]
                self.assertEqual(after, before)

    def test_approved_run_stops_before_cleanup_while_semantic_canary_reviews_are_open(self):
        from community_os.release_operator import ReleaseOperatorState
        from tests.test_rich_semantic_review import proposal

        calls: list[str] = []
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _seed_validated_operator_sources(root)
            state = ReleaseOperatorState(
                root, operator_code="privacy_lead",
                event_definition=_event_definition(),
                clock=lambda: NOW,
            )
            state.record_public_source_authorization(
                "github", source_gate("applicant_supplied_github", 30), now=NOW,
            )
            state.record_public_source_authorization(
                "public_pages",
                source_gate("applicant_supplied_public_pages", 14),
                now=NOW,
            )
            approval_sha256 = authorize_operator_rich_semantics(state, now=NOW)
            timing = {
                "approval_sha256": approval_sha256,
                "created_at": NOW.isoformat(),
                "expires_at": (NOW + timedelta(days=6)).isoformat(),
            }
            for ordinal in range(1, 6):
                state.rich_semantic_reviews.submit(proposal(ordinal, **timing))

            def factory(_state):
                calls.append("sync")
                return {
                    stage: (
                        lambda stage=stage: calls.append(stage) or []
                    )
                    for stage in (
                        "privacy_cleanup", "reconcile", "github", "public_pages",
                        "classification", "aggregate", "report", "publish",
                    )
                } | {
                    "classification_canary": lambda: [{
                        "canary_subject_count": 5,
                        "interrupted_subject_count": 0,
                        "state": "complete",
                    }],
                }

            with _running_release_operator(
                root, stage_operation_factory=factory,
            ) as (base_url, auth_headers):
                status, page = _http_result(Request(
                    base_url + "/", headers=auth_headers,
                ))
                self.assertEqual(status, 200)
                csrf = re.search(
                    rb'name="operator-csrf" content="([^"]+)"', page,
                )
                self.assertIsNotNone(csrf)

                status, body = _http_result(Request(
                    base_url + "/run-approved",
                    data=b"{}", method="POST",
                    headers={
                        **auth_headers,
                        "Content-Type": "application/json",
                        "X-Operator-CSRF": csrf.group(1).decode(),
                    },
                ))

            self.assertEqual(status, 400)
            self.assertIn(b"semantic canary review remains open", body)
            self.assertEqual(calls, ["sync"])

    def test_page_separates_optional_internal_coresignal_from_mandatory_release_stages(self):
        from community_os.release_operator import ReleaseOperatorState, render_release_operator_page

        with tempfile.TemporaryDirectory() as directory:
            state = ReleaseOperatorState(Path(directory), operator_code="release_owner", event_definition=_event_definition())
            state.configure_optional_stage_policy(())
            html = render_release_operator_page(state)

        blocker_markup = html.split('<ul class="blockers">', 1)[1].split("</ul>", 1)[0]
        self.assertIn(
            "Approval-gated stages remain locked: GitHub, Public Pages, Classification.",
            blocker_markup,
        )
        self.assertNotIn("Coresignal", blocker_markup)
        self.assertIn("Mandatory stages locked</small><strong>3</strong>", html)
        self.assertIn("GitHub semantic assessment", html)
        self.assertIn("Required for release", html)
        self.assertIn("Optional internal-only Coresignal evaluation", html)
        self.assertIn("not covered by the participant notice", html)
        self.assertIn("retained records never enter partner output", html)
        self.assertIn(
            "reviewed aggregate semantic facts require exact release approval", html,
        )
        self.assertNotIn("cannot enter release or public output", html)
        self.assertNotIn('data-stage="coresignal"', html)
        self.assertNotIn("include-coresignal", html)
        self.assertNotIn("include_coresignal:document", html)
        self.assertEqual(state.snapshot()["stages"]["coresignal"]["status"], "locked")

    def test_page_keeps_public_pages_pending_until_approval_policy_is_bound(self):
        from community_os.release_operator import (
            ReleaseOperatorState,
            render_release_operator_page,
        )

        with tempfile.TemporaryDirectory() as directory:
            state = ReleaseOperatorState(
                Path(directory), operator_code="release_owner",
                event_definition=_event_definition(),
            )
            bound_before = state.optional_stage_policy_bound
            unbound = render_release_operator_page(state)
            state.configure_optional_stage_policy(())
            bound_after = state.optional_stage_policy_bound
            enabled = render_release_operator_page(state)

        self.assertFalse(bound_before)
        self.assertTrue(bound_after)
        self.assertNotIn('data-stage="public_pages"', unbound)
        self.assertNotIn("Public Pages</strong>", unbound)
        self.assertIn("Public-page policy awaits approval validation", unbound)
        self.assertIn(
            "No public-page operation can run until approval bundle is validated",
            unbound,
        )
        self.assertIn('data-stage="public_pages"', enabled)
        self.assertIn("Public Pages</strong>", enabled)
        self.assertNotIn("Public-page policy awaits approval validation", enabled)

    def test_page_exposes_bounded_rich_semantic_status_and_exact_next_action(self):
        from community_os.release_operator import ReleaseOperatorState, render_release_operator_page
        from tests.test_rich_semantic_review import proposal

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            now = datetime.now(UTC)
            state = ReleaseOperatorState(root, operator_code="release_owner", event_definition=_event_definition())
            state.configure_semantic_release_authority(SEMANTIC_SIGNING_SECRET)
            approval_sha256 = authorize_operator_rich_semantics(state, now=now)
            timing = {
                "approval_sha256": approval_sha256,
                "created_at": (now - timedelta(minutes=1)).isoformat(),
                "expires_at": (now + timedelta(days=1)).isoformat(),
            }
            open_case = state.rich_semantic_reviews.submit(proposal(1, **timing))
            reviewed_case = state.rich_semantic_reviews.submit(proposal(2, **timing))
            state.review_classification(
                reviewed_case.case_code, reviewed_case.case_hash, "approved",
            )
            rich_root = root / "protected" / "rich-semantic-review"
            (rich_root / "reviewed" / "classification_stale.json").write_text(
                json.dumps({
                    "fact": {
                        "name": "Hidden Person",
                        "profile_url": "https://participant.example/profile",
                        "provenance": {"source_coverage": ["application"]},
                    },
                }),
                encoding="utf-8",
            )

            snapshot = state.snapshot()
            html = render_release_operator_page(state)

        self.assertEqual(snapshot["event_counts"], {
            "applied": None, "accepted": None, "present": None,
        })
        self.assertEqual(snapshot["rich_semantic_status"], {
            "aggregate_summary": None,
            "next_action": "Review 1 pending rich semantic proposal.",
            "pending": 1,
            "projection_incomplete": 0,
            "reviewed": 1,
            "source_coverage": {
                "application": 2, "career": 0, "devpost": 0, "projects": 2,
            },
        })
        self.assertIn("Reviewed event counts are not recorded yet", html)
        self.assertNotIn("83 accepted / 78 present", html)
        self.assertIn("Rich proposals pending</small><strong>1</strong>", html)
        self.assertIn("Rich proposals reviewed</small><strong>1</strong>", html)
        self.assertIn("Review 1 pending rich semantic proposal.", html)
        self.assertIn("Application evidence: 2", html)
        self.assertIn("GitHub project evidence: 2", html)
        self.assertIn("Career evidence: 0", html)
        self.assertNotIn("Hidden Person", html)
        self.assertNotIn("participant.example", html)
        self.assertNotIn("case:v1:", html)

    def test_private_operator_renders_evidence_visible_semantic_review_packet_only(self):
        from community_os.release_operator import (
            ReleaseOperatorState,
            release_export_ready,
            render_release_operator_page,
        )
        from tests.test_rich_semantic_review import proposal

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            now = datetime.now(UTC)
            state = ReleaseOperatorState(
                root,
                operator_code="release_owner",
                event_definition=_event_definition(),
            )
            state.configure_semantic_release_authority(SEMANTIC_SIGNING_SECRET)
            approval_sha256 = authorize_operator_rich_semantics(state, now=now)
            case = state.rich_semantic_reviews.submit(proposal(
                1,
                approval_sha256=approval_sha256,
                created_at=(now - timedelta(minutes=1)).isoformat(),
                expires_at=(now + timedelta(days=1)).isoformat(),
            ))

            snapshot = state.snapshot()
            html = render_release_operator_page(state)

        self.assertIn('data-private-review-packet="rich-semantic-review-packet-v1"', html)
        self.assertIn("Proposed semantic judgment", html)
        self.assertIn("Builder Level</dt><dd>Substantial", html)
        self.assertIn("Product Maturity</dt><dd>Working Product", html)
        self.assertIn("Technical Depth</dt><dd>Advanced", html)
        self.assertIn("Confidence</dt><dd>Medium", html)
        self.assertIn(
            "The supplied project evidence supports the bounded classification.",
            html,
        )
        self.assertIn("End To End Delivery", html)
        self.assertIn("Shipped Working Product", html)
        self.assertIn("Application: 1 available, 1 shown", html)
        self.assertIn("Projects: 1 available, 1 shown", html)
        self.assertIn(
            "Product workflow with durable jobs and audit receipts.", html,
        )
        self.assertIn(
            "Runs background work, retries failures, and records decisions.", html,
        )
        self.assertIn("Deployment Signal: Deployment Observed", html)
        self.assertIn(
            f'data-case-code="{case.case_code}" data-case-hash="{case.case_hash}"',
            html,
        )
        self.assertIn('data-review-action="approved"', html)
        self.assertIn('data-review-action="corrected"', html)
        self.assertIn('data-review-action="rejected"', html)
        self.assertIn('aria-label="Corrected rich semantic assessment JSON"', html)
        self.assertIn('&quot;builder_level&quot;: &quot;substantial&quot;', html)
        self.assertIn('&quot;review_state&quot;: &quot;human_review_required&quot;', html)
        self.assertNotIn("professional_identity", html)
        self.assertNotIn("case:v1:", html)
        self.assertNotIn("subject_ref", html)
        self.assertNotIn("profile_url", html)
        self.assertNotIn(
            "Product workflow with durable jobs and audit receipts.",
            json.dumps(snapshot, sort_keys=True),
        )
        self.assertFalse(release_export_ready(state, "semantic_review_packet"))
        self.assertFalse((root / "public-staging").exists())

    def test_private_operator_maps_current_application_name_to_open_semantic_case(self):
        from community_os.release_operations import rich_semantic_subject_ref
        from community_os.release_operator import (
            ReleaseOperatorState,
            render_release_operator_page,
        )
        from tests.test_rich_semantic_review import NOW as semantic_now, proposal

        secret = SEMANTIC_SIGNING_SECRET
        fixture = (
            Path(__file__).resolve().parent
            / "fixtures" / "luma_guests_synthetic.csv"
        ).read_bytes()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = ReleaseOperatorState(
                root,
                operator_code="release_owner",
                event_definition=_event_definition(),
                clock=lambda: semantic_now,
            )
            state.store_upload(
                "applications", fixture, filename="applications.csv",
            )
            state.configure_semantic_release_authority(secret)
            approval_sha256 = authorize_operator_rich_semantics(
                state, now=semantic_now,
            )
            case = state.rich_semantic_reviews.submit(proposal(
                1,
                approval_sha256=approval_sha256,
                subject_ref=rich_semantic_subject_ref(
                    "gst_synthetic_001", secret=secret,
                ),
            ))

            html = render_release_operator_page(state)
            snapshot = state.snapshot()

        self.assertIn(
            '<p class="private-subject-name"><strong>Applicant</strong>'
            '<span>Ada Example</span></p>',
            html,
        )
        self.assertIn(f'data-case-code="{case.case_code}"', html)
        self.assertNotIn("ada@example.org", html.casefold())
        self.assertNotIn("Ada Example", json.dumps(snapshot, sort_keys=True))
        self.assertNotIn("case:v1:", json.dumps(snapshot, sort_keys=True))

    def test_private_operator_lists_only_final_evidence_bound_semantic_highlights(self):
        from community_os.partner_report import render_partner_talent_report
        from community_os.release_operations import rich_semantic_subject_ref
        from community_os.release_operator import (
            ReleaseOperatorState,
            render_release_operator_page,
        )
        from tests.test_partner_report import PartnerReportTests
        from tests.test_rich_semantic_review import NOW as semantic_now, proposal

        secret = SEMANTIC_SIGNING_SECRET
        fixture = (
            Path(__file__).resolve().parent
            / "fixtures" / "luma_guests_synthetic.csv"
        ).read_bytes()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = ReleaseOperatorState(
                root,
                operator_code="release_owner",
                event_definition=_event_definition(),
                clock=lambda: semantic_now,
            )
            state.store_upload(
                "applications", fixture, filename="applications.csv",
            )
            state.configure_semantic_release_authority(secret)
            state.rich_semantic_reviews.configure_identity_corpus((
                "gst_synthetic_001", "Ada Example", "Ada", "Example",
                "ada@example.org",
            ))
            approval_sha256 = authorize_operator_rich_semantics(
                state, now=semantic_now,
            )
            case = state.rich_semantic_reviews.submit(proposal(
                1,
                approval_sha256=approval_sha256,
                subject_ref=rich_semantic_subject_ref(
                    "gst_synthetic_001", secret=secret,
                ),
            ))
            state.review_classification(
                case.case_code, case.case_hash, "approved",
            )

            operator_html = render_release_operator_page(state)
            snapshot = state.snapshot()
            durable_files = tuple(
                (path, path.read_bytes()) for path in root.rglob("*")
                if path.is_file() and state.protected_uploads not in path.parents
            )

        start = operator_html.index('data-private-reviewed-highlights="v1"')
        end = operator_html.index("</details>", start)
        highlights = operator_html[start:end]
        self.assertIn("Ada Example", highlights)
        self.assertIn(
            "A working product with explicit operational evidence.", highlights,
        )
        self.assertIn("Product Maturity</dt><dd>Working Product", highlights)
        self.assertIn("Technical Depth</dt><dd>Advanced", highlights)
        self.assertIn(
            "Execution Scope</dt><dd>Substantial Contributor", highlights,
        )
        self.assertIn("Market Domains</dt><dd>Education Learning", highlights)
        self.assertNotIn("Ordinary", highlights)
        self.assertNotIn("None Observed", highlights)
        self.assertNotIn("Partner fit", highlights)
        self.assertNotIn("Impressive", highlights)
        self.assertNotIn("case:v1:", highlights)
        self.assertNotIn("subject_ref", highlights)
        self.assertNotIn("Ada Example", json.dumps(snapshot, sort_keys=True))
        for path, contents in durable_files:
            self.assertNotIn(b"Ada Example", contents, str(path))

        PartnerReportTests.setUpClass()
        partner_html = render_partner_talent_report(
            PartnerReportTests.report, PartnerReportTests.v3_report,
        )
        self.assertNotIn("Ada Example", partner_html)
        self.assertNotIn("case:v1:", partner_html)
        self.assertNotIn("subject_ref", partner_html)

    def test_private_operator_authors_hash_bound_standout_evidence_for_follow_up(self):
        from community_os.release_operations import rich_semantic_subject_ref
        from community_os.release_operator import (
            ReleaseOperatorState,
            render_release_operator_page,
        )
        from tests.test_rich_semantic_review import NOW as semantic_now, proposal

        secret = SEMANTIC_SIGNING_SECRET
        fixture = (
            Path(__file__).resolve().parent
            / "fixtures" / "luma_guests_synthetic.csv"
        ).read_bytes()
        rationale = (
            "Reviewed project evidence includes a deployed product used by customers."
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = ReleaseOperatorState(
                root,
                operator_code="release_owner",
                event_definition=_event_definition(),
                clock=lambda: semantic_now,
            )
            state.store_upload(
                "applications", fixture, filename="applications.csv",
            )
            state.configure_semantic_release_authority(secret)
            state.rich_semantic_reviews.configure_identity_corpus((
                "gst_synthetic_001", "Ada Example", "Ada", "Example",
                "ada@example.org",
            ))
            approval_sha256 = authorize_operator_rich_semantics(
                state, now=semantic_now,
            )
            case = state.rich_semantic_reviews.submit(proposal(
                1,
                approval_sha256=approval_sha256,
                subject_ref=rich_semantic_subject_ref(
                    "gst_synthetic_001", secret=secret,
                ),
            ))
            state.review_classification(
                case.case_code, case.case_hash, "approved",
            )

            with state.acting_as("colleague_" + "1" * 32):
                state.record_standout_evidence(
                    case.case_code, case.case_hash, rationale,
                )

            html = render_release_operator_page(state)
            stored = json.loads(state.path.read_text(encoding="utf-8"))
            serialized = json.dumps(stored, ensure_ascii=True, sort_keys=True)

        self.assertIn("Standout evidence for human follow-up", html)
        self.assertIn(rationale, html)
        self.assertIn(
            f'data-standout-case-code="{case.case_code}" '
            f'data-standout-case-hash="{case.case_hash}"',
            html,
        )
        self.assertIn('aria-label="Neutral standout-evidence rationale"', html)
        self.assertIn('data-standout-action="record"', html)
        self.assertIn("postJson('/standout-evidence'", html)
        decision = stored["private_semantic_decisions"][case.case_code]
        self.assertEqual(decision["action"], "standout_evidence")
        self.assertEqual(decision["case_hash"], case.case_hash)
        self.assertEqual(
            decision["evidence_refs"],
            [
                "application_01:achievement",
                "application_01:experience",
                "project_01:deployment",
                "project_01:description",
            ],
        )
        self.assertNotIn("Ada Example", serialized)
        self.assertNotIn("ada@example.org", serialized)
        self.assertNotIn("case:v1:", serialized)
        self.assertTrue(any(
            event["action"] == "standout_evidence_recorded"
            and event["subject_code"] == case.case_code
            for event in stored["audit_events"]
        ))

    def test_authenticated_operator_endpoint_records_private_standout_evidence(self):
        from community_os.release_operations import rich_semantic_subject_ref
        from community_os.release_operator import ReleaseOperatorState
        from tests.test_rich_semantic_review import NOW as semantic_now, proposal

        secret = b"fixture-pseudonym-secret"
        fixture = (
            Path(__file__).resolve().parent
            / "fixtures" / "luma_guests_synthetic.csv"
        ).read_bytes()
        rationale = (
            "Reviewed project evidence includes a deployed product used by customers."
        )

        def stage_operation_factory(_state):
            return {}

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = ReleaseOperatorState(
                root,
                operator_code="privacy_lead",
                event_definition=_event_definition(),
                clock=lambda: semantic_now,
            )
            state.store_upload(
                "applications", fixture, filename="applications.csv",
            )
            state.configure_semantic_release_authority(secret)
            state.rich_semantic_reviews.configure_identity_corpus((
                "gst_synthetic_001", "Ada Example", "Ada", "Example",
                "ada@example.org",
            ))
            approval_sha256 = authorize_operator_rich_semantics(
                state, now=semantic_now,
            )
            case = state.rich_semantic_reviews.submit(proposal(
                1,
                approval_sha256=approval_sha256,
                subject_ref=rich_semantic_subject_ref(
                    "gst_synthetic_001", secret=secret,
                ),
            ))
            state.review_classification(
                case.case_code, case.case_hash, "approved",
            )

            with _running_release_operator(
                root, stage_operation_factory=stage_operation_factory,
            ) as (base_url, headers):
                page_request = Request(base_url + "/", headers=headers)
                page_status, page_body = _http_result(page_request)
                csrf = re.search(
                    rb'name="operator-csrf" content="([^"]+)"', page_body,
                )
                self.assertEqual(page_status, 200)
                self.assertIsNotNone(csrf)
                assert csrf is not None
                body = json.dumps({
                    "case": case.case_code,
                    "case_hash": case.case_hash,
                    "rationale": rationale,
                }).encode("utf-8")
                request = Request(
                    base_url + "/standout-evidence",
                    data=body,
                    headers={
                        **headers,
                        "Content-Type": "application/json",
                        "X-Operator-CSRF": csrf.group(1).decode("ascii"),
                    },
                    method="POST",
                )
                status, response = _http_result(request)
                final_status, final_page = _http_result(
                    Request(base_url + "/", headers=headers),
                )

        self.assertEqual(status, 200, response)
        self.assertEqual(final_status, 200)
        self.assertIn(b"Standout evidence for human follow-up", final_page)
        self.assertIn(rationale.encode("utf-8"), final_page)

    def test_private_standout_evidence_rejects_open_stale_or_identifying_decisions(self):
        from community_os.release_operations import rich_semantic_subject_ref
        from community_os.release_operator import (
            ReleaseOperatorState,
            render_release_operator_page,
        )
        from tests.test_rich_semantic_review import NOW as semantic_now, proposal

        secret = SEMANTIC_SIGNING_SECRET
        fixture = (
            Path(__file__).resolve().parent
            / "fixtures" / "luma_guests_synthetic.csv"
        ).read_bytes()
        valid_rationale = (
            "Reviewed project evidence includes a deployed product used by customers."
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = ReleaseOperatorState(
                root,
                operator_code="release_owner",
                event_definition=_event_definition(),
                clock=lambda: semantic_now,
            )
            state.store_upload(
                "applications", fixture, filename="applications.csv",
            )
            state.configure_semantic_release_authority(secret)
            state.rich_semantic_reviews.configure_identity_corpus((
                "gst_synthetic_001", "Ada Example", "Ada", "Example",
                "ada@example.org",
            ))
            approval_sha256 = authorize_operator_rich_semantics(
                state, now=semantic_now,
            )
            case = state.rich_semantic_reviews.submit(proposal(
                1,
                approval_sha256=approval_sha256,
                subject_ref=rich_semantic_subject_ref(
                    "gst_synthetic_001", secret=secret,
                ),
            ))
            with state.acting_as("colleague_" + "1" * 32):
                with self.assertRaisesRegex(PermissionError, "finalized current case"):
                    state.record_standout_evidence(
                        case.case_code, case.case_hash, valid_rationale,
                    )
            state.review_classification(
                case.case_code, case.case_hash, "approved",
            )
            with self.assertRaisesRegex(PermissionError, "authenticated operator"):
                state.record_standout_evidence(
                    case.case_code, case.case_hash, valid_rationale,
                )
            with state.acting_as("colleague_" + "1" * 32):
                for unsafe in (
                    "This is an impressive project and a strong partner fit.",
                    "We recommend this excellent candidate for a client introduction.",
                    "Ada Example built and deployed a production product.",
                    "Project evidence is available at https://participant.example/profile.",
                    "Reviewed project evidence includes 485123456789 customer records.",
                ):
                    with self.subTest(rationale=unsafe), self.assertRaisesRegex(
                        ValueError, "bounded neutral evidence prose|applicant name",
                    ):
                        state.record_standout_evidence(
                            case.case_code, case.case_hash, unsafe,
                        )
                with self.assertRaisesRegex(PermissionError, "finalized current case"):
                    state.record_standout_evidence(
                        case.case_code, "f" * 64, valid_rationale,
                    )
                state.record_standout_evidence(
                    case.case_code, case.case_hash, valid_rationale,
                )
            payload = json.loads(state.path.read_text(encoding="utf-8"))
            payload["private_semantic_decisions"][case.case_code]["rationale"] = (
                "Reviewed project evidence includes a deployed product and tests."
            )
            state.path.write_text(
                json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )
            state.path.chmod(0o600)
            reopened = ReleaseOperatorState(
                root,
                operator_code="release_owner",
                event_definition=_event_definition(),
                clock=lambda: semantic_now,
            )
            reopened.configure_semantic_release_authority(secret)
            tampered_html = render_release_operator_page(reopened)

        self.assertNotIn("Standout evidence for human follow-up", tampered_html)
        self.assertNotIn(valid_rationale, tampered_html)

    def test_private_standout_evidence_disappears_after_application_source_change(self):
        from community_os.release_operations import rich_semantic_subject_ref
        from community_os.release_operator import (
            ReleaseOperatorState,
            render_release_operator_page,
        )
        from tests.test_rich_semantic_review import NOW as semantic_now, proposal

        secret = SEMANTIC_SIGNING_SECRET
        fixture = (
            Path(__file__).resolve().parent
            / "fixtures" / "luma_guests_synthetic.csv"
        ).read_bytes()
        rationale = (
            "Reviewed project evidence includes a deployed product used by customers."
        )
        with tempfile.TemporaryDirectory() as directory:
            state = ReleaseOperatorState(
                Path(directory),
                operator_code="release_owner",
                event_definition=_event_definition(),
                clock=lambda: semantic_now,
            )
            state.store_upload(
                "applications", fixture, filename="applications.csv",
            )
            state.configure_semantic_release_authority(secret)
            state.rich_semantic_reviews.configure_identity_corpus((
                "gst_synthetic_001", "Ada Example", "Ada", "Example",
                "ada@example.org",
            ))
            approval_sha256 = authorize_operator_rich_semantics(
                state, now=semantic_now,
            )
            case = state.rich_semantic_reviews.submit(proposal(
                1,
                approval_sha256=approval_sha256,
                subject_ref=rich_semantic_subject_ref(
                    "gst_synthetic_001", secret=secret,
                ),
            ))
            state.review_classification(
                case.case_code, case.case_hash, "approved",
            )
            with state.acting_as("colleague_" + "1" * 32):
                state.record_standout_evidence(
                    case.case_code, case.case_hash, rationale,
                )
            current_html = render_release_operator_page(state)

            replacement = fixture.replace(b"Ada Example", b"Eve Example")
            state.store_upload(
                "applications", replacement, filename="applications.csv",
            )
            changed_html = render_release_operator_page(state)

        self.assertIn("Standout evidence for human follow-up", current_html)
        self.assertNotIn("Standout evidence for human follow-up", changed_html)
        self.assertNotIn(rationale, changed_html)

    def test_private_semantic_name_binding_disappears_after_application_source_change(self):
        from community_os.release_operations import rich_semantic_subject_ref
        from community_os.release_operator import (
            ReleaseOperatorState,
            render_release_operator_page,
        )
        from tests.test_rich_semantic_review import NOW as semantic_now, proposal

        secret = SEMANTIC_SIGNING_SECRET
        fixture = (
            Path(__file__).resolve().parent
            / "fixtures" / "luma_guests_synthetic.csv"
        ).read_bytes()
        with tempfile.TemporaryDirectory() as directory:
            state = ReleaseOperatorState(
                Path(directory),
                operator_code="release_owner",
                event_definition=_event_definition(),
                clock=lambda: semantic_now,
            )
            state.store_upload(
                "applications", fixture, filename="applications.csv",
            )
            state.configure_semantic_release_authority(secret)
            approval_sha256 = authorize_operator_rich_semantics(
                state, now=semantic_now,
            )
            case = state.rich_semantic_reviews.submit(proposal(
                1,
                approval_sha256=approval_sha256,
                subject_ref=rich_semantic_subject_ref(
                    "gst_synthetic_001", secret=secret,
                ),
            ))
            state.review_classification(
                case.case_code, case.case_hash, "approved",
            )
            current = render_release_operator_page(state)

            replacement = fixture.replace(b"Ada Example", b"Eve Example")
            replacement_result = state.store_upload(
                "applications", replacement, filename="applications.csv",
            )
            binding = (
                state.rich_semantic_reviews.application_source_bindings
                / f"{case.case_code}.json"
            )
            forged = json.loads(binding.read_text(encoding="utf-8"))
            forged["application_sha256"] = replacement_result["sha256"]
            binding.write_text(
                json.dumps(forged, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )
            binding.chmod(0o600)
            changed = render_release_operator_page(state)

        self.assertIn("Ada Example", current)
        self.assertNotIn("Ada Example", changed)
        self.assertNotIn("Eve Example", changed)
        self.assertNotIn('data-private-reviewed-highlights="v1"', changed)

    def test_private_semantic_name_binding_rejects_unsafe_binding_files(self):
        from community_os.release_operations import rich_semantic_subject_ref
        from community_os.release_operator import (
            ReleaseOperatorState,
            render_release_operator_page,
        )
        from tests.test_rich_semantic_review import NOW as semantic_now, proposal

        secret = SEMANTIC_SIGNING_SECRET
        fixture = (
            Path(__file__).resolve().parent
            / "fixtures" / "luma_guests_synthetic.csv"
        ).read_bytes()
        for mutation in ("world_readable", "hardlink", "symlink", "unsigned"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                state = ReleaseOperatorState(
                    Path(directory),
                    operator_code="release_owner",
                    event_definition=_event_definition(),
                    clock=lambda: semantic_now,
                )
                state.store_upload(
                    "applications", fixture, filename="applications.csv",
                )
                state.configure_semantic_release_authority(secret)
                approval_sha256 = authorize_operator_rich_semantics(
                    state, now=semantic_now,
                )
                case = state.rich_semantic_reviews.submit(proposal(
                    1,
                    approval_sha256=approval_sha256,
                    subject_ref=rich_semantic_subject_ref(
                        "gst_synthetic_001", secret=secret,
                    ),
                ))
                binding = (
                    state.rich_semantic_reviews.application_source_bindings
                    / f"{case.case_code}.json"
                )
                self.assertEqual(binding.stat().st_mode & 0o777, 0o600)
                if mutation == "world_readable":
                    binding.chmod(0o644)
                elif mutation == "hardlink":
                    os.link(binding, binding.with_name("binding-alias.json"))
                elif mutation == "symlink":
                    target = binding.with_name("binding-target.json")
                    binding.replace(target)
                    binding.symlink_to(target.name)
                else:
                    unsigned = json.loads(binding.read_text(encoding="utf-8"))
                    unsigned.pop("binding_hmac", None)
                    binding.write_text(
                        json.dumps(
                            unsigned, sort_keys=True, separators=(",", ":"),
                        ) + "\n",
                        encoding="utf-8",
                    )
                    binding.chmod(0o600)

                html = render_release_operator_page(state)
                self.assertNotIn("Ada Example", html)
                self.assertNotIn('class="private-subject-name"', html)

    def test_private_operator_rejects_praise_and_partner_fit_from_reviewed_highlights(self):
        from community_os.release_operations import rich_semantic_subject_ref
        from community_os.release_operator import (
            ReleaseOperatorState,
            render_release_operator_page,
        )
        from tests.test_rich_semantic_review import NOW as semantic_now, proposal

        unsafe_summaries = (
            "This is an impressive project and a strong partner fit.",
            "This is a fantastic project and an unusually strong match for partners.",
            "A high-quality and innovative product suitable for this client.",
            "We recommend hiring this excellent candidate.",
            "This is a top investment opportunity.",
            "exceptionally and innovatively engineered delivery.",
            "a polished delivery that others should notice.",
            "a first-rate project ready for introductions.",
            "the project merits a conversation.",
        )
        secret = SEMANTIC_SIGNING_SECRET
        fixture = (
            Path(__file__).resolve().parent
            / "fixtures" / "luma_guests_synthetic.csv"
        ).read_bytes()
        for unsafe_summary in unsafe_summaries:
            with self.subTest(summary=unsafe_summary), tempfile.TemporaryDirectory() as directory:
                state = ReleaseOperatorState(
                    Path(directory),
                    operator_code="release_owner",
                    event_definition=_event_definition(),
                    clock=lambda: semantic_now,
                )
                state.store_upload(
                    "applications", fixture, filename="applications.csv",
                )
                state.configure_semantic_release_authority(secret)
                state.rich_semantic_reviews.configure_identity_corpus((
                    "gst_synthetic_001", "Ada Example", "Ada", "Example",
                    "ada@example.org",
                ))
                approval_sha256 = authorize_operator_rich_semantics(
                    state, now=semantic_now,
                )
                candidate = proposal(
                    1,
                    approval_sha256=approval_sha256,
                    subject_ref=rich_semantic_subject_ref(
                        "gst_synthetic_001", secret=secret,
                    ),
                )
                candidate["assessment"]["project_summary"] = unsafe_summary
                case = state.rich_semantic_reviews.submit(candidate)

                open_html = render_release_operator_page(state)
                state.review_classification(
                    case.case_code, case.case_hash, "approved",
                )
                reviewed_html = render_release_operator_page(state)
                self.assertIn(unsafe_summary, open_html)
                start = reviewed_html.index(
                    'data-private-reviewed-highlights="v1"',
                )
                end = reviewed_html.index("</details>", start)
                highlights = reviewed_html[start:end]
                self.assertNotIn(unsafe_summary, highlights)
                self.assertNotIn("Project summary", highlights)
                self.assertIn(
                    "Product Maturity</dt><dd>Working Product", highlights,
                )

    def test_tampered_final_rich_record_is_not_reported_as_reviewed(self):
        from community_os.release_operator import ReleaseOperatorState
        from tests.test_rich_semantic_review import proposal

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            now = datetime.now(UTC)
            state = ReleaseOperatorState(root, operator_code="release_owner", event_definition=_event_definition())
            state.configure_semantic_release_authority(SEMANTIC_SIGNING_SECRET)
            approval_sha256 = authorize_operator_rich_semantics(state, now=now)
            case = state.rich_semantic_reviews.submit(proposal(
                1,
                approval_sha256=approval_sha256,
                created_at=(now - timedelta(minutes=1)).isoformat(),
                expires_at=(now + timedelta(days=1)).isoformat(),
            ))
            state.review_classification(case.case_code, case.case_hash, "approved")
            reviewed_path = (
                root / "protected" / "rich-semantic-review" / "reviewed"
                / f"{case.case_code}.json"
            )
            reviewed_record = json.loads(reviewed_path.read_text(encoding="utf-8"))
            reviewed_record["record_version"] = "tampered"
            reviewed_path.write_text(json.dumps(reviewed_record) + "\n", encoding="utf-8")

            status = state.snapshot()["rich_semantic_status"]

        self.assertEqual(status["reviewed"], 0)
        self.assertEqual(status["projection_incomplete"], 1)
        self.assertEqual(status["source_coverage"]["projects"], 0)
        self.assertEqual(
            status["next_action"],
            "Recover 1 interrupted rich semantic projection.",
        )

    def test_release_owner_http_attestation_authenticates_and_invalidates_first(self):
        from community_os.release_operator import ReleaseOperatorState
        from tests.test_rich_semantic_review import assessment, proposal

        secret = b"fixture-pseudonym-secret"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            now = datetime.now(UTC)
            state = ReleaseOperatorState(
                root,
                operator_code="privacy_lead",
                event_definition=_event_definition(),
                clock=lambda: now,
            )
            state.configure_semantic_release_authority(secret)
            approval_sha256 = authorize_operator_rich_semantics(state, now=now)
            case = state.rich_semantic_reviews.submit(proposal(
                1,
                approval_sha256=approval_sha256,
                assessment=assessment(cross_source_confidence="low"),
                created_at=(now - timedelta(minutes=1)).isoformat(),
                expires_at=(now + timedelta(days=1)).isoformat(),
            ))
            state.review_classification(case.case_code, case.case_hash, "approved")
            preview = state.rich_semantic_reviews.preview_required_human_attestation()
            expected = str(preview["required_review_set_sha256"])
            stale_approval = root / "protected" / "semantic-release-approval.json"
            stale_approval.write_text("{}\n", encoding="utf-8")

            def factory(_state):
                return {}

            with _running_release_operator(
                root,
                stage_operation_factory=factory,
                release_owner=True,
            ) as (base_url, auth_headers):
                status, page = _http_result(Request(
                    base_url + "/", headers=auth_headers,
                ))
                self.assertEqual(status, 200)
                csrf = re.search(
                    rb'name="operator-csrf" content="([^"]+)"', page,
                )
                self.assertIsNotNone(csrf)
                request_headers = {
                    **auth_headers,
                    "Content-Type": "application/json",
                    "X-Operator-CSRF": csrf.group(1).decode(),
                }
                status, _body = _http_result(Request(
                    base_url + "/attest-semantic-reviews",
                    data=json.dumps({"review_set_sha256": expected}).encode(),
                    method="POST",
                    headers={
                        **request_headers,
                        "X-Operator-Email": "attacker@example.org",
                    },
                ))
                self.assertEqual(status, 403)
                self.assertTrue(stale_approval.is_file())

                status, _body = _http_result(Request(
                    base_url + "/attest-semantic-reviews",
                    data=json.dumps({
                        "review_set_sha256": "0" * 64,
                    }).encode(),
                    method="POST",
                    headers=request_headers,
                ))
                self.assertEqual(status, 400)
                self.assertFalse(stale_approval.exists())
                self.assertFalse(
                    (root / "protected" / "rich-semantic-review"
                     / "human-attestation.json").exists(),
                )

                status, body = _http_result(Request(
                    base_url + "/attest-semantic-reviews",
                    data=json.dumps({"review_set_sha256": expected}).encode(),
                    method="POST",
                    headers=request_headers,
                ))
                self.assertEqual(status, 200)
                self.assertEqual(
                    json.loads(body)["attested_review_case_count"], 1,
                )

            reloaded = ReleaseOperatorState(
                root,
                operator_code="privacy_lead",
                event_definition=_event_definition(),
            )
            reloaded.configure_semantic_release_authority(secret)
            self.assertEqual(
                reloaded.rich_semantic_reviews.semantic_release_qa_evidence()[
                    "required_review_cases_resolved"
                ],
                1,
            )

    def test_tampered_rich_rejection_receipt_is_not_reported_as_reviewed(self):
        from community_os.release_operator import ReleaseOperatorState
        from tests.test_rich_semantic_review import proposal

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            now = datetime.now(UTC)
            state = ReleaseOperatorState(root, operator_code="release_owner", event_definition=_event_definition())
            state.configure_semantic_release_authority(SEMANTIC_SIGNING_SECRET)
            approval_sha256 = authorize_operator_rich_semantics(state, now=now)
            case = state.rich_semantic_reviews.submit(proposal(
                1,
                approval_sha256=approval_sha256,
                created_at=(now - timedelta(minutes=1)).isoformat(),
                expires_at=(now + timedelta(days=1)).isoformat(),
            ))
            state.review_classification(case.case_code, case.case_hash, "rejected")
            receipt_path = (
                root / "protected" / "rich-semantic-review" / "receipts"
                / f"{case.case_code}.json"
            )
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            receipt["receipt_version"] = "tampered"
            receipt_path.write_text(json.dumps(receipt) + "\n", encoding="utf-8")

            status = state.snapshot()["rich_semantic_status"]

        self.assertEqual(status["reviewed"], 0)
        self.assertEqual(status["projection_incomplete"], 1)

    def test_valid_internal_rich_aggregate_makes_operator_status_ready_for_human_review(self):
        from community_os.release_operator import (
            ReleaseOperatorState, render_release_operator_page,
        )
        from community_os.semantic_metrics import semantic_taxonomy_sha256
        from tests.test_rich_semantic_review import proposal

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            now = datetime.now(UTC)
            state = ReleaseOperatorState(root, operator_code="release_owner", event_definition=_event_definition())
            state.configure_semantic_release_authority(SEMANTIC_SIGNING_SECRET)
            approval_sha256 = authorize_operator_rich_semantics(state, now=now)
            for ordinal in range(1, 7):
                case = state.rich_semantic_reviews.submit(proposal(
                    ordinal,
                    approval_sha256=approval_sha256,
                    created_at=(now - timedelta(minutes=1)).isoformat(),
                    expires_at=(now + timedelta(days=1)).isoformat(),
                ))
                state.review_classification(
                    case.case_code, case.case_hash, "approved",
                )
            expected_subjects = tuple(sorted(
                str(proposal(ordinal)["subject_ref"]) for ordinal in range(1, 7)
            ))
            aggregate = state.rich_semantic_reviews.build_population_aggregate(
                expected_subject_refs=expected_subjects,
                binding_context={
                    "event_approval_sha256": state.rich_semantic_reviews.review_context_hashes[
                        "event_approval"
                    ],
                    "event_definition_sha256": state.event_definition_sha256,
                    "event_key": state.event_key,
                    "run_sha256": "1" * 64,
                    "source_snapshot_sha256": state.source_snapshot_sha256(),
                    "taxonomy_sha256": semantic_taxonomy_sha256(
                        state.event_definition.semantic.taxonomy_version,
                    ),
                    "taxonomy_version": state.event_definition.semantic.taxonomy_version,
                },
                generated_at=now,
            )
            aggregate_path = root / "protected" / "rich-semantic-internal.aggregate.json"
            aggregate_path.write_text(json.dumps(aggregate) + "\n", encoding="utf-8")
            aggregate_path.chmod(0o600)
            approval_ready_html = render_release_operator_page(state)
            (root / "protected" / "semantic-release-qa.json").write_text(
                "{}", encoding="utf-8",
            )
            (root / "protected" / "semantic-release-approval.json").write_text(
                "{}", encoding="utf-8",
            )

            status = state.snapshot()["rich_semantic_status"]
            html = render_release_operator_page(state)

        self.assertEqual(status["pending"], 0)
        self.assertEqual(status["projection_incomplete"], 0)
        self.assertEqual(status["reviewed"], 6)
        self.assertEqual(status["aggregate_summary"]["population"]["assessed_count"], 6)
        self.assertEqual(
            status["aggregate_summary"]["metrics"]["serious_product_builder"], 6,
        )
        self.assertEqual(
            status["next_action"],
            "Internal-only rich semantic aggregate is ready; human review remains required before release.",
        )
        self.assertIn("<button data-approve-semantic>", approval_ready_html)
        self.assertIn("Generates and verifies the protected semantic QA receipt", approval_ready_html)
        self.assertIn('id="semantic-results"', html)
        self.assertNotIn("Semantic release sealed", html)
        self.assertIn("stale", html.casefold())
        self.assertIn("Agent-assisted internal review. Not approved for partner release.", html)
        self.assertIn("Reviewed facts</dt><dd>6</dd>", html)
        self.assertIn("Serious Product Builder", html)
        self.assertIn("<td>6</td>", html)
        self.assertIn("Not approved for partner release", html)

    def test_page_marks_application_and_github_mandatory_and_coresignal_career_optional(self):
        from community_os.release_operator import ReleaseOperatorState, render_release_operator_page

        with tempfile.TemporaryDirectory() as directory:
            state = ReleaseOperatorState(Path(directory), operator_code="release_owner", event_definition=_event_definition())
            html = render_release_operator_page(state)

        self.assertIn("Run mandatory GitHub + application semantic enrichment.", html)
        self.assertIn("Mandatory semantic inputs: application + GitHub projects", html)
        self.assertIn("Optional career-only Coresignal overlay", html)
        self.assertIn("never a release prerequisite", html)
        self.assertNotIn('data-stage="coresignal"', html)
        self.assertNotIn("include-coresignal", html)
        self.assertNotIn("include_coresignal:document", html)

    def test_page_hides_public_pages_from_required_flow_when_explicitly_disabled(self):
        from community_os.release_operator import (
            ReleaseOperatorState,
            render_release_operator_page,
        )

        with tempfile.TemporaryDirectory() as directory:
            state = ReleaseOperatorState(
                Path(directory), operator_code="release_owner",
                event_definition=_event_definition(),
            )
            state.configure_optional_stage_policy(("public_pages",))
            html = render_release_operator_page(state)

        self.assertNotIn('data-stage="public_pages"', html)
        self.assertNotIn("Public Pages</strong>", html)
        self.assertIn("Public-page enrichment is off for this event", html)
        self.assertIn("GitHub + application evidence remains mandatory", html)

    def test_controlled_release_rejects_coresignal_evaluation_input(self):
        from community_os.enrichment.release_pipeline import ReleasePipeline
        from community_os.enrichment.state import PipelineState, StageStatus
        from community_os.release_operator import run_approved_release

        calls: list[str] = []
        with tempfile.TemporaryDirectory() as directory:
            state = PipelineState.create(Path(directory) / "pipeline.json", {
                stage: (
                    StageStatus.LOCKED
                    if stage in {"github", "public_pages", "coresignal", "classification"}
                    else StageStatus.ALLOWED
                )
                for stage in (
                    "reconcile", "github", "public_pages", "coresignal",
                    "classification", "aggregate", "report", "publish", "analytics",
                )
            })
            pipeline = ReleasePipeline(
                state, manifest_path=Path(directory) / "manifest.json",
                config={"optional_stage_policy_bound": True},
            )
            operations = {
                stage: (lambda stage=stage: calls.append(stage) or [])
                for stage in ("privacy_cleanup", *state.to_dict()["stages"])
            }

            with self.assertRaisesRegex(
                PermissionError,
                "Coresignal evaluation cannot enter the release pipeline",
            ):
                run_approved_release(pipeline, operations, include_coresignal=True)

        self.assertEqual(calls, [])

    def test_report_render_is_local_rerunnable_and_never_publishes(self):
        from community_os.enrichment.release_pipeline import ReleasePipeline
        from community_os.enrichment.state import PipelineState, StageStatus
        from community_os.release_operator import run_local_report_render

        calls: list[str] = []
        with tempfile.TemporaryDirectory() as directory:
            state = PipelineState.create(Path(directory) / "pipeline.json", {
                "aggregate": StageStatus.ALLOWED,
                "report": StageStatus.ALLOWED,
                "publish": StageStatus.ALLOWED,
                "analytics": StageStatus.ALLOWED,
            })
            state.start("aggregate")
            state.complete("aggregate", {"output_hash": "a" * 64, "record_count": 2})
            pipeline = ReleasePipeline(
                state, manifest_path=Path(directory) / "manifest.json",
                prerequisites={"report": ("aggregate",)},
            )
            html = Path(directory) / "report.html"
            pdf = Path(directory) / "report.pdf"

            def operation():
                calls.append("report")
                for path in (html, pdf):
                    temporary = path.with_suffix(path.suffix + ".tmp")
                    temporary.write_text(f"fresh-{len(calls)}", encoding="utf-8")
                    temporary.replace(path)
                return [{"artifact": "html_pdf"}]

            first = run_local_report_render(
                pipeline, operation, required_artifacts=(html, pdf),
            )
            second = run_local_report_render(
                pipeline, operation, required_artifacts=(html, pdf),
            )

        self.assertEqual(calls, ["report", "report"])
        self.assertEqual(first["record_count"], 1)
        self.assertEqual(second["record_count"], 1)
        self.assertEqual(state.stage("report").status, StageStatus.COMPLETE)
        self.assertEqual(state.stage("publish").status, StageStatus.ALLOWED)
        self.assertEqual(state.stage("analytics").status, StageStatus.ALLOWED)

    def test_semantic_approval_adopts_only_the_verified_existing_aggregate_without_provider_run(self):
        from community_os.enrichment.release_pipeline import ReleasePipeline
        from community_os.enrichment.state import PipelineState, StageStatus
        from community_os.release_operator import (
            _adopt_approved_semantic_aggregate,
        )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            protected = root / "protected"
            protected.mkdir()
            aggregate = protected / "rich-semantic-internal.aggregate.json"
            cohorts = protected / "rich-semantic-internal.cohorts.aggregate.json"
            aggregate.write_bytes(b'{"aggregate":"reviewed"}\n')
            cohorts.write_bytes(b'{"cohorts":"reviewed"}\n')
            aggregate.chmod(0o600)
            cohorts.chmod(0o600)
            state = PipelineState.create(root / "pipeline.json", {
                "classification": StageStatus.LOCKED,
                "aggregate": StageStatus.ALLOWED,
                "report": StageStatus.ALLOWED,
                "publish": StageStatus.ALLOWED,
                "analytics": StageStatus.ALLOWED,
            })
            pipeline = ReleasePipeline(
                state,
                manifest_path=protected / "enrichment-manifest.json",
                prerequisites={"aggregate": ("classification",)},
            )

            result = _adopt_approved_semantic_aggregate(
                pipeline,
                root=root,
                semantic_approval_sha256="a" * 64,
            )

        self.assertEqual(result["record_count"], 1)
        self.assertEqual(state.stage("classification").status, StageStatus.LOCKED)
        self.assertEqual(state.stage("aggregate").status, StageStatus.COMPLETE)
        self.assertEqual(state.stage("report").status, StageStatus.ALLOWED)

    def test_semantic_approval_refreshes_the_local_candidate_before_signing(self):
        from community_os.release_operator import (
            _regenerate_semantic_report_candidate,
        )

        calls: list[str] = []
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            html = root / "report.html"
            pdf = root / "report.pdf"
            html.write_text("stale", encoding="utf-8")
            pdf.write_bytes(b"stale")

            def operation():
                calls.append("report")
                for path, contents in (
                    (html, b"fresh-html"),
                    (pdf, b"fresh-pdf"),
                ):
                    temporary = path.with_suffix(path.suffix + ".next")
                    temporary.write_bytes(contents)
                    temporary.replace(path)
                return [{"artifact": "html_pdf"}]

            result = _regenerate_semantic_report_candidate(
                operation,
                required_artifacts=(html, pdf),
            )

        self.assertEqual(calls, ["report"])
        self.assertEqual(result["record_count"], 1)
        self.assertRegex(str(result["output_hash"]), r"^[0-9a-f]{64}$")

    def test_semantic_approval_endpoint_refreshes_candidate_before_approval(self):
        order: list[str] = []
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _seed_validated_operator_sources(root)

            def factory(_state):
                return {"report": lambda: [{"artifact": "report"}]}

            with (
                patch(
                    "community_os.release_operator."
                    "_regenerate_semantic_report_candidate",
                    side_effect=lambda *_args, **_kwargs: (
                        order.append("candidate")
                        or {"output_hash": "1" * 64, "record_count": 1}
                    ),
                ),
                patch(
                    "community_os.controlled_release."
                    "issue_current_semantic_release_approval",
                    side_effect=lambda *_args, **_kwargs: (
                        order.append("approval")
                        or {"approval_sha256": "2" * 64, "state": "complete"}
                    ),
                ),
                patch(
                    "community_os.release_operator."
                    "_adopt_approved_semantic_aggregate",
                    side_effect=lambda *_args, **_kwargs: (
                        order.append("aggregate")
                        or {"output_hash": "3" * 64, "record_count": 1}
                    ),
                ),
                patch(
                    "community_os.release_operator.run_local_report_render",
                    side_effect=lambda *_args, **_kwargs: (
                        order.append("report")
                        or {"output_hash": "4" * 64, "record_count": 1}
                    ),
                ),
                patch(
                    "community_os.release_operator.release_export_ready",
                    return_value=True,
                ),
                patch(
                    "community_os.release_operator.ReleaseOperatorState."
                    "semantic_release_authoritative_context",
                    return_value={},
                ),
                _running_release_operator(
                    root,
                    stage_operation_factory=factory,
                    release_owner=True,
                ) as (base_url, auth_headers),
            ):
                status, page = _http_result(Request(
                    base_url + "/", headers=auth_headers,
                ))
                self.assertEqual(status, 200)
                csrf = re.search(
                    rb'name="operator-csrf" content="([^"]+)"', page,
                )
                self.assertIsNotNone(csrf)
                approved, _body = _http_result(Request(
                    base_url + "/approve-semantic-release",
                    data=b"{}",
                    method="POST",
                    headers={
                        **auth_headers,
                        "Content-Type": "application/json",
                        "X-Operator-CSRF": csrf.group(1).decode(),
                    },
                ))

        self.assertEqual(approved, 200, _body.decode("utf-8"))
        self.assertEqual(order, ["candidate", "approval", "aggregate", "report"])

    def test_report_render_fails_if_html_and_pdf_are_not_freshly_generated(self):
        from community_os.enrichment.release_pipeline import ReleasePipeline
        from community_os.enrichment.state import PipelineState, StageStatus
        from community_os.release_operator import run_local_report_render

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = PipelineState.create(root / "pipeline.json", {
                "aggregate": StageStatus.ALLOWED,
                "report": StageStatus.ALLOWED,
                "publish": StageStatus.ALLOWED,
                "analytics": StageStatus.ALLOWED,
            })
            state.start("aggregate")
            state.complete("aggregate", {"output_hash": "a" * 64, "record_count": 2})
            pipeline = ReleasePipeline(
                state, manifest_path=root / "manifest.json",
                prerequisites={"report": ("aggregate",)},
            )
            html, pdf = root / "report.html", root / "report.pdf"
            html.write_text("stale", encoding="utf-8")
            pdf.write_text("stale", encoding="utf-8")

            with self.assertRaisesRegex(PermissionError, "freshly regenerate"):
                run_local_report_render(
                    pipeline, lambda: [{"artifact": "html_pdf"}],
                    required_artifacts=(html, pdf),
                )

        self.assertEqual(state.stage("report").status, StageStatus.FAILED)

    def test_report_render_button_requires_current_aggregates(self):
        from community_os.release_operator import ReleaseOperatorState, render_release_operator_page

        with tempfile.TemporaryDirectory() as directory:
            state = ReleaseOperatorState(Path(directory), operator_code="release_owner", event_definition=_event_definition())
            blocked = render_release_operator_page(state)
            state.pipeline.start("aggregate")
            state.pipeline.complete(
                "aggregate", {"output_hash": "a" * 64, "record_count": 2},
            )
            ready = render_release_operator_page(state)

        self.assertRegex(blocked, r'<button[^>]+data-render-report[^>]+disabled')
        self.assertRegex(ready, r'<button[^>]+data-render-report(?![^>]+disabled)')

    def test_page_does_not_report_reconciled_privacy_rights_as_blockers(self):
        from community_os.release_operator import ReleaseOperatorState, render_release_operator_page

        with tempfile.TemporaryDirectory() as directory:
            state = ReleaseOperatorState(Path(directory), operator_code="release_owner", event_definition=_event_definition())
            for field, status in (
                ("notice", "recorded"), ("objections", "reconciled"),
                ("exclusions", "reconciled"), ("suppressions", "reconciled"),
                ("deletions", "reconciled"),
                ("retention_cleanup", "complete"),
            ):
                state.record_privacy_status(field, status)
            html = render_release_operator_page(state)

        self.assertNotIn("Privacy Operations requires reconciliation", html)

    def test_single_controlled_action_runs_each_prepublication_stage_once_and_never_activates_analytics(self):
        from community_os.release_operator import run_approved_release
        from community_os.enrichment.release_pipeline import ReleasePipeline
        from community_os.enrichment.state import PipelineState, StageStatus
        calls = []
        with tempfile.TemporaryDirectory() as directory:
            state = PipelineState.create(Path(directory) / "pipeline.json", {
                stage: (StageStatus.LOCKED if stage in {"github", "public_pages", "classification"} else StageStatus.ALLOWED)
                for stage in ("reconcile", "github", "public_pages", "classification", "aggregate", "report", "publish", "analytics")
            })
            state.unlock("github", source_gate("applicant_supplied_github", 30), now=NOW)
            state.unlock("public_pages", source_gate("applicant_supplied_public_pages", 14), now=NOW)
            state.unlock("classification", processor_approval(), now=NOW)
            pipeline = ReleasePipeline(
                state, manifest_path=Path(directory) / "manifest.json",
                config={"optional_stage_policy_bound": True},
            )
            operations = {
                stage: (lambda stage=stage: calls.append(stage) or [])
                for stage in ("privacy_cleanup", *state.to_dict()["stages"])
            }
            operations["withdraw_publication"] = lambda: calls.append("withdraw_publication") or []
            run_approved_release(pipeline, operations, include_coresignal=False)
            self.assertEqual(calls, ["privacy_cleanup", "reconcile", "github", "public_pages", "classification", "aggregate", "report", "publish"])
            run_approved_release(pipeline, operations, include_coresignal=False)
            self.assertEqual(calls.count("privacy_cleanup"), 2)
            self.assertEqual(len(calls), 9)
            self.assertNotIn("analytics", calls)
            with self.assertRaises(PermissionError):
                run_approved_release(pipeline, {}, include_coresignal=False)

    def test_controlled_action_skips_only_manifest_bound_disabled_public_pages(self):
        from community_os.release_operator import run_approved_release
        from community_os.enrichment.release_pipeline import ReleasePipeline
        from community_os.enrichment.state import PipelineState, StageStatus

        calls: list[str] = []
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = PipelineState.create(root / "pipeline.json", {
                stage: (
                    StageStatus.LOCKED
                    if stage in {"github", "public_pages", "classification"}
                    else StageStatus.ALLOWED
                )
                for stage in (
                    "reconcile", "github", "public_pages", "classification",
                    "aggregate", "report", "publish", "analytics",
                )
            })
            state.unlock(
                "github", source_gate("applicant_supplied_github", 30), now=NOW,
            )
            state.unlock("classification", processor_approval(), now=NOW)
            pipeline = ReleasePipeline(
                state,
                manifest_path=root / "manifest.json",
                config={
                    "disabled_optional_stages": ["public_pages"],
                    "optional_stage_policy_bound": True,
                },
                prerequisites={
                    "github": ("reconcile",),
                    "classification": ("github",),
                    "aggregate": ("classification",),
                    "report": ("aggregate",),
                    "publish": ("report",),
                },
            )
            operations = {
                stage: (lambda stage=stage: calls.append(stage) or [])
                for stage in (
                    "privacy_cleanup", "reconcile", "github", "classification",
                    "aggregate", "report", "publish",
                )
            }

            run_approved_release(
                pipeline, operations, include_coresignal=False,
            )

            self.assertEqual(calls, [
                "privacy_cleanup", "reconcile", "github", "classification",
                "aggregate", "report", "publish",
            ])
            self.assertEqual(
                state.stage("public_pages").status, StageStatus.LOCKED,
            )
            manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(
                pipeline.config["disabled_optional_stages"], ["public_pages"],
            )
            self.assertEqual(manifest["stages"]["public_pages"]["status"], "locked")

    def test_controlled_action_rejects_unbound_optional_policy_before_cleanup(self):
        from community_os.enrichment.release_pipeline import ReleasePipeline
        from community_os.enrichment.state import PipelineState, StageStatus
        from community_os.release_operator import run_approved_release

        for marker in (None, False):
            with self.subTest(marker=marker), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                state = PipelineState.create(root / "pipeline.json", {
                    stage: (
                        StageStatus.LOCKED
                        if stage in {"github", "public_pages", "classification"}
                        else StageStatus.ALLOWED
                    )
                    for stage in (
                        "reconcile", "github", "public_pages", "classification",
                        "aggregate", "report", "publish", "analytics",
                    )
                })
                config = (
                    {} if marker is None
                    else {"optional_stage_policy_bound": marker}
                )
                calls: list[str] = []
                pipeline = ReleasePipeline(
                    state, manifest_path=root / "manifest.json", config=config,
                )

                with self.assertRaisesRegex(
                    PermissionError, "optional-stage approval policy was not bound",
                ):
                    run_approved_release(
                        pipeline,
                        {
                            stage: (lambda stage=stage: calls.append(stage) or [])
                            for stage in (
                                "privacy_cleanup", "reconcile", "github",
                                "public_pages", "classification", "aggregate",
                                "report", "publish",
                            )
                        },
                        include_coresignal=False,
                    )

                self.assertEqual(calls, [])

    def test_controlled_action_rejects_malformed_optional_stage_policy_before_cleanup(self):
        from community_os.release_operator import run_approved_release
        from community_os.enrichment.release_pipeline import ReleasePipeline
        from community_os.enrichment.state import PipelineState, StageStatus

        for malformed in ("public_pages", ["github"], ["public_pages", "public_pages"]):
            with self.subTest(malformed=malformed), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                state = PipelineState.create(root / "pipeline.json", {
                    stage: StageStatus.LOCKED if stage in {
                        "github", "public_pages", "classification",
                    } else StageStatus.ALLOWED
                    for stage in (
                        "reconcile", "github", "public_pages", "classification",
                        "aggregate", "report", "publish", "analytics",
                    )
                })
                calls: list[str] = []
                pipeline = ReleasePipeline(
                    state,
                    manifest_path=root / "manifest.json",
                    config={
                        "disabled_optional_stages": malformed,
                        "optional_stage_policy_bound": True,
                    },
                )

                with self.assertRaisesRegex(
                    PermissionError, "disabled optional stage policy is invalid",
                ):
                    run_approved_release(
                        pipeline,
                        {"privacy_cleanup": lambda: calls.append("cleanup") or []},
                        include_coresignal=False,
                    )

                self.assertEqual(calls, [])

    def test_disabled_public_pages_must_remain_locked_before_release_runs(self):
        from community_os.release_operator import run_approved_release
        from community_os.enrichment.release_pipeline import ReleasePipeline
        from community_os.enrichment.state import PipelineState, StageStatus

        calls: list[str] = []
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = PipelineState.create(root / "pipeline.json", {
                "reconcile": StageStatus.ALLOWED,
                "github": StageStatus.LOCKED,
                "public_pages": StageStatus.LOCKED,
                "classification": StageStatus.LOCKED,
                "aggregate": StageStatus.ALLOWED,
                "report": StageStatus.ALLOWED,
                "publish": StageStatus.ALLOWED,
                "analytics": StageStatus.ALLOWED,
            })
            state.unlock(
                "public_pages",
                source_gate("applicant_supplied_public_pages", 14),
                now=NOW,
            )
            pipeline = ReleasePipeline(
                state,
                manifest_path=root / "manifest.json",
                config={
                    "disabled_optional_stages": ["public_pages"],
                    "optional_stage_policy_bound": True,
                },
            )

            with self.assertRaisesRegex(
                PermissionError,
                "disabled optional stage public_pages must remain locked",
            ):
                run_approved_release(
                    pipeline,
                    {"privacy_cleanup": lambda: calls.append("cleanup") or []},
                    include_coresignal=False,
                )

        self.assertEqual(calls, [])

    def test_controlled_action_updates_manifest_when_publication_fails(self):
        from community_os.enrichment.release_pipeline import ReleasePipeline
        from community_os.enrichment.state import PipelineState, StageStatus
        from community_os.release_operator import run_approved_release

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = PipelineState.create(root / "pipeline.json", {
                stage: (StageStatus.LOCKED if stage in {"github", "public_pages", "classification"} else StageStatus.ALLOWED)
                for stage in ("reconcile", "github", "public_pages", "classification", "aggregate", "report", "publish", "analytics")
            })
            state.unlock("github", source_gate("applicant_supplied_github", 30), now=NOW)
            state.unlock("public_pages", source_gate("applicant_supplied_public_pages", 14), now=NOW)
            state.unlock("classification", processor_approval(), now=NOW)
            manifest_path = root / "manifest.json"
            manifest_path.write_text('{"stale":true}', encoding="utf-8")
            pipeline = ReleasePipeline(
                state, manifest_path=manifest_path,
                config={"optional_stage_policy_bound": True},
            )
            operations = {
                stage: (lambda: []) for stage in ("privacy_cleanup", *state.to_dict()["stages"])
            }
            operations["publish"] = lambda: (_ for _ in ()).throw(PermissionError("approval missing"))

            with self.assertRaisesRegex(PermissionError, "approval missing"):
                run_approved_release(pipeline, operations, include_coresignal=False)

            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            self.assertEqual(manifest["stages"]["report"]["status"], "complete")
            self.assertEqual(manifest["stages"]["publish"]["status"], "failed")

    def test_controlled_action_never_unlocks_a_missing_approval(self):
        from community_os.release_operator import run_approved_release
        from community_os.enrichment.release_pipeline import ReleasePipeline
        from community_os.enrichment.state import PipelineState, StageStatus
        with tempfile.TemporaryDirectory() as directory:
            state = PipelineState.create(Path(directory) / "pipeline.json", {
                "reconcile": StageStatus.ALLOWED,
                "github": StageStatus.LOCKED,
                "public_pages": StageStatus.LOCKED,
                "classification": StageStatus.LOCKED,
                "aggregate": StageStatus.ALLOWED,
                "report": StageStatus.ALLOWED,
                "publish": StageStatus.ALLOWED,
                "analytics": StageStatus.ALLOWED,
            })
            state.unlock("github", source_gate("applicant_supplied_github", 30), now=NOW)
            state.unlock("public_pages", source_gate("applicant_supplied_public_pages", 14), now=NOW)
            pipeline = ReleasePipeline(
                state, manifest_path=Path(directory) / "manifest.json",
                config={"optional_stage_policy_bound": True},
            )
            operations = {
                stage: (lambda: [])
                for stage in ("privacy_cleanup", *state.to_dict()["stages"])
            }
            with self.assertRaisesRegex(PermissionError, "classification remains locked"):
                run_approved_release(pipeline, operations, include_coresignal=False)
            self.assertEqual(state.stage("classification").status, StageStatus.LOCKED)

    def test_later_coresignal_evaluation_cannot_invalidate_or_enter_release(self):
        from community_os.enrichment.gates import CoresignalGate
        from community_os.enrichment.release_pipeline import ReleasePipeline
        from community_os.enrichment.state import PipelineState, StageStatus
        from community_os.release_operator import run_approved_release

        calls: list[str] = []
        with tempfile.TemporaryDirectory() as directory:
            state = PipelineState.create(Path(directory) / "pipeline.json", {
                stage: (StageStatus.LOCKED if stage in {"github", "public_pages", "coresignal", "classification"} else StageStatus.ALLOWED)
                for stage in ("reconcile", "github", "public_pages", "coresignal", "classification", "aggregate", "report", "publish", "analytics")
            })
            state.unlock("github", source_gate("applicant_supplied_github", 30), now=NOW)
            state.unlock("public_pages", source_gate("applicant_supplied_public_pages", 14), now=NOW)
            state.unlock("classification", processor_approval(), now=NOW)
            state.unlock("coresignal", CoresignalGate(
                notice_version="coresignal_transparency_v1", notice_sent_at="2026-07-13T08:00:00Z",
                notice_scope="linkedin_coresignal_enrichment",
                notice_content_sha256="d" * 64,
                objections_reconciled=True, exclusions_reconciled=True,
                suppressions_reconciled=True, deletions_reconciled=True,
                access_verified=True, provider_terms_version="terms_v1",
                source_scope="applicant_supplied_linkedin", retention_days=14,
                approval_id="release_approval_001",
                approved_at="2026-07-13T09:00:00Z",
            ), now=NOW)
            pipeline = ReleasePipeline(
                state, manifest_path=Path(directory) / "manifest.json",
                config={"optional_stage_policy_bound": True},
            )
            operations = {
                stage: (lambda stage=stage: calls.append(stage) or [])
                for stage in ("privacy_cleanup", *state.to_dict()["stages"])
            }
            operations["withdraw_publication"] = lambda: calls.append("withdraw_publication") or []
            run_approved_release(pipeline, operations, include_coresignal=False)
            calls.clear()

            with self.assertRaisesRegex(
                PermissionError,
                "Coresignal evaluation cannot enter the release pipeline",
            ):
                run_approved_release(pipeline, operations, include_coresignal=True)

            self.assertEqual(calls, [])
            for stage in ("classification", "aggregate", "report", "publish"):
                self.assertEqual(state.stage(stage).status, StageStatus.COMPLETE)

    def test_controlled_action_stops_before_enrichment_when_physical_cleanup_fails(self):
        from community_os.release_operator import run_approved_release
        from community_os.enrichment.release_pipeline import ReleasePipeline
        from community_os.enrichment.state import PipelineState, StageStatus
        calls = []
        with tempfile.TemporaryDirectory() as directory:
            state = PipelineState.create(Path(directory) / "pipeline.json", {
                stage: (StageStatus.LOCKED if stage in {"github", "public_pages", "classification"} else StageStatus.ALLOWED)
                for stage in ("reconcile", "github", "public_pages", "classification", "aggregate", "report", "publish", "analytics")
            })
            pipeline = ReleasePipeline(
                state, manifest_path=Path(directory) / "manifest.json",
                config={"optional_stage_policy_bound": True},
            )
            def cleanup():
                calls.append("privacy_cleanup")
                raise RuntimeError("physical deletion failed")
            operations = {
                stage: (lambda stage=stage: calls.append(stage) or [])
                for stage in state.to_dict()["stages"]
            }
            operations["privacy_cleanup"] = cleanup
            with self.assertRaisesRegex(RuntimeError, "physical deletion failed"):
                run_approved_release(pipeline, operations, include_coresignal=False)
            self.assertEqual(calls, ["privacy_cleanup"])

    def test_release_affecting_mutations_invalidate_completed_dependents_and_public_staging(self):
        from community_os.release_operator import ReleaseOperatorState, ReleaseSourceSlot
        from community_os.enrichment.state import StageStatus

        with tempfile.TemporaryDirectory() as directory:
            state = ReleaseOperatorState(Path(directory), operator_code="privacy_lead", event_definition=_event_definition())
            state.record_semantic_processor_authorization(processor_approval(), now=NOW)
            for stage in (
                "reconcile", "classification", "aggregate", "report", "publish",
                "analytics",
            ):
                state.pipeline.start(stage)
                state.pipeline.complete(stage, {"output_hash": "a" * 64, "record_count": 1})
            public = state.root / "public-staging"
            public.mkdir()
            (public / "index.html").write_text("stale")
            (public / "partner-talent-brief.pdf").write_text("stale")
            deployment = state.root / "deployment-staging"
            deployment.mkdir()
            for name in (
                "vercel.json", "index.html", "partner-talent-brief.pdf",
                "publication-manifest.json",
            ):
                (deployment / name).write_text("stale")
            analytics_audit = state.root / "protected" / "analytics-publication.json"
            analytics_audit.write_text("stale")

            state.apply_correction("going_accepted", 82, reason_code="owner_correction")

            self.assertEqual(state.pipeline.stage("reconcile").status, StageStatus.COMPLETE)
            self.assertEqual(state.pipeline.stage("classification").status, StageStatus.COMPLETE)
            for stage in ("aggregate", "report", "publish", "analytics"):
                self.assertEqual(state.pipeline.stage(stage).status, StageStatus.ALLOWED)
            self.assertFalse((public / "index.html").exists())
            self.assertFalse((public / "partner-talent-brief.pdf").exists())
            self.assertFalse(deployment.exists())
            self.assertFalse(analytics_audit.exists())
            self.assertEqual(state.snapshot()["release_state"], "Blocked")

            state.record_privacy_status("retention_cleanup", "complete")
            self.assertEqual(state.pipeline.stage("reconcile").status, StageStatus.COMPLETE)
            for stage in ("classification", "aggregate", "report", "publish"):
                self.assertEqual(state.pipeline.stage(stage).status, StageStatus.ALLOWED)

            state.record_source(
                ReleaseSourceSlot.APPLICATIONS, sha256="b" * 64,
                row_count=2, filename="applications.csv",
            )
            self.assertEqual(state.pipeline.stage("reconcile").status, StageStatus.ALLOWED)

    def test_operator_separates_partner_share_files_from_internal_evidence(self) -> None:
        from community_os.release_operator import (
            ReleaseOperatorState, render_release_operator_page,
        )

        with tempfile.TemporaryDirectory() as directory:
            state = ReleaseOperatorState(
                Path(directory), operator_code="release_owner",
            event_definition=_event_definition(),
            )
            html = render_release_operator_page(state)

        self.assertIn("Partner share files", html)
        self.assertIn("Internal operator evidence", html)
        self.assertIn("Never forward this internal evidence", html)
        self.assertLess(html.index("Partner share files"), html.index("Internal operator evidence"))
        share = html.split("Partner share files", 1)[1].split(
            "Internal operator evidence", 1,
        )[0]
        internal = html.split("Internal operator evidence", 1)[1]
        self.assertIn("partner HTML", share)
        self.assertIn("partner PDF", share)
        self.assertIn("publication manifest", share)
        self.assertNotIn("aggregates", share)
        self.assertIn("aggregates", internal)
        self.assertNotIn("Export QA report</a></div></section>", html)

    def test_operator_hides_superseded_legacy_classification_queue(self) -> None:
        from community_os.release_operations import ReviewCase, ReviewDecision
        from community_os.release_operator import (
            ReleaseOperatorState, render_release_operator_page,
        )

        with tempfile.TemporaryDirectory() as directory:
            state = ReleaseOperatorState(
                Path(directory),
                operator_code="privacy_lead",
                event_definition=_event_definition(),
            )
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
            state.review_repository.replace((legacy, rich))
            state.review_repository.decide(
                ReviewDecision(
                    case_code=rich.case_code,
                    case_hash=rich.case_hash,
                    action="approved",
                ),
                actor_code="colleague_0123456789abcdef0123456789abcdef",
                decided_at=NOW,
            )

            html = render_release_operator_page(state)

        self.assertNotIn(legacy.case_code, html)
        self.assertIn("0 open classification review(s)", html)
        self.assertNotIn("1 review case(s) still need a recorded decision", html)

    def test_publication_approval_endpoint_is_owner_only_and_runs_no_provider_stage(self) -> None:
        from community_os.release_operator import ReleaseOperatorState

        calls: list[str] = []
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _seed_validated_operator_sources(root)
            state = ReleaseOperatorState(
                root,
                operator_code="privacy_lead",
                event_definition=_event_definition(),
            )
            state.configure_optional_stage_policy(())
            state.pipeline.start("reconcile")
            state.pipeline.complete(
                "reconcile", {"output_hash": "1" * 64, "record_count": 1},
            )
            state.record_public_source_authorization(
                "github", source_gate("applicant_supplied_github", 30), now=NOW,
            )
            state.record_public_source_authorization(
                "public_pages",
                source_gate("applicant_supplied_public_pages", 14),
                now=NOW,
            )
            for stage in ("github", "public_pages"):
                state.pipeline.start(stage)
                state.pipeline.complete(
                    stage, {"output_hash": "2" * 64, "record_count": 1},
                )
            authorize_operator_rich_semantics(state, now=NOW)
            for stage in ("classification", "aggregate", "report"):
                state.pipeline.start(stage)
                state.pipeline.complete(
                    stage, {"output_hash": "3" * 64, "record_count": 1},
                )
            approval_bundle = (
                root / "protected" / "controlled-release-approval.json"
            )
            approval_bundle.write_bytes(b'{"publication_approval":null}\n')
            approval_bundle.chmod(0o600)

            def factory(_state):
                return {
                    "publish": lambda: calls.append("publish") or [{
                        "release_state": "Safe to publish",
                    }],
                }

            with (
                patch(
                    "community_os.controlled_release."
                    "issue_current_publication_approval",
                    side_effect=lambda *_args, **_kwargs: (
                        calls.append("approve") or {"state": "complete"}
                    ),
                ),
                _running_release_operator(
                    root,
                    stage_operation_factory=factory,
                    release_owner=True,
                ) as (base_url, auth_headers),
            ):
                status, page = _http_result(Request(
                    base_url + "/", headers=auth_headers,
                ))
                self.assertEqual(status, 200)
                csrf = re.search(
                    rb'name="operator-csrf" content="([^"]+)"', page,
                )
                self.assertIsNotNone(csrf)
                headers = {
                    **auth_headers,
                    "Content-Type": "application/json",
                    "X-Operator-CSRF": csrf.group(1).decode(),
                }
                denied, _body = _http_result(Request(
                    base_url + "/approve-publication",
                    data=b"{}",
                    method="POST",
                    headers={
                        **headers,
                        "X-Operator-Email": "attacker@example.org",
                    },
                ))
                self.assertEqual(denied, 403)
                self.assertEqual(calls, [])

                approved, body = _http_result(Request(
                    base_url + "/approve-publication",
                    data=b"{}",
                    method="POST",
                    headers=headers,
                ))

            self.assertEqual(approved, 200, body)
            self.assertEqual(calls, ["approve", "publish"])

    def test_failed_publication_staging_rolls_back_approval_bundle(self) -> None:
        from community_os.release_operator import ReleaseOperatorState

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _seed_validated_operator_sources(root)
            state = ReleaseOperatorState(
                root,
                operator_code="privacy_lead",
                event_definition=_event_definition(),
            )
            state.configure_optional_stage_policy(())
            state.pipeline.start("reconcile")
            state.pipeline.complete(
                "reconcile", {"output_hash": "1" * 64, "record_count": 1},
            )
            state.record_public_source_authorization(
                "github", source_gate("applicant_supplied_github", 30), now=NOW,
            )
            state.record_public_source_authorization(
                "public_pages",
                source_gate("applicant_supplied_public_pages", 14),
                now=NOW,
            )
            for stage in ("github", "public_pages"):
                state.pipeline.start(stage)
                state.pipeline.complete(
                    stage, {"output_hash": "2" * 64, "record_count": 1},
                )
            authorize_operator_rich_semantics(state, now=NOW)
            for stage in ("classification", "aggregate", "report"):
                state.pipeline.start(stage)
                state.pipeline.complete(
                    stage, {"output_hash": "3" * 64, "record_count": 1},
                )

            bundle_path = root / "protected" / "controlled-release-approval.json"
            original = b'{"publication_approval":null}\n'
            bundle_path.write_bytes(original)
            bundle_path.chmod(0o600)

            def issue(*_args, **_kwargs):
                bundle_path.write_bytes(b'{"publication_approval":{"issued":true}}\n')
                return {"state": "complete"}

            def factory(_state):
                def publish():
                    raise PermissionError("synthetic publication failure")

                return {"publish": publish}

            with (
                patch(
                    "community_os.controlled_release."
                    "issue_current_publication_approval",
                    side_effect=issue,
                ),
                _running_release_operator(
                    root,
                    stage_operation_factory=factory,
                    release_owner=True,
                ) as (base_url, auth_headers),
            ):
                status, page = _http_result(Request(
                    base_url + "/", headers=auth_headers,
                ))
                self.assertEqual(status, 200)
                csrf = re.search(
                    rb'name="operator-csrf" content="([^"]+)"', page,
                )
                self.assertIsNotNone(csrf)
                failed, _body = _http_result(Request(
                    base_url + "/approve-publication",
                    data=b"{}",
                    method="POST",
                    headers={
                        **auth_headers,
                        "Content-Type": "application/json",
                        "X-Operator-CSRF": csrf.group(1).decode(),
                    },
                ))

            self.assertNotEqual(failed, 200)
            self.assertEqual(bundle_path.read_bytes(), original)

    def test_generic_stage_endpoint_cannot_bypass_owner_only_publication_action(self) -> None:
        from community_os.release_operator import ReleaseOperatorState

        calls: list[str] = []
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _seed_validated_operator_sources(root)
            state = ReleaseOperatorState(
                root,
                operator_code="privacy_lead",
                event_definition=_event_definition(),
            )
            state.configure_optional_stage_policy(())
            state.pipeline.start("reconcile")
            state.pipeline.complete(
                "reconcile", {"output_hash": "1" * 64, "record_count": 1},
            )
            state.record_public_source_authorization(
                "github", source_gate("applicant_supplied_github", 30), now=NOW,
            )
            state.record_public_source_authorization(
                "public_pages",
                source_gate("applicant_supplied_public_pages", 14),
                now=NOW,
            )
            for stage in ("github", "public_pages"):
                state.pipeline.start(stage)
                state.pipeline.complete(
                    stage, {"output_hash": "2" * 64, "record_count": 1},
                )
            authorize_operator_rich_semantics(state, now=NOW)
            for stage in ("classification", "aggregate", "report"):
                state.pipeline.start(stage)
                state.pipeline.complete(
                    stage, {"output_hash": "3" * 64, "record_count": 1},
                )

            def factory(_state):
                return {
                    "publish": lambda: calls.append("publish") or [{
                        "release_state": "Safe to publish",
                    }],
                }

            with _running_release_operator(
                root,
                stage_operation_factory=factory,
                release_owner=False,
            ) as (base_url, auth_headers):
                status, page = _http_result(Request(
                    base_url + "/", headers=auth_headers,
                ))
                self.assertEqual(status, 200)
                csrf = re.search(
                    rb'name="operator-csrf" content="([^"]+)"', page,
                )
                self.assertIsNotNone(csrf)
                denied, _body = _http_result(Request(
                    base_url + "/stage",
                    data=b'{"stage":"publish"}',
                    method="POST",
                    headers={
                        **auth_headers,
                        "Content-Type": "application/json",
                        "X-Operator-CSRF": csrf.group(1).decode(),
                    },
                ))

            self.assertEqual(denied, 400)
            self.assertEqual(calls, [])

    def test_partner_bundle_exports_fail_closed_after_manifest_or_byte_tampering(self) -> None:
        from community_os.enrichment.release_pipeline import canonical_hash
        from community_os.postpublication_analytics import (
            AnalyticsActivationApproval,
            PostHogPrivacyVerification,
            prepare_analytics_publication_bundle,
        )
        from community_os.release_operator import (
            _verified_vercel_config, release_export_ready,
        )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = _seed_staged_public_bundle(root)
            source = root / "public-staging"
            source_index = source / "index.html"
            source_manifest = source / "publication-manifest.json"
            deployment = root / "deployment-staging"
            privacy_verification = PostHogPrivacyVerification(
                receipt_version="posthog-project-privacy-v1",
                api_origin="https://eu.posthog.com",
                ingestion_origin="https://eu.i.posthog.com",
                project_id=73155,
                public_key_sha256=hashlib.sha256(
                    b"phc_public_123",
                ).hexdigest(),
                anonymize_ips=True,
                verified_at=NOW,
                project_response_sha256=hashlib.sha256(
                    json.dumps({
                        "anonymize_ips": True,
                        "project_id": 73155,
                        "public_key_sha256": hashlib.sha256(
                            b"phc_public_123",
                        ).hexdigest(),
                    }, sort_keys=True, separators=(",", ":")).encode("utf-8"),
                ).hexdigest(),
            )
            privacy_receipt_path = (
                root / "protected" / "posthog-project-privacy.json"
            )
            with patch(
                "community_os.postpublication_analytics._posthog_json_get",
                side_effect=(
                    {
                        "id": 73155,
                        "api_token": "phc_public_123",
                        "anonymize_ips": True,
                        "name": "Partner report",
                    },
                ),
            ):
                manifest = prepare_analytics_publication_bundle(
                    source_directory=source,
                    destination=deployment,
                    approval=AnalyticsActivationApproval(
                        approval_code="approval_12345678",
                        actor_code="actor_12345678",
                        scope="privacy_limited_posthog",
                        report_sha256=hashlib.sha256(
                            source_index.read_bytes(),
                        ).hexdigest(),
                        publication_manifest_sha256=hashlib.sha256(
                            source_manifest.read_bytes(),
                        ).hexdigest(),
                        posthog_privacy_receipt_sha256=privacy_verification.sha256,
                        approved_at=NOW,
                        expires_at=NOW + timedelta(minutes=15),
                    ),
                    public_key="phc_public_123",
                    posthog_host="https://eu.i.posthog.com",
                    personal_api_key="phx_" + "private_operator_key",
                    posthog_project_id=73155,
                    now=NOW,
                    posthog_privacy_artifact_path=privacy_receipt_path,
                )
            manifest_path = deployment / "publication-manifest.json"
            exact_manifest_bytes = manifest_path.read_bytes()
            exact_privacy_receipt_bytes = privacy_receipt_path.read_bytes()
            state.pipeline.start("analytics")
            state.pipeline.complete(
                "analytics",
                {
                    "output_hash": canonical_hash([{
                        "analytics_policy_version": "posthog-minimal-v3",
                        "artifact_count": 3,
                        "manifest_hash": hashlib.sha256(
                            exact_manifest_bytes,
                        ).hexdigest(),
                        "release_state": "Safe to publish",
                    }]),
                    "record_count": 1,
                },
            )

            for artifact in (
                "vercel_config", "site_html", "site_pdf", "site_manifest",
            ):
                self.assertTrue(release_export_ready(state, artifact))

            privacy_receipt_path.write_text("{}\n", encoding="utf-8")
            for artifact in (
                "vercel_config", "site_html", "site_pdf", "site_manifest",
            ):
                self.assertFalse(release_export_ready(state, artifact))
            privacy_receipt_path.write_bytes(exact_privacy_receipt_bytes)

            vercel_config = json.loads(
                (deployment / "vercel.json").read_text(encoding="utf-8"),
            )
            self.assertTrue(_verified_vercel_config(vercel_config))
            for header in vercel_config["headers"][0]["headers"]:
                if header["key"] == "Permissions-Policy":
                    header["value"] = "camera=*"
            self.assertFalse(_verified_vercel_config(vercel_config))

            manifest_path.write_text(
                json.dumps(manifest, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            for artifact in (
                "vercel_config", "site_html", "site_pdf", "site_manifest",
            ):
                self.assertFalse(release_export_ready(state, artifact))
            manifest_path.write_bytes(exact_manifest_bytes)

            source_index.write_text("source staged tamper", encoding="utf-8")
            for artifact in (
                "vercel_config", "site_html", "site_pdf", "site_manifest",
            ):
                self.assertFalse(release_export_ready(state, artifact))

            source_index.write_bytes(
                (root / "protected" / "release" / "talent-brief.real.html")
                .read_bytes()
                .replace(b"talent-brief.real.pdf", b"partner-talent-brief.pdf"),
            )
            deployed_index = deployment / "index.html"
            deployed_index.write_text("coordinated staged tamper", encoding="utf-8")
            manifest["artifact_hashes"]["index.html"] = hashlib.sha256(
                deployed_index.read_bytes(),
            ).hexdigest()
            manifest_path.write_text(
                json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )
            for artifact in (
                "vercel_config", "site_html", "site_pdf", "site_manifest",
            ):
                self.assertFalse(release_export_ready(state, artifact))

    def test_operator_offers_explicit_local_analytics_preparation_after_staging(self) -> None:
        from community_os.enrichment.release_pipeline import canonical_hash
        from community_os.publication import artifact_set_sha256, _public_html_bytes
        from community_os.release_operator import (
            ReleaseOperatorState,
            render_release_operator_page,
        )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = ReleaseOperatorState(
                root,
                operator_code="privacy_lead",
                event_definition=_event_definition(),
            )
            release = root / "protected" / "release"
            release.mkdir(parents=True)
            source_html = release / "talent-brief.real.html"
            source_pdf = release / "talent-brief.real.pdf"
            source_html.write_text(
                '<html><head><style>body{color:#00002c}</style></head><body>'
                '<a href="talent-brief.real.pdf" download>Download PDF</a>'
                '<script>document.documentElement.classList.add("js")</script>'
                '</body></html>',
                encoding="utf-8",
            )
            source_pdf.write_bytes(b"%PDF-sites-bundle\n%%EOF")
            public = root / "public-staging"
            public.mkdir()
            index = public / "index.html"
            pdf = public / "partner-talent-brief.pdf"
            index.write_bytes(_public_html_bytes(source_html.read_bytes()))
            pdf.write_bytes(source_pdf.read_bytes())
            manifest_path = public / "publication-manifest.json"
            manifest = {
                "analytics_enabled": False,
                "artifact_set_sha256": artifact_set_sha256(
                    (source_html, source_pdf),
                ),
                "artifact_hashes": {
                    "index.html": hashlib.sha256(index.read_bytes()).hexdigest(),
                    "partner-talent-brief.pdf": hashlib.sha256(pdf.read_bytes()).hexdigest(),
                },
                "entrypoint": "index.html",
                "manifest_version": "partner-static-bundle-v1",
                "pdf": "partner-talent-brief.pdf",
                "privacy_state": "aggregate_only",
                "public_transform_version": "neutral-public-artifact-names-v1",
                "release_state": "Safe to publish",
            }
            manifest_path.write_text(
                json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )
            state.pipeline.start("publish")
            state.pipeline.complete("publish", {
                "output_hash": canonical_hash([{
                    "artifact_count": 2,
                    "manifest_hash": hashlib.sha256(
                        manifest_path.read_bytes(),
                    ).hexdigest(),
                    "release_state": "Safe to publish",
                }]),
                "record_count": 1,
            })

            html = render_release_operator_page(state)

        self.assertIn('data-analytics-form', html)
        self.assertIn('name="public_key"', html)
        self.assertNotIn('name="ip_capture_disabled"', html)
        self.assertIn("PostHog EU", html)
        self.assertIn("POSTHOG_PERSONAL_API_KEY", html)
        self.assertIn("POSTHOG_PROJECT_ID", html)
        self.assertIn("verifies the live project setting", html)
        self.assertIn("does not publish", html)
        self.assertNotIn("session replay is enabled", html)

    def test_release_owner_prepares_analytics_bundle_without_publishing(self) -> None:
        from community_os.release_operator import (
            ReleaseOperatorState,
            release_export_ready,
        )

        def stage_operation_factory(_state):
            return {}

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _seed_staged_public_bundle(root)
            with _running_release_operator(
                root,
                stage_operation_factory=stage_operation_factory,
                release_owner=True,
            ) as (base_url, headers):
                page_status, page = _http_result(Request(
                    base_url + "/", headers=headers,
                ))
                self.assertEqual(page_status, 200)
                csrf = re.search(
                    rb'name="operator-csrf" content="([^"]+)"', page,
                )
                self.assertIsNotNone(csrf)
                assert csrf is not None
                denied_status, denied_response = _http_result(Request(
                    base_url + "/prepare-analytics",
                    data=json.dumps({"public_key": "phc_public_123"}).encode(),
                    method="POST",
                    headers={
                        **headers,
                        "Content-Type": "application/json",
                        "X-Operator-CSRF": csrf.group(1).decode("ascii"),
                    },
                ))
                with patch.dict(os.environ, {
                    "POSTHOG_PERSONAL_API_KEY": "phx_" + "private_operator_key",
                    "POSTHOG_PROJECT_ID": "73155",
                }, clear=False), patch(
                    "community_os.postpublication_analytics._posthog_json_get",
                    side_effect=(
                        {
                            "id": 73155,
                            "api_token": "phc_public_123",
                            "anonymize_ips": True,
                            "name": "Partner report",
                        },
                        {
                            "id": 73155,
                            "api_token": "phc_public_123",
                            "anonymize_ips": True,
                            "name": "Partner report",
                        },
                    ),
                ) as posthog_get:
                    status, response = _http_result(Request(
                        base_url + "/prepare-analytics",
                        data=json.dumps({
                            "public_key": "phc_public_123",
                        }).encode(),
                        method="POST",
                        headers={
                            **headers,
                            "Content-Type": "application/json",
                            "X-Operator-CSRF": csrf.group(1).decode("ascii"),
                        },
                    ))

            deployment = root / "deployment-staging"
            state = ReleaseOperatorState(
                root,
                operator_code="privacy_lead",
                event_definition=_event_definition(),
            )
            self.assertEqual(denied_status, 400, denied_response)
            self.assertIn(b"POSTHOG_PERSONAL_API_KEY", denied_response)
            self.assertEqual(status, 200, response)
            self.assertEqual(posthog_get.call_count, 2)
            self.assertEqual(
                {path.name for path in deployment.iterdir()},
                {
                    "vercel.json", "index.html", "partner-talent-brief.pdf",
                    "publication-manifest.json",
                },
            )
            self.assertEqual(
                state.pipeline.stage("analytics").status.value,
                "complete",
            )
            for artifact in (
                "vercel_config", "site_html", "site_manifest", "site_pdf",
            ):
                self.assertTrue(release_export_ready(state, artifact), artifact)
            self.assertIn(
                "phc_public_123",
                (deployment / "index.html").read_text(encoding="utf-8"),
            )
            self.assertFalse((root / "published").exists())

            with _running_release_operator(
                root,
                stage_operation_factory=stage_operation_factory,
                release_owner=True,
            ) as (base_url, headers):
                ready_status, ready_page = _http_result(Request(
                    base_url + "/", headers=headers,
                ))
            self.assertEqual(ready_status, 200)
            self.assertIn(b"Analytics bundle sealed", ready_page)
            self.assertNotIn(b"<form class=\"report-build\" data-analytics-form", ready_page)

    def test_protected_operator_page_fences_the_legacy_unauthenticated_command(self) -> None:
        from community_os.release_operator import (
            ReleaseOperatorState, render_release_operator_page,
        )

        with tempfile.TemporaryDirectory() as directory:
            state = ReleaseOperatorState(
                Path(directory), operator_code="release_owner",
            event_definition=_event_definition(),
            )
            html = render_release_operator_page(state)

        self.assertIn("Authenticated release operator", html)
        self.assertIn("release-operator", html)
        self.assertIn("legacy operator command is unauthenticated", html)

    def test_release_invalidation_removes_the_local_partner_share_directory(self) -> None:
        from community_os.release_operator import ReleaseOperatorState

        with tempfile.TemporaryDirectory() as directory:
            state = ReleaseOperatorState(
                Path(directory), operator_code="release_owner",
            event_definition=_event_definition(),
            )
            share = state.root / "protected" / "release" / "partner-share"
            share.mkdir(parents=True)
            (share / "talent-brief.real.html").write_text(
                "stale partner share", encoding="utf-8",
            )

            state.apply_correction(
                "going_accepted", 82, reason_code="owner_correction",
            )

            self.assertFalse(share.exists())


if __name__ == "__main__":
    unittest.main()
