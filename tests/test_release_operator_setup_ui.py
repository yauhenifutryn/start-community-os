"""Focused tests for the authenticated first-run event setup surface."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import socket
import stat
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


def event_setup_payload() -> dict[str, object]:
    return {
        "version": "event-setup-v1",
        "event": {
            "key": "start-warsaw-autumn-2027",
            "name": "START Warsaw Autumn Hackathon",
            "starts_on": "2027-10-02",
            "ends_on": "2027-10-03",
            "timezone": "Europe/Warsaw",
        },
        "source_profile": "start-hackathon-v1",
        "selected_sheets": {
            "preferences": ["Responses 2027"],
            "submissions": ["health tech", "developer tools"],
        },
        "report_profile": "start-partner-talent-v1",
    }


def free_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def seed_ready_semantic_aggregate(root: Path):
    from datetime import UTC, datetime, timedelta

    from community_os.release_operator import ReleaseOperatorState
    from community_os.semantic_metrics import semantic_taxonomy_sha256
    from tests.test_release_operator import (
        _event_definition,
        authorize_operator_rich_semantics,
    )
    from tests.test_rich_semantic_review import proposal

    state = ReleaseOperatorState(
        root, operator_code="privacy_lead",
        event_definition=_event_definition(),
    )
    state.configure_semantic_release_authority(b"fixture-pseudonym-secret")
    now = datetime.now(UTC)
    approval_sha256 = authorize_operator_rich_semantics(state, now=now)
    for ordinal in range(1, 7):
        case = state.rich_semantic_reviews.submit(proposal(
            ordinal,
            approval_sha256=approval_sha256,
            created_at=(now - timedelta(minutes=1)).isoformat(),
            expires_at=(now + timedelta(days=1)).isoformat(),
        ))
        state.review_classification(case.case_code, case.case_hash, "approved")
    subjects = tuple(sorted(
        str(proposal(ordinal)["subject_ref"]) for ordinal in range(1, 7)
    ))
    aggregate = state.rich_semantic_reviews.build_population_aggregate(
        expected_subject_refs=subjects,
        binding_context={
            "event_approval_sha256": (
                state.rich_semantic_reviews.review_context_hashes["event_approval"]
            ),
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
    path = root / "protected" / "rich-semantic-internal.aggregate.json"
    path.write_text(json.dumps(aggregate) + "\n", encoding="utf-8")
    path.chmod(0o600)
    return state


def alternative_presentation_edits() -> dict[str, str]:
    from community_os.partner_report_presentation import (
        partner_report_presentation_copy_options,
    )

    options = partner_report_presentation_copy_options()
    return {
        key: options[key][-1]
        for key in ("cover_title", "cover_dek")
    }


class ReleaseOperatorSetupUITests(unittest.TestCase):
    def test_setup_page_exposes_only_registered_choices_and_event_metadata(self) -> None:
        from community_os.release_operator import render_event_setup_page

        html = render_event_setup_page(
            csrf="fixture-csrf", operator_code="privacy_lead",
        )

        self.assertIn('name="operator-csrf" content="fixture-csrf"', html)
        self.assertIn('value="start-hackathon-v1"', html)
        self.assertIn('value="start-partner-talent-v1"', html)
        self.assertIn('name="event-key"', html)
        self.assertIn('name="event-name"', html)
        self.assertIn('name="starts-on"', html)
        self.assertIn('name="ends-on"', html)
        self.assertIn('name="timezone"', html)
        self.assertIn('name="preference-sheets"', html)
        self.assertIn('name="submission-sheets"', html)
        self.assertIn("privacy_lead", html)
        self.assertNotIn("mapping_path", html)
        self.assertNotIn("mapping_sha256", html)
        self.assertNotIn("adapter_id", html)
        self.assertNotIn("source_sha256", html)

    def test_setup_server_requires_auth_and_csrf_then_writes_mode_0600_definition(self) -> None:
        from community_os.release_operator import (
            OperatorAccessPolicy,
            run_event_setup_operator,
        )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "operator"
            port = free_port()
            policy = OperatorAccessPolicy(
                allowed_emails=frozenset({"reviewer@example.org"}),
                proxy_secret="fixture-proxy-secret",
            )
            thread = threading.Thread(
                target=run_event_setup_operator,
                kwargs={
                    "root": root,
                    "access_policy": policy,
                    "operator_code": "privacy_lead",
                    "pseudonym_secret": b"fixture-pseudonym-secret",
                    "port": port,
                },
                daemon=True,
            )
            thread.start()
            base_url = f"http://127.0.0.1:{port}"
            headers = {
                "X-Operator-Email": "reviewer@example.org",
                "X-Operator-Proxy-Secret": "fixture-proxy-secret",
            }
            page = ""
            for _ in range(100):
                try:
                    with urlopen(
                        Request(base_url + "/", headers=headers), timeout=1,
                    ) as response:
                        page = response.read().decode("utf-8")
                    break
                except URLError:
                    time.sleep(0.01)
            else:
                self.fail("event setup operator did not start")

            with self.assertRaises(HTTPError) as unauthorized:
                urlopen(base_url + "/", timeout=1)
            self.assertEqual(unauthorized.exception.code, 403)
            unauthorized.exception.close()
            csrf_match = re.search(
                r'name="operator-csrf" content="([^"]+)"', page,
            )
            self.assertIsNotNone(csrf_match)
            destination = root / "event-definition.json"

            without_csrf = Request(
                base_url + "/event-setup",
                data=json.dumps(event_setup_payload()).encode("utf-8"),
                headers={**headers, "Content-Type": "application/json"},
                method="POST",
            )
            with self.assertRaises(HTTPError) as rejected:
                urlopen(without_csrf, timeout=1)
            self.assertEqual(rejected.exception.code, 403)
            rejected.exception.close()
            self.assertFalse(destination.exists())

            attacker_payload = event_setup_payload()
            attacker_payload["mapping_path"] = "../../private.json"
            invalid = Request(
                base_url + "/event-setup",
                data=json.dumps(attacker_payload).encode("utf-8"),
                headers={
                    **headers,
                    "Content-Type": "application/json",
                    "X-Operator-CSRF": csrf_match.group(1),
                },
                method="POST",
            )
            with self.assertRaises(HTTPError) as rejected:
                urlopen(invalid, timeout=1)
            self.assertEqual(rejected.exception.code, 400)
            rejected.exception.close()
            self.assertFalse(destination.exists())

            valid = Request(
                base_url + "/event-setup",
                data=json.dumps(event_setup_payload()).encode("utf-8"),
                headers={
                    **headers,
                    "Content-Type": "application/json",
                    "X-Operator-CSRF": csrf_match.group(1),
                },
                method="POST",
            )
            with urlopen(valid, timeout=2) as response:
                result = json.loads(response.read().decode("utf-8"))

            self.assertTrue(result["ok"])
            self.assertTrue(result["restart_required"])
            self.assertEqual(result["event_key"], "start-warsaw-autumn-2027")
            self.assertTrue(destination.is_file())
            self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o600)
            persisted = json.loads(destination.read_text(encoding="utf-8"))
            self.assertEqual(
                persisted["sources"][0]["adapter_id"], "luma-csv-v2",
            )
            self.assertEqual(
                persisted["sources"][0]["mapping_path"],
                "mappings/luma-guests-v2.json",
            )
            thread.join(timeout=2)
            self.assertFalse(thread.is_alive())

    def test_cli_without_event_config_bootstraps_setup_without_runtime(self) -> None:
        from community_os.__main__ import main

        with tempfile.TemporaryDirectory() as directory, patch.dict(
            os.environ,
            {
                "OPERATOR_PROXY_SECRET": "proxy-secret-long",
                "OPERATOR_ALLOWED_EMAILS": "colleague@example.org",
                "OPERATOR_PSEUDONYM_SECRET": "fixture-pseudonym-secret-long",
            },
            clear=False,
        ), patch(
            "community_os.release_operator.run_event_setup_operator",
        ) as setup_server, patch(
            "community_os.controlled_release.build_controlled_release_factory",
        ) as build_runtime:
            self.assertEqual(main([
                "release-operator", "--root", directory,
                "--allow-ephemeral-root",
            ]), 0)

        setup_server.assert_called_once()
        self.assertEqual(
            setup_server.call_args.kwargs["root"],
            str(Path(directory).resolve()),
        )
        build_runtime.assert_not_called()

    def test_cli_rejects_ephemeral_operator_storage_without_override(self) -> None:
        from community_os.__main__ import main

        with tempfile.TemporaryDirectory() as directory, patch.dict(
            os.environ,
            {
                "OPERATOR_PROXY_SECRET": "proxy-secret-long",
                "OPERATOR_ALLOWED_EMAILS": "colleague@example.org",
                "OPERATOR_PSEUDONYM_SECRET": "fixture-pseudonym-secret-long",
            },
            clear=False,
        ), patch(
            "community_os.release_operator.run_event_setup_operator",
        ) as setup_server:
            with self.assertRaisesRegex(ValueError, "ephemeral"):
                main(["release-operator", "--root", directory])

        setup_server.assert_not_called()

    def test_cli_reuses_generated_definition_on_next_start(self) -> None:
        from community_os.__main__ import main
        from community_os.event_setup import write_event_definition

        sentinel = object()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            definition = write_event_definition(
                root / "event-definition.json", event_setup_payload(),
            )
            with patch.dict(
                os.environ,
                {
                    "OPERATOR_PROXY_SECRET": "proxy-secret-long",
                    "OPERATOR_ALLOWED_EMAILS": "colleague@example.org",
                    "OPERATOR_PSEUDONYM_SECRET": "fixture-pseudonym-secret-long",
                },
                clear=False,
            ), patch(
                "community_os.controlled_release.build_controlled_release_factory",
                return_value=sentinel,
            ) as build_runtime, patch(
                "community_os.release_operator.run_release_operator",
            ) as run_operator, patch(
                "community_os.release_operator.run_event_setup_operator",
            ) as setup_server:
                self.assertEqual(main([
                    "release-operator", "--root", str(root),
                    "--allow-ephemeral-root",
                ]), 0)

            setup_server.assert_not_called()
            build_runtime.assert_called_once()
            self.assertEqual(
                run_operator.call_args.kwargs["event_definition"].sha256,
                definition.sha256,
            )

    def test_bounded_presentation_editor_preserves_server_owned_contract(self) -> None:
        from community_os.partner_report_presentation import (
            build_default_partner_report_presentation,
        )
        from community_os.partner_semantic_projection import (
            build_protected_partner_semantic_candidate_summary,
        )
        from community_os.release_operator import (
            apply_partner_presentation_edits,
            render_partner_presentation_editor,
        )
        from tests.test_partner_semantic_projection import semantic_aggregate

        summary = build_protected_partner_semantic_candidate_summary(
            semantic_aggregate(),
        )
        original = build_default_partner_report_presentation(summary)
        edits = alternative_presentation_edits()

        updated = apply_partner_presentation_edits(
            original, edits, semantic_summary=summary,
        )
        html = render_partner_presentation_editor(updated)

        self.assertEqual(updated.cover_title, edits["cover_title"])
        self.assertEqual(updated.cover_dek, edits["cover_dek"])
        self.assertEqual(
            updated.questions,
            original.questions,
        )
        self.assertEqual(
            tuple(question.evidence_refs for question in updated.questions),
            tuple(question.evidence_refs for question in original.questions),
        )
        self.assertEqual(
            tuple(question.target_sections for question in updated.questions),
            tuple(question.target_sections for question in original.questions),
        )
        self.assertIn('data-partner-presentation-form', html)
        self.assertIn('name="cover_title"', html)
        self.assertIn('name="cover_dek"', html)
        self.assertNotIn('name="overview"', html)
        self.assertNotIn('name="invest"', html)
        self.assertNotIn('name="hire"', html)
        self.assertNotIn('name="portfolio"', html)
        self.assertIn('<select', html)
        self.assertNotIn('<textarea', html)
        self.assertNotIn("evidence_refs", html)
        self.assertNotIn("target_sections", html)

    def test_presentation_editor_rejects_unknown_fields_and_authored_claims(self) -> None:
        from community_os.partner_report_presentation import (
            build_default_partner_report_presentation,
        )
        from community_os.partner_semantic_projection import (
            build_protected_partner_semantic_candidate_summary,
        )
        from community_os.release_operator import apply_partner_presentation_edits
        from tests.test_partner_semantic_projection import semantic_aggregate

        summary = build_protected_partner_semantic_candidate_summary(
            semantic_aggregate(),
        )
        presentation = build_default_partner_report_presentation(summary)
        safe = {
            "cover_title": presentation.cover_title,
            "cover_dek": presentation.cover_dek,
        }
        attacks = (
            {**safe, "evidence_refs": ["metric:attacker"]},
            {**safe, "overview": "Exactly 48 applicants qualify."},
            {**safe, "questions": []},
        )
        for payload in attacks:
            with self.subTest(payload=payload):
                with self.assertRaises((PermissionError, ValueError)):
                    apply_partner_presentation_edits(
                        presentation, payload, semantic_summary=summary,
                    )

    def test_ready_semantic_aggregate_exposes_editor_and_saves_copy_privately(self) -> None:
        from community_os.partner_report_presentation import (
            load_partner_report_presentation,
        )
        from community_os.partner_semantic_projection import (
            load_protected_partner_semantic_candidate_summary,
        )
        from community_os.release_operator import (
            persist_partner_presentation_edits,
            render_release_operator_page,
        )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = seed_ready_semantic_aggregate(root)
            html = render_release_operator_page(state)
            self.assertIn("data-partner-presentation-form", html)
            self.assertIn("'/partner-presentation'", html)
            self.assertNotIn("overview:data.get('overview')", html)
            self.assertNotIn('name="overview"', html)

            edits = alternative_presentation_edits()
            with patch.object(state, "_invalidate_release") as invalidate:
                result = persist_partner_presentation_edits(state, edits)

            invalidate.assert_called_once_with(
                ("report", "publish", "analytics"),
                reason_code="partner_presentation_changed",
            )
            self.assertEqual(result["ok"], True)
            destination = (
                root / "protected" / "release"
                / "partner-report-presentation.json"
            )
            self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o600)
            summary = load_protected_partner_semantic_candidate_summary(
                root / "protected" / "rich-semantic-internal.aggregate.json",
            )
            saved = load_partner_report_presentation(
                destination, semantic_summary=summary,
            )
            self.assertEqual(saved.cover_title, edits["cover_title"])

    def test_operator_resets_stale_aggregate_copy_then_accepts_current_choices(self) -> None:
        from community_os.partner_report_presentation import (
            build_default_partner_report_presentation,
            load_partner_report_presentation,
            write_partner_report_presentation,
        )
        from community_os.partner_semantic_projection import (
            build_protected_partner_semantic_candidate_summary,
        )
        from community_os.release_operator import persist_partner_presentation_edits
        from tests.test_partner_semantic_projection import semantic_aggregate

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            protected = root / "protected"
            release = protected / "release"
            release.mkdir(parents=True)
            current_aggregate = semantic_aggregate()
            aggregate_path = protected / "rich-semantic-internal.aggregate.json"
            aggregate_path.write_text(
                json.dumps(current_aggregate) + "\n", encoding="utf-8",
            )
            aggregate_path.chmod(0o600)
            current_summary = build_protected_partner_semantic_candidate_summary(
                current_aggregate,
            )

            stale_aggregate = semantic_aggregate()
            stale_aggregate["metrics"]["standout_builder"] = 6
            stale_summary = build_protected_partner_semantic_candidate_summary(
                stale_aggregate,
            )
            destination = release / "partner-report-presentation.json"
            write_partner_report_presentation(
                destination,
                build_default_partner_report_presentation(stale_summary),
                semantic_summary=stale_summary,
            )

            class State:
                event_key = current_summary.event_key
                event_definition_sha256 = current_summary.event_definition_sha256

                def __init__(self) -> None:
                    self.root = root
                    self.invalidations: list[tuple[object, object]] = []

                def _rich_semantic_status(self) -> dict[str, object]:
                    return {"aggregate_summary": {"state": "reviewed"}}

                def _invalidate_release(self, stages, *, reason_code) -> None:
                    self.invalidations.append((stages, reason_code))

            state = State()
            edits = alternative_presentation_edits()
            result = persist_partner_presentation_edits(state, edits)

            self.assertTrue(result["ok"])
            saved = load_partner_report_presentation(
                destination, semantic_summary=current_summary,
            )
            self.assertEqual(saved.aggregate_sha256, current_summary.aggregate_sha256)
            self.assertEqual(saved.cover_title, edits["cover_title"])
            self.assertEqual(
                state.invalidations,
                [(("report", "publish", "analytics"), "partner_presentation_changed")],
            )

    def test_direct_editor_post_cannot_bind_copy_to_a_foreign_or_unready_aggregate(self) -> None:
        from community_os.release_operator import (
            ReleaseOperatorState,
            persist_partner_presentation_edits,
        )
        from tests.test_partner_semantic_projection import semantic_aggregate
        from tests.test_release_operator import _event_definition

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = ReleaseOperatorState(
                root, operator_code="privacy_lead",
                event_definition=_event_definition(),
            )
            aggregate_path = (
                root / "protected" / "rich-semantic-internal.aggregate.json"
            )
            aggregate_path.write_text(
                json.dumps(semantic_aggregate()) + "\n", encoding="utf-8",
            )
            aggregate_path.chmod(0o600)
            edits = alternative_presentation_edits()

            with self.assertRaisesRegex(
                PermissionError, "current reviewed aggregate",
            ):
                persist_partner_presentation_edits(state, edits)

            self.assertFalse(
                (
                    root / "protected" / "release"
                    / "partner-report-presentation.json"
                ).exists(),
            )


if __name__ == "__main__":
    unittest.main()
