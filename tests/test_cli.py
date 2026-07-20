"""Tests for the command-line entry point."""

import hashlib
import json
from pathlib import Path
import os
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from unittest.mock import ANY

from community_os.__main__ import build_parser


class CliHelpTests(unittest.TestCase):
    def test_help_lists_pipeline_commands(self) -> None:
        project_root = Path(__file__).resolve().parents[1]

        result = subprocess.run(
            [sys.executable, "-m", "community_os", "--help"],
            cwd=project_root,
            capture_output=True,
            check=False,
            text=True,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        for command in (
            "build", "cleanup", "privacy-cleanup", "coresignal-evaluation-cleanup",
            "github-semantic-evaluation-cleanup",
            "review-identities", "export-pdf", "render-partner", "release-operator",
        ):
            with self.subTest(command=command):
                self.assertIn(command, result.stdout)

    def test_build_accepts_config_and_pdf_flags(self) -> None:
        arguments = build_parser().parse_args([
            "build", "--config", "event.json", "--pdf",
        ])
        self.assertEqual(arguments.config, "event.json")
        self.assertTrue(arguments.pdf)

    def test_privacy_cleanup_requires_an_explicit_event_config(self) -> None:
        with self.assertRaises(SystemExit):
            build_parser().parse_args([
                "privacy-cleanup", "--root", "protected-operator",
            ])

    def test_export_pdf_requires_input_and_output_paths(self) -> None:
        arguments = build_parser().parse_args([
            "export-pdf", "report.html", "report.pdf",
        ])
        self.assertEqual(arguments.html, "report.html")
        self.assertEqual(arguments.pdf, "report.pdf")

    def test_render_partner_accepts_protected_semantic_summary_without_analytics_path(self) -> None:
        arguments = build_parser().parse_args([
            "render-partner",
            "--contract", "talent.json",
            "--event-contract", "event.json",
            "--semantic-aggregate", "private/rich-semantic.json",
            "--semantic-context", "private/semantic-context.json",
            "--semantic-candidate",
            "--html", "report.html",
        ])

        self.assertEqual(arguments.semantic_aggregate, "private/rich-semantic.json")
        self.assertTrue(arguments.semantic_candidate)
        self.assertFalse(hasattr(arguments, "posthog_token_env"))
        self.assertFalse(hasattr(arguments, "posthog_host"))

    def test_real_release_requires_explicit_candidate_or_approval_semantic_mode(self) -> None:
        from community_os.__main__ import _load_cli_semantic_summary

        with self.assertRaisesRegex(ValueError, "exactly one"):
            _load_cli_semantic_summary(
                aggregate_path="private/population-semantic.json",
                candidate_mode=False,
                approval_path=None,
                approval_secret=None,
            )
        arguments = build_parser().parse_args([
            "real-release",
            "--event-config", "event.json",
            "--event-approval", "private/event-approval.json",
            "--applications", "applications.csv",
            "--attendance", "attendance.csv",
            "--preferences", "preferences.xlsx",
            "--submissions", "submissions.xlsx",
            "--override", "override.json",
            "--output", "output",
            "--semantic-aggregate", "private/population-semantic.json",
            "--semantic-context", "private/semantic-context.json",
            "--semantic-approval", "private/semantic-approval.json",
            "--semantic-approval-secret-env", "SEMANTIC_APPROVAL_SECRET",
            "--semantic-qa", "private/semantic-release-qa.json",
            "--pdf",
        ])
        self.assertEqual(
            arguments.semantic_approval, "private/semantic-approval.json",
        )
        self.assertEqual(
            arguments.semantic_approval_secret_env, "SEMANTIC_APPROVAL_SECRET",
        )
        self.assertEqual(arguments.event_config, "event.json")
        self.assertEqual(arguments.event_approval, "private/event-approval.json")

    def test_real_release_binds_event_approval_and_exact_exclusion_mapping(self) -> None:
        from community_os.__main__ import main
        from community_os import real_report as _real_report
        from community_os.enrichment.state import pseudonymous_id

        self.assertTrue(callable(_real_report.load_event_definition))

        definition = SimpleNamespace(
            sources=tuple(
                SimpleNamespace(role=role, required=True)
                for role in ("applications", "attendance", "preferences", "submissions")
            ),
        )
        approval = SimpleNamespace(sha256="a" * 64)
        pseudonym_secret = b"cli-exclusion-pseudonym-secret"
        excluded_ref = pseudonymous_id(
            "app-excluded", secret=pseudonym_secret, key_version="v1",
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bindings = root / "exclusions.json"
            bindings.write_text(
                '{"app-excluded":"' + excluded_ref + '"}\n', encoding="utf-8",
            )
            with (
                patch.dict(os.environ, {
                    "REAL_RELEASE_PSEUDONYM_SECRET": pseudonym_secret.decode("utf-8"),
                }, clear=False),
                patch("community_os.event_definition.load_event_definition", return_value=definition),
                patch("community_os.event_approval.load_event_approval", return_value=approval) as load_approval,
                patch("community_os.real_report.sha256_file", return_value="c" * 64),
                patch("community_os.real_report.build_real_release", return_value={}) as build_release,
            ):
                self.assertEqual(main([
                    "real-release",
                    "--event-config", str(root / "event.json"),
                    "--event-approval", str(root / "event-approval.json"),
                    "--exclusion-bindings", str(bindings),
                    "--pseudonym-secret-env", "REAL_RELEASE_PSEUDONYM_SECRET",
                    "--applications", str(root / "applications.csv"),
                    "--attendance", str(root / "attendance.csv"),
                    "--preferences", str(root / "preferences.xlsx"),
                    "--submissions", str(root / "submissions.xlsx"),
                    "--override", str(root / "override.json"),
                    "--output", str(root / "output"),
                ]), 0)

        self.assertEqual(
            load_approval.call_args.kwargs["excluded_subject_refs"],
            (excluded_ref,),
        )
        build_kwargs = build_release.call_args.kwargs
        self.assertIs(build_kwargs["event_definition"], definition)
        self.assertIs(build_kwargs["event_approval"], approval)
        self.assertEqual(build_kwargs["excluded_application_ids"], frozenset({"app-excluded"}))
        self.assertEqual(
            build_kwargs["excluded_subject_refs_by_application_id"],
            {"app-excluded": excluded_ref},
        )
        self.assertEqual(build_kwargs["pseudonym_secret"], pseudonym_secret)
        expected_hash = hashlib.sha256(
            json.dumps([excluded_ref], separators=(",", ":")).encode("utf-8"),
        ).hexdigest()
        self.assertEqual(build_kwargs["exclusion_set_sha256"], expected_hash)

    def test_real_release_rejects_claimed_exclusion_pseudonym_not_derived_from_env_secret(self) -> None:
        from community_os.__main__ import main

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bindings = root / "exclusions.json"
            bindings.write_text(
                '{"app-excluded":"pid:v1:' + "f" * 64 + '"}\n',
                encoding="utf-8",
            )
            definition = SimpleNamespace(sources=())
            with (
                patch.dict(os.environ, {
                    "REAL_RELEASE_PSEUDONYM_SECRET": "correct-secret-is-long-enough",
                }, clear=False),
                patch("community_os.event_definition.load_event_definition", return_value=definition),
                patch("community_os.event_approval.load_event_approval"),
                patch("community_os.real_report.build_real_release") as build_release,
            ):
                with self.assertRaisesRegex(ValueError, "pseudonym"):
                    main([
                        "real-release", "--event-config", str(root / "event.json"),
                        "--event-approval", str(root / "approval.json"),
                        "--exclusion-bindings", str(bindings),
                        "--pseudonym-secret-env", "REAL_RELEASE_PSEUDONYM_SECRET",
                        "--applications", str(root / "applications.csv"),
                        "--attendance", str(root / "attendance.csv"),
                        "--preferences", str(root / "preferences.xlsx"),
                        "--submissions", str(root / "submissions.xlsx"),
                        "--override", str(root / "override.json"),
                        "--output", str(root / "output"),
                    ])
            build_release.assert_not_called()

    def test_render_partner_accepts_approved_semantics_only_with_secret_and_qa_flags(self) -> None:
        arguments = build_parser().parse_args([
            "render-partner",
            "--contract", "talent.json",
            "--event-contract", "event.json",
            "--semantic-aggregate", "private/rich-semantic.json",
            "--semantic-context", "private/semantic-context.json",
            "--semantic-approval", "private/semantic-approval.json",
            "--semantic-approval-secret-env", "SEMANTIC_APPROVAL_SECRET",
            "--semantic-qa", "private/semantic-release-qa.json",
            "--html", "report.html",
            "--pdf", "report.pdf",
        ])
        self.assertEqual(
            arguments.semantic_approval, "private/semantic-approval.json",
        )
        self.assertEqual(arguments.semantic_qa, "private/semantic-release-qa.json")

    def test_render_partner_candidate_uses_contract_timestamp_for_pdf(self) -> None:
        from community_os.__main__ import main
        from community_os.talent_intelligence_contract import (
            load_talent_intelligence_contract,
        )

        repository = Path(__file__).resolve().parents[1]
        contract_path = repository / "config/contracts/talent-intelligence-v1.synthetic.json"
        timestamps: list[str | None] = []

        def write_pdf(html, pdf, *, stable_timestamp=None):
            self.assertTrue(Path(html).is_file())
            destination = Path(pdf)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(b"%PDF-candidate\n%%EOF")
            timestamps.append(stable_timestamp)
            return destination

        with (
            tempfile.TemporaryDirectory() as directory,
            patch("community_os.partner_report.render_partner_talent_report", return_value="candidate-html"),
            patch("community_os.pdf_export.export_pdf", side_effect=write_pdf),
            patch(
                "community_os.talent_intelligence_contract.load_talent_intelligence_contract",
                wraps=load_talent_intelligence_contract,
            ) as load_contract,
        ):
            root = Path(directory)
            html = root / "candidate" / "report.html"
            pdf = root / "elsewhere" / "report.pdf"
            self.assertEqual(main([
                "render-partner",
                "--contract", str(contract_path),
                "--event-contract", str(repository / "config/contracts/talent-report-v3.synthetic.json"),
                "--html", str(html),
                "--pdf", str(pdf),
            ]), 0)

        self.assertEqual(timestamps, ["2026-07-12T20:00:00Z"])
        load_contract.assert_called_once_with(str(contract_path))

    def test_render_partner_candidate_pdf_failure_preserves_prior_outputs(self) -> None:
        from community_os.__main__ import main

        repository = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            html = root / "report.html"
            pdf = root / "report.pdf"
            html.write_text("old-html", encoding="utf-8")
            pdf.write_bytes(b"old-pdf")
            with (
                patch(
                    "community_os.partner_report.render_partner_talent_report",
                    return_value="new-html",
                ),
                patch(
                    "community_os.pdf_export.export_pdf",
                    side_effect=RuntimeError("simulated PDF failure"),
                ),
            ):
                with self.assertRaisesRegex(RuntimeError, "simulated PDF failure"):
                    main([
                        "render-partner",
                        "--contract", str(repository / "config/contracts/talent-intelligence-v1.synthetic.json"),
                        "--event-contract", str(repository / "config/contracts/talent-report-v3.synthetic.json"),
                        "--html", str(html), "--pdf", str(pdf),
                    ])
            self.assertEqual(html.read_text(encoding="utf-8"), "old-html")
            self.assertEqual(pdf.read_bytes(), b"old-pdf")

    def test_render_partner_approved_install_failure_restores_the_complete_prior_pair(self) -> None:
        from community_os.__main__ import main

        repository = Path(__file__).resolve().parents[1]
        approved_summary = SimpleNamespace(
            semantic_release_approval_sha256="a" * 64,
        )
        timestamps: list[str | None] = []

        def write_pdf(html, pdf, *, stable_timestamp=None):
            self.assertEqual(Path(html).read_text(encoding="utf-8"), "new-html")
            destination = Path(pdf)
            destination.write_bytes(b"new-pdf")
            timestamps.append(stable_timestamp)
            return destination

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = root / "approved-bundle"
            bundle.mkdir()
            html = bundle / "report.html"
            pdf = bundle / "report.pdf"
            html.write_text("old-html", encoding="utf-8")
            pdf.write_bytes(b"old-pdf")
            real_replace = os.replace

            def fail_install(source, destination):
                if Path(source).name == "release" and Path(destination) == bundle:
                    raise OSError("simulated directory-set install failure")
                return real_replace(source, destination)

            with (
                patch.dict(os.environ, {"SEMANTIC_APPROVAL_SECRET": "fixture-secret-long"}),
                patch("community_os.__main__._load_cli_semantic_summary", return_value=approved_summary),
                patch("community_os.__main__._load_semantic_context", return_value={}),
                patch("community_os.__main__._verify_approved_semantic_outputs"),
                patch("community_os.partner_report.render_partner_talent_report", return_value="new-html"),
                patch("community_os.pdf_export.export_pdf", side_effect=write_pdf),
                patch("community_os.publication.os.replace", side_effect=fail_install),
            ):
                with self.assertRaisesRegex(OSError, "simulated directory-set install failure"):
                    main([
                        "render-partner",
                        "--contract", str(repository / "config/contracts/talent-intelligence-v1.synthetic.json"),
                        "--event-contract", str(repository / "config/contracts/talent-report-v3.synthetic.json"),
                        "--semantic-aggregate", str(root / "semantic.json"),
                        "--semantic-context", str(root / "context.json"),
                        "--semantic-approval", str(root / "approval.json"),
                        "--semantic-approval-secret-env", "SEMANTIC_APPROVAL_SECRET",
                        "--semantic-qa", str(root / "qa.json"),
                        "--html", str(html),
                        "--pdf", str(pdf),
                    ])

            self.assertEqual(html.read_text(encoding="utf-8"), "old-html")
            self.assertEqual(pdf.read_bytes(), b"old-pdf")
            self.assertEqual(timestamps, ["2026-07-12T20:00:00Z"])

    def test_render_partner_approved_requires_one_dedicated_output_directory(self) -> None:
        from community_os.__main__ import main

        repository = Path(__file__).resolve().parents[1]
        approved_summary = SimpleNamespace(
            semantic_release_approval_sha256="a" * 64,
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with (
                patch.dict(os.environ, {"SEMANTIC_APPROVAL_SECRET": "fixture-secret-long"}),
                patch("community_os.__main__._load_cli_semantic_summary", return_value=approved_summary),
                patch("community_os.__main__._load_semantic_context", return_value={}),
                patch("community_os.__main__._verify_approved_semantic_outputs"),
                patch("community_os.partner_report.render_partner_talent_report", return_value="new-html"),
                patch("community_os.pdf_export.export_pdf", side_effect=lambda _html, pdf, **_kwargs: Path(pdf).write_bytes(b"new-pdf") or Path(pdf)),
            ):
                with self.assertRaisesRegex(ValueError, "same dedicated directory"):
                    main([
                        "render-partner",
                        "--contract", str(repository / "config/contracts/talent-intelligence-v1.synthetic.json"),
                        "--event-contract", str(repository / "config/contracts/talent-report-v3.synthetic.json"),
                        "--semantic-aggregate", str(root / "semantic.json"),
                        "--semantic-context", str(root / "context.json"),
                        "--semantic-approval", str(root / "approval.json"),
                        "--semantic-approval-secret-env", "SEMANTIC_APPROVAL_SECRET",
                        "--semantic-qa", str(root / "qa.json"),
                        "--html", str(root / "html" / "report.html"),
                        "--pdf", str(root / "pdf" / "report.pdf"),
                    ])

    def test_release_operator_injects_lazy_production_operations_without_startup_network(self) -> None:
        from community_os.__main__ import main

        sentinel = object()
        with (
            patch.dict(os.environ, {
                "OPERATOR_PROXY_SECRET": "proxy-secret-long",
                "OPERATOR_ALLOWED_EMAILS": "colleague@example.org",
                "OPERATOR_RELEASE_OWNER_EMAILS": "colleague@example.org",
                "OPERATOR_PSEUDONYM_SECRET": "fixture-pseudonym-secret-long",
            }, clear=False),
            patch("community_os.controlled_release.build_controlled_release_factory", return_value=sentinel) as build,
            patch("community_os.release_operator.run_release_operator") as run,
        ):
            self.assertEqual(main([
                "release-operator", "--root", "protected-operator",
                "--event-config", "config/events/openai-hackathon-2026.json",
                "--approval-bundle", "protected-approval.json",
                "--coresignal-career-evaluation-root", "protected/coresignal-career-evaluation",
                "--openai-input-cost-per-million-usd-micros", "5000000",
                "--openai-output-cost-per-million-usd-micros", "30000000",
            ]), 0)
        build.assert_called_once()
        runtime = build.call_args.args[0]
        self.assertEqual(
            runtime.coresignal_career_evaluation_root,
            Path("protected/coresignal-career-evaluation"),
        )
        self.assertEqual(runtime.openai_input_cost_per_million_usd_micros, 5_000_000)
        self.assertEqual(runtime.openai_output_cost_per_million_usd_micros, 30_000_000)
        self.assertIs(run.call_args.kwargs["stage_operation_factory"], sentinel)
        self.assertEqual(
            run.call_args.kwargs["pseudonym_secret"], b"fixture-pseudonym-secret-long",
        )
        self.assertEqual(
            run.call_args.kwargs["event_definition"].event_key,
            "openai-hackathon-2026",
        )
        self.assertEqual(
            run.call_args.kwargs["access_policy"].release_owner_emails,
            frozenset({"colleague@example.org"}),
        )

    def test_privacy_cleanup_runs_without_release_approval_bundle(self) -> None:
        from community_os.__main__ import main

        with patch(
            "community_os.controlled_release.run_scheduled_privacy_cleanup",
            return_value={"state": "complete"},
        ) as cleanup:
            self.assertEqual(main([
                "privacy-cleanup", "--root", "protected-operator",
                "--event-config", "config/events/openai-hackathon-2026.json",
            ]), 0)
        cleanup.assert_called_once()
        self.assertEqual(cleanup.call_args.args, ("protected-operator",))
        self.assertEqual(
            cleanup.call_args.kwargs["event_definition"].event_key,
            "openai-hackathon-2026",
        )

    def test_coresignal_evaluation_cleanup_has_a_dedicated_scheduled_command(self) -> None:
        from community_os.__main__ import main

        with tempfile.TemporaryDirectory() as directory:
            evaluation = Path(directory) / "protected" / "coresignal-career-evaluation"
            release = Path(directory) / "protected" / "release"
            now = ANY
            with patch(
                "community_os.coresignal_career_evaluation.CoresignalCareerEvaluationStore",
            ) as store_type:
                store_type.return_value.cleanup_expired.return_value = {
                    "cleanup_version": "coresignal-career-evaluation-cleanup-v1",
                    "deleted_count": 0,
                }
                self.assertEqual(main([
                    "coresignal-evaluation-cleanup", "--root", str(evaluation),
                    "--release-root", str(release),
                ]), 0)
            store_type.assert_called_once_with(
                str(evaluation), release_root=str(release), clock=ANY,
            )
            store_type.return_value.cleanup_expired.assert_called_once_with()

    def test_direct_partner_candidate_rejects_symlink_output_before_rendering(self) -> None:
        from community_os.__main__ import main

        repository = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            outside = root / "outside.html"
            outside.write_text("keep", encoding="utf-8")
            destination = root / "report.html"
            destination.symlink_to(outside)
            with patch(
                "community_os.partner_report.render_partner_talent_report",
            ) as renderer:
                with self.assertRaisesRegex(PermissionError, "symlink"):
                    main([
                        "render-partner",
                        "--contract", str(repository / "config/contracts/talent-intelligence-v1.synthetic.json"),
                        "--event-contract", str(repository / "config/contracts/talent-report-v3.synthetic.json"),
                        "--html", str(destination),
                    ])
            renderer.assert_not_called()
            self.assertEqual(outside.read_text(encoding="utf-8"), "keep")

    def test_export_pdf_rejects_symlink_source_and_destination_before_export(self) -> None:
        from community_os.__main__ import main

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            actual_html = root / "actual.html"
            actual_html.write_text("safe", encoding="utf-8")
            linked_html = root / "linked.html"
            linked_html.symlink_to(actual_html)
            with patch("community_os.pdf_export.export_pdf") as exporter:
                with self.assertRaisesRegex(PermissionError, "symlink"):
                    main(["export-pdf", str(linked_html), str(root / "report.pdf")])
            exporter.assert_not_called()

            actual_pdf = root / "actual.pdf"
            actual_pdf.write_bytes(b"keep")
            linked_pdf = root / "linked.pdf"
            linked_pdf.symlink_to(actual_pdf)
            with patch("community_os.pdf_export.export_pdf") as exporter:
                with self.assertRaisesRegex(PermissionError, "symlink"):
                    main(["export-pdf", str(actual_html), str(linked_pdf)])
            exporter.assert_not_called()
            self.assertEqual(actual_pdf.read_bytes(), b"keep")

    def test_github_semantic_cleanup_has_a_dedicated_scheduled_command(self) -> None:
        from community_os.__main__ import main

        with patch(
            "community_os.github_evaluation.cleanup_expired_github_evaluation",
            return_value={"deleted_count": 0},
        ) as cleanup:
            self.assertEqual(main([
                "github-semantic-evaluation-cleanup",
                "--root", "protected/github-semantic-evaluation",
                "--release-root", "protected/release",
            ]), 0)
        cleanup.assert_called_once_with(
            "protected/github-semantic-evaluation",
            release_root="protected/release", now=ANY,
        )


if __name__ == "__main__":
    unittest.main()
