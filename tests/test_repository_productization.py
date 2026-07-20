from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]


class RepositoryProductizationTests(unittest.TestCase):
    def test_public_snapshot_excludes_private_history_and_person_specific_roles(self) -> None:
        private_history = (
            ROOT / "docs" / "handoffs",
            ROOT / "docs" / "plans",
            ROOT / "docs" / "superpowers",
            ROOT / "docs" / "codex-handoff-prompt.md",
            ROOT / "docs" / "brand-assets.md",
            ROOT / "docs" / "REPOSITORY_INVENTORY.md",
            ROOT / "docs" / "crm-assessment.md",
            ROOT / "docs" / "legal-gap-analysis-hackathon-rules.md",
            ROOT / "docs" / "voice-agent-notes.md",
        )
        self.assertFalse(
            any(path.exists() for path in private_history),
            "historical operator documents must stay in the ignored private archive",
        )

        public_roots = (
            ROOT / "community_os",
            ROOT / "deploy",
            ROOT / "docs",
            ROOT / "README.md",
            ROOT / "DESIGN.md",
            ROOT / "PRODUCT.md",
        )
        public_text = "\n".join(
            path.read_text(encoding="utf-8")
            for root in public_roots
            for path in (
                root.rglob("*") if root.is_dir() else (root,)
            )
            if path.is_file()
            and (
                path.suffix in {".md", ".py", ".json"}
                or path.name in {"Dockerfile", "_headers"}
            )
        )
        for forbidden in (
            "/Users/" + "jen" + "yafutrin",
            "/private/tmp/start-community-os",
            "start" + "_privacy_lead",
            "jen" + "ya",
        ):
            self.assertNotIn(forbidden, public_text)

    def test_git_tracks_no_private_instruction_secret_or_generated_artifact(self) -> None:
        result = subprocess.run(
            ["git", "ls-files", "-z"], cwd=ROOT, check=True,
            capture_output=True,
        )
        tracked = tuple(
            item.decode("utf-8")
            for item in result.stdout.split(b"\0")
            if item
        )
        forbidden_exact = {
            ".agent/HANDOFF.md", "AGENTS.md", "CONTINUITY.md",
            "PROJECT_LOG.md", "UI_TRINITY.md",
        }
        self.assertFalse(forbidden_exact.intersection(tracked))
        self.assertFalse(any(
            path.endswith((".pdf", ".sqlite", ".db"))
            or "/protected/" in f"/{path}/"
            or "/private/" in f"/{path}/"
            or (Path(path).name.startswith(".env") and path != ".env.example")
            for path in tracked
        ))

    def test_tracked_snapshot_contains_no_literal_provider_credentials(self) -> None:
        patterns = {
            "github": re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),
            "openai": re.compile(r"sk-[A-Za-z0-9_-]{20,}"),
            "posthog": re.compile(r"ph[cx]_[A-Za-z0-9_-]{20,}"),
            "slack": re.compile(r"xox[baprs]-[A-Za-z0-9-]{20,}"),
            "aws": re.compile(r"AKIA[0-9A-Z]{16}"),
        }
        result = subprocess.run(
            ["git", "ls-files", "-z"], cwd=ROOT, check=True,
            capture_output=True,
        )
        for raw_path in result.stdout.split(b"\0"):
            if not raw_path:
                continue
            relative = raw_path.decode("utf-8")
            path = ROOT / relative
            try:
                body = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            for provider, pattern in patterns.items():
                self.assertIsNone(
                    pattern.search(body),
                    f"{relative} contains a literal {provider} credential shape",
                )

    def test_blank_provider_template_and_product_docs_are_present(self) -> None:
        template = (ROOT / ".env.example").read_text(encoding="utf-8")
        assignments = {
            line.split("=", 1)[0]: line.split("=", 1)[1]
            for line in template.splitlines()
            if line and not line.startswith("#") and "=" in line
        }
        self.assertEqual(set(assignments), {
            "COMMUNITY_OS_CHROMIUM_EXECUTABLE",
            "CORESIGNAL_API_TOKEN",
            "GITHUB_TOKEN",
            "OPENAI_API_KEY",
            "OPERATOR_ALLOWED_EMAILS",
            "OPERATOR_PROXY_SECRET",
            "OPERATOR_PSEUDONYM_SECRET",
            "OPERATOR_RELEASE_OWNER_EMAILS",
            "POSTHOG_PERSONAL_API_KEY",
            "POSTHOG_PROJECT_ID",
            "POSTHOG_PUBLIC_PROJECT_KEY",
            "VERCEL_PROJECT_ID",
            "VERCEL_TEAM_SLUG",
            "VERCEL_TOKEN",
        })
        self.assertTrue(all(value == "" for value in assignments.values()))
        for relative, headings in {
            "docs/ARCHITECTURE.md": (
                "Privacy boundaries", "Deployment separation",
                "Commercial extension points",
            ),
            "docs/OPERATOR_GUIDE.md": (
                "Synthetic demo", "Provider gates", "Cleanup and retention",
                "Troubleshooting", "Analytics review loop",
                "Protected operator state is durable evidence",
            ),
            "docs/DEPLOYMENT.md": (
                "Private and public boundaries", "Host matrix",
                "PostHog setup", "Current recommendation",
            ),
        }.items():
            body = (ROOT / relative).read_text(encoding="utf-8")
            for heading in headings:
                self.assertIn(heading, body)

    def test_clean_clone_acceptance_unsets_every_provider_and_deployment_secret(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        acceptance = readme.split(
            "Clean-clone acceptance after a verified commit:", 1,
        )[1].split(
            "The acceptance run must succeed", 1,
        )[0]

        for variable in (
            "CORESIGNAL_API_TOKEN",
            "GITHUB_TOKEN",
            "OPENAI_API_KEY",
            "POSTHOG_PERSONAL_API_KEY",
            "POSTHOG_PROJECT_ID",
            "POSTHOG_PUBLIC_PROJECT_KEY",
            "VERCEL_PROJECT_ID",
            "VERCEL_TEAM_SLUG",
            "VERCEL_TOKEN",
        ):
            self.assertIn(f"-u {variable}", acceptance)

    def test_design_contract_matches_the_interactive_aggregate_release(self) -> None:
        design = (ROOT / "DESIGN.md").read_text(encoding="utf-8")

        for expected in (
            "All, Accepted, and Attended",
            "deliberately avoids editorial lens switches",
            "One reviewed three-signal exact partition",
            "separate post-publication transform",
            "aggregate-only",
        ):
            self.assertIn(expected, design)
        self.assertNotIn("two-set overlap", design)
        self.assertNotIn("The initial VC and company briefs intentionally omit cohort filtering", design)
        self.assertNotIn("This release has no analytics", design)

    def test_gitignore_preserves_blank_template_and_blocks_private_outputs(self) -> None:
        ignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
        for rule in (
            ".agent/HANDOFF.md", ".env.*", "!.env.example", "/protected/",
            "**/protected/", "*.pdf", "public-staging/", "deployment-staging/",
            "/videos/",
        ):
            self.assertIn(rule, ignore)

    def test_build_week_submission_evidence_and_live_demo_are_publicly_documented(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        submission = (ROOT / "docs" / "BUILD_WEEK_SUBMISSION.md").read_text(
            encoding="utf-8",
        )
        deployment = (ROOT / "docs" / "DEPLOYMENT.md").read_text(
            encoding="utf-8",
        )

        for body in (readme, submission):
            self.assertIn(
                "https://start-community-os.vercel.app/openai-hackathon-2026/",
                body,
            )
            self.assertIn("Work and Productivity", body)
            self.assertIn("GPT-5.6-sol", body)
            self.assertIn("Codex", body)
        for expected in (
            "019f7482-e669-7963-aabd-9066b0f26989",
            "What START Community OS does",
            "What changed during Build Week",
            "Demo video outline",
        ):
            self.assertIn(expected, submission)
        self.assertIn("/openai-hackathon-2026/", deployment)
        self.assertIn("event-specific route", deployment)

    def test_operator_deployment_contract_matches_the_static_bundle_workflow(self) -> None:
        contract = (ROOT / "deploy/operator/README.md").read_text(
            encoding="utf-8",
        )
        for expected in (
            "`index.html`",
            '"Approve and stage partner share"',
            "exact four-file deployment bundle",
            '"Prepare analytics bundle"',
            "`vercel.json`",
            "host-independent",
        ):
            self.assertIn(expected, contract)
        self.assertNotIn("single pre-share action", contract)

    def test_static_header_template_cannot_be_mistaken_for_a_safe_policy(self) -> None:
        headers = (ROOT / "deploy/public/_headers").read_text(encoding="utf-8")
        deployment_note = (ROOT / "deploy/public/README.md").read_text(
            encoding="utf-8",
        )

        self.assertNotIn("unsafe-inline", headers)
        self.assertIn("not a deployable header policy", headers.casefold())
        self.assertIn("must not be copied", deployment_note.casefold())
        self.assertIn("hash-pinned", deployment_note.casefold())

    def test_host_guidance_separates_sites_reach_analytics_from_posthog(self) -> None:
        deployment = (ROOT / "docs/DEPLOYMENT.md").read_text(encoding="utf-8")
        architecture = (ROOT / "docs/ARCHITECTURE.md").read_text(encoding="utf-8")

        for body in (deployment, architecture):
            self.assertIn("unique visitors and page views", body)
            self.assertIn("custom response headers", body)
            self.assertIn("PostHog", body)
        self.assertNotIn("analytics behavior; Vercel", architecture)
        self.assertNotIn("Current analytics adapter | Unverified", deployment)

    def test_operator_guide_uses_evidence_unknowns_not_linkage_as_talent_signal(self) -> None:
        guide = (ROOT / "docs/OPERATOR_GUIDE.md").read_text(encoding="utf-8")

        self.assertIn("missing or unresolved reviewed evidence", guide)
        self.assertNotIn("carries linkage gaps into unknowns", guide)

    def test_public_quickstart_states_the_supported_event_boundary(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("git clone <repository-url> start-community-os", readme)
        self.assertNotIn("<private-repository-url>", readme)
        for expected in (
            "Hackathons using the registered Luma and Devpost export profiles",
            "does not train a model for each event",
            "new registered adapter and synthetic fixture",
        ):
            self.assertIn(expected, readme)

    def test_local_environment_instructions_match_actual_cli_loading(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        guide = (ROOT / "docs/OPERATOR_GUIDE.md").read_text(encoding="utf-8")

        for body in (readme, guide):
            self.assertIn(".env.local", body)
            self.assertIn("does not auto-load", body)
            self.assertIn("set -a", body)
            self.assertIn(". ./.env.local", body)
            self.assertNotIn("cp .env.example .env\n", body)

    def test_operator_docs_name_the_strict_registered_event_contract(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        guide = (ROOT / "docs/OPERATOR_GUIDE.md").read_text(encoding="utf-8")

        for body in (readme, guide):
            self.assertIn("event-release-v1", body)
            self.assertIn("config/events/openai-hackathon-2026.json", body)
            self.assertIn("registered START source profile", body)
        self.assertNotIn(
            "Alternatively, copy `config/events/example.synthetic.json`",
            guide,
        )

    def test_current_synthetic_contracts_render_pdf_path_and_use_exact_cross_sections(self) -> None:
        from community_os.__main__ import main
        from community_os.report_contract import load_report_contract
        from community_os.talent_intelligence_contract import (
            load_talent_intelligence_contract,
        )

        intelligence_path = ROOT / "config/contracts/talent-intelligence-v1.synthetic.json"
        event_path = ROOT / "config/contracts/talent-report-v3.synthetic.json"
        intelligence = load_talent_intelligence_contract(intelligence_path)
        event = load_report_contract(event_path)

        self.assertEqual(intelligence.metadata.generated_at, event.metadata.generated_at)
        cross_dimension = next(
            dimension
            for dimension in intelligence.dimensions
            if dimension.key == "cross_dimension_signals"
        )
        self.assertEqual(cross_dimension.known_count.value, 286)
        exact_rows = {
            item.key: item
            for item in intelligence.intersections
            if item.key.endswith("_exact")
        }
        self.assertEqual(set(exact_rows), {
            "founder_technical_shipped_product_exact",
            "founder_technical_exact",
            "founder_shipped_product_exact",
            "founder_only_exact",
            "technical_shipped_product_exact",
            "technical_only_exact",
            "shipped_product_only_exact",
            "neither_recorded_exact",
        })
        self.assertEqual(
            sum(int(item.count.value or 0) for item in exact_rows.values()),
            286,
        )
        serialized = json.dumps(json.loads(intelligence_path.read_text(encoding="utf-8")))
        self.assertNotIn("hackathon_submission", serialized)
        self.assertNotIn("submitted_team", serialized)

        def export_pdf(_html: Path, pdf: Path, **_kwargs: object) -> Path:
            destination = Path(pdf)
            destination.write_bytes(b"%PDF-synthetic\n%%EOF")
            return destination

        with tempfile.TemporaryDirectory() as directory, patch(
            "community_os.pdf_export.export_pdf", side_effect=export_pdf,
        ):
            root = Path(directory)
            html = root / "partner.html"
            pdf = root / "partner.pdf"
            self.assertEqual(main([
                "render-partner",
                "--contract", str(intelligence_path),
                "--event-contract", str(event_path),
                "--html", str(html),
                "--pdf", str(pdf),
            ]), 0)
            self.assertTrue(html.is_file())
            self.assertEqual(pdf.read_bytes(), b"%PDF-synthetic\n%%EOF")
            public_text = html.read_text(encoding="utf-8").casefold()
            self.assertNotIn("linked to a submitted team", public_text)
            self.assertNotIn("submitted-team", public_text)

    def test_canonical_docs_explain_cross_sections_and_retention_schedule(self) -> None:
        architecture = (ROOT / "docs/ARCHITECTURE.md").read_text(encoding="utf-8")
        guide = (ROOT / "docs/OPERATOR_GUIDE.md").read_text(encoding="utf-8")

        for expected in (
            "Founder or co-founder evidence",
            "Technical function",
            "Shipped-product evidence",
            "eight mutually exclusive rows",
            "sum to the full denominator",
            "student-stage overlay is separate and non-additive",
            "signal not recorded",
        ):
            self.assertIn(expected.casefold(), architecture.casefold())

        for expected in (
            "run `privacy-cleanup` daily",
            "maximum 24 hours",
            "1 to 30 days",
            "1 to 14 days",
            "30 days",
            "12-month",
            "36-month",
            "not covered by `privacy-cleanup`",
        ):
            self.assertIn(expected.casefold(), guide.casefold())
        self.assertIn(
            "--event-config /absolute/private/operator-root/event-definition.json",
            guide,
        )

    def test_operator_guide_requires_machine_verified_posthog_privacy_receipt(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        guide = (ROOT / "docs/OPERATOR_GUIDE.md").read_text(encoding="utf-8")

        for expected in (
            "three-signal exact UpSet-style partition",
            "machine-verifies and binds the PostHog privacy receipt",
            "config/contracts/talent-intelligence-v1.synthetic.json",
            "config/contracts/talent-report-v3.synthetic.json",
        ):
            self.assertIn(expected, readme)
        self.assertNotIn("release owner confirms project-level IP capture", readme)

        for expected in (
            "POSTHOG_PERSONAL_API_KEY",
            "Project: Read",
            "Organization-wide access is not required",
            "POSTHOG_PROJECT_ID",
            "anonymize_ips=true",
            "public-key binding",
            "protected hash receipt",
            "Preparation succeeds only after live verification",
        ):
            self.assertIn(expected, guide)
        self.assertNotIn("Organization:Read", guide)
        self.assertNotIn(
            'before "Prepare analytics bundle" becomes available',
            guide,
        )
        self.assertNotIn("confirm the IP setting", guide.casefold())
        self.assertNotIn("cannot inspect the remote PostHog setting", guide)


if __name__ == "__main__":
    unittest.main()
