"""Practical end-to-end behavior for privacy, cleanup, rendering, and PDF."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from community_os.db import initialize


class ProductPipelineTests(unittest.TestCase):
    def test_distribution_uses_complementary_suppression(self) -> None:
        from community_os.privacy import safe_distribution

        result = safe_distribution(
            {"student": set(range(12)), "founder": {20, 21}, "other": set(range(30, 41))},
            eligible_count=25,
            k=5,
        )
        statuses = {cell.key: cell.status for cell in result.cells}
        self.assertEqual(statuses["founder"], "primary")
        self.assertEqual(sum(status != "published" for status in statuses.values()), 2)
        self.assertFalse(result.total_published)

    def test_cross_tab_with_small_cell_is_withheld_conservatively(self) -> None:
        from community_os.privacy import safe_crosstab

        result = safe_crosstab({("student", "checked_in"): {1, 2}}, eligible_count=20)
        self.assertTrue(result.withheld)
        self.assertEqual(result.reason, "sub_threshold_cross_tab")

    def test_cleanup_erases_expired_payloads_and_ghost_removes_pii(self) -> None:
        from community_os.retention import cleanup_expired, ghost_person

        connection = initialize(":memory:")
        event_id = connection.execute(
            "INSERT INTO event(event_key,name,starts_at,event_type) VALUES('e','E','2020-01-01T00:00:00Z','hackathon')"
        ).lastrowid
        source_file_id = connection.execute(
            "INSERT INTO source_file(event_id,source_type,file_sha256,mapping_version,observed_at) VALUES(?,?,?,?,?)",
            (event_id, "luma_guests", "hash", "v1", "2020-01-01T00:00:00Z"),
        ).lastrowid
        source_record_id = connection.execute(
            "INSERT INTO source_record(source_file_id,external_record_id,mapping_version,observed_at,raw_payload_json) VALUES(?,?,?,?,?)",
            (source_file_id, "r1", "v1", "2020-01-01T00:00:00Z", '{"email":"alice@example.com"}'),
        ).lastrowid
        person_id = connection.execute("INSERT INTO person DEFAULT VALUES").lastrowid
        identity_id = connection.execute(
            """INSERT INTO person_identity(person_id,source_record_id,identity_type,display_value,
               normalized_value,verified,applicant_provided,observed_at) VALUES(?,?,?,?,?,1,1,?)""",
            (person_id, source_record_id, "email", "alice@example.com", "alice@example.com", "2020-01-01T00:00:00Z"),
        ).lastrowid
        connection.execute(
            "INSERT INTO enrichment_snapshot(person_id,source_record_id,source_type,payload_json,fetched_at,expires_at) VALUES(?,?,?,?,?,?)",
            (person_id, source_record_id, "github", '{"repos":1}', "2020-01-01T00:00:00Z", "2021-01-01T00:00:00Z"),
        )
        report = cleanup_expired(connection, now=datetime(2026, 7, 11, tzinfo=UTC), apply=True)
        self.assertEqual(report.enrichment_payloads_erased, 1)
        self.assertEqual(report.raw_source_payloads_erased, 1)
        ghost_person(connection, person_id, secret="synthetic-secret", key_version="v1", now="2026-07-11T00:00:00Z")
        self.assertEqual(connection.execute("SELECT state FROM person WHERE id=?", (person_id,)).fetchone()[0], "ghost")
        self.assertIsNone(connection.execute("SELECT 1 FROM person_identity WHERE id=?", (identity_id,)).fetchone())
        self.assertEqual(connection.execute("SELECT COUNT(*) FROM hashed_identity WHERE person_id=?", (person_id,)).fetchone()[0], 1)
        from community_os.ingest.base import MappedRecord
        from community_os.normalize import GhostIdentityMatch, normalize_record

        return_source_file_id = connection.execute(
            "INSERT INTO source_file(event_id,source_type,file_sha256,mapping_version,observed_at) VALUES(?,?,?,?,?)",
            (event_id, "luma_guests", "return-hash", "v1", "2026-07-12T00:00:00Z"),
        ).lastrowid
        return_source_record_id = connection.execute(
            "INSERT INTO source_record(source_file_id,external_record_id,mapping_version,observed_at) VALUES(?,?,?,?)",
            (return_source_file_id, "return-r1", "v1", "2026-07-12T00:00:00Z"),
        ).lastrowid
        returning = MappedRecord(
            external_record_id="return-r1", applicant_identity="alice@example.com",
            mapping_version="v1", authority=None,
            authoritative_fields=frozenset(), identity_only_fields=frozenset({"email"}),
            values={"email": "alice@example.com"}, raw={"email": "alice@example.com"},
        )
        with self.assertRaises(GhostIdentityMatch):
            normalize_record(
                connection, event_id=event_id, source_type="luma_guests",
                source_record_id=return_source_record_id, record=returning,
                ghost_secrets={"v1": "synthetic-secret"},
            )
        connection.close()

    def test_renderer_is_self_contained_and_analytics_config_is_private(self) -> None:
        from community_os.report import FunnelStage, ReportData, load_report_profile
        from community_os.render import render_report

        repo = Path(__file__).resolve().parents[1]
        data = load_report_profile(
            repo / "config/demo/talent-data-room.synthetic.json",
            event_key="synthetic-event", event_name="Synthetic Event",
            event_date="11 July 2026", partner_key="partner-preview",
            generated_at="11 July 2026",
        )
        html = render_report(data)
        for expected in (
            "Talent Data Room", "Illustrative synthetic cohort", "Executive readout",
            "Participation funnel", "Cohort composition", "Builder evidence",
            "Build domains", "Data confidence", "View as table",
            "data-chart-mode", "window.print()", "IntersectionObserver",
            "aria-label=\"Report sections\"", "data-section-key",
            "data-chart-view=\"cohort\"", "role=\"group\"",
            "unit-dot advanced", "unit-dot stopped", "Longitudinal evidence",
            "data-funnel-stage=\"0\"", "data-funnel-detail", "aria-controls=\"funnel-detail\"",
            "data-trend-event=\"0\"", "data-trend-detail", "Submission rate",
            "data-evidence-target", "data-reading-progress",
            "data-evidence-target=\"composition\"", "<span class=\"dot-field\"",
            "disabled><span class=\"funnel-value\"",
            "<details class=\"methodology\" open",
        ):
            self.assertIn(expected, html)
        self.assertIn("@media print", html)
        self.assertIn(".screen-only,.chart-controls,.interactive-only{display:none!important}", html)
        self.assertNotIn("http://", html)
        self.assertNotIn("https://", html)
        self.assertNotIn("partner-preview@example", html)
        small = ReportData(
            event_key="small", event_name="Small", event_date="11 July 2026",
            partner_key="partner", generated_at="11 July 2026", eligible_people=1,
            stages=(FunnelStage("Applied", None, "withheld"),), source_notes=(),
        )
        small_html = render_report(small)
        self.assertIn("<strong>Eligible records</strong><span>Withheld</span>", small_html)
        self.assertNotIn("<strong>Eligible records</strong><span>1</span>", small_html)
        self.assertIn("Awaiting classified data", small_html)
        self.assertIn("Cohort composition awaits validated classification", small_html)
        self.assertNotIn("Founders and startup operators anchor the cohort", small_html)
        privacy = ReportData(
            event_key="private", event_name="Private", event_date="2026-07-11",
            partner_key="partner", generated_at="2026-07-11", eligible_people=10,
            stages=(FunnelStage("Applied", 10), FunnelStage("Accepted", None, "withheld")),
            source_notes=(),
        )
        privacy_html = render_report(privacy)
        self.assertEqual(privacy_html.count('class="unit-dot withheld"'), 11)
        self.assertNotIn('class="unit-dot stopped"', privacy_html)
        enabled = render_report(data, posthog_key="phc_public", posthog_host="https://eu.i.posthog.com")
        for expected in (
            "persistence: 'memory'", "autocapture: false", "disable_session_recording: true",
            "https://eu.i.posthog.com", "data_room_opened", "report_section_viewed",
            "chart_mode_changed", "methodology_opened", "print_requested",
            "funnel_stage_opened", "trend_point_inspected",
            "evidence_link_clicked", "report_completed", "section_engaged",
        ):
            self.assertIn(expected, enabled)

    def test_renderer_safely_embeds_analytics_values_in_scripts(self) -> None:
        from community_os.report import FunnelStage, ReportData
        from community_os.render import render_report

        payload = "</script><script>alert(1)</script>"
        data = ReportData(
            event_key=payload, event_name="Safe", event_date="2026-07-11",
            partner_key=payload, generated_at="2026-07-11", eligible_people=10,
            stages=(FunnelStage("Applied", 10),), source_notes=(),
        )
        html = render_report(data, posthog_key=payload, posthog_host=payload)
        self.assertNotIn(payload, html)
        self.assertIn("\\u003c/script\\u003e", html)

    def test_synthetic_profile_is_explicit_and_rejects_unsafe_buckets(self) -> None:
        from community_os.report import load_report_profile

        repo = Path(__file__).resolve().parents[1]
        profile = load_report_profile(
            repo / "config/demo/talent-data-room.synthetic.json",
            event_key="e", event_name="E", event_date="2026-07-11",
            partner_key="p", generated_at="2026-07-11",
        )
        self.assertTrue(profile.synthetic)
        self.assertEqual(profile.eligible_people, 84)
        self.assertGreaterEqual(len(profile.executive_readout), 3)
        self.assertGreaterEqual(len(profile.cohort_mix), 4)
        with tempfile.TemporaryDirectory() as directory:
            invalid = Path(directory) / "unsafe.json"
            payload = json.loads(
                (repo / "config/demo/talent-data-room.synthetic.json").read_text(encoding="utf-8")
            )
            payload["cohort_mix"][0]["count"] = 2
            invalid.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "disclosure threshold"):
                load_report_profile(
                    invalid, event_key="e", event_name="E", event_date="2026-07-11",
                    partner_key="p", generated_at="2026-07-11",
                )
            payload = json.loads(
                (repo / "config/demo/talent-data-room.synthetic.json").read_text(encoding="utf-8")
            )
            payload["executive_readout"][0]["evidence"] = "Alice alice@example.test"
            invalid.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "personal or link-like content"):
                load_report_profile(
                    invalid, event_key="e", event_name="E", event_date="2026-07-11",
                    partner_key="p", generated_at="2026-07-11",
                )

    def test_report_profile_requires_explicit_demo_mode(self) -> None:
        from community_os.build import build_from_config

        repo = Path(__file__).resolve().parents[1]
        payload = json.loads(
            (repo / "config/events/example.synthetic.json").read_text(encoding="utf-8")
        )
        payload.pop("demo_mode")
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "event.json"
            config.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "explicit demo_mode"):
                build_from_config(config, output_root=Path(directory))

    def test_every_funnel_stage_excludes_withdrawn_people(self) -> None:
        from community_os.report import build_report_data

        connection = initialize(":memory:")
        event_id = connection.execute(
            "INSERT INTO event(event_key,name,starts_at,event_type) VALUES('privacy','Privacy','2026-07-11T09:00:00Z','hackathon')"
        ).lastrowid
        source_file_id = connection.execute(
            "INSERT INTO source_file(event_id,source_type,file_sha256,mapping_version,observed_at) VALUES(?,?,?,?,?)",
            (event_id, "luma_guests", "privacy-fixture", "v1", "2026-07-11T09:00:00Z"),
        ).lastrowid
        people: list[tuple[int, int, int]] = []
        for index in range(11):
            source_record_id = connection.execute(
                "INSERT INTO source_record(source_file_id,external_record_id,mapping_version,observed_at) VALUES(?,?,?,?)",
                (source_file_id, f"record-{index}", "v1", "2026-07-11T09:00:00Z"),
            ).lastrowid
            person_id = connection.execute("INSERT INTO person DEFAULT VALUES").lastrowid
            connection.execute(
                """INSERT INTO person_identity(person_id,source_record_id,identity_type,display_value,
                   normalized_value,verified,applicant_provided,observed_at) VALUES(?,?,?,?,?,1,1,?)""",
                (person_id, source_record_id, "email", f"person-{index}@example.test", f"person-{index}@example.test", "2026-07-11T09:00:00Z"),
            )
            connection.execute(
                "INSERT INTO application(person_id,event_id,source_record_id,status,applied_at) VALUES(?,?,?,'accepted',?)",
                (person_id, event_id, source_record_id, "2026-07-11T09:00:00Z"),
            )
            consent_id = connection.execute(
                """INSERT INTO consent_assertion(person_id,event_id,source_record_id,purpose,recipient_scope,
                   granted,source_text,source_version,observed_at,evidence_source)
                   VALUES(?,?,?,'aggregate_stats','event_partners',1,'yes','v1',?,'form')""",
                (person_id, event_id, source_record_id, "2026-07-11T09:00:00Z"),
            ).lastrowid
            people.append((person_id, source_record_id, consent_id))
        person_id, source_record_id, consent_id = people[-1]
        connection.execute(
            """INSERT INTO consent_assertion(person_id,event_id,source_record_id,purpose,recipient_scope,
               granted,source_text,source_version,observed_at,withdrawal_time,evidence_source,supersedes_assertion_id)
               VALUES(?,?,?,'aggregate_stats','event_partners',0,'withdrawn','v1',?,?,'manual',?)""",
            (person_id, event_id, source_record_id, "2026-07-12T09:00:00Z", "2026-07-12T09:00:00Z", consent_id),
        )
        report = build_report_data(connection, event_id=event_id, partner_key="partner")
        self.assertEqual(report.eligible_people, 10)
        self.assertEqual(report.stages[1].count, 10)
        review_person_id, review_source_record_id, _ = people[-2]
        connection.execute(
            """INSERT INTO identity_review(source_record_id,provisional_person_id,reason_code,evidence_json)
               VALUES(?,?,'WEAK_MATCH','{}')""",
            (review_source_record_id, review_person_id),
        )
        report_with_review = build_report_data(
            connection, event_id=event_id, partner_key="partner"
        )
        self.assertEqual(report_with_review.eligible_people, 9)
        connection.close()

    def test_build_config_runs_without_pdf_browser(self) -> None:
        from community_os.build import build_from_config

        repo = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory:
            result = build_from_config(
                repo / "config/events/example.synthetic.json",
                output_root=Path(directory),
                include_pdf=False,
            )
            self.assertTrue(result.html_path.exists())
            self.assertTrue(result.database_path.exists())
            generated = result.html_path.read_text(encoding="utf-8")
            self.assertIn("Talent Data Room", generated)
            self.assertIn("Illustrative synthetic cohort", generated)

    def test_draft_taxonomy_cannot_classify_real_people(self) -> None:
        from community_os.taxonomy import load_taxonomy, validate_classification

        repo = Path(__file__).resolve().parents[1]
        taxonomy = load_taxonomy(repo / "taxonomy/v1.draft.json")
        with self.assertRaisesRegex(ValueError, "not approved"):
            taxonomy.require_real_person_approval()
        validated = validate_classification(
            taxonomy,
            {
                "occupation": "student",
                "builder_signal": "claimed_unverified",
                "standout_fact": "Built a synthetic scheduling tool.",
                "confidence": 0.72,
            },
        )
        self.assertEqual(validated["occupation"], "student")
        with self.assertRaisesRegex(ValueError, "occupation"):
            validate_classification(taxonomy, {**validated, "occupation": "wizard"})


if __name__ == "__main__":
    unittest.main()
