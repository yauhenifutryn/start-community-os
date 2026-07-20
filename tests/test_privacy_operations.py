from __future__ import annotations

from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta
import unittest


NOW = datetime(2026, 7, 13, 12, tzinfo=UTC)


def rights(
    pseudonym: str,
    *,
    objection: str = "none",
    exclusion: str = "included",
    suppression: str = "not_requested",
    deletion: str = "not_requested",
    reconciled: bool = True,
    sent_at: datetime = NOW,
):
    from community_os.privacy_operations import RightsState

    return RightsState(
        pseudonym=pseudonym,
        notice_version="notice_v2",
        notice_sent_at=sent_at,
        objection_status=objection,
        exclusion_status=exclusion,
        suppression_status=suppression,
        deletion_status=deletion,
        reconciled=reconciled,
    )


def asset(
    asset_id: str,
    pseudonym: str,
    *,
    deadline: datetime | None = None,
    data_class=None,
):
    from community_os.privacy_operations import DataAsset, DataClass

    return DataAsset(
        asset_id=asset_id,
        version="inventory_v1",
        pseudonym=pseudonym,
        source="github",
        purpose="aggregate_talent_evidence",
        accountable_owner="privacy_lead",
        retention_deadline=deadline or NOW + timedelta(days=30),
        allowed_uses=frozenset({"aggregate"}),
        data_class=data_class or DataClass.RAW_ENRICHMENT,
        storage_scope="protected_enrichment",
        resource_ref=f"protected/{asset_id}.json",
    )


def approval(*, use: str = "aggregate", expires_at: datetime | None = None):
    from community_os.privacy_operations import UseApproval

    return UseApproval(
        source="github",
        purpose="aggregate_talent_evidence",
        use=use,
        owner_code="privacy_lead",
        actor_code="release_owner",
        approved_at=NOW - timedelta(hours=1),
        expires_at=expires_at or NOW + timedelta(days=1),
    )


class DataAssetTests(unittest.TestCase):
    def test_inventory_requires_complete_versioned_code_only_metadata(self) -> None:
        from community_os.privacy_operations import DataAsset, DataClass

        valid = asset("asset_001", "psn_001")
        self.assertEqual(valid.source_purpose_code, "github:aggregate_talent_evidence")
        self.assertIs(valid.data_class, DataClass.RAW_ENRICHMENT)

        values = dict(valid.__dict__)
        for field in (
            "asset_id", "version", "pseudonym", "source", "purpose",
            "accountable_owner", "storage_scope", "resource_ref",
        ):
            with self.subTest(field=field):
                with self.assertRaisesRegex(ValueError, field):
                    DataAsset(**{**values, field: "Ada Person"})
        with self.assertRaisesRegex(ValueError, "allowed_uses"):
            DataAsset(**{**values, "allowed_uses": frozenset()})
        with self.assertRaisesRegex(ValueError, "retention_deadline"):
            DataAsset(**{**values, "retention_deadline": datetime(2026, 8, 1)})
        with self.assertRaisesRegex(ValueError, "data_class"):
            DataAsset(**{**values, "data_class": "raw_enrichment"})

    def test_every_raw_or_cache_data_class_is_in_the_deletion_allowlist(self) -> None:
        from community_os.privacy_operations import DataClass, DELETABLE_DATA_CLASSES

        expected = {
            item for item in DataClass
            if item.value.startswith("raw_") or item.value.endswith("_cache")
        }
        self.assertEqual(expected, DELETABLE_DATA_CLASSES)

    def test_may_use_enforces_allowlist_owner_expiry_rights_and_exact_approval(self) -> None:
        from community_os.privacy_operations import ExclusionRegistry

        item = asset("asset_001", "psn_001")
        registry = ExclusionRegistry()
        registry.record(rights("psn_001"))
        accepted = approval()
        self.assertTrue(item.may_use(
            "aggregate", NOW, owner_code="privacy_lead",
            approval=accepted, registry=registry,
        ))
        self.assertFalse(item.may_use(
            "classify", NOW, owner_code="privacy_lead",
            approval=accepted, registry=registry,
        ))
        self.assertFalse(item.may_use(
            "aggregate", NOW, owner_code="other_owner",
            approval=accepted, registry=registry,
        ))
        self.assertFalse(asset(
            "asset_002", "psn_001", deadline=NOW
        ).may_use(
            "aggregate", NOW, owner_code="privacy_lead",
            approval=accepted, registry=registry,
        ))
        self.assertFalse(item.may_use(
            "aggregate", NOW, owner_code="privacy_lead",
            approval=approval(expires_at=NOW), registry=registry,
        ))
        self.assertFalse(item.may_use(
            "aggregate", NOW, owner_code="privacy_lead",
            approval=None, registry=registry,
        ))


class ExclusionRegistryTests(unittest.TestCase):
    def test_missing_and_unreconciled_rights_fail_closed_for_every_surface(self) -> None:
        from community_os.privacy_operations import ExclusionRegistry

        registry = ExclusionRegistry()
        registry.record(rights("psn_unreconciled", reconciled=False))
        members = {"psn_missing", "psn_unreconciled"}
        for surface in ("classification", "aggregate", "html", "pdf"):
            with self.subTest(surface=surface):
                self.assertEqual(registry.publishable_members(surface, members), frozenset())
        self.assertTrue(registry.is_excluded("psn_missing"))

    def test_rights_history_is_append_only_and_monotonic(self) -> None:
        from community_os.privacy_operations import ExclusionRegistry

        registry = ExclusionRegistry()
        registry.record(rights("psn_001"))
        excluded = rights(
            "psn_001", objection="received", exclusion="excluded",
            suppression="requested", deletion="requested",
            sent_at=NOW + timedelta(minutes=1),
        )
        registry.record(excluded)
        registry.record(rights(
            "psn_001", objection="resolved", exclusion="excluded",
            suppression="propagated", deletion="completed",
            sent_at=NOW + timedelta(minutes=2),
        ))
        self.assertEqual(len(registry.history("psn_001")), 3)
        self.assertTrue(registry.is_excluded("psn_001"))
        for reversal in (
            rights("psn_001", sent_at=NOW + timedelta(minutes=3)),
            rights(
                "psn_001", objection="resolved", exclusion="excluded",
                suppression="requested", deletion="completed",
                sent_at=NOW + timedelta(minutes=3),
            ),
        ):
            with self.subTest(reversal=reversal):
                with self.assertRaisesRegex(ValueError, "monotonic"):
                    registry.record(reversal)
        self.assertEqual(len(registry.history("psn_001")), 3)

    def test_exclusion_propagates_to_all_membership_surfaces(self) -> None:
        from community_os.privacy_operations import ExclusionRegistry

        registry = ExclusionRegistry()
        registry.record(rights("psn_001"))
        registry.record(rights(
            "psn_002", objection="received", exclusion="excluded",
            suppression="propagated", deletion="completed",
        ))
        for surface in ("classification", "aggregate", "html", "pdf"):
            self.assertEqual(
                registry.publishable_members(surface, {"psn_001", "psn_002"}),
                frozenset({"psn_001"}),
            )


class AuditAndCleanupTests(unittest.TestCase):
    def test_audit_event_is_code_only_frozen_and_log_is_append_only(self) -> None:
        from community_os.privacy_operations import (
            PseudonymousAuditEvent, PseudonymousAuditLog,
        )

        event = PseudonymousAuditEvent(
            run_id="run_20260713_001",
            asset_id="asset_001",
            asset_version="inventory_v1",
            pseudonym="psn_001",
            actor_code="retention_worker",
            reason_code="retention_expired",
            timestamp=NOW,
            action="asset_deleted",
            source_code="github",
            purpose_code="aggregate_talent_evidence",
        )
        log = PseudonymousAuditLog()
        log.append(event)
        self.assertEqual(log.events, (event,))
        with self.assertRaises(AttributeError):
            log.events.append(event)
        with self.assertRaises(FrozenInstanceError):
            event.action = "changed"
        for field, value in (
            ("pseudonym", "ada@example.org"),
            ("actor_code", "Ada Person"),
            ("reason_code", "because the operator said so"),
            ("source_code", "GitHub API"),
            ("purpose_code", "Aggregate talent"),
        ):
            with self.subTest(field=field):
                with self.assertRaisesRegex(ValueError, field):
                    PseudonymousAuditEvent(**{**event.__dict__, field: value})

    def test_cleanup_preflights_all_deleters_before_any_mutation(self) -> None:
        from community_os.privacy_operations import DataAsset, DataClass, delete_expired_assets

        first = asset("asset_001", "psn_001", deadline=NOW)
        second = DataAsset(**{
            **asset("asset_002", "psn_002", deadline=NOW).__dict__,
            "storage_scope": "missing_storage",
            "data_class": DataClass.ENRICHMENT_CACHE,
        })
        deleted: list[str] = []
        with self.assertRaisesRegex(RuntimeError, "deleter"):
            delete_expired_assets(
                (first, second), now=NOW,
                deleters={"protected_enrichment": deleted.append},
                run_id="run_20260713_001", actor_code="retention_worker",
                reason_code="retention_expired",
            )
        self.assertEqual(deleted, [])

    def test_cleanup_deletes_expired_assets_and_returns_attributable_audit(self) -> None:
        from community_os.privacy_operations import DataClass, delete_expired_assets

        expired_raw = asset("asset_001", "psn_001", deadline=NOW)
        expired_cache = asset(
            "asset_002", "psn_002", deadline=NOW,
            data_class=DataClass.ENRICHMENT_CACHE,
        )
        current = asset("asset_003", "psn_003")
        deleted: list[str] = []
        report = delete_expired_assets(
            (expired_raw, expired_cache, current), now=NOW,
            deleters={"protected_enrichment": deleted.append},
            run_id="run_20260713_001", actor_code="retention_worker",
            reason_code="retention_expired",
        )
        self.assertEqual(len(deleted), 2)
        self.assertEqual(report.deleted_count, 2)
        self.assertEqual(report.retained_count, 1)
        self.assertEqual(
            {event.pseudonym for event in report.audit_events},
            {"psn_001", "psn_002"},
        )
        self.assertTrue(all(event.action == "asset_deleted" for event in report.audit_events))
        rendered = repr(report)
        self.assertNotIn("protected/", rendered)
        self.assertIn("asset_001", rendered)


class ReleaseStateTests(unittest.TestCase):
    def _evidence(self):
        from community_os.privacy_operations import (
            ExclusionRegistry, PrivacyParityRecord, PublicationApproval,
            ReleaseEvidence, ReviewRecord,
        )

        registry = ExclusionRegistry()
        registry.record(rights("psn_001"))
        from community_os.privacy_operations import DataAsset, DataClass
        item = DataAsset(**{
            **asset("asset_001", "psn_001", data_class=DataClass.AGGREGATE).__dict__,
            "allowed_uses": frozenset({"publish"}),
        })
        parity = PrivacyParityRecord(
            classification_members=frozenset({"psn_001"}),
            aggregate_members=frozenset({"psn_001"}),
            html_members=frozenset({"psn_001"}),
            pdf_members=frozenset({"psn_001"}),
        )
        publication = PublicationApproval(
            report_hash="a" * 64,
            actor_code="release_owner",
            approved_at=NOW,
        )
        return ReleaseEvidence(
            inventory=(item,), registry=registry, approvals=(approval(use="publish"),),
            cleanup_report=None, parity=parity,
            reviews=(ReviewRecord(review_code="semantic_review", resolved=True),),
            publication_approval=publication,
            report_hash="a" * 64,
            report_generated_at=NOW - timedelta(minutes=1),
        )

    def test_release_state_has_exact_public_values(self) -> None:
        from community_os.privacy_operations import ReleaseState

        self.assertEqual(
            {state.value for state in ReleaseState},
            {"Blocked", "Needs review", "Safe to publish"},
        )

    def test_release_state_is_derived_from_concrete_records(self) -> None:
        from community_os.privacy_operations import (
            PrivacyParityRecord, ReleaseEvidence, ReleaseState, ReviewRecord,
            evaluate_release,
        )

        safe = self._evidence()
        self.assertIs(evaluate_release(safe, now=NOW), ReleaseState.SAFE_TO_PUBLISH)
        self.assertNotIn("compliant", evaluate_release(safe, now=NOW).value.casefold())

        missing_approval = ReleaseEvidence(**{**safe.__dict__, "approvals": ()})
        self.assertIs(evaluate_release(missing_approval, now=NOW), ReleaseState.BLOCKED)

        mismatch = PrivacyParityRecord(**{
            **safe.parity.__dict__, "pdf_members": frozenset(),
        })
        self.assertIs(
            evaluate_release(ReleaseEvidence(**{**safe.__dict__, "parity": mismatch}), now=NOW),
            ReleaseState.BLOCKED,
        )

        pending = ReleaseEvidence(**{
            **safe.__dict__,
            "reviews": (ReviewRecord(review_code="semantic_review", resolved=False),),
        })
        self.assertIs(evaluate_release(pending, now=NOW), ReleaseState.NEEDS_REVIEW)

        no_publication_approval = ReleaseEvidence(**{
            **safe.__dict__, "publication_approval": None,
        })
        self.assertIs(
            evaluate_release(no_publication_approval, now=NOW),
            ReleaseState.NEEDS_REVIEW,
        )

        unrelated_hash = ReleaseEvidence(**{
            **safe.__dict__,
            "publication_approval": type(safe.publication_approval)(
                report_hash="b" * 64,
                actor_code="release_owner",
                approved_at=NOW,
            ),
        })
        self.assertIs(evaluate_release(unrelated_hash, now=NOW), ReleaseState.BLOCKED)

        future_approval = ReleaseEvidence(**{
            **safe.__dict__,
            "publication_approval": type(safe.publication_approval)(
                report_hash="a" * 64,
                actor_code="release_owner",
                approved_at=NOW + timedelta(minutes=1),
            ),
        })
        self.assertIs(evaluate_release(future_approval, now=NOW), ReleaseState.BLOCKED)

        research_only = ReleaseEvidence(**{
            **safe.__dict__,
            "inventory": (asset("asset_001", "psn_001"),),
            "approvals": (approval(),),
        })
        self.assertIs(evaluate_release(research_only, now=NOW), ReleaseState.BLOCKED)

    def test_authenticated_pseudonymous_release_owner_is_not_hard_coded_to_one_person(self) -> None:
        from community_os.privacy_operations import (
            PublicationApproval, ReleaseEvidence, ReleaseState, evaluate_release,
        )

        safe = self._evidence()
        pseudonymous_owner = PublicationApproval(
            report_hash=safe.report_hash,
            actor_code="colleague_0123456789abcdef0123456789abcdef",
            approved_at=NOW,
        )
        evidence = ReleaseEvidence(**{
            **safe.__dict__, "publication_approval": pseudonymous_owner,
        })

        self.assertIs(
            evaluate_release(evidence, now=NOW),
            ReleaseState.SAFE_TO_PUBLISH,
        )

    def test_release_blocks_when_expired_inventory_lacks_matching_cleanup_evidence(self) -> None:
        from community_os.privacy_operations import ReleaseEvidence, ReleaseState, evaluate_release

        safe = self._evidence()
        expired = asset("asset_001", "psn_001", deadline=NOW)
        evidence = ReleaseEvidence(**{
            **safe.__dict__, "inventory": (expired,), "cleanup_report": None,
        })
        self.assertIs(evaluate_release(evidence, now=NOW), ReleaseState.BLOCKED)

    def test_cleanup_evidence_is_bound_one_to_one_to_asset_and_version(self) -> None:
        from community_os.privacy_operations import (
            CleanupReport, DataAsset, PseudonymousAuditEvent, ReleaseEvidence,
            ReleaseState, evaluate_release,
        )
        safe = self._evidence()
        first = asset("asset_001", "psn_001", deadline=NOW)
        second = DataAsset(**{**first.__dict__, "asset_id": "asset_002"})
        one_event = PseudonymousAuditEvent(
            run_id="run_20260713_001", asset_id="asset_001", asset_version="inventory_v1",
            pseudonym="psn_001", actor_code="retention_worker",
            reason_code="retention_expired", timestamp=NOW, action="asset_deleted",
            source_code="github", purpose_code="aggregate_talent_evidence",
        )
        evidence = ReleaseEvidence(**{
            **safe.__dict__, "inventory": (first, second),
            "cleanup_report": CleanupReport(1, 1, (one_event,)),
        })
        self.assertIs(evaluate_release(evidence, now=NOW), ReleaseState.BLOCKED)


if __name__ == "__main__":
    unittest.main()
