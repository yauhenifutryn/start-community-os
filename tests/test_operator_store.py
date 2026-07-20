from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from community_os.db import initialize
from community_os.operator_store import (
    FinalRecord,
    aggregate_facts,
    decide_review,
    ensure_event,
    ingest_records,
    list_open_reviews,
    source_file_row_count,
    normalize_track,
)


class OperatorStoreTests(unittest.TestCase):
    def test_observed_track_labels_normalize_to_two_contract_keys(self) -> None:
        self.assertEqual(normalize_track("BOSKI Challenge"), "boski")
        self.assertEqual(normalize_track("Solidgate Challenge"), "solidgate")

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.database = Path(self.temporary.name) / "operator.sqlite3"
        self.connection = initialize(self.database)
        self.event_id = ensure_event(self.connection)

    def tearDown(self) -> None:
        self.connection.close()
        self.temporary.cleanup()

    def test_exact_email_links_and_replay_is_idempotent(self) -> None:
        luma = FinalRecord("luma-1", {"status": "approved"}, "ada@example.org", "Ada", checked_in_at="2026-07-11T09:00:00Z")
        track = FinalRecord("track-1-member-1", {"track": "Boski"}, "ADA@example.org", "Ada", team_name="A", track="boski")
        first = ingest_records(self.connection, event_id=self.event_id, source_type="luma_final", digest="a" * 64, records=[luma], observed_at="2026-07-12T00:00:00Z")
        ingest_records(self.connection, event_id=self.event_id, source_type="track_preferences_final", digest="b" * 64, records=[track], observed_at="2026-07-12T00:00:00Z")
        replay = ingest_records(self.connection, event_id=self.event_id, source_type="luma_final", digest="a" * 64, records=[luma], observed_at="2026-07-12T01:00:00Z")
        self.connection.close()
        self.connection = initialize(self.database)
        self.assertFalse(first.skipped)
        self.assertTrue(replay.skipped)
        self.assertEqual(self.connection.execute("SELECT COUNT(*) FROM person").fetchone()[0], 1)
        self.assertEqual(list_open_reviews(self.connection, self.event_id), [])

    def test_record_failure_rolls_back_whole_source_file(self) -> None:
        good = FinalRecord("one", {}, "one@example.org", "One")
        bad = FinalRecord("two", {}, "not-an-email", "Two")
        with self.assertRaisesRegex(ValueError, "valid email"):
            ingest_records(self.connection, event_id=self.event_id, source_type="luma_final", digest="c" * 64, records=[good, bad], observed_at="2026-07-12T00:00:00Z")
        self.assertEqual(self.connection.execute("SELECT COUNT(*) FROM source_file").fetchone()[0], 0)
        self.assertEqual(self.connection.execute("SELECT COUNT(*) FROM person").fetchone()[0], 0)

    def test_unmatched_review_decision_is_durable_and_attributable(self) -> None:
        record = FinalRecord("track-1-member-1", {}, "new@example.org", "New", team_name="A", track="boski")
        ingest_records(self.connection, event_id=self.event_id, source_type="track_preferences_final", digest="d" * 64, records=[record], observed_at="2026-07-12T00:00:00Z")
        review = list_open_reviews(self.connection, self.event_id)[0]
        decide_review(self.connection, review_id=review["review_id"], decision="keep_separate", reviewer="reviewer", decided_at="2026-07-12T02:00:00Z")
        self.connection.close()
        self.connection = initialize(self.database)
        self.assertEqual(list_open_reviews(self.connection, self.event_id), [])
        stored = self.connection.execute("SELECT decision, reviewer FROM identity_decision").fetchone()
        self.assertEqual(tuple(stored), ("kept_separate", "reviewer"))
        with self.assertRaisesRegex(Exception, "append-only"):
            self.connection.execute("UPDATE identity_decision SET reviewer='other'")

    def test_different_email_auto_links_only_with_bilateral_profile_evidence(self) -> None:
        luma = FinalRecord("luma-1", {}, "old@example.org", "Ada", github="https://github.com/ada")
        devpost = FinalRecord("devpost-1", {}, "new@example.org", "Ada", github="@ada", submission_title="Build")
        ingest_records(self.connection, event_id=self.event_id, source_type="luma_final", digest="e" * 64, records=[luma], observed_at="2026-07-12T00:00:00Z")
        ingest_records(self.connection, event_id=self.event_id, source_type="devpost_final", digest="f" * 64, records=[devpost], observed_at="2026-07-12T01:00:00Z")
        self.assertEqual(self.connection.execute("SELECT COUNT(*) FROM person").fetchone()[0], 1)
        self.assertEqual(self.connection.execute("SELECT decision FROM identity_decision").fetchone()[0], "merged_with_email_mismatch")
        self.assertEqual(list_open_reviews(self.connection, self.event_id), [])

    def test_aggregate_facts_are_derived_from_persisted_canonical_state(self) -> None:
        luma = [
            FinalRecord(f"luma-{index}", {"approval_status": "approved"}, f"p{index}@example.org", f"P{index}", checked_in_at="2026-07-11T09:00:00Z", team_name="A" if index <= 5 else None)
            for index in range(1, 11)
        ]
        track = [
            FinalRecord(f"track-{index}", {"Track": "Boski", "Team name": "A"}, f"p{index}@example.org", f"P{index}", team_name="A", track="boski")
            for index in range(1, 6)
        ]
        devpost = [
            FinalRecord(f"devpost-{index}", {"Track": "Boski"}, f"p{index}@example.org", f"P{index}", team_name="A", track="boski", submission_title="Build", repository_present=True, demo_present=True)
            for index in range(1, 6)
        ]
        ingest_records(self.connection, event_id=self.event_id, source_type="luma_final", digest="1" * 64, records=luma, observed_at="2026-07-12T00:00:00Z")
        ingest_records(self.connection, event_id=self.event_id, source_type="track_preferences_final", digest="2" * 64, records=track, observed_at="2026-07-12T00:00:00Z")
        ingest_records(self.connection, event_id=self.event_id, source_type="devpost_final", digest="3" * 64, records=devpost, observed_at="2026-07-12T00:00:00Z")
        facts = aggregate_facts(self.connection, self.event_id)
        self.assertEqual((facts["approved"], facts["checked_in"], facts["submitted_people"]), (10, 10, 5))
        self.assertEqual(facts["teams_by_track"]["boski"]["submitted"], 1)
        self.assertEqual(facts["artifact_counts"]["repository"], (1, 1))
        track_file_id = self.connection.execute("SELECT id FROM source_file WHERE source_type='track_preferences_final'").fetchone()[0]
        devpost_file_id = self.connection.execute("SELECT id FROM source_file WHERE source_type='devpost_final'").fetchone()[0]
        self.assertEqual(source_file_row_count(self.connection, track_file_id, "track_preferences_final"), 1)
        self.assertEqual(source_file_row_count(self.connection, devpost_file_id, "devpost_final"), 1)

    def test_weak_name_and_team_match_creates_review_with_immutable_suggestion(self) -> None:
        luma = FinalRecord("luma-1", {"name": "Ada", "Team name (if applying with a team)": "A"}, "old@example.org", "Ada", team_name="A")
        incoming = FinalRecord("devpost-1", {}, "new@example.org", "Ada", team_name="A", submission_title="Build")
        ingest_records(self.connection, event_id=self.event_id, source_type="luma_final", digest="4" * 64, records=[luma], observed_at="2026-07-12T00:00:00Z")
        ingest_records(self.connection, event_id=self.event_id, source_type="devpost_final", digest="5" * 64, records=[incoming], observed_at="2026-07-12T01:00:00Z")
        review = list_open_reviews(self.connection, self.event_id)[0]
        self.assertIsNotNone(review["suggested_person_id"])
        self.assertNotEqual(review["provisional_person_id"], review["suggested_person_id"])
        self.assertEqual(review["candidate_name"], "Ada")
        self.assertNotEqual(review["candidate_email"], "new@example.org")
        self.assertIn("@example.org", review["candidate_email"])

    def test_approved_review_aliases_people_in_aggregate_counts(self) -> None:
        luma = FinalRecord("luma-1", {"name": "Ada", "Team name (if applying with a team)": "A", "approval_status": "approved"}, "old@example.org", "Ada", checked_in_at="2026-07-11T09:00:00Z", team_name="A")
        exact = FinalRecord("devpost-1", {}, "old@example.org", "Ada", team_name="A", submission_title="Build")
        weak = FinalRecord("devpost-2", {}, "new@example.org", "Ada", team_name="A", submission_title="Build")
        ingest_records(self.connection, event_id=self.event_id, source_type="luma_final", digest="6" * 64, records=[luma], observed_at="2026-07-12T00:00:00Z")
        ingest_records(self.connection, event_id=self.event_id, source_type="devpost_final", digest="7" * 64, records=[exact, weak], observed_at="2026-07-12T01:00:00Z")
        review = list_open_reviews(self.connection, self.event_id)[0]
        decide_review(self.connection, review_id=review["review_id"], decision="approve", reviewer="reviewer", decided_at="2026-07-12T02:00:00Z")
        self.assertEqual(aggregate_facts(self.connection, self.event_id)["submitted_people"], 1)

    def test_conflicting_strong_identifiers_quarantine_without_creating_person(self) -> None:
        first = FinalRecord("luma-1", {}, "a@example.org", "A", github="https://github.com/one")
        second = FinalRecord("luma-2", {}, "b@example.org", "B", github="https://github.com/two")
        conflict = FinalRecord("devpost-1", {}, "a@example.org", "Conflict", github="https://github.com/two", submission_title="Build")
        ingest_records(self.connection, event_id=self.event_id, source_type="luma_final", digest="8" * 64, records=[first, second], observed_at="2026-07-12T00:00:00Z")
        ingest_records(self.connection, event_id=self.event_id, source_type="devpost_final", digest="9" * 64, records=[conflict], observed_at="2026-07-12T01:00:00Z")
        self.assertEqual(self.connection.execute("SELECT COUNT(*) FROM person").fetchone()[0], 2)
        self.assertEqual(self.connection.execute("SELECT quarantined FROM source_record WHERE external_record_id='devpost-1'").fetchone()[0], 1)
        self.assertEqual(self.connection.execute("SELECT decision FROM identity_decision WHERE person_id IS NULL").fetchone()[0], "quarantined")


if __name__ == "__main__":
    unittest.main()
