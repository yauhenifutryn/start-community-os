from __future__ import annotations

import json
from pathlib import Path
import sqlite3
import unittest

from community_os.identity import (
    IdentityRecord,
    PersonCandidate,
    apply_identity_decisions,
    canonicalize_github,
    canonicalize_linkedin,
    deterministic_review_report,
    load_source_aliases,
    normalize_email,
    persist_resolution,
    resolve_identity,
    unresolved_identity_candidates,
)


def record(source: str, key: str, **kwargs: object) -> IdentityRecord:
    return IdentityRecord(source, key, **kwargs)


class IdentityResolutionTests(unittest.TestCase):
    def test_normalized_exact_email_is_the_primary_match(self) -> None:
        existing = PersonCandidate(3, (record("luma", "l-1", email=" PERSON@Example.COM "),))
        result = resolve_identity(record("devpost", "d-1", email="person@example.com"), [existing])
        self.assertEqual(normalize_email("  PERSON@Example.COM\u00a0"), "person@example.com")
        self.assertEqual((result.action, result.person_id, result.decision), ("merge", 3, "linked"))

    def test_different_email_merges_only_for_applicant_provided_profile_in_both_records(self) -> None:
        for field, left, right in (
            ("github", "https://github.com/PersonX", "@personx"),
            ("linkedin", "https://pl.linkedin.com/in/person-x/?trk=x", "linkedin.com/in/person-x"),
        ):
            with self.subTest(field=field):
                existing = PersonCandidate(
                    4,
                    (record("luma", "l-1", email="first@example.com", applicant_provided=(field,), **{field: left}),),
                )
                incoming = record("devpost", "d-1", email="other@example.com", applicant_provided=(field,), **{field: right})
                result = resolve_identity(incoming, [existing])
                self.assertEqual((result.action, result.person_id), ("merge", 4))
                self.assertEqual(result.decision, "merged_with_email_mismatch")
        self.assertEqual(canonicalize_github("https://github.com/PersonX/"), "personx")
        self.assertEqual(canonicalize_linkedin("https://pl.linkedin.com/in/Person-X/?trk=x"), "person-x")

    def test_one_sided_profile_and_weak_names_never_auto_merge(self) -> None:
        existing = PersonCandidate(4, (record("luma", "l-1", github="@same", name="Ada", team="A"),))
        result = resolve_identity(
            record("devpost", "d-1", github="same", applicant_provided=("github",), name="Ada", team="A"),
            [existing],
        )
        self.assertEqual(result.action, "review")
        self.assertIsNone(result.person_id)
        self.assertEqual(result.suggested_person_ids, (4,))

    def test_shared_or_contradictory_strong_identifiers_quarantine(self) -> None:
        candidates = [
            PersonCandidate(1, (record("luma", "a", email="a@example.com", github="shared", applicant_provided=("github",)),)),
            PersonCandidate(2, (record("luma", "b", email="b@example.com", github="shared", linkedin="linkedin.com/in/other", applicant_provided=("github", "linkedin")),)),
        ]
        shared = resolve_identity(record("devpost", "d", github="shared", applicant_provided=("github",)), candidates)
        self.assertEqual(shared.action, "quarantine")
        contradictory = resolve_identity(
            record("devpost", "d2", email="a@example.com", linkedin="https://linkedin.com/in/other", applicant_provided=("linkedin",)),
            candidates,
        )
        self.assertEqual(contradictory.action, "quarantine")

    def test_explicit_alias_is_source_record_scoped(self) -> None:
        path = Path(__file__).parent / "fixtures" / "identity_aliases.synthetic.json"
        aliases = load_source_aliases(path)
        result = resolve_identity(record("devpost", "submission-alias"), [], aliases=aliases)
        self.assertEqual((result.action, result.person_id), ("merge", 7))
        other = resolve_identity(record("luma", "submission-alias"), [], aliases=aliases)
        self.assertEqual(other.action, "new")

    def test_review_report_is_deterministic_and_minimal(self) -> None:
        rows = [
            resolve_identity(record("devpost", "z", name="Zed"), []),
            resolve_identity(record("devpost", "a", name="Ada", team="One"), [PersonCandidate(9, (record("luma", "x", name="Ada", team="One"),))]),
        ]
        first = deterministic_review_report(rows)
        second = deterministic_review_report(reversed(rows))
        self.assertEqual(first, second)
        self.assertNotIn('"a"', first)
        self.assertNotIn('"z"', first)
        decoded = json.loads(first)
        self.assertEqual(
            list(decoded[0]),
            ["candidate_ref", "source_type", "reason_code", "suggested_person_ids"],
        )
        self.assertRegex(decoded[0]["candidate_ref"], r"^candidate-[0-9]{4}$")


class IdentityDecisionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.connection = sqlite3.connect(":memory:")
        self.connection.execute("PRAGMA foreign_keys = ON")
        schema = Path(__file__).resolve().parents[1] / "community_os" / "schema.sql"
        self.connection.executescript(schema.read_text(encoding="utf-8"))
        self.event_id = self.connection.execute(
            "INSERT INTO event(event_key,name,starts_at,event_type) VALUES('e','E','2026-01-01','hackathon')"
        ).lastrowid
        file_id = self.connection.execute(
            "INSERT INTO source_file(event_id,source_type,file_sha256,mapping_version,observed_at) VALUES(?, 'luma','x','v1','2026-01-01')",
            (self.event_id,),
        ).lastrowid
        self.source_record_id = self.connection.execute(
            "INSERT INTO source_record(source_file_id,external_record_id,mapping_version,observed_at,raw_payload_json) VALUES(?,'r','v1','2026-01-01','{}')",
            (file_id,),
        ).lastrowid
        self.person_id = self.connection.execute("INSERT INTO person DEFAULT VALUES").lastrowid

    def tearDown(self) -> None:
        self.connection.close()

    def test_decisions_are_validated_and_supersede_append_only(self) -> None:
        first = apply_identity_decisions(self.connection, [{
            "source_record_id": self.source_record_id, "person_id": self.person_id,
            "decision": "linked", "reviewer": "reviewer", "reason": "confirmed", "decided_at": "2026-07-11T10:00:00Z",
        }])[0]
        second = apply_identity_decisions(self.connection, [{
            "source_record_id": self.source_record_id, "person_id": self.person_id,
            "decision": "kept_separate", "reviewer": "reviewer", "reason": "corrected", "decided_at": "2026-07-11T11:00:00Z",
            "supersedes_decision_id": first,
        }])[0]
        self.assertNotEqual(first, second)
        self.assertEqual(self.connection.execute("SELECT COUNT(*) FROM identity_decision").fetchone()[0], 2)
        with self.assertRaises(ValueError):
            apply_identity_decisions(self.connection, [{"decision": "invented"}])

    def test_decision_semantics_and_single_current_decision_are_enforced(self) -> None:
        base = {
            "source_record_id": self.source_record_id,
            "person_id": self.person_id,
            "decision": "linked",
            "reviewer": "reviewer",
            "reason": "confirmed",
            "decided_at": "2026-07-11T10:00:00Z",
        }
        first = apply_identity_decisions(self.connection, [base])[0]
        with self.assertRaises(ValueError):
            apply_identity_decisions(self.connection, [{**base, "decision": "kept_separate", "reason": "changed", "decided_at": "2026-07-11T11:00:00Z"}])
        self.assertEqual(self.connection.execute("SELECT COUNT(*) FROM identity_decision").fetchone()[0], 1)
        with self.assertRaises(ValueError):
            apply_identity_decisions(self.connection, [{**base, "person_id": None}])
        with self.assertRaises(ValueError):
            apply_identity_decisions(self.connection, [{**base, "decision": "kept_separate", "person_id": None}])
        with self.assertRaises(ValueError):
            apply_identity_decisions(self.connection, [{**base, "decision": "rejected"}])
        with self.assertRaises(ValueError):
            apply_identity_decisions(self.connection, [{**base, "decision": "quarantined"}])
        replacement = {**base, "decision": "kept_separate", "reason": "changed", "decided_at": "2026-07-11T11:00:00Z", "supersedes_decision_id": first}
        apply_identity_decisions(self.connection, [replacement])
        self.assertEqual(self.connection.execute("SELECT COUNT(*) FROM identity_decision d WHERE source_record_id=? AND NOT EXISTS (SELECT 1 FROM identity_decision newer WHERE newer.supersedes_decision_id=d.id)", (self.source_record_id,)).fetchone()[0], 1)
        with self.assertRaises(ValueError):
            apply_identity_decisions(self.connection, [base])

    def test_strict_candidate_query_returns_only_open_within_event_reviews(self) -> None:
        self.connection.execute(
            "INSERT INTO identity_review(source_record_id,provisional_person_id,reason_code,evidence_json) VALUES(?,?, 'WEAK_MATCH','{}')",
            (self.source_record_id, self.person_id),
        )
        self.assertEqual(unresolved_identity_candidates(self.connection, self.event_id)[0]["source_record_id"], self.source_record_id)
        apply_identity_decisions(self.connection, [{
            "source_record_id": self.source_record_id,
            "person_id": self.person_id,
            "decision": "linked",
            "reviewer": "reviewer",
            "reason": "confirmed",
            "decided_at": "2026-07-11T10:00:00Z",
        }])
        self.assertEqual(unresolved_identity_candidates(self.connection, self.event_id), [])

    def test_email_mismatch_merge_persists_both_identity_and_audit_outcome(self) -> None:
        existing_source = self.source_record_id
        self.connection.execute(
            """INSERT INTO person_identity(person_id,source_record_id,identity_type,display_value,
                   normalized_value,applicant_provided,observed_at)
               VALUES(?,?,'email','old@example.com','old@example.com',1,'2026-01-01')""",
            (self.person_id, existing_source),
        )
        file_id = self.connection.execute("SELECT source_file_id FROM source_record WHERE id=?", (existing_source,)).fetchone()[0]
        incoming_source = self.connection.execute(
            "INSERT INTO source_record(source_file_id,external_record_id,mapping_version,observed_at,raw_payload_json) VALUES(?,'d','v1','2026-01-02','{}')",
            (file_id,),
        ).lastrowid
        incoming = record("devpost", "d", source_record_id=incoming_source, email="new@example.com", github="same", applicant_provided=("email", "github"))
        resolution = resolve_identity(
            incoming,
            [PersonCandidate(self.person_id, (record("luma", "r", email="old@example.com", github="same", applicant_provided=("email", "github")),))],
        )
        persist_resolution(self.connection, incoming, resolution, reviewer="pipeline:v1", decided_at="2026-07-11T12:00:00Z")
        self.assertEqual(
            {row[0] for row in self.connection.execute("SELECT normalized_value FROM person_identity WHERE person_id=? AND identity_type='email'", (self.person_id,))},
            {"old@example.com", "new@example.com"},
        )
        self.assertEqual(
            self.connection.execute("SELECT decision FROM identity_decision WHERE source_record_id=?", (incoming_source,)).fetchone()[0],
            "merged_with_email_mismatch",
        )


if __name__ == "__main__":
    unittest.main()
