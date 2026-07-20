from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from community_os.db import initialize
from community_os.operator import OperatorState
from community_os.operator_pipeline import OperatorError, SourceSlot
from community_os.operator_store import FinalRecord, ensure_event, ingest_records


class OperatorStateTests(unittest.TestCase):
    def test_identical_source_digest_is_scoped_to_each_event(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            connection = initialize(Path(directory) / "operator.sqlite3")
            self.addCleanup(connection.close)
            first_event_id = ensure_event(connection)
            second_event_id = int(connection.execute(
                """INSERT INTO event(event_key,name,starts_at,event_type)
                   VALUES('second-event','Second Event','2026-08-01','hackathon')"""
            ).lastrowid)
            digest = "a" * 64

            first = ingest_records(
                connection,
                event_id=first_event_id,
                source_type="luma_final",
                digest=digest,
                records=[FinalRecord(
                    "luma-1", {"approval_status": "approved"},
                    "first@example.org", "First",
                )],
                observed_at="2026-07-12T00:00:00Z",
            )
            second = ingest_records(
                connection,
                event_id=second_event_id,
                source_type="luma_final",
                digest=digest,
                records=[FinalRecord(
                    "luma-2", {"approval_status": "approved"},
                    "second@example.org", "Second",
                )],
                observed_at="2026-08-01T00:00:00Z",
            )

            self.assertFalse(first.skipped)
            self.assertFalse(second.skipped)
            self.assertNotEqual(second.source_file_id, first.source_file_id)
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM source_file WHERE file_sha256=?",
                    (digest,),
                ).fetchone()[0],
                2,
            )

    def test_reopened_operator_rejects_changed_persisted_source(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            connection = initialize(output / "operator.sqlite3")
            event_id = ensure_event(connection)
            ingest_records(
                connection, event_id=event_id, source_type="luma_final", digest="a" * 64,
                records=[FinalRecord("luma-1", {"approval_status": "approved"}, "old@example.org", "Old")],
                observed_at="2026-07-12T00:00:00Z",
            )
            connection.close()
            state = OperatorState(output, "tester")
            try:
                body = (
                    "name,first_name,last_name,email,approval_status,checked_in_at,"
                    "Are you applying solo or with a team? Each team member has to register separately.,"
                    "Team name (if applying with a team)\nNew,New,N,new@example.org,approved,,solo,\n"
                ).encode()
                with self.assertRaisesRegex(OperatorError, "different source version"):
                    state.store(SourceSlot.LUMA, body)
            finally:
                state.close()


if __name__ == "__main__":
    unittest.main()
