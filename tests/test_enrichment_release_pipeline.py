from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from community_os.enrichment.release_pipeline import ReleasePipeline, canonical_hash
from community_os.enrichment.state import PipelineState, StageStatus


class EnrichmentReleasePipelineTests(unittest.TestCase):
    def test_declared_prerequisites_block_out_of_order_stage_execution(self) -> None:
        calls: list[str] = []
        with tempfile.TemporaryDirectory() as directory:
            state = PipelineState.create(Path(directory) / "state.json", {
                "reconcile": StageStatus.ALLOWED,
                "aggregate": StageStatus.ALLOWED,
            })
            pipeline = ReleasePipeline(
                state,
                manifest_path=Path(directory) / "manifest.json",
                prerequisites={"aggregate": ("reconcile",)},
            )
            with self.assertRaisesRegex(PermissionError, "requires completed stage reconcile"):
                pipeline.run("aggregate", lambda: calls.append("aggregate") or [])
            self.assertEqual(calls, [])
            self.assertEqual(state.stage("aggregate").attempts, 0)
            pipeline.run("reconcile", lambda: calls.append("reconcile") or [])
            pipeline.run("aggregate", lambda: calls.append("aggregate") or [])
            self.assertEqual(calls, ["reconcile", "aggregate"])

    def test_complete_stage_is_skipped_and_failed_stage_resumes_without_other_reruns(self) -> None:
        calls: list[str] = []
        with tempfile.TemporaryDirectory() as directory:
            state = PipelineState.create(Path(directory) / "state.json", {
                "first_stage": StageStatus.ALLOWED, "second_stage": StageStatus.ALLOWED,
                "coresignal": StageStatus.LOCKED,
            })
            pipeline = ReleasePipeline(state, manifest_path=Path(directory) / "manifest.json")
            first = pipeline.run("first_stage", lambda: calls.append("first") or [{"state": "observed"}])
            again = pipeline.run("first_stage", lambda: calls.append("first-again") or [])
            self.assertEqual(first, again)
            self.assertEqual(calls, ["first"])
            with self.assertRaisesRegex(RuntimeError, "fixture_failure"):
                pipeline.run("second_stage", lambda: (_ for _ in ()).throw(RuntimeError("fixture_failure")))
            pipeline.run("second_stage", lambda: calls.append("second-resume") or [])
            self.assertEqual(calls, ["first", "second-resume"])
            self.assertEqual(state.stage("second_stage").attempts, 2)

    def test_manifest_is_deterministic_minimized_and_coresignal_remains_locked(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state = PipelineState.create(Path(directory) / "state.json", {
                "local_stage": StageStatus.ALLOWED, "coresignal": StageStatus.LOCKED,
            })
            pipeline = ReleasePipeline(
                state, manifest_path=Path(directory) / "manifest.json",
                source_hashes={"applications": "a" * 64},
                config={"classifier_version": "v1"},
            )
            pipeline.run("local_stage", lambda: [{"evidence_ref": "evidence:github:" + "b" * 64}])
            manifest = pipeline.write_manifest()
            self.assertEqual(manifest["run_id"], canonical_hash({"config": {"classifier_version": "v1"}, "source_hashes": {"applications": "a" * 64}}))
            text = (Path(directory) / "manifest.json").read_text()
            self.assertEqual(
                (Path(directory) / "manifest.json").stat().st_mode & 0o777,
                0o600,
            )
            self.assertEqual(Path(directory).stat().st_mode & 0o777, 0o700)
            self.assertNotIn("@", text)
            self.assertNotIn("/Users/", text)
            self.assertEqual(manifest["stages"]["coresignal"]["status"], "locked")


if __name__ == "__main__":
    unittest.main()
