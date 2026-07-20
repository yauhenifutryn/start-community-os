"""Deterministic, resumable stage orchestration for controlled enrichment runs."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
from typing import Callable, Mapping, Sequence

from community_os.enrichment.state import PipelineState, StageStatus


def canonical_hash(value: object) -> str:
    encoded = json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


class ReleasePipeline:
    def __init__(
        self, state: PipelineState, *, manifest_path: str | Path,
        source_hashes: Mapping[str, str] | None = None,
        config: Mapping[str, object] | None = None,
        prerequisites: Mapping[str, Sequence[str]] | None = None,
    ) -> None:
        self.state = state
        self.manifest_path = Path(manifest_path)
        self.source_hashes = dict(source_hashes or {})
        self.config = dict(config or {})
        self.prerequisites = {
            stage: tuple(required) for stage, required in (prerequisites or {}).items()
        }
        if any(not re.fullmatch(r"[0-9a-f]{64}", value) for value in self.source_hashes.values()):
            raise ValueError("source hashes must be SHA-256 values")
        known = set(self.state.to_dict()["stages"])
        for stage, required in self.prerequisites.items():
            if stage not in known or any(item not in known for item in required):
                raise ValueError("stage prerequisite references an unknown stage")
            if stage in required or len(required) != len(set(required)):
                raise ValueError("stage prerequisites are cyclic or duplicated")
        self._validate_prerequisite_cycles()
        if self.prerequisites:
            self.config["stage_prerequisites"] = {
                key: list(self.prerequisites[key]) for key in sorted(self.prerequisites)
            }

    def _validate_prerequisite_cycles(self) -> None:
        visiting: set[str] = set()
        visited: set[str] = set()

        def visit(stage: str) -> None:
            if stage in visiting:
                raise ValueError("stage prerequisites contain a cycle")
            if stage in visited:
                return
            visiting.add(stage)
            for required in self.prerequisites.get(stage, ()):
                visit(required)
            visiting.remove(stage)
            visited.add(stage)

        for stage in self.prerequisites:
            visit(stage)

    def run(self, stage: str, operation: Callable[[], Sequence[Mapping[str, object]]]) -> dict[str, object]:
        for required in self.prerequisites.get(stage, ()):
            if self.state.stage(required).status is not StageStatus.COMPLETE:
                raise PermissionError(f"stage {stage} requires completed stage {required}")
        current = self.state.stage(stage)
        if current.status is StageStatus.COMPLETE:
            return dict(current.result or {})
        if current.status is StageStatus.FAILED:
            self.state.resume(stage)
        elif current.status is StageStatus.ALLOWED:
            self.state.start(stage)
        else:
            raise PermissionError(f"stage {stage} is not runnable")
        try:
            records = [dict(item) for item in operation()]
            result = {"output_hash": canonical_hash(records), "record_count": len(records)}
            self.state.complete(stage, result)
            return result
        except Exception:
            self.state.fail(stage, "stage_operation_failed")
            raise

    def write_manifest(self) -> dict[str, object]:
        state = self.state.to_dict()
        manifest = {
            "config_hash": canonical_hash(self.config),
            "manifest_version": "enrichment-release-v1",
            "run_id": canonical_hash({"config": self.config, "source_hashes": self.source_hashes}),
            "source_hashes": dict(sorted(self.source_hashes.items())),
            "stages": {
                key: {
                    "attempts": value["attempts"], "result": value["result"],
                    "status": value["status"],
                }
                for key, value in sorted(state["stages"].items())
            },
        }
        self.manifest_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.manifest_path.parent.chmod(0o700)
        temporary = self.manifest_path.with_suffix(".tmp")
        temporary.write_text(
            json.dumps(manifest, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        temporary.chmod(0o600)
        temporary.replace(self.manifest_path)
        return manifest
