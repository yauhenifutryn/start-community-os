"""Versioned taxonomy loading and deterministic classifier-output validation."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Mapping


@dataclass(frozen=True)
class Taxonomy:
    version: str
    approved: bool
    occupations: tuple[str, ...]
    builder_signals: tuple[str, ...]

    def require_real_person_approval(self) -> None:
        if not self.approved:
            raise ValueError(f"taxonomy {self.version!r} is not approved for real-person classification")


def load_taxonomy(path: str | Path) -> Taxonomy:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    required = {"version", "approved", "occupation", "builder_signal", "evidence_sources"}
    if set(payload) != required:
        raise ValueError("taxonomy keys do not match the supported schema")
    if not isinstance(payload["approved"], bool):
        raise ValueError("taxonomy approval must be boolean")
    for key in ("occupation", "builder_signal", "evidence_sources"):
        values = payload[key]
        if not isinstance(values, list) or not values or not all(isinstance(item, str) and item for item in values):
            raise ValueError(f"taxonomy {key} must be a non-empty string list")
        if len(values) != len(set(values)):
            raise ValueError(f"taxonomy {key} contains duplicates")
    return Taxonomy(
        version=payload["version"], approved=payload["approved"],
        occupations=tuple(payload["occupation"]),
        builder_signals=tuple(payload["builder_signal"]),
    )


def validate_classification(
    taxonomy: Taxonomy, output: Mapping[str, object],
) -> dict[str, object]:
    """Validate model or reviewer output without trusting provider formatting."""
    required = {"occupation", "builder_signal", "standout_fact", "confidence"}
    if set(output) != required:
        raise ValueError("classification keys do not match the structured output schema")
    if output["occupation"] not in taxonomy.occupations:
        raise ValueError("classification occupation is outside the taxonomy")
    if output["builder_signal"] not in taxonomy.builder_signals:
        raise ValueError("classification builder_signal is outside the taxonomy")
    fact = output["standout_fact"]
    if fact is not None and (not isinstance(fact, str) or len(fact) > 500):
        raise ValueError("classification standout_fact must be null or at most 500 characters")
    confidence = output["confidence"]
    if isinstance(confidence, bool) or not isinstance(confidence, (int, float)) or not 0 <= confidence <= 1:
        raise ValueError("classification confidence must be between zero and one")
    return dict(output)
