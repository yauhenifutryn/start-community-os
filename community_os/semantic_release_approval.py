"""Human approval boundary for protected semantic report candidates."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
import hashlib
import hmac
import json
from pathlib import Path
import re
from typing import Any

from community_os.semantic_metrics import (
    AGGREGATE_VERSION,
    REGISTRY_VERSION,
    metric_registry,
    metric_registry_sha256,
    semantic_aggregate_sha256,
    semantic_taxonomy_dimension_registry,
    semantic_taxonomy_sha256,
)


APPROVAL_VERSION = "semantic-release-approval-v3"
MAX_APPROVAL_LIFETIME = timedelta(days=7)

_HASH = re.compile(r"^[0-9a-f]{64}$")
_CODE = re.compile(r"^[a-z][a-z0-9._-]{0,127}$")
_AUTHENTICATED_ACTOR = re.compile(r"^colleague_[0-9a-f]{32}$")
_APPROVAL_HMAC_DOMAIN = b"start-community-os:semantic-release-approval:v3\0"
_TOP_LEVEL_KEYS = frozenset({
    "actor_code", "actor_type", "approval_hmac_sha256", "approved_at",
    "bindings", "decision", "expires_at", "version",
})
_APPROVAL_BINDING_KEYS = frozenset({
    "aggregate_sha256", "event_approval_sha256", "event_definition_sha256",
    "event_key", "html_sha256",
    "metric_registry_sha256", "metric_registry_version", "pdf_sha256",
    "population", "population_key", "population_sha256", "qa_sha256",
    "report_candidate_sha256", "run_sha256", "source_snapshot_sha256",
    "taxonomy_sha256", "taxonomy_version",
})
_AGGREGATE_KEYS = frozenset({
    "aggregate_version", "bindings", "generated_at", "internal_only", "metrics",
    "minimum_group_size", "population", "release_eligible", "source_coverage",
    "taxonomy_dimensions",
})
_AGGREGATE_BINDING_KEYS = frozenset({
    "event_approval_sha256", "event_definition_sha256", "event_key",
    "metric_registry_sha256", "metric_registry_version", "population_key",
    "population_sha256", "run_sha256", "source_snapshot_sha256",
    "taxonomy_sha256", "taxonomy_version",
})
_POPULATION_KEYS = frozenset({
    "assessed_count", "eligible_count", "excluded_count", "population_key",
    "snapshot_sha256", "state_counts", "total_count", "unknown_count",
})
_STATE_KEYS = frozenset({
    "assessed", "conflict", "excluded", "no_evidence", "provider_unavailable",
    "rejected",
})
_SOURCE_KEYS = frozenset({
    "application", "career_context", "event_submission", "public_projects",
})


class SemanticReleaseApprovalError(PermissionError):
    """The candidate or its approval is not safe to promote."""


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise SemanticReleaseApprovalError(
            "semantic release value is not canonical JSON",
        ) from error


def _detached(value: object) -> Any:
    return json.loads(_canonical(value))


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _mapping(value: object, *, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise SemanticReleaseApprovalError(f"semantic release {label} is invalid")
    return value


def _exact(
    value: object, *, label: str, keys: frozenset[str],
) -> Mapping[str, object]:
    mapping = _mapping(value, label=label)
    if set(mapping) != keys:
        raise SemanticReleaseApprovalError(f"semantic release {label} keys are invalid")
    return mapping


def _hash(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not _HASH.fullmatch(value):
        raise SemanticReleaseApprovalError(f"semantic release {label} is invalid")
    return value


def _code(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not _CODE.fullmatch(value):
        raise SemanticReleaseApprovalError(f"semantic release {label} is invalid")
    return value


def _signing_secret(value: object) -> bytes:
    if not isinstance(value, bytes) or len(value) < 16:
        raise SemanticReleaseApprovalError(
            "semantic release approval signing secret is invalid",
        )
    return value


def _integer(value: object, *, label: str, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise SemanticReleaseApprovalError(f"semantic release {label} is invalid")
    return value


def _datetime(value: object, *, label: str) -> datetime:
    if not isinstance(value, str):
        raise SemanticReleaseApprovalError(
            f"semantic release {label} timestamp is invalid",
        )
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise SemanticReleaseApprovalError(
            f"semantic release {label} timestamp is invalid",
        ) from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise SemanticReleaseApprovalError(
            f"semantic release {label} timezone is required",
        )
    return parsed.astimezone(UTC)


def _validate_population(value: object) -> dict[str, object]:
    population = _exact(value, label="population", keys=_POPULATION_KEYS)
    state_counts_raw = _exact(
        population["state_counts"], label="population state counts", keys=_STATE_KEYS,
    )
    state_counts = {
        key: _integer(state_counts_raw[key], label=f"population state {key}")
        for key in sorted(_STATE_KEYS)
    }
    assessed = _integer(population["assessed_count"], label="population assessed count")
    eligible = _integer(population["eligible_count"], label="population eligible count")
    excluded = _integer(population["excluded_count"], label="population excluded count")
    total = _integer(population["total_count"], label="population total count")
    unknown = _integer(population["unknown_count"], label="population unknown count")
    expected_eligible = sum(
        state_counts[key] for key in (
            "assessed", "conflict", "no_evidence", "provider_unavailable", "rejected",
        )
    )
    expected_unknown = sum(
        state_counts[key] for key in (
            "conflict", "no_evidence", "provider_unavailable", "rejected",
        )
    )
    if (
        assessed != state_counts["assessed"]
        or excluded != state_counts["excluded"]
        or eligible != expected_eligible
        or unknown != expected_unknown
        or total != eligible + excluded
        or total != sum(state_counts.values())
    ):
        raise SemanticReleaseApprovalError(
            "semantic release population arithmetic does not reconcile",
        )
    population_key = _code(population["population_key"], label="population key")
    snapshot = _hash(population["snapshot_sha256"], label="population snapshot hash")
    return {
        "assessed_count": assessed,
        "eligible_count": eligible,
        "excluded_count": excluded,
        "population_key": population_key,
        "snapshot_sha256": snapshot,
        "state_counts": state_counts,
        "total_count": total,
        "unknown_count": unknown,
    }


def _validate_taxonomy_dimensions(
    value: object, *, eligible_count: int,
) -> dict[str, object]:
    registry = semantic_taxonomy_dimension_registry()
    dimensions = _mapping(value, label="taxonomy dimensions")
    if set(dimensions) != set(registry):
        raise SemanticReleaseApprovalError(
            "semantic release taxonomy dimension keys are invalid",
        )

    normalized: dict[str, object] = {}
    dimension_keys = frozenset({"cells", "denominator", "mode", "unknown_count"})
    for field, spec in registry.items():
        dimension = _exact(
            dimensions[field], label=f"taxonomy dimension {field}",
            keys=dimension_keys,
        )
        denominator = _integer(
            dimension["denominator"],
            label=f"taxonomy dimension {field} denominator",
        )
        mode = dimension["mode"]
        if denominator != eligible_count or mode != spec["mode"]:
            raise SemanticReleaseApprovalError(
                f"semantic release taxonomy dimension {field} does not reconcile",
            )
        values = tuple(str(item) for item in spec["values"])
        cells_raw = _mapping(
            dimension["cells"], label=f"taxonomy dimension {field} cells",
        )
        if set(cells_raw) != set(values):
            raise SemanticReleaseApprovalError(
                f"semantic release taxonomy dimension {field} cell keys are invalid",
            )
        cells = {
            code: _integer(
                cells_raw[code], label=f"taxonomy dimension {field}.{code}",
            )
            for code in values
        }
        unknown_count = _integer(
            dimension["unknown_count"],
            label=f"taxonomy dimension {field} unknown count",
        )
        if unknown_count > eligible_count or any(
            count > eligible_count for count in cells.values()
        ):
            raise SemanticReleaseApprovalError(
                f"semantic release taxonomy dimension {field} exceeds population",
            )
        if mode == "exclusive":
            if (
                "unknown" not in cells
                or sum(cells.values()) != eligible_count
                or cells["unknown"] != unknown_count
            ):
                raise SemanticReleaseApprovalError(
                    f"semantic release taxonomy dimension {field} does not reconcile",
                )
        else:
            observed_count = eligible_count - unknown_count
            if (
                any(count > observed_count for count in cells.values())
                or sum(cells.values()) < observed_count
            ):
                raise SemanticReleaseApprovalError(
                    f"semantic release taxonomy dimension {field} does not reconcile",
                )
        normalized[field] = {
            "cells": cells,
            "denominator": denominator,
            "mode": mode,
            "unknown_count": unknown_count,
        }
    return normalized


def _validate_aggregate(value: object) -> dict[str, object]:
    aggregate = _exact(value, label="aggregate", keys=_AGGREGATE_KEYS)
    if (
        aggregate["aggregate_version"] != AGGREGATE_VERSION
        or aggregate["internal_only"] is not True
        or aggregate["release_eligible"] is not False
    ):
        raise SemanticReleaseApprovalError(
            "semantic release aggregate boundary is invalid",
        )
    _datetime(aggregate["generated_at"], label="aggregate generated_at")
    minimum_group_size = _integer(
        aggregate["minimum_group_size"], label="minimum group size", minimum=5,
    )
    bindings = _exact(
        aggregate["bindings"], label="aggregate bindings", keys=_AGGREGATE_BINDING_KEYS,
    )
    normalized_bindings = {
        "event_approval_sha256": _hash(
            bindings["event_approval_sha256"], label="event approval hash",
        ),
        "event_definition_sha256": _hash(
            bindings["event_definition_sha256"], label="event definition hash",
        ),
        "event_key": _code(bindings["event_key"], label="event key"),
        "metric_registry_sha256": _hash(
            bindings["metric_registry_sha256"], label="metric registry hash",
        ),
        "metric_registry_version": _code(
            bindings["metric_registry_version"], label="metric registry version",
        ),
        "population_key": _code(bindings["population_key"], label="population key"),
        "population_sha256": _hash(
            bindings["population_sha256"], label="population hash",
        ),
        "run_sha256": _hash(bindings["run_sha256"], label="run hash"),
        "source_snapshot_sha256": _hash(
            bindings["source_snapshot_sha256"], label="source snapshot hash",
        ),
        "taxonomy_sha256": _hash(bindings["taxonomy_sha256"], label="taxonomy hash"),
        "taxonomy_version": _code(bindings["taxonomy_version"], label="taxonomy version"),
    }
    if (
        normalized_bindings["metric_registry_version"] != REGISTRY_VERSION
        or not hmac.compare_digest(
            normalized_bindings["metric_registry_sha256"], metric_registry_sha256(),
        )
        or not hmac.compare_digest(
            normalized_bindings["taxonomy_sha256"],
            semantic_taxonomy_sha256(normalized_bindings["taxonomy_version"]),
        )
    ):
        raise SemanticReleaseApprovalError(
            "semantic release registry or taxonomy binding does not match",
        )
    population = _validate_population(aggregate["population"])
    if (
        population["population_key"] != normalized_bindings["population_key"]
        or not hmac.compare_digest(
            str(population["snapshot_sha256"]),
            normalized_bindings["population_sha256"],
        )
    ):
        raise SemanticReleaseApprovalError(
            "semantic release population binding does not match",
        )

    expected_metric_keys = set(
        _mapping(metric_registry()["metrics"], label="metric registry metrics"),
    )
    metrics = _mapping(aggregate["metrics"], label="aggregate metrics")
    if set(metrics) != expected_metric_keys:
        raise SemanticReleaseApprovalError("semantic release aggregate metric keys are invalid")
    normalized_metrics = {
        key: _integer(metrics[key], label=f"metric {key}")
        for key in sorted(expected_metric_keys)
    }
    if any(value > population["assessed_count"] for value in normalized_metrics.values()):
        raise SemanticReleaseApprovalError(
            "semantic release metric exceeds assessed population",
        )

    coverage_raw = _exact(
        aggregate["source_coverage"], label="source coverage", keys=_SOURCE_KEYS,
    )
    source_coverage = {
        key: _integer(coverage_raw[key], label=f"source coverage {key}")
        for key in sorted(_SOURCE_KEYS)
    }
    if any(value > population["eligible_count"] for value in source_coverage.values()):
        raise SemanticReleaseApprovalError(
            "semantic release source coverage exceeds eligible population",
        )
    taxonomy_dimensions = _validate_taxonomy_dimensions(
        aggregate["taxonomy_dimensions"],
        eligible_count=int(population["eligible_count"]),
    )
    return {
        "aggregate_version": AGGREGATE_VERSION,
        "bindings": normalized_bindings,
        "generated_at": aggregate["generated_at"],
        "internal_only": True,
        "metrics": normalized_metrics,
        "minimum_group_size": minimum_group_size,
        "population": population,
        "release_eligible": False,
        "source_coverage": source_coverage,
        "taxonomy_dimensions": taxonomy_dimensions,
    }


@dataclass(frozen=True)
class SemanticReleaseCandidate:
    """A protected, hash-bound candidate that has not yet been human-approved."""

    aggregate: Mapping[str, object]
    bindings: Mapping[str, object]

    def approval_bindings(self) -> dict[str, object]:
        return _detached(self.bindings)


@dataclass(frozen=True)
class ApprovedSemanticRelease:
    """A candidate paired with a validated, current human approval."""

    candidate: SemanticReleaseCandidate
    approval: Mapping[str, object]
    sha256: str
    version: str
    actor_type: str

    @property
    def aggregate(self) -> Mapping[str, object]:
        return self.candidate.aggregate


def build_semantic_release_candidate(
    aggregate: Mapping[str, object],
    *,
    qa_sha256: str,
    report_candidate_sha256: str,
    html_sha256: str,
    pdf_sha256: str,
) -> SemanticReleaseCandidate:
    normalized = _validate_aggregate(aggregate)
    bindings = normalized["bindings"]
    population = normalized["population"]
    assert isinstance(bindings, Mapping)
    assert isinstance(population, Mapping)
    approval_bindings = {
        "aggregate_sha256": semantic_aggregate_sha256(normalized),
        "event_approval_sha256": bindings["event_approval_sha256"],
        "event_definition_sha256": bindings["event_definition_sha256"],
        "event_key": bindings["event_key"],
        "html_sha256": _hash(html_sha256, label="HTML hash"),
        "metric_registry_sha256": bindings["metric_registry_sha256"],
        "metric_registry_version": bindings["metric_registry_version"],
        "pdf_sha256": _hash(pdf_sha256, label="PDF hash"),
        "population": _detached(population),
        "population_key": bindings["population_key"],
        "population_sha256": bindings["population_sha256"],
        "qa_sha256": _hash(qa_sha256, label="QA hash"),
        "report_candidate_sha256": _hash(
            report_candidate_sha256, label="report candidate hash",
        ),
        "run_sha256": bindings["run_sha256"],
        "source_snapshot_sha256": bindings["source_snapshot_sha256"],
        "taxonomy_sha256": bindings["taxonomy_sha256"],
        "taxonomy_version": bindings["taxonomy_version"],
    }
    return SemanticReleaseCandidate(
        aggregate=_detached(normalized), bindings=_detached(approval_bindings),
    )


def validate_protected_semantic_aggregate(
    aggregate: Mapping[str, object],
) -> dict[str, object]:
    """Validate and detach a candidate without granting publication authority."""

    return _detached(_validate_aggregate(aggregate))


def _approval_hmac(unsigned_record: Mapping[str, object], *, secret: bytes) -> str:
    return hmac.new(
        _signing_secret(secret),
        _APPROVAL_HMAC_DOMAIN + _canonical(unsigned_record),
        hashlib.sha256,
    ).hexdigest()


def issue_semantic_release_approval(
    candidate: SemanticReleaseCandidate,
    *,
    actor_code: str,
    approved_at: datetime,
    expires_at: datetime,
    signing_secret: bytes,
) -> dict[str, object]:
    """Issue a release approval only for an authenticated operator identity."""

    if not isinstance(candidate, SemanticReleaseCandidate):
        raise SemanticReleaseApprovalError("semantic release candidate is invalid")
    actor = _code(actor_code, label="approval actor")
    if not _AUTHENTICATED_ACTOR.fullmatch(actor):
        raise SemanticReleaseApprovalError(
            "semantic release approval requires an authenticated operator actor",
        )
    if (
        not isinstance(approved_at, datetime)
        or approved_at.tzinfo is None
        or approved_at.utcoffset() is None
        or not isinstance(expires_at, datetime)
        or expires_at.tzinfo is None
        or expires_at.utcoffset() is None
    ):
        raise SemanticReleaseApprovalError(
            "semantic release approval timestamp timezone is required",
        )
    approved = approved_at.astimezone(UTC)
    expires = expires_at.astimezone(UTC)
    generated = _datetime(
        candidate.aggregate["generated_at"], label="aggregate generated_at",
    )
    if (
        generated > approved
        or expires <= approved
        or expires - approved > MAX_APPROVAL_LIFETIME
    ):
        raise SemanticReleaseApprovalError(
            "semantic release approval timestamp or expiry is invalid",
        )
    unsigned = {
        "actor_code": actor,
        "actor_type": "human",
        "approved_at": approved.isoformat().replace("+00:00", "Z"),
        "bindings": candidate.approval_bindings(),
        "decision": "approved",
        "expires_at": expires.isoformat().replace("+00:00", "Z"),
        "version": APPROVAL_VERSION,
    }
    return _detached({
        **unsigned,
        "approval_hmac_sha256": _approval_hmac(
            unsigned, secret=_signing_secret(signing_secret),
        ),
    })


def validate_semantic_release_approval_record(
    value: object,
    *,
    candidate: SemanticReleaseCandidate,
    now: datetime,
    signing_secret: bytes,
) -> ApprovedSemanticRelease:
    if not isinstance(candidate, SemanticReleaseCandidate):
        raise SemanticReleaseApprovalError("semantic release candidate is invalid")
    if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
        raise SemanticReleaseApprovalError("semantic release current timestamp requires timezone")
    current = now.astimezone(UTC)
    record = _exact(value, label="approval", keys=_TOP_LEVEL_KEYS)
    provided_hmac = _hash(
        record["approval_hmac_sha256"], label="approval authentication seal",
    )
    unsigned_record = {
        key: record[key] for key in sorted(_TOP_LEVEL_KEYS - {"approval_hmac_sha256"})
    }
    expected_hmac = _approval_hmac(
        unsigned_record, secret=_signing_secret(signing_secret),
    )
    if not hmac.compare_digest(provided_hmac, expected_hmac):
        raise SemanticReleaseApprovalError(
            "semantic release approval authentication seal does not match",
        )
    if record["version"] != APPROVAL_VERSION:
        raise SemanticReleaseApprovalError("semantic release approval version is invalid")
    if record["decision"] != "approved":
        raise SemanticReleaseApprovalError("semantic release decision must be approved")
    if record["actor_type"] != "human":
        raise SemanticReleaseApprovalError("semantic release approval must be human")
    actor_code = _code(record["actor_code"], label="approval actor")
    if not _AUTHENTICATED_ACTOR.fullmatch(actor_code):
        raise SemanticReleaseApprovalError(
            "semantic release approval requires an authenticated operator actor",
        )
    approved_at = _datetime(record["approved_at"], label="approval approved_at")
    expires_at = _datetime(record["expires_at"], label="approval expires_at")
    generated_at = _datetime(
        candidate.aggregate["generated_at"], label="aggregate generated_at",
    )
    if (
        generated_at > approved_at
        or approved_at > current
        or current >= expires_at
        or expires_at <= approved_at
        or expires_at - approved_at > MAX_APPROVAL_LIFETIME
    ):
        raise SemanticReleaseApprovalError(
            "semantic release approval timestamp or expiry is invalid",
        )
    bindings = _exact(
        record["bindings"], label="approval bindings", keys=_APPROVAL_BINDING_KEYS,
    )
    expected_bindings = candidate.approval_bindings()
    if not hmac.compare_digest(_canonical(bindings), _canonical(expected_bindings)):
        raise SemanticReleaseApprovalError(
            "semantic release approval binding does not match candidate",
        )
    normalized_record = {
        "actor_code": actor_code,
        "actor_type": "human",
        "approval_hmac_sha256": provided_hmac,
        "approved_at": record["approved_at"],
        "bindings": expected_bindings,
        "decision": "approved",
        "expires_at": record["expires_at"],
        "version": APPROVAL_VERSION,
    }
    return ApprovedSemanticRelease(
        candidate=candidate,
        approval=_detached(normalized_record),
        sha256=_sha256(normalized_record),
        version=APPROVAL_VERSION,
        actor_type="human",
    )


def _reject_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise SemanticReleaseApprovalError(
                "semantic release approval contains duplicate keys",
            )
        result[key] = value
    return result


def _reject_nonfinite(value: str) -> None:
    raise SemanticReleaseApprovalError(
        f"semantic release approval contains non-finite value: {value}",
    )


def _read_strict_json(path: str | Path, *, label: str) -> object:
    source = Path(path)
    if source.is_symlink() or not source.is_file():
        raise SemanticReleaseApprovalError(
            f"semantic release {label} is missing or unsafe",
        )
    try:
        encoded = source.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise SemanticReleaseApprovalError(
            f"semantic release {label} is unreadable",
        ) from error
    try:
        return json.loads(
            encoded,
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_nonfinite,
        )
    except SemanticReleaseApprovalError:
        raise
    except json.JSONDecodeError as error:
        raise SemanticReleaseApprovalError(
            f"semantic release {label} is unreadable",
        ) from error


def load_semantic_release_approval(
    path: str | Path,
    *,
    candidate: SemanticReleaseCandidate,
    now: datetime,
    signing_secret: bytes,
) -> ApprovedSemanticRelease:
    value = _read_strict_json(path, label="approval")
    return validate_semantic_release_approval_record(
        value, candidate=candidate, now=now, signing_secret=signing_secret,
    )


def load_approved_semantic_release(
    aggregate_path: str | Path,
    approval_path: str | Path,
    *,
    now: datetime,
    signing_secret: bytes,
) -> ApprovedSemanticRelease:
    """Load an aggregate and derive its candidate only from approval-bound hashes."""

    aggregate = _read_strict_json(aggregate_path, label="aggregate")
    if not isinstance(aggregate, Mapping):
        raise SemanticReleaseApprovalError("semantic release aggregate is invalid")
    approval = _read_strict_json(approval_path, label="approval")
    record = _exact(approval, label="approval", keys=_TOP_LEVEL_KEYS)
    bindings = _exact(
        record["bindings"], label="approval bindings", keys=_APPROVAL_BINDING_KEYS,
    )
    candidate = build_semantic_release_candidate(
        aggregate,
        qa_sha256=_hash(bindings["qa_sha256"], label="QA hash"),
        report_candidate_sha256=_hash(
            bindings["report_candidate_sha256"], label="report candidate hash",
        ),
        html_sha256=_hash(bindings["html_sha256"], label="HTML hash"),
        pdf_sha256=_hash(bindings["pdf_sha256"], label="PDF hash"),
    )
    return validate_semantic_release_approval_record(
        record, candidate=candidate, now=now, signing_secret=signing_secret,
    )
