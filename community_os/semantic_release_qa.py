"""Structured, privacy-minimized QA receipt for one semantic release candidate."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat

from community_os.semantic_metrics import semantic_taxonomy_sha256


RECEIPT_VERSION = "semantic-release-qa-v3"
MAX_RECEIPT_BYTES = 1024 * 1024
POSITIVE_CLAIM_SAMPLE_LIMIT = 10

CHECK_KEYS = frozenset({
    "aggregate_rederived",
    "artifact_privacy_parity",
    "dashboard_state_parity",
    "html_pdf_text_parity",
    "pdf_layout",
    "positive_claim_sample_bound_to_final_reviewed_facts",
    "required_review_cases_resolved",
})

_NONEMPTY_CHECKS = frozenset({
    "aggregate_rederived",
    "artifact_privacy_parity",
    "dashboard_state_parity",
    "html_pdf_text_parity",
    "pdf_layout",
})
_TOP_LEVEL_KEYS = frozenset({"checks", "context", "version"})
_CONTEXT_KEYS = frozenset({
    "aggregate_sha256",
    "event_approval_sha256",
    "event_definition_sha256",
    "event_key",
    "html_candidate_sha256",
    "pdf_candidate_sha256",
    "population",
    "positive_claim_count",
    "required_review_case_count",
    "review_evidence_sha256",
    "run_sha256",
    "source_snapshot_sha256",
    "taxonomy_sha256",
    "taxonomy_version",
})
_POPULATION_KEYS = frozenset({
    "assessed_count",
    "eligible_count",
    "excluded_count",
    "population_key",
    "snapshot_sha256",
    "state_counts",
    "total_count",
    "unknown_count",
})
_STATE_KEYS = frozenset({
    "assessed",
    "conflict",
    "excluded",
    "no_evidence",
    "provider_unavailable",
    "rejected",
})
_CHECK_VALUE_KEYS = frozenset({"evidence_count", "expected_count", "passed"})

_HASH = re.compile(r"^[0-9a-f]{64}$")
_CODE = re.compile(r"^[a-z][a-z0-9._-]{0,127}$")
_EVENT_KEY = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")


class SemanticReleaseQAError(PermissionError):
    """The QA receipt cannot authorize semantic release."""


@dataclass(frozen=True)
class SemanticReleaseQAReceipt:
    """An immutable canonical receipt and its deterministic SHA-256."""

    _canonical_bytes: bytes
    sha256: str

    def canonical_bytes(self) -> bytes:
        return self._canonical_bytes

    def canonical_json(self) -> str:
        return self._canonical_bytes.decode("ascii")

    def to_record(self) -> dict[str, object]:
        value = json.loads(self.canonical_json())
        assert isinstance(value, dict)
        return value


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError) as error:
        raise SemanticReleaseQAError(
            "semantic release QA value is not canonical JSON",
        ) from error


def _mapping(value: object, *, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise SemanticReleaseQAError(f"semantic release QA {label} is invalid")
    return value


def _exact(
    value: object,
    *,
    label: str,
    keys: frozenset[str],
) -> Mapping[str, object]:
    mapping = _mapping(value, label=label)
    if set(mapping) != keys:
        raise SemanticReleaseQAError(
            f"semantic release QA {label} keys are invalid",
        )
    return mapping


def _hash(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not _HASH.fullmatch(value):
        raise SemanticReleaseQAError(
            f"semantic release QA {label} is invalid",
        )
    return value


def _code(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not _CODE.fullmatch(value):
        raise SemanticReleaseQAError(
            f"semantic release QA {label} is invalid",
        )
    return value


def _integer(value: object, *, label: str) -> int:
    if type(value) is not int or value < 0:
        raise SemanticReleaseQAError(
            f"semantic release QA {label} is invalid",
        )
    return value


def _normalize_population(value: object) -> dict[str, object]:
    population = _exact(value, label="population", keys=_POPULATION_KEYS)
    raw_states = _exact(
        population["state_counts"],
        label="population state counts",
        keys=_STATE_KEYS,
    )
    states = {
        key: _integer(raw_states[key], label=f"population state {key}")
        for key in sorted(_STATE_KEYS)
    }
    assessed = _integer(
        population["assessed_count"], label="population assessed count",
    )
    eligible = _integer(
        population["eligible_count"], label="population eligible count",
    )
    excluded = _integer(
        population["excluded_count"], label="population excluded count",
    )
    total = _integer(population["total_count"], label="population total count")
    unknown = _integer(
        population["unknown_count"], label="population unknown count",
    )
    expected_unknown = sum(
        states[key]
        for key in (
            "conflict", "no_evidence", "provider_unavailable", "rejected",
        )
    )
    if (
        total == 0
        or assessed != states["assessed"]
        or excluded != states["excluded"]
        or unknown != expected_unknown
        or eligible != assessed + unknown
        or total != eligible + excluded
        or total != sum(states.values())
    ):
        raise SemanticReleaseQAError(
            "semantic release QA population arithmetic does not reconcile",
        )
    return {
        "assessed_count": assessed,
        "eligible_count": eligible,
        "excluded_count": excluded,
        "population_key": _code(
            population["population_key"], label="population key",
        ),
        "snapshot_sha256": _hash(
            population["snapshot_sha256"], label="population snapshot hash",
        ),
        "state_counts": states,
        "total_count": total,
        "unknown_count": unknown,
    }


def _normalize_context(value: object) -> dict[str, object]:
    context = _exact(value, label="context", keys=_CONTEXT_KEYS)
    event_key = context["event_key"]
    if not isinstance(event_key, str) or not _EVENT_KEY.fullmatch(event_key):
        raise SemanticReleaseQAError("semantic release QA event key is invalid")
    taxonomy_version = _code(
        context["taxonomy_version"], label="taxonomy version",
    )
    taxonomy_hash = _hash(
        context["taxonomy_sha256"], label="taxonomy hash",
    )
    try:
        expected_taxonomy_hash = semantic_taxonomy_sha256(taxonomy_version)
    except ValueError as error:
        raise SemanticReleaseQAError(
            "semantic release QA taxonomy version is invalid",
        ) from error
    if not hmac.compare_digest(taxonomy_hash, expected_taxonomy_hash):
        raise SemanticReleaseQAError(
            "semantic release QA taxonomy hash does not match its version",
        )
    return {
        "aggregate_sha256": _hash(
            context["aggregate_sha256"], label="aggregate hash",
        ),
        "event_approval_sha256": _hash(
            context["event_approval_sha256"], label="event approval hash",
        ),
        "event_definition_sha256": _hash(
            context["event_definition_sha256"], label="event definition hash",
        ),
        "event_key": event_key,
        "html_candidate_sha256": _hash(
            context["html_candidate_sha256"], label="HTML candidate hash",
        ),
        "pdf_candidate_sha256": _hash(
            context["pdf_candidate_sha256"], label="PDF candidate hash",
        ),
        "population": _normalize_population(context["population"]),
        "positive_claim_count": _integer(
            context["positive_claim_count"], label="positive claim count",
        ),
        "required_review_case_count": _integer(
            context["required_review_case_count"],
            label="required review case count",
        ),
        "review_evidence_sha256": _hash(
            context["review_evidence_sha256"], label="review evidence hash",
        ),
        "run_sha256": _hash(context["run_sha256"], label="run hash"),
        "source_snapshot_sha256": _hash(
            context["source_snapshot_sha256"], label="source snapshot hash",
        ),
        "taxonomy_sha256": taxonomy_hash,
        "taxonomy_version": taxonomy_version,
    }


def _normalize_checks(
    value: object, *, context: Mapping[str, object],
) -> dict[str, object]:
    checks = _exact(value, label="checks", keys=CHECK_KEYS)
    normalized: dict[str, object] = {}
    for key in sorted(CHECK_KEYS):
        check = _exact(
            checks[key], label=f"check {key}", keys=_CHECK_VALUE_KEYS,
        )
        evidence_count = _integer(
            check["evidence_count"], label=f"check {key} evidence count",
        )
        expected_count = _integer(
            check["expected_count"], label=f"check {key} expected count",
        )
        if (
            check["passed"] is not True
            or evidence_count != expected_count
            or (key in _NONEMPTY_CHECKS and expected_count == 0)
        ):
            raise SemanticReleaseQAError(
                f"semantic release QA check {key} did not pass completely",
            )
        if (
            key == "positive_claim_sample_bound_to_final_reviewed_facts"
            and expected_count != min(
                POSITIVE_CLAIM_SAMPLE_LIMIT,
                int(context["positive_claim_count"]),
            )
        ):
            raise SemanticReleaseQAError(
                "semantic release QA check "
                "positive_claim_sample_bound_to_final_reviewed_facts "
                "does not match the current positive claims",
            )
        if key == "required_review_cases_resolved" and expected_count != int(
            context["required_review_case_count"],
        ):
            raise SemanticReleaseQAError(
                "semantic release QA check required_review_cases_resolved "
                "does not match the current review cases",
            )
        normalized[key] = {
            "evidence_count": evidence_count,
            "expected_count": expected_count,
            "passed": True,
        }
    return normalized


def build_semantic_release_qa_context(
    *,
    event_approval_sha256: str,
    event_definition_sha256: str,
    event_key: str,
    source_snapshot_sha256: str,
    population: Mapping[str, object],
    run_sha256: str,
    taxonomy_version: str,
    aggregate_sha256: str,
    html_candidate_sha256: str,
    pdf_candidate_sha256: str,
    positive_claim_count: int,
    required_review_case_count: int,
    review_evidence_sha256: str,
) -> dict[str, object]:
    """Build the exact minimized context bound by a QA receipt."""

    try:
        taxonomy_hash = semantic_taxonomy_sha256(taxonomy_version)
    except ValueError as error:
        raise SemanticReleaseQAError(
            "semantic release QA taxonomy version is invalid",
        ) from error
    return _normalize_context({
        "aggregate_sha256": aggregate_sha256,
        "event_approval_sha256": event_approval_sha256,
        "event_definition_sha256": event_definition_sha256,
        "event_key": event_key,
        "html_candidate_sha256": html_candidate_sha256,
        "pdf_candidate_sha256": pdf_candidate_sha256,
        "population": population,
        "positive_claim_count": positive_claim_count,
        "required_review_case_count": required_review_case_count,
        "review_evidence_sha256": review_evidence_sha256,
        "run_sha256": run_sha256,
        "source_snapshot_sha256": source_snapshot_sha256,
        "taxonomy_sha256": taxonomy_hash,
        "taxonomy_version": taxonomy_version,
    })


def validate_semantic_release_qa_receipt(
    value: object,
    *,
    expected_context: Mapping[str, object],
) -> SemanticReleaseQAReceipt:
    """Validate a complete passing receipt against the observed release context."""

    receipt = _exact(value, label="receipt", keys=_TOP_LEVEL_KEYS)
    if receipt["version"] != RECEIPT_VERSION:
        raise SemanticReleaseQAError(
            "semantic release QA receipt version is unsupported",
        )
    normalized_context = _normalize_context(receipt["context"])
    normalized_expected_context = _normalize_context(expected_context)
    if not hmac.compare_digest(
        _canonical(normalized_context), _canonical(normalized_expected_context),
    ):
        raise SemanticReleaseQAError(
            "semantic release QA context does not match the release candidate",
        )
    normalized = {
        "checks": _normalize_checks(
            receipt["checks"], context=normalized_context,
        ),
        "context": normalized_context,
        "version": RECEIPT_VERSION,
    }
    canonical = _canonical(normalized)
    return SemanticReleaseQAReceipt(
        _canonical_bytes=canonical,
        sha256=hashlib.sha256(canonical).hexdigest(),
    )


def build_semantic_release_qa_receipt(
    *,
    context: Mapping[str, object],
    checks: Mapping[str, object],
) -> SemanticReleaseQAReceipt:
    """Build only a complete passing receipt, never a partial success artifact."""

    return validate_semantic_release_qa_receipt(
        {"checks": checks, "context": context, "version": RECEIPT_VERSION},
        expected_context=context,
    )


def _reject_duplicate_keys(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise SemanticReleaseQAError(
                f"semantic release QA JSON contains duplicate key: {key}",
            )
        result[key] = value
    return result


def _reject_nonfinite(value: str) -> None:
    raise SemanticReleaseQAError(
        f"semantic release QA JSON contains non-finite value: {value}",
    )


def _read_protected_receipt(path: str | Path) -> object:
    source = Path(path)
    try:
        if source.is_symlink():
            raise SemanticReleaseQAError(
                "semantic release QA receipt is missing or unsafe",
            )
    except OSError as error:
        raise SemanticReleaseQAError(
            "semantic release QA receipt is missing or unsafe",
        ) from error

    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(source, flags)
    except OSError as error:
        raise SemanticReleaseQAError(
            "semantic release QA receipt is missing or unsafe",
        ) from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise SemanticReleaseQAError(
                "semantic release QA receipt is missing or unsafe",
            )
        if stat.S_IMODE(metadata.st_mode) != 0o600:
            raise SemanticReleaseQAError(
                "semantic release QA receipt must use mode 0600",
            )
        if metadata.st_size > MAX_RECEIPT_BYTES:
            raise SemanticReleaseQAError(
                "semantic release QA receipt exceeds the size limit",
            )
        encoded = bytearray()
        while True:
            block = os.read(descriptor, 64 * 1024)
            if not block:
                break
            encoded.extend(block)
            if len(encoded) > MAX_RECEIPT_BYTES:
                raise SemanticReleaseQAError(
                    "semantic release QA receipt exceeds the size limit",
                )
    finally:
        os.close(descriptor)

    try:
        decoded = bytes(encoded).decode("utf-8")
    except UnicodeError as error:
        raise SemanticReleaseQAError(
            "semantic release QA receipt is not valid UTF-8",
        ) from error
    try:
        return json.loads(
            decoded,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite,
        )
    except SemanticReleaseQAError:
        raise
    except json.JSONDecodeError as error:
        raise SemanticReleaseQAError(
            "semantic release QA receipt is malformed JSON",
        ) from error


def load_semantic_release_qa_receipt(
    path: str | Path,
    *,
    expected_context: Mapping[str, object],
) -> SemanticReleaseQAReceipt:
    """Load a protected 0600 receipt and revalidate every release binding."""

    return validate_semantic_release_qa_receipt(
        _read_protected_receipt(path), expected_context=expected_context,
    )


def load_semantic_release_qa_review_evidence(
    path: str | Path,
) -> dict[str, object]:
    """Read only the minimized review binding from a strict protected receipt."""

    receipt = _exact(
        _read_protected_receipt(path), label="receipt", keys=_TOP_LEVEL_KEYS,
    )
    if receipt["version"] != RECEIPT_VERSION:
        raise SemanticReleaseQAError(
            "semantic release QA receipt version is unsupported",
        )
    context = _normalize_context(receipt["context"])
    return {
        key: context[key]
        for key in (
            "positive_claim_count", "required_review_case_count",
            "review_evidence_sha256",
        )
    }
