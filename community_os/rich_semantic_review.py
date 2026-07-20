"""Protected human review and internal aggregation for rich semantic proposals."""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable, Iterable, Mapping
from datetime import UTC, datetime, timedelta
import hashlib
import hmac
import json
from pathlib import Path
import re
from community_os.enrichment.openai_rich_semantic_assessment import (
    rich_semantic_schema_sha256,
)
from community_os.enrichment.rich_semantic_assessment import (
    ASSESSMENT_ENUMS,
    MODEL_ALLOWLIST,
    PROMPT_VERSION,
    REASON_CODES,
    validate_profile_evidence,
    validate_rich_semantic_assessment,
)
from community_os.enrichment.semantic_evidence import (
    assert_no_known_identity_literals,
    assert_safe_semantic_payload,
    sanitize_professional_text,
)
from community_os.enrichment.semantic_taxonomy import (
    validate_semantic_taxonomy_fact,
)
from community_os.release_operations import (
    ReviewCase,
    ReviewDecision,
    ReviewRepository,
)


_HASH = re.compile(r"^[0-9a-f]{64}$")
_SUBJECT = re.compile(r"^case:v1:[0-9a-f]{64}$")
_AUTHENTICATED_ACTOR = re.compile(r"^colleague_[0-9a-f]{32}$")
_DECISION_HMAC_DOMAIN = b"start-community-os:rich-semantic-review-decision:v2\0"
_HUMAN_ATTESTATION_HMAC_DOMAIN = (
    b"start-community-os:rich-semantic-human-attestation:v1\0"
)
_REVIEW_CONTEXT_KEYS = frozenset({
    "event_approval", "event_definition", "event_key",
})
_PROPOSAL_FIELDS = frozenset({
    "approval_sha256", "assessment", "created_at", "evidence",
    "evidence_sha256", "expires_at", "model", "model_sha256",
    "prompt_sha256", "prompt_version", "schema_sha256", "source_coverage",
    "subject_ref",
})
_PROPOSAL_ENVELOPE_V1_FIELDS = frozenset({
    "case_code", "case_hash", "proposal", "proposal_sha256", "proposal_version",
})
_PROPOSAL_ENVELOPE_V2_FIELDS = _PROPOSAL_ENVELOPE_V1_FIELDS | {
    "identity_corpus_sha256",
}
_SOURCE_FAMILIES = ("application", "career", "devpost", "projects")
_FACT_DIMENSIONS = (
    "builder_level", "product_maturity", "technical_depth", "execution_scope",
    "external_validation", "originality",
)
_AGGREGATE_DIMENSIONS = _FACT_DIMENSIONS + ("cross_source_confidence",)
_IMPRESSIVE_BANDS = ("impressive", "not_impressive", "unknown")
_FACT_FIELDS = frozenset({
    "confidence", "fact_version", "provenance", "review_action", "reviewed_at",
    "reason_codes", "semantic_fact", "subject_ref", "unknown_state",
})
_LEGACY_FACT_FIELDS = _FACT_FIELDS - {"reason_codes"}
_V3_FACT_FIELDS = _FACT_FIELDS | {"semantic_taxonomy"}
_CURRENT_FACT_FIELDS = _V3_FACT_FIELDS | {"reviewed_narrative"}
_NARRATIVE_FIELDS = frozenset({
    "career", "identity_corpus_sha256", "narrative_version", "project",
})
_NARRATIVE_ITEM_FIELDS = frozenset({
    "confidence", "evidence_refs", "state", "text",
})
_NARRATIVE_VERSION = "rich-semantic-reviewed-narrative-v1"
_POPULATION_CONTEXT_KEYS = frozenset({
    "event_approval_sha256", "event_definition_sha256", "event_key",
    "run_sha256", "source_snapshot_sha256", "taxonomy_sha256",
    "taxonomy_version",
})
_PROVENANCE_FIELDS = frozenset({
    "approval_sha256", "assessment_sha256", "evidence_refs", "evidence_sha256",
    "model", "model_sha256", "prompt_sha256", "prompt_version",
    "schema_sha256", "source_coverage",
})
_LEGACY_RECEIPT_FIELDS = frozenset({
    "actor_code", "assessment_sha256", "case_code", "case_hash", "decided_at",
    "deletion_state", "evidence_sha256", "fact_sha256",
    "minimized_evidence_deleted", "projected_at", "proposal_sha256",
    "receipt_version", "review_action", "transient_cache_deleted",
})
_RECEIPT_FIELDS = _LEGACY_RECEIPT_FIELDS | {"decision_hmac_sha256"}
_MANIFEST_RECEIPT_FIELDS = _RECEIPT_FIELDS | {
    "decision_manifest_sha256", "decision_manifest_version",
}
_RECORD_FIELDS = frozenset({"audit_receipt", "fact", "record_version"})
_ATTEMPT_FIELDS = frozenset({
    "attempt_version", "audit_receipt", "case_code", "case_hash", "fact",
    "proposal_sha256", "review_action",
})
_CLEANUP_ATTEMPT_FIELDS = frozenset({
    "attempt_version", "created_at", "deletions",
})
_CLEANUP_DELETION_FIELDS = frozenset({
    "case_code", "case_hash", "proposal_sha256", "reason",
})
_REVIEW_PACKET_VERSION = "rich-semantic-review-packet-v1"
_DECISION_MANIFEST_VERSION = "rich-semantic-decision-manifest-v1"
_DECISION_MANIFEST_FIELDS = frozenset({"decisions", "manifest_version"})
_DECISION_MANIFEST_ROW_FIELDS = frozenset({
    "action", "actor_code", "case_code", "case_hash", "proposal_sha256",
})
_PROOF_FOR_ME_ACTOR = "proof_for_me_agent"
_HUMAN_ATTESTATION_VERSION = "rich-semantic-human-attestation-v1"
_HUMAN_ATTESTATION_FIELDS = frozenset({
    "actor_code", "attestation_hmac_sha256", "attestation_version",
    "attested_at", "review_case_count", "review_set_sha256", "reviews",
})
_HUMAN_ATTESTATION_ROW_FIELDS = frozenset({
    "case_code", "case_hash", "decision_hmac_sha256", "fact_sha256",
    "proposal_sha256", "review_action",
})
_REVIEW_EXCERPT_CHARS = 500
_REVIEW_MAX_ITEMS_PER_SOURCE = 4
_REVIEW_EXCERPT_FIELDS = {
    "application": (
        ("achievement_excerpt", "achievement"),
        ("experience_excerpt", "experience"),
    ),
    "career": (
        ("title_excerpt", "title"),
        ("description_excerpt", "description"),
    ),
    "devpost": (("project_excerpt", "project"),),
    "projects": (
        ("description_excerpt", "description"),
        ("readme_excerpt", "readme"),
    ),
}
_REVIEW_SIGNAL_FIELDS = {
    "application": (),
    "career": (
        "active_state", "duration_band", "industry_code",
        "organization_size_band", "seniority_context",
    ),
    "devpost": ("demo_state", "submission_state", "technology_codes"),
    "projects": (
        "activity_recency", "age_band", "deployment_signal", "forks_band",
        "issues_band", "language_code", "productization_codes",
        "repository_relationship", "release_signal", "size_band",
        "stars_band", "topic_codes",
    ),
}
_REVIEW_SAFE_KEYS = frozenset({
    "active_state", "activity_recency", "age_band", "available",
    "builder_level", "career", "career_delivery", "career_functions",
    "career_stage", "classification", "confidence", "demo_state",
    "demonstrated_capabilities", "deployment_signal", "duration_band",
    "evidence_by_dimension", "evidence_items", "evidence_refs", "excerpt_kind",
    "excerpts", "execution_scope", "external_validation", "forks_band",
    "founder_state", "industry_code", "issues_band", "item_index",
    "language_code", "leadership_state", "market_domains", "originality",
    "organization_size_band", "problem_differentiation",
    "product_maturity", "productization_codes", "project", "project_summary",
    "career_summary", "rationale", "reason_codes", "references",
    "release_signal", "repository_relationship", "semantic_taxonomy",
    "seniority_context", "shown", "signals", "size_band", "source_coverage",
    "source_family", "stars_band", "submission_state", "technical_depth",
    "technical_methods", "technology_codes", "text", "topic_codes", "version",
})


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _timestamp(value: object, field: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError(f"rich semantic proposal {field} is invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(f"rich semantic proposal {field} is invalid") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"rich semantic proposal {field} requires a timezone")
    return parsed.astimezone(UTC)


def _utc_timestamp(value: datetime) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("rich semantic review timestamp requires a timezone")
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def _subject_code(subject_ref: str) -> str:
    return "semantic_" + hashlib.sha256(subject_ref.encode("ascii")).hexdigest()[:24]


def _proposal_path_name(case_code: str) -> str:
    return f"{case_code}.json"


def _source_coverage(evidence: Mapping[str, object]) -> list[str]:
    return sorted(source for source in _SOURCE_FAMILIES if evidence[source])


def _impressive_band(fact: Mapping[str, object]) -> str:
    semantic = fact["semantic_fact"]
    if not isinstance(semantic, Mapping):
        raise PermissionError("rich semantic reviewed fact is invalid")
    builder = semantic["builder_level"]
    maturity = semantic["product_maturity"]
    if builder == "insufficient" or maturity == "unknown":
        return "unknown"
    if (
        builder in {"substantial", "standout"}
        and maturity in {"working_product", "production_evidence"}
    ):
        return "impressive"
    return "not_impressive"


def _privacy_safe_cells(
    counts: Counter[str], codes: tuple[str, ...] | list[str], *,
    minimum_group_size: int,
) -> dict[str, dict[str, object]]:
    ordered = sorted(codes)
    sensitive_complement = any(
        0 < counts.get(code, 0) < minimum_group_size for code in ordered
    )
    return {
        code: (
            {"count": counts.get(code, 0), "state": "reported"}
            if counts.get(code, 0) >= minimum_group_size and not sensitive_complement
            else {"count": None, "state": "withheld"}
        )
        for code in ordered
    }


def _normalize_proposal(
    value: object, *, now: datetime, allow_expired: bool = False,
) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != _PROPOSAL_FIELDS:
        raise ValueError("rich semantic proposal fields are invalid")
    subject_ref = value.get("subject_ref")
    if not isinstance(subject_ref, str) or not _SUBJECT.fullmatch(subject_ref):
        raise ValueError("rich semantic proposal subject must be pseudonymous")
    normalized_evidence = validate_profile_evidence(value.get("evidence"))
    normalized_assessment = validate_rich_semantic_assessment(
        value.get("assessment"), evidence=normalized_evidence,
    )
    model = value.get("model")
    if model not in MODEL_ALLOWLIST:
        raise ValueError("rich semantic proposal model is invalid")
    hashes = (
        value.get("approval_sha256"), value.get("evidence_sha256"),
        value.get("model_sha256"), value.get("prompt_sha256"),
        value.get("schema_sha256"),
    )
    if any(not isinstance(item, str) or not _HASH.fullmatch(item) for item in hashes):
        raise ValueError("rich semantic proposal hash binding is invalid")
    if (
        value["prompt_version"] != PROMPT_VERSION
        or value["schema_sha256"] != rich_semantic_schema_sha256()
        or not hmac.compare_digest(str(value["evidence_sha256"]), _sha256(normalized_evidence))
        or not hmac.compare_digest(str(value["model_sha256"]), _sha256(model))
        or not hmac.compare_digest(str(value["prompt_sha256"]), _sha256(PROMPT_VERSION))
    ):
        raise PermissionError("rich semantic proposal binding does not match its content")
    coverage = value.get("source_coverage")
    if (
        not isinstance(coverage, list)
        or coverage != sorted(set(coverage))
        or coverage != _source_coverage(normalized_evidence)
    ):
        raise PermissionError("rich semantic proposal source coverage does not match evidence")
    created = _timestamp(value.get("created_at"), "creation timestamp")
    expires = _timestamp(value.get("expires_at"), "expiry")
    current = now.astimezone(UTC)
    if created > current:
        raise PermissionError("rich semantic proposal is not active yet")
    if expires <= current and not allow_expired:
        raise PermissionError("rich semantic proposal expired")
    if expires <= created or expires - created > timedelta(days=7):
        raise PermissionError("rich semantic proposal TTL exceeds seven days")
    normalized = dict(value)
    normalized["assessment"] = normalized_assessment
    normalized["evidence"] = normalized_evidence
    normalized["source_coverage"] = coverage
    return normalized


def _case_for(
    proposal: Mapping[str, object], *, review_context_hashes: Mapping[str, str],
    identity_corpus_sha256: str | None = None,
) -> ReviewCase:
    assessment = proposal["assessment"]
    if not isinstance(assessment, Mapping):
        raise ValueError("rich semantic proposal assessment is invalid")
    source_hashes = {
        "approval": str(proposal["approval_sha256"]),
        "assessment": _sha256(assessment),
        "coverage": _sha256(proposal["source_coverage"]),
        "evidence": str(proposal["evidence_sha256"]),
        "model": str(proposal["model_sha256"]),
        "prompt": str(proposal["prompt_sha256"]),
        "proposal": _sha256(proposal),
        "schema": str(proposal["schema_sha256"]),
    }
    if identity_corpus_sha256 is not None:
        if not _HASH.fullmatch(identity_corpus_sha256):
            raise ValueError("rich semantic identity corpus binding is invalid")
        source_hashes["identity_corpus"] = identity_corpus_sha256
    return ReviewCase.create(
        kind="classification",
        subject_code=_subject_code(str(proposal["subject_ref"])),
        reason_codes=("human_review_required",),
        candidate_codes=(),
        source_hashes={**source_hashes, **review_context_hashes},
        version="rich_semantic_review_v1",
    )


def _legacy_correction_bindings(
    assessment: Mapping[str, object], *, evidence_sha256: str,
) -> dict[str, object]:
    """Map the rich correction into the existing classification decision contract."""
    reference = f"evidence:rich:{evidence_sha256}"
    mapping = {
        "professional_identity": "builder_level",
        "seniority": "execution_scope",
        "functional_role": "builder_level",
        "employer_pedigree": "external_validation",
        "builder_evidence": "product_maturity",
        "capabilities": "technical_depth",
        "domains": "originality",
    }
    return {
        dimension: {
            "confidence": 1.0,
            "evidence_refs": [reference],
            "labels": [str(assessment[field])],
            "state": "observed",
        }
        for dimension, field in mapping.items()
    }


def _minimized_fact(
    proposal: Mapping[str, object], assessment: Mapping[str, object], *,
    action: str, reviewed_at: datetime,
    known_identity_literals: tuple[str, ...],
    identity_corpus_sha256: str | None,
) -> dict[str, object]:
    semantic_fact = {field: assessment[field] for field in _FACT_DIMENSIONS}
    taxonomy = validate_semantic_taxonomy_fact(assessment["semantic_taxonomy"])
    unknown = sorted(
        field for field, result in semantic_fact.items()
        if result == "unknown"
    )
    if assessment["builder_level"] == "insufficient":
        unknown.append("builder_evidence")
    reviewed_narrative = _reviewed_narrative(
        assessment, known_identity_literals=known_identity_literals,
        identity_corpus_sha256=identity_corpus_sha256,
    )
    return {
        "confidence": assessment["cross_source_confidence"],
        "fact_version": "rich-semantic-reviewed-fact-v4",
        "provenance": {
            "approval_sha256": proposal["approval_sha256"],
            "assessment_sha256": _sha256(assessment),
            "evidence_refs": list(assessment["evidence_refs"]),
            "evidence_sha256": proposal["evidence_sha256"],
            "model": proposal["model"],
            "model_sha256": proposal["model_sha256"],
            "prompt_sha256": proposal["prompt_sha256"],
            "prompt_version": proposal["prompt_version"],
            "schema_sha256": proposal["schema_sha256"],
            "source_coverage": list(proposal["source_coverage"]),
        },
        "reason_codes": list(assessment["reason_codes"]),
        "reviewed_narrative": reviewed_narrative,
        "review_action": action,
        "reviewed_at": _utc_timestamp(reviewed_at),
        "semantic_fact": semantic_fact,
        "semantic_taxonomy": {
            "version": taxonomy.version,
            "project": taxonomy.project,
            "career": taxonomy.career,
            "evidence_by_dimension": taxonomy.evidence_by_dimension,
        },
        "subject_ref": proposal["subject_ref"],
        "unknown_state": sorted(set(unknown)),
    }


def _reviewed_narrative(
    assessment: Mapping[str, object], *,
    known_identity_literals: tuple[str, ...],
    identity_corpus_sha256: str | None = None,
) -> dict[str, object]:
    """Minimize reviewed prose, or retain an explicit unknown state."""

    references = assessment["evidence_refs"]
    if not isinstance(references, list):
        raise PermissionError("rich semantic narrative references are invalid")
    confidence = assessment["cross_source_confidence"]
    if confidence not in ASSESSMENT_ENUMS["cross_source_confidence"]:
        raise PermissionError("rich semantic narrative confidence is invalid")
    if known_identity_literals:
        verified_identity_corpus_sha256 = assert_no_known_identity_literals(
            {}, known_identity_literals,
        )
        if (
            identity_corpus_sha256 is not None
            and not hmac.compare_digest(
                verified_identity_corpus_sha256, identity_corpus_sha256,
            )
        ):
            raise PermissionError(
                "rich semantic narrative identity binding changed",
            )
    else:
        verified_identity_corpus_sha256 = identity_corpus_sha256
    if (
        verified_identity_corpus_sha256 is not None
        and not _HASH.fullmatch(verified_identity_corpus_sha256)
    ):
        raise PermissionError("rich semantic narrative identity binding is invalid")

    def item(field: str, prefixes: tuple[str, ...]) -> dict[str, object]:
        bound_references = sorted({
            reference for reference in references
            if isinstance(reference, str) and reference.startswith(prefixes)
        })
        raw = assessment[field]
        if (
            verified_identity_corpus_sha256 is None
            or not isinstance(raw, str)
            or not raw.strip()
            or not bound_references
        ):
            return {
                "confidence": confidence, "evidence_refs": [],
                "state": "unknown", "text": "",
            }
        try:
            if known_identity_literals:
                assert_no_known_identity_literals(
                    {"text": raw}, known_identity_literals,
                )
            assert_safe_semantic_payload(
                {"text": raw}, max_total_chars=1_000,
                allowed_keys={"text"},
            )
            safe = sanitize_professional_text(
                raw, forbidden_literals=known_identity_literals,
                max_chars=500,
            )
            if known_identity_literals:
                assert_no_known_identity_literals(
                    {"text": safe}, known_identity_literals,
                )
            assert_safe_semantic_payload(
                {"text": safe}, max_total_chars=1_000,
                allowed_keys={"text"},
            )
        except (TypeError, ValueError):
            safe = ""
        if not safe or safe != raw.strip():
            return {
                "confidence": confidence, "evidence_refs": [],
                "state": "unknown", "text": "",
            }
        return {
            "confidence": confidence,
            "evidence_refs": bound_references,
            "state": "reviewed",
            "text": safe,
        }

    return {
        "career": item("career_summary", ("role_",)),
        "identity_corpus_sha256": (
            verified_identity_corpus_sha256
        ),
        "narrative_version": _NARRATIVE_VERSION,
        "project": item(
            "project_summary", ("application_", "devpost_", "project_"),
        ),
    }


def _bind_proposal_narrative(
    proposal: Mapping[str, object], *,
    known_identity_literals: tuple[str, ...],
) -> tuple[dict[str, object], str | None]:
    """Scan proposal prose once, then remove unsafe text before persistence."""

    assessment = proposal.get("assessment")
    if not isinstance(assessment, Mapping):
        raise PermissionError("rich semantic proposal assessment is invalid")
    narrative = _reviewed_narrative(
        assessment, known_identity_literals=known_identity_literals,
    )
    project = narrative["project"]
    career = narrative["career"]
    if not isinstance(project, Mapping) or not isinstance(career, Mapping):
        raise PermissionError("rich semantic proposal narrative is invalid")
    sanitized_assessment = dict(assessment)
    sanitized_assessment["project_summary"] = project["text"]
    sanitized_assessment["career_summary"] = career["text"]
    sanitized = dict(proposal)
    sanitized["assessment"] = validate_rich_semantic_assessment(
        sanitized_assessment, evidence=proposal["evidence"],
    )
    if known_identity_literals:
        assert_no_known_identity_literals(sanitized, known_identity_literals)
    identity_hash = narrative["identity_corpus_sha256"]
    if identity_hash is not None and not isinstance(identity_hash, str):
        raise PermissionError("rich semantic proposal identity binding is invalid")
    return sanitized, identity_hash


class RichSemanticReviewStore:
    """Keep proposals private until case-bound review, then retain minimal facts."""

    RECORD_VERSION = "rich-semantic-reviewed-record-v1"
    ATTEMPT_VERSION = "rich-semantic-projection-attempt-v1"
    RECEIPT_VERSION = "rich-semantic-deletion-receipt-v2"
    MANIFEST_RECEIPT_VERSION = "rich-semantic-deletion-receipt-v3"
    LEGACY_RECEIPT_VERSION = "rich-semantic-deletion-receipt-v1"
    CLEANUP_ATTEMPT_VERSION = "rich-semantic-pending-cleanup-attempt-v1"

    def __init__(
        self, root: str | Path, *, release_root: str | Path,
        review_repository: ReviewRepository, clock: Callable[[], datetime],
        review_context_hashes: Mapping[str, str],
        transient_cache_root: str | Path | None = None,
        failpoint: Callable[[str], None] | None = None,
        approval_verifier: Callable[[str], bool] | None = None,
        decision_signing_secret: bytes | None = None,
        known_identity_literals: Iterable[str] = (),
    ) -> None:
        self.root = Path(root).resolve()
        self.release_root = Path(release_root).resolve()
        if self.root.name != "rich-semantic-review" or (
            self.root == self.release_root
            or _is_relative_to(self.root, self.release_root)
            or _is_relative_to(self.release_root, self.root)
        ):
            raise ValueError("rich semantic review storage must be isolated from release storage")
        if not isinstance(review_repository, ReviewRepository) or not callable(clock):
            raise ValueError("rich semantic review dependencies are invalid")
        if (
            not isinstance(review_context_hashes, Mapping)
            or set(review_context_hashes) != _REVIEW_CONTEXT_KEYS
            or any(
                not isinstance(value, str) or not _HASH.fullmatch(value)
                for value in review_context_hashes.values()
            )
        ):
            raise ValueError("rich semantic review context is invalid")
        self.review_repository = review_repository
        self.review_context_hashes = dict(review_context_hashes)
        self.clock = clock
        self.failpoint = failpoint
        self.approval_verifier = approval_verifier
        if isinstance(known_identity_literals, (str, bytes)):
            raise TypeError("known identity corpus must be an iterable of strings")
        pending_identity_literals = tuple(known_identity_literals)
        if any(
            not isinstance(literal, str) or not literal.strip()
            for literal in pending_identity_literals
        ):
            raise ValueError("known identity corpus is invalid")
        self._known_identity_literals: tuple[str, ...] = ()
        self._identity_corpus_sha256: str | None = None
        self._decision_signing_secret: bytes | None = None
        self.transient_cache_root = Path(
            transient_cache_root if transient_cache_root is not None
            else self.root / "cache"
        ).resolve()
        if (
            self.transient_cache_root != self.root / "cache"
            or self.transient_cache_root == self.release_root
            or _is_relative_to(self.transient_cache_root, self.release_root)
        ):
            raise ValueError(
                "rich semantic transient cache must be isolated within review storage",
            )
        self.proposals = self.root / "proposals"
        self.transient = self.root / "transient"
        self.attempts = self.root / "attempts"
        self.reviewed = self.root / "reviewed"
        self.receipts = self.root / "receipts"
        self.human_attestation = self.root / "human-attestation.json"
        for directory in (
            self.root, self.proposals, self.transient, self.attempts,
            self.reviewed, self.receipts, self.transient_cache_root,
        ):
            directory.mkdir(parents=True, exist_ok=True, mode=0o700)
            directory.chmod(0o700)
        if pending_identity_literals:
            self.configure_identity_corpus(pending_identity_literals)
        if decision_signing_secret is not None:
            self.configure_decision_authority(decision_signing_secret)
        elif not any(self.attempts.glob("*.json")):
            cleanup_recovered = self._recover_cleanup_attempt()
            if not cleanup_recovered:
                self.cleanup_expired()

    def configure_identity_corpus(self, literals: Iterable[str]) -> str:
        """Bind in-memory identity literals without persisting their values."""

        if isinstance(literals, (str, bytes)):
            raise TypeError("known identity corpus must be an iterable of strings")
        normalized = tuple(literals)
        if (
            not normalized
            or any(
                not isinstance(literal, str) or not literal.strip()
                for literal in normalized
            )
        ):
            raise ValueError("known identity corpus is invalid")
        corpus_sha256 = assert_no_known_identity_literals({}, normalized)
        for path in sorted(self.proposals.glob("*.json")):
            payload = self._read(
                path, "rich semantic proposal is unreadable during identity binding",
            )
            if (
                isinstance(payload, dict)
                and set(payload) == _PROPOSAL_ENVELOPE_V2_FIELDS
                and payload.get("proposal_version") == "rich-semantic-proposal-v2"
                and payload.get("identity_corpus_sha256") is not None
                and payload.get("identity_corpus_sha256") != corpus_sha256
            ):
                raise PermissionError(
                    "known identity corpus conflicts with an open proposal binding",
                )
        self._known_identity_literals = normalized
        self._identity_corpus_sha256 = corpus_sha256
        return corpus_sha256

    def configure_decision_authority(self, secret: bytes) -> None:
        """Attach authority, then recover only authenticated persisted intents."""

        if not isinstance(secret, bytes) or len(secret) < 16:
            raise ValueError(
                "rich semantic review signing secret must contain at least 16 bytes",
            )
        self._decision_signing_secret = secret
        if hasattr(self, "attempts"):
            # A persisted review intent is authoritative even if its proposal
            # TTL elapsed while the process was down. Authenticate and resolve
            # it before any expiry cleanup can remove its still-open evidence.
            self.recover_interrupted()
            cleanup_recovered = self._recover_cleanup_attempt()
            if not cleanup_recovered:
                self.cleanup_expired()

    @staticmethod
    def _decision_hmac_payload(receipt: Mapping[str, object]) -> dict[str, object]:
        payload = {
            key: receipt[key]
            for key in (
                "actor_code", "assessment_sha256", "case_code", "case_hash",
                "decided_at", "evidence_sha256", "fact_sha256",
                "proposal_sha256", "review_action",
            )
        }
        if receipt.get("receipt_version") == (
            RichSemanticReviewStore.MANIFEST_RECEIPT_VERSION
        ):
            payload.update({
                "decision_manifest_sha256": receipt["decision_manifest_sha256"],
                "decision_manifest_version": receipt["decision_manifest_version"],
            })
        return payload

    def _decision_hmac(self, receipt: Mapping[str, object]) -> str:
        secret = self._decision_signing_secret
        if secret is None:
            raise PermissionError(
                "rich semantic review signing authority is not configured",
            )
        return hmac.new(
            secret,
            _DECISION_HMAC_DOMAIN + _canonical(self._decision_hmac_payload(receipt)),
            hashlib.sha256,
        ).hexdigest()

    def _valid_signed_decision(self, receipt: Mapping[str, object]) -> bool:
        if receipt.get("receipt_version") not in {
            self.RECEIPT_VERSION, self.MANIFEST_RECEIPT_VERSION,
        }:
            return False
        digest = receipt.get("decision_hmac_sha256")
        if (
            not isinstance(digest, str) or not _HASH.fullmatch(digest)
            or self._decision_signing_secret is None
        ):
            return False
        return hmac.compare_digest(digest, self._decision_hmac(receipt))

    def _direct_authenticated_human_decision(
        self, receipt: Mapping[str, object],
    ) -> bool:
        actor_code = receipt.get("actor_code")
        return (
            receipt.get("receipt_version") == self.RECEIPT_VERSION
            and isinstance(actor_code, str)
            and _AUTHENTICATED_ACTOR.fullmatch(actor_code) is not None
            and self._valid_signed_decision(receipt)
        )

    def _human_attestation_row(
        self, receipt: Mapping[str, object],
    ) -> dict[str, object]:
        if not self._valid_signed_decision(receipt):
            raise PermissionError(
                "human attestation requires a signed current review decision",
            )
        return {
            "case_code": receipt["case_code"],
            "case_hash": receipt["case_hash"],
            "decision_hmac_sha256": receipt["decision_hmac_sha256"],
            "fact_sha256": receipt["fact_sha256"],
            "proposal_sha256": receipt["proposal_sha256"],
            "review_action": receipt["review_action"],
        }

    def _human_attestation_hmac(
        self, value: Mapping[str, object],
    ) -> str:
        secret = self._decision_signing_secret
        if secret is None:
            raise PermissionError(
                "rich semantic review signing authority is not configured",
            )
        payload = {
            key: value[key]
            for key in _HUMAN_ATTESTATION_FIELDS
            if key != "attestation_hmac_sha256"
        }
        return hmac.new(
            secret,
            _HUMAN_ATTESTATION_HMAC_DOMAIN + _canonical(payload),
            hashlib.sha256,
        ).hexdigest()

    def _load_human_attestation(self) -> dict[str, object] | None:
        path = self.human_attestation
        if not path.exists():
            return None
        if path.is_symlink() or not path.is_file():
            raise PermissionError("rich semantic human attestation is unsafe")
        value = self._read(
            path, "rich semantic human attestation is unreadable",
        )
        if not isinstance(value, dict) or set(value) != _HUMAN_ATTESTATION_FIELDS:
            raise PermissionError("rich semantic human attestation is invalid")
        rows = value.get("reviews")
        actor = value.get("actor_code")
        digest = value.get("attestation_hmac_sha256")
        if (
            value.get("attestation_version") != _HUMAN_ATTESTATION_VERSION
            or not isinstance(actor, str)
            or _AUTHENTICATED_ACTOR.fullmatch(actor) is None
            or not isinstance(rows, list)
            or not rows
            or any(
                not isinstance(row, dict)
                or set(row) != _HUMAN_ATTESTATION_ROW_FIELDS
                for row in rows
            )
            or rows != sorted(rows, key=lambda row: str(row["case_code"]))
            or len({str(row["case_code"]) for row in rows}) != len(rows)
            or value.get("review_case_count") != len(rows)
            or value.get("review_set_sha256") != _sha256(rows)
            or not isinstance(digest, str)
            or _HASH.fullmatch(digest) is None
            or self._decision_signing_secret is None
            or not hmac.compare_digest(digest, self._human_attestation_hmac(value))
        ):
            raise PermissionError("rich semantic human attestation is invalid")
        _timestamp(value.get("attested_at"), "human attestation timestamp")
        return value

    def _authenticated_human_decision(self, receipt: Mapping[str, object]) -> bool:
        if self._direct_authenticated_human_decision(receipt):
            return True
        if not self._valid_signed_decision(receipt):
            return False
        attestation = self._load_human_attestation()
        if attestation is None:
            return False
        row = self._human_attestation_row(receipt)
        return row in attestation["reviews"]

    def _required_human_attestation_rows(self) -> list[dict[str, object]]:
        rows: list[dict[str, object]] = []
        for case in self.review_repository.list(kind="classification"):
            if case.version != "rich_semantic_review_v1" or case.status != "resolved":
                continue
            reviewed_path = self.reviewed / _proposal_path_name(case.case_code)
            rejected_path = self.receipts / _proposal_path_name(case.case_code)
            if reviewed_path.is_file() == rejected_path.is_file():
                raise PermissionError(
                    "rich semantic review outcome is incomplete for attestation",
                )
            if rejected_path.is_file():
                receipt = self._load_rejected_receipt(rejected_path)
                required = True
            else:
                record = self._load_reviewed_record(reviewed_path)
                receipt = record["audit_receipt"]
                fact = record["fact"]
                assert isinstance(receipt, Mapping)
                assert isinstance(fact, Mapping)
                required = (
                    fact.get("confidence") == "low"
                    or fact.get("review_action") == "corrected"
                )
            if required and not self._direct_authenticated_human_decision(receipt):
                rows.append(self._human_attestation_row(receipt))
        return sorted(rows, key=lambda row: str(row["case_code"]))

    def preview_required_human_attestation(self) -> dict[str, object]:
        """Return a content-free binding for one explicit batch sign-off."""

        rows = self._required_human_attestation_rows()
        return {
            "required_review_case_count": len(rows),
            "required_review_set_sha256": _sha256(rows),
        }

    def attest_required_human_reviews(
        self, *, expected_review_set_sha256: str, actor_code: str,
        attested_at: datetime,
    ) -> dict[str, object]:
        """Bind an authenticated colleague sign-off to finalized review outputs."""

        if (
            not isinstance(actor_code, str)
            or _AUTHENTICATED_ACTOR.fullmatch(actor_code) is None
        ):
            raise PermissionError(
                "required semantic review attestation needs an authenticated human",
            )
        if (
            not isinstance(expected_review_set_sha256, str)
            or _HASH.fullmatch(expected_review_set_sha256) is None
        ):
            raise ValueError("required semantic review set hash is invalid")
        rows = self._required_human_attestation_rows()
        if not rows or not hmac.compare_digest(
            expected_review_set_sha256, _sha256(rows),
        ):
            raise PermissionError("required semantic review set changed")
        value: dict[str, object] = {
            "actor_code": actor_code,
            "attestation_version": _HUMAN_ATTESTATION_VERSION,
            "attested_at": _utc_timestamp(attested_at),
            "review_case_count": len(rows),
            "review_set_sha256": expected_review_set_sha256,
            "reviews": rows,
        }
        value["attestation_hmac_sha256"] = self._human_attestation_hmac(value)
        self._write(self.human_attestation, value)
        self._load_human_attestation()
        return {
            "attested_review_case_count": len(rows),
            "review_set_sha256": expected_review_set_sha256,
            "state": "complete",
        }

    def _validate_receipt_shape(self, receipt: object) -> dict[str, object]:
        if not isinstance(receipt, dict):
            raise PermissionError("rich semantic projection receipt is invalid")
        version = receipt.get("receipt_version")
        expected_fields = (
            _MANIFEST_RECEIPT_FIELDS
            if version == self.MANIFEST_RECEIPT_VERSION
            else _RECEIPT_FIELDS if version == self.RECEIPT_VERSION
            else _LEGACY_RECEIPT_FIELDS
            if version == self.LEGACY_RECEIPT_VERSION
            else frozenset()
        )
        if not expected_fields or set(receipt) != expected_fields:
            raise PermissionError("rich semantic projection receipt is invalid")
        if version == self.MANIFEST_RECEIPT_VERSION and (
            receipt.get("actor_code") != _PROOF_FOR_ME_ACTOR
            or receipt.get("review_action") != "approved"
            or receipt.get("decision_manifest_version")
            != _DECISION_MANIFEST_VERSION
            or not isinstance(receipt.get("decision_manifest_sha256"), str)
            or not _HASH.fullmatch(str(receipt["decision_manifest_sha256"]))
        ):
            raise PermissionError("rich semantic manifest decision proof is invalid")
        if version in {self.RECEIPT_VERSION, self.MANIFEST_RECEIPT_VERSION}:
            digest = receipt.get("decision_hmac_sha256")
            if not isinstance(digest, str) or not _HASH.fullmatch(digest):
                raise PermissionError("rich semantic review decision proof is invalid")
            if self._decision_signing_secret is None:
                raise PermissionError(
                    "rich semantic review signing authority is not configured",
                )
            if not hmac.compare_digest(digest, self._decision_hmac(receipt)):
                raise PermissionError("rich semantic review decision proof was tampered")
        return receipt

    def _assert_authoritative_approval(self, proposal: Mapping[str, object]) -> None:
        approval_sha256 = str(proposal["approval_sha256"])
        try:
            approved = (
                self.approval_verifier(approval_sha256)
                if self.approval_verifier is not None else False
            )
        except Exception as error:
            raise PermissionError(
                "rich semantic proposal lacks authoritative approval",
            ) from error
        if approved is not True:
            raise PermissionError("rich semantic proposal lacks authoritative approval")

    @staticmethod
    def _write(path: Path, value: object) -> None:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.parent.chmod(0o700)
        temporary = path.with_name(path.name + ".tmp")
        temporary.write_text(
            json.dumps(
                value, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
                allow_nan=False,
            ) + "\n",
            encoding="utf-8",
        )
        temporary.chmod(0o600)
        temporary.replace(path)

    @staticmethod
    def _read(path: Path, message: str) -> object:
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise PermissionError(message) from error

    def submit(
        self, value: object, *, known_identity_literals: Iterable[str] | None = None,
    ) -> ReviewCase:
        proposal = _normalize_proposal(value, now=self.clock())
        self._assert_authoritative_approval(proposal)
        identity_literals = (
            self._known_identity_literals
            if known_identity_literals is None
            else tuple(known_identity_literals)
        )
        if any(
            not isinstance(literal, str) or not literal.strip()
            for literal in identity_literals
        ):
            raise ValueError("known identity corpus is invalid")
        proposal, identity_corpus_sha256 = _bind_proposal_narrative(
            proposal,
            known_identity_literals=identity_literals,
        )
        case = _case_for(
            proposal, review_context_hashes=self.review_context_hashes,
            identity_corpus_sha256=identity_corpus_sha256,
        )
        current_cases = self.review_repository.list(kind="classification")
        superseded = [
            item for item in current_cases
            if item.version == "rich_semantic_review_v1"
            and item.subject_code == case.subject_code
            and item.case_code != case.case_code
        ]
        if any(item.status != "open" for item in superseded):
            raise PermissionError("resolved rich semantic review cannot be replaced")
        name = _proposal_path_name(case.case_code)
        self._write(self.proposals / name, {
            "case_code": case.case_code,
            "case_hash": case.case_hash,
            "identity_corpus_sha256": identity_corpus_sha256,
            "proposal": proposal,
            "proposal_sha256": _sha256(proposal),
            "proposal_version": "rich-semantic-proposal-v2",
        })
        self._write(self.transient / name, {
            "evidence": proposal["evidence"],
            "evidence_sha256": proposal["evidence_sha256"],
            "transient_version": "rich-semantic-minimized-evidence-v1",
        })
        existing = [
            item for item in current_cases
            if item not in superseded and not (
                item.version == "rich_semantic_review_v1"
                and item.subject_code == case.subject_code
                and item.case_code == case.case_code
            )
        ]
        existing.append(case)
        self.review_repository.replace_for_kinds(("classification",), existing)
        for previous in superseded:
            previous_name = _proposal_path_name(previous.case_code)
            (self.proposals / previous_name).unlink(missing_ok=True)
            (self.transient / previous_name).unlink(missing_ok=True)
        return case

    def _load_proposal(
        self, case_code: str, *, allow_expired: bool = False,
    ) -> tuple[dict[str, object], ReviewCase, str, str | None]:
        path = self.proposals / _proposal_path_name(case_code)
        payload = self._read(path, "rich semantic proposal is missing or unreadable")
        if not isinstance(payload, dict):
            raise PermissionError("rich semantic proposal envelope is invalid")
        if (
            set(payload) == _PROPOSAL_ENVELOPE_V2_FIELDS
            and payload.get("proposal_version") == "rich-semantic-proposal-v2"
        ):
            identity_corpus_sha256 = payload.get("identity_corpus_sha256")
            if (
                identity_corpus_sha256 is not None
                and (
                    not isinstance(identity_corpus_sha256, str)
                    or not _HASH.fullmatch(identity_corpus_sha256)
                )
            ):
                raise PermissionError("rich semantic proposal identity binding is invalid")
        elif (
            set(payload) == _PROPOSAL_ENVELOPE_V1_FIELDS
            and payload.get("proposal_version") == "rich-semantic-proposal-v1"
        ):
            identity_corpus_sha256 = None
        else:
            raise PermissionError("rich semantic proposal envelope is invalid")
        proposal = _normalize_proposal(
            payload["proposal"], now=self.clock(), allow_expired=allow_expired,
        )
        self._assert_authoritative_approval(proposal)
        case = _case_for(
            proposal, review_context_hashes=self.review_context_hashes,
            identity_corpus_sha256=identity_corpus_sha256,
        )
        proposal_hash = _sha256(proposal)
        if (
            payload["case_code"] != case_code
            or payload["case_hash"] != case.case_hash
            or payload["case_code"] != case.case_code
            or not isinstance(payload["proposal_sha256"], str)
            or not hmac.compare_digest(payload["proposal_sha256"], proposal_hash)
        ):
            raise PermissionError("rich semantic proposal was tampered")
        return proposal, case, proposal_hash, identity_corpus_sha256

    def _current_case(self, case_code: str) -> ReviewCase:
        matches = [
            item for item in self.review_repository.list(kind="classification")
            if item.case_code == case_code
        ]
        if len(matches) != 1:
            raise PermissionError("rich semantic review case is not current")
        return matches[0]

    def load_review_packet(self, case_code: str) -> dict[str, object]:
        """Return one detached, bounded packet for an open private review case."""

        current = self._current_case(case_code)
        if current.version != "rich_semantic_review_v1" or current.status != "open":
            raise PermissionError("rich semantic review case is not open")
        name = _proposal_path_name(current.case_code)
        proposal_path = self.proposals / name
        transient_path = self.transient / name
        if (
            proposal_path.is_symlink() or transient_path.is_symlink()
            or proposal_path.parent.resolve() != self.proposals
            or transient_path.parent.resolve() != self.transient
            or not proposal_path.is_file() or not transient_path.is_file()
        ):
            raise PermissionError("rich semantic review packet storage is unsafe")
        try:
            proposal, expected_case, proposal_hash, _ = self._load_proposal(
                current.case_code,
            )
        except (TypeError, ValueError) as error:
            raise PermissionError(
                "rich semantic review packet contains identity leakage or unsafe content",
            ) from error
        if current.to_dict() != expected_case.to_dict():
            raise PermissionError("rich semantic review case is stale")

        transient = self._read(
            transient_path, "rich semantic minimized evidence is missing or unreadable",
        )
        if not isinstance(transient, dict) or set(transient) != {
            "evidence", "evidence_sha256", "transient_version",
        }:
            raise PermissionError("rich semantic minimized evidence is invalid")
        transient_evidence = validate_profile_evidence(transient["evidence"])
        if (
            transient["transient_version"] != "rich-semantic-minimized-evidence-v1"
            or not isinstance(transient["evidence_sha256"], str)
            or not hmac.compare_digest(
                transient["evidence_sha256"], str(proposal["evidence_sha256"]),
            )
            or transient_evidence != proposal["evidence"]
        ):
            raise PermissionError("rich semantic minimized evidence was tampered")

        assessment = proposal["assessment"]
        evidence = proposal["evidence"]
        if not isinstance(assessment, Mapping) or not isinstance(evidence, Mapping):
            raise PermissionError("rich semantic review packet is invalid")
        evidence_items: list[dict[str, object]] = []
        source_coverage: dict[str, dict[str, int]] = {}
        for family in _SOURCE_FAMILIES:
            source_items = evidence[family]
            if not isinstance(source_items, list):
                raise PermissionError("rich semantic review packet evidence is invalid")
            shown_items = source_items[:_REVIEW_MAX_ITEMS_PER_SOURCE]
            source_coverage[family] = {
                "available": len(source_items), "shown": len(shown_items),
            }
            for index, item in enumerate(shown_items, start=1):
                if not isinstance(item, Mapping):
                    raise PermissionError("rich semantic review packet evidence is invalid")
                excerpts: list[dict[str, str]] = []
                for field, kind in _REVIEW_EXCERPT_FIELDS[family]:
                    text = item[field]
                    if not isinstance(text, str):
                        raise PermissionError("rich semantic review excerpt is invalid")
                    if not text:
                        continue
                    safe_text = sanitize_professional_text(
                        text, max_chars=_REVIEW_EXCERPT_CHARS,
                    )
                    if not safe_text:
                        raise PermissionError(
                            "rich semantic review packet contains identity leakage",
                        )
                    excerpts.append({"excerpt_kind": kind, "text": safe_text})
                evidence_items.append({
                    "excerpts": excerpts,
                    "item_index": index,
                    "references": list(item["evidence_refs"]),
                    "signals": {
                        field: json.loads(_canonical(item[field]))
                        for field in _REVIEW_SIGNAL_FIELDS[family]
                    },
                    "source_family": family,
                })

        proposal_view = {
            "classification": {
                field: assessment[field] for field in _FACT_DIMENSIONS
            },
            "confidence": assessment["cross_source_confidence"],
            "evidence_refs": list(assessment["evidence_refs"]),
            "project_summary": assessment["project_summary"],
            "career_summary": assessment["career_summary"],
            "rationale": assessment["rationale"],
            "reason_codes": list(assessment["reason_codes"]),
            "semantic_taxonomy": json.loads(_canonical(
                assessment["semantic_taxonomy"],
            )),
        }
        display = {
            "evidence_items": evidence_items,
            "proposal": proposal_view,
            "source_coverage": source_coverage,
        }
        try:
            assert_safe_semantic_payload(
                display, max_total_chars=20_000, allowed_keys=_REVIEW_SAFE_KEYS,
            )
        except (TypeError, ValueError) as error:
            raise PermissionError(
                "rich semantic review packet contains identity leakage or unsafe content",
            ) from error
        return json.loads(_canonical({
            "case_code": current.case_code,
            "case_hash": current.case_hash,
            **display,
            "packet_version": _REVIEW_PACKET_VERSION,
            "proposal_sha256": proposal_hash,
        }))

    def apply_decision_manifest(
        self, value: object, *, decided_at: datetime,
    ) -> dict[str, object]:
        """Import explicit packet-reviewed Proof-for-Me approvals.

        This operation never selects cases or infers approval from confidence. Each
        row must come from a separately reviewed packet and bind its exact current
        case and proposal. Sensitive or uncertain decisions stay in the individual
        authenticated operator path.
        """

        if (
            not isinstance(value, dict)
            or set(value) != _DECISION_MANIFEST_FIELDS
            or value.get("manifest_version") != _DECISION_MANIFEST_VERSION
            or not isinstance(value.get("decisions"), list)
            or not value["decisions"]
        ):
            raise ValueError("rich semantic decision manifest is invalid")
        _utc_timestamp(decided_at)
        manifest_sha256 = _sha256(value)
        rows: list[dict[str, str]] = []
        case_codes: set[str] = set()
        for item in value["decisions"]:
            if not isinstance(item, dict) or set(item) != _DECISION_MANIFEST_ROW_FIELDS:
                raise ValueError("rich semantic decision manifest row is invalid")
            row = {key: item[key] for key in _DECISION_MANIFEST_ROW_FIELDS}
            if (
                any(not isinstance(row[key], str) for key in row)
                or not _HASH.fullmatch(row["case_hash"])
                or not _HASH.fullmatch(row["proposal_sha256"])
            ):
                raise ValueError("rich semantic decision manifest row is invalid")
            if row["case_code"] in case_codes:
                raise ValueError("rich semantic decision manifest has duplicate cases")
            case_codes.add(row["case_code"])
            if row["action"] != "approved":
                raise PermissionError(
                    "rich semantic batch action requires individual authenticated review",
                )
            if row["actor_code"] != _PROOF_FOR_ME_ACTOR:
                raise PermissionError(
                    "rich semantic decision manifest requires the Proof-for-Me actor",
                )
            rows.append(row)

        # Finish any signed per-case intent before comparing manifest bindings. This
        # makes a replay resume the existing authoritative decision rather than
        # creating a second decision path.
        self.recover_interrupted()
        pending: list[dict[str, str]] = []
        already_applied = 0
        for row in rows:
            current = self._current_case(row["case_code"])
            if current.case_hash != row["case_hash"]:
                raise PermissionError("rich semantic decision manifest binding drifted")
            if current.status == "open":
                packet = self.load_review_packet(row["case_code"])
                if (
                    packet["case_hash"] != row["case_hash"]
                    or packet["proposal_sha256"] != row["proposal_sha256"]
                ):
                    raise PermissionError(
                        "rich semantic decision manifest binding drifted",
                    )
                proposal_view = packet.get("proposal")
                confidence = (
                    proposal_view.get("confidence")
                    if isinstance(proposal_view, Mapping) else None
                )
                if confidence not in {"medium", "high"}:
                    raise PermissionError(
                        "Proof-for-Me decisions require medium or high confidence",
                    )
                pending.append(row)
                continue

            reviewed_path = self.reviewed / _proposal_path_name(row["case_code"])
            if not reviewed_path.is_file() or reviewed_path.is_symlink():
                raise PermissionError(
                    "rich semantic decision manifest conflicts with finalized review",
                )
            record = self._load_reviewed_record(reviewed_path)
            receipt = record["audit_receipt"]
            fact = record["fact"]
            if (
                not isinstance(receipt, Mapping)
                or not isinstance(fact, Mapping)
                or receipt.get("proposal_sha256") != row["proposal_sha256"]
                or receipt.get("review_action") != row["action"]
                or receipt.get("actor_code") != row["actor_code"]
                or receipt.get("decision_manifest_version")
                != _DECISION_MANIFEST_VERSION
                or receipt.get("decision_manifest_sha256") != manifest_sha256
                or fact.get("confidence") not in {"medium", "high"}
            ):
                raise PermissionError(
                    "rich semantic decision manifest conflicts with finalized review",
                )
            already_applied += 1

        # All rows are preflighted before the first mutation, so a malformed or stale
        # later row cannot partially apply an otherwise valid manifest.
        for row in pending:
            self.__decide_core(
                row["case_code"], action="approved",
                actor_code=row["actor_code"], decided_at=decided_at,
                decision_manifest={
                    "manifest_sha256": manifest_sha256,
                    "manifest_version": _DECISION_MANIFEST_VERSION,
                },
            )
        return {
            "already_applied_count": already_applied,
            "applied_count": len(pending),
            "decision_count": len(rows),
            "manifest_sha256": manifest_sha256,
            "state": "complete",
        }

    def decide(
        self, case_code: str, *, action: str, actor_code: str,
        decided_at: datetime, corrected_assessment: object | None = None,
    ) -> dict[str, object]:
        """Apply one authenticated human decision through the public API."""

        if actor_code == _PROOF_FOR_ME_ACTOR:
            raise PermissionError(
                "Proof-for-Me decisions require the bound decision manifest",
            )
        return self.__decide_core(
            case_code, action=action, actor_code=actor_code,
            decided_at=decided_at, corrected_assessment=corrected_assessment,
            decision_manifest=None,
        )

    def __decide_core(
        self, case_code: str, *, action: str, actor_code: str,
        decided_at: datetime, corrected_assessment: object | None = None,
        decision_manifest: Mapping[str, str] | None,
    ) -> dict[str, object]:
        manifest_authorized = (
            actor_code == _PROOF_FOR_ME_ACTOR
            and action == "approved"
            and isinstance(decision_manifest, dict)
            and set(decision_manifest) == {"manifest_sha256", "manifest_version"}
            and decision_manifest.get("manifest_version")
            == _DECISION_MANIFEST_VERSION
            and isinstance(decision_manifest.get("manifest_sha256"), str)
            and _HASH.fullmatch(str(decision_manifest["manifest_sha256"]))
            is not None
        )
        if actor_code == _PROOF_FOR_ME_ACTOR and not manifest_authorized:
            raise PermissionError(
                "Proof-for-Me decisions require the bound decision manifest",
            )
        if actor_code != _PROOF_FOR_ME_ACTOR and decision_manifest is not None:
            raise PermissionError(
                "human review cannot use the Proof-for-Me manifest proof",
            )
        if self._decision_signing_secret is None:
            raise PermissionError(
                "rich semantic review signing authority is not configured",
            )
        if action not in {"approved", "corrected", "rejected"}:
            raise ValueError("rich semantic review action is invalid")
        if (action == "corrected") != (corrected_assessment is not None):
            raise ValueError("rich semantic correction requires exactly one corrected assessment")
        (
            proposal, expected_case, proposal_hash,
            identity_corpus_sha256,
        ) = self._load_proposal(case_code)
        current = self._current_case(case_code)
        if current.case_hash != expected_case.case_hash:
            raise PermissionError("rich semantic review case is stale")
        evidence = proposal["evidence"]
        if not isinstance(evidence, Mapping):
            raise PermissionError("rich semantic minimized evidence is invalid")
        chosen = (
            validate_rich_semantic_assessment(corrected_assessment, evidence=evidence)
            if action == "corrected"
            else proposal["assessment"]
        )
        if not isinstance(chosen, Mapping):
            raise PermissionError("rich semantic assessment is invalid")
        name = _proposal_path_name(case_code)
        attempt_path = self.attempts / name
        if current.status != "open":
            if current.decision is None or current.decision.action != action:
                raise PermissionError("rich semantic review retry conflicts with resolved decision")
            if attempt_path.is_symlink():
                raise PermissionError(
                    "resolved rich semantic review lacks a safe persisted attempt",
                )
            if attempt_path.is_file() and not attempt_path.is_symlink():
                attempt = self._read(
                    attempt_path, "rich semantic projection attempt is unreadable",
                )
                attempt = self._complete_attempt_cleanup(attempt, path=attempt_path)
                return self._commit_attempt(attempt, path=attempt_path)
            raise PermissionError(
                "resolved rich semantic review lacks a persisted attempt",
            )
        decision_time = _timestamp(_utc_timestamp(decided_at), "decision timestamp")
        decision_actor = ReviewDecision(
            case_code=current.case_code, case_hash=current.case_hash, action=action,
            actor_code=actor_code, decided_at=_utc_timestamp(decision_time),
        ).actor_code
        if decision_actor is None:
            raise PermissionError("rich semantic review decision lacks attribution")
        fact = (
            _minimized_fact(
                proposal, chosen, action=action, reviewed_at=decision_time,
                known_identity_literals=(
                    self._known_identity_literals
                    if action == "corrected"
                    and self._identity_corpus_sha256 == identity_corpus_sha256
                    else ()
                ),
                identity_corpus_sha256=(
                    identity_corpus_sha256 if action == "approved" else None
                ),
            )
            if action != "rejected" else None
        )
        receipt: dict[str, object] = {
            "actor_code": decision_actor,
            "assessment_sha256": _sha256(chosen),
            "case_code": current.case_code,
            "case_hash": current.case_hash,
            "decided_at": _utc_timestamp(decision_time),
            "deletion_state": "pending_cleanup",
            "evidence_sha256": proposal["evidence_sha256"],
            "fact_sha256": _sha256(fact) if fact is not None else None,
            "minimized_evidence_deleted": False,
            "projected_at": _utc_timestamp(self.clock()),
            "proposal_sha256": proposal_hash,
            "receipt_version": (
                self.MANIFEST_RECEIPT_VERSION
                if manifest_authorized else self.RECEIPT_VERSION
            ),
            "review_action": action,
            "transient_cache_deleted": False,
        }
        if manifest_authorized:
            assert decision_manifest is not None
            receipt.update({
                "decision_manifest_sha256": decision_manifest["manifest_sha256"],
                "decision_manifest_version": decision_manifest["manifest_version"],
            })
        receipt["decision_hmac_sha256"] = self._decision_hmac(receipt)
        attempt = {
            "attempt_version": self.ATTEMPT_VERSION,
            "audit_receipt": receipt,
            "case_code": current.case_code,
            "case_hash": current.case_hash,
            "fact": fact,
            "proposal_sha256": proposal_hash,
            "review_action": action,
        }
        self._validate_attempt(attempt, require_cleanup=False, allow_open=True)
        self._write(attempt_path, attempt)
        if self.failpoint is not None:
            self.failpoint("after_intent_before_review")
        if current.status == "open":
            repository_output = (
                _legacy_correction_bindings(
                    chosen, evidence_sha256=str(proposal["evidence_sha256"]),
                )
                if action == "corrected" else None
            )
            self.review_repository.decide(
                ReviewDecision(
                    case_code=current.case_code, case_hash=current.case_hash,
                    action=action, corrected_output=repository_output,
                ),
                actor_code=decision_actor, decided_at=decision_time,
            )
            current = self._current_case(case_code)
        if self.failpoint is not None:
            self.failpoint("after_review_before_attempt")
        if self.failpoint is not None:
            self.failpoint("after_attempt_before_cleanup")
        attempt = self._complete_attempt_cleanup(attempt, path=attempt_path)
        if self.failpoint is not None:
            self.failpoint("after_cleanup_before_commit")
        return self._commit_attempt(attempt, path=attempt_path)

    def _validate_attempt(
        self, value: object, *, require_cleanup: bool = True,
        allow_open: bool = False,
    ) -> dict[str, object]:
        if not isinstance(value, dict) or set(value) != _ATTEMPT_FIELDS:
            raise PermissionError("rich semantic projection attempt is invalid")
        if (
            value["attempt_version"] != self.ATTEMPT_VERSION
            or value["review_action"] not in {"approved", "corrected", "rejected"}
            or not isinstance(value["case_code"], str)
            or not isinstance(value["case_hash"], str)
            or not _HASH.fullmatch(value["case_hash"])
            or not isinstance(value["proposal_sha256"], str)
            or not _HASH.fullmatch(value["proposal_sha256"])
        ):
            raise PermissionError("rich semantic projection attempt is invalid")
        case = self._current_case(str(value["case_code"]))
        review_bound = (
            case.status == "resolved"
            and case.decision is not None
            and case.decision.action == value["review_action"]
        )
        open_intent = allow_open and case.status == "open" and case.decision is None
        if case.case_hash != value["case_hash"] or not (review_bound or open_intent):
            raise PermissionError("rich semantic projection attempt is not review-bound")
        action = str(value["review_action"])
        if (action == "rejected") != (value["fact"] is None):
            raise PermissionError("rich semantic projection attempt output is invalid")
        if value["fact"] is not None:
            self._validate_fact(value["fact"])
        receipt = self._validate_receipt_shape(value["audit_receipt"])
        if (
            isinstance(value["fact"], Mapping)
            and value["fact"].get("fact_version") in {
                "rich-semantic-reviewed-fact-v2",
                "rich-semantic-reviewed-fact-v3",
                "rich-semantic-reviewed-fact-v4",
            }
            and receipt["receipt_version"] not in {
                self.RECEIPT_VERSION, self.MANIFEST_RECEIPT_VERSION,
            }
        ):
            raise PermissionError(
                "rich semantic v2 fact cannot use a legacy review receipt",
            )
        expected_fact_hash = _sha256(value["fact"]) if value["fact"] is not None else None
        if (
            receipt["receipt_version"] not in {
                self.RECEIPT_VERSION, self.MANIFEST_RECEIPT_VERSION,
                self.LEGACY_RECEIPT_VERSION,
            }
            or receipt["case_code"] != value["case_code"]
            or receipt["case_hash"] != value["case_hash"]
            or receipt["review_action"] != action
            or receipt["proposal_sha256"] != value["proposal_sha256"]
            or receipt["fact_sha256"] != expected_fact_hash
            or receipt["deletion_state"] not in {
                "pending_cleanup", "deleted_after_review",
            }
            or type(receipt["minimized_evidence_deleted"]) is not bool
            or type(receipt["transient_cache_deleted"]) is not bool
            or not isinstance(receipt["evidence_sha256"], str)
            or not _HASH.fullmatch(receipt["evidence_sha256"])
            or not isinstance(receipt["assessment_sha256"], str)
            or not _HASH.fullmatch(receipt["assessment_sha256"])
        ):
            raise PermissionError("rich semantic projection receipt is invalid")
        if review_bound and (
            receipt["actor_code"] != case.decision.actor_code
            or receipt["decided_at"] != case.decision.decided_at
        ):
            raise PermissionError("rich semantic projection receipt is invalid")
        if open_intent:
            ReviewDecision(
                case_code=case.case_code, case_hash=case.case_hash, action=action,
                actor_code=receipt["actor_code"], decided_at=receipt["decided_at"],
            )
            proposal, expected_case, proposal_hash, _ = self._load_proposal(
                case.case_code, allow_expired=True,
            )
            if (
                expected_case.case_hash != case.case_hash
                or proposal_hash != value["proposal_sha256"]
                or proposal["evidence_sha256"] != receipt["evidence_sha256"]
                or (
                    action != "corrected"
                    and _sha256(proposal["assessment"]) != receipt["assessment_sha256"]
                )
            ):
                raise PermissionError("rich semantic projection intent is not proposal-bound")
        if value["fact"] is not None and (
            receipt["assessment_sha256"]
            != value["fact"]["provenance"]["assessment_sha256"]
            or receipt["evidence_sha256"]
            != value["fact"]["provenance"]["evidence_sha256"]
            or receipt["decided_at"] != value["fact"]["reviewed_at"]
        ):
            raise PermissionError("rich semantic projection output is not decision-bound")
        cleanup_complete = (
            receipt["deletion_state"] == "deleted_after_review"
            and receipt["minimized_evidence_deleted"] is True
            and receipt["transient_cache_deleted"] is True
        )
        cleanup_pending = (
            receipt["deletion_state"] == "pending_cleanup"
            and receipt["minimized_evidence_deleted"] is False
            and receipt["transient_cache_deleted"] is False
        )
        if (require_cleanup and not cleanup_complete) or not (
            cleanup_complete or cleanup_pending
        ):
            raise PermissionError("rich semantic projection cleanup is not verified")
        _timestamp(receipt["decided_at"], "decision timestamp")
        _timestamp(receipt["projected_at"], "projection timestamp")
        return value

    def _resolve_attempt_intent(self, value: object) -> dict[str, object]:
        attempt = self._validate_attempt(
            value, require_cleanup=False, allow_open=True,
        )
        case = self._current_case(str(attempt["case_code"]))
        if case.status == "resolved":
            return self._validate_attempt(attempt, require_cleanup=False)
        receipt = attempt["audit_receipt"]
        fact = attempt["fact"]
        repository_output = None
        if attempt["review_action"] == "corrected":
            if not isinstance(fact, Mapping) or not isinstance(
                fact.get("semantic_fact"), Mapping,
            ):
                raise PermissionError("rich semantic correction recovery is invalid")
            repository_output = _legacy_correction_bindings(
                fact["semantic_fact"], evidence_sha256=str(receipt["evidence_sha256"]),
            )
        self.review_repository.decide(
            ReviewDecision(
                case_code=case.case_code, case_hash=case.case_hash,
                action=str(attempt["review_action"]),
                corrected_output=repository_output,
            ),
            actor_code=str(receipt["actor_code"]),
            decided_at=_timestamp(receipt["decided_at"], "decision timestamp"),
        )
        return self._validate_attempt(attempt, require_cleanup=False)

    def _complete_attempt_cleanup(
        self, value: object, *, path: Path,
    ) -> dict[str, object]:
        attempt = self._validate_attempt(value, require_cleanup=False)
        name = _proposal_path_name(str(attempt["case_code"]))
        (self.proposals / name).unlink(missing_ok=True)
        (self.transient / name).unlink(missing_ok=True)
        cache_targets = (
            self.transient_cache_root / name,
            self.transient_cache_root / f"{attempt['case_code']}.tmp",
        )
        for target in cache_targets:
            target.unlink(missing_ok=True)
        if (
            (self.proposals / name).exists()
            or (self.transient / name).exists()
            or any(target.exists() for target in cache_targets)
        ):
            raise PermissionError("rich semantic projection cleanup did not complete")
        receipt = dict(attempt["audit_receipt"])
        receipt.update({
            "deletion_state": "deleted_after_review",
            "minimized_evidence_deleted": True,
            "projected_at": _utc_timestamp(self.clock()),
            "transient_cache_deleted": True,
        })
        completed = {**attempt, "audit_receipt": receipt}
        self._write(path, completed)
        return self._validate_attempt(completed)

    def _commit_attempt(self, value: object, *, path: Path) -> dict[str, object]:
        attempt = self._validate_attempt(value)
        name = _proposal_path_name(str(attempt["case_code"]))
        if attempt["review_action"] == "rejected":
            self._write(self.receipts / name, attempt["audit_receipt"])
            result = {
                "audit_receipt": attempt["audit_receipt"],
                "fact": None,
                "record_version": self.RECORD_VERSION,
            }
        else:
            result = {
                "audit_receipt": attempt["audit_receipt"],
                "fact": attempt["fact"],
                "record_version": self.RECORD_VERSION,
            }
            self._write(self.reviewed / name, result)
        path.unlink(missing_ok=True)
        return result

    def recover_interrupted(self) -> dict[str, object]:
        recovered: list[str] = []
        pending = tuple(sorted(self.attempts.glob("*.json")))
        if pending and self._decision_signing_secret is None:
            raise PermissionError(
                "rich semantic review signing authority is not configured",
            )
        for temporary in self.root.rglob("*.tmp"):
            temporary.unlink(missing_ok=True)
        for path in pending:
            attempt = self._read(path, "rich semantic projection attempt is unreadable")
            attempt = self._resolve_attempt_intent(attempt)
            attempt = self._complete_attempt_cleanup(attempt, path=path)
            self._commit_attempt(attempt, path=path)
            recovered.append(path.name)
        return {
            "recovered_count": len(recovered),
            "recovery_sha256": _sha256(recovered),
            "state": "complete",
        }

    def _validate_cleanup_attempt(self, value: object) -> dict[str, object]:
        if not isinstance(value, dict) or set(value) != _CLEANUP_ATTEMPT_FIELDS:
            raise PermissionError("rich semantic cleanup attempt is invalid")
        deletions = value.get("deletions")
        if (
            value.get("attempt_version") != self.CLEANUP_ATTEMPT_VERSION
            or not isinstance(deletions, list)
        ):
            raise PermissionError("rich semantic cleanup attempt is invalid")
        case_codes: list[str] = []
        for deletion in deletions:
            if (
                not isinstance(deletion, dict)
                or set(deletion) != _CLEANUP_DELETION_FIELDS
                or not isinstance(deletion.get("case_code"), str)
                or not isinstance(deletion.get("case_hash"), str)
                or not _HASH.fullmatch(str(deletion["case_hash"]))
                or not isinstance(deletion.get("proposal_sha256"), str)
                or not _HASH.fullmatch(str(deletion["proposal_sha256"]))
                or deletion.get("reason") not in {"expired", "orphaned"}
            ):
                raise PermissionError("rich semantic cleanup attempt is invalid")
            case_codes.append(str(deletion["case_code"]))
        if case_codes != sorted(set(case_codes)):
            raise PermissionError("rich semantic cleanup attempt is invalid")
        _timestamp(value.get("created_at"), "cleanup timestamp")
        return value

    def _apply_cleanup_attempt(
        self, value: object, *, recovered_interruption: bool,
    ) -> dict[str, object]:
        attempt = self._validate_cleanup_attempt(value)
        deletions = attempt["deletions"]
        assert isinstance(deletions, list)
        by_code = {
            str(deletion["case_code"]): deletion
            for deletion in deletions
            if isinstance(deletion, Mapping)
        }
        current_cases = self.review_repository.list(kind="classification")
        for case in current_cases:
            deletion = by_code.get(case.case_code)
            if deletion is None:
                continue
            if (
                case.version != "rich_semantic_review_v1"
                or case.status != "open"
                or case.case_hash != deletion["case_hash"]
            ):
                raise PermissionError("rich semantic cleanup case changed after intent")
        kept_cases = [case for case in current_cases if case.case_code not in by_code]
        if by_code:
            self.review_repository.replace_for_kinds(("classification",), kept_cases)
        if self.failpoint is not None and not recovered_interruption:
            self.failpoint("after_cleanup_case_removal")
        for case_code, deletion in by_code.items():
            path = self.proposals / _proposal_path_name(case_code)
            if path.is_symlink():
                raise PermissionError("rich semantic cleanup proposal path is unsafe")
            if path.is_file():
                payload = self._read(
                    path, "rich semantic proposal is unreadable during cleanup",
                )
                if (
                    not isinstance(payload, dict)
                    or not (
                        (
                            set(payload) == _PROPOSAL_ENVELOPE_V1_FIELDS
                            and payload.get("proposal_version")
                            == "rich-semantic-proposal-v1"
                        )
                        or (
                            set(payload) == _PROPOSAL_ENVELOPE_V2_FIELDS
                            and payload.get("proposal_version")
                            == "rich-semantic-proposal-v2"
                        )
                    )
                    or payload.get("case_code") != case_code
                    or payload.get("case_hash") != deletion["case_hash"]
                    or payload.get("proposal_sha256") != deletion["proposal_sha256"]
                ):
                    raise PermissionError("rich semantic cleanup proposal changed after intent")
                path.unlink()
            transient = self.transient / _proposal_path_name(case_code)
            if transient.is_symlink():
                raise PermissionError("rich semantic cleanup transient path is unsafe")
            transient.unlink(missing_ok=True)
        if any(
            (self.proposals / _proposal_path_name(case_code)).exists()
            or (self.transient / _proposal_path_name(case_code)).exists()
            for case_code in by_code
        ):
            raise PermissionError("rich semantic pending cleanup did not complete")
        deleted_codes = sorted(by_code)
        receipt = {
            "cleanup_version": "rich-semantic-pending-cleanup-v3",
            "deleted_at": _utc_timestamp(self.clock()),
            "deleted_cases_sha256": _sha256(deleted_codes),
            "deleted_count": len(deleted_codes),
            "deletion_state": "pending_evidence_deleted",
            "expired_count": sum(
                deletion["reason"] == "expired" for deletion in by_code.values()
            ),
            "orphaned_count": sum(
                deletion["reason"] == "orphaned" for deletion in by_code.values()
            ),
            "recovered_interruption": recovered_interruption,
        }
        self._write(self.root / "cleanup-receipt.json", receipt)
        (self.root / "cleanup-attempt.json").unlink(missing_ok=True)
        return receipt

    def _recover_cleanup_attempt(self) -> bool:
        path = self.root / "cleanup-attempt.json"
        if not path.exists():
            return False
        if path.is_symlink() or not path.is_file():
            raise PermissionError("rich semantic cleanup attempt path is unsafe")
        attempt = self._read(path, "rich semantic cleanup attempt is unreadable")
        self._apply_cleanup_attempt(attempt, recovered_interruption=True)
        return True

    def cleanup_expired(self) -> dict[str, object]:
        """Delete expired or orphaned pending evidence and its open review case."""
        if self._recover_cleanup_attempt():
            receipt = self._read(
                self.root / "cleanup-receipt.json",
                "rich semantic cleanup receipt is unreadable",
            )
            if not isinstance(receipt, dict):
                raise PermissionError("rich semantic cleanup receipt is invalid")
            return receipt
        now = self.clock()
        current_cases = {
            case.case_code: case
            for case in self.review_repository.list(kind="classification")
        }
        deletions: list[dict[str, str]] = []
        for path in sorted(self.proposals.glob("*.json")):
            payload = self._read(path, "rich semantic proposal is unreadable during cleanup")
            if not isinstance(payload, dict):
                raise PermissionError("rich semantic proposal is invalid during cleanup")
            if (
                set(payload) == _PROPOSAL_ENVELOPE_V2_FIELDS
                and payload.get("proposal_version") == "rich-semantic-proposal-v2"
            ):
                identity_corpus_sha256 = payload.get("identity_corpus_sha256")
                if (
                    identity_corpus_sha256 is not None
                    and (
                        not isinstance(identity_corpus_sha256, str)
                        or not _HASH.fullmatch(identity_corpus_sha256)
                    )
                ):
                    raise PermissionError(
                        "rich semantic proposal identity binding is invalid during cleanup",
                    )
            elif (
                set(payload) == _PROPOSAL_ENVELOPE_V1_FIELDS
                and payload.get("proposal_version") == "rich-semantic-proposal-v1"
            ):
                identity_corpus_sha256 = None
            else:
                raise PermissionError("rich semantic proposal is invalid during cleanup")
            proposal = _normalize_proposal(
                payload["proposal"], now=now, allow_expired=True,
            )
            case = _case_for(
                proposal, review_context_hashes=self.review_context_hashes,
                identity_corpus_sha256=identity_corpus_sha256,
            )
            if (
                payload["case_code"] != case.case_code
                or payload["case_hash"] != case.case_hash
                or payload["proposal_sha256"] != _sha256(proposal)
            ):
                raise PermissionError("rich semantic proposal was tampered during cleanup")
            current = current_cases.get(case.case_code)
            reason = (
                "orphaned"
                if current is None
                else "expired"
                if _timestamp(proposal["expires_at"], "expiry") <= now.astimezone(UTC)
                else None
            )
            if reason is not None:
                if current is not None and (
                    current.status != "open" or current.case_hash != case.case_hash
                ):
                    raise PermissionError("expired rich semantic proposal has a non-open case")
                deletions.append({
                    "case_code": case.case_code,
                    "case_hash": case.case_hash,
                    "proposal_sha256": str(payload["proposal_sha256"]),
                    "reason": reason,
                })

        attempt = {
            "attempt_version": self.CLEANUP_ATTEMPT_VERSION,
            "created_at": _utc_timestamp(now),
            "deletions": sorted(deletions, key=lambda item: item["case_code"]),
        }
        self._validate_cleanup_attempt(attempt)
        self._write(self.root / "cleanup-attempt.json", attempt)
        return self._apply_cleanup_attempt(attempt, recovered_interruption=False)

    @staticmethod
    def _validate_fact(value: object) -> dict[str, object]:
        if not isinstance(value, dict):
            raise PermissionError("rich semantic reviewed fact is invalid")
        version = value.get("fact_version")
        expected_fields = (
            _CURRENT_FACT_FIELDS
            if version == "rich-semantic-reviewed-fact-v4"
            else _V3_FACT_FIELDS
            if version == "rich-semantic-reviewed-fact-v3"
            else _FACT_FIELDS
            if version == "rich-semantic-reviewed-fact-v2"
            else _LEGACY_FACT_FIELDS
            if version == "rich-semantic-reviewed-fact-v1"
            else None
        )
        if expected_fields is None or set(value) != expected_fields:
            raise PermissionError("rich semantic reviewed fact is invalid")
        semantic = value.get("semantic_fact")
        provenance = value.get("provenance")
        if (
            value.get("review_action") not in {"approved", "corrected"}
            or not isinstance(value.get("subject_ref"), str)
            or not _SUBJECT.fullmatch(str(value["subject_ref"]))
            or not isinstance(semantic, dict)
            or set(semantic) != set(_FACT_DIMENSIONS)
            or any(semantic[field] not in ASSESSMENT_ENUMS[field] for field in _FACT_DIMENSIONS)
            or value.get("confidence") not in ASSESSMENT_ENUMS["cross_source_confidence"]
            or not isinstance(value.get("unknown_state"), list)
            or value["unknown_state"] != sorted(set(value["unknown_state"]))
            or not isinstance(provenance, dict)
            or set(provenance) != _PROVENANCE_FIELDS
        ):
            raise PermissionError("rich semantic reviewed fact is invalid")
        if version in {
            "rich-semantic-reviewed-fact-v2",
            "rich-semantic-reviewed-fact-v3",
            "rich-semantic-reviewed-fact-v4",
        } and (
            not isinstance(value.get("reason_codes"), list)
            or value["reason_codes"] != sorted(set(value["reason_codes"]))
            or not value["reason_codes"]
            or any(reason not in REASON_CODES for reason in value["reason_codes"])
        ):
            raise PermissionError("rich semantic reviewed fact is invalid")
        if version in {
            "rich-semantic-reviewed-fact-v3",
            "rich-semantic-reviewed-fact-v4",
        }:
            try:
                taxonomy = validate_semantic_taxonomy_fact(
                    value.get("semantic_taxonomy"),
                )
            except ValueError as error:
                raise PermissionError(
                    "rich semantic reviewed taxonomy is invalid",
                ) from error
            project_evidence_reviewed = any(
                source in provenance["source_coverage"]
                for source in ("application", "devpost", "projects")
            )
            expected_overlap = {
                "product_maturity": semantic["product_maturity"],
                "technical_depth": semantic["technical_depth"],
                "execution_scope": semantic["execution_scope"],
                "external_validation": (
                    "unknown"
                    if not project_evidence_reviewed
                    else "none_observed"
                    if semantic["external_validation"] == "none"
                    else semantic["external_validation"]
                ),
                "problem_differentiation": semantic["originality"],
            }
            taxonomy_refs = {
                reference
                for references in taxonomy.evidence_by_dimension.values()
                for reference in references
            }
            if (
                taxonomy.builder_tier != semantic["builder_level"]
                or any(
                    taxonomy.project[field] != expected
                    for field, expected in expected_overlap.items()
                )
                or taxonomy_refs != set(provenance["evidence_refs"])
            ):
                raise PermissionError(
                    "rich semantic reviewed taxonomy is tampered or invalid",
                )
        if version == "rich-semantic-reviewed-fact-v4":
            narrative = value.get("reviewed_narrative")
            if (
                not isinstance(narrative, dict)
                or set(narrative) != _NARRATIVE_FIELDS
                or narrative.get("narrative_version") != _NARRATIVE_VERSION
                or (
                    narrative.get("identity_corpus_sha256") is not None
                    and (
                        not isinstance(
                            narrative.get("identity_corpus_sha256"), str,
                        )
                        or not _HASH.fullmatch(
                            str(narrative["identity_corpus_sha256"]),
                        )
                    )
                )
            ):
                raise PermissionError("rich semantic reviewed narrative is invalid")
            for kind, prefixes in (
                ("project", ("application_", "devpost_", "project_")),
                ("career", ("role_",)),
            ):
                item = narrative.get(kind)
                if (
                    not isinstance(item, dict)
                    or set(item) != _NARRATIVE_ITEM_FIELDS
                    or item.get("confidence") != value.get("confidence")
                    or item.get("state") not in {"reviewed", "unknown"}
                    or not isinstance(item.get("text"), str)
                    or len(item["text"]) > 500
                    or not isinstance(item.get("evidence_refs"), list)
                    or item["evidence_refs"] != sorted(set(item["evidence_refs"]))
                    or any(
                        not isinstance(reference, str)
                        or not reference.startswith(prefixes)
                        or reference not in provenance["evidence_refs"]
                        for reference in item["evidence_refs"]
                    )
                    or (
                        item["state"] == "reviewed"
                        and (not item["text"] or not item["evidence_refs"])
                    )
                    or (
                        item["state"] == "unknown"
                        and (item["text"] != "" or item["evidence_refs"] != [])
                    )
                ):
                    raise PermissionError(
                        "rich semantic reviewed narrative is invalid",
                    )
                try:
                    assert_safe_semantic_payload(
                        {"text": item["text"]}, max_total_chars=1_000,
                        allowed_keys={"text"},
                    )
                except (TypeError, ValueError) as error:
                    raise PermissionError(
                        "rich semantic reviewed narrative is unsafe",
                    ) from error
            if (
                narrative["identity_corpus_sha256"] is None
                and any(
                    narrative[kind]["state"] == "reviewed"
                    for kind in ("project", "career")
                )
            ):
                raise PermissionError(
                    "rich semantic reviewed narrative lacks identity binding",
                )
        if (
            provenance["model"] not in MODEL_ALLOWLIST
            or provenance["prompt_version"] != PROMPT_VERSION
            or provenance["schema_sha256"] != rich_semantic_schema_sha256()
            or any(
                not isinstance(provenance[field], str) or not _HASH.fullmatch(provenance[field])
                for field in (
                    "approval_sha256", "assessment_sha256", "evidence_sha256",
                    "model_sha256", "prompt_sha256", "schema_sha256",
                )
            )
            or not isinstance(provenance["source_coverage"], list)
            or provenance["source_coverage"] != sorted(set(provenance["source_coverage"]))
            or any(source not in _SOURCE_FAMILIES for source in provenance["source_coverage"])
            or not isinstance(provenance["evidence_refs"], list)
        ):
            raise PermissionError("rich semantic reviewed provenance is invalid")
        _timestamp(value["reviewed_at"], "review timestamp")
        return value

    def _load_reviewed_record(self, path: Path) -> dict[str, object]:
        if path.is_symlink() or path.parent.resolve() != self.reviewed:
            raise PermissionError("rich semantic reviewed record path is unsafe")
        record = self._read(path, "rich semantic reviewed record is unreadable")
        if not isinstance(record, dict) or set(record) != _RECORD_FIELDS:
            raise PermissionError("rich semantic reviewed record is invalid")
        if record["record_version"] != self.RECORD_VERSION:
            raise PermissionError("rich semantic reviewed record is invalid")
        receipt = record.get("audit_receipt")
        if (
            not isinstance(receipt, Mapping)
            or path.name != _proposal_path_name(str(receipt.get("case_code", "")))
        ):
            raise PermissionError("rich semantic reviewed record filename is invalid")
        fact = self._validate_fact(record["fact"])
        self._validate_final_receipt(record["audit_receipt"], fact=fact)
        return record

    def _validate_final_receipt(
        self, value: object, *, fact: Mapping[str, object] | None,
    ) -> dict[str, object]:
        try:
            receipt = self._validate_receipt_shape(value)
        except PermissionError as error:
            raise PermissionError("rich semantic final receipt is invalid") from error
        if (
            fact is not None
            and fact.get("fact_version") in {
                "rich-semantic-reviewed-fact-v2",
                "rich-semantic-reviewed-fact-v3",
                "rich-semantic-reviewed-fact-v4",
            }
            and receipt["receipt_version"] not in {
                self.RECEIPT_VERSION, self.MANIFEST_RECEIPT_VERSION,
            }
        ):
            raise PermissionError(
                "rich semantic v2 fact cannot use a legacy review receipt",
            )
        case = self._current_case(str(receipt["case_code"]))
        expected_action = "rejected" if fact is None else fact["review_action"]
        expected_fact_hash = None if fact is None else _sha256(fact)
        if (
            receipt["receipt_version"] not in {
                self.RECEIPT_VERSION, self.MANIFEST_RECEIPT_VERSION,
                self.LEGACY_RECEIPT_VERSION,
            }
            or receipt["fact_sha256"] != expected_fact_hash
            or receipt["review_action"] != expected_action
            or not isinstance(receipt["proposal_sha256"], str)
            or not _HASH.fullmatch(receipt["proposal_sha256"])
            or not isinstance(receipt["assessment_sha256"], str)
            or not _HASH.fullmatch(receipt["assessment_sha256"])
            or not isinstance(receipt["evidence_sha256"], str)
            or not _HASH.fullmatch(receipt["evidence_sha256"])
            or receipt["deletion_state"] != "deleted_after_review"
            or receipt["minimized_evidence_deleted"] is not True
            or receipt["transient_cache_deleted"] is not True
            or not isinstance(receipt["projected_at"], str)
            or receipt["actor_code"] != case.decision.actor_code
            or receipt["decided_at"] != case.decision.decided_at
        ):
            raise PermissionError("rich semantic final receipt was tampered")
        if fact is not None and (
            receipt["assessment_sha256"] != fact["provenance"]["assessment_sha256"]
            or receipt["evidence_sha256"] != fact["provenance"]["evidence_sha256"]
            or fact["reviewed_at"] != receipt["decided_at"]
        ):
            raise PermissionError("rich semantic reviewed record was tampered")
        if (
            case.case_hash != receipt["case_hash"]
            or case.status != "resolved"
            or case.decision is None
            or case.decision.action != receipt["review_action"]
        ):
            raise PermissionError("rich semantic final receipt is not current")
        _timestamp(receipt["decided_at"], "decision timestamp")
        _timestamp(receipt["projected_at"], "projection timestamp")
        return receipt

    def _load_rejected_receipt(self, path: Path) -> dict[str, object]:
        receipt = self._read(path, "rich semantic rejection receipt is unreadable")
        return self._validate_final_receipt(receipt, fact=None)

    def finalized_case_codes(self) -> frozenset[str]:
        """Return only current resolved cases with a fully validated final record."""

        finalized: set[str] = set()
        for case in self.review_repository.list(kind="classification"):
            if case.version != "rich_semantic_review_v1" or case.status != "resolved":
                continue
            reviewed_path = self.reviewed / _proposal_path_name(case.case_code)
            receipt_path = self.receipts / _proposal_path_name(case.case_code)
            if reviewed_path.is_symlink() or receipt_path.is_symlink():
                continue
            if reviewed_path.is_file() == receipt_path.is_file():
                continue
            try:
                if reviewed_path.is_file():
                    self._load_reviewed_record(reviewed_path)
                else:
                    self._load_rejected_receipt(receipt_path)
            except PermissionError:
                continue
            finalized.add(case.case_code)
        return frozenset(finalized)

    def source_coverage_counts(self) -> dict[str, int]:
        """Count source coverage only from validated current proposals or facts."""

        coverage = {source: 0 for source in _SOURCE_FAMILIES}
        finalized = self.finalized_case_codes()
        for case in self.review_repository.list(kind="classification"):
            if case.version != "rich_semantic_review_v1":
                continue
            try:
                if case.status == "open":
                    proposal, _, _, _ = self._load_proposal(case.case_code)
                    sources = proposal["source_coverage"]
                elif case.case_code in finalized:
                    path = self.reviewed / _proposal_path_name(case.case_code)
                    if not path.is_file() or path.is_symlink():
                        continue
                    record = self._load_reviewed_record(path)
                    sources = record["fact"]["provenance"]["source_coverage"]
                else:
                    continue
            except PermissionError:
                continue
            if not isinstance(sources, list):
                continue
            for source in _SOURCE_FAMILIES:
                if source in sources:
                    coverage[source] += 1
        return coverage

    def semantic_release_qa_evidence(
        self, *, sample_limit: int = 10,
    ) -> dict[str, object]:
        """Derive code-only release-review evidence from authenticated final records."""

        from community_os.semantic_metrics import (
            matching_metric_keys,
            partner_report_taxonomy_claim_keys,
        )

        if type(sample_limit) is not int or not 1 <= sample_limit <= 100:
            raise ValueError("semantic release QA sample limit is invalid")
        positive_claims: list[str] = []
        required_cases: list[str] = []
        resolved_required_cases: list[str] = []
        for case in self.review_repository.list(kind="classification"):
            if case.version != "rich_semantic_review_v1" or case.status != "resolved":
                continue
            reviewed_path = self.reviewed / _proposal_path_name(case.case_code)
            rejected_path = self.receipts / _proposal_path_name(case.case_code)
            if reviewed_path.is_file() == rejected_path.is_file():
                raise PermissionError(
                    "rich semantic release QA review outcome is incomplete",
                )
            if rejected_path.is_file():
                receipt = self._load_rejected_receipt(rejected_path)
                required_cases.append(_sha256({
                    "case_hash": case.case_hash,
                    "review_action": "rejected",
                }))
                if self._authenticated_human_decision(receipt):
                    resolved_required_cases.append(required_cases[-1])
                continue

            record = self._load_reviewed_record(reviewed_path)
            receipt = record["audit_receipt"]
            fact = record["fact"]
            assert isinstance(receipt, Mapping)
            assert isinstance(fact, Mapping)
            confidence = str(fact["confidence"])
            action = str(fact["review_action"])
            authenticated_human = self._authenticated_human_decision(receipt)
            human_required = confidence == "low" or action == "corrected"
            if human_required:
                required_case = _sha256({
                    "case_hash": case.case_hash,
                    "review_action": action,
                })
                required_cases.append(required_case)
                if authenticated_human:
                    resolved_required_cases.append(required_case)

            provenance = fact["provenance"]
            semantic = fact["semantic_fact"]
            assert isinstance(provenance, Mapping)
            assert isinstance(semantic, Mapping)
            references = provenance["evidence_refs"]
            assert isinstance(references, list)
            eligible = fact.get("fact_version") in {
                "rich-semantic-reviewed-fact-v3",
                "rich-semantic-reviewed-fact-v4",
            } and bool(
                references,
            ) and (
                authenticated_human
                or (confidence != "low" and action == "approved")
            )
            if not eligible:
                continue
            fact_sha256 = _sha256(fact)
            claim_keys = [
                *(f"metric:{key}" for key in matching_metric_keys(semantic)),
                *(
                    f"taxonomy:{key}"
                    for key in partner_report_taxonomy_claim_keys({
                        family: fact["semantic_taxonomy"][family]
                        for family in ("career", "project")
                    })
                ),
            ]
            for metric_key in claim_keys:
                positive_claims.append(_sha256({
                    "case_hash": case.case_hash,
                    "fact_sha256": fact_sha256,
                    "metric_key": metric_key,
                }))

        positive_claims.sort()
        required_cases.sort()
        resolved_required_cases.sort()
        if not set(resolved_required_cases) <= set(required_cases):
            raise PermissionError("semantic release QA review evidence is inconsistent")
        sample = positive_claims[:sample_limit]
        evidence = {
            "positive_claim_count": len(positive_claims),
            "positive_claim_sample_count": len(sample),
            "positive_claims_sha256": _sha256(positive_claims),
            "required_review_case_count": len(required_cases),
            "required_review_cases_resolved": len(resolved_required_cases),
        }
        return {
            **evidence,
            "review_evidence_sha256": _sha256({
                **evidence,
                "positive_claim_sample_sha256": _sha256(sample),
                "required_cases_sha256": _sha256(required_cases),
                "resolved_required_cases_sha256": _sha256(
                    resolved_required_cases,
                ),
            }),
        }

    def build_population_aggregate(
        self,
        *,
        expected_subject_refs: list[str] | tuple[str, ...],
        binding_context: Mapping[str, str],
        generated_at: datetime,
        minimum_group_size: int = 5,
        membership_by_subject: Mapping[str, Mapping[str, str]] | None = None,
        reviewed_cohort_totals: Mapping[str, int] | None = None,
    ) -> dict[str, object] | dict[str, dict[str, object]]:
        """Project terminal review outcomes onto one authoritative population."""

        from community_os.semantic_metrics import (
            FACT_VERSION,
            build_semantic_aggregate,
            build_semantic_cohort_aggregate_bundle,
            metric_registry_sha256,
            population_snapshot_sha256,
        )

        subjects = tuple(expected_subject_refs)
        if (
            not subjects
            or subjects != tuple(sorted(set(subjects)))
            or any(not isinstance(subject, str) or not _SUBJECT.fullmatch(subject) for subject in subjects)
        ):
            raise ValueError("rich semantic population subjects are invalid")
        if (
            not isinstance(binding_context, Mapping)
            or set(binding_context) != _POPULATION_CONTEXT_KEYS
            or any(not isinstance(value, str) or not value for value in binding_context.values())
        ):
            raise ValueError("rich semantic population binding context is invalid")
        normalized_membership: dict[str, dict[str, str]] | None = None
        if membership_by_subject is not None:
            if (
                not isinstance(membership_by_subject, Mapping)
                or set(membership_by_subject) != set(subjects)
            ):
                raise ValueError(
                    "rich semantic cohort membership subjects do not reconcile"
                )
            normalized_membership = {}
            for subject in subjects:
                membership = membership_by_subject[subject]
                if (
                    not isinstance(membership, Mapping)
                    or set(membership) != {"applied", "accepted", "present"}
                    or any(
                        membership[key] not in {"member", "not_member", "unknown"}
                        for key in ("applied", "accepted", "present")
                    )
                ):
                    raise ValueError(
                        "rich semantic cohort membership state is invalid"
                    )
                normalized_membership[subject] = {
                    key: str(membership[key])
                    for key in ("applied", "accepted", "present")
                }
        elif reviewed_cohort_totals is not None:
            raise ValueError(
                "reviewed cohort totals require person membership evidence",
            )

        subject_by_code: dict[str, str] = {}
        for subject in subjects:
            code = _subject_code(subject)
            if code in subject_by_code:
                raise PermissionError("rich semantic population subject codes collide")
            subject_by_code[code] = subject
        cases = tuple(
            case for case in self.review_repository.list(kind="classification")
            if case.version == "rich_semantic_review_v1"
        )
        cases_by_subject: dict[str, ReviewCase] = {}
        for case in cases:
            if case.subject_code not in subject_by_code or case.subject_code in cases_by_subject:
                raise PermissionError("rich semantic review case does not match population")
            cases_by_subject[case.subject_code] = case
        if set(cases_by_subject) != set(subject_by_code):
            raise PermissionError("rich semantic review cases do not cover population")
        if any(case.status != "resolved" or case.decision is None for case in cases):
            raise PermissionError("rich semantic population review remains open")

        source_map = {
            "application": "application",
            "career": "career_context",
            "devpost": "event_submission",
            "projects": "public_projects",
        }
        facts: list[dict[str, object]] = []
        for subject in subjects:
            case = cases_by_subject[_subject_code(subject)]
            assert case.decision is not None
            trusted_human = False
            state = "conflict"
            reasons = ["semantic_evidence_conflict"]
            confidence = "unknown"
            dimensions: dict[str, object] = {key: None for key in _FACT_DIMENSIONS}
            taxonomy: dict[str, object] | None = None
            evidence_refs: list[str] = []
            scopes = {source: "conflict" for source in source_map.values()}
            review_states = {
                "agent": "not_reviewed", "human": "not_required",
                "model": "not_run", "system": "valid",
            }

            if case.decision.action == "rejected":
                receipt_path = self.receipts / _proposal_path_name(case.case_code)
                receipt = self._load_rejected_receipt(receipt_path)
                trusted_human = self._authenticated_human_decision(receipt)
                if trusted_human:
                    state = "rejected"
                    reasons = ["semantic_review_rejected"]
                    review_states = {
                        "agent": "reviewed", "human": "rejected",
                        "model": "complete", "system": "valid",
                    }
            else:
                record_path = self.reviewed / _proposal_path_name(case.case_code)
                record = self._load_reviewed_record(record_path)
                receipt = record["audit_receipt"]
                assert isinstance(receipt, Mapping)
                trusted_human = self._authenticated_human_decision(receipt)
                reviewed = record["fact"]
                assert isinstance(reviewed, Mapping)
                provenance = reviewed["provenance"]
                semantic = reviewed["semantic_fact"]
                assert isinstance(provenance, Mapping)
                assert isinstance(semantic, Mapping)
                coverage = provenance["source_coverage"]
                assert isinstance(coverage, list)
                scopes = {
                    target: "observed" if source in coverage else "not_provided"
                    for source, target in source_map.items()
                }
                review_states = {
                    "agent": "reviewed",
                    "human": (
                        str(reviewed["review_action"])
                        if trusted_human else "not_required"
                    ),
                    "model": "complete", "system": "valid",
                }
                version = reviewed["fact_version"]
                refs = provenance["evidence_refs"]
                assert isinstance(refs, list)
                if version in {
                    "rich-semantic-reviewed-fact-v3",
                    "rich-semantic-reviewed-fact-v4",
                } and refs and (
                    trusted_human
                    or (
                        reviewed["confidence"] != "low"
                        and reviewed["review_action"] == "approved"
                    )
                ):
                    state = "assessed"
                    reasons = list(reviewed["reason_codes"])
                    confidence = str(reviewed["confidence"])
                    dimensions = {key: semantic[key] for key in _FACT_DIMENSIONS}
                    taxonomy_value = reviewed["semantic_taxonomy"]
                    assert isinstance(taxonomy_value, dict)
                    taxonomy = dict(taxonomy_value)
                    evidence_refs = sorted(set(refs))
                elif version in {
                    "rich-semantic-reviewed-fact-v3",
                    "rich-semantic-reviewed-fact-v4",
                } and not refs and (
                    semantic["builder_level"] == "insufficient"
                    and semantic["product_maturity"] == "unknown"
                    and semantic["technical_depth"] == "unknown"
                    and semantic["execution_scope"] == "unknown"
                    and semantic["external_validation"] == "unknown"
                    and semantic["originality"] == "unknown"
                ):
                    state = "no_evidence"
                    reasons = sorted(set(
                        list(reviewed["reason_codes"]) + ["no_semantic_evidence"],
                    ))
                    scopes = {source: "not_provided" for source in source_map.values()}

            bindings = {
                **dict(binding_context),
                "metric_registry_sha256": metric_registry_sha256(),
                "metric_registry_version": "partner-metrics-v1",
                "population_key": "all_applicants",
                "population_sha256": "0" * 64,
            }
            facts.append({
                "assessment_state": state,
                "bindings": bindings,
                "cohort_membership": {
                    "accepted": (
                        normalized_membership[subject]["accepted"]
                        if normalized_membership is not None else "unknown"
                    ),
                    "applied": (
                        normalized_membership[subject]["applied"]
                        if normalized_membership is not None else "member"
                    ),
                    "present": (
                        normalized_membership[subject]["present"]
                        if normalized_membership is not None else "unknown"
                    ),
                    "submitted": "unknown",
                },
                "confidence": confidence,
                "evidence_refs": evidence_refs,
                "evidence_scopes": scopes,
                "fact_version": FACT_VERSION,
                "population_key": "all_applicants",
                "reason_codes": reasons,
                "review_states": review_states,
                "semantic_dimensions": dimensions,
                "semantic_taxonomy": taxonomy,
                "subject_ref": subject,
            })

        population_sha256 = population_snapshot_sha256(facts)
        for fact in facts:
            bindings = fact["bindings"]
            assert isinstance(bindings, dict)
            bindings["population_sha256"] = population_sha256
        if normalized_membership is not None:
            return build_semantic_cohort_aggregate_bundle(
                facts,
                generated_at=generated_at,
                expected_subject_refs=list(subjects),
                minimum_group_size=minimum_group_size,
                reviewed_cohort_totals=reviewed_cohort_totals,
            )
        return build_semantic_aggregate(
            facts,
            generated_at=generated_at,
            expected_subject_refs=list(subjects),
            minimum_group_size=minimum_group_size,
        )

    def build_aggregate(self, *, minimum_group_size: int = 5) -> dict[str, object]:
        if type(minimum_group_size) is not int or minimum_group_size < 5:
            raise ValueError("rich semantic aggregate minimum group size must be at least five")
        facts = [
            self._load_reviewed_record(path)["fact"]
            for path in sorted(self.reviewed.glob("*.json"))
        ]
        dimensions: dict[str, object] = {}
        for dimension in _AGGREGATE_DIMENSIONS:
            values = [
                fact["confidence"] if dimension == "cross_source_confidence"
                else fact["semantic_fact"][dimension]
                for fact in facts
            ]
            counts = Counter(values)
            cells = _privacy_safe_cells(
                counts, sorted(ASSESSMENT_ENUMS[dimension]),
                minimum_group_size=minimum_group_size,
            )
            dimensions[dimension] = {
                "cells": cells,
                "denominator": len(values),
                "unknown_cell": cells.get(
                    "unknown", {"count": None, "state": "withheld"},
                ),
            }
        impressive_values = [_impressive_band(fact) for fact in facts]
        impressive_counts = Counter(impressive_values)
        impressive_cells = _privacy_safe_cells(
            impressive_counts, list(_IMPRESSIVE_BANDS),
            minimum_group_size=minimum_group_size,
        )
        dimensions["impressive_band"] = {
            "cells": impressive_cells,
            "denominator": len(impressive_values),
            "unknown_cell": impressive_cells["unknown"],
        }
        source_coverage = {
            source: sum(
                source in fact["provenance"]["source_coverage"]
                for fact in facts
            )
            for source in _SOURCE_FAMILIES
        }
        return {
            "aggregate_version": "rich-semantic-internal-aggregate-v4",
            "dimensions": dimensions,
            "generated_at": _utc_timestamp(self.clock()),
            "internal_only": True,
            "minimum_group_size": minimum_group_size,
            "release_eligible": False,
            "reviewed_denominator": len(facts),
            "source_coverage": source_coverage,
        }
