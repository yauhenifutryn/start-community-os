"""Versioned semantic classification with minimum-necessary structured AI egress."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
import hashlib
import json
import re
from typing import Callable, Mapping

from community_os.enrichment.cache import CanonicalJsonCache


_SIGNAL_KEYS = frozenset({"occupation_codes", "experience_band", "builder_codes"})
_LEGACY_PROCESSOR_FIELDS = frozenset({"subject_ref", "signals", "evidence_refs"})
_RICH_SEMANTIC_PROCESSOR_PURPOSE = "rich_semantic_assessment"
_DIMENSION_KEYS = frozenset({
    "professional_identity", "seniority", "functional_role", "employer_pedigree",
    "builder_evidence", "capabilities", "domains",
})
_EXCLUSIVE_DIMENSIONS = frozenset({"seniority", "employer_pedigree"})
DIMENSION_LABELS: dict[str, frozenset[str]] = {
    "professional_identity": frozenset({
        "founder_cofounder", "startup_operator", "researcher_academic",
        "insufficient_evidence",
    }),
    "seniority": frozenset({
        "student", "junior", "mid_level", "senior", "lead_staff_executive",
        "founder", "unknown",
    }),
    "functional_role": frozenset({
        "engineering", "data_ai", "product", "design", "commercial",
        "operations", "research", "unknown",
    }),
    "employer_pedigree": frozenset({
        "academia_research", "self_employed_founder", "student_no_employer", "unknown",
    }),
    "builder_evidence": frozenset({
        "founded_company", "shipped_product", "github_supplied", "active_github",
        "hackathon_submission", "insufficient_evidence",
    }),
    "capabilities": frozenset({
        "backend", "frontend", "ai_ml", "data", "cloud", "mobile", "product",
        "design", "growth", "security", "unknown",
    }),
    "domains": frozenset({
        "applied_ai", "developer_tools", "fintech", "cybersecurity", "marketplaces",
        "climate", "health", "education", "enterprise", "unknown",
    }),
}
UNKNOWN_LABELS = {
    "professional_identity": "insufficient_evidence",
    "seniority": "unknown", "functional_role": "unknown",
    "employer_pedigree": "unknown", "builder_evidence": "insufficient_evidence",
    "capabilities": "unknown", "domains": "unknown",
}
_CONSEQUENTIAL = frozenset({
    "founder_cofounder", "founder", "lead_staff_executive", "self_employed_founder",
})
_OCCUPATION_CODES = frozenset({"unknown"}).union(*(
    {f"{prefix}_{label}" for label in DIMENSION_LABELS[dimension]}
    for dimension, prefix in (
        ("professional_identity", "identity"), ("functional_role", "role"),
        ("employer_pedigree", "employer"), ("capabilities", "capability"),
        ("domains", "domain"),
    )
))
_BUILDER_CODES = frozenset({
    *(f"builder_{label}" for label in DIMENSION_LABELS["builder_evidence"]),
    "github_repos_none", "github_repos_few", "github_repos_many",
    "github_account_new", "github_account_established", "public_page_observed",
    "coresignal_company_unknown", "coresignal_company_startup",
    "coresignal_company_scaleup", "coresignal_company_venture_backed_startup",
    "coresignal_company_enterprise", "coresignal_company_academia_research",
    "coresignal_title_unknown", "coresignal_title_software_engineering",
    "coresignal_founder_history",
})
_CODE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_EVIDENCE = re.compile(r"^evidence:[a-z_]+:[a-z0-9]{3,128}$")
_PID = re.compile(r"^pid:[A-Za-z0-9._-]{1,32}:[0-9a-f]{64}$")


def _codes(value: object) -> list[str]:
    values = value if isinstance(value, list) else [value]
    if any(not isinstance(item, str) or not _CODE.fullmatch(item) for item in values):
        raise ValueError("classification signals must contain machine-readable codes")
    return list(values)


@dataclass(frozen=True)
class ClassificationInput:
    subject_ref: str
    signals: Mapping[str, object]
    evidence_refs: tuple[str, ...]

    def __post_init__(self) -> None:
        if not _PID.fullmatch(self.subject_ref):
            raise ValueError("classification subject must be pseudonymous")
        if set(self.signals) != _SIGNAL_KEYS:
            raise ValueError("classification signals do not match the field allowlist")
        normalized = {
            "occupation_codes": _codes(self.signals["occupation_codes"]),
            "experience_band": _codes(self.signals["experience_band"])[0],
            "builder_codes": _codes(self.signals["builder_codes"]),
        }
        if (
            any(value not in _OCCUPATION_CODES for value in normalized["occupation_codes"])
            or normalized["experience_band"] not in DIMENSION_LABELS["seniority"]
            or any(value not in _BUILDER_CODES for value in normalized["builder_codes"])
        ):
            raise ValueError("classification signals contain a value outside the local allowlist")
        if any(not _EVIDENCE.fullmatch(value) for value in self.evidence_refs):
            raise ValueError("classification evidence references are invalid")
        object.__setattr__(self, "signals", normalized)

    def provider_payload(self) -> dict[str, object]:
        return {
            "evidence_refs": list(self.evidence_refs),
            "signals": dict(self.signals),
            "subject_ref": self.subject_ref,
        }


@dataclass(frozen=True)
class ProcessorApproval:
    provider: str
    purpose: str
    dpa_version: str
    terms_version: str
    retention_mode: str
    region: str
    security_profile: str
    field_allowlist: frozenset[str]
    approved_by: str
    approved_at: str
    payload_version: str | None = None

    @classmethod
    def from_record(cls, value: object) -> "ProcessorApproval":
        expected = {
            "provider", "purpose", "dpa_version", "terms_version", "retention_mode",
            "region", "security_profile", "field_allowlist", "approved_by", "approved_at",
        }
        if not isinstance(value, dict) or frozenset(value) not in {
            frozenset(expected), frozenset(expected.union({"payload_version"})),
        }:
            raise PermissionError("AI processor approval record is incomplete")
        fields = value["field_allowlist"]
        if not isinstance(fields, list) or any(not isinstance(item, str) for item in fields):
            raise PermissionError("AI processor field allowlist is invalid")
        payload_version = value.get("payload_version")
        if payload_version is not None and (
            not isinstance(payload_version, str) or not payload_version.strip()
        ):
            raise PermissionError("AI processor payload version is invalid")
        return cls(
            provider=str(value["provider"]), purpose=str(value["purpose"]),
            dpa_version=str(value["dpa_version"]), terms_version=str(value["terms_version"]),
            retention_mode=str(value["retention_mode"]), region=str(value["region"]),
            security_profile=str(value["security_profile"]),
            field_allowlist=frozenset(fields), approved_by=str(value["approved_by"]),
            approved_at=str(value["approved_at"]),
            payload_version=payload_version,
        )

    def to_record(self) -> dict[str, object]:
        record: dict[str, object] = {
            "provider": self.provider, "purpose": self.purpose,
            "dpa_version": self.dpa_version, "terms_version": self.terms_version,
            "retention_mode": self.retention_mode, "region": self.region,
            "security_profile": self.security_profile,
            "field_allowlist": sorted(self.field_allowlist),
            "approved_by": self.approved_by, "approved_at": self.approved_at,
        }
        if self.payload_version is not None:
            record["payload_version"] = self.payload_version
        return record

    def authorize(self, *, now: datetime | None = None) -> None:
        values = (
            self.provider, self.purpose, self.dpa_version, self.terms_version, self.region,
            self.security_profile, self.approved_by, self.approved_at,
        )
        if any(not isinstance(value, str) or not value.strip() for value in values):
            raise PermissionError("AI processor approval record is incomplete")
        # PRIVACY_CEILING: each region/retention pair is an explicit reviewed posture;
        # broader retention or routing requires a new failing test and approval record.
        approved_postures = {
            ("eu", "zero_retention"),
            ("global", "default_abuse_monitoring_30d"),
        }
        if (self.region, self.retention_mode) not in approved_postures:
            raise PermissionError("AI processor region and retention posture are not approved")
        if (
            self.region == "global"
            and self.security_profile != "project_scoped_store_false_minimized_v1"
        ):
            raise PermissionError("AI processor global security profile is not approved")
        legacy_contract = (
            self.purpose == "talent_classification"
            and self.payload_version is None
            and self.field_allowlist == _LEGACY_PROCESSOR_FIELDS
        )
        rich_contract = (
            self.purpose == _RICH_SEMANTIC_PROCESSOR_PURPOSE
            and isinstance(self.payload_version, str)
            and bool(self.payload_version.strip())
            and bool(self.field_allowlist)
            and all(
                isinstance(field, str) and _CODE.fullmatch(field)
                for field in self.field_allowlist
            )
        )
        if not legacy_contract and not rich_contract:
            raise PermissionError("AI processor purpose, version, or field allowlist is not approved")
        if self.approved_by != "start_privacy_owner":
            raise PermissionError("AI processor purpose or approver is not approved")
        try:
            parsed = datetime.fromisoformat(self.approved_at.replace("Z", "+00:00"))
        except ValueError as error:
            raise PermissionError("AI processor approval timestamp is invalid") from error
        if parsed.tzinfo is None:
            raise PermissionError("AI processor approval timestamp requires a timezone")
        if now is not None:
            if now.tzinfo is None:
                raise PermissionError("AI processor authorization time requires a timezone")
            if parsed > now:
                raise PermissionError("AI processor approval cannot be future dated")

    def authorize_payload(
        self, *, purpose: str, payload_version: str | None,
        field_allowlist: frozenset[str], now: datetime | None = None,
    ) -> None:
        """Require the approval to match the exact outbound structured contract."""

        self.authorize(now=now)
        if (
            self.purpose != purpose
            or self.payload_version != payload_version
            or self.field_allowlist != field_allowlist
        ):
            raise PermissionError(
                "AI processor approval does not match the requested payload contract"
            )

    def authorization_hash(self, *, now: datetime | None = None) -> str:
        self.authorize(now=now)
        record = self.to_record()
        canonical = json.dumps(record, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class SemanticClassifier:
    def __init__(
        self, *, provider: Callable[[dict[str, object]], dict[str, object]],
        cache: CanonicalJsonCache, clock: Callable[[], datetime], approval: ProcessorApproval,
        model: str, prompt_version: str, taxonomy_version: str, classifier_version: str,
    ) -> None:
        self.provider = provider
        self.cache = cache
        self.clock = clock
        self.approval = approval
        self.model = model
        self.prompt_version = prompt_version
        self.taxonomy_version = taxonomy_version
        self.classifier_version = classifier_version

    def classify(self, source: ClassificationInput) -> dict[str, object]:
        now = self.clock()
        self.approval.authorize_payload(
            purpose="talent_classification", payload_version=None,
            field_allowlist=_LEGACY_PROCESSOR_FIELDS, now=now,
        )
        approval_hash = self.approval.authorization_hash(now=now)
        version = ":".join((
            self.classifier_version, self.taxonomy_version, self.prompt_version,
            self.model, approval_hash,
        ))
        cache_key = self.cache.key("classification", version, source.provider_payload())
        cached = self.cache.get(cache_key)
        if cached is not None:
            return cached
        raw = self.provider(source.provider_payload())
        if not isinstance(raw, dict) or set(raw) != {"dimensions"} or not isinstance(raw["dimensions"], dict):
            raise ValueError("semantic provider output is invalid")
        dimensions: dict[str, object] = {}
        reasons: set[str] = set()
        for key, value in raw["dimensions"].items():
            if key not in _DIMENSION_KEYS or not isinstance(value, dict):
                raise ValueError("semantic provider returned an unknown dimension")
            if set(value) != {"labels", "confidence", "evidence_refs"}:
                raise ValueError("semantic dimension output has invalid fields")
            labels = _codes(value["labels"])
            if not labels or len(labels) != len(set(labels)) or any(
                label not in DIMENSION_LABELS[key] for label in labels
            ):
                raise ValueError("semantic provider label is outside the versioned taxonomy")
            confidence = value["confidence"]
            evidence = value["evidence_refs"]
            if (
                isinstance(confidence, bool) or not isinstance(confidence, (int, float))
                or not 0 <= float(confidence) <= 1
                or not isinstance(evidence, list)
                or any(item not in source.evidence_refs for item in evidence)
            ):
                raise ValueError("semantic dimension evidence or confidence is invalid")
            includes_unknown = UNKNOWN_LABELS[key] in labels
            contradictory = (
                (includes_unknown and len(labels) > 1)
                or (key in _EXCLUSIVE_DIMENSIONS and len(labels) > 1)
            )
            unknown = labels == [UNKNOWN_LABELS[key]] or (
                includes_unknown and len(labels) > 1
            )
            if not unknown and not evidence:
                raise ValueError("observed semantic dimensions require bound evidence")
            if unknown:
                reasons.add("unknown_state")
            if contradictory:
                reasons.add("contradictory_labels")
            if float(confidence) < 0.75:
                reasons.add("low_confidence")
            if _CONSEQUENTIAL.intersection(labels):
                reasons.add("consequential_claim")
            dimensions[key] = {
                "confidence": float(confidence), "evidence_refs": list(evidence),
                "labels": labels, "state": "unknown" if unknown else "observed",
            }
        missing_dimensions = sorted(_DIMENSION_KEYS.difference(dimensions))
        if missing_dimensions:
            reasons.update({"incomplete_provider_output", "low_confidence", "unknown_state"})
            for key in missing_dimensions:
                dimensions[key] = {
                    "confidence": 0.0,
                    "evidence_refs": [],
                    "labels": [UNKNOWN_LABELS[key]],
                    "state": "unknown",
                }
        result = {
            "classifier_version": self.classifier_version,
            "dimensions": dimensions,
            "model": self.model,
            "prompt_version": self.prompt_version,
            "processor_approval_hash": approval_hash,
            "provider": self.approval.provider,
            "review_reasons": sorted(reasons),
            "review_state": "pending" if reasons else "approved",
            "subject_ref": source.subject_ref,
            "taxonomy_version": self.taxonomy_version,
        }
        self.cache.set(cache_key, result, expires_at=self.clock() + timedelta(days=30))
        return result
