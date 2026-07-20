"""Machine-enforced authorization gates for consent-sensitive providers."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
import re
from typing import Callable, TypeVar


_T = TypeVar("_T")


def _timestamp(value: str) -> datetime:
    if not value:
        raise ValueError("timestamp is required")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include a timezone")
    return parsed


@dataclass(frozen=True)
class CoresignalGate:
    """A complete, attributable record required before any Coresignal transport call."""

    notice_version: str
    notice_sent_at: str
    notice_scope: str
    notice_content_sha256: str
    objections_reconciled: bool
    exclusions_reconciled: bool
    suppressions_reconciled: bool
    deletions_reconciled: bool
    access_verified: bool
    provider_terms_version: str
    source_scope: str
    retention_days: int
    approval_id: str
    approved_at: str

    @classmethod
    def from_record(cls, value: object) -> "CoresignalGate":
        if not isinstance(value, dict):
            raise ValueError("Coresignal authorization record must be an object")
        expected = {
            "access_verified", "deletions_reconciled", "exclusions_reconciled",
            "approval_id", "approved_at", "notice_sent_at",
            "notice_content_sha256", "notice_scope", "notice_version",
            "objections_reconciled", "provider_terms_version",
            "retention_days", "source_scope", "suppressions_reconciled",
        }
        if set(value) != expected:
            raise ValueError("Coresignal authorization record keys are invalid")
        return cls(**value)

    def to_record(self) -> dict[str, object]:
        return {
            "access_verified": self.access_verified,
            "deletions_reconciled": self.deletions_reconciled,
            "exclusions_reconciled": self.exclusions_reconciled,
            "approval_id": self.approval_id,
            "approved_at": self.approved_at,
            "notice_sent_at": self.notice_sent_at,
            "notice_content_sha256": self.notice_content_sha256,
            "notice_scope": self.notice_scope,
            "notice_version": self.notice_version,
            "objections_reconciled": self.objections_reconciled,
            "provider_terms_version": self.provider_terms_version,
            "retention_days": self.retention_days,
            "source_scope": self.source_scope,
            "suppressions_reconciled": self.suppressions_reconciled,
        }

    def authorize(self, *, now: datetime | None = None) -> None:
        """Fail closed unless notice, rights handling, provider, and approval records align."""
        required_text = (
            self.notice_version, self.notice_sent_at, self.provider_terms_version,
            self.notice_scope, self.notice_content_sha256, self.source_scope,
            self.approval_id, self.approved_at,
        )
        reconciled = (
            self.objections_reconciled, self.exclusions_reconciled,
            self.suppressions_reconciled, self.deletions_reconciled,
        )
        try:
            notice_time = _timestamp(self.notice_sent_at)
            approval_time = _timestamp(self.approved_at)
        except (TypeError, ValueError):
            self._locked()
        if (
            not all(isinstance(value, str) and value.strip() for value in required_text)
            or not all(value is True for value in reconciled)
            or self.access_verified is not True
            or not re.fullmatch(r"coresignal_transparency_v[1-9][0-9]*", self.notice_version)
            or not re.fullmatch(r"[0-9a-f]{64}", self.notice_content_sha256)
            or self.notice_scope != "linkedin_coresignal_enrichment"
            or self.source_scope != "applicant_supplied_linkedin"
            or isinstance(self.retention_days, bool)
            or not 1 <= self.retention_days <= 30
            or approval_time <= notice_time
            or (now is not None and (now.tzinfo is None or approval_time > now))
        ):
            self._locked()

    def authorization_hash(self, stage: str, *, now: datetime | None = None) -> str:
        """Return a deterministic binding only after this record authorizes Coresignal."""
        if stage != "coresignal":
            raise PermissionError("Coresignal authorization cannot bind another stage")
        self.authorize(now=now)
        payload = {**self.to_record(), "stage": stage}
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def call_after_authorization(
        self, transport_call: Callable[[], _T], *, now: datetime | None = None,
    ) -> _T:
        """Authorize first, then and only then invoke the injected provider transport."""
        self.authorize(now=now)
        return transport_call()

    @staticmethod
    def _locked() -> None:
        raise PermissionError("Coresignal locked: required authorization record is incomplete")


@dataclass(frozen=True)
class PublicSourceGate:
    """Bound notice, rights, source, terms, purpose, owner, and retention approval."""

    notice_version: str
    notice_sent_at: str
    objections_reconciled: bool
    exclusions_reconciled: bool
    suppressions_reconciled: bool
    deletions_reconciled: bool
    source_authorization_confirmed: bool
    provider_terms_version: str
    source_scope: str
    purpose_code: str
    retention_days: int
    accountable_owner: str
    approval_id: str
    approved_at: str

    @classmethod
    def from_record(cls, value: object) -> "PublicSourceGate":
        if not isinstance(value, dict) or set(value) != set(cls.__dataclass_fields__):
            raise ValueError("public-source authorization record keys are invalid")
        return cls(**value)

    def to_record(self) -> dict[str, object]:
        return {name: getattr(self, name) for name in self.__dataclass_fields__}

    def authorize(self, stage: str, *, now: datetime) -> None:
        scope = {
            "github": ("applicant_supplied_github", 30),
            "public_pages": ("applicant_supplied_public_pages", 14),
        }.get(stage)
        if scope is None or now.tzinfo is None:
            raise PermissionError("public-source stage authorization is invalid")
        try:
            notice = _timestamp(self.notice_sent_at)
            approved = _timestamp(self.approved_at)
        except (TypeError, ValueError) as error:
            raise PermissionError("public-source authorization timestamps are invalid") from error
        required_text = (
            self.notice_version, self.provider_terms_version, self.source_scope,
            self.purpose_code, self.accountable_owner, self.approval_id,
        )
        rights = (
            self.objections_reconciled, self.exclusions_reconciled,
            self.suppressions_reconciled, self.deletions_reconciled,
        )
        if (
            not all(isinstance(value, str) and value.strip() for value in required_text)
            or not all(value is True for value in rights)
            or self.source_authorization_confirmed is not True
            or self.source_scope != scope[0]
            or self.purpose_code != "aggregate_talent_evidence"
            or self.accountable_owner != "privacy_lead"
            or isinstance(self.retention_days, bool)
            or not 1 <= self.retention_days <= scope[1]
            or approved <= notice
            or approved > now
        ):
            raise PermissionError("public-source authorization record is incomplete")

    def authorization_hash(self, stage: str, *, now: datetime | None = None) -> str:
        if now is not None:
            self.authorize(stage, now=now)
        payload = {**self.to_record(), "stage": stage}
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
