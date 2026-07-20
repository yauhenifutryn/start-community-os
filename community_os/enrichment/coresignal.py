"""Hard-gated Coresignal adapter for applicant-supplied LinkedIn profiles."""

from __future__ import annotations

from datetime import datetime, timedelta
import hashlib
import hmac
import json
import re
import unicodedata
from typing import Callable
from urllib.parse import quote, urlencode, urlparse

from community_os.enrichment.cache import CanonicalJsonCache
from community_os.enrichment.evidence_vault import ProtectedEvidenceVault
from community_os.enrichment.gates import CoresignalGate
from community_os.enrichment.state import PipelineState, StageStatus
from community_os.enrichment.transport import (
    ApplicantSuppliedValue, RateLimitError, RetryPolicy, RetryableTransportError,
    Transport, call_with_retry,
)


_CORESIGNAL_ENDPOINT = "https://api.coresignal.com/cdapi/v2/employee_multi_source/collect"
_CORESIGNAL_FIELDS = (
    "active_experience_title",
    "active_experience_management_level",
    "experience",
)
_COMPANY_CATEGORIES = frozenset({
    "unknown", "startup", "scaleup", "venture_backed_startup", "enterprise",
    "academia_research",
})
_SENIORITY_CATEGORIES = frozenset({
    "unknown", "founder", "junior", "mid", "mid_level", "senior", "lead",
    "staff", "principal", "executive", "director", "head",
})


def _profile_url(value: str) -> str:
    parsed = urlparse(value.strip())
    if parsed.scheme != "https" or parsed.hostname not in {"linkedin.com", "www.linkedin.com"}:
        raise ValueError("Coresignal accepts only applicant-supplied LinkedIn profiles")
    parts = [part for part in parsed.path.split("/") if part]
    slug = unicodedata.normalize("NFC", parts[1]) if len(parts) == 2 else ""
    if (
        len(parts) != 2 or parts[0] != "in" or not 1 <= len(slug) <= 100
        or any(not (character.isalnum() or character in "_-") for character in slug)
    ):
        raise ValueError("LinkedIn profile path is invalid")
    if parsed.query or parsed.fragment or parsed.username or parsed.password:
        raise ValueError("LinkedIn profile URL contains forbidden components")
    return f"https://www.linkedin.com/in/{slug}"


def _profile_shorthand(profile_url: str) -> str:
    """Return the validated personal-profile slug accepted by Collect."""
    return _profile_url(profile_url).rsplit("/", 1)[-1]


def _optional_text(payload: dict[str, object], key: str) -> str:
    value = payload.get(key)
    if value is None:
        return ""
    if not isinstance(value, str) or len(value) > 256:
        raise TypeError(f"Coresignal {key} must be a bounded string")
    return value.strip()


def _seniority(management_level: str, title: str) -> str:
    value = f"{management_level} {title}".casefold()
    rules = (
        (("founder", "co-founder", "cofounder"), "founder"),
        (("chief", "c-suite", "c suite", "vice president", "vp ", "executive"), "executive"),
        (("principal",), "principal"),
        (("staff",), "staff"),
        (("director",), "director"),
        (("head",), "head"),
        (("lead", "manager"), "lead"),
        (("senior",), "senior"),
        (("junior", "entry"), "junior"),
        (("mid",), "mid"),
    )
    return next((category for tokens, category in rules if any(token in value for token in tokens)), "unknown")


def _company_category(company_type: str, company_size: str, company_industry: str) -> str:
    value = f"{company_type} {company_size} {company_industry}".casefold()
    if any(token in value for token in ("university", "education", "research", "academic")):
        return "academia_research"
    if "venture backed" in value or "venture-backed" in value:
        return "venture_backed_startup"
    if "scaleup" in value or "scale-up" in value:
        return "scaleup"
    if "startup" in value or "start-up" in value:
        return "startup"
    if "public company" in value or "10,001+" in value or "5001-10,000" in value:
        return "enterprise"
    return "unknown"


def normalize_coresignal_payload(
    payload: object, *, evidence_ref: str,
) -> dict[str, object]:
    """Reduce a provider response to the allowlisted semantic projection."""
    if not isinstance(payload, dict):
        raise TypeError("Coresignal payload must be an object")
    title = _optional_text(payload, "active_experience_title")
    management = _optional_text(payload, "active_experience_management_level")
    company_type = _optional_text(payload, "company_type")
    company_size = _optional_text(payload, "company_size_range")
    company_industry = _optional_text(payload, "company_industry")
    experience = payload.get("experience", [])
    if not isinstance(experience, list) or len(experience) > 100:
        raise TypeError("Coresignal experience must be a bounded list")
    history_titles = []
    active_company_types: list[str] = []
    active_company_sizes: list[str] = []
    active_company_industries: list[str] = []
    for item in experience:
        if not isinstance(item, dict):
            raise TypeError("Coresignal experience item must be an object")
        history_titles.append(_optional_text(item, "position_title"))
        _optional_text(item, "management_level")
        active = item.get("active_experience")
        if active is not None and type(active) not in {bool, int}:
            raise TypeError("Coresignal active_experience has an invalid type")
        nested_company_type = _optional_text(item, "company_type")
        nested_company_size = _optional_text(item, "company_size_range")
        nested_company_industry = _optional_text(item, "company_industry")
        if active in {True, 1}:
            active_company_types.append(nested_company_type)
            active_company_sizes.append(nested_company_size)
            active_company_industries.append(nested_company_industry)
    if not company_type:
        company_type = " ".join(active_company_types)
    if not company_size:
        company_size = " ".join(active_company_sizes)
    if not company_industry:
        company_industry = " ".join(active_company_industries)
    founder_history = any(
        re.search(r"\b(?:co[ -]?founder|founder)\b", item.casefold())
        for item in history_titles
    )
    title_value = title.casefold()
    result = {
        "company_category": _company_category(company_type, company_size, company_industry),
        "evidence_ref": evidence_ref,
        "founder_history": founder_history,
        "seniority": _seniority(management, title),
        "state": "observed",
        "title_category": "software_engineering" if any(
            token in title_value
            for token in ("engineer", "developer", "software", "machine learning")
        ) else "unknown",
    }
    for key in ("company_category", "seniority", "title_category"):
        if not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", str(result[key])):
            raise ValueError("Coresignal response contains an invalid category")
    if (
        result["company_category"] not in _COMPANY_CATEGORIES
        or result["seniority"] not in _SENIORITY_CATEGORIES
        or result["title_category"] not in {"unknown", "software_engineering"}
    ):
        raise ValueError("Coresignal response did not match the allowlisted schema")
    return result


class CoresignalAdapter:
    VERSION = "coresignal-employee-multi-source-v3"

    def __init__(
        self, *, transport: Transport, cache: CanonicalJsonCache, pseudonym_secret: bytes,
        clock: Callable[[], datetime], api_token: str,
        source_verifier: Callable[[ApplicantSuppliedValue], bool],
        sleeper: Callable[[float], None] = lambda _seconds: None,
        endpoint: str = _CORESIGNAL_ENDPOINT,
        evidence_vault: ProtectedEvidenceVault | None = None,
    ) -> None:
        if not pseudonym_secret or not api_token:
            raise ValueError("Coresignal secret and API token are required")
        if endpoint.rstrip("/") != _CORESIGNAL_ENDPOINT:
            raise ValueError("Coresignal endpoint is not allowlisted")
        self.transport = transport
        self.cache = cache
        self.secret = pseudonym_secret
        self.clock = clock
        self.api_token = api_token
        self.source_verifier = source_verifier
        self.sleeper = sleeper
        self.endpoint = _CORESIGNAL_ENDPOINT
        self.evidence_vault = evidence_vault

    def enrich(
        self, reference: ApplicantSuppliedValue | str, *, state: PipelineState,
        authorization: CoresignalGate, subject_ref: str | None = None,
    ) -> dict[str, object]:
        if not isinstance(reference, ApplicantSuppliedValue):
            raise PermissionError("Coresignal requires persisted applicant-source evidence")
        if self.source_verifier(reference) is not True:
            raise PermissionError("Coresignal applicant-source evidence could not be verified")
        stage = state.stage("coresignal")
        if stage.status is not StageStatus.RUNNING:
            raise PermissionError("Coresignal stage is not authorized and running")
        expected = authorization.authorization_hash("coresignal", now=self.clock())
        if stage.authorization_hash is None or not hmac.compare_digest(stage.authorization_hash, expected):
            raise PermissionError("Coresignal authorization does not match the running stage")
        profile = _profile_url(reference.value)
        cache_key = self.cache.key(
            "coresignal", self.VERSION,
            {"profile": profile, "source_record_ref": reference.source_record_ref},
        )
        cached = self.cache.get(cache_key)
        if cached is not None:
            return cached

        def fetch() -> dict[str, object]:
            query = urlencode([("fields", field) for field in _CORESIGNAL_FIELDS])
            response = self.transport.request(
                "GET", self.endpoint + "/" + quote(_profile_shorthand(profile), safe="") + "?" + query,
                headers={"apikey": self.api_token, "Accept": "application/json"},
                timeout=10.0, max_bytes=262144,
            )
            if response.status == 429:
                try:
                    delay = float(response.headers.get("Retry-After", "1"))
                except ValueError:
                    delay = 1.0
                raise RateLimitError("Coresignal rate limit", retry_after=max(1.0, delay))
            if response.status >= 500:
                raise RetryableTransportError("Coresignal unavailable")
            if response.status != 200:
                raise ValueError("Coresignal profile request was not successful")
            evidence_material = (
                f"{self.VERSION}:{stage.attempts}:{reference.source_record_ref}:"
                f"{subject_ref or 'no_subject'}:{profile}"
            ).encode("utf-8")
            evidence_ref = "evidence:coresignal:" + hmac.new(
                self.secret, evidence_material, hashlib.sha256,
            ).hexdigest()
            if self.evidence_vault is not None:
                if subject_ref is None:
                    raise PermissionError("Coresignal raw evidence requires a pseudonymous subject")
                self.evidence_vault.capture(
                    source="coresignal", purpose="talent_classification",
                    subject_ref=subject_ref, evidence_ref=evidence_ref,
                    provider_version=self.VERSION, content_type="application/json",
                    payload=response.body, ttl=timedelta(hours=24),
                )
            try:
                payload = json.loads(response.body)
                result = normalize_coresignal_payload(payload, evidence_ref=evidence_ref)
            except (TypeError, ValueError, json.JSONDecodeError) as error:
                if self.evidence_vault is not None:
                    self.evidence_vault.delete(evidence_ref, reason="invalid_provider_payload")
                raise ValueError("Coresignal response did not match the allowlisted schema") from error
            return result

        result = authorization.call_after_authorization(
            lambda: call_with_retry(fetch, RetryPolicy(), self.sleeper), now=self.clock(),
        )
        self.cache.set(cache_key, result, expires_at=self.clock() + timedelta(days=authorization.retention_days))
        return result

    def discard_transient(self) -> None:
        if self.evidence_vault is not None:
            self.evidence_vault.delete_source("coresignal", reason="coresignal_stage_failed")
        self.cache.delete_all()
