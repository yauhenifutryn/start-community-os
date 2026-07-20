"""Bounded extraction from applicant-supplied public portfolio pages."""

from __future__ import annotations

from datetime import datetime, timedelta
from html.parser import HTMLParser
import hashlib
import hmac
import re
from typing import Callable

from community_os.enrichment.cache import CanonicalJsonCache
from community_os.enrichment.evidence_vault import ProtectedEvidenceVault
from community_os.enrichment.gates import PublicSourceGate
from community_os.enrichment.state import PipelineState, StageStatus
from community_os.enrichment.transport import ApplicantSuppliedValue, Transport, canonical_public_url


class _VisibleText(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.hidden = 0
        self.parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in {"script", "style", "noscript", "svg"}:
            self.hidden += 1

    def handle_endtag(self, tag: str) -> None:
        if tag in {"script", "style", "noscript", "svg"} and self.hidden:
            self.hidden -= 1

    def handle_data(self, data: str) -> None:
        if not self.hidden:
            text = re.sub(r"\s+", " ", data).strip()
            if text:
                self.parts.append(text)


def extract_visible_text(payload: bytes) -> str:
    parser = _VisibleText()
    parser.feed(payload.decode("utf-8", errors="replace"))
    return " ".join(parser.parts)[:4000]


class PublicPageAdapter:
    # v2 removes extracted page text from both cache and protected stage output.
    VERSION = "applicant-public-page-v2"

    def __init__(
        self, *, transport: Transport, cache: CanonicalJsonCache, pseudonym_secret: bytes,
        clock: Callable[[], datetime], source_verifier: Callable[[ApplicantSuppliedValue], bool],
        evidence_vault: ProtectedEvidenceVault,
    ) -> None:
        if not pseudonym_secret:
            raise ValueError("pseudonym secret is required")
        self.transport = transport
        self.cache = cache
        self.secret = pseudonym_secret
        self.clock = clock
        self.source_verifier = source_verifier
        self.evidence_vault = evidence_vault

    def enrich(
        self, reference: ApplicantSuppliedValue | str, *, state: PipelineState,
        authorization: PublicSourceGate, subject_ref: str,
    ) -> dict[str, object]:
        if not isinstance(reference, ApplicantSuppliedValue):
            raise PermissionError("public-page enrichment requires persisted applicant-source evidence")
        if self.source_verifier(reference) is not True:
            raise PermissionError("public-page applicant-source evidence could not be verified")
        stage = state.stage("public_pages")
        expected = authorization.authorization_hash("public_pages", now=self.clock())
        if (
            stage.status is not StageStatus.RUNNING
            or stage.authorization_hash is None
            or not hmac.compare_digest(stage.authorization_hash, expected)
        ):
            raise PermissionError("public-page stage is not authorized and running")
        url = canonical_public_url(reference.value)
        cache_key = self.cache.key(
            "public_page", self.VERSION,
            {"source_record_ref": reference.source_record_ref, "url": url},
        )
        cached = self.cache.get(cache_key)
        if cached is not None:
            return cached
        response = self.transport.request(
            "GET", url, headers={"Accept": "text/html", "User-Agent": "START-Community-OS/1"},
            timeout=8.0, max_bytes=262144,
        )
        canonical_public_url(response.url)
        content_type = response.headers.get("Content-Type", "").casefold()
        if response.status != 200 or not content_type.startswith("text/html"):
            raise ValueError("public page must return HTML successfully")
        evidence = hmac.new(self.secret, url.encode(), hashlib.sha256).hexdigest()
        evidence_ref = "evidence:public_page:" + evidence
        self.evidence_vault.capture(
            source="public_pages", purpose="talent_classification",
            subject_ref=subject_ref, evidence_ref=evidence_ref,
            provider_version=self.VERSION, content_type="text/html",
            payload=response.body, ttl=timedelta(hours=24),
        )
        try:
            text = extract_visible_text(response.body)
            if not text:
                raise ValueError("public page contains no extractable visible text")
        except Exception:
            self.evidence_vault.delete(evidence_ref, reason="invalid_provider_payload")
            raise
        result = {"evidence_ref": evidence_ref, "state": "observed"}
        self.cache.set(
            cache_key, result,
            expires_at=self.clock() + timedelta(days=authorization.retention_days),
        )
        return result

    def discard_transient(self) -> None:
        self.evidence_vault.delete_source("public_pages", reason="public_pages_stage_failed")
        self.cache.delete_all()
