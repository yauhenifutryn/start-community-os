"""Privacy-limited analytics gates around verified publication.

Bundle preparation never deploys. Its one provider-backed action is a read-only
project-settings check that verifies PostHog drops IP addresses before a bundle can
be prepared. Deployment and report rendering remain separate, explicit actions.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
import hashlib
import hmac
import http.client
import json
import os
from pathlib import Path
import re
import ssl
import tempfile
from typing import Mapping
from urllib.parse import urlsplit


_HASH = re.compile(r"[a-f0-9]{64}")
_PUBLIC_KEY = re.compile(r"phc_[A-Za-z0-9_-]{4,128}")
_ACTOR_CODE = re.compile(r"actor_[a-f0-9]{8,64}")
_APPROVAL_CODE = re.compile(r"approval_[a-f0-9]{8,64}")
_POSTHOG_HOSTS = frozenset({"https://eu.i.posthog.com"})
_POSTHOG_API_ORIGIN = "https://eu.posthog.com"
_POSTHOG_API_HOST = "eu.posthog.com"
_POSTHOG_PRIVACY_MAX_AGE = timedelta(minutes=10)
_MAX_POSTHOG_RESPONSE_BYTES = 1024 * 1024
_REPORT_NAME = "talent-brief.real.html"
_STATIC_SOURCE_NAMES = frozenset({
    "index.html", "partner-talent-brief.pdf", "publication-manifest.json",
})
_RECEIPT_KEYS = frozenset({
    "receipt_version", "publication_state", "privacy_state", "report_sha256",
    "publication_manifest_sha256", "published_at",
})
_POSTHOG_PRIVACY_RECEIPT_KEYS = frozenset({
    "anonymize_ips", "api_origin", "ingestion_origin", "project_id",
    "project_response_sha256", "public_key_sha256", "receipt_version",
    "verified_at",
})


def _require_aware(value: datetime, field: str) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field} must be timezone-aware")


def _iso(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _parse_time(value: object, field: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be an ISO timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(f"{field} must be an ISO timestamp") from error
    _require_aware(parsed, field)
    return parsed


def _sha256(path: Path) -> str:
    if not path.is_file() or path.is_symlink():
        raise ValueError("analytics evidence must be a regular file")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _load_manifest(path: Path) -> Mapping[str, object]:
    if not path.is_file() or path.is_symlink() or path.stat().st_size > 1024 * 1024:
        raise ValueError("publication manifest must be a bounded regular file")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("publication manifest is invalid") from error
    if not isinstance(value, dict):
        raise ValueError("publication manifest is invalid")
    return value


def load_posthog_privacy_verification(
    path: str | Path,
) -> PostHogPrivacyVerification:
    receipt_path = Path(path)
    if (
        not receipt_path.is_file()
        or receipt_path.is_symlink()
        or receipt_path.stat().st_size > 64 * 1024
    ):
        raise ValueError("PostHog privacy receipt must be a bounded regular file")
    try:
        value = json.loads(receipt_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("PostHog privacy receipt is invalid") from error
    try:
        return PostHogPrivacyVerification.from_dict(value)
    except (KeyError, TypeError, ValueError, PermissionError) as error:
        raise ValueError("PostHog privacy receipt is invalid") from error


def _normalized_host(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("PostHog host is invalid")
    parsed = urlsplit(value)
    normalized = value.rstrip("/")
    if (
        parsed.scheme != "https"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or normalized not in _POSTHOG_HOSTS
    ):
        raise ValueError("PostHog host is not an allowlisted HTTPS origin")
    return normalized


def _canonical_sha256(value: Mapping[str, object]) -> str:
    serialized = json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(serialized).hexdigest()


@dataclass(frozen=True)
class PostHogPrivacyVerification:
    """Bounded evidence from a read-only PostHog project-settings response."""

    receipt_version: str
    api_origin: str
    ingestion_origin: str
    project_id: int
    public_key_sha256: str
    anonymize_ips: bool
    verified_at: datetime
    project_response_sha256: str

    def __post_init__(self) -> None:
        if self.receipt_version != "posthog-project-privacy-v1":
            raise ValueError("PostHog privacy receipt version is invalid")
        if self.api_origin != _POSTHOG_API_ORIGIN:
            raise ValueError("PostHog privacy API origin is invalid")
        _normalized_host(self.ingestion_origin)
        if type(self.project_id) is not int or self.project_id < 1:
            raise ValueError("PostHog project ID is invalid")
        if not _HASH.fullmatch(self.public_key_sha256):
            raise ValueError("PostHog public key hash is invalid")
        if self.anonymize_ips is not True:
            raise PermissionError("PostHog project IP capture is not disabled")
        _require_aware(self.verified_at, "verified_at")
        if not _HASH.fullmatch(self.project_response_sha256):
            raise ValueError("PostHog project response hash is invalid")

    def as_dict(self) -> dict[str, object]:
        return {
            "anonymize_ips": self.anonymize_ips,
            "api_origin": self.api_origin,
            "ingestion_origin": self.ingestion_origin,
            "project_id": self.project_id,
            "project_response_sha256": self.project_response_sha256,
            "public_key_sha256": self.public_key_sha256,
            "receipt_version": self.receipt_version,
            "verified_at": _iso(self.verified_at),
        }

    @classmethod
    def from_dict(cls, value: object) -> PostHogPrivacyVerification:
        if not isinstance(value, dict) or frozenset(value) != _POSTHOG_PRIVACY_RECEIPT_KEYS:
            raise ValueError("PostHog privacy receipt fields are invalid")
        return cls(
            receipt_version=value["receipt_version"],
            api_origin=value["api_origin"],
            ingestion_origin=value["ingestion_origin"],
            project_id=value["project_id"],
            public_key_sha256=value["public_key_sha256"],
            anonymize_ips=value["anonymize_ips"],
            verified_at=_parse_time(value["verified_at"], "verified_at"),
            project_response_sha256=value["project_response_sha256"],
        )

    @property
    def sha256(self) -> str:
        return _canonical_sha256(self.as_dict())


def _posthog_json_get(
    *, path: str, personal_api_key: str, api_origin: str = _POSTHOG_API_ORIGIN,
) -> Mapping[str, object]:
    """Read one bounded PostHog EU API response without following redirects."""

    if api_origin != _POSTHOG_API_ORIGIN:
        raise ValueError("PostHog privacy API origin is invalid")
    if (
        not isinstance(personal_api_key, str)
        or personal_api_key.strip() != personal_api_key
        or not 8 <= len(personal_api_key) <= 512
        or any(character.isspace() for character in personal_api_key)
    ):
        raise ValueError("PostHog personal API key is invalid")
    if not isinstance(path, str) or not path.startswith("/api/") or "//" in path:
        raise ValueError("PostHog API path is invalid")
    connection = http.client.HTTPSConnection(
        _POSTHOG_API_HOST,
        timeout=10,
        context=ssl.create_default_context(),
    )
    try:
        connection.request(
            "GET",
            path,
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {personal_api_key}",
                "User-Agent": "start-community-os/1.0",
            },
        )
        response = connection.getresponse()
        body = response.read(_MAX_POSTHOG_RESPONSE_BYTES + 1)
    finally:
        connection.close()
    if len(body) > _MAX_POSTHOG_RESPONSE_BYTES:
        raise ValueError("PostHog API response exceeds the privacy verification limit")
    if response.status in {401, 403}:
        raise PermissionError(
            "PostHog personal API key requires project:read for this project",
        )
    if response.status != 200:
        raise ConnectionError(f"PostHog project verification returned HTTP {response.status}")
    try:
        value = json.loads(body.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("PostHog API response is invalid JSON") from error
    if not isinstance(value, dict):
        raise ValueError("PostHog API response is invalid")
    return value


def verify_posthog_project_privacy(
    *,
    personal_api_key: str,
    project_id: int,
    public_key: str,
    now: datetime,
    artifact_path: str | Path | None = None,
) -> PostHogPrivacyVerification:
    """Verify the EU project, public key, and IP-drop setting through PostHog."""

    _require_aware(now, "now")
    if type(project_id) is not int or project_id < 1:
        raise ValueError("PostHog project ID is invalid")
    if not isinstance(public_key, str) or not _PUBLIC_KEY.fullmatch(public_key):
        raise ValueError("configured PostHog public key is invalid")
    project = _posthog_json_get(
        path=f"/api/projects/{project_id}/",
        personal_api_key=personal_api_key,
    )
    if project.get("id") != project_id:
        raise ValueError("PostHog project response ID does not match")
    response_public_key = project.get("api_token")
    if not isinstance(response_public_key, str) or not hmac.compare_digest(
        response_public_key,
        public_key,
    ):
        raise PermissionError("PostHog public project key does not match the project")
    if project.get("anonymize_ips") is not True:
        raise PermissionError("PostHog project IP capture is not disabled")
    verification = PostHogPrivacyVerification(
        receipt_version="posthog-project-privacy-v1",
        api_origin=_POSTHOG_API_ORIGIN,
        ingestion_origin="https://eu.i.posthog.com",
        project_id=project_id,
        public_key_sha256=hashlib.sha256(public_key.encode("ascii")).hexdigest(),
        anonymize_ips=True,
        verified_at=now,
        project_response_sha256=_canonical_sha256({
            "anonymize_ips": True,
            "project_id": project_id,
            "public_key_sha256": hashlib.sha256(
                public_key.encode("ascii"),
            ).hexdigest(),
        }),
    )
    if artifact_path is not None:
        _write_artifact(Path(artifact_path), verification.as_dict())
    return verification


@dataclass(frozen=True)
class AnalyticsActivationApproval:
    """Explicit, short-lived approval bound to one published report and manifest."""

    approval_code: str
    actor_code: str
    scope: str
    report_sha256: str
    publication_manifest_sha256: str
    posthog_privacy_receipt_sha256: str
    approved_at: datetime
    expires_at: datetime

    def __post_init__(self) -> None:
        if not _APPROVAL_CODE.fullmatch(self.approval_code):
            raise ValueError("approval_code must be an opaque pseudonymous code")
        if not _ACTOR_CODE.fullmatch(self.actor_code):
            raise ValueError("actor_code must be an opaque pseudonymous code")
        if not _HASH.fullmatch(self.report_sha256):
            raise ValueError("approval report hash is invalid")
        if not _HASH.fullmatch(self.publication_manifest_sha256):
            raise ValueError("approval manifest hash is invalid")
        if not _HASH.fullmatch(self.posthog_privacy_receipt_sha256):
            raise ValueError("approval PostHog privacy receipt hash is invalid")
        _require_aware(self.approved_at, "approved_at")
        _require_aware(self.expires_at, "expires_at")
        if self.expires_at <= self.approved_at:
            raise ValueError("analytics approval expiry must follow approval")


def _validate_posthog_privacy_verification(
    verification: PostHogPrivacyVerification,
    *,
    public_key: str,
    posthog_host: str,
    now: datetime,
) -> str:
    if not isinstance(verification, PostHogPrivacyVerification):
        raise TypeError("machine-verified PostHog project privacy evidence is required")
    expected_public_key_hash = hashlib.sha256(public_key.encode("ascii")).hexdigest()
    if not hmac.compare_digest(
        verification.public_key_sha256,
        expected_public_key_hash,
    ):
        raise PermissionError("PostHog privacy evidence public key does not match")
    if verification.ingestion_origin != posthog_host:
        raise PermissionError("PostHog privacy evidence ingestion host does not match")
    if verification.verified_at > now:
        raise PermissionError("PostHog privacy evidence is in the future")
    if now - verification.verified_at > _POSTHOG_PRIVACY_MAX_AGE:
        raise PermissionError("PostHog privacy evidence is stale")
    return verification.sha256


def _validate_receipt(receipt: Mapping[str, object]) -> tuple[str, str, datetime]:
    if not isinstance(receipt, Mapping) or frozenset(receipt) != _RECEIPT_KEYS:
        raise ValueError("publication receipt fields are invalid")
    if receipt["receipt_version"] != "partner-publication-receipt-v1":
        raise ValueError("publication receipt version is invalid")
    if receipt["publication_state"] != "published":
        raise PermissionError("analytics require a published publication receipt")
    if receipt["privacy_state"] != "aggregate_only":
        raise PermissionError("analytics require an aggregate-only publication receipt")
    report_hash = receipt["report_sha256"]
    manifest_hash = receipt["publication_manifest_sha256"]
    if not isinstance(report_hash, str) or not _HASH.fullmatch(report_hash):
        raise ValueError("publication receipt report hash is invalid")
    if not isinstance(manifest_hash, str) or not _HASH.fullmatch(manifest_hash):
        raise ValueError("publication receipt manifest hash is invalid")
    published_at = _parse_time(receipt["published_at"], "published_at")
    return report_hash, manifest_hash, published_at


def _validate_manifest(manifest: Mapping[str, object]) -> str:
    if manifest.get("manifest_version") != "public-partner-release-v1":
        raise ValueError("publication manifest version is invalid")
    if manifest.get("release_state") != "Safe to publish":
        raise PermissionError("publication manifest release state is not safe")
    if manifest.get("privacy_state") != "aggregate_only":
        raise PermissionError("publication manifest is not aggregate-only")
    if manifest.get("analytics_enabled") is not False:
        raise PermissionError("publication manifest is not in pre-activation state")
    artifact_hashes = manifest.get("artifact_hashes")
    if not isinstance(artifact_hashes, dict):
        raise ValueError("publication manifest artifact hashes are invalid")
    report_hash = artifact_hashes.get(_REPORT_NAME)
    if not isinstance(report_hash, str) or not _HASH.fullmatch(report_hash):
        raise ValueError("publication manifest report hash is invalid")
    return report_hash


def _write_artifact(path: Path, artifact: Mapping[str, object]) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    serialized = json.dumps(artifact, sort_keys=True, separators=(",", ":")) + "\n"
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=path.parent, prefix=f".{path.name}.",
            delete=False,
        ) as stream:
            temporary_name = stream.name
            os.fchmod(stream.fileno(), 0o600)
            stream.write(serialized)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_name, path)
        os.chmod(path, 0o600)
    finally:
        if temporary_name is not None:
            try:
                Path(temporary_name).unlink()
            except FileNotFoundError:
                pass


def activate_postpublication_analytics(
    *,
    publication_manifest_path: str | Path,
    local_public_report_path: str | Path,
    deployed_report_path: str | Path,
    publication_receipt: Mapping[str, object],
    approval: AnalyticsActivationApproval,
    public_key: str,
    posthog_host: str,
    personal_api_key: str,
    posthog_project_id: int,
    now: datetime,
    artifact_path: str | Path | None = None,
    posthog_privacy_artifact_path: str | Path | None = None,
) -> dict[str, object]:
    """Verify post-publication evidence and prepare an activation artifact.

    ``deployed_report_path`` is a caller-supplied download or deployment snapshot.
    This function reads PostHog project privacy settings but never deploys or emits
    analytics events.
    """
    _require_aware(now, "now")
    if not isinstance(approval, AnalyticsActivationApproval):
        raise TypeError("explicit analytics approval is required")
    if not isinstance(public_key, str) or not _PUBLIC_KEY.fullmatch(public_key):
        raise ValueError("configured PostHog public key is invalid")
    host = _normalized_host(posthog_host)
    posthog_privacy_verification = verify_posthog_project_privacy(
        personal_api_key=personal_api_key,
        project_id=posthog_project_id,
        public_key=public_key,
        now=now,
        artifact_path=posthog_privacy_artifact_path,
    )
    privacy_receipt_sha256 = _validate_posthog_privacy_verification(
        posthog_privacy_verification,
        public_key=public_key,
        posthog_host=host,
        now=now,
    )
    if not hmac.compare_digest(
        approval.posthog_privacy_receipt_sha256,
        privacy_receipt_sha256,
    ):
        raise PermissionError("analytics approval PostHog privacy receipt does not match")

    manifest_path = Path(publication_manifest_path)
    local_path = Path(local_public_report_path)
    deployed_path = Path(deployed_report_path)
    manifest = _load_manifest(manifest_path)
    manifest_report_hash = _validate_manifest(manifest)
    receipt_report_hash, receipt_manifest_hash, published_at = _validate_receipt(
        publication_receipt,
    )
    actual_manifest_hash = _sha256(manifest_path)
    local_report_hash = _sha256(local_path)
    deployed_report_hash = _sha256(deployed_path)

    comparisons = (
        (actual_manifest_hash, receipt_manifest_hash, "publication receipt manifest"),
        (manifest_report_hash, receipt_report_hash, "publication receipt report"),
        (local_report_hash, manifest_report_hash, "local public report"),
        (deployed_report_hash, local_report_hash, "deployed report"),
        (approval.report_sha256, local_report_hash, "analytics approval report"),
        (
            approval.publication_manifest_sha256,
            actual_manifest_hash,
            "analytics approval manifest",
        ),
    )
    for actual, expected, label in comparisons:
        if not hmac.compare_digest(actual, expected):
            raise PermissionError(f"{label} hash does not match")

    if approval.scope != "privacy_limited_posthog":
        raise PermissionError("analytics approval scope is invalid")
    if approval.approved_at < published_at:
        raise PermissionError("analytics approval predates publication")
    if approval.approved_at > now:
        raise PermissionError("analytics approval is in the future")
    if now >= approval.expires_at:
        raise PermissionError("analytics approval has expired")
    if now < published_at:
        raise PermissionError("activation time predates publication")

    artifact: dict[str, object] = {
        "artifact_version": "postpublication-analytics-v1",
        "analytics_config": {
            "api_host": host,
            "autocapture": False,
            "capture_pageleave": False,
            "capture_pageview": False,
            "disable_session_recording": True,
            "disable_surveys": True,
            "identity_mode": "ephemeral_per_page_load",
            "persistence": "memory_only",
            "person_profile_processing": False,
            "transport": "direct_capture",
        },
        "event_policy": {
            "allowed_events": [
                "cohort_selected", "metric_selected", "overlap_region_selected",
                "pdf_downloaded", "report_opened",
            ],
            "allowed_properties": [
                "cohort_key", "metric_key", "overlap_region", "report_version",
            ],
            "forbidden_dimensions": [
                "email", "evidence_url", "github", "linkedin", "name",
                "participant_id", "person_id", "profile_url", "stable_identifier",
            ],
        },
        "activation_receipt": {
            "activation_state": "ready_to_configure",
            "actor_code": approval.actor_code,
            "approval_code": approval.approval_code,
            "activated_at": _iso(now),
            "audit_reason_code": "explicit_postpublication_privacy_limited_approval",
            "ip_capture_disabled_confirmed": True,
            "posthog_privacy_receipt_sha256": privacy_receipt_sha256,
            "publication_manifest_sha256": actual_manifest_hash,
            "publication_state": "published",
            "published_at": _iso(published_at),
            "report_sha256": local_report_hash,
        },
    }
    if artifact_path is not None:
        _write_artifact(Path(artifact_path), artifact)
    return artifact


def _script_json(value: object) -> str:
    return json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
        allow_nan=False,
    ).replace("<", "\\u003c").replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")


def _analytics_runtime(*, public_key: str, host: str, report_version: str) -> str:
    """Return a fixed allowlist capture client with a per-load in-memory identity."""

    config = _script_json({
        "api_host": host,
        "api_key": public_key,
        "report_version": report_version,
    })
    return f"""(()=>{{
const config=Object.freeze({config});
const eventProperties=Object.freeze({{
  report_opened:[],
  pdf_downloaded:['cohort_key'],
  cohort_selected:['cohort_key'],
  metric_selected:['cohort_key','metric_key'],
  overlap_region_selected:['overlap_region']
}});
const pageIdentity=crypto.randomUUID();
const safeKey=value=>typeof value==='string'&&/^[a-z0-9][a-z0-9_-]{{0,63}}$/.test(value)?value:null;
const activeKey=attribute=>{{
  const item=document.querySelector('['+attribute+'][aria-pressed="true"]');
  return safeKey(item?.dataset[attribute.replace('data-','').replace(/-([a-z])/g,(_,letter)=>letter.toUpperCase())]);
}};
const context=()=>({{cohort_key:activeKey('data-cohort-select')}});
const capture=(event,properties={{}})=>{{
  const allowed=eventProperties[event];if(!allowed)return;
  const selected={{}};for(const key of allowed){{const value=safeKey(properties[key]);if(value)selected[key]=value;}}
  const body=JSON.stringify({{api_key:config.api_key,event,properties:{{
    distinct_id:pageIdentity,$process_person_profile:false,$lib:'start-community-os',
    report_version:config.report_version,...selected
  }}}});
  const endpoint=config.api_host+'/capture/';
  fetch(endpoint,{{method:'POST',mode:'cors',credentials:'omit',
    referrerPolicy:'no-referrer',keepalive:true,
    headers:{{'Content-Type':'application/json'}},body}}).catch(()=>{{}});
}};
capture('report_opened');
document.querySelectorAll('[data-cohort-select]').forEach(button=>button.addEventListener('click',()=>capture('cohort_selected',context())));
document.addEventListener('click',event=>{{
  const target=event.target instanceof Element?event.target:null;if(!target)return;
  const metric=target.closest('[data-dashboard-metric-select]');
  if(metric)capture('metric_selected',{{...context(),metric_key:metric.dataset.dashboardMetricSelect}});
  const overlap=target.closest('[data-overlap-region]');
  if(overlap)capture('overlap_region_selected',{{overlap_region:overlap.dataset.overlapRegion}});
}});
document.querySelectorAll('.pdf-actions a[download]').forEach(link=>link.addEventListener('click',()=>capture('pdf_downloaded',context())));
}})();"""


_ANALYTICS_DISCLOSURE_STYLE = """
.analytics-disclosure{margin:0;padding:18px clamp(24px,6vw,88px);color:#626274;background:#f7f7f4;border-top:1px solid #d9d9df;font:600 .76rem/1.5 Avenir,"Avenir Next",system-ui,sans-serif}
.analytics-disclosure strong{color:#00002c}
""".strip()

_ANALYTICS_DISCLOSURE = (
    '<aside class="analytics-disclosure" role="note"><strong>Privacy-minimized analytics.</strong> '
    'This public report records aggregate report opens and interactions only. '
    'No participant data, names, emails, session replay, or stable viewer profiles are collected.'
    '</aside>'
)


def _hash_source(value: str) -> str:
    digest = hashlib.sha256(value.encode("utf-8")).digest()
    return "'sha256-" + base64.b64encode(digest).decode("ascii") + "'"


def _content_security_policy(html: str, *, host: str, include_frame_guard: bool) -> str:
    scripts = re.findall(r"<script\b[^>]*>(.*?)</script\s*>", html, re.DOTALL | re.IGNORECASE)
    styles = re.findall(r"<style\b[^>]*>(.*?)</style\s*>", html, re.DOTALL | re.IGNORECASE)
    if not scripts or not styles:
        raise ValueError("analytics publication requires hashable inline scripts and styles")
    script_sources = " ".join(sorted({_hash_source(item) for item in scripts}))
    style_sources = " ".join(sorted({_hash_source(item) for item in styles}))
    directives = [
        "default-src 'none'",
        "base-uri 'none'",
        "form-action 'none'",
        "object-src 'none'",
        "img-src data:",
        f"style-src-elem {style_sources}",
        "style-src-attr 'unsafe-inline'",
        f"script-src {script_sources}",
        "script-src-attr 'none'",
        f"connect-src {host}",
        "font-src 'none'",
        "media-src 'none'",
        "worker-src 'none'",
        "manifest-src 'none'",
    ]
    if include_frame_guard:
        directives.append("frame-ancestors 'none'")
    return "; ".join(directives)


def _analytics_html(
    source: str, *, public_key: str, host: str, report_version: str,
) -> tuple[str, str]:
    if "</head>" not in source or "</body>" not in source:
        raise ValueError("public HTML is missing a complete document boundary")
    runtime = _analytics_runtime(
        public_key=public_key, host=host, report_version=report_version,
    )
    enriched = source.replace(
        "</head>",
        '<meta name="referrer" content="no-referrer">'
        f"<style>{_ANALYTICS_DISCLOSURE_STYLE}</style></head>",
        1,
    ).replace(
        "</body>", _ANALYTICS_DISCLOSURE + f"<script>{runtime}</script></body>", 1,
    )
    meta_policy = _content_security_policy(
        enriched, host=host, include_frame_guard=False,
    )
    meta = (
        '<meta http-equiv="Content-Security-Policy" content="'
        + meta_policy
        + '">'
    )
    head = re.search(r"<head\b[^>]*>", enriched, re.IGNORECASE)
    if head is None:
        raise ValueError("public HTML is missing a head boundary")
    enriched = enriched[:head.end()] + meta + enriched[head.end():]
    header_policy = _content_security_policy(
        enriched, host=host, include_frame_guard=True,
    )
    return enriched, header_policy


def _vercel_config(policy: str) -> str:
    """Return a static-only Vercel wrapper with explicit response headers."""

    config = {
        "$schema": "https://openapi.vercel.sh/vercel.json",
        "framework": None,
        "headers": [{
            "source": "/(.*)",
            "headers": [
                {"key": "Content-Security-Policy", "value": policy},
                {"key": "Referrer-Policy", "value": "no-referrer"},
                {"key": "X-Content-Type-Options", "value": "nosniff"},
                {"key": "X-Frame-Options", "value": "DENY"},
                {
                    "key": "Permissions-Policy",
                    "value": (
                        "camera=(), geolocation=(), microphone=(), "
                        "payment=(), usb=()"
                    ),
                },
                {
                    "key": "X-Robots-Tag",
                    "value": "noindex, nofollow, noarchive",
                },
            ],
        }],
    }
    return json.dumps(config, sort_keys=True, separators=(",", ":")) + "\n"


def _validate_static_source(source: Path) -> tuple[dict[str, object], Path, Path, Path]:
    if source.is_symlink() or not source.is_dir():
        raise ValueError("analytics source must be a trusted static bundle directory")
    if {path.name for path in source.iterdir()} != _STATIC_SOURCE_NAMES:
        raise ValueError("analytics source bundle is incomplete or contains extra files")
    index = source / "index.html"
    pdf = source / "partner-talent-brief.pdf"
    manifest_path = source / "publication-manifest.json"
    if any(path.is_symlink() or not path.is_file() for path in (index, pdf, manifest_path)):
        raise ValueError("analytics source bundle contains an unsafe file")
    manifest = dict(_load_manifest(manifest_path))
    required = {
        "analytics_enabled", "artifact_hashes", "artifact_set_sha256",
        "entrypoint", "manifest_version", "pdf", "privacy_state",
        "public_transform_version", "release_state",
    }
    if set(manifest) != required:
        raise ValueError("analytics source manifest fields are invalid")
    if (
        manifest.get("analytics_enabled") is not False
        or manifest.get("entrypoint") != "index.html"
        or manifest.get("manifest_version") != "partner-static-bundle-v1"
        or manifest.get("pdf") != "partner-talent-brief.pdf"
        or manifest.get("privacy_state") != "aggregate_only"
        or manifest.get("public_transform_version") != "neutral-public-artifact-names-v1"
        or manifest.get("release_state") != "Safe to publish"
    ):
        raise PermissionError("analytics source manifest is not an approved aggregate bundle")
    hashes = manifest.get("artifact_hashes")
    if not isinstance(hashes, dict) or set(hashes) != {"index.html", "partner-talent-brief.pdf"}:
        raise ValueError("analytics source artifact hashes are invalid")
    for path in (index, pdf):
        expected = hashes.get(path.name)
        if not isinstance(expected, str) or not _HASH.fullmatch(expected):
            raise ValueError("analytics source artifact hash is invalid")
        if not hmac.compare_digest(_sha256(path), expected):
            raise PermissionError("analytics source artifact hash does not match")
    return manifest, index, pdf, manifest_path


def prepare_analytics_publication_bundle(
    *,
    source_directory: str | Path,
    destination: str | Path,
    approval: AnalyticsActivationApproval,
    public_key: str,
    posthog_host: str,
    personal_api_key: str,
    posthog_project_id: int,
    now: datetime,
    artifact_path: str | Path | None = None,
    posthog_privacy_artifact_path: str | Path | None = None,
) -> dict[str, object]:
    """Prepare, but never deploy, one analytics-enabled static partner bundle."""

    _require_aware(now, "now")
    if not isinstance(approval, AnalyticsActivationApproval):
        raise TypeError("explicit analytics approval is required")
    if approval.scope != "privacy_limited_posthog":
        raise PermissionError("analytics approval scope is invalid")
    if approval.approved_at > now:
        raise PermissionError("analytics approval is in the future")
    if now >= approval.expires_at:
        raise PermissionError("analytics approval has expired")
    if not isinstance(public_key, str) or not _PUBLIC_KEY.fullmatch(public_key):
        raise ValueError("configured PostHog public key is invalid")
    host = _normalized_host(posthog_host)
    posthog_privacy_verification = verify_posthog_project_privacy(
        personal_api_key=personal_api_key,
        project_id=posthog_project_id,
        public_key=public_key,
        now=now,
        artifact_path=posthog_privacy_artifact_path,
    )
    privacy_receipt_sha256 = _validate_posthog_privacy_verification(
        posthog_privacy_verification,
        public_key=public_key,
        posthog_host=host,
        now=now,
    )
    if not hmac.compare_digest(
        approval.posthog_privacy_receipt_sha256,
        privacy_receipt_sha256,
    ):
        raise PermissionError("analytics approval PostHog privacy receipt does not match")
    source = Path(source_directory)
    target = Path(destination)
    source_resolved = source.resolve()
    target_resolved = target.resolve()
    if (
        source_resolved == target_resolved
        or source_resolved in target_resolved.parents
        or target_resolved in source_resolved.parents
    ):
        raise ValueError("analytics destination must be separate from its source bundle")
    manifest, index, pdf, manifest_path = _validate_static_source(source)
    source_manifest_sha256 = _sha256(manifest_path)
    source_index_sha256 = _sha256(index)
    if not hmac.compare_digest(approval.report_sha256, source_index_sha256):
        raise PermissionError("analytics approval report hash does not match")
    if not hmac.compare_digest(
        approval.publication_manifest_sha256, source_manifest_sha256,
    ):
        raise PermissionError("analytics approval manifest hash does not match")
    source_html = index.read_text(encoding="utf-8")
    for forbidden in (
        "document.cookie", "document.referrer", "localStorage", "sessionStorage",
    ):
        if forbidden in source_html:
            raise PermissionError("source report contains a forbidden tracking primitive")
    enriched_html, csp = _analytics_html(
        source_html,
        public_key=public_key,
        host=host,
        report_version=str(manifest["artifact_set_sha256"]),
    )
    from community_os.publication import _FORBIDDEN_TEXT, _install_publication_set

    if any(pattern.search(enriched_html) for pattern in _FORBIDDEN_TEXT):
        raise ValueError("analytics report contains forbidden personal or protected data")
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.is_symlink() or (target.exists() and not target.is_dir()):
        raise ValueError("analytics destination is not a trusted directory")
    with tempfile.TemporaryDirectory(
        prefix="start-community-os-analytics-", dir=target.parent,
    ) as temporary_directory:
        staged = Path(temporary_directory)
        staged_index = staged / "index.html"
        staged_pdf = staged / "partner-talent-brief.pdf"
        staged_vercel_config = staged / "vercel.json"
        staged_index.write_text(enriched_html, encoding="utf-8")
        staged_pdf.write_bytes(pdf.read_bytes())
        staged_vercel_config.write_text(_vercel_config(csp), encoding="utf-8")
        hashes = {
            path.name: _sha256(path)
            for path in (staged_vercel_config, staged_index, staged_pdf)
        }
        final_manifest = {
            **manifest,
            "analytics_enabled": True,
            "analytics_policy_version": "posthog-minimal-v2",
            "artifact_hashes": hashes,
            "manifest_version": "partner-static-bundle-v2",
            "posthog_privacy_receipt_sha256": privacy_receipt_sha256,
            "source_index_sha256": source_index_sha256,
            "source_manifest_sha256": source_manifest_sha256,
        }
        (staged / "publication-manifest.json").write_text(
            json.dumps(final_manifest, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        _install_publication_set(staged, target)
    audit_artifact: dict[str, object] = {
        "activation_receipt": {
            "activation_state": "ready_to_publish",
            "actor_code": approval.actor_code,
            "approval_code": approval.approval_code,
            "prepared_at": _iso(now),
            "source_index_sha256": source_index_sha256,
            "source_manifest_sha256": source_manifest_sha256,
        },
        "analytics_policy": {
            "api_host": host,
            "allowed_events": [
                "cohort_selected", "metric_selected", "overlap_region_selected",
                "pdf_downloaded", "report_opened",
            ],
            "allowed_properties": [
                "cohort_key", "metric_key", "overlap_region", "report_version",
            ],
            "identity_mode": "ephemeral_per_page_load",
            "ip_capture_disabled_confirmed": True,
            "person_profile_processing": False,
            "persistence": "memory_only",
            "posthog_privacy_receipt_sha256": privacy_receipt_sha256,
        },
        "artifact_version": "analytics-publication-v1",
    }
    if artifact_path is not None:
        _write_artifact(Path(artifact_path), audit_artifact)
    return final_manifest
