"""Minimized GitHub enrichment for applicant-supplied profile identifiers."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime
import hashlib
import hmac
import json
import re
from typing import Callable
from urllib.parse import quote, urlparse

from community_os.enrichment.cache import CanonicalJsonCache
from community_os.enrichment.evidence_vault import ProtectedEvidenceVault
from community_os.enrichment.gates import PublicSourceGate
from community_os.enrichment.github_assessment import (
    build_project_vectors, validate_assessment,
)
from community_os.enrichment.github_content_evidence import (
    build_rich_project_packets,
    select_rich_repository_indices,
)
from community_os.enrichment.state import PipelineState, StageStatus
from community_os.enrichment.transport import (
    ApplicantSuppliedValue, RateLimitError, ResponseTooLargeError, RetryPolicy,
    RetryableTransportError, Transport, call_with_retry,
)


_USERNAME = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$")
_SUBJECT_REF = re.compile(r"^pid:v1:[0-9a-f]{64}$")
_REPOSITORY_NAME = re.compile(r"^[A-Za-z0-9._-]{1,100}$")
_RICH_PROFILE_PHYSICAL_REQUEST_BUDGET = 11
_LANGUAGE_CODES = {
    "c": "systems", "c++": "systems", "c#": "dotnet", "css": "web_frontend",
    "dart": "dart", "f#": "dotnet", "go": "go", "html": "web_frontend",
    "java": "jvm", "javascript": "javascript_typescript",
    "jupyter notebook": "data_notebook", "kotlin": "jvm", "php": "php",
    "python": "python", "ruby": "ruby", "rust": "rust", "shell": "shell",
    "svelte": "web_frontend", "swift": "swift",
    "typescript": "javascript_typescript", "vue": "web_frontend",
}


def _username(value: str) -> str:
    candidate = value.strip()
    if "://" in candidate:
        parsed = urlparse(candidate)
        if parsed.scheme != "https" or parsed.hostname != "github.com" or parsed.query or parsed.fragment:
            raise ValueError("GitHub identifier must be a github.com profile")
        parts = [part for part in parsed.path.split("/") if part]
        if len(parts) != 1:
            raise ValueError("GitHub identifier must name one profile")
        candidate = parts[0]
    if not _USERNAME.fullmatch(candidate) or candidate.casefold() == "localhost":
        raise ValueError("invalid GitHub username")
    return candidate


class GitHubAdapter:
    VERSION = "github-public-activity-v3"
    RICH_EVIDENCE_VERSION = "rich-project-evidence-v10"

    def __init__(
        self, *, transport: Transport, cache: CanonicalJsonCache, pseudonym_secret: bytes,
        clock: Callable[[], datetime], sleeper: Callable[[float], None],
        source_verifier: Callable[[ApplicantSuppliedValue], bool], token: str | None = None,
        evidence_vault: ProtectedEvidenceVault | None = None,
        project_assessor: object | None = None,
        collect_rich_evidence: bool = False,
        identity_literals: tuple[str, ...] = (),
        subject_identity_literals: Mapping[str, tuple[str, ...]] | None = None,
    ) -> None:
        if not pseudonym_secret:
            raise ValueError("pseudonym secret is required")
        self.transport = transport
        self.cache = cache
        self.secret = pseudonym_secret
        self.clock = clock
        self.sleeper = sleeper
        self.source_verifier = source_verifier
        self.token = token
        self.evidence_vault = evidence_vault
        if project_assessor is not None and not callable(getattr(project_assessor, "assess", None)):
            raise ValueError("GitHub project assessor must expose an assess operation")
        if project_assessor is not None and not isinstance(
            getattr(project_assessor, "cache_identity", None), str,
        ):
            raise ValueError("GitHub project assessor must expose a cache identity")
        self.project_assessor = project_assessor
        if type(collect_rich_evidence) is not bool:
            raise ValueError("GitHub rich evidence flag must be boolean")
        if (
            not isinstance(identity_literals, tuple)
            or any(not isinstance(value, str) for value in identity_literals)
        ):
            raise ValueError("GitHub rich evidence identity literals are invalid")
        if collect_rich_evidence and (
            not identity_literals or any(not value.strip() for value in identity_literals)
        ):
            raise ValueError("GitHub rich evidence identity literals are required")
        subject_literals = (
            {} if subject_identity_literals is None else subject_identity_literals
        )
        if (
            not isinstance(subject_literals, Mapping)
            or any(
                not isinstance(subject, str)
                or _SUBJECT_REF.fullmatch(subject) is None
                or not isinstance(values, tuple)
                or not values
                or any(not isinstance(value, str) or not value.strip() for value in values)
                for subject, values in subject_literals.items()
            )
            or (collect_rich_evidence and not subject_literals)
        ):
            raise ValueError("GitHub rich evidence subject identity literals are invalid")
        self.collect_rich_evidence = collect_rich_evidence
        self.identity_literals = identity_literals
        self.subject_identity_literals = {
            subject: tuple(values)
            for subject, values in subject_literals.items()
        }

    def enrich(
        self, profile: ApplicantSuppliedValue | str, *, state: PipelineState,
        authorization: PublicSourceGate, subject_ref: str | None = None,
        collection_generation: int = 0,
    ) -> dict[str, object]:
        if (
            type(collection_generation) is not int
            or not 0 <= collection_generation <= 1_000_000
        ):
            raise ValueError("GitHub collection generation is invalid")
        if not isinstance(profile, ApplicantSuppliedValue):
            raise PermissionError("GitHub enrichment requires persisted applicant-source evidence")
        if self.source_verifier(profile) is not True:
            raise PermissionError("GitHub applicant-source evidence could not be verified")
        stage = state.stage("github")
        expected = authorization.authorization_hash("github", now=self.clock())
        if (
            stage.status is not StageStatus.RUNNING
            or stage.authorization_hash is None
            or not hmac.compare_digest(stage.authorization_hash, expected)
        ):
            raise PermissionError("GitHub stage is not authorized and running")
        username = _username(profile.value)
        current_identity_literals: tuple[str, ...] = ()
        identity_policy_sha256 = "not_applicable"
        if self.collect_rich_evidence:
            if (
                not isinstance(subject_ref, str)
                or _SUBJECT_REF.fullmatch(subject_ref) is None
                or subject_ref not in self.subject_identity_literals
            ):
                raise PermissionError(
                    "GitHub rich evidence subject identity binding is missing",
                )
            current_identity_literals = (
                self.identity_literals
                + self.subject_identity_literals[subject_ref]
                + (username,)
            )
            identity_policy_sha256 = hmac.new(
                self.secret,
                json.dumps(
                    sorted(
                        set(current_identity_literals),
                        key=lambda value: (value.casefold(), value),
                    ),
                    ensure_ascii=True,
                    separators=(",", ":"),
                ).encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()
        cache_version = self.VERSION
        if self.project_assessor is not None:
            cache_version += ":" + str(getattr(self.project_assessor, "cache_identity"))
        if self.collect_rich_evidence:
            cache_version += ":" + self.RICH_EVIDENCE_VERSION
        cache_key = self.cache.key(
            "github", cache_version,
            {
                "collection_generation": collection_generation,
                "identity_policy_sha256": identity_policy_sha256,
                "source_record_ref": profile.source_record_ref,
                "username": username.casefold(),
            },
        )
        cached = self.cache.get(cache_key)
        if cached is not None:
            return cached
        physical_request_count = 0

        def request(
            url: str, *, max_bytes: int,
            accept: str = "application/vnd.github+json",
        ) -> bytes | None:
            headers = {"Accept": accept, "User-Agent": "START-Community-OS/1"}
            if self.token:
                headers["Authorization"] = "Bearer " + self.token
            def send() -> bytes | None:
                nonlocal physical_request_count
                if (
                    self.collect_rich_evidence
                    and physical_request_count >= _RICH_PROFILE_PHYSICAL_REQUEST_BUDGET
                ):
                    raise RuntimeError("GitHub physical request budget exceeded")
                physical_request_count += 1
                response = self.transport.request(
                    "GET", url, headers=headers, timeout=8.0, max_bytes=max_bytes,
                )
                if response.status in {403, 429}:
                    raw = response.headers.get("Retry-After", "1")
                    try:
                        delay = float(raw)
                    except ValueError:
                        try:
                            delay = max(
                                1.0,
                                (parsedate_to_datetime(raw) - self.clock()).total_seconds(),
                            )
                        except (TypeError, ValueError):
                            delay = 1.0
                    raise RateLimitError("GitHub rate limit", retry_after=max(1.0, delay))
                if response.status >= 500:
                    raise RetryableTransportError("GitHub unavailable")
                if response.status == 404:
                    return None
                if response.status != 200:
                    raise ValueError("GitHub public activity request was not successful")
                return response.body

            return call_with_retry(send, RetryPolicy(), self.sleeper)

        def fetch() -> dict[str, object]:
            profile_body = request(
                "https://api.github.com/users/" + username, max_bytes=131072,
            )
            if profile_body is None:
                return {"reason_code": "profile_not_found", "state": "unknown"}
            repositories_body = request(
                "https://api.github.com/users/" + username
                + "/repos?per_page=100&sort=updated&direction=desc",
                max_bytes=1048576,
            )
            if repositories_body is None:
                return {"reason_code": "profile_not_found", "state": "unknown"}
            evidence_material = (
                f"{cache_version}:{stage.attempts}:{collection_generation}:"
                f"{profile.source_record_ref}:"
                f"{subject_ref or 'no_subject'}:{username.casefold()}:"
                f"{identity_policy_sha256}"
            ).encode("utf-8")
            evidence = hmac.new(
                self.secret, evidence_material, hashlib.sha256,
            ).hexdigest()
            evidence_ref = "evidence:github:" + evidence
            try:
                payload = json.loads(profile_body)
                repositories = json.loads(repositories_body)
                created = datetime.fromisoformat(str(payload["created_at"]).replace("Z", "+00:00"))
                updated = datetime.fromisoformat(str(payload["updated_at"]).replace("Z", "+00:00"))
                repos = int(payload["public_repos"])
                if not isinstance(repositories, list) or len(repositories) > 100:
                    raise TypeError("repositories must be a bounded list")
            except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
                raise ValueError("GitHub response did not match the allowlisted schema") from error
            now = self.clock().astimezone(UTC)
            rich_details: dict[int, dict[str, object]] = {}
            if self.collect_rich_evidence:
                for index in select_rich_repository_indices(repositories, now=now):
                    repository = repositories[index]
                    name = repository.get("name")
                    if not isinstance(name, str) or not _REPOSITORY_NAME.fullmatch(name):
                        raise ValueError("GitHub repository name is invalid")
                    base = (
                        "https://api.github.com/repos/" + quote(username, safe="")
                        + "/" + quote(name, safe="")
                    )
                    try:
                        readme_body = request(
                            base + "/readme", max_bytes=65_536,
                            accept="application/vnd.github.raw+json",
                        )
                    except ResponseTooLargeError:
                        readme_body = None
                    try:
                        releases_body = request(
                            base + "/releases?per_page=1", max_bytes=131_072,
                        )
                    except ResponseTooLargeError:
                        releases_body = None
                    try:
                        deployments_body = request(
                            base + "/deployments?per_page=1", max_bytes=131_072,
                        )
                    except ResponseTooLargeError:
                        deployments_body = None
                    try:
                        readme = None if readme_body is None else readme_body.decode("utf-8")
                        releases = None if releases_body is None else json.loads(releases_body)
                        deployments = None if deployments_body is None else json.loads(deployments_body)
                    except (UnicodeDecodeError, json.JSONDecodeError) as error:
                        raise ValueError("GitHub rich project detail failed validation") from error
                    rich_details[index] = {
                        "readme": readme,
                        "releases": releases,
                        "deployments": deployments,
                    }
            owned = 0
            recent = 0
            stars = 0
            forks = 0
            technologies: set[str] = set()
            try:
                for repository in repositories:
                    if not isinstance(repository, dict):
                        raise TypeError("repository must be an object")
                    fork = repository["fork"]
                    archived = repository["archived"]
                    disabled = repository["disabled"]
                    star_count = repository["stargazers_count"]
                    fork_count = repository["forks_count"]
                    language = repository.get("language")
                    pushed_at = repository.get("pushed_at")
                    if (
                        any(not isinstance(flag, bool) for flag in (fork, archived, disabled))
                        or isinstance(star_count, bool) or not isinstance(star_count, int)
                        or isinstance(fork_count, bool) or not isinstance(fork_count, int)
                        or star_count < 0 or fork_count < 0
                        or (language is not None and not isinstance(language, str))
                        or (pushed_at is not None and not isinstance(pushed_at, str))
                    ):
                        raise TypeError("repository fields are invalid")
                    if fork or archived or disabled:
                        continue
                    owned += 1
                    stars += star_count
                    forks += fork_count
                    if language:
                        code = _LANGUAGE_CODES.get(language.casefold())
                        if code is not None:
                            technologies.add(code)
                    if pushed_at:
                        pushed = datetime.fromisoformat(pushed_at.replace("Z", "+00:00"))
                        if pushed.tzinfo is None:
                            raise ValueError("repository timestamp requires a timezone")
                        if now - pushed.astimezone(UTC) <= timedelta(days=365):
                            recent += 1
            except (KeyError, TypeError, ValueError) as error:
                raise ValueError("GitHub response did not match the allowlisted schema") from error
            if self.evidence_vault is not None:
                if subject_ref is None:
                    raise PermissionError("GitHub raw evidence requires a pseudonymous subject")
                evidence_projection = {
                    "profile": {
                        "created_at": payload["created_at"],
                        "public_repos": repos,
                        "updated_at": payload["updated_at"],
                    },
                    "repositories": [
                        {
                            key: repository.get(key)
                            for key in (
                                "archived", "disabled", "fork", "forks_count",
                                "language", "pushed_at", "stargazers_count",
                            )
                        }
                        for repository in repositories
                    ],
                }
                self.evidence_vault.capture(
                    source="github", purpose="talent_classification",
                    subject_ref=subject_ref, evidence_ref=evidence_ref,
                    provider_version=self.VERSION, content_type="application/json",
                    payload=json.dumps(
                        evidence_projection,
                        ensure_ascii=True, sort_keys=True, separators=(",", ":"),
                    ).encode("utf-8"),
                    ttl=timedelta(hours=24),
                )
            result = {
                "account_age_days": max(0, (now - created.astimezone(UTC)).days),
                "evidence_ref": evidence_ref,
                "forks_received": forks,
                "last_public_update": updated.astimezone(UTC).date().isoformat(),
                "owned_public_repos_sampled": owned,
                "public_repos": max(0, repos),
                "recently_active_repos": recent,
                "state": "observed",
                "stars_received": stars,
                "technology_codes": sorted(technologies),
            }
            if self.collect_rich_evidence:
                result["rich_project_evidence"] = build_rich_project_packets(
                    repositories, rich_details, now=now,
                    identity_literals=current_identity_literals,
                )
            if self.project_assessor is not None:
                vectors = build_project_vectors(repositories, now=now)
                assessment = getattr(self.project_assessor, "assess")(vectors)
                result["project_assessment"] = validate_assessment(assessment)
            return result

        result = fetch()
        self.cache.set(
            cache_key, result,
            expires_at=self.clock() + timedelta(days=min(
                authorization.retention_days, 7 if self.collect_rich_evidence else authorization.retention_days,
            )),
        )
        return result

    def discard_transient(self) -> None:
        if self.evidence_vault is not None:
            self.evidence_vault.delete_source("github", reason="github_stage_failed")
        self.cache.delete_all()
