from __future__ import annotations

from datetime import UTC, datetime, timedelta
import json
from pathlib import Path
import tempfile
import unittest

from community_os.enrichment.cache import CanonicalJsonCache
from community_os.enrichment.evidence_vault import ProtectedEvidenceVault
from community_os.enrichment.github import GitHubAdapter
from community_os.enrichment.gates import PublicSourceGate
from community_os.enrichment.public_pages import PublicPageAdapter
from community_os.enrichment.state import PipelineState, StageStatus
from community_os.enrichment.transport import (
    ApplicantSuppliedValue, HttpResponse, PinnedHttpsTransport, RateLimitError,
    RetryPolicy, call_with_retry, canonical_public_url,
)

FIXTURES = Path(__file__).parent / "fixtures" / "enrichment"


def source_gate(scope: str, retention_days: int) -> PublicSourceGate:
    return PublicSourceGate(
        notice_version="notice_v2", notice_sent_at="2026-07-13T08:00:00Z",
        objections_reconciled=True, exclusions_reconciled=True,
        suppressions_reconciled=True, deletions_reconciled=True,
        source_authorization_confirmed=True, provider_terms_version="terms_v1",
        source_scope=scope, purpose_code="aggregate_talent_evidence",
        retention_days=retention_days, accountable_owner="privacy_lead",
        approval_id="approval_001", approved_at="2026-07-13T09:00:00Z",
    )


class FixtureTransport:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []
    def request(self, method, url, *, headers, timeout, max_bytes):
        self.calls.append({"method": method, "url": url, "headers": headers, "timeout": timeout, "max_bytes": max_bytes})
        response = self.responses.pop(0)
        if len(response.body) > max_bytes:
            raise ValueError("response exceeds byte limit")
        return response


class EnrichmentAdapterTests(unittest.TestCase):
    def test_cache_is_canonical_expires_and_rejects_tampering(self):
        now = datetime(2026, 7, 13, 10, tzinfo=UTC)
        with tempfile.TemporaryDirectory() as directory:
            cache = CanonicalJsonCache(Path(directory), clock=lambda: now)
            key = cache.key("github", "v1", {"b": 2, "a": 1})
            self.assertEqual(key, cache.key("github", "v1", {"a": 1, "b": 2}))
            cache.set(key, {"record_count": 1}, expires_at=now + timedelta(seconds=1))
            self.assertEqual(cache.get(key), {"record_count": 1})
            with self.assertRaises(ValueError):
                cache.set(key, {"bad": float("nan")}, expires_at=now + timedelta(days=1))
            expired = CanonicalJsonCache(Path(directory), clock=lambda: now + timedelta(seconds=2))
            self.assertIsNone(expired.get(key))
            cache = CanonicalJsonCache(Path(directory), clock=lambda: now)
            path = cache._path(key)
            path.write_text(json.dumps({"cache_version": cache.VERSION, "created_at": "bad", "expires_at": "2026-07-14T10:00:00Z", "key": key, "value": {}}))
            with self.assertRaises(ValueError):
                cache.get(key)

    def test_cache_hardens_existing_directory_and_can_delete_all_transient_entries(self):
        now = datetime(2026, 7, 13, 10, tzinfo=UTC)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "cache"
            root.mkdir(mode=0o755)
            root.chmod(0o755)
            cache = CanonicalJsonCache(root, clock=lambda: now)
            key = cache.key("github", "v1", {"subject_ref": "opaque"})
            cache.set(key, {"state": "observed"}, expires_at=now + timedelta(days=1))

            self.assertEqual(root.stat().st_mode & 0o777, 0o700)
            self.assertEqual(cache.delete_all(), 1)
            self.assertEqual(list(root.iterdir()), [])

    def test_retry_honors_rate_limit_and_is_bounded(self):
        attempts, sleeps = [], []
        def operation():
            attempts.append(1)
            if len(attempts) < 3:
                raise RateLimitError("limited", retry_after=4)
            return "ok"
        self.assertEqual(call_with_retry(operation, RetryPolicy(max_attempts=3), sleeps.append), "ok")
        self.assertEqual((len(attempts), sleeps), (3, [4, 4]))

    def test_github_is_minimized_cached_rate_limit_aware_and_source_verified(self):
        now = datetime(2026, 7, 13, 10, tzinfo=UTC)
        url = "https://api.github.com/users/fixture-builder"
        transport = FixtureTransport([
            HttpResponse(429, {"Retry-After": "2"}, b"{}", url),
            HttpResponse(200, {"Content-Type": "application/json"}, (FIXTURES / "github_user.json").read_bytes(), url),
            HttpResponse(200, {"Content-Type": "application/json"}, b"[]", url + "/repos"),
        ])
        verify = lambda ref: ref.source_record_ref == "source:application:001"
        with tempfile.TemporaryDirectory() as directory:
            state = PipelineState.create(Path(directory) / "state.json", {"github": StageStatus.LOCKED})
            gate = source_gate("applicant_supplied_github", 30)
            state.unlock("github", gate, now=now); state.start("github")
            adapter = GitHubAdapter(
                transport=transport, cache=CanonicalJsonCache(Path(directory), clock=lambda: now),
                pseudonym_secret=b"secret", clock=lambda: now, sleeper=lambda _seconds: None,
                source_verifier=verify,
            )
            reference = ApplicantSuppliedValue("https://github.com/fixture-builder", "source:application:001")
            result = adapter.enrich(reference, state=state, authorization=gate)
            self.assertEqual(result, adapter.enrich(ApplicantSuppliedValue("fixture-builder", "source:application:001"), state=state, authorization=gate))
            with self.assertRaises(PermissionError):
                adapter.enrich(ApplicantSuppliedValue("fixture-builder", "source:application:fake"), state=state, authorization=gate)
        self.assertEqual(len(transport.calls), 3)
        self.assertEqual(set(result), {
            "account_age_days", "evidence_ref", "forks_received", "last_public_update",
            "owned_public_repos_sampled", "public_repos", "recently_active_repos",
            "stars_received", "state", "technology_codes",
        })
        self.assertNotIn("fixture-builder", json.dumps(result))

    def test_github_derives_bounded_repository_activity_without_persisting_repo_text(self):
        now = datetime(2026, 7, 13, 10, tzinfo=UTC)
        profile_url = "https://api.github.com/users/fixture-builder"
        repositories_url = (
            "https://api.github.com/users/fixture-builder/repos"
            "?per_page=100&sort=updated&direction=desc"
        )
        repositories = [
            {
                "name": "private-looking-name", "description": "Jane Smith customer project",
                "fork": False, "archived": False, "disabled": False,
                "stargazers_count": 7, "forks_count": 2, "language": "Python",
                "pushed_at": "2026-06-01T00:00:00Z",
            },
            {
                "name": "web-client", "description": "person@example.org",
                "fork": False, "archived": False, "disabled": False,
                "stargazers_count": 3, "forks_count": 1, "language": "TypeScript",
                "pushed_at": "2024-01-01T00:00:00Z",
            },
            {
                "name": "forked", "description": "must not count as owned work",
                "fork": True, "archived": False, "disabled": False,
                "stargazers_count": 999, "forks_count": 999, "language": "Rust",
                "pushed_at": "2026-06-01T00:00:00Z",
            },
        ]
        transport = FixtureTransport([
            HttpResponse(
                200, {"Content-Type": "application/json"},
                (FIXTURES / "github_user.json").read_bytes(), profile_url,
            ),
            HttpResponse(
                200, {"Content-Type": "application/json"},
                json.dumps(repositories).encode(), repositories_url,
            ),
        ])
        with tempfile.TemporaryDirectory() as directory:
            vault = ProtectedEvidenceVault(
                Path(directory) / "protected" / "raw-evidence", clock=lambda: now,
            )
            state = PipelineState.create(
                Path(directory) / "state.json", {"github": StageStatus.LOCKED},
            )
            gate = source_gate("applicant_supplied_github", 30)
            state.unlock("github", gate, now=now)
            state.start("github")
            adapter = GitHubAdapter(
                transport=transport,
                cache=CanonicalJsonCache(Path(directory) / "cache", clock=lambda: now),
                pseudonym_secret=b"secret", clock=lambda: now,
                sleeper=lambda _seconds: None, source_verifier=lambda _ref: True,
                evidence_vault=vault,
            )
            subject_ref = "pid:v1:" + "c" * 64
            result = adapter.enrich(
                ApplicantSuppliedValue(
                    "https://github.com/fixture-builder", "source:application:001",
                ),
                state=state, authorization=gate, subject_ref=subject_ref,
            )
            temporary_evidence = vault.read(
                result["evidence_ref"], source="github", subject_ref=subject_ref,
            ).decode("utf-8")

        self.assertEqual([call["url"] for call in transport.calls], [profile_url, repositories_url])
        self.assertEqual(result["owned_public_repos_sampled"], 2)
        self.assertEqual(result["recently_active_repos"], 1)
        self.assertEqual(result["stars_received"], 10)
        self.assertEqual(result["forks_received"], 3)
        self.assertEqual(result["technology_codes"], ["javascript_typescript", "python"])
        serialized = json.dumps(result, sort_keys=True)
        for forbidden in (
            "private-looking-name", "Jane Smith", "person@example.org", "web-client",
        ):
            self.assertNotIn(forbidden, serialized)
            self.assertNotIn(forbidden, temporary_evidence)

    def test_github_semantic_assessment_receives_only_structural_vectors(self):
        now = datetime(2026, 7, 13, 10, tzinfo=UTC)
        profile_url = "https://api.github.com/users/fixture-builder"
        repositories_url = (
            profile_url + "/repos?per_page=100&sort=updated&direction=desc"
        )
        repositories = [{
            "name": "secret-product-name",
            "description": "Jane Smith customer product",
            "html_url": "https://github.com/fixture-builder/secret-product-name",
            "topics": ["medical", "private-customer"],
            "fork": False, "archived": False, "disabled": False,
            "is_template": False, "created_at": "2024-01-01T00:00:00Z",
            "pushed_at": "2026-06-01T00:00:00Z", "size": 2500,
            "stargazers_count": 12, "forks_count": 3, "open_issues_count": 2,
            "language": "Python", "has_pages": True, "has_issues": True,
            "license": {"key": "mit"},
        }]

        class Assessor:
            cache_identity = "github-project-assessment-v1:structural-project-evidence-v1:gpt-5.6-luna"

            def __init__(self):
                self.calls = []

            def assess(self, projects):
                self.calls.append(projects)
                return {
                    "evidence_strength": "moderate", "maintenance": "active",
                    "external_validation": "moderate", "productization": "moderate",
                    "categories": ["data_ai"],
                    "reason_codes": ["external_interest", "recent_activity"],
                    "confidence_state": "medium", "review_state": "human_review_required",
                }

        assessor = Assessor()
        transport = FixtureTransport([
            HttpResponse(
                200, {"Content-Type": "application/json"},
                (FIXTURES / "github_user.json").read_bytes(), profile_url,
            ),
            HttpResponse(
                200, {"Content-Type": "application/json"},
                json.dumps(repositories).encode(), repositories_url,
            ),
        ])
        with tempfile.TemporaryDirectory() as directory:
            state = PipelineState.create(
                Path(directory) / "state.json", {"github": StageStatus.LOCKED},
            )
            gate = source_gate("applicant_supplied_github", 30)
            state.unlock("github", gate, now=now)
            state.start("github")
            cache = CanonicalJsonCache(Path(directory) / "cache", clock=lambda: now)
            stale_key = cache.key(
                "github", GitHubAdapter.VERSION,
                {
                    "source_record_ref": "source:application:001",
                    "username": "fixture-builder",
                },
            )
            cache.set(
                stale_key, {"reason_code": "legacy_without_semantics", "state": "unknown"},
                expires_at=now + timedelta(days=1),
            )
            adapter = GitHubAdapter(
                transport=transport,
                cache=cache,
                pseudonym_secret=b"secret", clock=lambda: now,
                sleeper=lambda _seconds: None, source_verifier=lambda _ref: True,
                project_assessor=assessor,
            )
            result = adapter.enrich(
                ApplicantSuppliedValue(
                    "https://github.com/fixture-builder", "source:application:001",
                ),
                state=state, authorization=gate,
                subject_ref="pid:v1:" + "a" * 64,
            )

        self.assertEqual(len(assessor.calls), 1)
        vectors = assessor.calls[0]
        self.assertEqual(len(vectors), 1)
        self.assertEqual(vectors[0]["project_code"], "project_01")
        self.assertEqual(result["project_assessment"]["evidence_strength"], "moderate")
        serialized = json.dumps({"vectors": vectors, "result": result}).casefold()
        for forbidden in (
            "secret-product-name", "jane smith", "github.com", "medical",
            "private-customer", "description", "topics",
        ):
            self.assertNotIn(forbidden, serialized)

    def test_missing_github_profile_is_a_minimized_unknown_not_a_stage_failure(self):
        now = datetime(2026, 7, 13, 10, tzinfo=UTC)
        url = "https://api.github.com/users/deleted-profile"
        transport = FixtureTransport([
            HttpResponse(404, {"Content-Type": "application/json"}, b'{"message":"Not Found"}', url),
        ])
        with tempfile.TemporaryDirectory() as directory:
            state = PipelineState.create(
                Path(directory) / "state.json", {"github": StageStatus.LOCKED},
            )
            gate = source_gate("applicant_supplied_github", 30)
            state.unlock("github", gate, now=now)
            state.start("github")
            adapter = GitHubAdapter(
                transport=transport,
                cache=CanonicalJsonCache(Path(directory) / "cache", clock=lambda: now),
                pseudonym_secret=b"secret", clock=lambda: now,
                sleeper=lambda _seconds: None, source_verifier=lambda _ref: True,
            )
            result = adapter.enrich(
                ApplicantSuppliedValue("deleted-profile", "source:application:001"),
                state=state, authorization=gate,
            )

        self.assertEqual(result, {"reason_code": "profile_not_found", "state": "unknown"})
        self.assertNotIn("deleted-profile", json.dumps(result))

    def test_github_retry_uses_a_new_evidence_reference_after_failed_attempt_cleanup(self):
        now = datetime(2026, 7, 13, 10, tzinfo=UTC)
        profile_url = "https://api.github.com/users/fixture-builder"
        repositories_url = profile_url + "/repos"
        profile = HttpResponse(
            200, {"Content-Type": "application/json"},
            (FIXTURES / "github_user.json").read_bytes(), profile_url,
        )
        repositories = HttpResponse(
            200, {"Content-Type": "application/json"}, b"[]", repositories_url,
        )
        transport = FixtureTransport([profile, repositories, profile, repositories])
        with tempfile.TemporaryDirectory() as directory:
            state = PipelineState.create(
                Path(directory) / "state.json", {"github": StageStatus.LOCKED},
            )
            gate = source_gate("applicant_supplied_github", 30)
            state.unlock("github", gate, now=now)
            state.start("github")
            vault = ProtectedEvidenceVault(
                Path(directory) / "protected" / "raw-evidence", clock=lambda: now,
            )
            adapter = GitHubAdapter(
                transport=transport,
                cache=CanonicalJsonCache(Path(directory) / "cache", clock=lambda: now),
                pseudonym_secret=b"secret", clock=lambda: now,
                sleeper=lambda _seconds: None, source_verifier=lambda _ref: True,
                evidence_vault=vault,
            )
            reference = ApplicantSuppliedValue(
                "fixture-builder", "source:application:001",
            )
            first = adapter.enrich(
                reference, state=state, authorization=gate,
                subject_ref="pid:v1:" + "c" * 64,
            )
            adapter.discard_transient()
            state.fail("github", "fixture_failure")
            state.resume("github")
            second = adapter.enrich(
                reference, state=state, authorization=gate,
                subject_ref="pid:v1:" + "c" * 64,
            )
            retained_records = len(list(vault.records.glob("*.json")))

        self.assertNotEqual(first["evidence_ref"], second["evidence_ref"])
        self.assertEqual(retained_records, 1)

    def test_duplicate_supplied_handle_is_bound_to_each_pseudonymous_subject(self):
        now = datetime(2026, 7, 13, 10, tzinfo=UTC)
        profile_url = "https://api.github.com/users/fixture-builder"
        profile = HttpResponse(
            200, {"Content-Type": "application/json"},
            (FIXTURES / "github_user.json").read_bytes(), profile_url,
        )
        repositories = HttpResponse(
            200, {"Content-Type": "application/json"}, b"[]", profile_url + "/repos",
        )
        transport = FixtureTransport([profile, repositories, profile, repositories])
        with tempfile.TemporaryDirectory() as directory:
            state = PipelineState.create(
                Path(directory) / "state.json", {"github": StageStatus.LOCKED},
            )
            gate = source_gate("applicant_supplied_github", 30)
            state.unlock("github", gate, now=now)
            state.start("github")
            vault = ProtectedEvidenceVault(
                Path(directory) / "protected" / "raw-evidence", clock=lambda: now,
            )
            adapter = GitHubAdapter(
                transport=transport,
                cache=CanonicalJsonCache(Path(directory) / "cache", clock=lambda: now),
                pseudonym_secret=b"secret", clock=lambda: now,
                sleeper=lambda _seconds: None, source_verifier=lambda _ref: True,
                evidence_vault=vault,
            )
            first = adapter.enrich(
                ApplicantSuppliedValue("fixture-builder", "source:application:001"),
                state=state, authorization=gate,
                subject_ref="pid:v1:" + "a" * 64,
            )
            second = adapter.enrich(
                ApplicantSuppliedValue("fixture-builder", "source:application:002"),
                state=state, authorization=gate,
                subject_ref="pid:v1:" + "b" * 64,
            )

        self.assertNotEqual(first["evidence_ref"], second["evidence_ref"])

    def test_public_pages_block_ssrf_validate_source_and_extract_bounded_visible_text(self):
        self.assertEqual(PublicPageAdapter.VERSION, "applicant-public-page-v2")
        now = datetime(2026, 7, 13, 10, tzinfo=UTC)
        transport = FixtureTransport([HttpResponse(200, {"Content-Type": "text/html"}, (FIXTURES / "public_page.html").read_bytes(), "https://portfolio.example/work")])
        with tempfile.TemporaryDirectory() as directory:
            state = PipelineState.create(Path(directory) / "state.json", {"public_pages": StageStatus.LOCKED})
            gate = source_gate("applicant_supplied_public_pages", 14)
            state.unlock("public_pages", gate, now=now); state.start("public_pages")
            adapter = PublicPageAdapter(
                transport=transport, cache=CanonicalJsonCache(Path(directory), clock=lambda: now),
                pseudonym_secret=b"secret", clock=lambda: now,
                source_verifier=lambda ref: ref.source_record_ref == "source:application:001",
                evidence_vault=ProtectedEvidenceVault(
                    Path(directory) / "protected" / "raw-evidence", clock=lambda: now,
                ),
            )
            subject_ref = "pid:v1:" + "c" * 64
            result = adapter.enrich(
                ApplicantSuppliedValue("https://Portfolio.Example/work", "source:application:001"),
                state=state, authorization=gate, subject_ref=subject_ref,
            )
            raw = adapter.evidence_vault.read(
                result["evidence_ref"], source="public_pages", subject_ref=subject_ref,
            )
        self.assertNotIn("text", result)
        from community_os.enrichment.public_pages import extract_visible_text
        extracted = extract_visible_text(raw)
        self.assertIn("Production systems", extracted)
        self.assertNotIn("secret", extracted)
        self.assertNotIn("portfolio.example", json.dumps(result))
        for unsafe in (
            "http://portfolio.example/work", "https://user:pass@portfolio.example/work",
            "https://localhost/work", "https://127.0.0.1/work", "https://127.1/work",
            "https://127.0.1/work", "https://10.0.0.1/work", "https://2130706433/work",
            "https://0177.0.0.1/work", "https://0x7f000001/work", "https://%31%32%37.0.0.1/work",
            "https://portfolio.example:8443/work", "https://portfolio.example/work#fragment",
        ):
            with self.subTest(unsafe=unsafe), self.assertRaises(ValueError):
                canonical_public_url(unsafe)
        self.assertEqual(
            canonical_public_url(
                "https://api.coresignal.com/cdapi/v2/employee_multi_source/collect/https%3A%2F%2Fwww.linkedin.com%2Fin%2Fbuilder"
            ),
            "https://api.coresignal.com/cdapi/v2/employee_multi_source/collect/https%3A%2F%2Fwww.linkedin.com%2Fin%2Fbuilder",
        )

    def test_transport_blocks_redirect_before_private_contact_and_sensitive_token_forward(self):
        class Response:
            status = 302
            def getheaders(self): return [("Location", "https://other.example/private")]
            def read(self, _size): return b""
        class Connection:
            def request(self, *_args, **_kwargs): return None
            def getresponse(self): return Response()
            def close(self): return None
        for header, value in (
            ("authorization", "Bearer TOPSECRET"),
            ("apikey", "TOPSECRET"),
            ("X-API-Key", "TOPSECRET"),
            ("Cookie", "session=TOPSECRET"),
        ):
            with self.subTest(header=header):
                created = []
                def factory(host, address, _timeout):
                    created.append((host, address)); return Connection()
                transport = PinnedHttpsTransport(
                    resolver=lambda _host: ["93.184.216.34"], connection_factory=factory,
                    monotonic=lambda: 0.0,
                )
                with self.assertRaisesRegex(ValueError, "authenticated redirect"):
                    transport.request(
                        "GET", "https://api.github.com/users/a",
                        headers={header: value}, timeout=8, max_bytes=1024,
                    )
                self.assertEqual(created, [("api.github.com", "93.184.216.34")])


if __name__ == "__main__":
    unittest.main()
