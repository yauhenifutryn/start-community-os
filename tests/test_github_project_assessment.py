from __future__ import annotations

from datetime import UTC, datetime, timedelta
import json
from pathlib import Path
import tempfile
import unittest

from community_os.enrichment.cache import CanonicalJsonCache
from community_os.enrichment.github_assessment import (
    GitHubProjectAssessor,
    build_project_vectors,
)
from community_os.enrichment.openai_github_assessment import (
    OpenAIGitHubAssessmentProvider,
)
from community_os.enrichment.transport import HttpResponse


NOW = datetime(2026, 7, 15, 12, tzinfo=UTC)


def semantic_result(**overrides: object) -> dict[str, object]:
    result: dict[str, object] = {
        "evidence_strength": "moderate",
        "maintenance": "active",
        "external_validation": "limited",
        "productization": "moderate",
        "categories": ["backend", "data_ai"],
        "reason_codes": ["multiple_projects", "recent_activity"],
        "confidence_state": "medium",
        "review_state": "human_review_required",
    }
    result.update(overrides)
    return result


class FakeResponsesTransport:
    def __init__(self, result: dict[str, object]) -> None:
        self.requests: list[dict[str, object]] = []
        self.result = result

    def request(
        self, *, headers: dict[str, str], body: bytes, timeout: float, max_bytes: int,
    ) -> HttpResponse:
        self.requests.append({
            "headers": dict(headers), "body": body, "timeout": timeout,
            "max_bytes": max_bytes,
        })
        envelope = {
            "status": "completed",
            "output": [{
                "type": "message",
                "content": [{"type": "output_text", "text": json.dumps(self.result)}],
            }],
        }
        return HttpResponse(
            200, {}, json.dumps(envelope).encode("utf-8"),
            "https://api.openai.com/v1/responses",
        )


class GitHubProjectVectorTests(unittest.TestCase):
    def test_builds_at_most_six_call_local_structural_vectors_without_repo_text(self) -> None:
        repositories = []
        for index in range(9):
            repositories.append({
                "name": f"secret-repo-{index}",
                "description": f"Jane Smith customer product {index}",
                "html_url": f"https://github.com/jane/secret-repo-{index}",
                "topics": ["private-customer", "medical"],
                "fork": False,
                "archived": False,
                "disabled": False,
                "is_template": False,
                "created_at": f"202{index % 5}-01-01T00:00:00Z",
                "pushed_at": f"2026-0{(index % 6) + 1}-01T00:00:00Z",
                "size": 100 + index * 1000,
                "stargazers_count": index,
                "forks_count": index // 2,
                "open_issues_count": index % 3,
                "language": "Python" if index % 2 else "TypeScript",
                "has_pages": index % 3 == 0,
                "has_issues": True,
                "license": {"key": "mit"} if index % 2 else None,
            })
        repositories.extend([
            {**repositories[0], "name": "fork", "fork": True},
            {**repositories[0], "name": "archive", "archived": True},
            {**repositories[0], "name": "disabled", "disabled": True},
            {**repositories[0], "name": "template", "is_template": True},
        ])

        vectors = build_project_vectors(repositories, now=NOW)

        self.assertEqual(len(vectors), 6)
        self.assertEqual(
            [vector["project_code"] for vector in vectors],
            [f"project_{index:02d}" for index in range(1, 7)],
        )
        serialized = json.dumps(vectors, sort_keys=True).casefold()
        for forbidden in (
            "secret-repo", "jane smith", "github.com", "private-customer",
            "medical", "description", "html_url", "topics",
        ):
            self.assertNotIn(forbidden, serialized)
        allowed_fields = {
            "project_code", "age_band", "activity_recency", "size_band",
            "stars_band", "forks_band", "issues_band", "language_code",
            "productization_codes",
        }
        self.assertTrue(all(set(vector) == allowed_fields for vector in vectors))

    def test_invalid_repository_structure_fails_closed(self) -> None:
        with self.assertRaises(ValueError):
            build_project_vectors([{
                "fork": "false", "archived": False, "disabled": False,
                "is_template": False,
            }], now=NOW)


class OpenAIGitHubAssessmentProviderTests(unittest.TestCase):
    def test_request_is_luna_none_store_false_strict_and_contains_only_safe_vectors(self) -> None:
        transport = FakeResponsesTransport(semantic_result())
        provider = OpenAIGitHubAssessmentProvider(
            api_key="fixture-key-not-secret", transport=transport,
            sleeper=lambda _seconds: None,
        )
        vectors = build_project_vectors([{
            "name": "do-not-send-this-name",
            "description": "person@example.org Jane Smith customer project",
            "html_url": "https://github.com/jane/do-not-send-this-name",
            "topics": ["medical"],
            "fork": False, "archived": False, "disabled": False,
            "is_template": False, "created_at": "2024-01-01T00:00:00Z",
            "pushed_at": "2026-07-01T00:00:00Z", "size": 1200,
            "stargazers_count": 4, "forks_count": 1, "open_issues_count": 2,
            "language": "Python", "has_pages": True, "has_issues": True,
            "license": {"key": "mit"},
        }], now=NOW)

        result = provider({"projects": vectors})

        self.assertEqual(result, semantic_result())
        self.assertEqual(len(transport.requests), 1)
        request = transport.requests[0]
        body = json.loads(request["body"])
        self.assertEqual(body["model"], "gpt-5.6-luna")
        self.assertEqual(body["reasoning"], {"effort": "none"})
        self.assertIs(body["store"], False)
        self.assertIs(body["text"]["format"]["strict"], True)
        self.assertNotIn("tools", body)
        serialized = json.dumps(body, sort_keys=True).casefold()
        for forbidden in (
            "pid:v1", "subject_ref", "person@example.org", "jane smith",
            "github.com", "do-not-send-this-name", "description", "readme",
            "topics", "filename", "fixture-key-not-secret",
        ):
            self.assertNotIn(forbidden, serialized)
        self.assertEqual(
            request["headers"]["Authorization"], "Bearer fixture-key-not-secret",
        )

    def test_direct_provider_call_rejects_extra_fields_and_stable_identifiers_before_transport(self) -> None:
        transport = FakeResponsesTransport(semantic_result())
        provider = OpenAIGitHubAssessmentProvider(
            api_key="fixture-key-not-secret", transport=transport,
            sleeper=lambda _seconds: None,
        )

        for unsafe in (
            {"subject_ref": "pid:v1:" + "a" * 64, "projects": []},
            {"projects": [{"project_code": "repo_abcdef", "name": "private"}]},
            {"projects": [{"project_code": "project_01", "description": "private"}]},
        ):
            with self.assertRaises(ValueError):
                provider(unsafe)

        self.assertEqual(transport.requests, [])


class GitHubProjectAssessorTests(unittest.TestCase):
    def test_retention_is_required_and_cannot_exceed_evaluation_approval_limit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            cache = CanonicalJsonCache(Path(directory), clock=lambda: NOW)
            with self.assertRaises(TypeError):
                GitHubProjectAssessor(
                    provider=lambda _payload: semantic_result(),
                    cache=cache, clock=lambda: NOW,
                )
            with self.assertRaises(ValueError):
                GitHubProjectAssessor(
                    provider=lambda _payload: semantic_result(),
                    cache=cache, clock=lambda: NOW, retention_days=8,
                )

    def test_assessment_is_deterministically_cached_and_validated(self) -> None:
        calls: list[dict[str, object]] = []

        def provider(payload: dict[str, object]) -> dict[str, object]:
            calls.append(payload)
            return semantic_result()

        vectors = [{
            "project_code": "project_01", "age_band": "established",
            "activity_recency": "active_90d", "size_band": "small",
            "stars_band": "some", "forks_band": "some", "issues_band": "some",
            "language_code": "python",
            "productization_codes": ["issues_enabled", "license_present"],
        }]
        with tempfile.TemporaryDirectory() as directory:
            assessor = GitHubProjectAssessor(
                provider=provider,
                cache=CanonicalJsonCache(Path(directory), clock=lambda: NOW),
                clock=lambda: NOW, retention_days=7,
            )
            first = assessor.assess(vectors)
            second = assessor.assess(vectors)

        self.assertEqual(first, semantic_result())
        self.assertEqual(second, first)
        self.assertEqual(calls, [{"projects": vectors}])

    def test_uncertain_or_consequential_output_remains_human_review_gated(self) -> None:
        for result in (
            semantic_result(confidence_state="low", review_state="ready"),
            semantic_result(evidence_strength="strong", review_state="ready"),
            semantic_result(categories=["private_personality_trait"]),
        ):
            with tempfile.TemporaryDirectory() as directory:
                assessor = GitHubProjectAssessor(
                    provider=lambda _payload, value=result: value,
                    cache=CanonicalJsonCache(Path(directory), clock=lambda: NOW),
                    clock=lambda: NOW, retention_days=7,
                )
                with self.assertRaises(ValueError):
                    assessor.assess([])

    def test_evaluation_cache_expiry_obeys_the_short_approved_retention(self) -> None:
        current = [NOW]
        calls = []
        with tempfile.TemporaryDirectory() as directory:
            assessor = GitHubProjectAssessor(
                provider=lambda payload: calls.append(payload) or semantic_result(),
                cache=CanonicalJsonCache(Path(directory), clock=lambda: current[0]),
                clock=lambda: current[0], retention_days=1,
            )
            assessor.assess([])
            current[0] = NOW + timedelta(days=2)
            assessor.assess([])

        self.assertEqual(len(calls), 2)


if __name__ == "__main__":
    unittest.main()
