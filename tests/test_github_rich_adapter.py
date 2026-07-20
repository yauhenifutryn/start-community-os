from __future__ import annotations

from datetime import UTC, datetime
import json
from pathlib import Path
import tempfile
import unittest

from community_os.enrichment.cache import CanonicalJsonCache
from community_os.enrichment.gates import PublicSourceGate
from community_os.enrichment.github import GitHubAdapter
from community_os.enrichment.github_content_evidence import select_rich_repository_indices
from community_os.enrichment.state import PipelineState, StageStatus
from community_os.enrichment.transport import (
    ApplicantSuppliedValue, HttpResponse, ResponseTooLargeError,
)


NOW = datetime(2026, 7, 15, 12, tzinfo=UTC)
SUBJECT_REF = "pid:v1:" + "a" * 64
OTHER_SUBJECT_REF = "pid:v1:" + "b" * 64


def gate() -> PublicSourceGate:
    return PublicSourceGate(
        notice_version="notice_v2", notice_sent_at="2026-07-13T08:00:00Z",
        objections_reconciled=True, exclusions_reconciled=True,
        suppressions_reconciled=True, deletions_reconciled=True,
        source_authorization_confirmed=True, provider_terms_version="terms_v1",
        source_scope="applicant_supplied_github", purpose_code="aggregate_talent_evidence",
        retention_days=30, accountable_owner="privacy_lead",
        approval_id="approval_001", approved_at="2026-07-13T09:00:00Z",
    )


def repository(index: int) -> dict[str, object]:
    return {
        "name": f"private-product-{index}",
        "description": "A working scheduling product for schools by Jane Smith.",
        "topics": ["education", "artificial-intelligence"],
        "homepage": "https://product.example.org",
        "fork": False, "archived": False, "disabled": False, "is_template": False,
        "created_at": "2025-01-01T00:00:00Z",
        "pushed_at": f"2026-07-0{index + 1}T00:00:00Z", "size": 5000,
        "stargazers_count": 10 - index, "forks_count": 0, "open_issues_count": 2,
        "language": "Python", "has_pages": False, "has_issues": True,
        "license": {"key": "mit"},
    }


class RoutingTransport:
    def __init__(self, responses: dict[str, HttpResponse]) -> None:
        self.responses = responses
        self.calls: list[dict[str, object]] = []

    def request(self, method, url, *, headers, timeout, max_bytes):
        self.calls.append({
            "method": method, "url": url, "headers": dict(headers),
            "timeout": timeout, "max_bytes": max_bytes,
        })
        response = self.responses[url]
        if len(response.body) > max_bytes:
            raise ResponseTooLargeError("response exceeds byte limit")
        return response


class FlakyRoutingTransport(RoutingTransport):
    def __init__(
        self, responses: dict[str, HttpResponse], *, fail_once_url: str,
    ) -> None:
        super().__init__(responses)
        self.fail_once_url = fail_once_url
        self.failed_once = False

    def request(self, method, url, *, headers, timeout, max_bytes):
        if url == self.fail_once_url and not self.failed_once:
            self.failed_once = True
            self.calls.append({
                "method": method, "url": url, "headers": dict(headers),
                "timeout": timeout, "max_bytes": max_bytes,
            })
            return HttpResponse(500, {}, b"{}", url)
        return super().request(
            method, url, headers=headers, timeout=timeout, max_bytes=max_bytes,
        )


class GitHubRichAdapterTests(unittest.TestCase):
    def test_rich_evidence_cache_identity_is_subject_scoped_v10(self) -> None:
        self.assertEqual(
            GitHubAdapter.RICH_EVIDENCE_VERSION,
            "rich-project-evidence-v10",
        )

    def test_rich_collection_uses_only_the_current_subjects_derived_literals(self) -> None:
        profile_url = "https://api.github.com/users/fixture-builder"
        repositories_url = profile_url + "/repos?per_page=100&sort=updated&direction=desc"
        repository_url = "https://api.github.com/repos/fixture-builder/private-product-0"
        project = repository(0)
        project["description"] = (
            "built commonword tooling with ownmail and ownslug evidence"
        )
        responses = {
            profile_url: HttpResponse(200, {}, json.dumps({
                "created_at": "2020-01-01T00:00:00Z",
                "updated_at": "2026-07-01T00:00:00Z", "public_repos": 1,
            }).encode(), profile_url),
            repositories_url: HttpResponse(
                200, {}, json.dumps([project]).encode(), repositories_url,
            ),
            repository_url + "/readme": HttpResponse(
                200, {}, b"commonword delivery with ownmail and ownslug",
                repository_url + "/readme",
            ),
            repository_url + "/releases?per_page=1": HttpResponse(
                200, {}, b"[]", repository_url + "/releases?per_page=1",
            ),
            repository_url + "/deployments?per_page=1": HttpResponse(
                200, {}, b"[]", repository_url + "/deployments?per_page=1",
            ),
        }
        with tempfile.TemporaryDirectory() as directory:
            state = PipelineState.create(
                Path(directory) / "state.json", {"github": StageStatus.LOCKED},
            )
            authorization = gate()
            state.unlock("github", authorization, now=NOW)
            state.start("github")
            result = GitHubAdapter(
                transport=RoutingTransport(responses),
                cache=CanonicalJsonCache(
                    Path(directory) / "cache", clock=lambda: NOW,
                ),
                pseudonym_secret=b"secret", clock=lambda: NOW,
                sleeper=lambda _seconds: None, source_verifier=lambda _ref: True,
                collect_rich_evidence=True,
                identity_literals=("High Confidence Direct Identifier",),
                subject_identity_literals={
                    SUBJECT_REF: ("ownmail", "ownslug"),
                    OTHER_SUBJECT_REF: ("commonword",),
                },
            ).enrich(
                ApplicantSuppliedValue(
                    "fixture-builder", "source:application:001",
                ),
                state=state, authorization=authorization,
                subject_ref=SUBJECT_REF,
            )

        serialized = json.dumps(result["rich_project_evidence"]).casefold()
        self.assertIn("commonword", serialized)
        self.assertNotIn("ownmail", serialized)
        self.assertNotIn("ownslug", serialized)

    def test_rich_collection_rejects_malformed_or_unbound_subject_identity_maps(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            common = {
                "transport": RoutingTransport({}),
                "cache": CanonicalJsonCache(
                    Path(directory) / "cache", clock=lambda: NOW,
                ),
                "pseudonym_secret": b"secret",
                "clock": lambda: NOW,
                "sleeper": lambda _seconds: None,
                "source_verifier": lambda _ref: True,
                "collect_rich_evidence": True,
                "identity_literals": ("High Confidence Direct Identifier",),
            }
            with self.assertRaisesRegex(ValueError, "subject identity"):
                GitHubAdapter(
                    **common,
                    subject_identity_literals={"raw-applicant-id": ("ownmail",)},
                )
            with self.assertRaisesRegex(ValueError, "subject identity"):
                GitHubAdapter(
                    **common,
                    subject_identity_literals=[],  # type: ignore[arg-type]
                )

            state = PipelineState.create(
                Path(directory) / "state.json", {"github": StageStatus.LOCKED},
            )
            authorization = gate()
            state.unlock("github", authorization, now=NOW)
            state.start("github")
            adapter = GitHubAdapter(
                **common,
                subject_identity_literals={OTHER_SUBJECT_REF: ("othermail",)},
            )
            with self.assertRaisesRegex(PermissionError, "subject identity"):
                adapter.enrich(
                    ApplicantSuppliedValue(
                        "fixture-builder", "source:application:001",
                    ),
                    state=state, authorization=authorization,
                    subject_ref=SUBJECT_REF,
                )

    def test_rich_evidence_reference_changes_with_minimization_version(self) -> None:
        class NextRichVersion(GitHubAdapter):
            RICH_EVIDENCE_VERSION = "rich-project-evidence-v8-test"

        profile_url = "https://api.github.com/users/fixture-builder"
        repositories_url = profile_url + "/repos?per_page=100&sort=updated&direction=desc"
        repository_url = "https://api.github.com/repos/fixture-builder/private-product-0"
        responses = {
            profile_url: HttpResponse(200, {}, json.dumps({
                "created_at": "2020-01-01T00:00:00Z",
                "updated_at": "2026-07-01T00:00:00Z", "public_repos": 1,
            }).encode(), profile_url),
            repositories_url: HttpResponse(
                200, {}, json.dumps([repository(0)]).encode(), repositories_url,
            ),
            repository_url + "/readme": HttpResponse(
                200, {}, b"built a deployed workflow.", repository_url + "/readme",
            ),
            repository_url + "/releases?per_page=1": HttpResponse(
                200, {}, b"[]", repository_url + "/releases?per_page=1",
            ),
            repository_url + "/deployments?per_page=1": HttpResponse(
                200, {}, b"[]", repository_url + "/deployments?per_page=1",
            ),
        }
        with tempfile.TemporaryDirectory() as directory:
            state = PipelineState.create(
                Path(directory) / "state.json", {"github": StageStatus.LOCKED},
            )
            authorization = gate()
            state.unlock("github", authorization, now=NOW)
            state.start("github")
            results = []
            for index, adapter_class in enumerate((GitHubAdapter, NextRichVersion)):
                results.append(adapter_class(
                    transport=RoutingTransport(responses),
                    cache=CanonicalJsonCache(
                        Path(directory) / f"cache-{index}", clock=lambda: NOW,
                    ),
                    pseudonym_secret=b"secret", clock=lambda: NOW,
                    sleeper=lambda _seconds: None, source_verifier=lambda _ref: True,
                    collect_rich_evidence=True,
                    identity_literals=("Fixture Builder",),
                    subject_identity_literals={
                        SUBJECT_REF: ("fixture-builder",),
                    },
                ).enrich(
                    ApplicantSuppliedValue(
                        "fixture-builder", "source:application:001",
                    ),
                    state=state, authorization=authorization,
                    subject_ref="pid:v1:" + "a" * 64,
                ))

        self.assertNotEqual(results[0]["evidence_ref"], results[1]["evidence_ref"])

    def test_interruption_retry_uses_new_collection_generation_without_resurrecting_evidence(self) -> None:
        from community_os.enrichment.evidence_vault import ProtectedEvidenceVault

        profile_url = "https://api.github.com/users/fixture-builder"
        repositories_url = profile_url + "/repos?per_page=100&sort=updated&direction=desc"
        responses = {
            profile_url: HttpResponse(200, {}, json.dumps({
                "created_at": "2020-01-01T00:00:00Z",
                "updated_at": "2026-07-01T00:00:00Z", "public_repos": 0,
            }).encode(), profile_url),
            repositories_url: HttpResponse(200, {}, b"[]", repositories_url),
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = PipelineState.create(
                root / "state.json", {"github": StageStatus.LOCKED},
            )
            authorization = gate()
            state.unlock("github", authorization, now=NOW)
            state.start("github")
            cache = CanonicalJsonCache(root / "cache", clock=lambda: NOW)
            vault = ProtectedEvidenceVault(
                root / "protected" / "raw-evidence", clock=lambda: NOW,
            )
            results = []
            for generation in (1, 2):
                adapter = GitHubAdapter(
                    transport=RoutingTransport(responses), cache=cache,
                    pseudonym_secret=b"secret", clock=lambda: NOW,
                    sleeper=lambda _seconds: None, source_verifier=lambda _ref: True,
                    collect_rich_evidence=True, identity_literals=("Fixture Builder",),
                    subject_identity_literals={
                        SUBJECT_REF: ("fixture-builder",),
                    },
                    evidence_vault=vault,
                )
                results.append(adapter.enrich(
                    ApplicantSuppliedValue(
                        "fixture-builder", "source:application:001",
                    ),
                    state=state, authorization=authorization,
                    subject_ref="pid:v1:" + "a" * 64,
                    collection_generation=generation,
                ))
                if generation == 1:
                    vault.delete_all(reason="interruption_cleanup")
                    cache.delete_all()

            self.assertNotEqual(results[0]["evidence_ref"], results[1]["evidence_ref"])
            self.assertEqual(len(tuple(vault.receipts.glob("*.json"))), 1)
            self.assertEqual(len(tuple(vault.records.glob("*.json"))), 1)

    def test_rich_collection_requires_callers_to_supply_identity_literals(self) -> None:
        with tempfile.TemporaryDirectory() as directory, self.assertRaisesRegex(
            ValueError, "identity literals",
        ):
            GitHubAdapter(
                transport=RoutingTransport({}),
                cache=CanonicalJsonCache(Path(directory) / "cache", clock=lambda: NOW),
                pseudonym_secret=b"secret", clock=lambda: NOW,
                sleeper=lambda _seconds: None, source_verifier=lambda _ref: True,
                collect_rich_evidence=True,
            )

    def test_fetches_three_bounded_detail_sets_and_returns_only_sanitized_evidence(self) -> None:
        profile_url = "https://api.github.com/users/fixture-builder"
        repositories_url = profile_url + "/repos?per_page=100&sort=updated&direction=desc"
        repositories = [repository(index) for index in range(4)]
        responses = {
            profile_url: HttpResponse(200, {}, json.dumps({
                "created_at": "2020-01-01T00:00:00Z",
                "updated_at": "2026-07-01T00:00:00Z", "public_repos": 4,
            }).encode(), profile_url),
            repositories_url: HttpResponse(200, {}, json.dumps(repositories).encode(), repositories_url),
        }
        selected = select_rich_repository_indices(repositories, now=NOW)
        self.assertEqual(len(selected), 3)
        for index in selected:
            base = f"https://api.github.com/repos/fixture-builder/private-product-{index}"
            responses[base + "/readme"] = HttpResponse(
                200, {}, (
                    "# Private Product\nDeployed workflow with tests and authentication. "
                    "Contact jane@example.org or @janesmith."
                ).encode(), base + "/readme",
            )
            responses[base + "/releases?per_page=1"] = HttpResponse(
                200, {}, b'[{"id":1,"url":"https://github.com/private"}]',
                base + "/releases?per_page=1",
            )
            responses[base + "/deployments?per_page=1"] = HttpResponse(
                200, {}, b'[{"id":2,"environment":"private"}]',
                base + "/deployments?per_page=1",
            )
        transport = RoutingTransport(responses)
        with tempfile.TemporaryDirectory() as directory:
            state = PipelineState.create(Path(directory) / "state.json", {"github": StageStatus.LOCKED})
            authorization = gate()
            state.unlock("github", authorization, now=NOW)
            state.start("github")
            adapter = GitHubAdapter(
                transport=transport,
                cache=CanonicalJsonCache(Path(directory) / "cache", clock=lambda: NOW),
                pseudonym_secret=b"secret", clock=lambda: NOW,
                sleeper=lambda _seconds: None, source_verifier=lambda _ref: True,
                token="fixture-token", collect_rich_evidence=True,
                identity_literals=("Jane Smith", "janesmith", "Private Product"),
                subject_identity_literals={
                    SUBJECT_REF: ("fixture-builder", "janesmith"),
                },
            )
            result = adapter.enrich(
                ApplicantSuppliedValue("fixture-builder", "source:application:001"),
                state=state, authorization=authorization,
                subject_ref="pid:v1:" + "a" * 64,
            )

        self.assertEqual(len(transport.calls), 11)
        self.assertEqual(len(result["rich_project_evidence"]), 3)
        for project in result["rich_project_evidence"]:
            self.assertEqual(
                project["repository_relationship"], "profile_owned_nonfork",
            )
            self.assertIn(
                f'{project["project_code"]}:ownership', project["evidence_refs"],
            )
        serialized = json.dumps(result["rich_project_evidence"]).casefold()
        for forbidden in (
            "fixture-builder", "private-product", "private product", "jane smith",
            "jane@example.org", "janesmith", "github.com", "https://", "environment",
        ):
            self.assertNotIn(forbidden, serialized)

    def test_detail_404_becomes_unknown_and_never_aborts_profile(self) -> None:
        profile_url = "https://api.github.com/users/fixture-builder"
        repositories_url = profile_url + "/repos?per_page=100&sort=updated&direction=desc"
        repository_url = "https://api.github.com/repos/fixture-builder/private-product-0"
        responses = {
            profile_url: HttpResponse(200, {}, json.dumps({
                "created_at": "2020-01-01T00:00:00Z",
                "updated_at": "2026-07-01T00:00:00Z", "public_repos": 1,
            }).encode(), profile_url),
            repositories_url: HttpResponse(200, {}, json.dumps([repository(0)]).encode(), repositories_url),
            repository_url + "/readme": HttpResponse(404, {}, b"{}", repository_url + "/readme"),
            repository_url + "/releases?per_page=1": HttpResponse(404, {}, b"{}", repository_url + "/releases?per_page=1"),
            repository_url + "/deployments?per_page=1": HttpResponse(404, {}, b"{}", repository_url + "/deployments?per_page=1"),
        }
        with tempfile.TemporaryDirectory() as directory:
            state = PipelineState.create(Path(directory) / "state.json", {"github": StageStatus.LOCKED})
            authorization = gate()
            state.unlock("github", authorization, now=NOW)
            state.start("github")
            result = GitHubAdapter(
                transport=RoutingTransport(responses),
                cache=CanonicalJsonCache(Path(directory) / "cache", clock=lambda: NOW),
                pseudonym_secret=b"secret", clock=lambda: NOW,
                sleeper=lambda _seconds: None, source_verifier=lambda _ref: True,
                collect_rich_evidence=True, identity_literals=("Fixture Builder",),
                subject_identity_literals={
                    SUBJECT_REF: ("fixture-builder",),
                },
            ).enrich(
                ApplicantSuppliedValue("fixture-builder", "source:application:001"),
                state=state, authorization=authorization,
                subject_ref="pid:v1:" + "a" * 64,
            )

        evidence = result["rich_project_evidence"][0]
        self.assertEqual(evidence["readme_excerpt"], "")
        self.assertEqual(evidence["release_signal"], "unknown")
        self.assertEqual(evidence["deployment_signal"], "repository_homepage")

    def test_oversized_optional_readme_becomes_unknown_without_aborting_profile(self) -> None:
        profile_url = "https://api.github.com/users/fixture-builder"
        repositories_url = profile_url + "/repos?per_page=100&sort=updated&direction=desc"
        repository_url = "https://api.github.com/repos/fixture-builder/private-product-0"
        responses = {
            profile_url: HttpResponse(200, {}, json.dumps({
                "created_at": "2020-01-01T00:00:00Z",
                "updated_at": "2026-07-01T00:00:00Z", "public_repos": 1,
            }).encode(), profile_url),
            repositories_url: HttpResponse(200, {}, json.dumps([repository(0)]).encode(), repositories_url),
            repository_url + "/readme": HttpResponse(200, {}, b"x" * 65_537, repository_url + "/readme"),
            repository_url + "/releases?per_page=1": HttpResponse(200, {}, b"[]", repository_url + "/releases?per_page=1"),
            repository_url + "/deployments?per_page=1": HttpResponse(200, {}, b"[]", repository_url + "/deployments?per_page=1"),
        }
        with tempfile.TemporaryDirectory() as directory:
            state = PipelineState.create(Path(directory) / "state.json", {"github": StageStatus.LOCKED})
            authorization = gate()
            state.unlock("github", authorization, now=NOW)
            state.start("github")
            result = GitHubAdapter(
                transport=RoutingTransport(responses),
                cache=CanonicalJsonCache(Path(directory) / "cache", clock=lambda: NOW),
                pseudonym_secret=b"secret", clock=lambda: NOW,
                sleeper=lambda _seconds: None, source_verifier=lambda _ref: True,
                collect_rich_evidence=True, identity_literals=("Fixture Builder",),
                subject_identity_literals={
                    SUBJECT_REF: ("fixture-builder",),
                },
            ).enrich(
                ApplicantSuppliedValue("fixture-builder", "source:application:001"),
                state=state, authorization=authorization,
                subject_ref="pid:v1:" + "a" * 64,
            )

        self.assertEqual(result["state"], "observed")
        self.assertEqual(result["rich_project_evidence"][0]["readme_excerpt"], "")

    def test_retries_cannot_exceed_rich_profile_physical_request_budget(self) -> None:
        profile_url = "https://api.github.com/users/fixture-builder"
        repositories_url = profile_url + "/repos?per_page=100&sort=updated&direction=desc"
        repositories = [repository(index) for index in range(3)]
        responses = {
            profile_url: HttpResponse(200, {}, json.dumps({
                "created_at": "2020-01-01T00:00:00Z",
                "updated_at": "2026-07-01T00:00:00Z", "public_repos": 3,
            }).encode(), profile_url),
            repositories_url: HttpResponse(
                200, {}, json.dumps(repositories).encode(), repositories_url,
            ),
        }
        for index in select_rich_repository_indices(repositories, now=NOW):
            base = f"https://api.github.com/repos/fixture-builder/private-product-{index}"
            responses[base + "/readme"] = HttpResponse(
                200, {}, b"# Product\nDeployed with tests.", base + "/readme",
            )
            responses[base + "/releases?per_page=1"] = HttpResponse(
                200, {}, b"[]", base + "/releases?per_page=1",
            )
            responses[base + "/deployments?per_page=1"] = HttpResponse(
                200, {}, b"[]", base + "/deployments?per_page=1",
            )
        transport = FlakyRoutingTransport(responses, fail_once_url=profile_url)

        with tempfile.TemporaryDirectory() as directory:
            state = PipelineState.create(
                Path(directory) / "state.json", {"github": StageStatus.LOCKED},
            )
            authorization = gate()
            state.unlock("github", authorization, now=NOW)
            state.start("github")
            adapter = GitHubAdapter(
                transport=transport,
                cache=CanonicalJsonCache(Path(directory) / "cache", clock=lambda: NOW),
                pseudonym_secret=b"secret", clock=lambda: NOW,
                sleeper=lambda _seconds: None, source_verifier=lambda _ref: True,
                collect_rich_evidence=True, identity_literals=("Fixture Builder",),
                subject_identity_literals={
                    SUBJECT_REF: ("fixture-builder",),
                },
            )

            with self.assertRaisesRegex(
                RuntimeError, "GitHub physical request budget exceeded",
            ):
                adapter.enrich(
                    ApplicantSuppliedValue("fixture-builder", "source:application:001"),
                    state=state, authorization=authorization,
                    subject_ref="pid:v1:" + "a" * 64,
                )

        self.assertEqual(len(transport.calls), 11)


if __name__ == "__main__":
    unittest.main()
