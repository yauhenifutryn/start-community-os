from __future__ import annotations

from datetime import UTC, datetime
import unittest

from community_os.enrichment.github_content_evidence import (
    RICH_PROJECT_FIELDS,
    build_rich_project_packets,
    validate_rich_project_packets,
)
from community_os.enrichment.rich_semantic_assessment import validate_profile_evidence


NOW = datetime(2026, 7, 15, tzinfo=UTC)


def repository(index: int, *, stars: int = 0, pushed_at: str = "2026-07-01T00:00:00Z") -> dict[str, object]:
    return {
        "name": f"private-project-{index}",
        "description": (
            f"Built an AI scheduling product for schools. Demo https://example.org/{index} "
            "by Jane Smith at jane@example.org"
        ),
        "topics": ["artificial-intelligence", "education", f"private-project-{index}"],
        "homepage": f"https://product-{index}.example.org",
        "fork": False,
        "archived": False,
        "disabled": False,
        "is_template": False,
        "created_at": "2025-01-01T00:00:00Z",
        "pushed_at": pushed_at,
        "size": 5000,
        "stargazers_count": stars,
        "forks_count": 0,
        "open_issues_count": 1,
        "language": "Python",
        "has_pages": False,
        "has_issues": True,
        "license": {"key": "mit"},
    }


class GitHubContentEvidenceTests(unittest.TestCase):
    def test_builds_bounded_semantic_packets_for_at_most_three_projects(self) -> None:
        repositories = [repository(index, stars=20 - index) for index in range(6)]
        details = {
            index: {
                "readme": (
                    "# Private Project\nA deployed workflow for school operators with tests, "
                    "authentication, and audit history. Contact @janesmith."
                ),
                "releases": [{"id": index + 1}],
                "deployments": [{"id": index + 10}],
            }
            for index in range(6)
        }

        packets = build_rich_project_packets(
            repositories, details, now=NOW,
            identity_literals=("Jane Smith", "Private Project", "janesmith"),
        )

        self.assertEqual(len(packets), 3)
        self.assertEqual([item["project_code"] for item in packets], [
            "project_01", "project_02", "project_03",
        ])
        for packet in packets:
            self.assertEqual(set(packet), RICH_PROJECT_FIELDS)
            self.assertEqual(packet["repository_relationship"], "profile_owned_nonfork")
            self.assertIn(
                f'{packet["project_code"]}:ownership', packet["evidence_refs"],
            )
            self.assertIn("scheduling product for schools", packet["description_excerpt"])
            self.assertIn("deployed workflow for school operators", packet["readme_excerpt"])
            self.assertEqual(packet["topic_codes"], ["applied_ai", "education"])
            self.assertEqual(packet["release_signal"], "release_observed")
            self.assertEqual(packet["deployment_signal"], "deployment_observed")
            serialized = repr(packet).casefold()
            for forbidden in (
                "jane smith", "janesmith", "private-project", "private project",
                "example.org", "github.com", "@", "http", "jane@example.org",
            ):
                self.assertNotIn(forbidden, serialized)

    def test_readme_heading_cannot_preserve_a_searchable_product_slug(self) -> None:
        candidate = repository(0)
        candidate["name"] = "private-product-router"
        details = {
            0: {
                "readme": (
                    "# private-product-router\n"
                    "A local router forwards requests by category and preserves normal traffic."
                ),
                "releases": [],
                "deployments": [],
            }
        }

        packet = build_rich_project_packets([candidate], details, now=NOW)[0]

        self.assertNotIn("private-product-router", packet["readme_excerpt"])
        self.assertIn("local router forwards requests", packet["readme_excerpt"].casefold())

    def test_profile_boundary_removes_obfuscated_searchable_identifiers(self) -> None:
        candidate = repository(0)
        candidate["description"] = (
            "demo at privateproduct .info with a working deployment"
        )
        details = {
            0: {
                "readme": (
                    "contact otheruser at example dot com or @ otheruser while "
                    "shipping audit workflows"
                ),
                "releases": [],
                "deployments": [],
            }
        }

        packets = build_rich_project_packets([candidate], details, now=NOW)
        profile = validate_profile_evidence({
            "projects": packets,
            "application": [],
            "devpost": [],
            "career": [],
        })
        serialized = repr(profile).casefold()

        for forbidden in (
            "privateproduct", ".info", "otheruser", "example dot com",
        ):
            self.assertNotIn(forbidden, serialized)
        self.assertIn("working deployment", serialized)
        self.assertIn("shipping audit workflows", serialized)

    def test_repository_name_fragments_are_removed_without_erasing_generic_terms(self) -> None:
        candidate = repository(0)
        candidate["name"] = "medicare-platform"
        candidate["description"] = (
            "medicare is a platform for coordinating a clinical workflow"
        )
        details = {
            0: {
                "readme": "the medicare platform coordinates a clinical workflow",
                "releases": [],
                "deployments": [],
            }
        }

        packet = build_rich_project_packets([candidate], details, now=NOW)[0]

        combined = (
            packet["description_excerpt"] + " " + packet["readme_excerpt"]
        ).casefold()
        self.assertNotIn("medicare", combined)
        self.assertIn("platform", combined)
        self.assertIn("clinical workflow", combined)

    def test_repository_name_preserves_generic_domain_terms(self) -> None:
        candidate = repository(0)
        candidate["name"] = "healthcare-agent"
        candidate["description"] = "healthcare workflow for hospital operations"

        packet = build_rich_project_packets(
            [candidate],
            {0: {"readme": "healthcare workflow", "releases": [], "deployments": []}},
            now=NOW,
        )[0]

        combined = (
            packet["description_excerpt"] + " " + packet["readme_excerpt"]
        ).casefold()
        self.assertIn("healthcare workflow", combined)

    def test_relationship_is_bounded_and_cannot_be_recast_as_a_personal_identifier(self) -> None:
        packet = build_rich_project_packets(
            [repository(0)],
            {0: {"readme": "Working product", "releases": [], "deployments": []}},
            now=NOW,
        )[0]

        for relationship in ("owner:janesmith", "contributor", "profile_owned_fork"):
            invalid = {**packet, "repository_relationship": relationship}
            with self.subTest(relationship=relationship), self.assertRaises(ValueError):
                validate_rich_project_packets([invalid])

    def test_fork_cannot_create_profile_owned_nonfork_evidence(self) -> None:
        fork = repository(0)
        fork["fork"] = True

        self.assertEqual(
            build_rich_project_packets(
                [fork],
                {0: {"readme": "Working product", "releases": [], "deployments": []}},
                now=NOW,
            ),
            [],
        )

    def test_recent_zero_star_project_can_enter_bounded_selection(self) -> None:
        repositories = [
            repository(0, stars=100, pushed_at="2024-01-01T00:00:00Z"),
            repository(1, stars=50, pushed_at="2024-01-01T00:00:00Z"),
            repository(2, stars=25, pushed_at="2024-01-01T00:00:00Z"),
            repository(3, stars=0, pushed_at="2026-07-14T00:00:00Z"),
        ]

        packets = build_rich_project_packets(
            repositories, {index: {"readme": "Working product", "releases": [], "deployments": []} for index in range(4)},
            now=NOW,
        )

        selected_descriptions = [item["description_excerpt"] for item in packets]
        self.assertTrue(any("scheduling product" in item for item in selected_descriptions))
        self.assertIn("none", {item["stars_band"] for item in packets})

    def test_missing_detail_evidence_is_unknown_without_profile_failure(self) -> None:
        packet = build_rich_project_packets(
            [repository(0)], {}, now=NOW,
        )[0]

        self.assertEqual(packet["readme_excerpt"], "")
        self.assertEqual(packet["release_signal"], "unknown")
        self.assertEqual(packet["deployment_signal"], "repository_homepage")
        self.assertEqual(packet["evidence_refs"], [
            "project_01:ownership", "project_01:description",
        ])

    def test_short_identity_literal_uses_token_boundaries_without_erasing_words(self) -> None:
        candidate = repository(0)
        candidate["description"] = "data platform built by a with audit trails"

        packet = build_rich_project_packets(
            [candidate],
            {0: {
                "readme": "data architecture and a deployed workflow",
                "releases": [], "deployments": [],
            }},
            now=NOW, identity_literals=("a",),
        )[0]

        self.assertIn("data platform", packet["description_excerpt"])
        self.assertIn("data architecture", packet["readme_excerpt"])
        self.assertNotIn(" by a ", f' {packet["description_excerpt"]} ')
        self.assertNotIn(" and a ", f' {packet["readme_excerpt"]} ')

    def test_subject_initial_literal_is_contextual_and_preserves_ordinary_prose(self) -> None:
        candidate = repository(0)
        candidate["description"] = "I built x ray tooling. Built by X."

        packet = build_rich_project_packets(
            [candidate],
            {0: {
                "readme": "I built x ray architecture",
                "releases": [], "deployments": [],
            }},
            now=NOW, identity_literals=("subject-initial:X",),
        )[0]

        self.assertIn("I built x ray tooling", packet["description_excerpt"])
        self.assertNotRegex(
            packet["description_excerpt"], r"(?i)\bby\s+x\b",
        )
        self.assertIn("I built x ray architecture", packet["readme_excerpt"])

    def test_validation_rejects_extra_fields_and_invented_references(self) -> None:
        packet = build_rich_project_packets(
            [repository(0)],
            {0: {"readme": "Working product", "releases": [], "deployments": []}},
            now=NOW,
        )[0]
        invalid = dict(packet)
        invalid["repository_name"] = "secret"
        with self.assertRaises(ValueError):
            validate_rich_project_packets([invalid])

        invalid = dict(packet)
        invalid["evidence_refs"] = ["project_01:invented"]
        with self.assertRaises(ValueError):
            validate_rich_project_packets([invalid])


if __name__ == "__main__":
    unittest.main()
