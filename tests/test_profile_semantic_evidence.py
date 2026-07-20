from __future__ import annotations

import json
import unittest

from community_os.enrichment.profile_semantic_evidence import (
    build_application_evidence,
    build_devpost_evidence,
)
from community_os.enrichment.rich_semantic_assessment import validate_profile_evidence


class ProfileSemanticEvidenceTests(unittest.TestCase):
    def test_application_keeps_product_substance_and_removes_identity(self) -> None:
        evidence = build_application_evidence(
            experience=(
                "Jane Smith built an event operations product with authentication, "
                "billing, monitoring, and 40 active organizers. github.com/janesmith/product"
            ),
            achievement="Shipped Secret Product to 20 schools. Contact jane@example.org.",
            identity_literals=("Jane Smith", "janesmith", "Secret Product"),
        )

        self.assertEqual(len(evidence), 1)
        self.assertIn("authentication", evidence[0]["experience_excerpt"])
        self.assertIn("20 schools", evidence[0]["achievement_excerpt"])
        self.assertEqual(
            evidence[0]["evidence_refs"],
            ["application_01:achievement", "application_01:experience"],
        )
        serialized = json.dumps(evidence).casefold()
        for forbidden in (
            "jane smith", "janesmith", "secret product", "jane@example.org",
            "github.com", "http", "source:application", "pid:v1",
        ):
            self.assertNotIn(forbidden, serialized)

    def test_application_requires_identity_literals_before_semantic_text(self) -> None:
        with self.assertRaisesRegex(ValueError, "identity literals"):
            build_application_evidence(
                experience="Built a production product.", achievement="Shipped it.",
                identity_literals=(),
            )

    def test_application_redacts_unlisted_name_and_uncommon_bare_domain(self) -> None:
        evidence = build_application_evidence(
            experience=(
                "Alex built a production scheduling product documented at participant.work. "
                "It includes billing, monitoring, and deployment automation."
            ),
            achievement="Led end-to-end delivery for 20 organizations.",
            identity_literals=("known@example.org",),
        )

        serialized = json.dumps(evidence).casefold()
        self.assertNotIn("alex", serialized)
        self.assertNotIn("participant.work", serialized)
        self.assertIn("billing", serialized)
        self.assertIn("deployment automation", serialized)

    def test_devpost_keeps_project_semantics_without_project_identity(self) -> None:
        evidence = build_devpost_evidence(
            projects=[{
                "project_text": (
                    "Secret Demo is a working supply-chain planner with a live API and dashboard."
                ),
                "technology_codes": ["python", "web_frontend"],
                "submission_state": "submitted",
                "demo_state": "observed",
            }],
            identity_literals=("Secret Demo", "Jane Smith"),
        )

        self.assertEqual(evidence[0]["evidence_code"], "devpost_01")
        self.assertEqual(
            evidence[0]["evidence_refs"],
            ["devpost_01:demo", "devpost_01:project"],
        )
        self.assertNotIn("secret demo", json.dumps(evidence).casefold())
        validated = validate_profile_evidence({
            "projects": [], "application": [], "devpost": evidence, "career": [],
        })
        self.assertEqual(validated["devpost"], evidence)

    def test_devpost_is_bounded_and_rejects_unknown_states(self) -> None:
        projects = [{
            "project_text": f"Working project {index}",
            "technology_codes": [], "submission_state": "submitted",
            "demo_state": "observed",
        } for index in range(4)]
        with self.assertRaisesRegex(ValueError, "three"):
            build_devpost_evidence(projects=projects, identity_literals=("Person",))
        projects[0]["submission_state"] = "winner"
        with self.assertRaisesRegex(ValueError, "state"):
            build_devpost_evidence(projects=projects[:1], identity_literals=("Person",))

    def test_devpost_rejects_identity_disguised_as_technology_code(self) -> None:
        with self.assertRaisesRegex(ValueError, "state or fields"):
            build_devpost_evidence(
                projects=[{
                    "project_text": "Built a working product.",
                    "technology_codes": ["jane_smith"],
                    "submission_state": "submitted",
                    "demo_state": "observed",
                }],
                identity_literals=("Jane Smith",),
            )


if __name__ == "__main__":
    unittest.main()
