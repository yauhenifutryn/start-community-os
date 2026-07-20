from __future__ import annotations

import json
import unittest

from community_os.enrichment.coresignal_career_evidence import build_career_evidence
from community_os.enrichment.rich_semantic_assessment import validate_profile_evidence


class CoresignalCareerEvidenceTests(unittest.TestCase):
    def test_projects_current_and_historic_roles_without_posts_or_identifiers(self) -> None:
        payload = {
            "full_name": "Jane Smith",
            "email": "jane@example.org",
            "profile_url": "https://linkedin.com/in/jane-smith",
            "activity": [{"title": "A personal post"}],
            "posts": [{"article_body": "Do not process this"}],
            "recommendations": [{"recommendation": "Do not process this"}],
            "experience": [
                {
                    "position_title": "Founder at Secret Company",
                    "description": (
                        "Built and operated a production analytics product used by factories. "
                        "Contact jane@example.org"
                    ),
                    "management_level": "Founder",
                    "active_experience": True,
                    "date_from_year": 2024,
                    "date_from_month": 2,
                    "date_to_year": None,
                    "date_to_month": None,
                    "duration_months": 29,
                    "company_name": "Secret Company",
                    "company_url": "https://secret.example.org",
                    "company_industry": "Software Development",
                    "company_size_range": "11-50 employees",
                },
                {
                    "position_title": "Senior Software Engineer",
                    "description": "Led delivery of distributed data services.",
                    "management_level": "Senior",
                    "active_experience": False,
                    "date_from_year": 2020,
                    "date_from_month": 1,
                    "date_to_year": 2023,
                    "date_to_month": 12,
                    "duration_months": 48,
                    "company_name": "Previous Employer",
                    "company_industry": "Financial Services",
                    "company_size_range": "1001-5000 employees",
                },
            ],
        }

        roles = build_career_evidence(
            payload, identity_literals=("Jane Smith", "Secret Company", "Previous Employer"),
        )

        self.assertEqual(len(roles), 2)
        self.assertEqual(roles[0]["role_code"], "role_01")
        self.assertEqual(roles[0]["active_state"], "current")
        self.assertEqual(roles[0]["duration_band"], "one_to_three_years")
        self.assertEqual(roles[0]["seniority_context"], "founder_executive")
        self.assertEqual(roles[0]["industry_code"], "software")
        self.assertEqual(roles[0]["organization_size_band"], "small")
        self.assertEqual(roles[1]["active_state"], "historic")
        self.assertEqual(roles[1]["duration_band"], "over_three_years")
        serialized = json.dumps(roles).casefold()
        for forbidden in (
            "jane smith", "jane@example.org", "linkedin", "secret company",
            "previous employer", "http", "personal post", "do not process this",
            "recommendation", "2024", "2020", "2023",
        ):
            self.assertNotIn(forbidden, serialized)

    def test_caps_roles_at_six_and_prioritizes_current_then_recent(self) -> None:
        payload = {"experience": [
            {
                "position_title": f"Engineer {index}",
                "description": f"Built system {index}",
                "management_level": "Senior",
                "active_experience": index == 7,
                "date_from_year": 2010 + index,
                "duration_months": 12,
                "company_industry": "Software",
                "company_size_range": "1-10 employees",
            }
            for index in range(8)
        ]}

        roles = build_career_evidence(payload, identity_literals=("Fixture Person",))

        self.assertEqual(len(roles), 6)
        self.assertEqual(roles[0]["active_state"], "current")
        self.assertIn("Engineer 7", roles[0]["title_excerpt"])
        self.assertNotIn("Engineer 0", json.dumps(roles))

    def test_missing_or_ambiguous_dates_remain_unknown(self) -> None:
        roles = build_career_evidence({"experience": [{
            "position_title": "Product Engineer",
            "description": "Built internal products.",
            "management_level": "",
            "active_experience": None,
        }]}, identity_literals=("Fixture Person",))

        self.assertEqual(roles[0]["active_state"], "unknown")
        self.assertEqual(roles[0]["duration_band"], "unknown")
        self.assertEqual(roles[0]["organization_size_band"], "unknown")

    def test_nonnumeric_organization_size_remains_unknown(self) -> None:
        for organization_size in ("unknown", "confidential"):
            with self.subTest(organization_size=organization_size):
                roles = build_career_evidence({"experience": [{
                    "position_title": "Product Engineer",
                    "active_experience": True,
                    "company_size_range": organization_size,
                }]}, identity_literals=("Fixture Person",))

                self.assertEqual(roles[0]["organization_size_band"], "unknown")

    def test_output_is_accepted_by_unified_profile_contract(self) -> None:
        career = build_career_evidence({"experience": [{
            "position_title": "Lead Engineer",
            "description": "Owned end-to-end product delivery.",
            "management_level": "Lead",
            "active_experience": True,
            "duration_months": 18,
            "company_industry": "Software",
            "company_size_range": "51-200 employees",
        }]}, identity_literals=("Fixture Person",))

        result = validate_profile_evidence({
            "projects": [], "application": [], "devpost": [], "career": career,
        })

        self.assertEqual(result["career"], career)

    def test_projection_requires_participant_identity_literals(self) -> None:
        with self.assertRaisesRegex(ValueError, "identity literals"):
            build_career_evidence({"experience": [{
                "position_title": "Product Engineer",
                "description": "Built a production product.",
                "active_experience": True,
            }]})


if __name__ == "__main__":
    unittest.main()
