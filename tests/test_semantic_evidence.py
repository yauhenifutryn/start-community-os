from __future__ import annotations

import unittest

from community_os.enrichment.semantic_evidence import (
    assert_no_known_identity_literals,
    assert_safe_semantic_payload,
    sanitize_professional_text,
)


class SemanticEvidenceTests(unittest.TestCase):
    def test_global_identity_corpus_blocks_normalized_variants_without_echoing_value(self) -> None:
        packet = {"professional_excerpt": "built alongside yauheni-futryn."}

        with self.assertRaisesRegex(
            ValueError, r"known identity literal$",
        ) as raised:
            assert_no_known_identity_literals(
                packet,
                ("Yauheni Futryn", "https://github.com/example-person"),
            )

        self.assertNotIn("yauheni", str(raised.exception).casefold())

    def test_global_identity_corpus_returns_a_stable_hash_for_safe_payload(self) -> None:
        corpus = ("Jane Smith", "example-person", "Northwind Labs")
        packet = {"professional_excerpt": "built a working scheduling product."}

        first = assert_no_known_identity_literals(packet, corpus)
        second = assert_no_known_identity_literals(packet, reversed(corpus))

        self.assertRegex(first, r"^[0-9a-f]{64}$")
        self.assertEqual(first, second)

    def test_forbidden_identity_literals_remove_punctuation_variants(self) -> None:
        result = sanitize_professional_text(
            "delivery credit: yauheni-futryn; production workflow.",
            forbidden_literals=("Yauheni Futryn",),
        )

        self.assertNotIn("yauheni", result.casefold())
        self.assertNotIn("futryn", result.casefold())
        self.assertIsNone(assert_safe_semantic_payload({"excerpt": result}))

    def test_direct_identifier_error_reports_only_the_structural_path(self) -> None:
        packet = {
            "projects": [{"readme_excerpt": "contact test@example.com"}],
        }

        with self.assertRaisesRegex(
            ValueError,
            r"direct identifier \(email\) at "
            r"root\.projects\[0\]\.readme_excerpt$",
        ):
            assert_safe_semantic_payload(packet)

    def test_sanitizer_preserves_professional_substance_and_removes_identifiers(self) -> None:
        value = (
            "Built a production planning system used by 20 schools. "
            "Contact Jane Smith at jane@example.org or +48 600 700 800. "
            "Demo: https://example.org/private-product and @janesmith. "
            "[Architecture notes](https://github.com/jane/private-product)."
        )

        result = sanitize_professional_text(
            value, forbidden_literals=("Jane Smith", "private-product"),
        )

        self.assertIn("production planning system used by 20 schools", result)
        for forbidden in (
            "Jane Smith", "jane@example.org", "+48 600 700 800",
            "https://", "@janesmith", "private-product", "github.com",
        ):
            self.assertNotIn(forbidden, result)
        self.assertIn("Architecture notes", result)

    def test_sanitizer_normalizes_controls_and_truncates_deterministically(self) -> None:
        value = "Shipped\x00 a\nworking\tproduct " + ("x" * 3000)

        first = sanitize_professional_text(value, max_chars=120)
        second = sanitize_professional_text(value, max_chars=120)

        self.assertEqual(first, second)
        self.assertEqual(len(first), 120)
        self.assertNotRegex(first, r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
        self.assertTrue(first.startswith("Shipped a working product"))

    def test_sanitizer_removes_secret_like_material(self) -> None:
        fake_github_token = "ghp_" + "abcdefghijklmnopqrstuvwxyz123456"
        result = sanitize_professional_text(
            f"Implemented OAuth. token={fake_github_token} and kept shipping."
        )

        self.assertIn("Implemented OAuth", result)
        self.assertIn("kept shipping", result)
        self.assertNotIn("ghp_", result)

    def test_sanitizer_removes_every_stray_at_marker(self) -> None:
        for value in ("Contact user@ for access.", "Owner @. shipped it."):
            with self.subTest(value=value):
                self.assertNotIn("@", sanitize_professional_text(value))
                with self.assertRaises(ValueError):
                    assert_safe_semantic_payload({"professional_excerpt": value})

    def test_sanitizer_rechecks_identifiers_created_by_name_redaction(self) -> None:
        result = sanitize_professional_text(
            "Built 2020 Acme 12345678 system and shipped it.",
        )

        self.assertNotIn("12345678", result)
        self.assertIsNone(assert_safe_semantic_payload({"professional_excerpt": result}))

    def test_sanitizer_does_not_truncate_into_a_new_identifier(self) -> None:
        result = sanitize_professional_text(
            "built shipping. Product delivery.", max_chars=20,
        )

        self.assertLessEqual(len(result), 20)
        self.assertNotIn("Prod", result)
        self.assertIsNone(assert_safe_semantic_payload({"professional_excerpt": result}))

    def test_sanitizer_does_not_truncate_to_a_dangling_location_cue(self) -> None:
        value = "built a working product at scale and shipped it."
        max_chars = value.index(" scale")

        result = sanitize_professional_text(value, max_chars=max_chars)

        self.assertLessEqual(len(result), max_chars)
        self.assertFalse(result.endswith((" at", " in")))
        self.assertIsNone(assert_safe_semantic_payload({"professional_excerpt": result}))

    def test_sanitizer_redacts_unicode_title_cased_names_and_places(self) -> None:
        result = sanitize_professional_text(
            "Built the system with Łukasz in Łódź and Żaneta in München.",
        )

        self.assertIn("Built the system", result)
        for forbidden in ("Łukasz", "Łódź", "Żaneta", "München"):
            self.assertNotIn(forbidden, result)
        self.assertIsNone(assert_safe_semantic_payload({"professional_excerpt": result}))

    def test_sanitizer_removes_lowercase_street_and_location_evidence(self) -> None:
        value = "lives at 12 main street, warsaw and built a production workflow."

        result = sanitize_professional_text(value)

        for forbidden in ("12 main street", "warsaw", "lives at"):
            self.assertNotIn(forbidden, result)
        self.assertIn("built a production workflow", result)
        self.assertIsNone(assert_safe_semantic_payload({"professional_excerpt": result}))
        with self.assertRaisesRegex(ValueError, "location_or_address"):
            assert_safe_semantic_payload({"professional_excerpt": value})

    def test_lowercase_people_organizations_and_places_fail_closed(self) -> None:
        unsafe_values = (
            ("worked with john smith on delivery.", ("john", "smith")),
            ("jane doe", ("jane", "doe")),
            ("built systems for acme corporation.", ("acme", "corporation")),
            ("deployed the product in warsaw.", ("warsaw",)),
        )

        for value, forbidden_tokens in unsafe_values:
            with self.subTest(value=value):
                result = sanitize_professional_text(value)
                for token in forbidden_tokens:
                    self.assertNotIn(token, result.casefold())
                self.assertIsNone(
                    assert_safe_semantic_payload({"professional_excerpt": result}),
                )
                with self.assertRaisesRegex(
                    ValueError,
                    "possible_person|organization|location_or_address",
                ):
                    assert_safe_semantic_payload({"professional_excerpt": value})

    def test_arbitrary_lowercase_entity_phrases_are_removed(self) -> None:
        unsafe_values = (
            (
                "built by yauheni futryn for openai in gdansk.",
                ("yauheni", "futryn", "openai", "gdansk"),
            ),
            (
                "worked with xavier dupont at northwind labs.",
                ("xavier", "dupont", "northwind", "labs"),
            ),
            (
                "evidence is limited but built with sofia kovacs.",
                ("sofia", "kovacs"),
            ),
        )

        for value, forbidden_tokens in unsafe_values:
            with self.subTest(value=value):
                result = sanitize_professional_text(value).casefold()
                for token in forbidden_tokens:
                    self.assertNotIn(token, result)
                self.assertIsNone(
                    assert_safe_semantic_payload({"professional_excerpt": result}),
                )

    def test_generic_limited_language_is_not_an_organization_identifier(self) -> None:
        for value in (
            "evidence is limited.",
            "support is limited but the workflow is working.",
            "scope is limited to a prototype.",
        ):
            with self.subTest(value=value):
                self.assertEqual(sanitize_professional_text(value), value)
                self.assertIsNone(
                    assert_safe_semantic_payload({"professional_excerpt": value}),
                )

    def test_payload_rejects_residual_unicode_title_cased_identifiers(self) -> None:
        for value in (
            "Łukasz built a working product.",
            "Deployed for München operators.",
            "Worked with Żaneta on delivery.",
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                assert_safe_semantic_payload({"professional_excerpt": value})

    def test_sanitizer_removes_bare_domains_and_labeled_or_stable_identifiers(self) -> None:
        result = sanitize_professional_text(
            "Documentation: product.example.org/docs. "
            "GitHub: octocat; source_ref=cs_123456789; "
            "subject pid:v1:0123456789abcdef0123456789abcdef."
        )

        self.assertIn("Documentation", result)
        for forbidden in (
            "product.example.org", "octocat", "source_ref", "cs_123456789",
            "pid:v1:", "0123456789abcdef",
        ):
            self.assertNotIn(forbidden, result)

    def test_sanitizer_removes_repository_shorthand_and_payload_rejects_it(self) -> None:
        value = (
            "repo: /sample-owner/sample-project and built a working product."
        )

        result = sanitize_professional_text(value)

        self.assertNotIn("sample-owner", result)
        self.assertNotIn("sample-project", result)
        self.assertIn("built a working product", result)
        with self.assertRaisesRegex(ValueError, "repository_path"):
            assert_safe_semantic_payload({"professional_excerpt": value})

    def test_sanitizer_removes_orphan_repository_slug_after_owner_redaction(self) -> None:
        value = "Built a public repo this week: / /linear-mcp-lean"

        result = sanitize_professional_text(value)

        self.assertNotIn("linear-mcp-lean", result.casefold())
        self.assertNotIn("/", result)

    def test_sanitizer_removes_unlabeled_and_short_repository_paths(self) -> None:
        for value in (
            "Reviewed owner/repository before release",
            "Reviewed /a/b before release",
        ):
            with self.subTest(value=value):
                result = sanitize_professional_text(value)
                self.assertNotIn("/", result)
                with self.assertRaisesRegex(ValueError, "repository_path"):
                    assert_safe_semantic_payload({"professional_excerpt": value})

    def test_sanitizer_removes_lower_camel_case_product_identifiers(self) -> None:
        value = "Used xStocks and yFinance in the workflow"

        result = sanitize_professional_text(value)

        self.assertNotIn("xstocks", result.casefold())
        self.assertNotIn("yfinance", result.casefold())

    def test_sanitizer_removes_spaced_or_partial_hostname_fragments(self) -> None:
        value = "Demo: private-product .verc .app and a working deployment"

        result = sanitize_professional_text(value)

        self.assertNotIn(".app", result.casefold())
        self.assertNotIn(".verc", result.casefold())
        self.assertIn("working deployment", result.casefold())

    def test_sanitizer_removes_single_spaced_hostname(self) -> None:
        value = "Demo: example .com and a working deployment"

        result = sanitize_professional_text(value)

        self.assertNotIn("example", result.casefold())
        self.assertNotIn(".com", result.casefold())
        with self.assertRaisesRegex(ValueError, "bare_domain"):
            assert_safe_semantic_payload({"professional_excerpt": value})

    def test_sanitizer_removes_obfuscated_email_without_erasing_technical_context(self) -> None:
        value = (
            "contact otheruser at example dot com for audit workflows and "
            "technical documentation"
        )

        result = sanitize_professional_text(value)

        self.assertNotIn("otheruser", result.casefold())
        self.assertNotIn("example dot com", result.casefold())
        self.assertIn("audit workflows", result.casefold())
        self.assertIn("technical documentation", result.casefold())
        with self.assertRaises(ValueError):
            assert_safe_semantic_payload({"professional_excerpt": value})

    def test_sanitizer_removes_compact_bracketed_and_parenthesized_email(self) -> None:
        unsafe_values = (
            "contact john[at]example[dot]com for technical documentation",
            "contact john(at)example(dot)com for technical documentation",
        )

        for value in unsafe_values:
            with self.subTest(value=value):
                result = sanitize_professional_text(value)
                self.assertNotIn("john", result.casefold())
                self.assertNotIn("example", result.casefold())
                self.assertIn("technical documentation", result.casefold())
                with self.assertRaisesRegex(ValueError, "email"):
                    assert_safe_semantic_payload({"professional_excerpt": value})

    def test_sanitizer_removes_dot_word_and_uncommon_spaced_tld_domains(self) -> None:
        unsafe_values = (
            "demo privateproduct dot info with a working deployment",
            "demo privateproduct .us with a working deployment",
        )

        for value in unsafe_values:
            with self.subTest(value=value):
                result = sanitize_professional_text(value)
                self.assertNotIn("privateproduct", result.casefold())
                self.assertIn("working deployment", result.casefold())
                with self.assertRaisesRegex(ValueError, "bare_domain"):
                    assert_safe_semantic_payload({"professional_excerpt": value})

    def test_sanitizer_removes_arbitrary_spaced_hostname_without_erasing_domain_context(self) -> None:
        value = (
            "demo at privateproduct .info with a working deployment and "
            "information systems"
        )

        result = sanitize_professional_text(value)

        self.assertNotIn("privateproduct", result.casefold())
        self.assertNotIn(".info", result.casefold())
        self.assertIn("working deployment", result.casefold())
        self.assertIn("information systems", result.casefold())
        with self.assertRaisesRegex(ValueError, "bare_domain"):
            assert_safe_semantic_payload({"professional_excerpt": value})

    def test_sanitizer_removes_spaced_handle_without_erasing_shipping_context(self) -> None:
        value = "source by @ otheruser and shipping workflows with audit trails"

        result = sanitize_professional_text(value)

        self.assertNotIn("otheruser", result.casefold())
        self.assertNotIn("@", result)
        self.assertIn("shipping workflows", result.casefold())
        self.assertIn("audit trails", result.casefold())
        with self.assertRaisesRegex(ValueError, "handle"):
            assert_safe_semantic_payload({"professional_excerpt": value})

    def test_legacy_resanitization_rechecks_marker_created_by_gap_cleanup(self) -> None:
        from community_os.enrichment.semantic_evidence import (
            redact_legacy_searchable_markers,
        )

        result = redact_legacy_searchable_markers("// . comment")

        self.assertNotIn("/", result)
        self.assertIsNone(assert_safe_semantic_payload({"excerpt": result}))

    def test_sanitizer_preserves_allowlisted_lower_camel_technology_terms(self) -> None:
        value = "Uses iOS, eBPF, mTLS, useState, and gRPC in production"

        result = sanitize_professional_text(value)

        for term in ("iOS", "eBPF", "mTLS", "useState", "gRPC"):
            self.assertIn(term, result)

    def test_sanitizer_removes_candidate_associated_channel_titles(self) -> None:
        value = "creating AI software for This is IT YT and shipping workflows"

        result = sanitize_professional_text(value)

        self.assertNotIn("This is IT YT", result)
        self.assertIn("creating AI software", result)
        self.assertIn("shipping workflows", result)
        with self.assertRaisesRegex(ValueError, "channel_identifier"):
            assert_safe_semantic_payload({"professional_excerpt": value})

    def test_sanitizer_removes_url_marker_even_when_embedded_in_text(self) -> None:
        for value in (
            "Configured image_srchttps://example.org/private and continued delivery.",
            "Configured app:*** https:// .app/private and continued delivery.",
        ):
            with self.subTest(value=value):
                result = sanitize_professional_text(value)
                self.assertNotIn("https://", result)
                self.assertNotIn("example.org", result)
                with self.assertRaises(ValueError):
                    assert_safe_semantic_payload({"professional_excerpt": value})

    def test_sanitizer_preserves_professional_terms_that_resemble_identifiers(self) -> None:
        result = sanitize_professional_text(
            "Built source_control tooling and person_centered workflows."
        )

        self.assertEqual(
            result, "Built source_control tooling and person_centered workflows.",
        )

    def test_payload_rejects_excluded_fields_at_any_depth(self) -> None:
        for key in (
            "name", "email", "phone", "profile_url", "linkedin_posts",
            "activity", "recommendations", "contact_details", "owner_login",
            "source_ref", "stable_identifier",
        ):
            with self.subTest(key=key), self.assertRaises(ValueError):
                assert_safe_semantic_payload({"project": {key: "forbidden"}})

    def test_payload_rejects_residual_direct_identifiers(self) -> None:
        for value in (
            "person@example.org", "https://github.com/person/project",
            "Reach me at @person", "+1 (415) 555-0123",
            "api_key=fixture-secret-abcdefghijklmnopqrstuvwxyz",
            "product.example.org/docs", "username=octocat",
            "source_ref=cs_123456789",
            "pid:v1:0123456789abcdef0123456789abcdef",
            "person_001", "source_1234",
            "Alex built a production workflow.",
            "Documentation lives at participant.work.",
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                assert_safe_semantic_payload({"professional_excerpt": value})

    def test_payload_accepts_bounded_professional_content(self) -> None:
        packet = {
            "projects": [{
                "project_code": "project_01",
                "description_excerpt": "Built a working scheduling product for schools.",
                "readme_excerpt": "Includes deployment, tests, and an operator workflow.",
                "topic_codes": ["education", "developer_tools"],
            }],
            "career": [{
                "role_code": "role_01",
                "role_excerpt": "Led delivery of production data systems.",
            }],
        }

        self.assertIsNone(assert_safe_semantic_payload(packet))

    def test_payload_rejects_more_than_total_character_ceiling(self) -> None:
        with self.assertRaises(ValueError):
            assert_safe_semantic_payload(
                {"professional_excerpt": "x" * 12001}, max_total_chars=12000,
            )


if __name__ == "__main__":
    unittest.main()
