from __future__ import annotations

from datetime import UTC, datetime
import json
from pathlib import Path
import tempfile
import unittest

from community_os.enrichment.cache import CanonicalJsonCache
from community_os.enrichment.coresignal import CoresignalAdapter
from community_os.enrichment.evidence_vault import ProtectedEvidenceVault
from community_os.enrichment.gates import CoresignalGate
from community_os.enrichment.state import PipelineState, StageStatus
from community_os.enrichment.transport import ApplicantSuppliedValue, HttpResponse


FIXTURE = Path(__file__).parent / "fixtures" / "enrichment" / "coresignal_profile.json"


def gate() -> CoresignalGate:
    return CoresignalGate(
        notice_version="coresignal_transparency_v1", notice_sent_at="2026-07-13T09:00:00Z",
        notice_scope="linkedin_coresignal_enrichment",
        notice_content_sha256="d" * 64,
        objections_reconciled=True, exclusions_reconciled=True,
        suppressions_reconciled=True, deletions_reconciled=True,
        access_verified=True, provider_terms_version="terms-v1",
        source_scope="applicant_supplied_linkedin", retention_days=30,
        approval_id="approval-1", approved_at="2026-07-13T10:00:00Z",
    )


class Transport:
    def __init__(self):
        self.calls = 0
        self.last = None

    def request(self, method, url, *, headers, timeout, max_bytes):
        self.calls += 1
        self.last = (method, url, headers, timeout, max_bytes)
        return HttpResponse(200, {"Content-Type": "application/json"}, FIXTURE.read_bytes(), url)


class CoresignalAdapterTests(unittest.TestCase):
    def test_linkedin_profile_accepts_unicode_vanity_slug_but_rejects_other_paths(self) -> None:
        from community_os.enrichment.coresignal import _profile_url

        self.assertEqual(
            _profile_url("https://www.linkedin.com/in/zażółć-gęślą"),
            "https://www.linkedin.com/in/zażółć-gęślą",
        )
        for value in (
            "https://www.linkedin.com/company/start",
            "https://www.linkedin.com/in/bad slug",
            "https://www.linkedin.com/in/profile?tracking=1",
            "https://www.linkedin.com/in/profile#contact",
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                _profile_url(value)

    def test_provider_fields_must_match_allowlisted_types_before_normalization(self) -> None:
        now = datetime(2026, 7, 13, 10, tzinfo=UTC)
        malformed_payloads = (
            {
                "active_experience_title": ["Engineer"],
                "active_experience_management_level": "Senior",
                "experience": [],
            },
            {
                "active_experience_title": "Engineer",
                "active_experience_management_level": "Senior",
                "experience": [{"position_title": ["Founder"]}],
            },
            ["not", "an", "object"],
        )

        for payload in malformed_payloads:
            class MalformedTransport:
                def request(self, method, url, *, headers, timeout, max_bytes):
                    return HttpResponse(
                        200, {"Content-Type": "application/json"},
                        json.dumps(payload).encode(), url,
                    )

            with self.subTest(payload=payload), tempfile.TemporaryDirectory() as directory:
                state = PipelineState.create(
                    Path(directory) / "state.json", {"coresignal": StageStatus.LOCKED},
                )
                state.unlock("coresignal", gate(), now=now)
                state.start("coresignal")
                adapter = CoresignalAdapter(
                    transport=MalformedTransport(),
                    cache=CanonicalJsonCache(Path(directory) / "cache", clock=lambda: now),
                    pseudonym_secret=b"secret", clock=lambda: now,
                    api_token="fixture-token", source_verifier=lambda _ref: True,
                )

                with self.assertRaisesRegex(ValueError, "allowlisted schema"):
                    adapter.enrich(
                        ApplicantSuppliedValue(
                            "https://linkedin.com/in/fixture-builder",
                            "source:application:001",
                        ),
                        state=state, authorization=gate(),
                    )

    def test_provider_text_is_mapped_to_allowlisted_categories_not_copied(self) -> None:
        now = datetime(2026, 7, 13, 10, tzinfo=UTC)

        class UnexpectedCategoryTransport:
            def request(self, method, url, *, headers, timeout, max_bytes):
                body = json.dumps({
                    "active_experience_title": "Jane Smith",
                    "active_experience_management_level": "Individual Contributor",
                    "company_type": "Jane Smith Holdings",
                    "company_size_range": "11-50 employees",
                    "company_industry": "Software Development",
                    "experience": [],
                }).encode()
                return HttpResponse(200, {"Content-Type": "application/json"}, body, url)

        with tempfile.TemporaryDirectory() as directory:
            state = PipelineState.create(
                Path(directory) / "state.json", {"coresignal": StageStatus.LOCKED},
            )
            state.unlock("coresignal", gate(), now=now)
            state.start("coresignal")
            adapter = CoresignalAdapter(
                transport=UnexpectedCategoryTransport(),
                cache=CanonicalJsonCache(Path(directory) / "cache", clock=lambda: now),
                pseudonym_secret=b"secret", clock=lambda: now, api_token="fixture-token",
                source_verifier=lambda _ref: True,
            )
            result = adapter.enrich(
                ApplicantSuppliedValue(
                    "https://linkedin.com/in/fixture-builder", "source:application:001",
                ),
                state=state, authorization=gate(),
            )
        self.assertEqual(result["company_category"], "unknown")
        self.assertEqual(result["seniority"], "unknown")
        self.assertEqual(result["title_category"], "unknown")
        self.assertNotIn("Jane", json.dumps(result))

    def test_endpoint_is_exactly_allowlisted_before_an_api_key_can_exist(self) -> None:
        now = datetime(2026, 7, 13, 10, tzinfo=UTC)
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "endpoint"):
                CoresignalAdapter(
                    transport=Transport(),
                    cache=CanonicalJsonCache(Path(directory) / "cache", clock=lambda: now),
                    pseudonym_secret=b"secret", clock=lambda: now, api_token="TOPSECRET",
                    source_verifier=lambda _ref: True,
                    endpoint="https://attacker.example/collect",
                )

    def test_transport_is_impossible_until_bound_gate_and_running_stage(self) -> None:
        now = datetime(2026, 7, 13, 10, tzinfo=UTC)
        transport = Transport()
        with tempfile.TemporaryDirectory() as directory:
            state = PipelineState.create(Path(directory) / "state.json", {"coresignal": StageStatus.LOCKED})
            adapter = CoresignalAdapter(
                transport=transport, cache=CanonicalJsonCache(Path(directory) / "cache", clock=lambda: now),
                pseudonym_secret=b"secret", clock=lambda: now, api_token="fixture-token",
                source_verifier=lambda ref: ref.source_record_ref == "source:application:001",
            )
            reference = ApplicantSuppliedValue("https://linkedin.com/in/fixture-builder", "source:application:001")
            with self.assertRaises(PermissionError):
                adapter.enrich(reference, state=state, authorization=gate())
            self.assertEqual(transport.calls, 0)
            state.unlock("coresignal", gate(), now=now)
            state.start("coresignal")
            result = adapter.enrich(reference, state=state, authorization=gate())
        self.assertEqual(transport.calls, 1)
        method, url, headers, timeout, max_bytes = transport.last
        self.assertEqual(method, "GET")
        self.assertTrue(url.startswith(
            "https://api.coresignal.com/cdapi/v2/employee_multi_source/collect/"
        ))
        self.assertIn("/collect/fixture-builder?", url)
        self.assertNotIn("linkedin.com", url)
        self.assertNotIn("%", url)
        self.assertIn("fields=active_experience_title", url)
        self.assertIn("fields=experience", url)
        self.assertNotIn("fields=company_type", url)
        self.assertNotIn("fields=company_size_range", url)
        self.assertNotIn("fields=company_industry", url)
        self.assertEqual(headers["apikey"], "fixture-token")
        self.assertNotIn("Authorization", headers)
        self.assertEqual(timeout, 10.0)
        self.assertEqual(max_bytes, 262144)
        self.assertEqual(set(result), {"company_category", "evidence_ref", "founder_history", "seniority", "state", "title_category"})
        self.assertTrue(result["founder_history"])
        self.assertEqual(result["seniority"], "senior")
        self.assertEqual(result["title_category"], "software_engineering")
        self.assertNotIn("fixture-builder", json.dumps(result))
        self.assertNotIn("person_name", json.dumps(result))

    def test_active_company_category_is_derived_from_nested_experience_only(self) -> None:
        from community_os.enrichment.coresignal import normalize_coresignal_payload

        result = normalize_coresignal_payload({
            "active_experience_title": "Senior Engineer",
            "active_experience_management_level": "Senior",
            "experience": [{
                "position_title": "Senior Engineer", "management_level": "Senior",
                "active_experience": 1, "company_type": "Startup",
                "company_size_range": "11-50 employees",
                "company_industry": "Software Development",
            }],
        }, evidence_ref="evidence:coresignal:" + "a" * 64)

        self.assertEqual(result["company_category"], "startup")

    def test_linkedin_scope_and_gate_hash_must_match_exactly(self) -> None:
        now = datetime(2026, 7, 13, 10, tzinfo=UTC)
        transport = Transport()
        with tempfile.TemporaryDirectory() as directory:
            state = PipelineState.create(Path(directory) / "state.json", {"coresignal": StageStatus.LOCKED})
            state.unlock("coresignal", gate(), now=now)
            state.start("coresignal")
            adapter = CoresignalAdapter(
                transport=transport, cache=CanonicalJsonCache(Path(directory) / "cache", clock=lambda: now),
                pseudonym_secret=b"secret", clock=lambda: now, api_token="fixture-token",
                source_verifier=lambda ref: ref.source_record_ref == "source:application:001",
            )
            with self.assertRaises(ValueError):
                adapter.enrich(ApplicantSuppliedValue("https://evil.example/x", "source:application:001"), state=state, authorization=gate())
            changed = CoresignalGate(**{**gate().to_record(), "approval_id": "approval-2"})
            with self.assertRaises(PermissionError):
                adapter.enrich(ApplicantSuppliedValue("https://linkedin.com/in/a", "source:application:001"), state=state, authorization=changed)
        self.assertEqual(transport.calls, 0)

    def test_rate_limits_are_retried_with_bounded_retry_after(self) -> None:
        now = datetime(2026, 7, 13, 10, tzinfo=UTC)
        sleeps = []

        class RateLimitedTransport:
            def __init__(self):
                self.calls = 0

            def request(self, method, url, *, headers, timeout, max_bytes):
                self.calls += 1
                if self.calls == 1:
                    return HttpResponse(429, {"Retry-After": "2"}, b"", url)
                return HttpResponse(
                    200, {"Content-Type": "application/json"}, FIXTURE.read_bytes(), url,
                )

        transport = RateLimitedTransport()
        with tempfile.TemporaryDirectory() as directory:
            state = PipelineState.create(
                Path(directory) / "state.json", {"coresignal": StageStatus.LOCKED},
            )
            state.unlock("coresignal", gate(), now=now)
            state.start("coresignal")
            adapter = CoresignalAdapter(
                transport=transport,
                cache=CanonicalJsonCache(Path(directory) / "cache", clock=lambda: now),
                pseudonym_secret=b"secret", clock=lambda: now,
                api_token="fixture-token", source_verifier=lambda _ref: True,
                sleeper=sleeps.append,
            )

            result = adapter.enrich(
                ApplicantSuppliedValue(
                    "https://linkedin.com/in/fixture-builder", "source:application:001",
                ),
                state=state, authorization=gate(),
            )

        self.assertEqual(result["state"], "observed")
        self.assertEqual(transport.calls, 2)
        self.assertEqual(sleeps, [2.0])

    def test_retry_uses_new_evidence_reference_after_failed_attempt_cleanup(self) -> None:
        now = datetime(2026, 7, 13, 10, tzinfo=UTC)
        with tempfile.TemporaryDirectory() as directory:
            state = PipelineState.create(
                Path(directory) / "state.json", {"coresignal": StageStatus.LOCKED},
            )
            state.unlock("coresignal", gate(), now=now)
            state.start("coresignal")
            vault = ProtectedEvidenceVault(
                Path(directory) / "protected" / "raw-evidence", clock=lambda: now,
            )
            adapter = CoresignalAdapter(
                transport=Transport(),
                cache=CanonicalJsonCache(Path(directory) / "cache", clock=lambda: now),
                pseudonym_secret=b"secret", clock=lambda: now,
                api_token="fixture-token", source_verifier=lambda _ref: True,
                evidence_vault=vault,
            )
            reference = ApplicantSuppliedValue(
                "https://linkedin.com/in/fixture-builder", "source:application:001",
            )
            first = adapter.enrich(
                reference, state=state, authorization=gate(),
                subject_ref="pid:v1:" + "a" * 64,
            )
            adapter.discard_transient()
            state.fail("coresignal", "fixture_failure")
            state.resume("coresignal")
            second = adapter.enrich(
                reference, state=state, authorization=gate(),
                subject_ref="pid:v1:" + "a" * 64,
            )

        self.assertNotEqual(first["evidence_ref"], second["evidence_ref"])

    def test_duplicate_profile_is_bound_to_each_pseudonymous_subject(self) -> None:
        now = datetime(2026, 7, 13, 10, tzinfo=UTC)
        with tempfile.TemporaryDirectory() as directory:
            state = PipelineState.create(
                Path(directory) / "state.json", {"coresignal": StageStatus.LOCKED},
            )
            state.unlock("coresignal", gate(), now=now)
            state.start("coresignal")
            vault = ProtectedEvidenceVault(
                Path(directory) / "protected" / "raw-evidence", clock=lambda: now,
            )
            adapter = CoresignalAdapter(
                transport=Transport(),
                cache=CanonicalJsonCache(Path(directory) / "cache", clock=lambda: now),
                pseudonym_secret=b"secret", clock=lambda: now,
                api_token="fixture-token", source_verifier=lambda _ref: True,
                evidence_vault=vault,
            )
            first = adapter.enrich(
                ApplicantSuppliedValue(
                    "https://linkedin.com/in/fixture-builder", "source:application:001",
                ),
                state=state, authorization=gate(),
                subject_ref="pid:v1:" + "a" * 64,
            )
            second = adapter.enrich(
                ApplicantSuppliedValue(
                    "https://linkedin.com/in/fixture-builder", "source:application:002",
                ),
                state=state, authorization=gate(),
                subject_ref="pid:v1:" + "b" * 64,
            )

        self.assertNotEqual(first["evidence_ref"], second["evidence_ref"])


if __name__ == "__main__":
    unittest.main()
