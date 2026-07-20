from __future__ import annotations

import json
import unittest

from community_os.enrichment.transport import HttpResponse
from community_os.enrichment.openai_classification import OpenAIResponsesProvider


def semantic_output() -> dict[str, object]:
    return {"dimensions": {
        "professional_identity": {"labels": ["startup_operator"], "confidence": 0.86, "evidence_refs": ["evidence:application:" + "a" * 64]},
        "seniority": {"labels": ["senior"], "confidence": 0.91, "evidence_refs": ["evidence:application:" + "a" * 64]},
        "functional_role": {"labels": ["engineering"], "confidence": 0.88, "evidence_refs": ["evidence:application:" + "a" * 64]},
        "employer_pedigree": {"labels": ["unknown"], "confidence": 0.0, "evidence_refs": []},
        "builder_evidence": {"labels": ["shipped_product"], "confidence": 0.89, "evidence_refs": ["evidence:application:" + "a" * 64]},
        "capabilities": {"labels": ["backend"], "confidence": 0.87, "evidence_refs": ["evidence:application:" + "a" * 64]},
        "domains": {"labels": ["applied_ai"], "confidence": 0.82, "evidence_refs": ["evidence:application:" + "a" * 64]},
    }}


class FakeResponsesTransport:
    def __init__(self, responses: list[HttpResponse]) -> None:
        self.responses = list(responses)
        self.requests: list[dict[str, object]] = []

    def request(
        self, *, headers: dict[str, str], body: bytes, timeout: float, max_bytes: int,
    ) -> HttpResponse:
        self.requests.append({
            "headers": dict(headers), "body": body, "timeout": timeout,
            "max_bytes": max_bytes,
        })
        return self.responses.pop(0)


def response(payload: dict[str, object], *, status: int = 200) -> HttpResponse:
    body = json.dumps({
        "status": "completed",
        "output": [{
            "type": "message",
            "content": [{"type": "output_text", "text": json.dumps(payload)}],
        }],
    }).encode("utf-8")
    return HttpResponse(status=status, headers={}, body=body, url="https://api.openai.com/v1/responses")


class OpenAIResponsesProviderTests(unittest.TestCase):
    def test_empty_evidence_allowlist_forces_empty_dimension_references(self) -> None:
        from community_os.enrichment.openai_classification import (
            classification_output_schema,
        )

        schema = classification_output_schema(())
        dimensions = schema["properties"]["dimensions"]["properties"]

        for dimension in dimensions.values():
            evidence = dimension["properties"]["evidence_refs"]
            self.assertEqual(evidence["maxItems"], 0)
            self.assertEqual(evidence["items"], {"type": "string"})

    def test_transport_is_pinned_to_an_explicit_approved_route(self) -> None:
        from community_os.enrichment.openai_classification import (
            OpenAIHTTPSResponsesTransport,
        )

        eu = OpenAIHTTPSResponsesTransport(region="eu")
        global_route = OpenAIHTTPSResponsesTransport(region="global")

        self.assertEqual(eu.host, "eu.api.openai.com")
        self.assertEqual(eu.endpoint, "https://eu.api.openai.com/v1/responses")
        self.assertEqual(global_route.host, "api.openai.com")
        self.assertEqual(global_route.endpoint, "https://api.openai.com/v1/responses")
        with self.assertRaises(ValueError):
            OpenAIHTTPSResponsesTransport(region="arbitrary")

    def test_request_is_structured_store_false_and_contains_no_direct_identifiers_or_raw_text(self) -> None:
        transport = FakeResponsesTransport([response(semantic_output())])
        provider = OpenAIResponsesProvider(
            api_key="fixture-key-not-secret", model="gpt-5.6-terra",
            transport=transport, sleeper=lambda _seconds: None,
        )
        payload = {
            "subject_ref": "pid:v1:" + "b" * 64,
            "signals": {
                "occupation_codes": ["role_engineering", "domain_applied_ai"],
                "experience_band": "senior",
                "builder_codes": ["builder_shipped_product", "github_repos_many"],
            },
            "evidence_refs": ["evidence:application:" + "a" * 64],
        }

        result = provider(payload)

        self.assertEqual(result, semantic_output())
        self.assertEqual(len(transport.requests), 1)
        request = transport.requests[0]
        body = json.loads(request["body"])
        self.assertEqual(body["model"], "gpt-5.6-terra")
        self.assertIs(body["store"], False)
        self.assertNotIn("tools", body)
        self.assertEqual(body["text"]["format"]["type"], "json_schema")
        self.assertIs(body["text"]["format"]["strict"], True)
        dimension_schemas = body["text"]["format"]["schema"]["properties"]["dimensions"]["properties"]
        for dimension in dimension_schemas.values():
            self.assertEqual(
                dimension["properties"]["evidence_refs"]["items"],
                {
                    "type": "string",
                    "enum": ["evidence:application:" + "a" * 64],
                },
            )
        serialized = json.dumps(body, sort_keys=True).casefold()
        for forbidden in (
            "person@example.org", "jane smith", "github.com/", "linkedin.com/",
            "portfolio.example", "raw public page", "fixture-key-not-secret",
        ):
            self.assertNotIn(forbidden, serialized)
        self.assertEqual(
            request["headers"]["Authorization"], "Bearer fixture-key-not-secret",
        )

    def test_direct_provider_call_revalidates_minimized_classification_input_before_transport(self) -> None:
        transport = FakeResponsesTransport([response(semantic_output())])
        provider = OpenAIResponsesProvider(
            api_key="fixture-key-not-secret", model="gpt-5.6-terra",
            transport=transport, sleeper=lambda _seconds: None,
        )

        with self.assertRaises(ValueError):
            provider({
                "subject_ref": "pid:v1:" + "b" * 64,
                "signals": {
                    "occupation_codes": ["https://github.com/private-profile"],
                    "experience_band": "senior", "builder_codes": [],
                },
                "evidence_refs": ["evidence:application:" + "a" * 64],
            })

        self.assertEqual(transport.requests, [])

    def test_rate_limit_and_server_errors_retry_without_leaking_response_or_token(self) -> None:
        sleeps: list[float] = []
        transport = FakeResponsesTransport([
            HttpResponse(429, {"Retry-After": "2"}, b"secret upstream body", "https://api.openai.com/v1/responses"),
            HttpResponse(503, {}, b"another private body", "https://api.openai.com/v1/responses"),
            response(semantic_output()),
        ])
        provider = OpenAIResponsesProvider(
            api_key="fixture-key-not-secret", model="gpt-5.6-terra",
            transport=transport, sleeper=sleeps.append,
        )

        result = provider({
            "subject_ref": "pid:v1:" + "b" * 64,
            "signals": {"occupation_codes": ["unknown"], "experience_band": "unknown", "builder_codes": []},
            "evidence_refs": ["evidence:application:" + "a" * 64],
        })

        self.assertEqual(result, semantic_output())
        self.assertEqual(len(transport.requests), 3)
        self.assertEqual(sleeps, [2.0, 2.0])

    def test_refusal_and_malformed_responses_fail_closed_with_incident_safe_errors(self) -> None:
        unsafe = HttpResponse(200, {}, json.dumps({
            "status": "completed",
            "output": [{"type": "message", "content": [{
                "type": "refusal", "refusal": "private refusal detail",
            }]}],
        }).encode("utf-8"), "https://api.openai.com/v1/responses")
        provider = OpenAIResponsesProvider(
            api_key="fixture-key-not-secret", model="gpt-5.6-terra",
            transport=FakeResponsesTransport([unsafe]), sleeper=lambda _seconds: None,
        )

        with self.assertRaises(RuntimeError) as caught:
            provider({
                "subject_ref": "pid:v1:" + "b" * 64,
                "signals": {"occupation_codes": ["unknown"], "experience_band": "unknown", "builder_codes": []},
                "evidence_refs": ["evidence:application:" + "a" * 64],
            })

        message = str(caught.exception).casefold()
        self.assertNotIn("private refusal detail", message)
        self.assertNotIn("fixture-key-not-secret", message)
        self.assertIn("refused", message)


if __name__ == "__main__":
    unittest.main()
