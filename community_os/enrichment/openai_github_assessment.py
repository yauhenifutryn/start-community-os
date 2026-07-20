"""Pinned OpenAI Responses provider for structural GitHub project assessment."""

from __future__ import annotations

import json
from typing import Callable, Mapping

from community_os.enrichment.github_assessment import (
    ASSESSMENT_CATEGORIES, MODEL, PROMPT_VERSION,
    ASSESSMENT_ENUMS,
    ASSESSMENT_REASON_CODES,
    validate_project_vectors,
)
from community_os.enrichment.openai_classification import (
    OpenAIHTTPSResponsesTransport,
    ResponsesTransport,
)
from community_os.enrichment.transport import (
    HttpResponse, RateLimitError, RetryPolicy, RetryableTransportError,
    call_with_retry,
)


def github_assessment_output_schema() -> dict[str, object]:
    properties: dict[str, object] = {
        key: {"type": "string", "enum": sorted(allowed)}
        for key, allowed in ASSESSMENT_ENUMS.items()
    }
    properties.update({
        "categories": {
            "type": "array", "minItems": 1,
            "items": {"type": "string", "enum": sorted(ASSESSMENT_CATEGORIES)},
        },
        "reason_codes": {
            "type": "array", "minItems": 1,
            "items": {"type": "string", "enum": sorted(ASSESSMENT_REASON_CODES)},
        },
    })
    return {
        "type": "object", "properties": properties,
        "required": sorted(properties), "additionalProperties": False,
    }


_SYSTEM_PROMPT = """Assess only the supplied anonymous structural public-project vectors.
Return enum values from the schema. Evidence strength describes observable public structure,
not the person. Never infer identity, intent, novelty, real users, code quality, authorship,
commercial success, or what a project does. Weak, conflicting, or absent signals require low
confidence and human review. Use insufficient when structural evidence is too sparse."""


class OpenAIGitHubAssessmentProvider:
    """Minimum-field Responses call pinned to Luna with reasoning disabled."""

    def __init__(
        self, *, api_key: str, transport: ResponsesTransport | None = None,
        sleeper: Callable[[float], None], region: str = "global",
    ) -> None:
        if not isinstance(api_key, str) or not api_key.strip():
            raise PermissionError("OpenAI API key is missing from the managed runtime secret")
        self._api_key = api_key
        self.transport = transport or OpenAIHTTPSResponsesTransport(region=region)
        self.sleeper = sleeper

    def __call__(self, payload: dict[str, object]) -> dict[str, object]:
        if not isinstance(payload, dict) or set(payload) != {"projects"}:
            raise ValueError("GitHub assessment payload exceeds the field allowlist")
        projects = validate_project_vectors(payload["projects"])
        safe_payload = {"projects": projects}
        user_content = json.dumps(
            safe_payload, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
            allow_nan=False,
        )
        body = json.dumps({
            "model": MODEL,
            "input": [
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user", "content": user_content},
            ],
            "max_output_tokens": 800,
            "reasoning": {"effort": "none"},
            "store": False,
            "text": {"format": {
                "type": "json_schema", "name": "github_structural_assessment",
                "strict": True, "schema": github_assessment_output_schema(),
            }},
        }, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")

        def request() -> HttpResponse:
            response = self.transport.request(
                headers={
                    "Authorization": "Bearer " + self._api_key,
                    "Content-Type": "application/json", "Accept": "application/json",
                    "User-Agent": "START-Community-OS/1",
                },
                body=body, timeout=30.0, max_bytes=131072,
            )
            if response.status == 429:
                try:
                    delay = float(response.headers.get("Retry-After", "1"))
                except (TypeError, ValueError):
                    delay = 1.0
                raise RateLimitError(
                    "OpenAI Responses rate limit", retry_after=max(1.0, delay),
                )
            if response.status >= 500:
                raise RetryableTransportError("OpenAI Responses service unavailable")
            if response.status != 200:
                raise RuntimeError("OpenAI Responses request was not successful")
            return response

        response = call_with_retry(request, RetryPolicy(), self.sleeper)
        try:
            envelope = json.loads(response.body)
        except (TypeError, json.JSONDecodeError) as error:
            raise RuntimeError("OpenAI Responses returned invalid JSON") from error
        if not isinstance(envelope, Mapping) or envelope.get("status") != "completed":
            raise RuntimeError("OpenAI GitHub assessment did not complete")
        output = envelope.get("output")
        if not isinstance(output, list):
            raise RuntimeError("OpenAI GitHub assessment output is missing")
        texts: list[str] = []
        for item in output:
            if not isinstance(item, Mapping) or item.get("type") != "message":
                continue
            content = item.get("content")
            if not isinstance(content, list):
                continue
            for part in content:
                if not isinstance(part, Mapping):
                    continue
                if part.get("type") == "refusal":
                    raise RuntimeError("OpenAI GitHub assessment was refused")
                if part.get("type") == "output_text" and isinstance(part.get("text"), str):
                    texts.append(str(part["text"]))
        if len(texts) != 1:
            raise RuntimeError("OpenAI GitHub assessment output is missing")
        try:
            parsed = json.loads(texts[0])
        except json.JSONDecodeError as error:
            raise RuntimeError("OpenAI GitHub assessment output is invalid") from error
        if not isinstance(parsed, dict):
            raise RuntimeError("OpenAI GitHub assessment output is invalid")
        return parsed
