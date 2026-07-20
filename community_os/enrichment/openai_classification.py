"""Privacy-minimized OpenAI Responses transport for semantic classification."""

from __future__ import annotations

import http.client
import json
import re
import ssl
from typing import Callable, Mapping, Protocol

from community_os.enrichment.classification import DIMENSION_LABELS
from community_os.enrichment.transport import (
    HttpResponse, RateLimitError, RetryPolicy, RetryableTransportError,
    call_with_retry,
)


_ROUTES = {
    "eu": ("eu.api.openai.com", "https://eu.api.openai.com/v1/responses"),
    "global": ("api.openai.com", "https://api.openai.com/v1/responses"),
}
_MODEL = re.compile(r"^gpt-[a-z0-9][a-z0-9.-]{1,80}$")


class ResponsesTransport(Protocol):
    def request(
        self, *, headers: dict[str, str], body: bytes, timeout: float, max_bytes: int,
    ) -> HttpResponse: ...


class OpenAIHTTPSResponsesTransport:
    """Allowlisted HTTPS POST transport with no redirects and a bounded response."""

    def __init__(self, *, region: str = "eu") -> None:
        try:
            self.host, self.endpoint = _ROUTES[region]
        except KeyError as error:
            raise ValueError("OpenAI route is not allowlisted") from error

    def request(
        self, *, headers: dict[str, str], body: bytes, timeout: float, max_bytes: int,
    ) -> HttpResponse:
        if timeout <= 0 or max_bytes < 1 or len(body) > 262144:
            raise ValueError("OpenAI request bounds are invalid")
        connection = http.client.HTTPSConnection(
            self.host, 443, timeout=timeout, context=ssl.create_default_context(),
        )
        try:
            connection.request("POST", "/v1/responses", body=body, headers=headers)
            response = connection.getresponse()
            payload = response.read(max_bytes + 1)
            if len(payload) > max_bytes:
                raise ValueError("OpenAI response exceeds byte limit")
            return HttpResponse(
                status=response.status,
                headers={str(key): str(value) for key, value in response.getheaders()},
                body=payload,
                url=self.endpoint,
            )
        except (OSError, http.client.HTTPException) as error:
            raise RetryableTransportError("OpenAI Responses request failed") from error
        finally:
            connection.close()


def _dimension_schema(
    dimension: str, evidence_refs: tuple[str, ...],
) -> dict[str, object]:
    evidence_schema: dict[str, object] = {
        "type": "array",
        "items": (
            {"type": "string", "enum": list(evidence_refs)}
            if evidence_refs else {"type": "string"}
        ),
    }
    if not evidence_refs:
        evidence_schema["maxItems"] = 0
    return {
        "type": "object",
        "properties": {
            "labels": {
                "type": "array", "minItems": 1,
                "items": {"type": "string", "enum": sorted(DIMENSION_LABELS[dimension])},
            },
            "confidence": {"type": "number", "minimum": 0, "maximum": 1},
            "evidence_refs": evidence_schema,
        },
        "required": ["labels", "confidence", "evidence_refs"],
        "additionalProperties": False,
    }


def classification_output_schema(evidence_refs: tuple[str, ...]) -> dict[str, object]:
    dimensions = {
        dimension: _dimension_schema(dimension, evidence_refs)
        for dimension in sorted(DIMENSION_LABELS)
    }
    return {
        "type": "object",
        "properties": {
            "dimensions": {
                "type": "object", "properties": dimensions,
                "required": sorted(dimensions), "additionalProperties": False,
            },
        },
        "required": ["dimensions"],
        "additionalProperties": False,
    }


_SYSTEM_PROMPT = """Classify a pseudonymous talent evidence vector into the supplied taxonomy.
Use only the structured machine-readable signal codes and opaque evidence references supplied.
Do not infer identity, protected characteristics, or facts absent from those signals.
Return unknown or insufficient_evidence when support is weak. Confidence is evidential confidence,
not a score of the person. Cite only evidence references present in the input."""


class OpenAIResponsesProvider:
    """Callable provider for SemanticClassifier. It never logs request or response bodies."""

    def __init__(
        self, *, api_key: str, model: str,
        transport: ResponsesTransport | None = None,
        sleeper: Callable[[float], None],
    ) -> None:
        if not isinstance(api_key, str) or not api_key.strip():
            raise PermissionError("OpenAI API key is missing from the managed runtime secret")
        if not isinstance(model, str) or not _MODEL.fullmatch(model):
            raise ValueError("OpenAI model identifier is invalid")
        if model.endswith("-latest"):
            raise ValueError("OpenAI model must not use a moving latest alias")
        self._api_key = api_key
        self.model = model
        self.transport = transport or OpenAIHTTPSResponsesTransport()
        self.sleeper = sleeper

    def __call__(self, payload: dict[str, object]) -> dict[str, object]:
        if set(payload) != {"subject_ref", "signals", "evidence_refs"}:
            raise ValueError("OpenAI classification payload exceeds the field allowlist")
        from community_os.enrichment.classification import ClassificationInput

        payload = ClassificationInput(
            subject_ref=payload["subject_ref"],
            signals=payload["signals"],
            evidence_refs=tuple(payload["evidence_refs"]),
        ).provider_payload()
        encoded_payload = json.dumps(
            payload, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False,
        )
        request_body = json.dumps({
            "model": self.model,
            "input": [
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user", "content": encoded_payload},
            ],
            "max_output_tokens": 2500,
            "store": False,
            "text": {
                "format": {
                    "type": "json_schema", "name": "talent_classification",
                    "strict": True,
                    "schema": classification_output_schema(tuple(payload["evidence_refs"])),
                },
            },
        }, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")

        def request() -> HttpResponse:
            response = self.transport.request(
                headers={
                    "Authorization": "Bearer " + self._api_key,
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    "User-Agent": "START-Community-OS/1",
                },
                body=request_body, timeout=30.0, max_bytes=524288,
            )
            if response.status == 429:
                raw = response.headers.get("Retry-After", "1")
                try:
                    delay = float(raw)
                except (TypeError, ValueError):
                    delay = 1.0
                raise RateLimitError("OpenAI Responses rate limit", retry_after=max(1.0, delay))
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
            raise RuntimeError("OpenAI semantic classification did not complete")
        output = envelope.get("output")
        if not isinstance(output, list):
            raise RuntimeError("OpenAI semantic classification output is missing")
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
                    raise RuntimeError("OpenAI semantic classification was refused")
                if part.get("type") == "output_text" and isinstance(part.get("text"), str):
                    texts.append(str(part["text"]))
        if len(texts) != 1:
            raise RuntimeError("OpenAI semantic classification output is missing")
        try:
            parsed = json.loads(texts[0])
        except json.JSONDecodeError as error:
            raise RuntimeError("OpenAI semantic classification output is invalid") from error
        if not isinstance(parsed, dict):
            raise RuntimeError("OpenAI semantic classification output is invalid")
        return parsed
