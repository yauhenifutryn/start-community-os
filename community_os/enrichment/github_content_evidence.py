"""Bounded rich project evidence for applicant-supplied public GitHub profiles."""

from __future__ import annotations

from datetime import datetime
import re
from collections.abc import Iterable, Mapping, Sequence

from community_os.enrichment.github_assessment import (
    PROJECT_FIELDS,
    _project_vector,
    validate_project_vectors,
)
from community_os.enrichment.semantic_evidence import (
    assert_no_known_identity_literals,
    assert_safe_semantic_payload,
    redact_legacy_searchable_markers,
    sanitize_professional_text,
)


RICH_PROJECT_FIELDS = PROJECT_FIELDS.union({
    "deployment_signal", "description_excerpt", "evidence_refs",
    "readme_excerpt", "release_signal", "repository_relationship", "topic_codes",
})
_DETAIL_KEYS = frozenset({"deployments", "readme", "releases"})
_RELEASE_SIGNALS = frozenset({"unknown", "none_observed", "release_observed"})
_DEPLOYMENT_SIGNALS = frozenset({
    "unknown", "none_observed", "repository_homepage", "deployment_observed",
})
_EVIDENCE_REF = re.compile(
    r"^project_[0-9]{2}:(?:description|readme|release|deployment|ownership)$"
)
_TOPIC_CODES = frozenset({
    "ai_infrastructure", "applied_ai", "climate", "data", "developer_tools",
    "education", "fintech", "health", "marketplace", "mobile", "security", "web",
})
_TOPIC_MAP = {
    "ai": "applied_ai", "artificial-intelligence": "applied_ai",
    "machine-learning": "applied_ai", "deep-learning": "applied_ai",
    "llm": "ai_infrastructure", "large-language-models": "ai_infrastructure",
    "agents": "ai_infrastructure", "rag": "ai_infrastructure",
    "developer-tools": "developer_tools", "devtools": "developer_tools",
    "mcp": "developer_tools", "cli": "developer_tools",
    "education": "education", "edtech": "education",
    "fintech": "fintech", "payments": "fintech",
    "health": "health", "healthcare": "health",
    "climate": "climate", "climate-tech": "climate",
    "security": "security", "cybersecurity": "security",
    "data": "data", "analytics": "data",
    "web": "web", "webapp": "web", "mobile": "mobile",
    "marketplace": "marketplace",
}
_GENERIC_REPOSITORY_NAME_TOKENS = frozenset({
    "agent", "api", "app", "application", "backend", "biotech", "client",
    "climate", "commerce", "data", "demo", "education", "finance", "fintech",
    "frontend", "health", "healthcare", "medical", "mobile", "model", "platform",
    "product", "project", "router", "security", "server", "service", "system",
    "tool", "web", "workflow",
})


def _repository_identity_literals(name: str) -> tuple[str, ...]:
    """Return searchable repository-name forms that are unsafe in excerpts."""
    separated = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", name)
    tokens = tuple(
        token.casefold()
        for token in re.findall(r"[A-Za-z0-9]+", separated)
    )
    values = [name]
    values.extend(
        token for token in tokens
        if len(token) >= 4 and token not in _GENERIC_REPOSITORY_NAME_TOKENS
    )
    return tuple(dict.fromkeys(
        value for value in values
        if len(re.sub(r"[^A-Za-z0-9]+", "", value)) >= 4
    ))


def _detail_list(value: object, field: str) -> list[object] | None:
    if value is None:
        return None
    if not isinstance(value, list) or len(value) > 100:
        raise ValueError(f"GitHub {field} detail must be a bounded list")
    if any(not isinstance(item, Mapping) for item in value):
        raise ValueError(f"GitHub {field} detail item must be an object")
    return list(value)


def _repository_text(repository: Mapping[str, object], key: str) -> str:
    value = repository.get(key)
    if value is None:
        return ""
    if not isinstance(value, str) or len(value) > 100_000:
        raise ValueError(f"GitHub repository {key} is invalid")
    return value


def _selected(
    repositories: Sequence[Mapping[str, object]], *, now: datetime,
) -> list[tuple[int, Mapping[str, object], dict[str, object], tuple[int, int]]]:
    prepared: list[tuple[int, Mapping[str, object], dict[str, object], tuple[int, int]]] = []
    for index, repository in enumerate(repositories):
        vector, scores = _project_vector(repository, now=now)
        if vector:
            prepared.append((index, repository, vector, scores))
    by_engagement = sorted(prepared, key=lambda item: (-item[3][0], -item[3][1], item[0]))
    by_recency = sorted(prepared, key=lambda item: (-item[3][1], -item[3][0], item[0]))
    selected: list[tuple[int, Mapping[str, object], dict[str, object], tuple[int, int]]] = []
    seen: set[int] = set()
    for candidate in by_engagement[:2] + by_recency[:2] + by_engagement + by_recency:
        if candidate[0] in seen:
            continue
        selected.append(candidate)
        seen.add(candidate[0])
        if len(selected) == 3:
            break
    return selected


def select_rich_repository_indices(
    repositories: Sequence[Mapping[str, object]], *, now: datetime,
) -> tuple[int, ...]:
    """Return the exact bounded repository indices eligible for rich detail calls."""
    if isinstance(repositories, (str, bytes)) or not isinstance(repositories, Sequence):
        raise ValueError("GitHub repositories must be a bounded sequence")
    if len(repositories) > 100 or any(not isinstance(item, Mapping) for item in repositories):
        raise ValueError("GitHub repository sample exceeds the allowed bound")
    return tuple(item[0] for item in _selected(repositories, now=now))


def build_rich_project_packets(
    repositories: Sequence[Mapping[str, object]],
    details: Mapping[int, Mapping[str, object]], *, now: datetime,
    identity_literals: Iterable[str] = (),
) -> list[dict[str, object]]:
    """Build at most three sanitized semantic project packets."""
    if isinstance(repositories, (str, bytes)) or not isinstance(repositories, Sequence):
        raise ValueError("GitHub repositories must be a bounded sequence")
    if len(repositories) > 100:
        raise ValueError("GitHub repository sample exceeds the allowed bound")
    if not isinstance(details, Mapping) or any(
        type(index) is not int or not isinstance(value, Mapping)
        for index, value in details.items()
    ):
        raise ValueError("GitHub project details are invalid")
    literals = tuple(identity_literals)
    result: list[dict[str, object]] = []
    for ordinal, (index, repository, vector, _scores) in enumerate(
        _selected(repositories, now=now), start=1,
    ):
        name = _repository_text(repository, "name")
        if not name or len(name) > 100:
            raise ValueError("GitHub repository name is invalid")
        repository_literals = _repository_identity_literals(name)
        forbidden = literals + repository_literals
        description = sanitize_professional_text(
            _repository_text(repository, "description"),
            forbidden_literals=forbidden, max_chars=800,
        )
        topics = repository.get("topics", [])
        if not isinstance(topics, list) or len(topics) > 20 or any(
            not isinstance(topic, str) or len(topic) > 80 for topic in topics
        ):
            raise ValueError("GitHub repository topics are invalid")
        topic_codes = sorted({
            code for topic in topics
            if (code := _TOPIC_MAP.get(topic.casefold())) is not None
        })
        detail = details.get(index)
        readme = ""
        releases: list[object] | None = None
        deployments: list[object] | None = None
        if detail is not None:
            if set(detail) != _DETAIL_KEYS:
                raise ValueError("GitHub project detail fields are invalid")
            raw_readme = detail["readme"]
            if raw_readme is not None and not isinstance(raw_readme, str):
                raise ValueError("GitHub README detail must be text or null")
            readme = sanitize_professional_text(
                raw_readme or "", forbidden_literals=forbidden, max_chars=2_000,
            )
            releases = _detail_list(detail["releases"], "release")
            deployments = _detail_list(detail["deployments"], "deployment")
        if repository_literals:
            assert_no_known_identity_literals(
                {"description_excerpt": description, "readme_excerpt": readme},
                repository_literals,
            )
        homepage = _repository_text(repository, "homepage")
        has_pages = repository.get("has_pages", False)
        if not isinstance(has_pages, bool):
            raise ValueError("GitHub repository pages flag is invalid")
        release_signal = (
            "unknown" if releases is None else
            "release_observed" if releases else "none_observed"
        )
        deployment_signal = (
            "deployment_observed" if deployments else
            "repository_homepage" if homepage or has_pages else
            "unknown" if deployments is None else "none_observed"
        )
        safe = dict(vector)
        project_code = f"project_{ordinal:02d}"
        safe.update({
            "project_code": project_code,
            "deployment_signal": deployment_signal,
            "description_excerpt": description,
            "evidence_refs": [
                reference for present, reference in (
                    (True, f"{project_code}:ownership"),
                    (bool(description), f"{project_code}:description"),
                    (bool(readme), f"{project_code}:readme"),
                    (release_signal == "release_observed", f"{project_code}:release"),
                    (deployment_signal == "deployment_observed", f"{project_code}:deployment"),
                ) if present
            ],
            "readme_excerpt": readme,
            "release_signal": release_signal,
            # Repositories came from the applicant-supplied profile listing, and
            # _project_vector excludes forks before this packet is constructed.
            "repository_relationship": "profile_owned_nonfork",
            "topic_codes": topic_codes,
        })
        assert_safe_semantic_payload(safe, allowed_keys=RICH_PROJECT_FIELDS)
        result.append(safe)
    return validate_rich_project_packets(result)


def _validate_rich_project_packets(
    value: object, *, allow_repository_resanitization: bool,
) -> list[dict[str, object]]:
    if not isinstance(value, list) or len(value) > 3:
        raise ValueError("GitHub rich project packets exceed the bounded allowlist")
    structural: list[dict[str, object]] = []
    normalized: list[dict[str, object]] = []
    for ordinal, item in enumerate(value, start=1):
        if not isinstance(item, dict) or set(item) != RICH_PROJECT_FIELDS:
            raise ValueError("GitHub rich project packet fields are invalid")
        project_code = f"project_{ordinal:02d}"
        if item["project_code"] != project_code:
            raise ValueError("GitHub rich project codes must be call-local")
        if (
            not isinstance(item["description_excerpt"], str)
            or len(item["description_excerpt"]) > 800
            or not isinstance(item["readme_excerpt"], str)
            or len(item["readme_excerpt"]) > 2_000
            or item["release_signal"] not in _RELEASE_SIGNALS
            or item["deployment_signal"] not in _DEPLOYMENT_SIGNALS
            or item["repository_relationship"] != "profile_owned_nonfork"
        ):
            raise ValueError("GitHub rich project content is invalid")
        topics = item["topic_codes"]
        references = item["evidence_refs"]
        allowed_references = {
            f"{project_code}:description", f"{project_code}:readme",
            f"{project_code}:release", f"{project_code}:deployment",
            f"{project_code}:ownership",
        }
        if (
            not isinstance(topics, list) or topics != sorted(set(topics))
            or any(topic not in _TOPIC_CODES for topic in topics)
            or not isinstance(references, list) or references != list(dict.fromkeys(references))
            or f"{project_code}:ownership" not in references
            or any(
                not isinstance(reference, str)
                or not _EVIDENCE_REF.fullmatch(reference)
                or reference not in allowed_references
                for reference in references
            )
        ):
            raise ValueError("GitHub rich project evidence references are invalid")
        safety_view = item
        if allow_repository_resanitization:
            safety_view = dict(item)
            safety_view["description_excerpt"] = redact_legacy_searchable_markers(
                str(item["description_excerpt"]),
            )
            safety_view["readme_excerpt"] = redact_legacy_searchable_markers(
                str(item["readme_excerpt"]),
            )
        assert_safe_semantic_payload(
            safety_view, allowed_keys=RICH_PROJECT_FIELDS,
        )
        structural.append({key: item[key] for key in PROJECT_FIELDS})
        normalized.append(dict(item))
    validate_project_vectors(structural)
    return normalized


def validate_rich_project_packets(value: object) -> list[dict[str, object]]:
    return _validate_rich_project_packets(
        value, allow_repository_resanitization=False,
    )


def validate_rich_project_packets_for_resanitization(
    value: object,
) -> list[dict[str, object]]:
    """Validate protected legacy structure before bounded text resanitization."""
    return _validate_rich_project_packets(
        value, allow_repository_resanitization=True,
    )
