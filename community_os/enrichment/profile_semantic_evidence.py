"""Minimized application and Devpost evidence for semantic review."""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
import re

from community_os.enrichment.semantic_evidence import (
    assert_safe_semantic_payload,
    sanitize_professional_text,
)


APPLICATION_FIELDS = frozenset({
    "achievement_excerpt", "evidence_code", "evidence_refs", "experience_excerpt",
})
DEVPOST_FIELDS = frozenset({
    "demo_state", "evidence_code", "evidence_refs", "project_excerpt",
    "submission_state", "technology_codes",
})
_CODE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
DEVPOST_TECHNOLOGY_CODES = frozenset({
    "android", "applied_ai", "ar_vr", "blockchain", "cloud", "computer_vision",
    "data", "databases", "design", "devops", "dotnet", "go", "hardware",
    "ios", "javascript_typescript", "jvm", "llm", "machine_learning", "mobile",
    "no_code", "other", "php", "python", "robotics", "ruby", "rust", "shell",
    "speech", "swift", "systems", "web", "web_backend", "web_frontend",
})


def _identity_literals(value: Iterable[str]) -> tuple[str, ...]:
    if isinstance(value, (str, bytes)):
        raise ValueError("semantic evidence identity literals are invalid")
    literals = tuple(value)
    if not literals or any(not isinstance(item, str) or not item.strip() for item in literals):
        raise ValueError("semantic evidence identity literals are required")
    return literals


def build_application_evidence(
    *, experience: str, achievement: str, identity_literals: Iterable[str],
) -> list[dict[str, object]]:
    """Build the single bounded application packet used by the semantic assessor."""
    if not isinstance(experience, str) or not isinstance(achievement, str):
        raise ValueError("application semantic evidence must be text")
    literals = _identity_literals(identity_literals)
    safe_experience = sanitize_professional_text(
        experience, forbidden_literals=literals, max_chars=2_000,
    )
    safe_achievement = sanitize_professional_text(
        achievement, forbidden_literals=literals, max_chars=1_500,
    )
    if not safe_experience and not safe_achievement:
        return []
    packet = {
        "evidence_code": "application_01",
        "experience_excerpt": safe_experience,
        "achievement_excerpt": safe_achievement,
        "evidence_refs": [
            reference for present, reference in (
                (bool(safe_achievement), "application_01:achievement"),
                (bool(safe_experience), "application_01:experience"),
            ) if present
        ],
    }
    assert_safe_semantic_payload(packet, allowed_keys=APPLICATION_FIELDS)
    return [packet]


def build_devpost_evidence(
    *, projects: Sequence[Mapping[str, object]], identity_literals: Iterable[str],
) -> list[dict[str, object]]:
    """Build at most three bounded, identity-free Devpost project packets."""
    if isinstance(projects, (str, bytes)) or not isinstance(projects, Sequence):
        raise ValueError("Devpost semantic projects must be a sequence")
    if len(projects) > 3:
        raise ValueError("Devpost semantic evidence is limited to three projects")
    literals = _identity_literals(identity_literals)
    result: list[dict[str, object]] = []
    for ordinal, project in enumerate(projects, start=1):
        if not isinstance(project, Mapping):
            raise ValueError("Devpost semantic project must be an object")
        text = project.get("project_text", "")
        technologies = project.get("technology_codes", [])
        submission = project.get("submission_state")
        demo = project.get("demo_state")
        if (
            not isinstance(text, str)
            or not isinstance(technologies, list)
            or len(technologies) > 12
            or technologies != sorted(set(technologies))
            or any(
                not isinstance(code, str)
                or not _CODE.fullmatch(code)
                or code not in DEVPOST_TECHNOLOGY_CODES
                for code in technologies
            )
            or submission not in {"unknown", "draft", "submitted"}
            or demo not in {"unknown", "absent", "observed"}
        ):
            raise ValueError("Devpost semantic state or fields are invalid")
        excerpt = sanitize_professional_text(
            text, forbidden_literals=literals, max_chars=2_000,
        )
        code = f"devpost_{ordinal:02d}"
        packet = {
            "evidence_code": code,
            "project_excerpt": excerpt,
            "technology_codes": list(technologies),
            "submission_state": submission,
            "demo_state": demo,
            "evidence_refs": [
                reference for present, reference in (
                    (demo == "observed", f"{code}:demo"),
                    (bool(excerpt), f"{code}:project"),
                ) if present
            ],
        }
        assert_safe_semantic_payload(packet, allowed_keys=DEVPOST_FIELDS)
        result.append(packet)
    return result
