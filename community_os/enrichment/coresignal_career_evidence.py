"""Minimized semantic career evidence from Coresignal experience records."""

from __future__ import annotations

from collections.abc import Iterable, Mapping

from community_os.enrichment.semantic_evidence import (
    assert_safe_semantic_payload,
    sanitize_professional_text,
)


CAREER_FIELDS = frozenset({
    "active_state", "description_excerpt", "duration_band", "evidence_refs",
    "industry_code", "organization_size_band", "role_code", "seniority_context",
    "title_excerpt",
})


def _text(item: Mapping[str, object], key: str, *, limit: int = 20_000) -> str:
    value = item.get(key)
    if value is None:
        return ""
    if not isinstance(value, str) or len(value) > limit:
        raise ValueError(f"Coresignal career {key} is invalid")
    return value.strip()


def _optional_integer(item: Mapping[str, object], key: str) -> int | None:
    value = item.get(key)
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"Coresignal career {key} is invalid")
    return value


def _active_state(value: object) -> str:
    if value in {True, 1}:
        return "current"
    if value in {False, 0}:
        return "historic"
    if value is None:
        return "unknown"
    raise ValueError("Coresignal career active state is invalid")


def _duration_band(item: Mapping[str, object]) -> str:
    duration = _optional_integer(item, "duration_months")
    if duration is None:
        start_year = _optional_integer(item, "date_from_year")
        end_year = _optional_integer(item, "date_to_year")
        if start_year is not None and end_year is not None and end_year >= start_year:
            duration = (end_year - start_year) * 12
    if duration is None:
        return "unknown"
    if duration < 12:
        return "under_one_year"
    if duration <= 36:
        return "one_to_three_years"
    return "over_three_years"


def _seniority_context(management: str, title: str) -> str:
    value = f"{management} {title}".casefold()
    if any(token in value for token in ("founder", "co-founder", "chief", "c-suite", "vice president", "vp ")):
        return "founder_executive"
    if any(token in value for token in ("director", "head", "lead", "manager")):
        return "leadership"
    if any(token in value for token in ("principal", "staff", "senior")):
        return "senior"
    if any(token in value for token in ("junior", "intern", "trainee", "entry")):
        return "early_career"
    if title or management:
        return "individual_contributor"
    return "unknown"


def _industry_code(value: str) -> str:
    text = value.casefold()
    rules = (
        (("software", "technology", "internet", "computer"), "software"),
        (("financial", "bank", "fintech", "insurance"), "finance"),
        (("education", "university", "school"), "education"),
        (("health", "medical", "biotech"), "health"),
        (("research", "laboratory", "academic"), "research"),
        (("consult", "professional services"), "consulting"),
        (("manufactur", "industrial", "automotive"), "manufacturing"),
    )
    if not text:
        return "unknown"
    return next((code for tokens, code in rules if any(token in text for token in tokens)), "other")


def _organization_size_band(value: str) -> str:
    text = value.casefold().replace(",", "")
    if not text:
        return "unknown"
    if "self-employed" in text or "self employed" in text or text.strip() == "1":
        return "solo"
    numbers = [int(token) for token in text.replace("+", " ").replace("-", " ").split() if token.isdigit()]
    if not numbers:
        return "unknown"
    maximum = max(numbers)
    if maximum <= 10:
        return "small"
    if maximum <= 200:
        return "small"
    if maximum <= 1_000:
        return "medium"
    if maximum <= 5_000:
        return "large"
    return "enterprise"


def build_career_evidence(
    payload: object, *, identity_literals: Iterable[str] = (),
) -> list[dict[str, object]]:
    """Project at most six current or recent professional roles; ignore all social data."""
    if not isinstance(payload, Mapping):
        raise ValueError("Coresignal career payload must be an object")
    if isinstance(identity_literals, (str, bytes)):
        raise ValueError("Coresignal career identity literals are invalid")
    participant_literals = tuple(identity_literals)
    if not participant_literals or any(
        not isinstance(value, str) or not value.strip() for value in participant_literals
    ):
        raise ValueError("Coresignal career identity literals are required")
    experience = payload.get("experience", [])
    if not isinstance(experience, list) or len(experience) > 100:
        raise ValueError("Coresignal career experience must be a bounded list")
    prepared: list[tuple[int, int, Mapping[str, object]]] = []
    for index, item in enumerate(experience):
        if not isinstance(item, Mapping):
            raise ValueError("Coresignal career experience item must be an object")
        state = _active_state(item.get("active_experience"))
        start_year = _optional_integer(item, "date_from_year")
        _optional_integer(item, "date_from_month")
        _optional_integer(item, "date_to_year")
        _optional_integer(item, "date_to_month")
        prepared.append((0 if state == "current" else 1, -(start_year or 0), item))
    prepared.sort(key=lambda value: (value[0], value[1]))

    result: list[dict[str, object]] = []
    for ordinal, (_active_order, _year_order, item) in enumerate(prepared[:6], start=1):
        company_literals = tuple(
            value for key in (
                "company_name", "active_experience_company", "company",
            ) if (value := _text(item, key, limit=500))
        )
        forbidden = participant_literals + company_literals
        title = sanitize_professional_text(
            _text(item, "position_title", limit=1_000),
            forbidden_literals=forbidden, max_chars=300,
        ).strip(" -,:@")
        description = sanitize_professional_text(
            _text(item, "description"), forbidden_literals=forbidden,
            max_chars=1_500,
        )
        management = _text(item, "management_level", limit=500)
        code = f"role_{ordinal:02d}"
        record = {
            "role_code": code,
            "title_excerpt": title,
            "description_excerpt": description,
            "active_state": _active_state(item.get("active_experience")),
            "duration_band": _duration_band(item),
            "seniority_context": _seniority_context(management, title),
            "industry_code": _industry_code(_text(item, "company_industry", limit=1_000)),
            "organization_size_band": _organization_size_band(
                _text(item, "company_size_range", limit=200),
            ),
            "evidence_refs": [
                reference for present, reference in (
                    (bool(title), f"{code}:title"),
                    (bool(description), f"{code}:description"),
                ) if present
            ],
        }
        assert_safe_semantic_payload(record, allowed_keys=CAREER_FIELDS)
        result.append(record)
    return result
