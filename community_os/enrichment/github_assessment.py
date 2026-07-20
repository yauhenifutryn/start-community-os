"""Privacy-minimized structural assessment of public GitHub project activity."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Callable, Mapping, Sequence

from community_os.enrichment.cache import CanonicalJsonCache


PROJECT_FIELDS = frozenset({
    "project_code", "age_band", "activity_recency", "size_band",
    "stars_band", "forks_band", "issues_band", "language_code",
    "productization_codes",
})
MODEL = "gpt-5.6-luna"
PROMPT_VERSION = "structural-project-evidence-v1"
_AGE_BANDS = frozenset({"new", "established", "mature", "unknown"})
_RECENCY_BANDS = frozenset({"active_90d", "active_365d", "stale", "unknown"})
_SIZE_BANDS = frozenset({"tiny", "small", "medium", "large", "unknown"})
_COUNT_BANDS = frozenset({"none", "some", "notable", "high"})
_LANGUAGE_CODES = frozenset({
    "systems", "dotnet", "web_frontend", "dart", "go", "jvm",
    "javascript_typescript", "data_notebook", "php", "python", "ruby",
    "rust", "shell", "swift", "unknown",
})
_LANGUAGE_MAP = {
    "c": "systems", "c++": "systems", "c#": "dotnet", "css": "web_frontend",
    "dart": "dart", "f#": "dotnet", "go": "go", "html": "web_frontend",
    "java": "jvm", "javascript": "javascript_typescript",
    "jupyter notebook": "data_notebook", "kotlin": "jvm", "php": "php",
    "python": "python", "ruby": "ruby", "rust": "rust", "shell": "shell",
    "svelte": "web_frontend", "swift": "swift",
    "typescript": "javascript_typescript", "vue": "web_frontend",
}
_PRODUCTIZATION_CODES = frozenset({
    "issues_enabled", "license_present", "pages_enabled",
})

ASSESSMENT_FIELDS = frozenset({
    "evidence_strength", "maintenance", "external_validation", "productization",
    "categories", "reason_codes", "confidence_state", "review_state",
})
ASSESSMENT_ENUMS = {
    "evidence_strength": frozenset({"insufficient", "limited", "moderate", "strong"}),
    "maintenance": frozenset({"unknown", "inactive", "active", "sustained"}),
    "external_validation": frozenset({"none", "limited", "moderate", "strong"}),
    "productization": frozenset({"none", "limited", "moderate", "strong"}),
    "confidence_state": frozenset({"low", "medium", "high"}),
    # Model output is evidence for an operator, never an automatic person-level fact.
    "review_state": frozenset({"human_review_required"}),
}
ASSESSMENT_CATEGORIES = frozenset({
    "backend", "data_ai", "devtools", "frontend", "general_software",
    "mobile", "systems", "unknown",
})
ASSESSMENT_REASON_CODES = frozenset({
    "evidence_conflict", "external_interest", "low_signal", "multi_project_delivery",
    "multiple_projects", "no_eligible_projects", "production_signals",
    "recent_activity", "repeated_external_interest", "single_project",
    "sustained_activity",
})


def _utc(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ValueError("GitHub project timestamps require a timezone")
    return value.astimezone(UTC)


def _timestamp(value: object) -> datetime | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("GitHub repository timestamp is invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("GitHub repository timestamp is invalid") from error
    return _utc(parsed)


def _nonnegative_integer(repository: Mapping[str, object], key: str) -> int:
    value = repository.get(key, 0)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError("GitHub repository numeric signal is invalid")
    return value


def _count_band(value: int) -> str:
    if value == 0:
        return "none"
    if value < 10:
        return "some"
    if value < 100:
        return "notable"
    return "high"


def _project_vector(repository: Mapping[str, object], *, now: datetime) -> tuple[dict[str, object], tuple[int, int]]:
    flags: dict[str, bool] = {}
    for key in ("fork", "archived", "disabled"):
        value = repository.get(key)
        if not isinstance(value, bool):
            raise ValueError("GitHub repository eligibility flag is invalid")
        flags[key] = value
    template = repository.get("is_template", False)
    if not isinstance(template, bool):
        raise ValueError("GitHub repository eligibility flag is invalid")
    if flags["fork"] or flags["archived"] or flags["disabled"] or template:
        return {}, (0, 0)

    created = _timestamp(repository.get("created_at"))
    pushed = _timestamp(repository.get("pushed_at"))
    size = _nonnegative_integer(repository, "size")
    stars = _nonnegative_integer(repository, "stargazers_count")
    forks = _nonnegative_integer(repository, "forks_count")
    issues = _nonnegative_integer(repository, "open_issues_count")
    language = repository.get("language")
    if language is not None and not isinstance(language, str):
        raise ValueError("GitHub repository language signal is invalid")
    has_pages = repository.get("has_pages", False)
    has_issues = repository.get("has_issues", False)
    if not isinstance(has_pages, bool) or not isinstance(has_issues, bool):
        raise ValueError("GitHub repository productization signal is invalid")
    license_value = repository.get("license")
    if license_value is not None and not isinstance(license_value, Mapping):
        raise ValueError("GitHub repository license signal is invalid")

    current = _utc(now)
    age_days = None if created is None else max(0, (current - created).days)
    recency_days = None if pushed is None else max(0, (current - pushed).days)
    age_band = (
        "unknown" if age_days is None else
        "new" if age_days < 180 else
        "established" if age_days < 1095 else "mature"
    )
    recency = (
        "unknown" if recency_days is None else
        "active_90d" if recency_days <= 90 else
        "active_365d" if recency_days <= 365 else "stale"
    )
    size_band = (
        "tiny" if size < 300 else "small" if size < 3000 else
        "medium" if size < 30000 else "large"
    )
    productization = []
    if has_issues:
        productization.append("issues_enabled")
    if license_value is not None:
        productization.append("license_present")
    if has_pages:
        productization.append("pages_enabled")

    vector: dict[str, object] = {
        "project_code": "project_00",
        "age_band": age_band,
        "activity_recency": recency,
        "size_band": size_band,
        "stars_band": _count_band(stars),
        "forks_band": _count_band(forks),
        "issues_band": _count_band(issues),
        "language_code": _LANGUAGE_MAP.get((language or "").casefold(), "unknown"),
        "productization_codes": sorted(productization),
    }
    recency_score = 0 if recency_days is None else max(0, 100000 - recency_days)
    engagement_score = min(stars, 100000) * 3 + min(forks, 100000) * 5
    return vector, (engagement_score, recency_score)


def build_project_vectors(
    repositories: Sequence[Mapping[str, object]], *, now: datetime,
) -> list[dict[str, object]]:
    """Select at most six eligible repositories and discard every textual identifier."""
    if isinstance(repositories, (str, bytes)) or not isinstance(repositories, Sequence):
        raise ValueError("GitHub repositories must be a bounded sequence")
    if len(repositories) > 100:
        raise ValueError("GitHub repository sample exceeds the allowed bound")
    prepared: list[tuple[int, dict[str, object], tuple[int, int]]] = []
    for index, repository in enumerate(repositories):
        if not isinstance(repository, Mapping):
            raise ValueError("GitHub repository must be an object")
        vector, scores = _project_vector(repository, now=now)
        if vector:
            prepared.append((index, vector, scores))

    by_engagement = sorted(prepared, key=lambda item: (-item[2][0], -item[2][1], item[0]))
    by_recency = sorted(prepared, key=lambda item: (-item[2][1], -item[2][0], item[0]))
    selected: list[tuple[int, dict[str, object], tuple[int, int]]] = []
    selected_indices: set[int] = set()
    for candidate in by_engagement[:3] + by_recency[:3] + by_engagement:
        if candidate[0] in selected_indices:
            continue
        selected.append(candidate)
        selected_indices.add(candidate[0])
        if len(selected) == 6:
            break

    result: list[dict[str, object]] = []
    for ordinal, (_index, vector, _scores) in enumerate(selected, start=1):
        safe = dict(vector)
        safe["project_code"] = f"project_{ordinal:02d}"
        result.append(safe)
    validate_project_vectors(result)
    return result


def validate_project_vectors(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list) or len(value) > 6:
        raise ValueError("GitHub assessment projects exceed the bounded allowlist")
    normalized: list[dict[str, object]] = []
    for ordinal, item in enumerate(value, start=1):
        if not isinstance(item, dict) or set(item) != PROJECT_FIELDS:
            raise ValueError("GitHub assessment project fields exceed the allowlist")
        if item["project_code"] != f"project_{ordinal:02d}":
            raise ValueError("GitHub assessment project codes must be call-local")
        scalar_allowlists = {
            "age_band": _AGE_BANDS, "activity_recency": _RECENCY_BANDS,
            "size_band": _SIZE_BANDS, "stars_band": _COUNT_BANDS,
            "forks_band": _COUNT_BANDS, "issues_band": _COUNT_BANDS,
            "language_code": _LANGUAGE_CODES,
        }
        if any(item[key] not in allowed for key, allowed in scalar_allowlists.items()):
            raise ValueError("GitHub assessment project signal is outside the allowlist")
        codes = item["productization_codes"]
        if (
            not isinstance(codes, list) or len(codes) != len(set(codes))
            or any(code not in _PRODUCTIZATION_CODES for code in codes)
        ):
            raise ValueError("GitHub project productization signal is outside the allowlist")
        normalized.append(dict(item))
    return normalized


def validate_assessment(value: object) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != ASSESSMENT_FIELDS:
        raise ValueError("GitHub semantic assessment fields are invalid")
    for key, allowed in ASSESSMENT_ENUMS.items():
        if value[key] not in allowed:
            raise ValueError("GitHub semantic assessment value is outside the taxonomy")
    for key, allowed in (
        ("categories", ASSESSMENT_CATEGORIES),
        ("reason_codes", ASSESSMENT_REASON_CODES),
    ):
        items = value[key]
        if (
            not isinstance(items, list) or not items or len(items) != len(set(items))
            or any(item not in allowed for item in items)
        ):
            raise ValueError("GitHub semantic assessment list is outside the taxonomy")
    return dict(value)


class GitHubProjectAssessor:
    """Versioned, cached semantic assessment that retains the human-review boundary."""

    VERSION = "github-project-assessment-v1"
    MODEL = MODEL
    PROMPT_VERSION = PROMPT_VERSION
    cache_identity = ":".join((VERSION, PROMPT_VERSION, MODEL))

    def __init__(
        self, *, provider: Callable[[dict[str, object]], dict[str, object]],
        cache: CanonicalJsonCache, clock: Callable[[], datetime],
        retention_days: int,
    ) -> None:
        if type(retention_days) is not int or not 1 <= retention_days <= 7:
            raise ValueError("GitHub assessment retention must be between one and seven days")
        self.provider = provider
        self.cache = cache
        self.clock = clock
        self.retention_days = retention_days

    def assess(self, projects: object) -> dict[str, object]:
        vectors = validate_project_vectors(projects)
        payload = {"projects": vectors}
        key = self.cache.key("github_assessment", self.cache_identity, payload)
        cached = self.cache.get(key)
        if cached is not None:
            return validate_assessment(cached)
        result = validate_assessment(self.provider(payload))
        self.cache.set(
            key, result,
            expires_at=self.clock() + timedelta(days=self.retention_days),
        )
        return result
