"""Bounded sanitization for pseudonymous professional semantic evidence."""

from __future__ import annotations

import math
import hashlib
import json
import re
import unicodedata
from collections.abc import Iterable, Mapping, Sequence


DEFAULT_EXCERPT_CHARS = 2_000
DEFAULT_PACKET_CHARS = 12_000

_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_MARKDOWN_IMAGE = re.compile(r"!\[[^\]]*\]\([^)]*\)")
_MARKDOWN_LINK = re.compile(r"\[([^\]]+)\]\([^)]*\)")
_MARKDOWN_HEADING = re.compile(r"(?m)^[ \t]{0,3}#{1,6}[ \t]*")
_HTML_TAG = re.compile(r"<[^>]{1,500}>")
_EMAIL = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
_URL = re.compile(r"(?i)(?:https?://|www\.)\s*\S*")
_BARE_DOMAIN = re.compile(
    r"(?i)(?<![@\w])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z]{2,63}"
    r"(?::[0-9]{2,5})?(?:/[^\s]*)?"
)
_SPACED_DOMAIN_FRAGMENT = re.compile(
    r"(?i)(?<![@\w])(?:[a-z0-9-]+\s*)?"
    r"(?:\.\s*[a-z0-9-]{2,}\s*)*\.\s*(?:"
    r"academy|agency|ai|app|art|biz|blog|cloud|club|co|com|community|"
    r"company|design|dev|digital|email|eu|finance|health|info|io|live|"
    r"market|me|net|network|news|online|org|pl|site|solutions|store|"
    r"studio|systems|team|tech|tools|world|xyz"
    r")\b"
)
_SPACED_ARBITRARY_DOMAIN = re.compile(
    r"(?i)(?<![@\w])[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"\s+\.\s*[a-z]{2,63}\b"
)
_OBFUSCATED_EMAIL = re.compile(
    r"(?i)(?<![\w@])[a-z0-9._%+-]{2,}\s*"
    r"(?:\[\s*at\s*\]|\(\s*at\s*\)|\s+at\s+)\s*"
    r"[a-z0-9-]*(?:\s*(?:\[\s*dot\s*\]|\(\s*dot\s*\)|\s+dot\s+)"
    r"\s*[a-z0-9-]+)+\b"
)
_OBFUSCATED_DOMAIN = re.compile(
    r"(?i)(?<![@\w])[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"\s+(?:dot|\[\s*dot\s*\]|\(\s*dot\s*\))\s+"
    r"[a-z]{2,63}\b"
)
_REPOSITORY_PATH = re.compile(
    r"(?i)(?:\brepo(?:sitory)?\s*:\s*['\"]?/?|(?<![\w./-])/)"
    r"[a-z0-9][a-z0-9_.-]{1,38}/[a-z0-9][a-z0-9_.-]{1,99}"
    r"(?![\w./-])['\"]?"
)
_BARE_REPOSITORY_PATH = re.compile(
    r"(?i)(?<![\w./-])/?[a-z0-9][a-z0-9_.-]{0,38}/"
    r"[a-z0-9][a-z0-9_.-]{0,99}(?![\w./-])"
)
_ORPHAN_SLASH_IDENTIFIER = re.compile(
    r"(?i)(?<![\w./-])/(?:\s*/\s*)?"
    r"[a-z0-9][a-z0-9_.-]{1,99}(?![\w./-])"
)
_LOWER_CAMEL_IDENTIFIER = re.compile(
    r"\b(?!(?:eBPF|eSIM|gRPC|iOS|iPadOS|mDNS|mTLS|macOS|tvOS|useState|watchOS)\b)"
    r"[a-z][a-z0-9]*[A-Z][A-Za-z0-9]*\b"
)
_CHANNEL_IDENTIFIER = re.compile(
    r"\b[A-Z][A-Za-z0-9'&+-]*"
    r"(?:\s+(?:is|of|the|and|[A-Z][A-Za-z0-9'&+-]*)){0,4}"
    r"\s+(?:YT|YouTube(?:\s+Channel)?)\b"
)
_HANDLE = re.compile(r"(?<!\w)@[A-Za-z0-9_-]{2,}")
_SPACED_HANDLE = re.compile(r"(?<!\w)@\s+[A-Za-z0-9_-]{2,}")
_PHONE = re.compile(r"(?<!\w)\+?\d[\d\s().-]{7,}\d(?!\w)")
_STREET_ADDRESS = re.compile(
    r"(?i)\b\d{1,6}(?:\s+[^\W\d_][\w'-]*){1,5}\s+"
    r"(?:street|st|avenue|ave|road|rd|boulevard|blvd|lane|ln|drive|dr|"
    r"way|square|sq|place|pl|ulica|ul|aleja|al)\b"
    r"(?:\s*,\s*(?:(?!and\b|but\b)[^\W\d_][\w'-]*)"
    r"(?:\s+(?!and\b|but\b)[^\W\d_][\w'-]*){0,2})?"
)
_LOCATION_CUE = re.compile(
    r"(?i)\b(?:lives?|living|resides?|located|based)\s+"
    r"(?:in|at|near)\s+[^,.;\n]{1,80}?"
    r"(?=\s+(?:and|but)\b|[,.;\n]|$)"
)
_EMPTY_LOCATION_CUE = re.compile(
    r"(?i)\b(?:lives?|living|resides?|located|based)\s+"
    r"(?:in|at|near)\s*(?=(?:and|but)\b|[,.;\n]|$)"
)
_GENERAL_LOCATION_CUE = re.compile(
    r"(?i)\b(?:in|at|near|from)\s+(?:the\s+)?(?:"
    r"amsterdam|austria|barcelona|belgium|berlin|bratislava|brussels|"
    r"budapest|copenhagen|czech(?:ia|\s+republic)|dublin|europe|finland|"
    r"france|gdansk|gdańsk|germany|greece|helsinki|ireland|italy|krak(?:ow|ów)|lisbon|"
    r"london|madrid|munich|münchen|netherlands|new\s+york|norway|paris|"
    r"poland|polska|porto|prague|riga|rome|spain|stockholm|sweden|"
    r"switzerland|tallinn|ukraine|united\s+kingdom|united\s+states|"
    r"vienna|vilnius|warsaw|warszawa|wroclaw|wrocław|zurich"
    r")\b"
)
_EMPTY_GENERAL_LOCATION_CUE = re.compile(
    r"(?i)\b(?:in|at|near|from)\s*(?=(?:and|but|for|to)\b|[,.;:\n]|$)"
)
_PERSON_CUE = re.compile(
    r"\b(?P<cue>alongside|by|mentored\s+by|worked\s+with|with)\s+"
    r"(?P<first>[a-z][a-z'-]*)\s+[a-z][a-z'-]*"
    r"(?:\s+(?!(?:and|at|but|for|on|to|who)\b)[a-z][a-z'-]*)?"
    r"(?=\s+(?:and|at|but|for|on|to|who)\b|\s*[,.;:\n]|\s*$)"
)
_ORGANIZATION = re.compile(
    r"(?i)\b(?!(?:am|are|be|been|being|is|remain|remains|seem|seems|was|were)\s+)"
    r"[^\W\d_][\w&'-]*\s+"
    r"(?:company|corp(?:oration)?|foundation|gmbh|inc(?:orporated)?|labs?|"
    r"llc|ltd|limited|studio|technologies|ventures)\b"
)
_SERVICE_ENTITY = re.compile(r"(?i)\b(?:coresignal|github|linkedin|openai)\b")
_LABELED_IDENTIFIER = re.compile(
    r"(?i)\b(?:github|linkedin|login|owner|profile|repo(?:sitory)?|user(?:name)?|"
    r"source[_-]?(?:id|ref)|subject[_-]?(?:id|ref))"
    r"\s*[:=]\s*['\"]?[A-Za-z0-9][A-Za-z0-9_.:/-]{2,255}['\"]?"
)
_STABLE_IDENTIFIER = re.compile(
    r"(?i)\b(?:pid:v[0-9]+:[a-z0-9_-]{8,}|"
    r"(?:applicant|candidate|person|source|subject)[_:-]"
    r"(?=[a-z0-9_-]{3,}\b)(?=[a-z0-9_-]*[0-9])[a-z0-9_-]{3,}|"
    r"(?:cs|gh|li)_[a-z0-9_-]{6,}|[a-f0-9]{32,})\b"
)
_NAMED_SECRET = re.compile(
    r"(?i)\b(?:api[_-]?key|access[_-]?token|token|secret|password)"
    r"\s*[:=]\s*[A-Za-z0-9_./+\-=]{12,}\b"
)
_TOKEN = re.compile(r"(?i)\b(?:gh[pousr]_|sk-(?:proj-)?)[A-Za-z0-9_-]{16,}\b")
_PROPER_NOUN = re.compile(r"(?<![\w@])[^\W\d_][\w&+-]{2,}(?!\w)", re.UNICODE)
_REDACTION_GAP_PUNCTUATION = re.compile(r"\s+\.\s+")
_WHITESPACE = re.compile(r"\s+")

# Free-text evidence has no reliable local named-entity model. Keep a deliberately
# small allowlist of professional sentence openers and redact other title-cased
# tokens. Known identity literals remain the primary exact-match control.
_PROFESSIONAL_OPENERS = frozenset({
    "Architect", "Architected", "Architecture", "Built", "Changed", "Chief", "Created",
    "Currently", "Data", "Delivered", "Deployed", "Designed", "Developed",
    "Developer", "Director", "Documentation", "Engineer", "Engineering",
    "Founder", "Founded", "Head", "Implemented", "Includes", "Junior",
    "Launched", "Lead", "Led", "Machine", "Managed", "Manager", "Multiple",
    "OAuth", "Operations", "Previously", "Product", "Production", "Repeated",
    "Researcher", "Runs", "Senior", "Shipped", "Software", "Scientist",
    "Supports", "Technical", "That", "The", "This", "Uses", "Worked", "Working",
})
_PROFESSIONAL_BARE_WORDS = frozenset({
    "api", "architecture", "built", "cloud", "data", "deployed", "deployment",
    "designed", "developed", "developer", "engineering", "implemented",
    "infrastructure", "machine", "managed", "mobile", "operations", "platform",
    "product", "production", "project", "prototype", "research", "service",
    "shipped", "software", "system", "systems", "tool", "tooling", "web",
    "workflow", "workflows", "working",
})
_LIKELY_PERSON_FIRST_NAMES = frozenset({
    "adam", "alex", "anna", "david", "ewa", "jakub", "james", "jane", "jan",
    "john", "julia", "kamil", "karolina", "katarzyna", "lukasz", "maria",
    "marta", "mateusz", "michael", "michal", "natalia", "pawel", "peter",
    "piotr", "robert", "sarah", "sofia", "tomasz", "wojciech", "zaneta",
})

_FORBIDDEN_KEY_PARTS = frozenset({
    "activity", "contact", "email", "handle", "identifier", "linkedin", "login",
    "name", "owner", "phone", "post", "profile", "recommendation", "source",
    "telephone", "uri", "url", "username",
})
_SUBJECT_INITIAL_PREFIX = "subject-initial:"


def _is_disallowed_proper_noun(value: str) -> bool:
    return value[0].isupper() and value not in _PROFESSIONAL_OPENERS


def _possible_bare_person(value: str) -> bool:
    words = re.findall(r"[^\W\d_][\w'-]*", value, flags=re.UNICODE)
    return (
        bool(re.fullmatch(r"\s*[^\W\d_][\w'-]*(?:\s+[^\W\d_][\w'-]*){1,2}\s*", value))
        and words[0].casefold() in _LIKELY_PERSON_FIRST_NAMES
        and all(word.casefold() not in _PROFESSIONAL_BARE_WORDS for word in words)
    )


def _person_cue_is_name(match: re.Match[str]) -> bool:
    # Two- or three-word phrases after a person cue are not necessary for the
    # semantic rubric. Redact them even when a small local name list does not
    # recognize the first token.
    return (
        match.group("cue") != "with"
        or match.group("first") in _LIKELY_PERSON_FIRST_NAMES
    )


def _redact_person_cues(value: str) -> str:
    return _PERSON_CUE.sub(
        lambda match: " " if _person_cue_is_name(match) else match.group(0),
        value,
    )


def _contextual_initial_pattern(initial: str) -> re.Pattern[str]:
    """Match a one-character identity only in an explicit byline/label."""
    return re.compile(
        r"(?i)(?<!\w)(?:by|author|owner|maintainer)\s*[:=]?\s*"
        + re.escape(initial)
        + r"(?=\s*(?:[,.;:)\]}]|$))",
    )


def redact_repository_shorthand(value: str) -> str:
    """Remove slash-form repository identifiers without changing other text."""
    if not isinstance(value, str):
        raise TypeError("semantic evidence text must be a string")
    return _REPOSITORY_PATH.sub(" ", value)


def redact_legacy_searchable_markers(value: str) -> str:
    """Remove only versioned identifier variants allowed at protected import."""
    if not isinstance(value, str):
        raise TypeError("semantic evidence text must be a string")
    text = value
    patterns = (
        _MARKDOWN_HEADING, _SPACED_DOMAIN_FRAGMENT, _SPACED_ARBITRARY_DOMAIN,
        _OBFUSCATED_EMAIL, _OBFUSCATED_DOMAIN, _REPOSITORY_PATH,
        _BARE_REPOSITORY_PATH, _ORPHAN_SLASH_IDENTIFIER,
        _LOWER_CAMEL_IDENTIFIER, _EMPTY_LOCATION_CUE, _LOCATION_CUE,
        _EMPTY_GENERAL_LOCATION_CUE, _GENERAL_LOCATION_CUE,
    )
    for _ in range(3):
        previous = text
        for pattern in patterns:
            text = pattern.sub(" ", text)
        text = _REDACTION_GAP_PUNCTUATION.sub(" ", text)
        if text == previous:
            break
    return _WHITESPACE.sub(" ", text).strip()


def sanitize_professional_text(
    value: str, *, forbidden_literals: Iterable[str] = (),
    max_chars: int = DEFAULT_EXCERPT_CHARS,
) -> str:
    """Return bounded professional prose with direct identifiers removed."""
    if not isinstance(value, str):
        raise TypeError("semantic evidence text must be a string")
    if type(max_chars) is not int or not 1 <= max_chars <= DEFAULT_PACKET_CHARS:
        raise ValueError("semantic evidence text limit is invalid")
    text = unicodedata.normalize("NFC", value)
    text = _CONTROL.sub(" ", text)
    text = _MARKDOWN_IMAGE.sub(" ", text)
    text = _MARKDOWN_LINK.sub(r"\1", text)
    text = _MARKDOWN_HEADING.sub(" ", text)
    text = _HTML_TAG.sub(" ", text)
    for literal in forbidden_literals:
        if not isinstance(literal, str):
            raise TypeError("semantic evidence forbidden literal must be a string")
        normalized = unicodedata.normalize("NFC", literal).strip()
        if normalized:
            contextual_initial = None
            if normalized.startswith(_SUBJECT_INITIAL_PREFIX):
                candidate = normalized.removeprefix(_SUBJECT_INITIAL_PREFIX)
                if len(candidate) != 1 or not candidate.isalpha():
                    raise ValueError("semantic evidence subject initial is invalid")
                contextual_initial = candidate
            identity_words = re.findall(r"[^\W_]+", normalized, flags=re.UNICODE)
            if identity_words:
                if contextual_initial is not None:
                    text = _contextual_initial_pattern(contextual_initial).sub(
                        " ", text,
                    )
                else:
                    variant = (
                        r"(?<![^\W_])"
                        + r"[\W_]+".join(re.escape(word) for word in identity_words)
                        + r"(?![^\W_])"
                    )
                    text = re.sub(variant, " ", text, flags=re.IGNORECASE)
    for pattern in (
        _LABELED_IDENTIFIER, _STABLE_IDENTIFIER, _EMAIL, _OBFUSCATED_EMAIL,
        _URL, _BARE_DOMAIN,
        _SPACED_DOMAIN_FRAGMENT, _SPACED_ARBITRARY_DOMAIN,
        _OBFUSCATED_DOMAIN,
        _REPOSITORY_PATH, _BARE_REPOSITORY_PATH,
        _ORPHAN_SLASH_IDENTIFIER, _LOWER_CAMEL_IDENTIFIER, _CHANNEL_IDENTIFIER,
        _HANDLE, _SPACED_HANDLE, _STREET_ADDRESS, _EMPTY_LOCATION_CUE,
        _LOCATION_CUE,
        _ORGANIZATION, _SERVICE_ENTITY,
        _EMPTY_GENERAL_LOCATION_CUE, _GENERAL_LOCATION_CUE,
        _PHONE, _NAMED_SECRET, _TOKEN,
    ):
        text = pattern.sub(" ", text)
    text = _redact_person_cues(text)
    text = _PROPER_NOUN.sub(
        lambda match: " " if _is_disallowed_proper_noun(match.group(0)) else match.group(0),
        text,
    )
    # Name removal can make previously separated numeric or identifier fragments
    # adjacent. Re-run the direct-identifier pass before final normalization.
    text = _REDACTION_GAP_PUNCTUATION.sub(" ", text)
    for pattern in (
        _LABELED_IDENTIFIER, _STABLE_IDENTIFIER, _EMAIL, _OBFUSCATED_EMAIL,
        _URL, _BARE_DOMAIN,
        _SPACED_DOMAIN_FRAGMENT, _SPACED_ARBITRARY_DOMAIN,
        _OBFUSCATED_DOMAIN,
        _REPOSITORY_PATH, _BARE_REPOSITORY_PATH,
        _ORPHAN_SLASH_IDENTIFIER, _LOWER_CAMEL_IDENTIFIER, _CHANNEL_IDENTIFIER,
        _HANDLE, _SPACED_HANDLE, _STREET_ADDRESS, _EMPTY_LOCATION_CUE,
        _LOCATION_CUE,
        _ORGANIZATION, _SERVICE_ENTITY,
        _EMPTY_GENERAL_LOCATION_CUE, _GENERAL_LOCATION_CUE,
        _PHONE, _NAMED_SECRET, _TOKEN,
    ):
        text = pattern.sub(" ", text)
    text = _redact_person_cues(text)
    text = text.replace("@", " ")
    text = _REDACTION_GAP_PUNCTUATION.sub(" ", text)
    text = _WHITESPACE.sub(" ", text).strip()
    if _possible_bare_person(text):
        text = ""
    truncated = text[:max_chars]
    if (
        len(text) > max_chars
        and truncated
        and (truncated[-1].isalnum() or truncated[-1] in "_&+-")
        and (text[max_chars].isalnum() or text[max_chars] in "_&+-")
        and _unsafe_marker(truncated) is not None
    ):
        boundary = truncated.rfind(" ")
        truncated = truncated[:boundary] if boundary >= 0 else ""
    truncated = truncated.rstrip()
    # Truncation can create a new dangling cue, for example by cutting
    # "at scale" immediately after "at". Re-run the bounded direct-identifier
    # cleanup on the final slice and blank it if any unsafe marker remains.
    truncated = _REDACTION_GAP_PUNCTUATION.sub(" ", truncated)
    for pattern in (
        _LABELED_IDENTIFIER, _STABLE_IDENTIFIER, _EMAIL, _OBFUSCATED_EMAIL,
        _URL, _BARE_DOMAIN,
        _SPACED_DOMAIN_FRAGMENT, _SPACED_ARBITRARY_DOMAIN,
        _OBFUSCATED_DOMAIN,
        _REPOSITORY_PATH, _BARE_REPOSITORY_PATH,
        _ORPHAN_SLASH_IDENTIFIER, _LOWER_CAMEL_IDENTIFIER, _CHANNEL_IDENTIFIER,
        _HANDLE, _SPACED_HANDLE, _STREET_ADDRESS, _EMPTY_LOCATION_CUE,
        _LOCATION_CUE,
        _ORGANIZATION, _SERVICE_ENTITY,
        _EMPTY_GENERAL_LOCATION_CUE, _GENERAL_LOCATION_CUE,
        _PHONE, _NAMED_SECRET, _TOKEN,
    ):
        truncated = pattern.sub(" ", truncated)
    truncated = _redact_person_cues(truncated)
    truncated = _PROPER_NOUN.sub(
        lambda match: " " if _is_disallowed_proper_noun(match.group(0)) else match.group(0),
        truncated,
    )
    truncated = _WHITESPACE.sub(" ", truncated).strip()
    return truncated if _unsafe_marker(truncated) is None else ""


def _forbidden_key(key: str) -> bool:
    normalized = re.sub(r"[^a-z0-9]+", "_", key.casefold()).strip("_")
    parts = frozenset(part for part in normalized.split("_") if part)
    return any(
        part == forbidden or part.startswith(forbidden)
        for part in parts for forbidden in _FORBIDDEN_KEY_PARTS
    )


def _unsafe_marker(value: str) -> str | None:
    for label, pattern in (
        ("labeled_identifier", _LABELED_IDENTIFIER),
        ("stable_identifier", _STABLE_IDENTIFIER),
        ("email", _EMAIL),
        ("email", _OBFUSCATED_EMAIL),
        ("url", _URL),
        ("bare_domain", _BARE_DOMAIN),
        ("bare_domain", _SPACED_DOMAIN_FRAGMENT),
        ("bare_domain", _SPACED_ARBITRARY_DOMAIN),
        ("bare_domain", _OBFUSCATED_DOMAIN),
        ("repository_path", _REPOSITORY_PATH),
        ("repository_path", _BARE_REPOSITORY_PATH),
        ("repository_path", _ORPHAN_SLASH_IDENTIFIER),
        ("product_identifier", _LOWER_CAMEL_IDENTIFIER),
        ("channel_identifier", _CHANNEL_IDENTIFIER),
        ("markdown_heading", _MARKDOWN_HEADING),
        ("handle", _HANDLE),
        ("handle", _SPACED_HANDLE),
        ("location_or_address", _STREET_ADDRESS),
        ("location_or_address", _LOCATION_CUE),
        ("organization", _ORGANIZATION),
        ("organization", _SERVICE_ENTITY),
        ("location_or_address", _EMPTY_GENERAL_LOCATION_CUE),
        ("location_or_address", _GENERAL_LOCATION_CUE),
        ("phone", _PHONE),
        ("named_secret", _NAMED_SECRET),
        ("token", _TOKEN),
        ("control_character", _CONTROL),
    ):
        if pattern.search(value) is not None:
            return label
    if "@" in value:
        return "at_sign"
    if any(_person_cue_is_name(match) for match in _PERSON_CUE.finditer(value)):
        return "possible_person"
    if _possible_bare_person(value):
        return "possible_person"
    if any(
        _is_disallowed_proper_noun(match.group(0))
        for match in _PROPER_NOUN.finditer(value)
    ):
        return "proper_noun"
    return None


def _unsafe_string(value: str) -> bool:
    return _unsafe_marker(value) is not None


def _identity_words(value: str) -> str:
    normalized = unicodedata.normalize("NFKC", value).casefold()
    return " ".join(re.findall(r"[^\W_]+", normalized, flags=re.UNICODE))


def assert_no_known_identity_literals(
    value: object, identity_literals: Iterable[str],
) -> str:
    """Fail closed when a final model packet contains a known identity literal."""
    if isinstance(identity_literals, (str, bytes)):
        raise TypeError("known identity corpus must be an iterable of strings")
    forms: set[str] = set()
    for literal in identity_literals:
        if not isinstance(literal, str):
            raise TypeError("known identity corpus must contain only strings")
        form = _identity_words(literal)
        if len(form.replace(" ", "")) >= 4:
            forms.add(form)
    if not forms:
        raise ValueError("known identity corpus is empty")
    corpus_hash = hashlib.sha256(
        json.dumps(sorted(forms), ensure_ascii=True, separators=(",", ":")).encode()
    ).hexdigest()

    def visit(item: object) -> None:
        if isinstance(item, Mapping):
            for nested in item.values():
                visit(nested)
        elif isinstance(item, Sequence) and not isinstance(item, (str, bytes, bytearray)):
            for nested in item:
                visit(nested)
        elif isinstance(item, str):
            words = _identity_words(item)
            padded = f" {words} "
            if any(f" {form} " in padded for form in forms):
                raise ValueError("semantic evidence packet contains a known identity literal")

    visit(value)
    return corpus_hash


def assert_safe_semantic_payload(
    value: object, *, max_total_chars: int = DEFAULT_PACKET_CHARS,
    allowed_keys: Iterable[str] = (),
) -> None:
    """Fail closed when a semantic model payload exceeds the privacy boundary."""
    if type(max_total_chars) is not int or not 1 <= max_total_chars <= 100_000:
        raise ValueError("semantic evidence packet limit is invalid")
    explicit_keys = frozenset(allowed_keys)
    if any(not isinstance(key, str) for key in explicit_keys):
        raise TypeError("semantic evidence allowed keys must be strings")
    total = 0

    def visit(item: object, *, depth: int, path: str) -> None:
        nonlocal total
        if depth > 8:
            raise ValueError("semantic evidence packet is too deeply nested")
        if isinstance(item, Mapping):
            if len(item) > 100:
                raise ValueError("semantic evidence packet contains too many fields")
            for key, nested in item.items():
                if (
                    not isinstance(key, str)
                    or (key not in explicit_keys and _forbidden_key(key))
                ):
                    raise ValueError("semantic evidence packet contains a forbidden field")
                total += len(key)
                visit(nested, depth=depth + 1, path=f"{path}.{key}")
            return
        if isinstance(item, Sequence) and not isinstance(item, (str, bytes, bytearray)):
            if len(item) > 100:
                raise ValueError("semantic evidence packet contains too many items")
            for index, nested in enumerate(item):
                visit(nested, depth=depth + 1, path=f"{path}[{index}]")
            return
        if isinstance(item, str):
            total += len(item)
            marker = _unsafe_marker(item)
            if marker is not None:
                raise ValueError(
                    "semantic evidence packet contains a direct identifier "
                    f"({marker}) at {path}"
                )
        elif item is None or isinstance(item, (bool, int)):
            pass
        elif isinstance(item, float):
            if not math.isfinite(item):
                raise ValueError("semantic evidence packet contains a non-finite number")
        else:
            raise ValueError("semantic evidence packet contains an unsupported value")
        if total > max_total_chars:
            raise ValueError("semantic evidence packet exceeds the character ceiling")

    visit(value, depth=0, path="root")
