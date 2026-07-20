"""Deterministic, auditable cross-source identity resolution.

Only exact normalized email and bilateral applicant-provided profile identifiers
can merge people automatically. Names, teams, and affiliations are review hints.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
import json
from pathlib import Path
import re
import sqlite3
import unicodedata
from urllib.parse import urlparse


PROFILE_TYPES = ("github", "linkedin")
VALID_DECISIONS = {
    "linked", "kept_separate", "quarantined", "merged_with_email_mismatch"
}


def normalize_email(value: str | None) -> str | None:
    """Normalize without provider-specific dot or plus-address rewriting."""
    if value is None:
        return None
    normalized = unicodedata.normalize("NFKC", value).strip().casefold()
    return normalized or None


def canonicalize_github(value: str | None) -> str | None:
    if value is None:
        return None
    candidate = unicodedata.normalize("NFKC", value).strip()
    if not candidate:
        return None
    if "://" in candidate:
        parsed = urlparse(candidate)
        if parsed.hostname and parsed.hostname.casefold() not in {"github.com", "www.github.com"}:
            return None
        candidate = parsed.path.strip("/").split("/", 1)[0]
    candidate = candidate.lstrip("@").strip("/").casefold()
    return candidate if re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,38})", candidate) else None


def canonicalize_linkedin(value: str | None) -> str | None:
    if value is None:
        return None
    candidate = unicodedata.normalize("NFKC", value).strip()
    if not candidate:
        return None
    parsed = urlparse(candidate if "://" in candidate else f"https://{candidate}")
    hostname = (parsed.hostname or "").casefold()
    if hostname != "linkedin.com" and not hostname.endswith(".linkedin.com"):
        return None
    segments = [segment for segment in parsed.path.split("/") if segment]
    try:
        marker = next(index for index, segment in enumerate(segments) if segment.casefold() == "in")
        slug = segments[marker + 1]
    except (StopIteration, IndexError):
        return None
    slug = unicodedata.normalize("NFKC", slug).strip().casefold()
    return slug if re.fullmatch(r"[\w%.-]+", slug) else None


@dataclass(frozen=True)
class IdentityRecord:
    source_type: str
    external_record_id: str
    email: str | None = None
    github: str | None = None
    linkedin: str | None = None
    applicant_provided: tuple[str, ...] = ()
    name: str | None = None
    team: str | None = None
    affiliation: str | None = None
    source_record_id: int | None = None


@dataclass(frozen=True)
class PersonCandidate:
    person_id: int
    records: tuple[IdentityRecord, ...]


@dataclass(frozen=True)
class IdentityEvidence:
    evidence_type: str
    normalized_value: str
    source_type: str
    external_record_id: str
    applicant_provided: bool


@dataclass(frozen=True)
class Resolution:
    source_type: str
    external_record_id: str
    action: str
    person_id: int | None
    decision: str | None
    reason_code: str
    suggested_person_ids: tuple[int, ...] = ()
    evidence: tuple[IdentityEvidence, ...] = ()


def _normalized(record: IdentityRecord, identity_type: str) -> str | None:
    function = {
        "email": normalize_email,
        "github": canonicalize_github,
        "linkedin": canonicalize_linkedin,
    }[identity_type]
    return function(getattr(record, identity_type))


def _evidence(record: IdentityRecord) -> tuple[IdentityEvidence, ...]:
    values = []
    for identity_type in ("email", *PROFILE_TYPES):
        normalized = _normalized(record, identity_type)
        if normalized:
            values.append(IdentityEvidence(
                identity_type, normalized, record.source_type,
                record.external_record_id, identity_type in record.applicant_provided,
            ))
    return tuple(values)


def _weakly_matches(left: IdentityRecord, right: IdentityRecord) -> bool:
    name_left = unicodedata.normalize("NFKC", left.name or "").strip().casefold()
    name_right = unicodedata.normalize("NFKC", right.name or "").strip().casefold()
    if not name_left or name_left != name_right:
        return False
    return any(
        unicodedata.normalize("NFKC", a or "").strip().casefold()
        and unicodedata.normalize("NFKC", a or "").strip().casefold()
        == unicodedata.normalize("NFKC", b or "").strip().casefold()
        for a, b in ((left.team, right.team), (left.affiliation, right.affiliation))
    )


def resolve_identity(
    incoming: IdentityRecord,
    candidates: Iterable[PersonCandidate],
    *,
    aliases: Mapping[tuple[str, str], int] | None = None,
) -> Resolution:
    """Resolve one record using the conservative evidence ladder."""
    candidates = tuple(sorted(candidates, key=lambda item: item.person_id))
    evidence = _evidence(incoming)
    alias_person = (aliases or {}).get((incoming.source_type, incoming.external_record_id))
    email = _normalized(incoming, "email")
    strong: set[int] = set()
    matched_profiles: set[int] = set()
    one_sided: set[int] = set()

    for candidate in candidates:
        for existing in candidate.records:
            if email and email == _normalized(existing, "email"):
                strong.add(candidate.person_id)
            for profile_type in PROFILE_TYPES:
                profile = _normalized(incoming, profile_type)
                if not profile or profile != _normalized(existing, profile_type):
                    continue
                if (
                    profile_type in incoming.applicant_provided
                    and profile_type in existing.applicant_provided
                ):
                    strong.add(candidate.person_id)
                    matched_profiles.add(candidate.person_id)
                else:
                    one_sided.add(candidate.person_id)

    if alias_person is not None:
        strong.add(alias_person)
    if len(strong) > 1:
        return Resolution(
            incoming.source_type, incoming.external_record_id, "quarantine", None,
            "quarantined", "STRONG_IDENTIFIER_CONFLICT", tuple(sorted(strong)), evidence,
        )
    if strong:
        person_id = next(iter(strong))
        decision = "linked"
        reason = "EXACT_EMAIL"
        if alias_person == person_id:
            reason = "EXPLICIT_SOURCE_RECORD_ALIAS"
        elif person_id in matched_profiles:
            candidate = next((item for item in candidates if item.person_id == person_id), None)
            existing_emails = {
                _normalized(item, "email") for item in (candidate.records if candidate else ())
            } - {None}
            if email and existing_emails and email not in existing_emails:
                decision = "merged_with_email_mismatch"
                reason = "BILATERAL_APPLICANT_PROFILE_EMAIL_MISMATCH"
            else:
                reason = "BILATERAL_APPLICANT_PROFILE"
        return Resolution(
            incoming.source_type, incoming.external_record_id, "merge", person_id,
            decision, reason, evidence=evidence,
        )

    weak = set(one_sided)
    for candidate in candidates:
        if any(_weakly_matches(incoming, item) for item in candidate.records):
            weak.add(candidate.person_id)
    if weak:
        reason = "PROFILE_EVIDENCE_NOT_BILATERAL" if one_sided else "WEAK_NAME_CONTEXT_MATCH"
        return Resolution(
            incoming.source_type, incoming.external_record_id, "review", None, None,
            reason, tuple(sorted(weak)), evidence,
        )
    return Resolution(
        incoming.source_type, incoming.external_record_id, "new", None, None,
        "NO_STRONG_MATCH", evidence=evidence,
    )


def load_source_aliases(path: str | Path) -> dict[tuple[str, str], int]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if set(payload) != {"aliases"} or not isinstance(payload["aliases"], list):
        raise ValueError("alias file must contain only an 'aliases' list")
    aliases: dict[tuple[str, str], int] = {}
    for entry in payload["aliases"]:
        if not isinstance(entry, dict) or set(entry) != {
            "source_type", "external_record_id", "person_id", "reason"
        }:
            raise ValueError("invalid source-record alias")
        key = (entry["source_type"], entry["external_record_id"])
        if key in aliases or not isinstance(entry["person_id"], int) or entry["person_id"] <= 0:
            raise ValueError("duplicate or invalid source-record alias")
        aliases[key] = entry["person_id"]
    return aliases


def deterministic_review_report(resolutions: Iterable[Resolution]) -> str:
    """Return stable, PII-minimized JSON for human review."""
    candidates = sorted(
        (item for item in resolutions if item.action in {"review", "quarantine"}),
        key=lambda item: (item.source_type, item.external_record_id, item.reason_code),
    )
    rows = [
        {
            "candidate_ref": f"candidate-{index:04d}",
            "source_type": item.source_type,
            "reason_code": item.reason_code,
            "suggested_person_ids": list(item.suggested_person_ids),
        }
        for index, item in enumerate(candidates, start=1)
    ]
    return json.dumps(rows, ensure_ascii=False, separators=(",", ":"))


def _valid_timestamp(value: object) -> bool:
    if not isinstance(value, str) or not value.strip():
        return False
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return True


def apply_identity_decisions(
    connection: sqlite3.Connection,
    decisions: Sequence[Mapping[str, object]],
) -> list[int]:
    """Validate and append decisions; exact replay returns existing row IDs."""
    required = {"source_record_id", "person_id", "decision", "reviewer", "reason", "decided_at"}
    optional = {"supersedes_decision_id"}
    validated: list[dict[str, object]] = []
    for decision in decisions:
        if not isinstance(decision, Mapping) or not required <= set(decision) or set(decision) - required - optional:
            raise ValueError("identity decision has missing or unknown fields")
        if decision["decision"] not in VALID_DECISIONS:
            raise ValueError("invalid identity decision")
        if not isinstance(decision["source_record_id"], int) or decision["source_record_id"] <= 0:
            raise ValueError("source_record_id must be a positive integer")
        if decision["person_id"] is not None and (
            not isinstance(decision["person_id"], int) or decision["person_id"] <= 0
        ):
            raise ValueError("person_id must be null or a positive integer")
        if decision["decision"] in {"linked", "kept_separate", "merged_with_email_mismatch"}:
            if decision["person_id"] is None:
                raise ValueError(f"{decision['decision']} requires person_id")
        elif decision["decision"] == "quarantined" and decision["person_id"] is not None:
            raise ValueError("quarantined decisions must not select a person")
        if not all(isinstance(decision[key], str) and decision[key].strip() for key in ("reviewer", "reason")):
            raise ValueError("reviewer and reason are required")
        if not _valid_timestamp(decision["decided_at"]):
            raise ValueError("decided_at must be an ISO-8601 timestamp")
        supersedes = decision.get("supersedes_decision_id")
        if supersedes is not None and (not isinstance(supersedes, int) or supersedes <= 0):
            raise ValueError("supersedes_decision_id must be a positive integer")
        validated.append(dict(decision))

    inserted: list[int] = []
    with connection:
        for item in validated:
            supersedes = item.get("supersedes_decision_id")
            existing = connection.execute(
                """SELECT existing.id FROM identity_decision existing WHERE source_record_id=?
                   AND person_id IS ? AND decision=? AND reviewer=? AND reason=?
                   AND decided_at=? AND supersedes_decision_id IS ?
                   AND NOT EXISTS (
                       SELECT 1 FROM identity_decision newer
                       WHERE newer.supersedes_decision_id=existing.id
                   )""",
                (
                    item["source_record_id"], item["person_id"], item["decision"],
                    item["reviewer"], item["reason"], item["decided_at"], supersedes,
                ),
            ).fetchone()
            if existing:
                inserted.append(existing[0])
                connection.execute(
                    """UPDATE identity_review SET status='resolved', resolved_at=?
                       WHERE source_record_id=? AND status='open'""",
                    (item["decided_at"], item["source_record_id"]),
                )
                continue
            current = connection.execute(
                """SELECT current.id FROM identity_decision current
                   WHERE current.source_record_id=?
                     AND NOT EXISTS (
                         SELECT 1 FROM identity_decision newer
                         WHERE newer.supersedes_decision_id=current.id
                     )""",
                (item["source_record_id"],),
            ).fetchone()
            if current is not None and supersedes != current[0]:
                raise ValueError("new decision must explicitly supersede the current decision")
            if current is None and supersedes is not None:
                raise ValueError("superseded decision must be the current decision for this source record")
            row_id = connection.execute(
                """INSERT INTO identity_decision(
                       source_record_id,person_id,decision,reviewer,reason,decided_at,
                       supersedes_decision_id
                   ) VALUES(?,?,?,?,?,?,?)""",
                (
                    item["source_record_id"], item["person_id"], item["decision"],
                    item["reviewer"].strip(), item["reason"].strip(),
                    item["decided_at"], supersedes,
                ),
            ).lastrowid
            inserted.append(row_id)
            connection.execute(
                """UPDATE identity_review SET status='resolved', resolved_at=?
                   WHERE source_record_id=? AND status='open'""",
                (item["decided_at"], item["source_record_id"]),
            )
    return inserted


def persist_resolution(
    connection: sqlite3.Connection,
    incoming: IdentityRecord,
    resolution: Resolution,
    *,
    reviewer: str,
    decided_at: str,
) -> int:
    """Persist a merge with source-linked identities, evidence, and audit decision."""
    if incoming.source_record_id is None:
        raise ValueError("source_record_id is required for persistence")
    if resolution.action != "merge" or resolution.person_id is None or resolution.decision is None:
        raise ValueError("persist_resolution accepts completed merge resolutions only")
    source = connection.execute(
        "SELECT mapping_version, observed_at FROM source_record WHERE id = ?",
        (incoming.source_record_id,),
    ).fetchone()
    if source is None:
        raise ValueError("source record does not exist")
    mapping_version, observed_at = source
    with connection:
        for evidence in resolution.evidence:
            display_value = getattr(incoming, evidence.evidence_type)
            identity = connection.execute(
                """SELECT id FROM person_identity
                   WHERE person_id=? AND identity_type=? AND normalized_value=?""",
                (resolution.person_id, evidence.evidence_type, evidence.normalized_value),
            ).fetchone()
            if identity is None:
                identity_id = connection.execute(
                    """INSERT INTO person_identity(
                           person_id,source_record_id,identity_type,display_value,
                           normalized_value,verified,applicant_provided,observed_at
                       ) VALUES(?,?,?,?,?,0,?,?)""",
                    (
                        resolution.person_id, incoming.source_record_id,
                        evidence.evidence_type, display_value, evidence.normalized_value,
                        int(evidence.applicant_provided), observed_at,
                    ),
                ).lastrowid
            else:
                identity_id = identity[0]
            exists = connection.execute(
                """SELECT 1 FROM identity_evidence WHERE source_record_id=?
                   AND person_id=? AND evidence_type=? AND normalized_value=?""",
                (
                    incoming.source_record_id, resolution.person_id,
                    evidence.evidence_type, evidence.normalized_value,
                ),
            ).fetchone()
            if not exists:
                connection.execute(
                    """INSERT INTO identity_evidence(
                           source_record_id,person_id,person_identity_id,evidence_type,
                           normalized_value,applicant_provided,mapping_version,observed_at
                       ) VALUES(?,?,?,?,?,?,?,?)""",
                    (
                        incoming.source_record_id, resolution.person_id, identity_id,
                        evidence.evidence_type, evidence.normalized_value,
                        int(evidence.applicant_provided), mapping_version, observed_at,
                    ),
                )
        apply_identity_decisions(connection, [{
            "source_record_id": incoming.source_record_id,
            "person_id": resolution.person_id,
            "decision": resolution.decision,
            "reviewer": reviewer,
            "reason": resolution.reason_code,
            "decided_at": decided_at,
        }])
    return resolution.person_id


def unresolved_identity_candidates(
    connection: sqlite3.Connection, event_id: int
) -> list[dict[str, object]]:
    """Return open candidates that can affect an event's partner aggregates."""
    rows = connection.execute(
        """SELECT ir.id, ir.source_record_id, ir.provisional_person_id,
                  ir.suggested_person_id, ir.reason_code
           FROM identity_review ir
           JOIN source_record sr ON sr.id = ir.source_record_id
           JOIN source_file sf ON sf.id = sr.source_file_id
           WHERE ir.status = 'open' AND sf.event_id = ?
           ORDER BY ir.source_record_id, ir.id""",
        (event_id,),
    ).fetchall()
    keys = ("review_id", "source_record_id", "provisional_person_id", "suggested_person_id", "reason_code")
    return [dict(zip(keys, tuple(row), strict=True)) for row in rows]
