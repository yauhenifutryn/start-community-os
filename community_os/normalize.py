"""Normalize mapped source records into append-only canonical assertions."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import json
import sqlite3
from typing import Mapping

from community_os.identity import (
    IdentityRecord,
    PersonCandidate,
    canonicalize_github,
    canonicalize_linkedin,
    normalize_email,
    resolve_identity,
)
from community_os.ingest.base import MappedRecord


@dataclass(frozen=True)
class NormalizedRecord:
    person_id: int
    application_id: int | None = None
    participation_id: int | None = None
    team_id: int | None = None
    submission_id: int | None = None


class GhostIdentityMatch(ValueError):
    """Raised when a returning ghost needs explicit reactivation, not auto-linking."""

    def __init__(self, person_id: int):
        super().__init__("ghost identity requires explicit reactivation")
        self.person_id = person_id


def _status(value: str) -> str:
    return {
        "approved": "accepted", "accepted": "accepted", "declined": "declined",
        "rejected": "declined", "waitlist": "waitlist", "waitlisted": "waitlist",
    }.get(value.strip().casefold(), "applied")


def _truth(value: str) -> bool:
    return value.strip().casefold() in {"yes", "true", "1", "approved", "checked in"}


def _candidates(connection: sqlite3.Connection) -> tuple[PersonCandidate, ...]:
    rows = connection.execute(
        """SELECT p.id,sf.source_type,sr.external_record_id,pi.identity_type,
                  pi.display_value,pi.applicant_provided
           FROM person p LEFT JOIN person_identity pi ON pi.person_id=p.id
           LEFT JOIN source_record sr ON sr.id=pi.source_record_id
           LEFT JOIN source_file sf ON sf.id=sr.source_file_id ORDER BY p.id,pi.id"""
    ).fetchall()
    grouped: dict[int, dict[tuple[str, str], dict[str, object]]] = {}
    for row in rows:
        grouped.setdefault(row[0], {})
        if row[2] is None:
            continue
        item = grouped[row[0]].setdefault((row[1], row[2]), {
            "source_type": row[1], "external_record_id": row[2], "applicant_provided": [],
        })
        item[row[3]] = row[4]
        if row[5]:
            item["applicant_provided"].append(row[3])
    return tuple(
        PersonCandidate(person_id, tuple(IdentityRecord(**{**item, "applicant_provided": tuple(item["applicant_provided"])}) for item in records.values()))
        for person_id, records in grouped.items()
    )


def _append_fact(
    connection: sqlite3.Connection, *, subject_table: str, subject_id: int,
    field_name: str, value: object, source_record_id: int, mapping_version: str,
    authority: str, observed_at: str, pii_class: str = "non_pii",
) -> int:
    prior = connection.execute(
        """SELECT old.id FROM fact_assertion old
           WHERE old.subject_table=? AND old.subject_id=? AND old.field_name=?
             AND NOT EXISTS(SELECT 1 FROM fact_assertion newer WHERE newer.supersedes_assertion_id=old.id)
           ORDER BY old.id DESC LIMIT 1""",
        (subject_table, subject_id, field_name),
    ).fetchone()
    assertion_id = connection.execute(
        """INSERT INTO fact_assertion(subject_table,subject_id,field_name,source_record_id,
               mapping_version,authority,observed_at,supersedes_assertion_id)
           VALUES(?,?,?,?,?,?,?,?)""",
        (subject_table, subject_id, field_name, source_record_id, mapping_version,
         authority, observed_at, prior[0] if prior else None),
    ).lastrowid
    connection.execute(
        "INSERT INTO fact_assertion_payload(assertion_id,canonical_value_json,pii_class) VALUES(?,?,?)",
        (assertion_id, json.dumps(value, ensure_ascii=False), pii_class),
    )
    return assertion_id


def _persist_identity(
    connection: sqlite3.Connection, incoming: IdentityRecord, person_id: int,
    source_record_id: int, mapping_version: str, observed_at: str,
) -> None:
    normalizers = {"email": normalize_email, "github": canonicalize_github, "linkedin": canonicalize_linkedin}
    for identity_type, normalize in normalizers.items():
        display = getattr(incoming, identity_type)
        normalized = normalize(display)
        if not normalized:
            continue
        row = connection.execute(
            "SELECT id FROM person_identity WHERE person_id=? AND identity_type=? AND normalized_value=?",
            (person_id, identity_type, normalized),
        ).fetchone()
        if row is None:
            identity_id = connection.execute(
                """INSERT INTO person_identity(person_id,source_record_id,identity_type,display_value,
                       normalized_value,verified,applicant_provided,observed_at) VALUES(?,?,?,?,?,?,?,?)""",
                (person_id, source_record_id, identity_type, display, normalized,
                 int(identity_type == "email" and identity_type in incoming.applicant_provided),
                 int(identity_type in incoming.applicant_provided), observed_at),
            ).lastrowid
        else:
            identity_id = row[0]
        connection.execute(
            """INSERT INTO identity_evidence(source_record_id,person_id,person_identity_id,evidence_type,
                   normalized_value,applicant_provided,mapping_version,observed_at) VALUES(?,?,?,?,?,?,?,?)""",
            (source_record_id, person_id, identity_id, identity_type, normalized,
             int(identity_type in incoming.applicant_provided), mapping_version, observed_at),
        )


def normalize_record(
    connection: sqlite3.Connection, *, event_id: int, source_type: str,
    source_record_id: int, record: MappedRecord,
    ghost_secrets: Mapping[str, str] | None = None,
) -> NormalizedRecord:
    """Write one mapped record. The caller owns the transaction boundary."""
    source = connection.execute(
        "SELECT mapping_version,observed_at FROM source_record WHERE id=?", (source_record_id,)
    ).fetchone()
    if source is None:
        raise ValueError("source record does not exist")
    if source_type == "luma_supplement" and not record.authority:
        raise ValueError("supplement canonical writes require explicit authority")
    values = record.values
    incoming = IdentityRecord(
        source_type, record.external_record_id, email=values.get("email") or record.applicant_identity,
        github=values.get("github"), linkedin=values.get("linkedin"),
        applicant_provided=tuple(key for key in ("email", "github", "linkedin") if values.get(key) or key == "email"),
        name=values.get("name"), team=values.get("team_name"), affiliation=values.get("organization"),
        source_record_id=source_record_id,
    )
    ghost_rows = connection.execute(
        "SELECT person_id,identity_hmac,key_version FROM hashed_identity ORDER BY id"
    ).fetchall()
    if ghost_rows:
        if not ghost_secrets or any(row[2] not in ghost_secrets for row in ghost_rows):
            raise ValueError("all ghost identity key versions must be configured before ingestion")
        normalized_email = normalize_email(incoming.email)
        if normalized_email:
            for ghost_person_id, identity_hmac, key_version in ghost_rows:
                candidate = hmac.new(
                    ghost_secrets[key_version].encode(), normalized_email.encode(), hashlib.sha256
                ).hexdigest()
                if hmac.compare_digest(candidate, identity_hmac):
                    raise GhostIdentityMatch(ghost_person_id)
    resolution = resolve_identity(incoming, _candidates(connection))
    if resolution.action == "merge":
        person_id = resolution.person_id
    else:
        person_id = connection.execute("INSERT INTO person DEFAULT VALUES").lastrowid
        if resolution.action in {"review", "quarantine"}:
            connection.execute("UPDATE source_record SET quarantined=? WHERE id=?", (int(resolution.action == "quarantine"), source_record_id))
            for suggested in resolution.suggested_person_ids or (None,):
                connection.execute(
                    """INSERT INTO identity_review(source_record_id,provisional_person_id,suggested_person_id,
                           reason_code,evidence_json) VALUES(?,?,?,?,?)""",
                    (source_record_id, person_id, suggested, resolution.reason_code, "{}"),
                )
    assert person_id is not None
    _persist_identity(connection, incoming, person_id, source_record_id, source[0], source[1])
    if resolution.action in {"merge", "new", "quarantine"}:
        connection.execute(
            """INSERT INTO identity_decision(source_record_id,person_id,decision,reviewer,reason,decided_at)
               VALUES(?,?,?,?,?,?)""",
            (
                source_record_id,
                None if resolution.action == "quarantine" else person_id,
                resolution.decision or ("quarantined" if resolution.action == "quarantine" else "kept_separate"),
                "pipeline:normalize-v1",
                resolution.reason_code,
                source[1],
            ),
        )

    authority = record.authority or source_type
    application_id = participation_id = team_id = submission_id = None
    if source_type in {"luma_guests", "luma_supplement", "devpost_registrants"}:
        application = connection.execute(
            "SELECT id FROM application WHERE event_id=? AND person_id=? ORDER BY id LIMIT 1",
            (event_id, person_id),
        ).fetchone()
        status = _status(values.get("approval_status", ""))
        answers = {
            "impressive_thing": (
                {"state": "question_not_present"} if "impressive_thing" not in values
                else {"state": "empty"} if not values["impressive_thing"]
                else {"state": "answered", "value": values["impressive_thing"]}
            )
        }
        if application is None and source_type != "luma_supplement":
            application_id = connection.execute(
                """INSERT INTO application(person_id,event_id,source_record_id,status,raw_answers_json,applied_at)
                   VALUES(?,?,?,?,?,?)""",
                (person_id, event_id, source_record_id, status, json.dumps(answers),
                 values.get("created_at") or values.get("registered_at") or source[1]),
            ).lastrowid
        elif application is not None:
            application_id = application[0]
        if application_id is not None:
            if source_type == "luma_supplement":
                connection.execute("UPDATE application SET status=? WHERE id=?", (status, application_id))
            else:
                connection.execute(
                    "UPDATE application SET status=?,raw_answers_json=? WHERE id=?",
                    (status, json.dumps(answers), application_id),
                )
            _append_fact(connection, subject_table="application", subject_id=application_id,
                         field_name="status", value=status, source_record_id=source_record_id,
                         mapping_version=source[0], authority=authority, observed_at=source[1])
            if source_type != "luma_supplement":
                _append_fact(connection, subject_table="application", subject_id=application_id,
                             field_name="raw_answers_json", value=answers,
                             source_record_id=source_record_id, mapping_version=source[0],
                             authority=authority, observed_at=source[1], pii_class="free_text")

        team_name = values.get("team_name", "").strip()
        if team_name:
            team = connection.execute(
                "SELECT id FROM team WHERE event_id=? AND canonical_name=? ORDER BY id LIMIT 1",
                (event_id, team_name),
            ).fetchone()
            team_id = team[0] if team else connection.execute(
                "INSERT INTO team(event_id,source_record_id,canonical_name) VALUES(?,?,?)",
                (event_id, source_record_id, team_name),
            ).lastrowid
            _append_fact(connection, subject_table="team", subject_id=team_id, field_name="canonical_name",
                         value=team_name, source_record_id=source_record_id, mapping_version=source[0],
                         authority=authority, observed_at=source[1], pii_class="free_text")

        participation = connection.execute(
            "SELECT id FROM participation WHERE event_id=? AND person_id=? ORDER BY id LIMIT 1",
            (event_id, person_id),
        ).fetchone()
        checked_at = values.get("checked_in_at", "").strip() or None
        if participation is None and source_type != "luma_supplement":
            participation_id = connection.execute(
                """INSERT INTO participation(person_id,event_id,source_record_id,checked_in,checked_in_at,team_id)
                   VALUES(?,?,?,?,?,?)""",
                (person_id, event_id, source_record_id, int(bool(checked_at)), checked_at, team_id),
            ).lastrowid
        elif participation is not None:
            participation_id = participation[0]
        if participation_id is not None:
            connection.execute(
                "UPDATE participation SET checked_in=?,checked_in_at=? WHERE id=?",
                (int(bool(checked_at)), checked_at, participation_id),
            )
            for field, value in (("checked_in", bool(checked_at)), ("checked_in_at", checked_at)):
                _append_fact(connection, subject_table="participation", subject_id=participation_id,
                             field_name=field, value=value, source_record_id=source_record_id,
                             mapping_version=source[0], authority=authority, observed_at=source[1])

        consent_specs = {
            "processing_consent": ("event_operations", "start_warsaw"),
            "openai_sharing_consent": ("program_sharing", "openai"),
            "partner_sharing_consent": ("partner_recruitment", "case_partners"),
            "image_consent": ("event_media", "public"),
            "newsletter_consent": ("newsletter", "start_warsaw"),
        }
        for field, (purpose, scope) in consent_specs.items():
            if field not in values:
                continue
            prior = connection.execute(
                """SELECT old.id FROM consent_assertion old
                   WHERE old.person_id=? AND old.event_id=? AND old.purpose=? AND old.recipient_scope=?
                     AND NOT EXISTS(
                         SELECT 1 FROM consent_assertion newer
                         WHERE newer.supersedes_assertion_id=old.id
                     ) ORDER BY old.id DESC LIMIT 1""",
                (person_id, event_id, purpose, scope),
            ).fetchone()
            connection.execute(
                """INSERT INTO consent_assertion(person_id,event_id,source_record_id,purpose,
                       recipient_scope,granted,source_text,source_version,observed_at,evidence_source,
                       supersedes_assertion_id) VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                (person_id, event_id, source_record_id, purpose, scope, int(_truth(values[field])),
                 values[field], source[0], source[1], source_type, prior[0] if prior else None),
            )

    return NormalizedRecord(person_id, application_id, participation_id, team_id, submission_id)
