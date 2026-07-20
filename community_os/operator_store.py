"""Durable canonical storage used by the local Talent Data Room operator."""

from __future__ import annotations

from dataclasses import dataclass
import json
import re
import sqlite3
from typing import Iterable, Mapping

from community_os.identity import (
    IdentityRecord, PersonCandidate, apply_identity_decisions,
    canonicalize_github, canonicalize_linkedin, normalize_email,
    resolve_identity,
)


@dataclass(frozen=True)
class FinalRecord:
    external_id: str
    payload: Mapping[str, object]
    email: str
    name: str
    github: str | None = None
    linkedin: str | None = None
    checked_in_at: str | None = None
    team_name: str | None = None
    track: str | None = None
    submission_title: str | None = None
    repository_present: bool = False
    demo_present: bool = False


@dataclass(frozen=True)
class DurableIngestSummary:
    source_file_id: int
    digest: str
    records: int
    skipped: bool = False


def ensure_event(connection: sqlite3.Connection) -> int:
    row = connection.execute(
        "SELECT id FROM event WHERE event_key='openai-hackathon-2026'"
    ).fetchone()
    if row:
        return int(row[0])
    with connection:
        return int(connection.execute(
            """INSERT INTO event(event_key,name,starts_at,event_type)
               VALUES('openai-hackathon-2026','OpenAI Hackathon','2026-07-11','hackathon')"""
        ).lastrowid)


def source_file_row_count(
    connection: sqlite3.Connection, source_file_id: int, source_type: str
) -> int:
    if source_type == "luma_final":
        return int(connection.execute(
            "SELECT COUNT(*) FROM source_record WHERE source_file_id=?",
            (source_file_id,),
        ).fetchone()[0])
    return int(connection.execute(
        "SELECT COUNT(DISTINCT raw_payload_json) FROM source_record WHERE source_file_id=?",
        (source_file_id,),
    ).fetchone()[0])


def _valid_email(value: str) -> str:
    email = normalize_email(value)
    if not email or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
        raise ValueError("record requires a valid email")
    return email


def _candidates(connection: sqlite3.Connection) -> tuple[PersonCandidate, ...]:
    rows = connection.execute(
        """SELECT pi.person_id,pi.identity_type,pi.display_value,pi.applicant_provided,
                  sr.raw_payload_json
           FROM person_identity pi JOIN source_record sr ON sr.id=pi.source_record_id
           ORDER BY pi.person_id,pi.id"""
    ).fetchall()
    grouped: dict[int, dict[str, object]] = {}
    for person_id, identity_type, display_value, applicant_provided, raw_payload in rows:
        values = grouped.setdefault(int(person_id), {"applicant_provided": []})
        values.setdefault(str(identity_type), str(display_value))
        payload = json.loads(raw_payload or "{}")
        values.setdefault("name", payload.get("name") or payload.get("Member names"))
        values.setdefault(
            "team",
            payload.get("Team name (if applying with a team)") or payload.get("Team name"),
        )
        if applicant_provided:
            values["applicant_provided"].append(str(identity_type))
    return tuple(
        PersonCandidate(person_id, (IdentityRecord(
            "canonical", f"person-{person_id}",
            email=values.get("email"), github=values.get("github"),
            linkedin=values.get("linkedin"),
            applicant_provided=tuple(values["applicant_provided"]),
            name=values.get("name"), team=values.get("team"),
        ),))
        for person_id, values in sorted(grouped.items())
    )


def _create_person_with_evidence(
    connection: sqlite3.Connection, source_record_id: int, record: FinalRecord,
    *, mapping_version: str, observed_at: str,
) -> int:
    person_id = int(connection.execute("INSERT INTO person DEFAULT VALUES").lastrowid)
    values = (
        ("email", record.email, _valid_email(record.email)),
        ("github", record.github, canonicalize_github(record.github)),
        ("linkedin", record.linkedin, canonicalize_linkedin(record.linkedin)),
    )
    for identity_type, display_value, normalized in values:
        if not display_value or not normalized:
            continue
        identity_id = int(connection.execute(
            """INSERT INTO person_identity(
                   person_id,source_record_id,identity_type,display_value,normalized_value,
                   verified,applicant_provided,observed_at
               ) VALUES(?,?,?,?,?,?,1,?)""",
            (person_id, source_record_id, identity_type, str(display_value).strip(), normalized,
             int(identity_type == "email"), observed_at),
        ).lastrowid)
        connection.execute(
            """INSERT INTO identity_evidence(
                   source_record_id,person_id,person_identity_id,evidence_type,
                   normalized_value,applicant_provided,mapping_version,observed_at
               ) VALUES(?,?,?,?,?,1,?,?)""",
            (source_record_id, person_id, identity_id, identity_type, normalized,
             mapping_version, observed_at),
        )
    return person_id


def _resolve_person(
    connection: sqlite3.Connection, source_record_id: int, source_type: str,
    record: FinalRecord, *, mapping_version: str, observed_at: str,
) -> tuple[int | None, bool, str, tuple[int, ...], str]:
    _valid_email(record.email)
    provided = tuple(
        identity_type for identity_type, value in
        (("email", record.email), ("github", record.github), ("linkedin", record.linkedin))
        if value
    )
    incoming = IdentityRecord(
        source_type, record.external_id, email=record.email, github=record.github,
        linkedin=record.linkedin, applicant_provided=provided, name=record.name,
        team=record.team_name, source_record_id=source_record_id,
    )
    resolution = resolve_identity(incoming, _candidates(connection))
    if resolution.action == "merge":
        person_id = int(resolution.person_id)
        for evidence in resolution.evidence:
            display_value = getattr(incoming, evidence.evidence_type)
            identity = connection.execute(
                """SELECT id FROM person_identity
                   WHERE person_id=? AND identity_type=? AND normalized_value=?""",
                (person_id, evidence.evidence_type, evidence.normalized_value),
            ).fetchone()
            if identity is None:
                identity_id = int(connection.execute(
                    """INSERT INTO person_identity(
                           person_id,source_record_id,identity_type,display_value,
                           normalized_value,verified,applicant_provided,observed_at
                       ) VALUES(?,?,?,?,?,?,?,?)""",
                    (person_id, source_record_id, evidence.evidence_type, display_value,
                     evidence.normalized_value, int(evidence.evidence_type == "email"),
                     int(evidence.applicant_provided), observed_at),
                ).lastrowid)
            else:
                identity_id = int(identity[0])
            connection.execute(
                """INSERT INTO identity_evidence(
                       source_record_id,person_id,person_identity_id,evidence_type,
                       normalized_value,applicant_provided,mapping_version,observed_at
                   ) VALUES(?,?,?,?,?,?,?,?)""",
                (source_record_id, person_id, identity_id, evidence.evidence_type,
                 evidence.normalized_value, int(evidence.applicant_provided),
                 mapping_version, observed_at),
            )
        connection.execute(
            """INSERT INTO identity_decision(
                   source_record_id,person_id,decision,reviewer,reason,decided_at
               ) VALUES(?,?,?,?,?,?)""",
            (source_record_id, person_id, resolution.decision,
             "pipeline:final-v1", resolution.reason_code, observed_at),
        )
        return person_id, False, resolution.reason_code, (), resolution.action
    if resolution.action == "quarantine":
        return None, False, resolution.reason_code, resolution.suggested_person_ids, resolution.action
    person_id = _create_person_with_evidence(
        connection, source_record_id, record,
        mapping_version=mapping_version, observed_at=observed_at,
    )
    return person_id, True, resolution.reason_code, resolution.suggested_person_ids, resolution.action


def _team_id(
    connection: sqlite3.Connection, *, event_id: int, source_record_id: int,
    team_name: str | None,
) -> int | None:
    if not team_name or not team_name.strip():
        return None
    canonical = team_name.strip()
    existing = connection.execute(
        "SELECT id FROM team WHERE event_id=? AND canonical_name=? ORDER BY id LIMIT 1",
        (event_id, canonical),
    ).fetchone()
    if existing:
        return int(existing[0])
    return int(connection.execute(
        "INSERT INTO team(event_id,source_record_id,canonical_name) VALUES(?,?,?)",
        (event_id, source_record_id, canonical),
    ).lastrowid)


def ingest_records(
    connection: sqlite3.Connection, *, event_id: int, source_type: str, digest: str,
    records: Iterable[FinalRecord], observed_at: str,
) -> DurableIngestSummary:
    """Persist one validated source file atomically; exact hash replay is a no-op."""
    existing = connection.execute(
        """SELECT id FROM source_file
           WHERE event_id=? AND source_type=? AND file_sha256=?""",
        (event_id, source_type, digest),
    ).fetchone()
    if existing:
        return DurableIngestSummary(int(existing[0]), digest, 0, True)
    materialized = tuple(records)
    mapping_version = f"{source_type}-v1"
    connection.execute("SAVEPOINT operator_source_ingest")
    try:
        source_file_id = int(connection.execute(
            """INSERT INTO source_file(event_id,source_type,file_sha256,mapping_version,observed_at)
               VALUES(?,?,?,?,?)""",
            (event_id, source_type, digest, mapping_version, observed_at),
        ).lastrowid)
        for record in materialized:
            if not record.external_id.strip():
                raise ValueError("record requires an external id")
            source_record_id = int(connection.execute(
                """INSERT INTO source_record(
                       source_file_id,external_record_id,mapping_version,observed_at,raw_payload_json
                   ) VALUES(?,?,?,?,?)""",
                (source_file_id, record.external_id, mapping_version, observed_at,
                 json.dumps(dict(record.payload), ensure_ascii=False, sort_keys=True)),
            ).lastrowid)
            person_id, is_new, reason_code, suggested_ids, resolution_action = _resolve_person(
                connection, source_record_id, source_type, record,
                mapping_version=mapping_version, observed_at=observed_at,
            )
            if resolution_action == "quarantine":
                connection.execute(
                    "UPDATE source_record SET quarantined=1 WHERE id=?",
                    (source_record_id,),
                )
                connection.execute(
                    """INSERT INTO identity_decision(
                           source_record_id,person_id,decision,reviewer,reason,decided_at
                       ) VALUES(?,NULL,'quarantined','pipeline:final-v1',?,?)""",
                    (source_record_id, reason_code, observed_at),
                )
                continue
            assert person_id is not None
            existing_team = None
            if source_type == "devpost_final":
                existing_team = connection.execute(
                    """SELECT team_id FROM participation
                       WHERE event_id=? AND person_id=? AND team_id IS NOT NULL
                       ORDER BY id LIMIT 1""",
                    (event_id, person_id),
                ).fetchone()
            team_id = int(existing_team[0]) if existing_team else _team_id(
                connection, event_id=event_id, source_record_id=source_record_id,
                team_name=record.team_name,
            )
            if source_type == "luma_final":
                raw_status = str(record.payload.get("approval_status", record.payload.get("status", "applied"))).casefold()
                status = {"approved": "accepted", "accepted": "accepted", "declined": "declined", "waitlist": "waitlist"}.get(raw_status, "applied")
                connection.execute(
                    """INSERT INTO application(
                           person_id,event_id,source_record_id,status,raw_answers_json,applied_at
                       ) VALUES(?,?,?,?,?,?)""",
                    (person_id, event_id, source_record_id, status,
                     json.dumps(dict(record.payload), ensure_ascii=False, sort_keys=True), observed_at),
                )
                connection.execute(
                    """INSERT INTO participation(
                           person_id,event_id,source_record_id,checked_in,checked_in_at,team_id
                       ) VALUES(?,?,?,?,?,?)""",
                    (person_id, event_id, source_record_id, int(bool(record.checked_in_at)),
                     record.checked_in_at, team_id),
                )
            elif source_type == "track_preferences_final":
                connection.execute(
                    """INSERT INTO participation(
                           person_id,event_id,source_record_id,checked_in,team_id
                       ) VALUES(?,?,?,0,?)""",
                    (person_id, event_id, source_record_id, team_id),
                )
            elif source_type == "devpost_final":
                submission = None
                if record.submission_title:
                    submission = connection.execute(
                        "SELECT id FROM submission WHERE event_id=? AND title=? ORDER BY id LIMIT 1",
                        (event_id, record.submission_title),
                    ).fetchone()
                if submission is None:
                    submission_id = int(connection.execute(
                        """INSERT INTO submission(
                               event_id,team_id,source_record_id,title,built_with_json,links_json,submitted_at
                           ) VALUES(?,?,?,?,?,?,?)""",
                        (event_id, team_id, source_record_id, record.submission_title,
                         json.dumps(record.payload.get("built_with", [])),
                         json.dumps({"repository_present": record.repository_present,
                                     "demo_present": record.demo_present}), observed_at),
                    ).lastrowid)
                else:
                    submission_id = int(submission[0])
                connection.execute(
                    """INSERT INTO participation(
                           person_id,event_id,source_record_id,checked_in,team_id,submission_id
                       ) VALUES(?,?,?,0,?,?)""",
                    (person_id, event_id, source_record_id, team_id, submission_id),
                )
            else:
                raise ValueError("unsupported final source type")
            if source_type != "luma_final" and is_new:
                connection.execute(
                    """INSERT INTO identity_review(
                           source_record_id,provisional_person_id,suggested_person_id,
                           reason_code,evidence_json
                       ) VALUES(?,?,?,?,?)""",
                    (source_record_id, person_id,
                     suggested_ids[0] if suggested_ids else None,
                     reason_code if reason_code != "NO_STRONG_MATCH" else "NO_LUMA_EXACT_EMAIL",
                     json.dumps({"source_type": source_type, "candidate_name": record.name,
                                 "candidate_email": _mask_email(record.email)}, sort_keys=True)),
                )
    except Exception:
        connection.execute("ROLLBACK TO operator_source_ingest")
        connection.execute("RELEASE operator_source_ingest")
        raise
    else:
        connection.execute("RELEASE operator_source_ingest")
    return DurableIngestSummary(source_file_id, digest, len(materialized))


def list_open_reviews(connection: sqlite3.Connection, event_id: int) -> list[dict[str, object]]:
    rows = connection.execute(
        """SELECT ir.id,ir.source_record_id,ir.provisional_person_id,ir.suggested_person_id,
                  ir.reason_code,sf.source_type,ir.evidence_json
           FROM identity_review ir
           JOIN source_record sr ON sr.id=ir.source_record_id
           JOIN source_file sf ON sf.id=sr.source_file_id
           WHERE ir.status='open' AND sf.event_id=? ORDER BY ir.id""",
        (event_id,),
    ).fetchall()
    keys = ("review_id", "source_record_id", "provisional_person_id", "suggested_person_id", "reason_code", "source_type", "evidence_json")
    results = []
    for row in rows:
        item = dict(zip(keys, tuple(row), strict=True))
        evidence = json.loads(str(item.pop("evidence_json") or "{}"))
        item["candidate_name"] = evidence.get("candidate_name") or "Unknown"
        item["candidate_email"] = evidence.get("candidate_email") or "Unavailable"
        suggested = item["suggested_person_id"]
        if suggested is not None:
            suggested_email = connection.execute(
                """SELECT display_value FROM person_identity
                   WHERE person_id=? AND identity_type='email' ORDER BY id LIMIT 1""",
                (suggested,),
            ).fetchone()
            item["suggested_email"] = _mask_email(str(suggested_email[0])) if suggested_email else "Unavailable"
        else:
            item["suggested_email"] = None
        results.append(item)
    return results


def decide_review(
    connection: sqlite3.Connection, *, review_id: int, decision: str,
    reviewer: str, decided_at: str,
) -> int:
    review = connection.execute(
        """SELECT source_record_id,provisional_person_id,suggested_person_id
           FROM identity_review WHERE id=? AND status='open'""",
        (review_id,),
    ).fetchone()
    if review is None:
        raise ValueError("review is not open")
    source_record_id, provisional, suggested = map(lambda value: int(value) if value is not None else None, review)
    if decision == "keep_separate":
        stored_decision, person_id = "kept_separate", provisional
    elif decision == "approve":
        if suggested is None:
            raise ValueError("approve requires a suggested identity")
        stored_decision, person_id = "linked", suggested
    elif decision == "quarantine":
        stored_decision, person_id = "quarantined", None
    else:
        raise ValueError("invalid review decision")
    decision_id = apply_identity_decisions(connection, [{
        "source_record_id": source_record_id,
        "person_id": person_id,
        "decision": stored_decision,
        "reviewer": reviewer,
        "reason": f"operator:{decision}",
        "decided_at": decided_at,
    }])[0]
    if decision == "quarantine":
        with connection:
            connection.execute("UPDATE source_record SET quarantined=1 WHERE id=?", (source_record_id,))
    return decision_id


def aggregate_facts(connection: sqlite3.Connection, event_id: int) -> dict[str, object]:
    """Derive report facts only from persisted, non-quarantined canonical state."""
    approved_rows = connection.execute(
        """SELECT a.person_id,a.source_record_id FROM application a
           JOIN source_record sr ON sr.id=a.source_record_id
           WHERE a.event_id=? AND a.status='accepted' AND sr.quarantined=0""",
        (event_id,),
    ).fetchall()
    checked_rows = connection.execute(
        """SELECT p.person_id,p.source_record_id FROM participation p
           JOIN source_record sr ON sr.id=p.source_record_id
           WHERE p.event_id=? AND p.checked_in=1 AND sr.quarantined=0""",
        (event_id,),
    ).fetchall()
    submitted_rows = connection.execute(
        """SELECT p.person_id,p.source_record_id FROM participation p
           JOIN source_record sr ON sr.id=p.source_record_id
           WHERE p.event_id=? AND p.submission_id IS NOT NULL AND sr.quarantined=0""",
        (event_id,),
    ).fetchall()
    approved_people = {_canonical_person(connection, row[0], row[1]) for row in approved_rows}
    checked_people = {_canonical_person(connection, row[0], row[1]) for row in checked_rows}
    submitted_people = {_canonical_person(connection, row[0], row[1]) for row in submitted_rows}
    team_rows_for_people = connection.execute(
        """SELECT p.person_id,p.source_record_id FROM participation p
           JOIN source_record sr ON sr.id=p.source_record_id
           WHERE p.event_id=? AND p.team_id IS NOT NULL AND sr.quarantined=0""",
        (event_id,),
    ).fetchall()
    team_people = {
        _canonical_person(connection, row[0], row[1]) for row in team_rows_for_people
    }
    teams_by_track: dict[str, dict[str, int]] = {}
    team_rows = connection.execute(
        """SELECT sr.raw_payload_json,p.team_id
           FROM participation p JOIN source_record sr ON sr.id=p.source_record_id
           JOIN source_file sf ON sf.id=sr.source_file_id
           WHERE p.event_id=? AND p.team_id IS NOT NULL
             AND sf.source_type='track_preferences_final' AND sr.quarantined=0
           GROUP BY p.team_id""",
        (event_id,),
    ).fetchall()
    for raw_payload, team_id in team_rows:
        payload = json.loads(raw_payload or "{}")
        track = normalize_track(payload.get("Track") or payload.get("track"))
        submitted_state = "submitted" if connection.execute(
            "SELECT 1 FROM submission WHERE event_id=? AND team_id=? LIMIT 1",
            (event_id, team_id),
        ).fetchone() else "not_submitted"
        counts = teams_by_track.setdefault(track, {"submitted": 0, "not_submitted": 0})
        counts[submitted_state] += 1
    projects_by_track_domain: dict[str, dict[str, int]] = {}
    repository = demo = eligible = 0
    for raw_payload, links_json in connection.execute(
        """SELECT sr.raw_payload_json,s.links_json FROM submission s
           JOIN source_record sr ON sr.id=s.source_record_id
           WHERE s.event_id=? AND sr.quarantined=0""",
        (event_id,),
    ):
        payload = json.loads(raw_payload or "{}")
        track = normalize_track(payload.get("Track") or payload.get("track"))
        projects_by_track_domain.setdefault(track, {"unclassified": 0})["unclassified"] += 1
        links = json.loads(links_json or "{}")
        eligible += 1
        repository += int(bool(links.get("repository_present")))
        demo += int(bool(links.get("demo_present")))
    github_people = connection.execute(
        """SELECT COUNT(DISTINCT pi.person_id) FROM person_identity pi
           WHERE pi.identity_type='github'"""
    ).fetchone()[0]
    return {
        "approved": len(approved_people), "checked_in": len(checked_people),
        "submitted_people": len(submitted_people), "teams_by_track": teams_by_track,
        "projects_by_track_domain": projects_by_track_domain,
        "composition": {"team": len(checked_people & team_people),
                        "solo": len(checked_people - team_people)},
        "artifact_counts": {"demo": (demo, eligible), "repository": (repository, eligible)},
        "github_people": int(github_people),
    }


def normalize_track(value: object) -> str:
    key = re.sub(r"[^a-z0-9]+", "_", str(value or "").strip().casefold()).strip("_")
    key = {"boski_challenge": "boski", "solidgate_challenge": "solidgate"}.get(key, key)
    return key or "unclassified"


def _canonical_person(
    connection: sqlite3.Connection, person_id: object, source_record_id: object
) -> int:
    decision = connection.execute(
        """SELECT current.person_id FROM identity_decision current
           WHERE current.source_record_id=? AND current.person_id IS NOT NULL
             AND NOT EXISTS (
                 SELECT 1 FROM identity_decision newer
                 WHERE newer.supersedes_decision_id=current.id
             )
           ORDER BY current.id DESC LIMIT 1""",
        (source_record_id,),
    ).fetchone()
    return int(decision[0]) if decision else int(person_id)


def _mask_email(value: str) -> str:
    email = normalize_email(value) or ""
    if "@" not in email:
        return "Unavailable"
    local, domain = email.split("@", 1)
    return f"{local[:1]}***@{domain}"
