"""One-time, local-only real talent-report reconciliation and publication helpers."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from html import escape
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
from typing import Iterable, Mapping

from community_os.event_definition import EventDefinition, load_event_definition
from community_os.event_approval import EventApproval
from community_os.normalized_event import NormalizedEventData
from community_os.partner_semantic_projection import (
    PartnerSemanticSummary,
    semantic_summary_manifest_binding,
)


_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
_SHA256 = re.compile(r"[0-9a-f]{64}")
_GIT_SHA = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?")


@dataclass(frozen=True)
class PersonResolution:
    resolved_application_ids: frozenset[str]
    quarantined_refs: frozenset[str]
    unresolved_refs: frozenset[str]


def _validated_event_source_bindings(
    event_definition: EventDefinition,
    *,
    observed_source_hashes: Mapping[str, str | None],
    approved_source_hashes: Mapping[str, str | None],
) -> dict[str, dict[str, str | None]]:
    """Bind observed bytes to the configured adapters and approved source snapshot."""

    roles = {source.role for source in event_definition.sources}
    if set(observed_source_hashes) != roles or set(approved_source_hashes) != roles:
        raise ValueError("event source roles do not match the event definition")
    bindings: dict[str, dict[str, str | None]] = {}
    drift: list[str] = []
    for source in event_definition.sources:
        observed = observed_source_hashes[source.role]
        approved = approved_source_hashes[source.role]
        for label, digest in (("observed", observed), ("approved", approved)):
            if digest is not None and (
                not isinstance(digest, str) or _SHA256.fullmatch(digest) is None
            ):
                raise ValueError(
                    f"{label} source hash is invalid for {source.role}",
                )
        if source.required and (observed is None or approved is None):
            raise ValueError(f"required event source is unavailable: {source.role}")
        if observed != approved:
            drift.append(source.role)
        bindings[source.role] = {
            "adapter_id": source.adapter_id,
            "mapping_sha256": source.mapping_sha256,
            "source_sha256": observed,
        }
    if drift:
        raise ValueError("source hash drift: " + ", ".join(sorted(drift)))
    return dict(sorted(bindings.items()))


def _validated_event_approval_bindings(
    event_definition: EventDefinition,
    *,
    event_approval: EventApproval,
    observed_source_hashes: Mapping[str, str | None],
) -> dict[str, dict[str, str | None]]:
    """Recheck an approval object against the exact event and observed source bytes."""

    if event_approval.version != "event-approval-v2":
        raise ValueError("event approval version is unsupported")
    if event_approval.event_key != event_definition.event_key:
        raise ValueError("event approval event key does not match")
    if not hmac.compare_digest(
        event_approval.event_definition_sha256, event_definition.sha256,
    ):
        raise ValueError("event approval event definition does not match")
    if event_approval.policy_profile != event_definition.privacy.policy_profile:
        raise ValueError("event approval privacy policy does not match")
    if event_approval.taxonomy_version != event_definition.semantic.taxonomy_version:
        raise ValueError("event approval taxonomy does not match")
    if (
        event_approval.metric_registry_version
        != event_definition.semantic.metric_registry_version
    ):
        raise ValueError("event approval metric registry does not match")
    if _SHA256.fullmatch(event_approval.sha256) is None:
        raise ValueError("event approval hash is invalid")

    approvals = {source.role: source for source in event_approval.sources}
    if len(approvals) != len(event_approval.sources):
        raise ValueError("event approval source roles are duplicated")
    expected_roles = {source.role for source in event_definition.sources}
    if set(approvals) != expected_roles:
        raise ValueError("event approval source roles do not match")
    approved_hashes: dict[str, str | None] = {}
    for source in event_definition.sources:
        approved = approvals[source.role]
        if approved.adapter_id != source.adapter_id:
            raise ValueError(f"event approval adapter does not match: {source.role}")
        if not hmac.compare_digest(approved.mapping_sha256, source.mapping_sha256):
            raise ValueError(f"event approval mapping does not match: {source.role}")
        approved_hashes[source.role] = approved.source_sha256
    return _validated_event_source_bindings(
        event_definition,
        observed_source_hashes=observed_source_hashes,
        approved_source_hashes=approved_hashes,
    )


def _validate_event_approval_exclusions(
    event_approval: EventApproval,
    *,
    excluded_application_ids: set[str] | frozenset[str],
    excluded_subject_refs_by_application_id: Mapping[str, str] | None,
    exclusion_set_sha256: str | None,
    pseudonym_secret: bytes | None,
) -> str:
    """Bind the identifier-free exclusion evidence to the approved pseudonym set."""

    if not isinstance(excluded_application_ids, (set, frozenset)) or any(
        not isinstance(value, str) or not value.strip()
        for value in excluded_application_ids
    ):
        raise ValueError("event approval exclusion application identifiers are invalid")
    bindings = dict(excluded_subject_refs_by_application_id or {})
    if set(bindings) != set(excluded_application_ids):
        raise ValueError("event approval exclusion application binding does not match")
    if excluded_application_ids:
        if not isinstance(pseudonym_secret, bytes) or len(pseudonym_secret) < 16:
            raise ValueError("event approval exclusion pseudonym secret is required")
        from community_os.enrichment.state import pseudonymous_id

        for application_id, subject_ref in bindings.items():
            expected_subject_ref = pseudonymous_id(
                application_id, secret=pseudonym_secret, key_version="v1",
            )
            if not hmac.compare_digest(subject_ref, expected_subject_ref):
                raise ValueError(
                    "event approval exclusion pseudonym binding does not match",
                )
    bound_subject_refs = tuple(bindings.values())
    if (
        len(bound_subject_refs) != len(set(bound_subject_refs))
        or set(bound_subject_refs) != set(event_approval.excluded_subject_refs)
    ):
        raise ValueError("event approval exclusion subject binding does not match")
    canonical = json.dumps(
        sorted(event_approval.excluded_subject_refs),
        ensure_ascii=True,
        separators=(",", ":"),
    )
    expected = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    if exclusion_set_sha256 is None:
        if excluded_application_ids:
            raise ValueError("event approval exclusion set hash is required")
    elif (
        _SHA256.fullmatch(exclusion_set_sha256) is None
        or not hmac.compare_digest(exclusion_set_sha256, expected)
    ):
        raise ValueError("event approval exclusion set hash does not match")
    return expected


def _code_provenance(
    repository_root: str | Path = _REPOSITORY_ROOT,
    *,
    git_sha: str | None = None,
) -> dict[str, object]:
    """Bind a Git revision and the exact Python source bytes without local paths."""

    root = Path(repository_root).resolve()
    package = root / "community_os"
    source_files = tuple(
        sorted(
            (
                path for path in package.rglob("*.py")
                if "__pycache__" not in path.parts and path.is_file()
            ),
            key=lambda path: path.relative_to(root).as_posix(),
        )
    )
    if not source_files:
        raise ValueError("code provenance requires community_os Python sources")
    source_entries = [
        {
            "path": path.relative_to(root).as_posix(),
            "sha256": sha256_file(path),
        }
        for path in source_files
    ]
    source_sha256 = hashlib.sha256(json.dumps(
        source_entries,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")).hexdigest()
    revision = git_sha
    if revision is None:
        try:
            completed = subprocess.run(
                ["git", "-C", str(root), "rev-parse", "--verify", "HEAD"],
                check=True,
                capture_output=True,
                text=True,
                timeout=10,
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise ValueError("code provenance requires a readable Git revision") from error
        revision = completed.stdout.strip().casefold()
        try:
            changed = subprocess.run(
                [
                    "git", "-C", str(root), "diff", "--quiet", revision,
                    "--", "community_os",
                ],
                check=False,
                capture_output=True,
                timeout=10,
            )
            tracked = subprocess.run(
                [
                    "git", "-C", str(root), "ls-tree", "-r", "--name-only",
                    revision, "--", "community_os",
                ],
                check=True,
                capture_output=True,
                text=True,
                timeout=10,
            )
        except (OSError, subprocess.SubprocessError) as error:
            raise ValueError("code provenance requires readable committed sources") from error
        tracked_python = {
            line.strip()
            for line in tracked.stdout.splitlines()
            if line.strip().endswith(".py")
        }
        current_python = {entry["path"] for entry in source_entries}
        if changed.returncode == 1 or current_python != tracked_python:
            raise ValueError(
                "code provenance refuses uncommitted Python source changes",
            )
        if changed.returncode != 0:
            raise ValueError("code provenance could not compare committed sources")
    if not isinstance(revision, str) or _GIT_SHA.fullmatch(revision) is None:
        raise ValueError("code provenance Git SHA is invalid")
    return {
        "version": "code-provenance-v1",
        "git_sha": revision,
        "python_source_sha256": source_sha256,
        "python_file_count": len(source_entries),
    }


def _population_sha256(
    application_ids: Iterable[str],
    *,
    event_key: str,
) -> str:
    """Bind an event-scoped applicant set without writing its identifiers."""

    values = tuple(application_ids)
    if (
        not re.fullmatch(r"[a-z0-9][a-z0-9_-]{1,127}", event_key)
        or not values
        or any(not isinstance(value, str) or not value.strip() for value in values)
        or len(values) != len(set(values))
    ):
        raise ValueError("release population identifiers are invalid")
    canonical = json.dumps(
        {"event_key": event_key, "application_ids": sorted(values)},
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _release_manifest_context(
    event_definition: EventDefinition,
    *,
    source_bindings: Mapping[str, Mapping[str, str | None]],
    code_provenance: Mapping[str, object],
    event_approval_sha256: str,
) -> dict[str, object]:
    """Return the event, source, semantic, and code bindings used by a release."""

    roles = {source.role for source in event_definition.sources}
    if set(source_bindings) != roles:
        raise ValueError("manifest source bindings do not match the event definition")
    if _SHA256.fullmatch(event_approval_sha256) is None:
        raise ValueError("manifest event approval hash is invalid")
    return {
        "event_approval_sha256": event_approval_sha256,
        "event": {
            "artifact_profile": event_definition.artifact_profile,
            "definition_sha256": event_definition.sha256,
            "event_key": event_definition.event_key,
            "event_name": event_definition.event_name,
            "report_family": event_definition.report_family,
            "privacy_minimum_count": event_definition.privacy.minimum_count,
            "privacy_policy_profile": event_definition.privacy.policy_profile,
            "starts_on": event_definition.starts_on.isoformat(),
            "ends_on": event_definition.ends_on.isoformat(),
            "timezone": event_definition.timezone,
        },
        "sources": {
            role: dict(sorted(binding.items()))
            for role, binding in sorted(source_bindings.items())
        },
        "semantic": {
            "metric_registry_version": (
                event_definition.semantic.metric_registry_version
            ),
            "taxonomy_version": event_definition.semantic.taxonomy_version,
        },
        "code_provenance": dict(code_provenance),
    }


def _event_source_notes(
    event_definition: EventDefinition,
    *,
    coverage_states: Mapping[str, str] | None = None,
) -> list[dict[str, object]]:
    roles = {source.role for source in event_definition.sources}
    states = (
        {role: "available" for role in roles}
        if coverage_states is None else dict(coverage_states)
    )
    if set(states) != roles or any(
        state not in {"available", "missing_optional", "unavailable"}
        for state in states.values()
    ):
        raise ValueError("source coverage does not match the event definition")
    if any(
        source.required and states[source.role] != "available"
        for source in event_definition.sources
    ):
        raise ValueError("required normalized event source is unavailable")
    return [
        {
            "source": source.role,
            "state": (
                "validated" if states[source.role] == "available" else "pending"
            ),
            "note": (
                f"Configured {source.role.replace('_', ' ')} source normalized with "
                f"{source.adapter_id}"
                if states[source.role] == "available"
                else f"Optional {source.role.replace('_', ' ')} source was not supplied"
            ),
        }
        for source in event_definition.sources
    ]


def _validated_classification_review(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ValueError("override classification_review is required")
    review = dict(value)
    if review.get("status") != "approved" or not str(review.get("reviewer") or "").strip():
        raise ValueError("headline-driving classification review is not approved")
    version = review.get("classifier_version")
    if version == "deterministic-rules-v1":
        review.setdefault("model", "none")
        review.setdefault("prompt_version", "not_applicable")
        review.setdefault("processor_approval_hash", None)
    elif version == "semantic-v1":
        if (
            not str(review.get("model") or "").startswith("gpt-")
            or not str(review.get("prompt_version") or "").strip()
            or not re.fullmatch(r"[0-9a-f]{64}", str(review.get("processor_approval_hash") or ""))
        ):
            raise ValueError("semantic classification provenance is incomplete")
    else:
        raise ValueError("headline-driving classification review is not approved")
    return review


def normalize_team_name(value: object) -> str:
    """Normalize punctuation and spacing without inventing semantic equivalence."""

    return re.sub(r"\s+", " ", re.sub(r"[^a-z0-9]+", " ", str(value or "").casefold())).strip()


def match_teams(
    preferences: Mapping[str, Mapping[str, object]],
    projects: Mapping[str, Mapping[str, object]],
    *,
    reviewed_links: Mapping[str, str],
) -> dict[str, str]:
    """Match exact normalized team names automatically; require review otherwise."""

    project_by_normalized: dict[str, list[str]] = {}
    for project in projects:
        project_by_normalized.setdefault(normalize_team_name(project), []).append(project)
    result: dict[str, str] = {}
    used: set[str] = set()
    for preference in preferences:
        exact = project_by_normalized.get(normalize_team_name(preference), [])
        if len(exact) == 1:
            project = exact[0]
        else:
            project = reviewed_links.get(preference, "")
            if not project:
                raise ValueError(f"reviewed team link required for {preference!r}")
        if project not in projects:
            raise ValueError(f"reviewed team link references unknown project {project!r}")
        if project in used:
            raise ValueError(f"project {project!r} is linked more than once")
        preference_track = str(preferences[preference].get("track") or "")
        project_track = str(projects[project].get("track") or "")
        if preference_track != project_track:
            raise ValueError(f"team link crosses tracks for {preference!r}")
        result[preference] = project
        used.add(project)
    if used != set(projects):
        raise ValueError("team matching is not a complete one-to-one reconciliation")
    return result


def apply_attendance_overrides(
    source_counts: Mapping[str, int], override: Mapping[str, object], *, event_key: str,
) -> dict[str, int]:
    """Apply an attributable, replayable aggregate correction document."""

    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{1,127}", event_key):
        raise ValueError("override event key is invalid")
    for key in ("override_version", "operator", "timestamp"):
        if not isinstance(override.get(key), str) or not str(override[key]).strip():
            raise ValueError(f"override {key} is required")
    corrections = override.get("corrections")
    if not isinstance(corrections, list) or not corrections:
        raise ValueError("override corrections must be a non-empty list")
    result = dict(source_counts)
    seen: set[str] = set()
    required = {
        "stable_key", "field", "source_value", "corrected_value", "reason", "evidence_note",
    }
    for index, value in enumerate(corrections):
        if not isinstance(value, dict) or set(value) != required:
            raise ValueError(f"override correction {index} has invalid keys")
        field = str(value["field"])
        if field in seen:
            raise ValueError(f"override field {field!r} is duplicated")
        if field not in result:
            raise ValueError(f"override field {field!r} is unknown")
        if value["stable_key"] != f"event:{event_key}:{field}":
            raise ValueError(f"override correction {index} belongs to another event")
        if value["source_value"] != result[field]:
            raise ValueError(f"override source value drift for {field!r}")
        corrected = value["corrected_value"]
        if not isinstance(corrected, int) or isinstance(corrected, bool) or corrected < 0:
            raise ValueError(f"override corrected value for {field!r} must be a non-negative integer")
        if not str(value["stable_key"]).strip() or not str(value["reason"]).strip() or not str(value["evidence_note"]).strip():
            raise ValueError(f"override correction {index} is incomplete")
        result[field] = corrected
        seen.add(field)
    if result["going_accepted"] > result["applied"]:
        raise ValueError("going_accepted cannot exceed applied")
    if result["on_site_builders"] > result["going_accepted"]:
        raise ValueError("on_site_builders cannot exceed going_accepted")
    return result


def resolve_submission_people(
    applications: Mapping[str, Mapping[str, object]],
    source_people: Iterable[Mapping[str, object]],
    *,
    reviewed_links: Mapping[str, str],
    quarantined_refs: set[str] | frozenset[str],
) -> PersonResolution:
    """Resolve exact emails and attributable reviews; never infer from names."""

    email_to_application: dict[str, str] = {}
    for application_id, application in applications.items():
        email = str(application.get("email") or "").strip().casefold()
        if not email:
            continue
        if email in email_to_application:
            raise ValueError("application emails must be unique")
        email_to_application[email] = application_id
    resolved: set[str] = set()
    quarantined: set[str] = set()
    unresolved: set[str] = set()
    for person in source_people:
        source_ref = str(person.get("source_ref") or "").strip()
        if not source_ref:
            raise ValueError("source person requires source_ref")
        email = str(person.get("email") or "").strip().casefold()
        application_id = email_to_application.get(email)
        if application_id:
            resolved.add(application_id)
        elif source_ref in reviewed_links:
            linked = reviewed_links[source_ref]
            if linked not in applications:
                raise ValueError(f"reviewed person link references unknown application {linked!r}")
            resolved.add(linked)
        elif source_ref in quarantined_refs:
            quarantined.add(source_ref)
        else:
            unresolved.add(source_ref)
    return PersonResolution(frozenset(resolved), frozenset(quarantined), frozenset(unresolved))


def _count(value: int, minimum: int = 5) -> dict[str, object]:
    if value == 0 or value >= minimum:
        return {"value": value, "privacy": "published", "reason": None}
    return {"value": None, "privacy": "withheld", "reason": "Below publication threshold"}


def _nested_count(parent: int, child: int, minimum: int = 5) -> dict[str, object]:
    """Publish a nested cohort only when neither side reveals a below-k complement."""

    if parent < 0 or child < 0 or child > parent:
        raise ValueError("nested public count is invalid")
    count = _count(child, minimum)
    if count["value"] is not None and 0 < parent - child < minimum:
        return {
            "value": None,
            "privacy": "withheld",
            "reason": "Complement below publication threshold",
        }
    return count


def _require_non_derivable_binary_partition(
    total: int, selected: int, *, minimum: int = 5,
) -> None:
    """Fail closed when either side of an exact public partition would be suppressed."""

    if total < 0 or selected < 0 or selected > total:
        raise ValueError("binary public partition is invalid")
    remainder = total - selected
    if any(0 < value < minimum for value in (selected, remainder)):
        raise ValueError("public binary partition would reveal a suppressed complement")


def build_v3_payload(
    *,
    applied: int,
    going_accepted: int,
    on_site_builders: int,
    track_project_counts: Mapping[str, int],
    track_team_submission_counts: Mapping[str, Mapping[str, int]] | None = None,
    submitted_people: int,
    github_supplied: int,
    team_applicants: int,
    solo_applicants: int,
    repository_projects: int,
    demo_projects: int,
    generated_at: str,
    event_definition: EventDefinition,
    source_coverage_states: Mapping[str, str] | None = None,
    synthetic: bool = False,
) -> dict[str, object]:
    """Build the frozen operational contract with corrected public event semantics."""

    definition = event_definition
    if not isinstance(synthetic, bool):
        raise TypeError("synthetic must be a boolean")
    minimum = definition.privacy.minimum_count
    _require_non_derivable_binary_partition(
        applied, going_accepted, minimum=minimum,
    )
    if team_applicants + solo_applicants != applied:
        raise ValueError("applicant composition does not reconcile")
    _require_non_derivable_binary_partition(
        applied, team_applicants, minimum=minimum,
    )
    if any(
        not isinstance(track, str)
        or not track.strip()
        or isinstance(count, bool)
        or not isinstance(count, int)
        or count < 0
        for track, count in track_project_counts.items()
    ):
        raise ValueError("track project counts are invalid")
    project_total = sum(track_project_counts.values())
    on_site_count = _nested_count(going_accepted, on_site_builders, minimum)
    repository_count = _nested_count(project_total, repository_projects, minimum)
    demo_count = _nested_count(project_total, demo_projects, minimum)
    team_submission_counts = track_team_submission_counts or {
        track: {"submitted": count, "not_submitted": 0}
        for track, count in track_project_counts.items()
    }
    if any(
        not isinstance(track, str)
        or not track.strip()
        or not isinstance(counts, Mapping)
        or set(counts) != {"submitted", "not_submitted"}
        or any(
            isinstance(value, bool) or not isinstance(value, int) or value < 0
            for value in counts.values()
        )
        for track, counts in team_submission_counts.items()
    ):
        raise ValueError("track team submission counts are invalid")

    def public_count(value: int) -> dict[str, object]:
        return _count(value, minimum)

    source_notes = _event_source_notes(
        definition, coverage_states=source_coverage_states,
    )
    available_source_count = sum(
        note["state"] == "validated" for note in source_notes
    )

    payload: dict[str, object] = {
        "metadata": {
            "contract_version": "talent-report-v3",
            "title": f"{definition.event_name} Talent Data Room",
            "event_key": definition.event_key,
            "event_name": definition.event_name,
            "event_date": definition.starts_on.isoformat(),
            "generated_at": generated_at,
            "synthetic": synthetic,
            "publication_state": "review_ready",
        },
        "privacy": {"mode": "aggregate_only", "minimum_count": minimum, "pii_included": False, "state": "safe"},
        "attendance_funnel": {"unit": "people", "stages": [
            {"key": "applied", "label": "Applied", "order": 1, "count": public_count(applied)},
            {"key": "going_accepted", "label": "Going / accepted", "order": 2, "count": public_count(going_accepted)},
            {"key": "on_site", "label": "On site", "order": 3, "count": on_site_count},
        ]},
        "journey": {"unit": "people", "nodes": [
            {"key": "applied", "label": "Applied", "order": 1, "count": public_count(applied), "unit": "people"},
            {"key": "going_accepted", "label": "Going / accepted", "order": 2, "count": public_count(going_accepted), "unit": "people"},
            {"key": "not_accepted_reason_unknown", "label": "Not accepted, reason unknown", "order": 3, "count": public_count(applied - going_accepted), "unit": "people"},
            {"key": "on_site", "label": "On site", "order": 4, "count": on_site_count, "unit": "people"},
        ], "links": [
            {"source": "applied", "target": "going_accepted", "count": public_count(going_accepted), "unit": "people"},
            {"source": "applied", "target": "not_accepted_reason_unknown", "count": public_count(applied - going_accepted), "unit": "people"},
            {"source": "going_accepted", "target": "on_site", "count": on_site_count, "unit": "people"},
        ]},
        "team_submission_matrix": {
            "unit": "teams", "row_keys": sorted(team_submission_counts),
            "column_keys": ["submitted", "not_submitted"],
            "cells": [
                {"row": track, "column": state, "count": public_count(int(counts[state]))}
                for track, counts in sorted(team_submission_counts.items())
                for state in ("submitted", "not_submitted")
            ],
        },
        "builder_signal_intersections": {
            "unit": "people", "signal_keys": ["submitted_team"],
            "intersections": [
                {"signals": ["submitted_team"], "count": public_count(submitted_people)},
            ],
        },
        "track_domain_heatmap": {
            "unit": "projects", "track_keys": sorted(track_project_counts),
            "domain_keys": ["unclassified"],
            "cells": [
                {"track": track, "domain": "unclassified", "count": public_count(count)}
                for track, count in sorted(track_project_counts.items())
            ],
        },
        "composition": {"unit": "people", "categories": [
            {"key": "applied_solo", "label": "Applied solo", "count": public_count(solo_applicants)},
            {"key": "applied_with_team", "label": "Applied with a team", "count": public_count(team_applicants)},
        ]},
        "artifact_completeness": {"unit": "projects", "items": [
            {"key": "demo", "label": "Demo", "status": "complete" if demo_projects == project_total else ("missing" if demo_projects == 0 else "partial"), "present": demo_count, "eligible": public_count(project_total)},
            {"key": "repository", "label": "Repository", "status": "complete" if repository_projects == project_total else ("missing" if repository_projects == 0 else "partial"), "present": repository_count, "eligible": public_count(project_total)},
        ]},
        "readiness": [
            {"component": "identity_review", "state": "ready", "required": True, "note": "All membership records linked or quarantined"},
            {"component": "source_reconciliation", "state": "ready", "required": True, "note": f"{available_source_count} of {len(definition.sources)} configured source inputs validated"},
            {"component": "coresignal", "state": "off", "required": False, "note": "Not approved or enabled"},
        ],
        "source_notes": source_notes,
    }
    if any(
        isinstance(item, dict) and item.get("privacy") == "withheld"
        for item in _walk(payload)
    ):
        payload["privacy"]["state"] = "withheld_cells"
    return payload


def _walk(value: object) -> Iterable[object]:
    yield value
    if isinstance(value, dict):
        for child in value.values():
            yield from _walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk(child)


def classify_application(application: Mapping[str, object]) -> dict[str, set[str]]:
    """Conservative deterministic classifier; missing evidence stays unknown."""

    external_id = str(application.get("external_id") or "unknown")
    occupation = str(application.get("occupation") or "")
    experience = str(application.get("experience") or "")
    impressive = str(application.get("impressive_thing") or "")
    organization = str(application.get("organization") or "")
    text = " ".join((occupation, experience, impressive, organization)).casefold()

    professional: set[str] = set()
    if re.search(r"\b(co[ -]?founder|founder|founded)\b", text):
        professional.add("founder_cofounder")
    if re.search(r"\b(startup|scale[ -]?up|ceo|cto|cpo|coo)\b", text):
        professional.add("startup_operator")
    if re.search(r"\b(researcher|research scientist|professor|phd|academic)\b", occupation.casefold()):
        professional.add("researcher_academic")
    if not professional:
        professional.add("insufficient_evidence")

    if "founder_cofounder" in professional:
        seniority = {"founder"}
    elif re.search(r"\b(chief|head|lead|principal|staff|director|vp|manager)\b", occupation.casefold()):
        seniority = {"lead_staff_executive"}
    elif re.search(r"\bsenior\b", occupation.casefold()):
        seniority = {"senior"}
    elif re.search(r"\b(student|undergraduate|master'?s|bachelor'?s)\b", text):
        seniority = {"student"}
    elif re.search(r"\b(junior|intern|trainee)\b", text):
        seniority = {"junior"}
    else:
        years = [int(value) for value in re.findall(r"\b(\d{1,2})\+?\s+years?\b", text)]
        if years and max(years) >= 6:
            seniority = {"senior"}
        elif years and max(years) >= 3:
            seniority = {"mid_level"}
        elif years:
            seniority = {"junior"}
        else:
            seniority = {"unknown"}

    roles: set[str] = set()
    if re.search(r"\b(software|engineer|developer|backend|frontend|full[ -]?stack|devops|cloud)\b", text):
        roles.add("engineering")
    if re.search(r"\b(ai|machine learning|ml|data scientist|data engineer|analytics)\b", text):
        roles.add("data_ai")
    if re.search(r"\b(product manager|product owner|product strategy)\b", text):
        roles.add("product")
    if re.search(r"\b(designer|ux|ui|design)\b", text):
        roles.add("design")
    if re.search(r"\b(sales|marketing|growth|business development|partnerships)\b", text):
        roles.add("commercial")
    if re.search(r"\b(operations|operator|program manager)\b", text):
        roles.add("operations")
    if re.search(r"\b(research|scientist|academic|phd)\b", text):
        roles.add("research")
    if not roles:
        roles.add("unknown")

    if "founder_cofounder" in professional:
        employer = {"self_employed_founder"}
    elif seniority == {"student"}:
        employer = {"student_no_employer"}
    elif re.search(r"\b(university|research institute|academy|academic)\b", organization.casefold()):
        employer = {"academia_research"}
    else:
        employer = {"unknown"}

    builder: set[str] = set()
    if "founder_cofounder" in professional:
        builder.add("founded_company")
    if re.search(r"\b(shipped|launched|deployed|built|created|users|customers|revenue|production)\b", " ".join((experience, impressive)).casefold()):
        builder.add("shipped_product")
    if str(application.get("github") or "").strip():
        builder.add("github_supplied")
    if not builder:
        builder.add("insufficient_evidence")

    capabilities: set[str] = set()
    for key, pattern in {
        "backend": r"\b(backend|api|distributed|python|java|go|rust)\b",
        "frontend": r"\b(frontend|react|javascript|typescript|web)\b",
        "ai_ml": r"\b(ai|machine learning|ml|llm|model)\b",
        "data": r"\b(data|analytics|sql)\b",
        "cloud": r"\b(cloud|aws|gcp|azure|devops|kubernetes)\b",
        "mobile": r"\b(mobile|ios|android|flutter|react native)\b",
        "product": r"\b(product|discovery|roadmap)\b",
        "design": r"\b(design|ux|ui)\b",
        "growth": r"\b(growth|sales|marketing|commercial)\b",
        "security": r"\b(security|cyber|infosec)\b",
    }.items():
        if re.search(pattern, text):
            capabilities.add(key)
    if not capabilities:
        capabilities.add("unknown")

    domains: set[str] = set()
    for key, pattern in {
        "applied_ai": r"\b(ai|machine learning|llm|model)\b",
        "developer_tools": r"\b(developer tool|devtool|api platform|sdk)\b",
        "fintech": r"\b(fintech|payment|bank|finance|financial)\b",
        "cybersecurity": r"\b(cyber|security|infosec)\b",
        "marketplaces": r"\b(marketplace|commerce|ecommerce|retail)\b",
        "climate": r"\b(climate|energy|sustainab)\b",
        "health": r"\b(health|medical|care|biotech)\b",
        "education": r"\b(education|school|learning|student)\b",
        "enterprise": r"\b(enterprise|workflow|b2b|automation)\b",
    }.items():
        if re.search(pattern, text):
            domains.add(key)
    if not domains:
        domains.add("unknown")

    return {
        "professional_identity": professional,
        "seniority": seniority,
        "functional_role": roles,
        "employer_pedigree": employer,
        "builder_evidence": builder,
        "capabilities": capabilities,
        "domains": domains,
        "evidence_refs": {f"application:{external_id}"},
    }


_DIMENSION_SPECS: dict[str, tuple[str, str, tuple[tuple[str, str, str], ...]]] = {
    "professional_identity": (
        "Professional identity", "overlapping", (
            ("founder_cofounder", "Founder or co-founder", "Explicit founder evidence"),
            ("startup_operator", "Startup executive or operator", "Explicit startup operating evidence"),
            ("researcher_academic", "Researcher or academic", "Explicit research or academic evidence"),
            ("insufficient_evidence", "Insufficient professional evidence", "Available application evidence is insufficient"),
        ),
    ),
    "seniority": (
        "Seniority", "exclusive", (
            ("student", "Student", "Explicit current student evidence"),
            ("junior", "Junior", "Explicit junior, intern, or trainee evidence"),
            ("mid_level", "Mid-level", "Explicit mid-level evidence"),
            ("senior", "Senior", "Explicit senior evidence without leadership title"),
            ("lead_staff_executive", "Lead, staff, principal, head, or executive", "Explicit leadership or senior title evidence"),
            ("founder", "Founder", "Explicit founder evidence"),
            ("unknown", "Unknown", "Available evidence does not support a seniority classification"),
        ),
    ),
    "functional_role": (
        "Functional role", "overlapping", (
            ("engineering", "Engineering", "Software, systems, platform, or infrastructure evidence"),
            ("data_ai", "Data and AI", "Data, analytics, machine learning, or AI evidence"),
            ("product", "Product", "Product management or product strategy evidence"),
            ("design", "Design", "Product, interaction, or visual design evidence"),
            ("commercial", "Commercial and growth", "Sales, growth, marketing, or partnership evidence"),
            ("operations", "Operations", "Operations or program delivery evidence"),
            ("research", "Research", "Research or academic evidence"),
            ("unknown", "Unknown", "Available evidence does not support a functional classification"),
        ),
    ),
    "employer_pedigree": (
        "Employer pedigree", "exclusive", (
            ("academia_research", "Academia or research", "Explicit academic organization evidence"),
            ("self_employed_founder", "Founder or self-employed", "Explicit founder evidence"),
            ("student_no_employer", "Student or no current employer", "Explicit current student evidence"),
            ("unknown", "Unknown", "No reviewed employer taxonomy evidence is available"),
        ),
    ),
    "builder_evidence": (
        "Builder evidence", "overlapping", (
            ("founded_company", "Founded a company", "Explicit founder evidence"),
            ("shipped_product", "Shipped a real product", "Explicit shipping, deployment, user, or customer evidence"),
            ("github_supplied", "Applicant-supplied GitHub", "Applicant supplied a GitHub identifier; activity is not inferred"),
            ("active_github", "Active public GitHub", "At least one owned, non-archived public repository was pushed in the prior twelve months"),
            ("hackathon_submission", "Represented by a submitted team", "Resolved membership in a submitted project team"),
            ("insufficient_evidence", "Insufficient builder evidence", "Available evidence does not support a builder classification"),
        ),
    ),
    "capabilities": (
        "Capabilities", "overlapping", tuple(
            (key, label, f"Explicit {label.casefold()} evidence")
            for key, label in (
                ("backend", "Backend and systems"), ("frontend", "Frontend and web"),
                ("ai_ml", "AI and machine learning"), ("data", "Data"),
                ("cloud", "Cloud and infrastructure"), ("mobile", "Mobile"),
                ("product", "Product discovery and delivery"), ("design", "Design"),
                ("growth", "Growth and commercial"), ("security", "Security"),
                ("unknown", "Unknown"),
            )
        ),
    ),
    "domains": (
        "Domains", "overlapping", tuple(
            (key, label, f"Explicit {label.casefold()} evidence")
            for key, label in (
                ("applied_ai", "Applied AI"), ("developer_tools", "Developer tools"),
                ("fintech", "Fintech"), ("cybersecurity", "Cybersecurity"),
                ("marketplaces", "Marketplaces and commerce"), ("climate", "Climate and sustainability"),
                ("health", "Health"), ("education", "Education"),
                ("enterprise", "Enterprise workflows"), ("unknown", "Unknown"),
            )
        ),
    ),
}


_CROSS_DIMENSION_SIGNAL_SPECS = (
    (
        "founder_evidence",
        "Founder / co-founder evidence",
        "Application evidence explicitly recorded a founder or co-founder role.",
        "professional_identity",
        frozenset({"founder_cofounder"}),
    ),
    (
        "student_stage",
        "Student stage",
        "Application evidence explicitly recorded a current student stage.",
        "seniority",
        frozenset({"student"}),
    ),
    (
        "technical_function",
        "Technical function",
        "Application evidence recorded engineering or data and AI work; this is a role signal, not a technical-depth score.",
        "functional_role",
        frozenset({"engineering", "data_ai"}),
    ),
    (
        "shipped_product_evidence",
        "Shipped-product evidence",
        "Application evidence explicitly described shipping, deployment, users, or customers; external delivery was not independently verified.",
        "builder_evidence",
        frozenset({"shipped_product"}),
    ),
)

_UPSET_SIGNAL_KEYS = (
    "founder_evidence",
    "technical_function",
    "shipped_product_evidence",
)

_UPSET_REGION_SPECS = (
    ("founder_technical_shipped_product_exact", "Founder + technical + shipped product", (True, True, True)),
    ("founder_technical_exact", "Founder + technical only", (True, True, False)),
    ("founder_shipped_product_exact", "Founder + shipped product only", (True, False, True)),
    ("founder_only_exact", "Founder evidence only", (True, False, False)),
    ("technical_shipped_product_exact", "Technical + shipped product only", (False, True, True)),
    ("technical_only_exact", "Technical function only", (False, True, False)),
    ("shipped_product_only_exact", "Shipped-product evidence only", (False, False, True)),
    ("neither_recorded_exact", "No recorded signal among these three", (False, False, False)),
)


def _distribution_counts(counts: Mapping[str, int], minimum: int = 5) -> dict[str, dict[str, object]]:
    suppressed = {key for key, value in counts.items() if 0 < value < minimum}
    if len(suppressed) == 1:
        candidates = [(value, key) for key, value in counts.items() if key not in suppressed and value >= minimum]
        if candidates:
            suppressed.add(min(candidates)[1])
    return {
        key: (
            {"value": None, "privacy": "withheld", "reason": "Primary or complementary suppression"}
            if key in suppressed else _count(value, minimum)
        )
        for key, value in counts.items()
    }


def _cross_dimension_evidence(
    classifications: Mapping[str, Mapping[str, set[str]]],
    *,
    denominator: int,
    minimum: int,
) -> tuple[dict[str, object], list[dict[str, object]]]:
    """Build a reusable, privacy-projected intersection view from reviewed labels.

    The UpSet rows are one exact partition over three positive application signals.
    A separate student-and-shipping intersection is inclusive and non-additive.
    No person identifier crosses the returned aggregate boundary.
    """

    if denominator != len(classifications):
        raise ValueError("cross-dimension population does not match denominator")
    population = set(classifications)
    members: dict[str, set[str]] = {}
    for key, _label, _definition, dimension, accepted_values in (
        _CROSS_DIMENSION_SIGNAL_SPECS
    ):
        members[key] = {
            subject
            for subject, classification in classifications.items()
            if classification[dimension].intersection(accepted_values)
        }

    items: list[dict[str, object]] = []
    for key, label, definition, _dimension, _accepted_values in (
        _CROSS_DIMENSION_SIGNAL_SPECS
    ):
        items.append({
            "key": key,
            "label": label,
            "count": _count(len(members[key]), minimum),
            "definition": definition,
            "evidence_sources": ["application"],
        })
        if key in _UPSET_SIGNAL_KEYS:
            items.append({
                "key": f"{key}_not_recorded",
                "label": f"{label} not recorded",
                "count": _count(denominator - len(members[key]), minimum),
                "definition": (
                    f"The positive {label.casefold()} signal was not recorded in "
                    "the reviewed application classification. This is not a negative assessment."
                ),
                "evidence_sources": ["application"],
            })

    signal_dimension = {
        "key": "cross_dimension_signals",
        "label": "Cross-dimensional application evidence",
        "mode": "overlapping",
        "denominator_key": "valid_applicants",
        "known_count": _count(denominator, minimum),
        "items": items,
    }

    region_members: dict[str, set[str]] = {}
    for key, _label, signature in _UPSET_REGION_SPECS:
        region = set(population)
        for signal_key, required in zip(_UPSET_SIGNAL_KEYS, signature, strict=True):
            signal_members = members[signal_key]
            region.intersection_update(
                signal_members if required else population.difference(signal_members)
            )
        region_members[key] = region
    if set().union(*region_members.values()) != population or sum(
        len(region) for region in region_members.values()
    ) != denominator:
        raise ValueError("cross-dimension exact regions do not partition population")
    region_counts = {
        key: len(region) for key, region in region_members.items()
    }
    if any(0 < value < minimum for value in region_counts.values()):
        published_regions = {
            key: {
                "value": None,
                "privacy": "withheld",
                "reason": (
                    "Exact partition withheld because a small cell could be "
                    "recovered from the published equations"
                ),
            }
            for key in region_counts
        }
    else:
        published_regions = {
            key: _count(value, minimum)
            for key, value in region_counts.items()
        }

    intersections: list[dict[str, object]] = []
    for key, label, signature in _UPSET_REGION_SPECS:
        components = [
            "cross_dimension_signals."
            + (signal_key if required else f"{signal_key}_not_recorded")
            for signal_key, required in zip(
                _UPSET_SIGNAL_KEYS, signature, strict=True,
            )
        ]
        intersections.append({
            "key": key,
            "label": label,
            "count": published_regions[key],
            "component_keys": components,
            "evidence_sources": ["application"],
        })

    student_shipped_members = members["student_stage"].intersection(
        members["shipped_product_evidence"],
    )
    student_shipped_count = _nested_count(
        len(members["student_stage"]),
        len(student_shipped_members),
        minimum,
    )
    if student_shipped_count["value"] is not None:
        student_shipped_count = _nested_count(
            len(members["shipped_product_evidence"]),
            len(student_shipped_members),
            minimum,
        )
    intersections.append({
        "key": "student_shipped_product",
        "label": "Student stage + shipped-product evidence",
        "count": student_shipped_count,
        "component_keys": [
            "cross_dimension_signals.student_stage",
            "cross_dimension_signals.shipped_product_evidence",
        ],
        "evidence_sources": ["application"],
    })
    return signal_dimension, intersections


def refresh_cross_dimension_evidence(
    payload: Mapping[str, object],
    *,
    classification_projection: Mapping[str, Mapping[str, Iterable[str]]],
) -> dict[str, object]:
    """Refresh an aggregate-only V1 contract from retained reviewed classifications.

    This is the no-provider migration path for an already generated protected release.
    The returned payload never contains the classification identifiers or vectors.
    """

    refreshed = json.loads(json.dumps(payload))
    if not isinstance(refreshed, dict):
        raise ValueError("talent aggregate must be an object")
    try:
        privacy = refreshed["privacy"]
        cohort = refreshed["cohort"]
        dimensions = refreshed["dimensions"]
    except KeyError as error:
        raise ValueError("talent aggregate is incomplete") from error
    if (
        not isinstance(privacy, dict)
        or not isinstance(cohort, dict)
        or not isinstance(dimensions, list)
        or privacy.get("mode") != "aggregate_only"
    ):
        raise ValueError("talent aggregate is invalid")
    minimum = privacy.get("minimum_count")
    denominator_value = cohort.get("denominator")
    denominator = (
        denominator_value.get("value")
        if isinstance(denominator_value, dict) else None
    )
    if (
        isinstance(minimum, bool)
        or not isinstance(minimum, int)
        or minimum < 2
        or isinstance(denominator, bool)
        or not isinstance(denominator, int)
        or denominator != len(classification_projection)
    ):
        raise ValueError("talent aggregate population or privacy policy is invalid")

    normalized: dict[str, dict[str, set[str]]] = {}
    expected_dimensions = set(_DIMENSION_SPECS)
    for subject, raw_projection in classification_projection.items():
        if not isinstance(subject, str) or not subject or not isinstance(
            raw_projection, Mapping,
        ):
            raise ValueError("classification projection is invalid")
        projected = {
            key: value for key, value in raw_projection.items()
            if key != "evidence_refs"
        }
        if set(projected) != expected_dimensions:
            raise ValueError("classification projection dimensions are incomplete")
        normalized_projection: dict[str, set[str]] = {}
        for dimension, raw_values in projected.items():
            if isinstance(raw_values, str) or not isinstance(raw_values, Iterable):
                raise ValueError("classification projection values are invalid")
            values = set(raw_values)
            allowed = {item[0] for item in _DIMENSION_SPECS[dimension][2]}
            if (
                not values
                or any(not isinstance(value, str) for value in values)
                or not values.issubset(allowed)
            ):
                raise ValueError("classification projection contains an unknown label")
            normalized_projection[dimension] = values
        normalized[subject] = normalized_projection

    signal_dimension, intersections = _cross_dimension_evidence(
        normalized,
        denominator=denominator,
        minimum=minimum,
    )
    refreshed["dimensions"] = [
        dimension for dimension in dimensions
        if isinstance(dimension, dict)
        and dimension.get("key") != "cross_dimension_signals"
    ]
    builder_dimension = next(
        (
            dimension for dimension in refreshed["dimensions"]
            if dimension.get("key") == "builder_evidence"
        ),
        None,
    )
    if isinstance(builder_dimension, dict) and isinstance(
        builder_dimension.get("items"), list,
    ):
        builder_dimension["items"] = [
            item for item in builder_dimension["items"]
            if isinstance(item, dict) and item.get("key") != "hackathon_submission"
        ]
    refreshed["dimensions"].append(signal_dimension)
    refreshed["intersections"] = intersections
    privacy["state"] = "withheld_cells" if any(
        isinstance(item, dict) and item.get("privacy") == "withheld"
        for item in _walk(refreshed)
    ) else "safe"
    return refreshed


def build_v1_payload(
    applications: Iterable[Mapping[str, object]],
    *,
    going_accepted: int,
    on_site_builders: int,
    submitted_application_ids: set[str] | frozenset[str],
    generated_at: str,
    classification_projection: Mapping[str, Mapping[str, Iterable[str]]] | None = None,
    enrichment_coverage: Mapping[str, int] | None = None,
    rich_semantic_reviewed: bool = False,
    excluded_application_ids: set[str] | frozenset[str] = frozenset(),
    event_definition: EventDefinition,
    source_coverage_states: Mapping[str, str] | None = None,
    synthetic: bool = False,
) -> dict[str, object]:
    """Project reviewed application evidence into the strict publication contract."""

    definition = event_definition
    if not isinstance(synthetic, bool):
        raise TypeError("synthetic must be a boolean")
    if not isinstance(rich_semantic_reviewed, bool):
        raise TypeError("rich_semantic_reviewed must be a boolean")
    minimum = definition.privacy.minimum_count

    def public_count(value: int) -> dict[str, object]:
        return _count(value, minimum)

    def nested_count(parent: int, child: int) -> dict[str, object]:
        return _nested_count(parent, child, minimum)

    all_records = [dict(item) for item in applications]
    all_ids = [str(item.get("external_id") or "").strip() for item in all_records]
    if any(not value for value in all_ids) or len(set(all_ids)) != len(all_ids):
        raise ValueError("applications require unique external_id values")
    if (
        not isinstance(excluded_application_ids, (set, frozenset))
        or any(not isinstance(value, str) or not value for value in excluded_application_ids)
        or not excluded_application_ids.issubset(all_ids)
    ):
        raise ValueError("excluded application identifiers are invalid")
    records = [
        item for item, external_id in zip(all_records, all_ids, strict=True)
        if external_id not in excluded_application_ids
    ]
    denominator = len(records)
    if not denominator or on_site_builders > going_accepted or going_accepted > denominator:
        raise ValueError("attendance counts do not reconcile to the applicant denominator")
    _require_non_derivable_binary_partition(
        denominator, going_accepted, minimum=minimum,
    )
    classifications: dict[str, dict[str, set[str]]] = {}
    if classification_projection is not None:
        projection_ids = set(classification_projection)
        included_ids = set(all_ids).difference(excluded_application_ids)
        if projection_ids == set(all_ids):
            classification_projection = {
                key: value for key, value in classification_projection.items()
                if key in included_ids
            }
        elif projection_ids != included_ids:
            raise ValueError("classification projection does not match the applicant population")
    for record in records:
        external_id = str(record.get("external_id") or "").strip()
        if not external_id or external_id in classifications:
            raise ValueError("applications require unique external_id values")
        if classification_projection is None:
            classifications[external_id] = classify_application(record)
        else:
            projected = classification_projection[external_id]
            if set(projected) != set(_DIMENSION_SPECS):
                raise ValueError("classification projection dimensions are incomplete")
            normalized: dict[str, set[str]] = {}
            for dimension, values in projected.items():
                labels = set(values)
                allowed = {item[0] for item in _DIMENSION_SPECS[dimension][2]}
                if not labels or not labels.issubset(allowed):
                    raise ValueError("classification projection contains an unknown label")
                normalized[dimension] = labels
            classifications[external_id] = normalized
        if external_id in submitted_application_ids:
            classifications[external_id]["builder_evidence"].add("hackathon_submission")

    dimensions = []
    dimension_members: dict[str, dict[str, set[str]]] = {}
    for dimension_key, (label, mode, item_specs) in _DIMENSION_SPECS.items():
        public_item_specs = tuple(
            item for item in item_specs
            if not (
                dimension_key == "builder_evidence"
                and item[0] in {
                    "active_github", "github_supplied", "hackathon_submission",
                }
            )
        )
        groups = {
            item_key: {
                external_id for external_id, classification in classifications.items()
                if item_key in classification[dimension_key]
            }
            for item_key, _, _ in item_specs
        }
        dimension_members[dimension_key] = groups
        counts = {key: len(members) for key, members in groups.items()}
        published = _distribution_counts(counts, minimum) if mode == "exclusive" else {
            key: public_count(value) for key, value in counts.items()
        }
        dimensions.append({
            "key": dimension_key,
            "label": label,
            "mode": mode,
            "denominator_key": "valid_applicants",
            "known_count": public_count(denominator),
            "items": [
                {
                    "key": item_key, "label": item_label, "count": published[item_key],
                    "definition": definition, "evidence_sources": ["application"]
                    if item_key != "hackathon_submission" else ["application", "devpost", "track_preferences"],
                }
                for item_key, item_label, definition in public_item_specs
            ],
        })

    cross_dimension, intersections = _cross_dimension_evidence(
        classifications,
        denominator=denominator,
        minimum=minimum,
    )
    dimensions.append(cross_dimension)

    shipped_count = len(dimension_members["builder_evidence"]["shipped_product"])
    private_coverage = dict(enrichment_coverage or {})
    if any(
        key not in {"github", "public_pages", "coresignal"}
        or isinstance(value, bool) or not isinstance(value, int) or value < 0 or value > denominator
        for key, value in private_coverage.items()
    ):
        raise ValueError("enrichment coverage is invalid")
    on_site_count = nested_count(going_accepted, on_site_builders)
    source_notes = _event_source_notes(
        definition, coverage_states=source_coverage_states,
    )
    available_source_count = sum(
        note["state"] == "validated" for note in source_notes
    )
    payload: dict[str, object] = {
        "metadata": {
            "contract_version": "talent-intelligence-v1",
            "title": f"{definition.event_name} Talent Brief",
            "event_key": definition.event_key,
            "event_name": definition.event_name,
            "event_date": definition.starts_on.isoformat(), "generated_at": generated_at,
            "synthetic": synthetic, "publication_state": "review_ready",
        },
        "privacy": {"mode": "aggregate_only", "minimum_count": minimum, "pii_included": False, "state": "safe"},
        "cohort": {"unit": "people", "denominator": public_count(denominator), "stages": [
            {"key": "valid_applicants", "label": "Applied", "order": 1, "count": public_count(denominator)},
            {"key": "going_accepted", "label": "Going / accepted", "order": 2, "count": public_count(going_accepted)},
            {"key": "on_site", "label": "On site", "order": 3, "count": on_site_count},
        ]},
        "selection_outcomes": {"unit": "people", "denominator_key": "valid_applicants", "categories": [
            {"key": "going_accepted", "label": "Going / accepted", "reason_state": "operator_reviewed", "count": public_count(going_accepted)},
            {"key": "not_accepted_reason_unknown", "label": "Not accepted, reason unknown", "reason_state": "unknown", "count": public_count(denominator - going_accepted)},
        ]},
        "dimensions": dimensions,
        "intersections": intersections,
        "qualitative_themes": [
            {"key": "production_shipping", "label": "Production shipping", "statement": "A reviewed segment describes shipping or operating software beyond prototype stage", "count": public_count(shipped_count), "confidence": "medium", "review_state": "reviewed", "evidence_sources": ["application"]},
        ],
        "evidence_coverage": [
            {"source": "application", "label": "Application evidence", "eligible": public_count(denominator), "covered": public_count(denominator), "state": "ready", "note": "Structured and applicant-written fields were classified conservatively"},
        ],
        "readiness": [
            {"component": "classification_review", "state": "ready", "required": True, "note": "Deterministic classifier and headline categories reviewed"},
            {"component": "identity_review", "state": "ready", "required": True, "note": "Source membership records linked or quarantined"},
            {"component": "source_reconciliation", "state": "ready", "required": True, "note": f"{available_source_count} of {len(definition.sources)} configured source inputs validated"},
            {"component": "semantic_enrichment", "state": "ready" if rich_semantic_reviewed else "pending", "required": False, "note": "Reviewed semantic evidence is bound to this release" if rich_semantic_reviewed else "Rich semantic evidence remains unknown until review is complete"},
        ],
        "feature_gates": [
            {"feature": "gated_talent_appendix", "state": "disabled", "required": True, "note": "Named disclosure is not approved"},
        ],
        "source_notes": source_notes,
    }
    payload["privacy"]["state"] = "withheld_cells" if any(
        isinstance(item, dict) and item.get("privacy") == "withheld" for item in _walk(payload)
    ) else "safe"
    return payload


def build_event_payloads(
    *,
    event_definition: EventDefinition,
    normalized_event: NormalizedEventData,
    generated_at: str,
    synthetic: bool = False,
) -> dict[str, dict[str, object]]:
    """Build both public contracts from one provider-neutral normalized event."""

    if normalized_event.event_key != event_definition.event_key:
        raise ValueError("normalized event does not match the event definition")

    accepted_refs = {
        observation.applicant_ref
        for observation in normalized_event.attendance
        if observation.accepted is True
    }
    present_refs = {
        observation.applicant_ref
        for observation in normalized_event.attendance
        if observation.present is True
    }
    if not present_refs.issubset(accepted_refs):
        raise ValueError("present applicants must belong to the accepted population")

    teams_by_ref = {team.ref: team for team in normalized_event.teams}
    submitted_projects = tuple(
        project for project in normalized_event.projects if project.submitted is True
    )
    submitted_team_refs = {
        project.team_ref for project in submitted_projects if project.team_ref is not None
    }

    def team_track(team_ref: str) -> str:
        return teams_by_ref[team_ref].track or "unclassified"

    project_tracks: dict[str, str] = {}
    for project in submitted_projects:
        linked_track = (
            team_track(project.team_ref) if project.team_ref is not None else None
        )
        if (
            project.track is not None
            and linked_track not in {None, "unclassified", project.track}
        ):
            raise ValueError("project and team tracks do not match")
        project_tracks[project.ref] = project.track or linked_track or "unclassified"

    tracks = {
        *(team.track or "unclassified" for team in normalized_event.teams),
        *project_tracks.values(),
    }
    track_project_counts = {
        track: sum(project_track == track for project_track in project_tracks.values())
        for track in sorted(tracks)
    }
    track_team_submission_counts = {
        track: {
            "submitted": sum(
                team_track(team.ref) == track and team.ref in submitted_team_refs
                for team in normalized_event.teams
            ),
            "not_submitted": sum(
                team_track(team.ref) == track and team.ref not in submitted_team_refs
                for team in normalized_event.teams
            ),
        }
        for track in sorted(tracks)
    }

    applicant_rows = [
        {
            "external_id": applicant.ref,
            "github": "supplied" if applicant.github_supplied else "",
        }
        for applicant in normalized_event.applicants
    ]
    submitted_application_ids = {
        membership.applicant_ref
        for membership in normalized_event.submitted_project_memberships
    }
    github_supplied = sum(
        applicant.github_supplied for applicant in normalized_event.applicants
    )
    repository_projects = sum(
        project.repository_supplied is True for project in submitted_projects
    )
    demo_projects = sum(
        project.demo_supplied is True for project in submitted_projects
    )
    team_application_ids = {
        membership.applicant_ref for membership in normalized_event.team_memberships
    }
    source_coverage_states = (
        {
            coverage.source_role: coverage.state.value
            for coverage in normalized_event.coverage
        }
        if normalized_event.coverage else None
    )

    return {
        "v1": build_v1_payload(
            applicant_rows,
            going_accepted=len(accepted_refs),
            on_site_builders=len(present_refs),
            submitted_application_ids=submitted_application_ids,
            generated_at=generated_at,
            event_definition=event_definition,
            source_coverage_states=source_coverage_states,
            synthetic=synthetic,
        ),
        "v3": build_v3_payload(
            applied=len(normalized_event.applicants),
            going_accepted=len(accepted_refs),
            on_site_builders=len(present_refs),
            track_project_counts=track_project_counts,
            track_team_submission_counts=track_team_submission_counts,
            submitted_people=len(submitted_application_ids),
            github_supplied=github_supplied,
            team_applicants=len(team_application_ids),
            solo_applicants=len(normalized_event.applicants) - len(team_application_ids),
            repository_projects=repository_projects,
            demo_projects=demo_projects,
            generated_at=generated_at,
            event_definition=event_definition,
            source_coverage_states=source_coverage_states,
            synthetic=synthetic,
        ),
    }


def classification_confidence_summary(payload: Mapping[str, object]) -> dict[str, dict[str, int | None]]:
    """Summarize explicit deterministic matches versus preserved unknown outcomes."""

    denominator = int(payload["cohort"]["denominator"]["value"])
    result: dict[str, dict[str, int | None]] = {}
    for dimension in payload["dimensions"]:
        unknown_item = next(
            (
                item for item in dimension["items"]
                if item["key"] in {"unknown", "insufficient_evidence"}
            ),
            None,
        )
        unknown = None if unknown_item is None else unknown_item["count"]["value"]
        result[dimension["key"]] = {
            "explicit_rule_match": None if unknown is None else denominator - int(unknown),
            "unknown": unknown,
        }
    return result


def render_unified_report(publication: Mapping[str, object]) -> str:
    """Render a self-contained static report with no executable client code."""

    metadata = publication["metadata"]
    headline = publication["headline"]
    sections = publication["sections"]
    methodology = publication["methodology"]
    lens_labels = "".join(
        f'<span data-intent="{key}">{escape(label)}</span>'
        for key, label in (
            ("overview", "Overview"), ("invest", "Invest"), ("hire", "Hire"),
            ("portfolio_talent", "Portfolio talent"),
        )
    )
    section_html = "".join(
        '<section id="' + escape(str(section["key"])) + '" data-section-key="'
        + escape(str(section["key"])) + '"><h2>'
        + escape(str(section["title"])) + '</h2><dl>'
        + "".join(
            f'<div><dt>{escape(str(key).replace("_", " ").title())}</dt><dd>{escape(str(value))}</dd></div>'
            for key, value in dict(section["counts"]).items()
        )
        + "</dl></section>"
        for section in sections
    )
    limitations = "".join(f"<li>{escape(str(item))}</li>" for item in methodology["limitations"])
    applied = int(headline["applied"])
    accepted = int(headline["going_accepted"])
    onsite = int(headline["on_site"])
    submitted = int(headline["submitted_people"])
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{escape(str(metadata["title"]))}</title><link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'%3E%3Crect width='64' height='64' fill='%2300002c'/%3E%3Cpath d='M14 48 29 16h7l14 32h-9l-3-8H25l-3 8h-8Zm14-15h7l-3.5-9L28 33Z' fill='%23fcfbf7'/%3E%3C/svg%3E">
<style>:root{{--navy:#00002c;--burgundy:#80011f;--paper:#fcfbf7;--ink:#171729;--rule:#d5d4db}}*{{box-sizing:border-box}}body{{margin:0;background:var(--paper);color:var(--ink);font:16px/1.5 Avenir,"Avenir Next",system-ui,sans-serif}}header,main,footer{{padding:32px max(24px,6vw)}}header{{color:white;background:var(--navy)}}h1{{max-width:15ch;font-size:clamp(2.7rem,7vw,6rem);line-height:.92}}.lens{{display:flex;flex-wrap:wrap;gap:8px}}.lens span{{padding:10px 14px;border:1px solid var(--rule);background:white}}a:focus-visible,summary:focus-visible{{outline:3px solid #d8a7b4;outline-offset:3px}}.funnel{{display:grid;grid-template-columns:repeat(3,1fr);gap:1px;background:var(--rule)}}.funnel div,section,details{{padding:24px;background:white}}.funnel strong{{display:block;font-size:2rem}}section{{margin-top:24px}}dl div{{display:flex;justify-content:space-between;border-top:1px solid var(--rule);padding:10px 0}}@media(max-width:600px){{.funnel{{grid-template-columns:1fr}}header,main,footer{{padding:24px}}}}@media(prefers-reduced-motion:reduce){{*{{scroll-behavior:auto!important;transition:none!important;animation:none!important}}}}@page{{size:A4;margin:14mm}}@media print{{.lens{{display:none}}section{{break-inside:avoid}}footer{{display:none}}}}</style></head><body>
<header><p>Validated aggregate evidence</p><h1>{escape(str(metadata["title"]))}</h1><p>Applied, attendance, talent evidence, and demonstrated work from one reconciled source model.</p></header>
<main><nav class="lens" aria-label="Partner intent">{lens_labels}</nav><p><strong>No JavaScript is required</strong>. These intent labels are a static reading index; every reader receives the same evidence and order.</p>
<section aria-labelledby="funnel-title"><h2 id="funnel-title">Event participation</h2><div class="funnel"><div data-evidence-count="{applied}"><strong>{applied}</strong>Applied</div><div><strong>{accepted}</strong>Going / accepted</div><div><strong>{onsite}</strong>On site, {onsite / accepted:.1%} attendance conversion</div></div><p>{submitted} applicants have defensible submitted-team evidence. Submission is evidence coverage, not an attendance stage.</p></section>
{section_html}<details open><summary>Evidence trace</summary><p>Definition, denominator, evidence sources, coverage, confidence, and validation state are aggregate-only. No names, profiles, source rows, or suppressed values are exposed.</p></details>
<section id="methodology"><h2>Methodology and data coverage</h2><p>Published non-zero cells meet k={int(methodology["minimum_count"])}. Missing evidence remains unknown.</p><ul>{limitations}</ul></section></main>
<footer>Generated {escape(str(metadata["generated_at"]))}</footer></body></html>'''


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def load_override(path: str | Path) -> dict[str, object]:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot load override: {error}") from error
    if not isinstance(value, dict):
        raise ValueError("override must be an object")
    return value


_RELEASE_OUTPUT_NAMES = frozenset({
    "talent-report-v3.real.aggregate.json",
    "talent-intelligence-v1.real.aggregate.json",
    "talent-brief.real.html", "talent-brief.real.pdf",
    "talent-brief.internal-qa.md", "partner-feedback-template.md",
    "row-level-audit.md", "reproduce-real-report.md",
    "talent-report-v3.real.manifest.json",
})


def _assert_no_symlink_components(path: Path) -> None:
    absolute = path.expanduser().absolute()
    for candidate in (absolute, *absolute.parents):
        if candidate.is_symlink():
            if candidate in {Path("/var"), Path("/tmp")}:
                continue
            raise PermissionError(f"output path contains a symlink: {candidate}")
        if candidate.exists() and candidate != absolute and not candidate.is_dir():
            raise PermissionError(f"output path has a non-directory parent: {candidate}")


def _validate_release_output_root(
    output_root: str | Path, *, export_pdf: bool,
) -> Path:
    """Reject unsafe release destinations before creating or replacing anything."""

    root = Path(output_root).expanduser().absolute()
    _assert_no_symlink_components(root)
    if root == Path(root.anchor) or (root.exists() and not root.is_dir()):
        raise PermissionError("release output root is not a safe directory")
    expected = set(_RELEASE_OUTPUT_NAMES)
    if not export_pdf:
        expected.remove("talent-brief.real.pdf")
    targets = [root / name for name in expected]
    targets.append(root / "private" / "operator-state.real.json")
    for target in targets:
        _assert_no_symlink_components(target)
        if target.exists() and not target.is_file():
            raise PermissionError(
                f"release output target is not a regular file: {target.name}",
            )
    return root


def _atomic_text_write(path: Path, value: str, *, mode: int = 0o644) -> None:
    _assert_no_symlink_components(path)
    if path.exists() and not path.is_file():
        raise PermissionError(f"output target is not a regular file: {path.name}")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent,
    )
    temporary = Path(temporary_name)
    try:
        with open(descriptor, "w", encoding="utf-8", closefd=True) as stream:
            stream.write(value)
            stream.flush()
        temporary.chmod(mode)
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def _json_write(path: Path, value: object) -> None:
    _atomic_text_write(
        path,
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
    )


def _private_json_write(path: Path, value: object) -> None:
    _assert_no_symlink_components(path)
    if path.parent.exists() and not path.parent.is_dir():
        raise PermissionError("private output parent is not a directory")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.parent.chmod(0o700)
    _atomic_text_write(
        path,
        json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n",
        mode=0o600,
    )
    path.chmod(0o600)


def _reproduction_guide(
    generated_at: str, *, semantic_mode: str | None = None,
    exclusion_bindings: bool = False,
) -> str:
    """Return a path-independent recipe whose hash is stable across protected roots."""

    if semantic_mode not in {None, "candidate", "approved"}:
        raise ValueError("semantic reproduction mode is invalid")
    semantic_flag = {
        None: "",
        "candidate": (
            '--semantic-aggregate "$SEMANTIC_AGGREGATE" '
            '--semantic-context "$SEMANTIC_CONTEXT" --semantic-candidate '
        ),
        "approved": (
            '--semantic-aggregate "$SEMANTIC_AGGREGATE" '
            '--semantic-context "$SEMANTIC_CONTEXT" '
            '--semantic-approval "$SEMANTIC_APPROVAL" '
            '--semantic-approval-secret-env SEMANTIC_APPROVAL_SECRET '
            '--semantic-qa "$SEMANTIC_QA" '
        ),
    }[semantic_mode]
    exclusion_flags = (
        '--exclusion-bindings "$EXCLUSION_BINDINGS" '
        '--pseudonym-secret-env REAL_RELEASE_PSEUDONYM_SECRET '
        if exclusion_bindings else ""
    )
    return (
        "# Reproduce the real talent report\n\n"
        "Set each variable to a protected local path, then run from the repository root:\n\n"
        "```bash\n"
        "python3 -m community_os real-release "
        "--event-config \"$EVENT_CONFIG\" "
        "--event-approval \"$EVENT_APPROVAL\" "
        f"{exclusion_flags}"
        "--applications \"$APPLICATIONS_EXPORT\" "
        "--attendance \"$ATTENDANCE_EXPORT\" "
        "--preferences \"$PREFERENCES_EXPORT\" "
        "--submissions \"$SUBMISSIONS_EXPORT\" "
        "--override \"$OVERRIDE_FILE\" "
        "--output \"$OUTPUT_ROOT\" "
        f"{semantic_flag}"
        f"--generated-at '{generated_at}' --pdf\n"
        "```\n\n"
        "The command fails closed on source-hash drift, override drift, unresolved reviews, "
        "contract errors, or privacy errors. The protected manifest records source and output hashes.\n"
    )


def _application_reconciliation(
    path: Path,
    *,
    event_definition: EventDefinition,
) -> tuple[list[dict[str, object]], int]:
    """Normalize application rows and retain only a data-derived rejection count."""

    from community_os.ingest import ingest_csv
    from community_os.source_contract import load_registered_source_contract

    definition = event_definition
    application_source = definition.source("applications")
    if application_source.media_type != "text/csv":
        raise ValueError("legacy application projection requires a configured CSV source")
    result = ingest_csv(
        path,
        load_registered_source_contract(application_source).mapping,
    )
    rows = [
        {
            "external_id": record.external_record_id,
            "email": record.applicant_identity,
            "name": record.values.get("name", ""),
            "occupation": record.values.get("occupation", ""),
            "experience": record.values.get("relevant_experience", ""),
            "impressive_thing": record.values.get("impressive_thing", ""),
            "organization": record.values.get("organization", ""),
            "github": record.values.get("github", ""),
            "linkedin": record.values.get("linkedin", ""),
            "portfolio": record.values.get("portfolio", ""),
            "team_mode": record.values.get("team_mode", ""),
            "team_name": record.values.get("team_name", ""),
        }
        for record in result.records
    ]
    return rows, len(result.rejected)


def _application_rows(
    path: Path,
    *,
    event_definition: EventDefinition,
) -> list[dict[str, object]]:
    """Project configured application rows for callers that do not need rejection metadata."""

    rows, _ = _application_reconciliation(
        path, event_definition=event_definition,
    )
    return rows


def _reviewed_operational_facts(
    override: Mapping[str, object],
    *,
    event_key: str,
) -> dict[str, dict[str, object]]:
    """Return validated non-funnel facts bound to one event without fixed keys or counts."""

    raw_facts = override.get("operational_facts")
    if not isinstance(raw_facts, list):
        raise ValueError("override operational_facts must be a list")
    prefix = f"event:{event_key}:"
    facts: dict[str, dict[str, object]] = {}
    expected_keys = {
        "funnel_stage", "note", "reason", "stable_key", "unit", "value",
    }
    for raw in raw_facts:
        if not isinstance(raw, dict) or set(raw) != expected_keys:
            raise ValueError("reviewed operational fact is invalid")
        stable_key = raw["stable_key"]
        if not isinstance(stable_key, str) or not stable_key.startswith(prefix):
            raise ValueError("reviewed operational fact belongs to another event")
        fact_key = stable_key.removeprefix(prefix)
        if not re.fullmatch(r"[a-z][a-z0-9_]{1,63}", fact_key):
            raise ValueError("reviewed operational fact key is invalid")
        if raw["funnel_stage"] is not False:
            raise ValueError("reviewed operational fact entered the funnel")
        value = raw["value"]
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError("reviewed operational fact value is invalid")
        fields = {
            key: raw[key] for key in ("note", "reason", "unit")
        }
        if any(
            not isinstance(field, str) or not field.strip() or field != field.strip()
            for field in fields.values()
        ):
            raise ValueError("reviewed operational fact metadata is invalid")
        if fact_key in facts:
            raise ValueError("reviewed operational fact key is duplicated")
        facts[fact_key] = {**fields, "value": value}
    return dict(sorted(facts.items()))


def _filter_final_sources(
    preference_records: Iterable[object], submission_records: Iterable[object], *,
    excluded_source_refs: set[str] | frozenset[str] = frozenset(),
):
    """Remove excluded membership rows before building team or project evidence."""
    preference_records = tuple(
        record for record in preference_records
        if str(getattr(record, "external_id", "")) not in excluded_source_refs
    )
    submission_records = tuple(
        record for record in submission_records
        if str(getattr(record, "external_id", "")) not in excluded_source_refs
    )
    preferences: dict[str, dict[str, object]] = {}
    for record in preference_records:
        item = preferences.setdefault(
            str(record.team_name), {"track": str(record.track), "emails": set(), "source_refs": []},
        )
        item["emails"].add(record.email.casefold())
        item["source_refs"].append(record.external_id)
    projects: dict[str, dict[str, object]] = {}
    for record in submission_records:
        item = projects.setdefault(
            str(record.team_name), {
                "track": str(record.track), "emails": set(), "source_refs": [],
                "repository_present": False, "demo_present": False,
            },
        )
        item["emails"].add(record.email.casefold())
        item["source_refs"].append(record.external_id)
        item["repository_present"] = bool(item["repository_present"] or record.repository_present)
        item["demo_present"] = bool(item["demo_present"] or record.demo_present)
    return preference_records, submission_records, preferences, projects


def _group_final_sources(
    preferences_path: Path,
    submissions_path: Path,
    *,
    event_definition: EventDefinition,
):
    from community_os.operator_pipeline import SourceSlot, records_from_source

    return _filter_final_sources(
        records_from_source(
            preferences_path,
            SourceSlot.TRACK,
            selected_sheets=event_definition.source("preferences").sheets,
            source=event_definition.source("preferences"),
        ),
        records_from_source(
            submissions_path,
            SourceSlot.DEVPOST,
            selected_sheets=event_definition.source("submissions").sheets,
            source=event_definition.source("submissions"),
        ),
    )


def _excluded_attendance_records(
    attendance_records: Iterable[object], *, excluded_emails: set[str],
) -> tuple[object, ...]:
    """Require deterministic attendance linkage before subtracting excluded people."""
    if not excluded_emails:
        return ()
    records = tuple(attendance_records)
    matches = tuple(
        record for record in records
        if str(getattr(record, "email", "") or "").strip().casefold()
        in excluded_emails
    )
    matched_emails = {
        str(getattr(record, "email", "") or "").strip().casefold()
        for record in matches
    }
    if matched_emails != excluded_emails:
        raise ValueError("subject exclusions require reviewed attendance linkage")
    return matches


def _validate_semantic_release_context(
    summary: PartnerSemanticSummary,
    *,
    event_key: str,
    source_snapshot_sha256: str,
    total_population: int,
    semantic_context: Mapping[str, object],
) -> None:
    """Bind semantic evidence to the exact report inputs before any output write."""

    from community_os.partner_semantic_projection import (
        validate_partner_semantic_release_context,
    )

    validate_partner_semantic_release_context(summary, semantic_context)
    if summary.event_key != event_key:
        raise ValueError("semantic event does not match release event")
    if summary.total_population != total_population:
        raise ValueError("semantic population does not match release population")
    if not hmac.compare_digest(
        str(summary.source_snapshot_sha256), source_snapshot_sha256,
    ):
        raise ValueError("semantic source snapshot does not match release sources")


def _partner_feedback_template() -> str:
    """Return the reusable partner interview guide for report product learning."""

    return (
        "# Partner feedback session\n\nRole: VC / portfolio talent / hiring company\n\n"
        "1. What did you understand within 90 seconds?\n"
        "2. Which claim did you trust least, and why?\n"
        "3. What decision could this report help you make?\n"
        "4. What were you looking for but could not find?\n"
        "5. Would you forward it internally, and to whom?\n\n"
        "## Future data requests\n\n"
        "6. Which additional aggregate would change a decision? For each request, "
        "record the decision or purpose, acceptable denominator and unknown rate, and "
        "whether applicants can provide it directly.\n"
        "7. Which demographics are truly decision-relevant, and what collection notice "
        "and answer options would make them appropriate?\n\n"
        "## Post-hoc review\n\nRecord repeated decision questions, skipped or "
        "revisited sections, trust friction, missing evidence, and proposed changes "
        "ranked by decision value and implementation cost. Keep qualitative notes "
        "outside report analytics.\n"
    )


def build_real_release(
    *,
    applications_path: str | Path,
    attendance_path: str | Path,
    preferences_path: str | Path,
    submissions_path: str | Path,
    override_path: str | Path,
    output_root: str | Path,
    generated_at: str | None = None,
    export_pdf: bool = False,
    semantic_summary: PartnerSemanticSummary | None = None,
    semantic_context: Mapping[str, object] | None = None,
    classification_projection: Mapping[str, Mapping[str, Iterable[str]]] | None = None,
    enrichment_coverage: Mapping[str, int] | None = None,
    excluded_application_ids: set[str] | frozenset[str] = frozenset(),
    exclusion_set_sha256: str | None = None,
    event_definition: EventDefinition,
    event_approval: EventApproval | None = None,
    excluded_subject_refs_by_application_id: Mapping[str, str] | None = None,
    pseudonym_secret: bytes | None = None,
) -> dict[str, Path]:
    """Reproduce all real aggregate, report, QA, and private audit artifacts."""

    from community_os.operator_pipeline import SourceSlot, records_from_source
    from community_os.report_contract import load_report_contract
    from community_os.talent_intelligence_contract import load_talent_intelligence_contract

    definition = event_definition
    if event_approval is None:
        raise ValueError("event approval is required for a protected real release")
    sources = {
        "applications": Path(applications_path), "attendance": Path(attendance_path),
        "preferences": Path(preferences_path), "submissions": Path(submissions_path),
    }
    source_hashes = {key: sha256_file(path) for key, path in sources.items()}
    source_bindings = _validated_event_approval_bindings(
        definition,
        event_approval=event_approval,
        observed_source_hashes=source_hashes,
    )
    release_context = _release_manifest_context(
        definition,
        source_bindings=source_bindings,
        code_provenance=_code_provenance(),
        event_approval_sha256=event_approval.sha256,
    )
    override_file = Path(override_path)
    override = load_override(override_file)
    classification_review = _validated_classification_review(
        override.get("classification_review")
    )
    operational_facts = _reviewed_operational_facts(
        override, event_key=definition.event_key,
    )
    timestamp = generated_at or datetime.now(UTC).isoformat().replace("+00:00", "Z")

    all_applications, rejected_application_count = _application_reconciliation(
        sources["applications"], event_definition=definition,
    )
    all_application_ids = {str(item["external_id"]) for item in all_applications}
    if (
        not isinstance(excluded_application_ids, (set, frozenset))
        or any(not isinstance(value, str) or not value for value in excluded_application_ids)
        or not excluded_application_ids.issubset(all_application_ids)
    ):
        raise ValueError("excluded application identifiers are invalid")
    if excluded_application_ids and not re.fullmatch(
        r"[0-9a-f]{64}", str(exclusion_set_sha256 or ""),
    ):
        raise ValueError("subject exclusion set hash is required")
    _validate_event_approval_exclusions(
        event_approval,
        excluded_application_ids=excluded_application_ids,
        excluded_subject_refs_by_application_id=(
            excluded_subject_refs_by_application_id
        ),
        exclusion_set_sha256=exclusion_set_sha256,
        pseudonym_secret=pseudonym_secret,
    )
    excluded_applications = [
        item for item in all_applications
        if str(item["external_id"]) in excluded_application_ids
    ]
    excluded_emails = {
        str(item.get("email") or "").strip().casefold()
        for item in excluded_applications if str(item.get("email") or "").strip()
    }
    applications = [
        item for item in all_applications
        if str(item["external_id"]) not in excluded_application_ids
    ]
    population_sha256 = _population_sha256(
        (str(item["external_id"]) for item in applications),
        event_key=definition.event_key,
    )
    if semantic_summary is not None:
        from community_os.enrichment.release_pipeline import canonical_hash

        if semantic_context is None:
            raise ValueError("semantic release context is required")
        _validate_semantic_release_context(
            semantic_summary,
            event_key=definition.event_key,
            source_snapshot_sha256=canonical_hash(source_hashes),
            total_population=len(applications),
            semantic_context=semantic_context,
        )
    application_map = {str(item["external_id"]): item for item in applications}
    attendance_records = records_from_source(
        sources["attendance"],
        SourceSlot.LUMA,
        source=definition.source("attendance"),
    )
    accepted_stage = definition.funnel_stage("accepted")
    present_stage = definition.funnel_stage("present")

    def stage_value(record: object, field: str | None) -> object:
        if field is None:
            return None
        if field == "checked_in_at":
            return getattr(record, "checked_in_at", None)
        payload = getattr(record, "payload", {})
        return payload.get(field) if isinstance(payload, Mapping) else None

    def stage_match(record: object, stage: object) -> bool:
        match = str(getattr(stage, "match"))
        if match == "any_row":
            return True
        value = stage_value(record, getattr(stage, "field"))
        if match == "non_empty":
            return bool(str(value or "").strip())
        if match == "value_in":
            allowed = {
                str(item).casefold() for item in getattr(stage, "accepted_values")
            }
            return str(value or "").strip().casefold() in allowed
        raise ValueError("configured funnel match is unsupported")

    full_observed = {
        "applied": len(all_applications),
        "going_accepted": sum(stage_match(record, accepted_stage) for record in attendance_records),
        "on_site_builders": sum(stage_match(record, present_stage) for record in attendance_records),
    }
    reviewed_attendance = apply_attendance_overrides(
        full_observed, override, event_key=definition.event_key,
    )
    excluded_attendance = _excluded_attendance_records(
        attendance_records, excluded_emails=excluded_emails,
    )
    attendance = {
        "applied": reviewed_attendance["applied"] - len(excluded_application_ids),
        "going_accepted": reviewed_attendance["going_accepted"] - sum(
            stage_match(record, accepted_stage) for record in excluded_attendance
        ),
        "on_site_builders": reviewed_attendance["on_site_builders"] - sum(
            stage_match(record, present_stage) for record in excluded_attendance
        ),
    }
    if (
        min(attendance.values()) < 0
        or attendance["going_accepted"] > attendance["applied"]
        or attendance["on_site_builders"] > attendance["going_accepted"]
    ):
        raise ValueError("subject exclusions do not reconcile to attendance stages")

    preference_records, submission_records, preferences, projects = _group_final_sources(
        sources["preferences"],
        sources["submissions"],
        event_definition=definition,
    )
    person_links = override.get("person_links")
    quarantined_refs = override.get("quarantined_refs")
    if not isinstance(person_links, dict) or not isinstance(quarantined_refs, list):
        raise ValueError("override person review decisions are missing")
    source_people = [
        {"source_ref": record.external_id, "email": record.email, "name": record.name,
         "team": record.team_name, "source": "preference"}
        for record in preference_records
    ] + [
        {"source_ref": record.external_id, "email": record.email, "name": record.name,
         "team": record.team_name, "source": "devpost"}
        for record in submission_records
    ]
    excluded_source_refs = {
        str(item["source_ref"]) for item in source_people
        if str(item.get("email") or "").strip().casefold() in excluded_emails
        or str(person_links.get(str(item["source_ref"])) or "") in excluded_application_ids
    }
    preference_records, submission_records, preferences, projects = _filter_final_sources(
        preference_records, submission_records,
        excluded_source_refs=excluded_source_refs,
    )
    source_people = [
        item for item in source_people
        if str(item["source_ref"]) not in excluded_source_refs
    ]
    team_links = override.get("team_links")
    if not isinstance(team_links, dict):
        raise ValueError("override team_links must be an object")
    reviewed_team_links = {
        str(preference): str(project) for preference, project in team_links.items()
        if str(preference) in preferences and str(project) in projects
    }
    matches = match_teams(
        preferences, projects, reviewed_links=reviewed_team_links,
    )
    reviewed_person_links = {
        str(key): str(value) for key, value in person_links.items()
        if str(key) not in excluded_source_refs and str(value) not in excluded_application_ids
    }
    resolution = resolve_submission_people(
        application_map, source_people,
        reviewed_links=reviewed_person_links,
        quarantined_refs={
            str(value) for value in quarantined_refs
            if str(value) not in excluded_source_refs
        },
    )
    if resolution.unresolved_refs:
        raise ValueError(f"{len(resolution.unresolved_refs)} membership reviews remain unresolved")
    submitted_ids = set(resolution.resolved_application_ids)

    team_applicants = sum(
        "team" in str(item["team_mode"]).casefold() and "solo" not in str(item["team_mode"]).casefold()
        for item in applications
    )
    solo_applicants = len(applications) - team_applicants
    track_counts = {
        track: sum(str(project["track"]) == track for project in projects.values())
        for track in sorted({str(project["track"]) for project in projects.values()})
    }
    repository_projects = sum(bool(project["repository_present"]) for project in projects.values())
    demo_projects = sum(bool(project["demo_present"]) for project in projects.values())
    github_supplied = sum(bool(str(item["github"]).strip()) for item in applications)

    v3 = build_v3_payload(
        applied=attendance["applied"], going_accepted=attendance["going_accepted"],
        on_site_builders=attendance["on_site_builders"], track_project_counts=track_counts,
        submitted_people=len(submitted_ids), github_supplied=github_supplied,
        team_applicants=team_applicants, solo_applicants=solo_applicants,
        repository_projects=repository_projects, demo_projects=demo_projects,
        generated_at=timestamp, event_definition=definition,
    )
    publication_projection = (
        None if classification_projection is None else {
            key: value for key, value in classification_projection.items()
            if key in application_map
        }
    )
    v1 = build_v1_payload(
        applications, going_accepted=attendance["going_accepted"],
        on_site_builders=attendance["on_site_builders"],
        submitted_application_ids=submitted_ids, generated_at=timestamp,
        classification_projection=publication_projection,
        enrichment_coverage=enrichment_coverage,
        rich_semantic_reviewed=semantic_summary is not None,
        event_definition=definition,
    )
    root = _validate_release_output_root(output_root, export_pdf=export_pdf)
    root.mkdir(parents=True, exist_ok=True)
    v3_path = root / "talent-report-v3.real.aggregate.json"
    v1_path = root / "talent-intelligence-v1.real.aggregate.json"
    _json_write(v3_path, v3)
    _json_write(v1_path, v1)
    validated_v3 = load_report_contract(v3_path)
    validated_v1 = load_talent_intelligence_contract(v1_path)
    confidence_summary = classification_confidence_summary(v1)

    public_sections = []
    for dimension in validated_v1.dimensions:
        public_sections.append({
            "key": dimension.key, "title": dimension.label,
            "counts": {
                item.label: item.count.value if item.count.value is not None else "Withheld"
                for item in dimension.items
            },
        })
    public_sections.extend((
        {
            "key": "evidence_intersections", "title": "Privacy-safe intersections",
            "counts": {
                item.label: item.count.value if item.count.value is not None else "Withheld"
                for item in validated_v1.intersections
            },
        },
        {
            "key": "qualitative_themes", "title": "Aggregate qualitative themes",
            "counts": {
                item.label: item.count.value if item.count.value is not None else "Withheld"
                for item in validated_v1.qualitative_themes
            },
        },
        {
            "key": "evidence_coverage", "title": "Evidence coverage",
            "counts": {
                item.label: (
                    f"{item.covered.value if item.covered.value is not None else 'Withheld'} / "
                    f"{item.eligible.value if item.eligible.value is not None else 'Withheld'}"
                )
                for item in validated_v1.evidence_coverage
            },
        },
    ))
    gap = attendance["on_site_builders"] - len(submitted_ids)
    coverage = dict(enrichment_coverage or {})
    coresignal_coverage = int(coverage.get("coresignal", 0))
    publication = {
        "metadata": {"title": f"{definition.event_name} Talent Brief", "generated_at": timestamp},
        "headline": {
            "applied": attendance["applied"], "going_accepted": attendance["going_accepted"],
            "on_site": attendance["on_site_builders"], "submitted_people": len(submitted_ids),
        },
        "sections": public_sections,
        "methodology": {
            "minimum_count": definition.privacy.minimum_count,
            "limitations": [
                f"{gap} on-site builders lack defensible submitted-team linkage",
                f"{len(resolution.quarantined_refs)} source membership records were quarantined because they could not be linked safely",
                "External-source availability is retained in private QA, not published as a talent finding",
            ],
        },
    }
    from community_os.partner_report import render_partner_talent_report

    html_path = root / "talent-brief.real.html"
    _atomic_text_write(
        html_path,
        render_partner_talent_report(
            validated_v1, validated_v3,
            semantic_summary=semantic_summary,
            semantic_context=semantic_context,
        ),
    )

    state = {
        "state_version": "real-operator-state-v1", "generated_at": timestamp,
        "event": release_context["event"],
        "sources": {
            "application": {str(item["external_id"]): item for item in applications},
            "preference": {
                str(item["source_ref"]): item for item in source_people
                if item["source"] == "preference"
            },
            "devpost": {
                str(item["source_ref"]): item for item in source_people
                if item["source"] == "devpost"
            },
        },
        "team_matches": matches,
        "person_links": reviewed_person_links,
        "quarantined_refs": sorted(resolution.quarantined_refs),
        "submitted_application_ids": sorted(submitted_ids),
        "enrichment_coverage": coverage,
        "semantic_enrichment_reviewed": semantic_summary is not None,
        "classifications": {str(item["external_id"]): {
            key: sorted(value) for key, value in (
                publication_projection[str(item["external_id"])]
                if publication_projection is not None else classify_application(item)
            ).items()
        } for item in applications},
        "aggregates": {"v3": str(v3_path.name), "v1": str(v1_path.name)},
    }
    state_path = root / "private" / "operator-state.real.json"
    _private_json_write(state_path, state)

    qa_path = root / "talent-brief.internal-qa.md"
    coresignal_qa = (
        f"Coresignal: {coresignal_coverage} protected records incorporated into reviewed classifications."
        if coresignal_coverage and semantic_summary is not None
        else f"Coresignal: {coresignal_coverage} protected records observed; semantic incorporation remains unconfirmed."
        if coresignal_coverage
        else "Coresignal: off; no live professional-profile enrichment."
    )
    classifier_qa = (
        f"Classifier: semantic-v1 via {classification_review['model']}; minimized structured inputs only; "
        f"review status {classification_review['status']}."
        if classification_review["classifier_version"] == "semantic-v1"
        else f"Classifier: deterministic-rules-v1; no LLM classification was run; review status {classification_review['status']}."
    )
    attendance_conversion = (
        "not available"
        if attendance["going_accepted"] == 0
        else f"{attendance['on_site_builders'] / attendance['going_accepted']:.1%}"
    )
    operational_fact_lines = "".join(
        f"- {key.replace('_', ' ').title()}: {fact['value']} {fact['unit']}; "
        f"{str(fact['note']).rstrip('.')}\n"
        for key, fact in operational_facts.items()
    )
    _atomic_text_write(
        qa_path,
        "# Talent brief internal QA\n\n"
        f"- Source hashes: {len(source_bindings)} of {len(definition.sources)} matched.\n"
        f"- Applicants: {len(applications)}; artifacts rejected: {rejected_application_count}.\n"
        f"- Rights exclusions propagated: {len(excluded_application_ids)}.\n"
        f"- Attendance override before rights exclusions: {full_observed['going_accepted']} to "
        f"{reviewed_attendance['going_accepted']} going; {full_observed['on_site_builders']} to "
        f"{reviewed_attendance['on_site_builders']} on site.\n"
        f"- Attendance conversion: {attendance_conversion}.\n"
        f"- Teams: {len(matches)} of {len(preferences)} matched; tracks: {track_counts}.\n"
        f"- Submitted-team applicant identities: {len(submitted_ids)}; gap to on site: {gap}.\n"
        f"- Identity decisions: {len(reviewed_person_links)} reviewed links; {len(resolution.quarantined_refs)} quarantines; 0 unresolved.\n"
        f"- Artifacts: repositories {repository_projects}/{len(projects)}; demos {demo_projects}/{len(projects)}.\n"
        f"{operational_fact_lines}"
        f"- {coresignal_qa}\n"
        f"- {classifier_qa}\n"
        f"- Classification confidence distribution: {json.dumps(confidence_summary, sort_keys=True)}.\n",
    )
    feedback_path = root / "partner-feedback-template.md"
    _atomic_text_write(feedback_path, _partner_feedback_template())
    audit_doc_path = root / "row-level-audit.md"
    _atomic_text_write(
        audit_doc_path,
        "# Protected row-level audit\n\n"
        "Run `python3 -m community_os real-audit --state output/real/private/operator-state.real.json --source application --row-id <stable-id>`.\n"
        "Sources are `application`, `preference`, or `devpost`. Output may contain PII and must remain local.\n",
    )
    reproduce_path = root / "reproduce-real-report.md"
    _atomic_text_write(
        reproduce_path,
        _reproduction_guide(
            timestamp,
            semantic_mode=(
                None if semantic_summary is None
                else "approved"
                if semantic_summary.semantic_release_approval_sha256 is not None
                else "candidate"
            ),
            exclusion_bindings=bool(excluded_application_ids),
        ),
    )

    outputs = {
        "v3": v3_path, "v1": v1_path, "html": html_path, "qa": qa_path,
        "feedback": feedback_path, "audit_doc": audit_doc_path, "state": state_path,
        "reproduce": reproduce_path,
    }
    if export_pdf:
        from community_os.pdf_export import export_pdf as write_pdf

        pdf_path = root / "talent-brief.real.pdf"
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=".talent-brief.real.", suffix=".pdf", dir=root,
        )
        os.close(descriptor)
        Path(temporary_name).unlink(missing_ok=True)
        try:
            write_pdf(
                html_path, temporary_name, stable_timestamp=timestamp,
            )
            temporary_pdf = Path(temporary_name)
            if temporary_pdf.is_symlink() or not temporary_pdf.is_file():
                raise PermissionError("PDF exporter did not produce a regular file")
            temporary_pdf.replace(pdf_path)
        finally:
            Path(temporary_name).unlink(missing_ok=True)
        outputs["pdf"] = pdf_path
    output_hashes = {
        path.name: sha256_file(path) for key, path in outputs.items() if key != "state"
    }
    manifest = {
        "manifest_version": "talent-real-release-v1", "generated_at": timestamp,
        "release_context": release_context,
        "source_hashes": source_hashes,
        "override": {
            "sha256": sha256_file(override_file),
            "version": override["override_version"],
            "aggregate_correction_count": len(override["corrections"]),
            "application_status": "applied",
        },
        "classifier": {
            "version": classification_review["classifier_version"],
            "model": classification_review["model"],
            "prompt_version": classification_review["prompt_version"], "prompt_hash": None,
            "processor_approval_hash": classification_review["processor_approval_hash"],
            "review_status": classification_review["status"],
            "reviewer": classification_review["reviewer"],
            "reviewed_at": classification_review.get("reviewed_at"),
            "spot_check_count": classification_review.get("spot_check_count"),
            "confidence_distribution": confidence_summary,
        },
        "identity_review": {
            "reviewed_links": len(reviewed_person_links),
            "quarantined": len(resolution.quarantined_refs),
            "unresolved": 0,
        },
        "subject_exclusions": {
            "excluded_count": len(excluded_application_ids),
            "exclusion_set_sha256": exclusion_set_sha256,
            "reason_code": "rights_request",
        },
        "population": {
            "count": len(applications),
            "sha256": population_sha256,
        },
        "aggregates": {
            "applied": len(applications), "going_accepted": attendance["going_accepted"],
            "on_site": attendance["on_site_builders"], "submitted_team_people": len(submitted_ids),
            "submitted_gap": gap, "teams": len(matches), "projects": len(projects),
        },
        "operational_facts": operational_facts,
        "semantic_enrichment": (
            semantic_summary_manifest_binding(semantic_summary)
            if semantic_summary is not None else None
        ),
        "output_hashes": dict(sorted(output_hashes.items())),
    }
    manifest_path = root / "talent-report-v3.real.manifest.json"
    _json_write(manifest_path, manifest)
    outputs["manifest"] = manifest_path
    return outputs


def audit_row(state_path: str | Path, *, source: str, row_id: str) -> dict[str, object]:
    """Trace one protected source row through identity, team, classification, and aggregates."""

    state = json.loads(Path(state_path).read_text(encoding="utf-8"))
    sources = state.get("sources", {})
    if source not in sources or row_id not in sources[source]:
        raise ValueError("source row was not found")
    row = sources[source][row_id]
    application_id = row_id if source == "application" else state.get("person_links", {}).get(row_id)
    if source != "application" and application_id is None:
        email = str(row.get("email") or "").casefold()
        application_id = next(
            (key for key, value in sources["application"].items() if str(value.get("email") or "").casefold() == email),
            None,
        )
    decision = (
        "quarantined" if row_id in state.get("quarantined_refs", [])
        else "linked" if application_id else "unresolved"
    )
    submitted = application_id in set(state.get("submitted_application_ids", []))
    coverage = state.get("enrichment_coverage", {})
    if not isinstance(coverage, dict):
        coverage = {}
    # Provider coverage is cohort-level only. Keep each row observed-only until
    # the audit state carries reviewed, source-specific provenance for that row.
    github_observed = int(coverage.get("github", 0)) > 0
    coresignal_observed = int(coverage.get("coresignal", 0)) > 0
    return {
        "source_ingestion": {"source": source, "row_id": row_id},
        "canonical_record": row,
        "identity_resolution": {"application_id": application_id, "decision": decision},
        "manual_decisions": state.get("person_links", {}).get(row_id),
        "team_membership": row.get("team"),
        "submission_linkage": submitted,
        "enrichment": {
            "coresignal": (
                "observed_only" if coresignal_observed else "off"
            ),
            "github_live": (
                "observed_only" if github_observed else "not_run"
            ),
        },
        "semantic_classifications": state.get("classifications", {}).get(application_id),
        "aggregate_cells_affected": ["submitted_team_people"] if submitted else [],
        "rendered_claims_affected": ["submission_evidence_coverage"] if submitted else [],
    }
