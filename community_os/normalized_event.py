"""Immutable, provider-neutral records for one normalized event run."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum
import hashlib
from pathlib import Path
import re

from community_os.config import SourceMapping
from community_os.ingest.base import IngestResult, RejectionCode, ingest_csv, ingest_table


_EVENT_KEY = re.compile(r"[a-z0-9][a-z0-9_-]{1,127}")
_ROLE = re.compile(r"[a-z][a-z0-9_]{0,63}")
_SHA256 = re.compile(r"[0-9a-f]{64}")


class EntityKind(StrEnum):
    """Entity namespaces supported by deterministic stable references."""

    APPLICANT = "applicant"
    TEAM = "team"
    PROJECT = "project"
    SOURCE_RECORD = "source_record"


class StableIdStrategy(StrEnum):
    """Allowed sources for a stable reference, deliberately excluding row order."""

    PROVIDER_ID = "provider_id"
    CANONICAL_CONTENT_KEY = "canonical_content_key"


class SourceCoverageState(StrEnum):
    """Deterministic availability state for one configured source role."""

    AVAILABLE = "available"
    MISSING_OPTIONAL = "missing_optional"
    UNAVAILABLE = "unavailable"


class RejectionReason(StrEnum):
    """Bounded reasons that may be retained without raw rejected-row content."""

    MISSING_STABLE_ID = "missing_stable_id"
    INVALID_RELATION = "invalid_relation"
    MALFORMED_RECORD = "malformed_record"


def stable_reference(
    *,
    event_key: str,
    kind: EntityKind,
    strategy: StableIdStrategy,
    stable_value: str,
) -> str:
    """Return an event-scoped opaque reference independent of input row order."""

    if not _EVENT_KEY.fullmatch(event_key):
        raise ValueError("event_key must be a lowercase stable key")
    if not isinstance(kind, EntityKind):
        raise TypeError("kind must be an EntityKind")
    if not isinstance(strategy, StableIdStrategy):
        raise TypeError("strategy must be a StableIdStrategy")
    if not isinstance(stable_value, str) or not stable_value.strip():
        raise ValueError("stable_value must be a non-empty string")
    if stable_value != stable_value.strip():
        raise ValueError("stable_value must already be canonical and trimmed")

    event_scope = hashlib.sha256(event_key.encode("utf-8")).hexdigest()
    canonical = "\x00".join((event_key, kind.value, strategy.value, stable_value))
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return f"{kind.value}_{event_scope}_{digest}"


def _validate_ref(value: str, kind: EntityKind, *, event_key: str | None = None) -> None:
    match = re.fullmatch(
        rf"{re.escape(kind.value)}_([0-9a-f]{{64}})_[0-9a-f]{{64}}",
        value,
    )
    if match is None:
        raise ValueError(f"invalid {kind.value} reference")
    if event_key is not None:
        expected_scope = hashlib.sha256(event_key.encode("utf-8")).hexdigest()
        if match.group(1) != expected_scope:
            raise ValueError(f"{kind.value} reference belongs to another event")


@dataclass(frozen=True, slots=True)
class NormalizedApplicant:
    ref: str
    source_refs: tuple[str, ...] = ()
    github_supplied: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "source_refs", tuple(sorted(self.source_refs)))
        _validate_ref(self.ref, EntityKind.APPLICANT)
        if not isinstance(self.github_supplied, bool):
            raise TypeError("github_supplied must be a boolean")
        for source_ref in self.source_refs:
            _validate_ref(source_ref, EntityKind.SOURCE_RECORD)
        if len(self.source_refs) != len(set(self.source_refs)):
            raise ValueError("applicant source references must be unique")


@dataclass(frozen=True, slots=True)
class NormalizedAttendance:
    applicant_ref: str
    source_ref: str
    accepted: bool | None
    present: bool | None

    def __post_init__(self) -> None:
        _validate_ref(self.applicant_ref, EntityKind.APPLICANT)
        _validate_ref(self.source_ref, EntityKind.SOURCE_RECORD)
        for label, value in (("accepted", self.accepted), ("present", self.present)):
            if value is not None and not isinstance(value, bool):
                raise TypeError(f"{label} must be a boolean or None")


@dataclass(frozen=True, slots=True)
class NormalizedTeam:
    ref: str
    track: str | None = None

    def __post_init__(self) -> None:
        _validate_ref(self.ref, EntityKind.TEAM)
        if self.track is not None and (
            not isinstance(self.track, str)
            or not self.track.strip()
            or self.track != self.track.strip()
        ):
            raise ValueError("team track must be a non-empty trimmed string or None")


@dataclass(frozen=True, slots=True)
class NormalizedProject:
    ref: str
    team_ref: str | None = None
    submitted: bool | None = True
    track: str | None = None
    repository_supplied: bool | None = None
    demo_supplied: bool | None = None

    def __post_init__(self) -> None:
        _validate_ref(self.ref, EntityKind.PROJECT)
        if self.team_ref is not None:
            _validate_ref(self.team_ref, EntityKind.TEAM)
        if self.submitted is not None and not isinstance(self.submitted, bool):
            raise TypeError("submitted must be a boolean or None")
        for label, value in (
            ("repository_supplied", self.repository_supplied),
            ("demo_supplied", self.demo_supplied),
        ):
            if value is not None and not isinstance(value, bool):
                raise TypeError(f"{label} must be a boolean or None")
        if self.track is not None and (
            not isinstance(self.track, str)
            or not self.track.strip()
            or self.track != self.track.strip()
        ):
            raise ValueError("project track must be a non-empty trimmed string or None")


@dataclass(frozen=True, slots=True)
class TeamMembership:
    team_ref: str
    applicant_ref: str

    def __post_init__(self) -> None:
        _validate_ref(self.team_ref, EntityKind.TEAM)
        _validate_ref(self.applicant_ref, EntityKind.APPLICANT)


@dataclass(frozen=True, slots=True)
class SubmittedProjectMembership:
    project_ref: str
    applicant_ref: str

    def __post_init__(self) -> None:
        _validate_ref(self.project_ref, EntityKind.PROJECT)
        _validate_ref(self.applicant_ref, EntityKind.APPLICANT)


@dataclass(frozen=True, slots=True)
class SourceCoverage:
    source_role: str
    required: bool
    state: SourceCoverageState

    def __post_init__(self) -> None:
        if not _ROLE.fullmatch(self.source_role):
            raise ValueError("source_role must be a lowercase key")
        if not isinstance(self.required, bool):
            raise TypeError("required must be a boolean")
        if not isinstance(self.state, SourceCoverageState):
            raise TypeError("state must be a SourceCoverageState")
        if self.required and self.state is SourceCoverageState.MISSING_OPTIONAL:
            raise ValueError("a required source cannot be marked missing_optional")


@dataclass(frozen=True, slots=True)
class RejectedRow:
    source_role: str
    source_sha256: str
    row_number: int
    reason: RejectionReason
    source_partition: str | None = None

    def __post_init__(self) -> None:
        if not _ROLE.fullmatch(self.source_role):
            raise ValueError("source_role must be a lowercase key")
        if not _SHA256.fullmatch(self.source_sha256):
            raise ValueError("source_sha256 must be a lowercase SHA-256")
        if (
            isinstance(self.row_number, bool)
            or not isinstance(self.row_number, int)
            or self.row_number < 1
        ):
            raise ValueError("row_number must be a positive integer")
        if not isinstance(self.reason, RejectionReason):
            raise TypeError("reason must be a RejectionReason")
        if self.source_partition is not None and (
            not isinstance(self.source_partition, str)
            or not self.source_partition.strip()
            or self.source_partition != self.source_partition.strip()
            or len(self.source_partition) > 128
        ):
            raise ValueError("source_partition must be a safe trimmed label or None")


@dataclass(frozen=True, slots=True)
class MappedSourceInput:
    """One transient mapped CSV source supplied to event normalization."""

    role: str
    required: bool
    path: Path | None
    mapping: SourceMapping
    positive_values: tuple[str, ...] = ()
    sheets: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not _ROLE.fullmatch(self.role):
            raise ValueError("source role must be a lowercase key")
        if not isinstance(self.required, bool):
            raise TypeError("required must be a boolean")
        if self.path is not None:
            object.__setattr__(self, "path", Path(self.path))
        if not isinstance(self.mapping, SourceMapping):
            raise TypeError("mapping must be a SourceMapping")
        normalized_values = tuple(
            sorted({value.strip().casefold() for value in self.positive_values if value.strip()})
        )
        object.__setattr__(self, "positive_values", normalized_values)
        normalized_sheets = tuple(self.sheets)
        if len(normalized_sheets) != len(set(normalized_sheets)) or any(
            not isinstance(sheet, str)
            or not sheet.strip()
            or sheet != sheet.strip()
            or len(sheet) > 128
            for sheet in normalized_sheets
        ):
            raise ValueError("sheets must contain unique safe trimmed labels")
        object.__setattr__(self, "sheets", normalized_sheets)


@dataclass(frozen=True, slots=True)
class NormalizedEventData:
    """Canonical normalized records and relations for one event."""

    event_key: str
    applicants: tuple[NormalizedApplicant, ...] = ()
    attendance: tuple[NormalizedAttendance, ...] = ()
    teams: tuple[NormalizedTeam, ...] = ()
    projects: tuple[NormalizedProject, ...] = ()
    team_memberships: tuple[TeamMembership, ...] = ()
    submitted_project_memberships: tuple[SubmittedProjectMembership, ...] = ()
    coverage: tuple[SourceCoverage, ...] = ()
    rejected_rows: tuple[RejectedRow, ...] = ()

    @classmethod
    def create(
        cls,
        *,
        event_key: str,
        applicants: Iterable[NormalizedApplicant] = (),
        attendance: Iterable[NormalizedAttendance] = (),
        teams: Iterable[NormalizedTeam] = (),
        projects: Iterable[NormalizedProject] = (),
        team_memberships: Iterable[TeamMembership] = (),
        submitted_project_memberships: Iterable[SubmittedProjectMembership] = (),
        coverage: Iterable[SourceCoverage] = (),
        rejected_rows: Iterable[RejectedRow] = (),
    ) -> NormalizedEventData:
        """Create a relation-checked contract with deterministic tuple ordering."""

        return cls(
            event_key=event_key,
            applicants=tuple(sorted(applicants, key=lambda item: item.ref)),
            attendance=tuple(
                sorted(
                    attendance,
                    key=lambda item: (item.applicant_ref, item.source_ref),
                )
            ),
            teams=tuple(sorted(teams, key=lambda item: item.ref)),
            projects=tuple(sorted(projects, key=lambda item: item.ref)),
            team_memberships=tuple(
                sorted(team_memberships, key=lambda item: (item.team_ref, item.applicant_ref))
            ),
            submitted_project_memberships=tuple(
                sorted(
                    submitted_project_memberships,
                    key=lambda item: (item.project_ref, item.applicant_ref),
                )
            ),
            coverage=tuple(sorted(coverage, key=lambda item: item.source_role)),
            rejected_rows=tuple(
                sorted(
                    rejected_rows,
                    key=lambda item: (
                        item.source_role,
                        item.source_sha256,
                        item.source_partition or "",
                        item.row_number,
                    ),
                )
            ),
        )

    def __post_init__(self) -> None:
        if not _EVENT_KEY.fullmatch(self.event_key):
            raise ValueError("event_key must be a lowercase stable key")

        object.__setattr__(
            self,
            "applicants",
            tuple(sorted(self.applicants, key=lambda item: item.ref)),
        )
        object.__setattr__(
            self,
            "attendance",
            tuple(
                sorted(
                    self.attendance,
                    key=lambda item: (item.applicant_ref, item.source_ref),
                )
            ),
        )
        object.__setattr__(
            self,
            "teams",
            tuple(sorted(self.teams, key=lambda item: item.ref)),
        )
        object.__setattr__(
            self,
            "projects",
            tuple(sorted(self.projects, key=lambda item: item.ref)),
        )
        object.__setattr__(
            self,
            "team_memberships",
            tuple(
                sorted(
                    self.team_memberships,
                    key=lambda item: (item.team_ref, item.applicant_ref),
                )
            ),
        )
        object.__setattr__(
            self,
            "submitted_project_memberships",
            tuple(
                sorted(
                    self.submitted_project_memberships,
                    key=lambda item: (item.project_ref, item.applicant_ref),
                )
            ),
        )
        object.__setattr__(
            self,
            "coverage",
            tuple(sorted(self.coverage, key=lambda item: item.source_role)),
        )
        object.__setattr__(
            self,
            "rejected_rows",
            tuple(
                sorted(
                    self.rejected_rows,
                    key=lambda item: (item.source_role, item.source_sha256, item.row_number),
                )
            ),
        )

        applicant_refs = {item.ref for item in self.applicants}
        team_refs = {item.ref for item in self.teams}
        project_refs = {item.ref for item in self.projects}
        if len(applicant_refs) != len(self.applicants):
            raise ValueError("applicant references must be unique")
        if len(team_refs) != len(self.teams):
            raise ValueError("team references must be unique")
        if len(project_refs) != len(self.projects):
            raise ValueError("project references must be unique")

        for applicant in self.applicants:
            _validate_ref(applicant.ref, EntityKind.APPLICANT, event_key=self.event_key)
            for source_ref in applicant.source_refs:
                _validate_ref(
                    source_ref,
                    EntityKind.SOURCE_RECORD,
                    event_key=self.event_key,
                )
        for observation in self.attendance:
            _validate_ref(
                observation.applicant_ref,
                EntityKind.APPLICANT,
                event_key=self.event_key,
            )
            _validate_ref(
                observation.source_ref,
                EntityKind.SOURCE_RECORD,
                event_key=self.event_key,
            )
        for team in self.teams:
            _validate_ref(team.ref, EntityKind.TEAM, event_key=self.event_key)
        for project in self.projects:
            _validate_ref(project.ref, EntityKind.PROJECT, event_key=self.event_key)
            if project.team_ref is not None:
                _validate_ref(project.team_ref, EntityKind.TEAM, event_key=self.event_key)
        for membership in self.team_memberships:
            _validate_ref(membership.team_ref, EntityKind.TEAM, event_key=self.event_key)
            _validate_ref(
                membership.applicant_ref,
                EntityKind.APPLICANT,
                event_key=self.event_key,
            )
        for membership in self.submitted_project_memberships:
            _validate_ref(
                membership.project_ref,
                EntityKind.PROJECT,
                event_key=self.event_key,
            )
            _validate_ref(
                membership.applicant_ref,
                EntityKind.APPLICANT,
                event_key=self.event_key,
            )

        for project in self.projects:
            if project.team_ref is not None and project.team_ref not in team_refs:
                raise ValueError("project references an unknown team")
        for membership in self.team_memberships:
            if membership.team_ref not in team_refs:
                raise ValueError("team membership references an unknown team")
            if membership.applicant_ref not in applicant_refs:
                raise ValueError("team membership references an unknown applicant")
        for observation in self.attendance:
            if observation.applicant_ref not in applicant_refs:
                raise ValueError("attendance references an unknown applicant")
        submitted_projects = {item.ref for item in self.projects if item.submitted is True}
        for membership in self.submitted_project_memberships:
            if membership.project_ref not in submitted_projects:
                raise ValueError("submitted membership references an unknown submission")
            if membership.applicant_ref not in applicant_refs:
                raise ValueError("submitted membership references an unknown applicant")

        if len(self.team_memberships) != len(set(self.team_memberships)):
            raise ValueError("team memberships must be unique")
        if len(self.submitted_project_memberships) != len(
            set(self.submitted_project_memberships)
        ):
            raise ValueError("submitted project memberships must be unique")
        coverage_roles = [item.source_role for item in self.coverage]
        if len(coverage_roles) != len(set(coverage_roles)):
            raise ValueError("source coverage roles must be unique")


def _source_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _mapped_source_ref(event_key: str, role: str, external_record_id: str) -> str:
    return stable_reference(
        event_key=event_key,
        kind=EntityKind.SOURCE_RECORD,
        strategy=StableIdStrategy.PROVIDER_ID,
        stable_value=f"{role}:{external_record_id}",
    )


def _applicant_ref(event_key: str, applicant_identity: str) -> str:
    return stable_reference(
        event_key=event_key,
        kind=EntityKind.APPLICANT,
        strategy=StableIdStrategy.CANONICAL_CONTENT_KEY,
        stable_value=applicant_identity,
    )


def _canonical_field_requirements(role: str) -> frozenset[str]:
    return {
        "applications": frozenset(),
        "attendance": frozenset({"approval_status", "checked_in_at"}),
        "teams": frozenset({"team_id", "track"}),
        "submissions": frozenset({"project_id", "team_id", "submission_status", "track"}),
    }.get(role, frozenset())


def _ingest_mapped_source(source: MappedSourceInput) -> IngestResult:
    if source.path is None:
        raise ValueError("cannot ingest a missing source")
    if source.path.suffix.casefold() != ".xlsx":
        if source.sheets:
            raise ValueError(f"{source.role}: sheet selectors require an XLSX source")
        return ingest_csv(source.path, source.mapping)

    if not source.sheets:
        raise ValueError(f"{source.role}: XLSX source requires configured sheets")
    from community_os.operator_pipeline import read_xlsx

    workbook = read_xlsx(source.path, selected_sheets=source.sheets)
    combined = IngestResult(mapping=source.mapping)
    for sheet in source.sheets:
        rows = workbook[sheet]
        if not rows:
            raise ValueError(f"{source.role}: configured sheet is empty: {sheet}")
        result = ingest_table(
            rows[0],
            rows[1:],
            source.mapping,
            source_partition=sheet,
        )
        combined.records.extend(result.records)
        combined.rejected.extend(result.rejected)
        combined.warnings.extend(result.warnings)
    external_ids = [record.external_record_id for record in combined.records]
    if len(external_ids) != len(set(external_ids)):
        raise ValueError(f"{source.role}: duplicate external record id across selected sheets")
    return combined


def normalize_mapped_sources(
    *,
    event_key: str,
    sources: Iterable[MappedSourceInput],
) -> NormalizedEventData:
    """Normalize mapped hackathon CSV sources without row-order assumptions."""

    materialized = tuple(sources)
    by_role = {source.role: source for source in materialized}
    if len(by_role) != len(materialized):
        raise ValueError("source roles must be unique")
    if "applications" not in by_role:
        raise ValueError("applications source is required for population normalization")

    coverage: list[SourceCoverage] = []
    rejected_rows: list[RejectedRow] = []
    ingested: dict[str, tuple[object, str]] = {}
    for role in sorted(by_role):
        source = by_role[role]
        if source.path is None:
            if source.required:
                raise ValueError(f"required source is missing: {role}")
            coverage.append(
                SourceCoverage(role, required=False, state=SourceCoverageState.MISSING_OPTIONAL)
            )
            continue
        required_fields = _canonical_field_requirements(role)
        missing_fields = sorted(required_fields - source.mapping.field_map.keys())
        if missing_fields:
            raise ValueError(
                f"{role} mapping is missing canonical fields: {', '.join(missing_fields)}"
            )
        result = _ingest_mapped_source(source)
        digest = _source_sha256(source.path)
        ingested[role] = (result, digest)
        coverage.append(SourceCoverage(role, source.required, SourceCoverageState.AVAILABLE))
        for row in result.rejected:
            reason = (
                RejectionReason.MISSING_STABLE_ID
                if row.code
                in {
                    RejectionCode.MISSING_SOURCE_IDENTITY,
                    RejectionCode.MISSING_APPLICANT_IDENTITY,
                }
                else RejectionReason.MALFORMED_RECORD
            )
            rejected_rows.append(
                RejectedRow(
                    role,
                    digest,
                    row.row_number,
                    reason,
                    source_partition=row.source_partition,
                )
            )

    application_result = ingested.get("applications")
    if application_result is None:
        raise ValueError("applications source is unavailable")
    application_records = application_result[0].records
    population = {record.applicant_identity for record in application_records}
    applicant_sources: dict[str, set[str]] = {identity: set() for identity in population}
    applicant_github_supplied = {identity: False for identity in population}

    attendance: list[NormalizedAttendance] = []
    teams: dict[str, NormalizedTeam] = {}
    projects: dict[str, NormalizedProject] = {}
    team_memberships: set[TeamMembership] = set()
    project_memberships: set[SubmittedProjectMembership] = set()

    for role in ("applications", "attendance", "teams", "submissions"):
        source = by_role.get(role)
        result_and_digest = ingested.get(role)
        if source is None or result_and_digest is None:
            continue
        result, digest = result_and_digest
        positive_values = set(source.positive_values)
        for record in result.records:
            if record.applicant_identity not in population:
                rejected_rows.append(
                    RejectedRow(
                        role,
                        digest,
                        record.row_number,
                        RejectionReason.INVALID_RELATION,
                        source_partition=record.source_partition,
                    )
                )
                continue
            applicant_ref = _applicant_ref(event_key, record.applicant_identity)
            source_ref = _mapped_source_ref(event_key, role, record.external_record_id)
            applicant_sources[record.applicant_identity].add(source_ref)

            if role == "applications":
                applicant_github_supplied[record.applicant_identity] = (
                    applicant_github_supplied[record.applicant_identity]
                    or bool(record.values.get("github", "").strip())
                )

            if role == "attendance":
                raw_status = record.values.get("approval_status", "").strip().casefold()
                accepted = True if raw_status in positive_values else None
                raw_present = record.values.get("checked_in_at", "").strip()
                attendance.append(
                    NormalizedAttendance(
                        applicant_ref=applicant_ref,
                        source_ref=source_ref,
                        accepted=accepted,
                        present=True if raw_present else None,
                    )
                )
                continue

            if role == "teams":
                raw_team_id = record.values.get("team_id", "").strip()
                if not raw_team_id:
                    rejected_rows.append(
                        RejectedRow(
                            role,
                            digest,
                            record.row_number,
                            RejectionReason.MALFORMED_RECORD,
                            source_partition=record.source_partition,
                        )
                    )
                    continue
                team_ref = stable_reference(
                    event_key=event_key,
                    kind=EntityKind.TEAM,
                    strategy=StableIdStrategy.PROVIDER_ID,
                    stable_value=raw_team_id,
                )
                candidate = NormalizedTeam(
                    team_ref,
                    track=record.values.get("track", "").strip() or None,
                )
                if team_ref in teams and teams[team_ref] != candidate:
                    raise ValueError("conflicting normalized team records")
                teams[team_ref] = candidate
                team_memberships.add(TeamMembership(team_ref, applicant_ref))
                continue

            if role == "submissions":
                raw_project_id = record.values.get("project_id", "").strip()
                if not raw_project_id:
                    rejected_rows.append(
                        RejectedRow(
                            role,
                            digest,
                            record.row_number,
                            RejectionReason.MALFORMED_RECORD,
                            source_partition=record.source_partition,
                        )
                    )
                    continue
                project_ref = stable_reference(
                    event_key=event_key,
                    kind=EntityKind.PROJECT,
                    strategy=StableIdStrategy.PROVIDER_ID,
                    stable_value=raw_project_id,
                )
                raw_team_id = record.values.get("team_id", "").strip()
                team_ref = None
                track = record.values.get("track", "").strip() or None
                if raw_team_id:
                    team_ref = stable_reference(
                        event_key=event_key,
                        kind=EntityKind.TEAM,
                        strategy=StableIdStrategy.PROVIDER_ID,
                        stable_value=raw_team_id,
                    )
                    candidate_team = NormalizedTeam(team_ref, track=track)
                    if team_ref in teams and teams[team_ref] != candidate_team:
                        raise ValueError("submission conflicts with normalized team record")
                    teams[team_ref] = candidate_team
                raw_status = record.values.get("submission_status", "").strip().casefold()
                submitted = True if raw_status in positive_values else None
                candidate_project = NormalizedProject(
                    project_ref,
                    team_ref=team_ref,
                    submitted=submitted,
                    track=track,
                    repository_supplied=(
                        bool(record.values.get("repository", "").strip())
                        if "repository" in source.mapping.field_map else None
                    ),
                    demo_supplied=(
                        bool(record.values.get("demo", "").strip())
                        if "demo" in source.mapping.field_map else None
                    ),
                )
                if project_ref in projects and projects[project_ref] != candidate_project:
                    raise ValueError("conflicting normalized project records")
                projects[project_ref] = candidate_project
                if submitted:
                    project_memberships.add(
                        SubmittedProjectMembership(project_ref, applicant_ref)
                    )

    applicants = [
        NormalizedApplicant(
            ref=_applicant_ref(event_key, identity),
            source_refs=tuple(source_refs),
            github_supplied=applicant_github_supplied[identity],
        )
        for identity, source_refs in applicant_sources.items()
    ]
    return NormalizedEventData.create(
        event_key=event_key,
        applicants=applicants,
        attendance=attendance,
        teams=teams.values(),
        projects=projects.values(),
        team_memberships=team_memberships,
        submitted_project_memberships=project_memberships,
        coverage=coverage,
        rejected_rows=rejected_rows,
    )
