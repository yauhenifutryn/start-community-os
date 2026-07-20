"""Typed production-operation and human-review primitives for protected releases."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
import csv
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
import fcntl
import hashlib
import hmac
import io
import json
import os
from pathlib import Path
import re
import secrets
import stat
from typing import Callable, Iterable, Mapping, Protocol, Sequence
import unicodedata


_CODE = re.compile(r"^[a-z][a-z0-9_]{1,63}$")
_EVENT_KEY = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_SOURCE_CODE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_HASH = re.compile(r"^[0-9a-f]{64}$")
_KINDS = frozenset({"identity", "team", "classification"})
_CLASSIFICATION_DIMENSIONS = frozenset({
    "professional_identity", "seniority", "functional_role", "employer_pedigree",
    "builder_evidence", "capabilities", "domains",
})
_REVIEW_BINDINGS_VERSION = "release-review-bindings-v2"
_REVIEW_BINDING_KEYS = frozenset({
    "bindings", "bindings_version", "event_approval_sha256",
    "event_definition_sha256", "event_key", "source_hashes",
})
_NO_EVENT_APPROVAL_SHA256 = hashlib.sha256(b"no-event-approval").hexdigest()
_RICH_GITHUB_COLLECTION_APPROVAL_KEYS = frozenset({
    "approval_id", "approval_version", "approved_at", "approved_by",
    "candidate_set_sha256", "distribution", "event_definition_sha256",
    "event_key", "expires_at", "github_authorization_sha256",
    "max_physical_requests", "max_profiles", "purpose", "release_eligible",
    "source_file_sha256", "source_scope", "ttl_days",
})
_RICH_GITHUB_STAGE_KEYS = frozenset({
    "approval_sha256", "created_at", "expires_at", "records", "stage",
    "stage_output_version",
})
_RICH_GITHUB_OBSERVED_KEYS = frozenset({
    "account_age_days", "evidence_ref", "forks_received", "last_public_update",
    "owned_public_repos_sampled", "public_repos", "recently_active_repos",
    "rich_project_evidence", "stars_received", "state", "subject_ref",
    "technology_codes",
})
_RICH_GITHUB_UNKNOWN_KEYS = frozenset({"reason_code", "state", "subject_ref"})
_RICH_GITHUB_TECHNOLOGY_CODES = frozenset({
    "systems", "dotnet", "web_frontend", "dart", "go", "jvm",
    "javascript_typescript", "data_notebook", "php", "python", "ruby",
    "rust", "shell", "swift",
})
_PSEUDONYMOUS_SUBJECT = re.compile(r"^pid:v1:[0-9a-f]{64}$")
_GITHUB_EVIDENCE_REF = re.compile(r"^evidence:github:[0-9a-f]{64}$")
_SUBJECT_INITIAL_PREFIX = "subject-initial:"
_CANONICAL_RICH_GITHUB_RECEIPT_SCHEME = "canonical-record-array-v1"
_LEGACY_RICH_GITHUB_RECEIPT_SCHEME = "legacy-record-file-sha256-chain-v1"
_LEGACY_RICH_GITHUB_RECORD_FILENAME = re.compile(r"^[0-9a-f]{64}\.json$")


class _CareerEvidenceLoader(Protocol):
    def __call__(
        self, subject_refs: frozenset[str], *, identity_literals: tuple[str, ...],
    ) -> Mapping[str, Sequence[Mapping[str, object]]]: ...


def _code(value: str, field: str) -> str:
    if not isinstance(value, str) or not _CODE.fullmatch(value):
        raise ValueError(f"{field} must be a machine-readable code")
    return value


def _canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False,
    ).encode("utf-8")


def _canonical_hash(value: object) -> str:
    return hashlib.sha256(_canonical_json_bytes(value)).hexdigest()


@dataclass(frozen=True)
class _LegacyRichGitHubRecordsSnapshot:
    directory_metadata: tuple[int, int, int, int, int]
    filenames: tuple[str, ...]
    files: tuple[
        tuple[str, bytes, tuple[int, int, int, int, int, int, int]], ...
    ]


class _LegacyRichGitHubReceiptUnavailable(PermissionError):
    """The source has no legacy record-file receipt to validate."""


def _canonical_private_path(path: str | Path) -> Path:
    """Normalize only fixed macOS system aliases before no-follow traversal."""
    absolute = Path(os.path.abspath(os.fspath(path)))
    parts = absolute.parts
    if len(parts) > 1 and parts[1] in {"etc", "tmp", "var"}:
        alias = Path(os.sep) / parts[1]
        expected = Path("/private") / parts[1]
        try:
            if alias.is_symlink() and Path(os.path.realpath(alias)) == expected:
                return Path("/private").joinpath(*parts[1:])
        except OSError:
            pass
    return absolute


def _open_private_root(path: str | Path, label: str) -> tuple[int, Path]:
    """Open every root component with O_NOFOLLOW and return the anchored directory fd."""
    canonical = _canonical_private_path(path)
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(os.sep, directory_flags)
    try:
        for component in canonical.parts[1:]:
            next_descriptor = os.open(
                component, directory_flags, dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = next_descriptor
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise PermissionError(f"{label} must be a private non-symlink directory")
    except PermissionError:
        os.close(descriptor)
        raise
    except OSError as error:
        os.close(descriptor)
        raise PermissionError(
            f"{label} must be a private non-symlink directory; symlink ancestor is unsafe"
        ) from error
    return descriptor, canonical


def _assert_private_root_binding(
    path: str | Path, *, expected_identity: tuple[int, int], label: str,
) -> None:
    """Fail closed unless a path still names the already-open private root."""
    try:
        descriptor, _canonical = _open_private_root(path, label)
    except PermissionError as error:
        raise PermissionError(f"{label} changed during protected import") from error
    try:
        metadata = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (metadata.st_dev, metadata.st_ino) != expected_identity:
        raise PermissionError(f"{label} changed during protected import")


@contextmanager
def _anchored_operator_mutation_lock(root_descriptor: int):
    """Serialize the import on the same anchored lock used by operator mutations."""
    flags = (
        os.O_RDWR | os.O_CREAT
        | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor: int | None = None
    try:
        descriptor = os.open(
            ".operator-mutation.lock", flags, 0o600, dir_fd=root_descriptor,
        )
        os.fchmod(descriptor, 0o600)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise PermissionError("operator mutation lock must be a private regular file")
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _open_private_relative_directory(
    root_descriptor: int, parts: Sequence[str], label: str,
) -> int:
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.dup(root_descriptor)
    try:
        for component in parts:
            if not component or component in {".", ".."} or Path(component).name != component:
                raise PermissionError(f"{label} has an unsafe protected file path")
            next_descriptor = os.open(
                component, directory_flags, dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = next_descriptor
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or stat.S_IMODE(metadata.st_mode) != 0o700
            ):
                raise PermissionError(f"{label} protected directory must be 0700")
    except PermissionError:
        os.close(descriptor)
        raise
    except OSError as error:
        os.close(descriptor)
        raise PermissionError(f"{label} has an unsafe protected file path") from error
    return descriptor


def _read_protected_file(
    root_descriptor: int, parts: Sequence[str], label: str, *, max_bytes: int,
) -> bytes:
    payload, _metadata = _read_protected_file_snapshot(
        root_descriptor, parts, label, max_bytes=max_bytes,
    )
    return payload


def _read_protected_file_snapshot(
    root_descriptor: int, parts: Sequence[str], label: str, *, max_bytes: int,
) -> tuple[bytes, tuple[int, int, int, int, int]]:
    """Read one protected file and bind its exact inode, bytes, and metadata."""
    if not parts:
        raise PermissionError(f"{label} has an unsafe protected file path")
    directory_descriptor = _open_private_relative_directory(
        root_descriptor, parts[:-1], label,
    )
    file_descriptor: int | None = None
    try:
        filename = parts[-1]
        if not filename or filename in {".", ".."} or Path(filename).name != filename:
            raise PermissionError(f"{label} has an unsafe protected file path")
        file_flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            file_descriptor = os.open(
                filename, file_flags, dir_fd=directory_descriptor,
            )
        except OSError as error:
            raise PermissionError(f"{label} has an unsafe protected file") from error
        before = os.fstat(file_descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_IMODE(before.st_mode) != 0o600
        ):
            raise PermissionError(
                f"{label} must be a regular non-symlink 0600 protected file"
            )
        if before.st_size <= 0 or before.st_size > max_bytes:
            raise PermissionError(f"{label} exceeds its protected size bound")
        chunks: list[bytes] = []
        total = 0
        while total <= max_bytes:
            chunk = os.read(file_descriptor, min(64 * 1024, max_bytes + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        if total == 0 or total > max_bytes:
            raise PermissionError(f"{label} exceeds its protected size bound")
        after = os.fstat(file_descriptor)
        before_identity = (
            before.st_dev, before.st_ino, before.st_size,
            before.st_mtime_ns, before.st_ctime_ns,
        )
        after_identity = (
            after.st_dev, after.st_ino, after.st_size,
            after.st_mtime_ns, after.st_ctime_ns,
        )
        if before_identity != after_identity or total != after.st_size:
            raise PermissionError(f"{label} changed during its protected read")
        return b"".join(chunks), after_identity
    finally:
        if file_descriptor is not None:
            os.close(file_descriptor)
        os.close(directory_descriptor)


def _assert_protected_file_snapshot(
    root_descriptor: int, parts: Sequence[str], label: str, *, max_bytes: int,
    expected_payload: bytes, expected_metadata: tuple[int, int, int, int, int],
) -> None:
    """Fail closed if the anchored path no longer names the validated file."""
    payload, metadata = _read_protected_file_snapshot(
        root_descriptor, parts, label, max_bytes=max_bytes,
    )
    if (
        metadata != expected_metadata
        or not hmac.compare_digest(payload, expected_payload)
    ):
        raise PermissionError(f"{label} changed during protected import")


def _decode_protected_json(payload: bytes, label: str) -> object:
    def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        value: dict[str, object] = {}
        for key, item in pairs:
            if key in value:
                raise ValueError(f"{label} contains duplicate JSON keys")
            value[key] = item
        return value

    try:
        decoded = json.loads(
            payload, object_pairs_hook=unique_object,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                ValueError(f"{label} contains a non-finite number")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise PermissionError(f"{label} is invalid JSON") from error
    return decoded


def _legacy_directory_metadata(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        stat.S_IMODE(metadata.st_mode),
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _read_legacy_record_file_snapshot(
    directory_descriptor: int, filename: str,
) -> tuple[bytes, tuple[int, int, int, int, int, int, int]]:
    descriptor: int | None = None
    try:
        try:
            descriptor = os.open(
                filename,
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=directory_descriptor,
            )
        except OSError as error:
            raise PermissionError(
                "legacy rich GitHub record is not a safe protected file",
            ) from error
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_nlink != 1
        ):
            raise PermissionError(
                "legacy rich GitHub record must be a private regular non-symlink file",
            )
        max_bytes = 512 * 1024
        if before.st_size <= 0 or before.st_size > max_bytes:
            raise PermissionError("legacy rich GitHub record exceeds its size bound")
        chunks: list[bytes] = []
        total = 0
        while total <= max_bytes:
            chunk = os.read(descriptor, min(64 * 1024, max_bytes + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        after = os.fstat(descriptor)
        before_metadata = (
            before.st_dev,
            before.st_ino,
            stat.S_IMODE(before.st_mode),
            before.st_nlink,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        after_metadata = (
            after.st_dev,
            after.st_ino,
            stat.S_IMODE(after.st_mode),
            after.st_nlink,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if (
            total == 0
            or total > max_bytes
            or total != after.st_size
            or before_metadata != after_metadata
        ):
            raise PermissionError(
                "legacy rich GitHub record changed during its protected read",
            )
        return b"".join(chunks), after_metadata
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _read_legacy_rich_github_records_snapshot(
    source_descriptor: int, *, approval: Mapping[str, object],
    records: Sequence[object], pipeline_output_hash: str,
) -> _LegacyRichGitHubRecordsSnapshot:
    """Verify the bounded legacy collector's file-chain receipt exactly."""
    if (
        approval.get("approval_version") != "rich-github-collection-approval-v1"
        or approval.get("purpose") != "rich_semantic_project_evidence"
    ):
        raise PermissionError("legacy rich GitHub collection approval scope is invalid")
    try:
        directory_descriptor = _open_private_relative_directory(
            source_descriptor, ("records",), "legacy rich GitHub records",
        )
    except PermissionError as error:
        if isinstance(error.__cause__, FileNotFoundError):
            raise _LegacyRichGitHubReceiptUnavailable(
                "legacy rich GitHub records directory is missing",
            ) from error
        raise PermissionError(
            "legacy rich GitHub records directory is missing or unsafe",
        ) from error
    try:
        before_metadata = _legacy_directory_metadata(os.fstat(directory_descriptor))
        try:
            filenames = tuple(sorted(os.listdir(directory_descriptor)))
        except OSError as error:
            raise PermissionError(
                "legacy rich GitHub records directory is unreadable",
            ) from error
        if (
            len(filenames) != len(records)
            or any(
                not isinstance(filename, str)
                or not _LEGACY_RICH_GITHUB_RECORD_FILENAME.fullmatch(filename)
                for filename in filenames
            )
        ):
            raise PermissionError(
                "legacy rich GitHub records directory has unexpected contents",
            )

        stage_filenames: list[str] = []
        for record in records:
            if not isinstance(record, Mapping):
                raise PermissionError("legacy rich GitHub record is invalid")
            subject_ref = record.get("subject_ref")
            if not isinstance(subject_ref, str) or not _PSEUDONYMOUS_SUBJECT.fullmatch(
                subject_ref,
            ):
                raise PermissionError("legacy rich GitHub record subject is invalid")
            stage_filenames.append(
                hashlib.sha256(subject_ref.encode("utf-8")).hexdigest() + ".json",
            )
        if tuple(stage_filenames) != filenames:
            raise PermissionError(
                "legacy rich GitHub records do not match sorted stage subjects",
            )

        file_snapshots: list[
            tuple[str, bytes, tuple[int, int, int, int, int, int, int]]
        ] = []
        decoded_records: list[object] = []
        record_file_hashes: list[str] = []
        for filename in filenames:
            payload, metadata = _read_legacy_record_file_snapshot(
                directory_descriptor, filename,
            )
            decoded = _decode_protected_json(payload, "legacy rich GitHub record")
            if not hmac.compare_digest(payload, _canonical_json_bytes(decoded) + b"\n"):
                raise PermissionError(
                    "legacy rich GitHub record is not canonical JSON with one newline",
                )
            file_snapshots.append((filename, payload, metadata))
            decoded_records.append(decoded)
            record_file_hashes.append(hashlib.sha256(payload).hexdigest())

        try:
            after_filenames = tuple(sorted(os.listdir(directory_descriptor)))
        except OSError as error:
            raise PermissionError(
                "legacy rich GitHub records directory changed during protected read",
            ) from error
        after_metadata = _legacy_directory_metadata(os.fstat(directory_descriptor))
        if before_metadata != after_metadata or filenames != after_filenames:
            raise PermissionError(
                "legacy rich GitHub records directory changed during protected read",
            )
        if decoded_records != list(records):
            raise PermissionError(
                "legacy rich GitHub record files do not exactly match the stage",
            )
        observed_file_chain_hash = _canonical_hash(record_file_hashes)
        if not hmac.compare_digest(observed_file_chain_hash, pipeline_output_hash):
            raise PermissionError(
                "legacy rich GitHub file-chain receipt does not match its records",
            )
        return _LegacyRichGitHubRecordsSnapshot(
            directory_metadata=after_metadata,
            filenames=filenames,
            files=tuple(file_snapshots),
        )
    finally:
        os.close(directory_descriptor)


def _assert_legacy_rich_github_records_snapshot(
    source_descriptor: int, *, approval: Mapping[str, object],
    records: Sequence[object], pipeline_output_hash: str,
    expected: _LegacyRichGitHubRecordsSnapshot,
) -> None:
    try:
        observed = _read_legacy_rich_github_records_snapshot(
            source_descriptor,
            approval=approval,
            records=records,
            pipeline_output_hash=pipeline_output_hash,
        )
    except (PermissionError, ValueError) as error:
        raise PermissionError(
            "legacy rich GitHub records changed during protected import",
        ) from error
    if observed != expected:
        raise PermissionError(
            "legacy rich GitHub records changed during protected import",
        )


def _read_protected_json(
    root_descriptor: int, parts: Sequence[str], label: str, *, max_bytes: int,
) -> tuple[object, bytes]:
    payload = _read_protected_file(
        root_descriptor, parts, label, max_bytes=max_bytes,
    )
    return _decode_protected_json(payload, label), payload


def _protected_timestamp(value: object, label: str) -> datetime:
    if not isinstance(value, str):
        raise PermissionError(f"{label} is invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise PermissionError(f"{label} is invalid") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise PermissionError(f"{label} requires a timezone")
    return parsed.astimezone(UTC)


def _protected_pipeline_stage(
    payload: bytes, *, stage: str, label: str,
) -> object:
    """Validate protected pipeline bytes without reopening the checked path."""
    from community_os.enrichment.state import (
        PipelineState, StageRecord, StageStatus, sanitize_audit_event,
    )

    try:
        value = _decode_protected_json(payload, label)
        if not isinstance(value, dict) or set(value) != {
            "audit_events", "state_version", "stages",
        }:
            raise ValueError("pipeline keys are invalid")
        if value["state_version"] != PipelineState.VERSION:
            raise ValueError("pipeline version is invalid")
        raw_stages = value["stages"]
        if not isinstance(raw_stages, dict) or stage not in raw_stages:
            raise ValueError("pipeline stages are invalid")
        records: dict[str, StageRecord] = {}
        for name, raw in raw_stages.items():
            PipelineState._validate_stage_name(name)
            if not isinstance(raw, dict) or set(raw) != {
                "attempts", "authorization_hash", "authorization_record",
                "reason_code", "result", "status",
            }:
                raise ValueError("pipeline stage keys are invalid")
            attempts = raw["attempts"]
            if isinstance(attempts, bool) or not isinstance(attempts, int):
                raise ValueError("pipeline attempts are invalid")
            record = StageRecord(
                StageStatus(raw["status"]), attempts, raw["result"],
                raw["reason_code"], raw["authorization_hash"],
                raw["authorization_record"],
            )
            PipelineState._validate_record(name, record)
            records[name] = record
        audit_events = value["audit_events"]
        if not isinstance(audit_events, list):
            raise ValueError("pipeline audit is invalid")
        for event in audit_events:
            if not isinstance(event, dict) or set(event) != {"event", "properties"}:
                raise ValueError("pipeline audit event is invalid")
            if not isinstance(event["event"], str) or not isinstance(event["properties"], dict):
                raise ValueError("pipeline audit event is invalid")
            sanitize_audit_event(event["event"], event["properties"])
        return records[stage]
    except (KeyError, TypeError, ValueError) as error:
        raise PermissionError(f"{label} is invalid") from error


def _application_rows_from_bytes(
    payload: bytes, *, event_definition: object,
) -> tuple[Mapping[str, object], ...]:
    """Parse the exact verified application bytes through the configured adapter."""
    from community_os.ingest.base import ingest_table
    from community_os.source_contract import load_registered_source_contract

    try:
        source = getattr(event_definition, "source")("applications")
        if getattr(source, "media_type", None) != "text/csv":
            raise ValueError("application source is not CSV")
        mapping = load_registered_source_contract(source).mapping
        text = payload.decode("utf-8-sig")
        reader = csv.reader(io.StringIO(text, newline=""))
        headers = next(reader)
        result = ingest_table(headers, reader, mapping)
    except (AttributeError, StopIteration, TypeError, UnicodeDecodeError, ValueError, csv.Error) as error:
        raise PermissionError("current application source is invalid") from error
    return tuple({
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
    } for record in result.records)


def _atomic_replace_protected_file(
    root_descriptor: int, directory_parts: Sequence[str], filename: str,
    payload: bytes, *, label: str,
) -> None:
    """Replace one private file relative to an anchored, no-follow directory fd."""
    directory_descriptor = _open_private_relative_directory(
        root_descriptor, directory_parts, label,
    )
    temporary_name = f".{filename}.{secrets.token_hex(12)}.tmp"
    file_descriptor: int | None = None
    try:
        flags = (
            os.O_WRONLY | os.O_CREAT | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        )
        file_descriptor = os.open(
            temporary_name, flags, 0o600, dir_fd=directory_descriptor,
        )
        os.fchmod(file_descriptor, 0o600)
        view = memoryview(payload)
        written = 0
        while written < len(view):
            count = os.write(file_descriptor, view[written:])
            if count <= 0:
                raise OSError("protected write made no progress")
            written += count
        os.fsync(file_descriptor)
        os.close(file_descriptor)
        file_descriptor = None
        os.replace(
            temporary_name, filename,
            src_dir_fd=directory_descriptor, dst_dir_fd=directory_descriptor,
        )
        os.fsync(directory_descriptor)
    except BaseException:
        if file_descriptor is not None:
            os.close(file_descriptor)
        try:
            os.unlink(temporary_name, dir_fd=directory_descriptor)
        except FileNotFoundError:
            pass
        raise
    finally:
        os.close(directory_descriptor)


def _application_identity_corpus(
    applications: Sequence[Mapping[str, object]],
) -> tuple[str, ...]:
    """Build the high-confidence run-wide direct-identifier corpus."""

    literals: set[str] = set()
    identity_fields = (
        "external_id", "name", "email", "organization", "portfolio", "team_name",
    )
    for application in applications:
        for field in identity_fields:
            value = str(application.get(field) or "").strip()
            if value:
                literals.add(value)
        # Full profile locators are unambiguous direct identifiers. Bare handles
        # and slugs are intentionally subject-scoped because ordinary prose can
        # contain the same single token for unrelated applicants.
        for field in ("github", "linkedin"):
            value = str(application.get(field) or "").strip()
            normalized = unicodedata.normalize("NFKC", value).casefold()
            if value and (
                "://" in normalized
                or normalized.startswith("www.")
                or normalized.startswith("github.com/")
                or normalized.startswith("linkedin.com/")
            ):
                literals.add(value)
    if not literals:
        raise PermissionError("rich GitHub identity corpus is empty")
    return tuple(sorted(literals, key=lambda value: (value.casefold(), value)))


def _application_subject_identity_literals(
    applications: Sequence[Mapping[str, object]], *, pseudonym_secret: bytes,
) -> dict[str, tuple[str, ...]]:
    """Key ambiguous derived identity forms only by pseudonymous subject."""
    from community_os.enrichment.state import pseudonymous_id
    from community_os.identity import canonicalize_linkedin, normalize_email

    if not isinstance(pseudonym_secret, bytes) or not pseudonym_secret:
        raise ValueError("subject identity corpus requires a pseudonym secret")
    result: dict[str, tuple[str, ...]] = {}
    external_ids: set[str] = set()
    for application in applications:
        if not isinstance(application, Mapping):
            raise ValueError("subject identity application must be an object")
        external_id = str(application.get("external_id") or "").strip()
        if not external_id or external_id in external_ids:
            raise ValueError("subject identity applications require unique identifiers")
        external_ids.add(external_id)
        subject_ref = pseudonymous_id(
            external_id, secret=pseudonym_secret, key_version="v1",
        )
        if subject_ref in result:
            raise ValueError("subject identity pseudonyms are duplicated")
        literals: set[str] = set()
        name = str(application.get("name") or "").strip()
        # Two-character name parts are common and safe to scope to their own
        # pseudonymous subject. One-character initials are retained only for
        # contextual byline/labeled checks, never global token erasure.
        for part in re.findall(r"[^\W\d_]+", name, flags=re.UNICODE):
            literals.add(
                _SUBJECT_INITIAL_PREFIX + part if len(part) == 1 else part
            )
        github_handle = _canonicalize_applicant_github_identity(
            str(application.get("github") or ""),
        )
        if github_handle:
            literals.add(github_handle)
        linkedin_slug = canonicalize_linkedin(
            str(application.get("linkedin") or ""),
        )
        if linkedin_slug:
            literals.add(linkedin_slug)
        email = normalize_email(str(application.get("email") or ""))
        if email and "@" in email:
            literals.add(email.split("@", 1)[0])
        if not literals:
            raise PermissionError("subject identity corpus is empty")
        result[subject_ref] = tuple(sorted(
            literals, key=lambda value: (value.casefold(), value),
        ))
    if not result:
        raise PermissionError("subject identity corpus is empty")
    return result


def _identity_word_tokens(value: str) -> tuple[str, ...]:
    normalized = unicodedata.normalize("NFKC", value).casefold()
    return tuple(re.findall(r"[^\W_]+", normalized, flags=re.UNICODE))


def _contextual_subject_initial_pattern(initial: str) -> re.Pattern[str]:
    """Recognize one-character identities only in explicit byline labels."""
    return re.compile(
        r"(?i)(?<!\w)(?:by|author|owner|maintainer)\s*[:=]?\s*"
        + re.escape(initial)
        + r"(?=\s*(?:[,.;:)\]}]|$))",
    )


def _canonicalize_applicant_github_identity(value: str) -> str | None:
    """Recognize a bare handle, supported URL, or exact schemeless profile form."""
    from community_os.identity import canonicalize_github

    normalized = unicodedata.normalize("NFKC", value).strip()
    schemeless = re.fullmatch(
        r"(?:www\.)?github\.com/([a-z0-9](?:[a-z0-9-]{0,38}))/?",
        normalized,
        flags=re.IGNORECASE,
    )
    if schemeless is not None:
        return canonicalize_github(schemeless.group(1))
    return canonicalize_github(normalized)


def _github_handle_tokens(value: str) -> tuple[str, ...]:
    normalized = unicodedata.normalize("NFKC", value).casefold()
    return tuple(re.findall(r"[a-z0-9-]+", normalized))


def _assert_no_short_identity_literals(
    value: object, identity_literals: Sequence[str],
) -> None:
    """Catch exact short identity token sequences omitted by the general scan."""
    short_forms = {
        tokens
        for literal in identity_literals
        if (tokens := _identity_word_tokens(literal))
        and len("".join(tokens)) < 4
    }
    if not short_forms:
        return

    def visit(item: object) -> None:
        if isinstance(item, Mapping):
            for nested in item.values():
                visit(nested)
        elif isinstance(item, Sequence) and not isinstance(
            item, (str, bytes, bytearray),
        ):
            for nested in item:
                visit(nested)
        elif isinstance(item, str):
            tokens = _identity_word_tokens(item)
            for form in short_forms:
                width = len(form)
                if any(
                    tokens[index:index + width] == form
                    for index in range(len(tokens) - width + 1)
                ):
                    raise ValueError(
                        "semantic evidence packet contains a known identity literal",
                    )

    visit(value)


def _assert_no_identity_literals(
    value: object, identity_literals: Sequence[str],
) -> None:
    from community_os.enrichment.semantic_evidence import (
        assert_no_known_identity_literals,
    )

    long_literals = tuple(
        literal for literal in identity_literals
        if len("".join(_identity_word_tokens(literal))) >= 4
    )
    if long_literals:
        assert_no_known_identity_literals(value, long_literals)
    _assert_no_short_identity_literals(value, identity_literals)


def _assert_no_subject_identity_literals(
    value: object, identity_literals: Sequence[str],
) -> None:
    """Scan only prose fields for ambiguous current-subject derived forms."""
    contextual_initials: set[str] = set()
    forms: set[tuple[str, ...]] = set()
    for literal in identity_literals:
        normalized = unicodedata.normalize("NFKC", literal).strip()
        if normalized.startswith(_SUBJECT_INITIAL_PREFIX):
            initial = normalized.removeprefix(_SUBJECT_INITIAL_PREFIX)
            if len(initial) != 1 or not initial.isalpha():
                raise ValueError("subject identity initial is invalid")
            contextual_initials.add(initial.casefold())
            continue
        tokens = _identity_word_tokens(literal)
        if tokens:
            forms.add(tokens)
    if not forms and not contextual_initials:
        raise ValueError("subject identity corpus is empty")

    def check(text: str) -> None:
        tokens = _identity_word_tokens(text)
        for form in forms:
            width = len(form)
            if any(
                tokens[index:index + width] == form
                for index in range(len(tokens) - width + 1)
            ):
                raise ValueError(
                    "semantic evidence packet contains a known identity literal",
                )
        if any(
            _contextual_subject_initial_pattern(initial).search(text) is not None
            for initial in contextual_initials
        ):
            raise ValueError(
                "semantic evidence packet contains a known identity literal",
            )

    def visit(item: object) -> None:
        if isinstance(item, Mapping):
            for key, nested in item.items():
                if (
                    isinstance(key, str)
                    and (
                        key.endswith("_excerpt")
                        or key in {"career_summary", "project_summary", "rationale"}
                    )
                    and isinstance(nested, str)
                ):
                    check(nested)
                else:
                    visit(nested)
        elif isinstance(item, Sequence) and not isinstance(
            item, (str, bytes, bytearray),
        ):
            for nested in item:
                visit(nested)

    visit(value)


def _validate_rich_github_record(
    record: object, *, now: datetime,
    allow_repository_resanitization: bool = False,
) -> tuple[str, bool]:
    from community_os.enrichment.github_content_evidence import (
        validate_rich_project_packets,
        validate_rich_project_packets_for_resanitization,
    )

    if not isinstance(record, dict):
        raise ValueError("protected rich GitHub record must be an object")
    subject_ref = record.get("subject_ref")
    if not isinstance(subject_ref, str) or not _PSEUDONYMOUS_SUBJECT.fullmatch(subject_ref):
        raise ValueError("protected rich GitHub subject is invalid")
    state = record.get("state")
    if state == "unknown":
        if set(record) != _RICH_GITHUB_UNKNOWN_KEYS or record.get("reason_code") != "profile_not_found":
            raise ValueError("protected rich GitHub unknown record is invalid")
        return subject_ref, False
    if state != "observed" or set(record) != _RICH_GITHUB_OBSERVED_KEYS:
        raise ValueError("protected rich GitHub observed record fields are invalid")
    counts = (
        "account_age_days", "forks_received", "owned_public_repos_sampled",
        "public_repos", "recently_active_repos", "stars_received",
    )
    if any(
        isinstance(record[key], bool) or not isinstance(record[key], int)
        or record[key] < 0
        for key in counts
    ):
        raise ValueError("protected rich GitHub numeric evidence is invalid")
    if (
        record["owned_public_repos_sampled"] > 100
        or record["owned_public_repos_sampled"] > record["public_repos"]
        or record["recently_active_repos"] > record["owned_public_repos_sampled"]
        or not isinstance(record["evidence_ref"], str)
        or not _GITHUB_EVIDENCE_REF.fullmatch(record["evidence_ref"])
    ):
        raise ValueError("protected rich GitHub structural evidence is invalid")
    try:
        updated = datetime.strptime(str(record["last_public_update"]), "%Y-%m-%d").date()
    except ValueError as error:
        raise ValueError("protected rich GitHub update date is invalid") from error
    if updated > now.date():
        raise ValueError("protected rich GitHub update date cannot be in the future")
    technologies = record["technology_codes"]
    if (
        not isinstance(technologies, list)
        or technologies != sorted(set(technologies))
        or any(code not in _RICH_GITHUB_TECHNOLOGY_CODES for code in technologies)
    ):
        raise ValueError("protected rich GitHub technology codes are invalid")
    project_validator = (
        validate_rich_project_packets_for_resanitization
        if allow_repository_resanitization
        else validate_rich_project_packets
    )
    projects = project_validator(record["rich_project_evidence"])
    return subject_ref, bool(projects)


def _project_rich_github_record(
    record: object, *, now: datetime,
    run_wide_identity_literals: Sequence[str],
    subject_identity_literals: Mapping[str, Sequence[str]],
) -> tuple[dict[str, object], bool, int, int]:
    """Derive one deterministic identity-safe destination record."""
    from community_os.enrichment.github_content_evidence import (
        validate_rich_project_packets,
        validate_rich_project_packets_for_resanitization,
    )
    from community_os.enrichment.semantic_evidence import sanitize_professional_text

    subject_ref, has_rich_evidence = _validate_rich_github_record(
        record, now=now, allow_repository_resanitization=True,
    )
    derived = subject_identity_literals.get(subject_ref)
    if (
        not isinstance(derived, Sequence)
        or isinstance(derived, (str, bytes, bytearray))
        or not derived
        or any(not isinstance(value, str) or not value for value in derived)
    ):
        raise PermissionError("protected rich GitHub subject identity binding is missing")
    identity_literals = tuple(run_wide_identity_literals) + tuple(derived)
    if not isinstance(record, dict):  # Guaranteed above, retained for type narrowing.
        raise ValueError("protected rich GitHub record must be an object")
    if record.get("state") == "unknown":
        projected_unknown = dict(record)
        _assert_no_identity_literals(
            projected_unknown, run_wide_identity_literals,
        )
        _assert_no_subject_identity_literals(projected_unknown, derived)
        return projected_unknown, has_rich_evidence, 0, 0

    redaction_count = 0
    normalization_count = 0
    projected_projects: list[dict[str, object]] = []
    for project in validate_rich_project_packets_for_resanitization(
        record["rich_project_evidence"],
    ):
        projected = dict(project)
        for field, limit in (
            ("description_excerpt", 800), ("readme_excerpt", 2_000),
        ):
            original = str(project[field])
            sanitized = sanitize_professional_text(
                original,
                forbidden_literals=identity_literals,
                max_chars=limit,
            )
            if sanitized != original:
                redaction_count += 1
            projected[field] = sanitized
        project_code = str(projected["project_code"])
        normalized_references = [f"{project_code}:ownership"]
        if projected["description_excerpt"]:
            normalized_references.append(f"{project_code}:description")
        if projected["readme_excerpt"]:
            normalized_references.append(f"{project_code}:readme")
        if projected["release_signal"] == "release_observed":
            normalized_references.append(f"{project_code}:release")
        if projected["deployment_signal"] == "deployment_observed":
            normalized_references.append(f"{project_code}:deployment")
        if normalized_references != project["evidence_refs"]:
            normalization_count += 1
        projected["evidence_refs"] = normalized_references
        projected_projects.append(projected)
    projected_record = dict(record)
    projected_record["rich_project_evidence"] = validate_rich_project_packets(
        projected_projects,
    )
    _validate_rich_github_record(projected_record, now=now)
    _assert_no_identity_literals(
        projected_record, run_wide_identity_literals,
    )
    _assert_no_subject_identity_literals(projected_record, derived)
    return (
        projected_record, has_rich_evidence,
        redaction_count, normalization_count,
    )


def import_protected_rich_github_stage(
    state: object, *, source_root: str | Path, pseudonym_secret: bytes,
    clock: Callable[[], datetime],
) -> dict[str, object]:
    """Import an existing reviewed-input GitHub collection without provider access."""
    if not isinstance(pseudonym_secret, bytes) or not pseudonym_secret:
        raise ValueError("rich GitHub import requires a pseudonym secret")
    if not callable(clock):
        raise TypeError("rich GitHub import clock must be callable")
    current = clock()
    if not isinstance(current, datetime) or current.tzinfo is None or current.utcoffset() is None:
        raise ValueError("rich GitHub import clock must be timezone-aware")
    current = current.astimezone(UTC)

    source_descriptor: int | None = None
    destination_descriptor: int | None = None
    try:
        source_descriptor, source_canonical = _open_private_root(
            source_root, "rich GitHub source root",
        )
        destination_descriptor, destination_canonical = _open_private_root(
            Path(getattr(state, "root")), "operator destination root",
        )
        source_metadata = os.fstat(source_descriptor)
        destination_metadata = os.fstat(destination_descriptor)
        if (
            source_canonical == destination_canonical
            or (source_metadata.st_dev, source_metadata.st_ino)
            == (destination_metadata.st_dev, destination_metadata.st_ino)
        ):
            raise ValueError("rich GitHub import source and destination must be separate")
        destination_identity = (
            destination_metadata.st_dev, destination_metadata.st_ino,
        )
        source_identity = (source_metadata.st_dev, source_metadata.st_ino)
        with _anchored_operator_mutation_lock(destination_descriptor):
            _assert_private_root_binding(
                Path(getattr(state, "root")),
                expected_identity=destination_identity,
                label="operator destination root",
            )
            getattr(state, "refresh_import_authority")()
            _assert_private_root_binding(
                Path(getattr(state, "root")),
                expected_identity=destination_identity,
                label="operator destination root",
            )

            def source_guard() -> None:
                _assert_private_root_binding(
                    source_canonical,
                    expected_identity=source_identity,
                    label="rich GitHub source root",
                )

            return _import_protected_rich_github_from_open_roots(
                state,
                source_descriptor=source_descriptor,
                destination_descriptor=destination_descriptor,
                destination_identity=destination_identity,
                source_root_guard=source_guard,
                pseudonym_secret=pseudonym_secret,
                current=current,
            )
    finally:
        if destination_descriptor is not None:
            os.close(destination_descriptor)
        if source_descriptor is not None:
            os.close(source_descriptor)


def _import_protected_rich_github_from_open_roots(
    state: object, *, source_descriptor: int, destination_descriptor: int,
    destination_identity: tuple[int, int], source_root_guard: Callable[[], None],
    pseudonym_secret: bytes,
    current: datetime,
) -> dict[str, object]:
    from community_os.enrichment.gates import PublicSourceGate
    from community_os.enrichment.state import StageStatus, pseudonymous_id

    source_pipeline_bytes, source_pipeline_metadata = _read_protected_file_snapshot(
        source_descriptor, ("pipeline-state.json",),
        "rich GitHub source pipeline state", max_bytes=4 * 1024 * 1024,
    )
    destination_pipeline_bytes = _read_protected_file(
        destination_descriptor, ("pipeline-state.json",),
        "operator pipeline state", max_bytes=4 * 1024 * 1024,
    )
    source_stage_bytes, source_stage_metadata = _read_protected_file_snapshot(
        source_descriptor, ("protected", "stages", "github.json"),
        "rich GitHub source stage", max_bytes=25 * 1024 * 1024,
    )
    destination_stage_bytes = _read_protected_file(
        destination_descriptor, ("protected", "stages", "github.json"),
        "operator GitHub stage", max_bytes=25 * 1024 * 1024,
    )
    source_stage = _protected_pipeline_stage(
        source_pipeline_bytes, stage="github",
        label="rich GitHub source pipeline state",
    )
    destination_stage = _protected_pipeline_stage(
        destination_pipeline_bytes, stage="github", label="operator pipeline state",
    )
    in_memory_stage = getattr(state, "pipeline").stage("github")
    if any(
        item.status is not StageStatus.COMPLETE
        for item in (source_stage, destination_stage, in_memory_stage)
    ):
        raise PermissionError("rich GitHub source and destination stages must be complete")
    if (
        source_stage.authorization_hash is None
        or destination_stage.authorization_hash is None
        or in_memory_stage.authorization_hash is None
        or not hmac.compare_digest(
            source_stage.authorization_hash, destination_stage.authorization_hash,
        )
        or not hmac.compare_digest(
            destination_stage.authorization_hash, in_memory_stage.authorization_hash,
        )
        or source_stage.authorization_record != destination_stage.authorization_record
        or destination_stage.authorization_record != in_memory_stage.authorization_record
    ):
        raise PermissionError("rich GitHub source authorization does not match destination")
    try:
        authorization = PublicSourceGate.from_record(
            destination_stage.authorization_record,
        )
        current_authorization_sha256 = authorization.authorization_hash(
            "github", now=current,
        )
    except (PermissionError, TypeError, ValueError) as error:
        raise PermissionError("current GitHub authorization is invalid") from error
    if not hmac.compare_digest(
        destination_stage.authorization_hash, current_authorization_sha256,
    ):
        raise PermissionError("current GitHub authorization hash does not match")

    approval_bytes, approval_metadata = _read_protected_file_snapshot(
        source_descriptor, ("collection-approval.json",),
        "rich GitHub collection approval", max_bytes=64 * 1024,
    )
    approval_value = _decode_protected_json(
        approval_bytes, "rich GitHub collection approval",
    )
    if not isinstance(approval_value, dict) or set(approval_value) != _RICH_GITHUB_COLLECTION_APPROVAL_KEYS:
        raise PermissionError("rich GitHub collection approval keys are invalid")
    approval = approval_value
    required = {
        "approval_version": "rich-github-collection-approval-v1",
        "distribution": "internal_only_pending_review",
        "purpose": "rich_semantic_project_evidence",
        "release_eligible": False,
        "source_scope": "applicant_supplied_public_github",
    }
    if any(approval[key] != value for key, value in required.items()):
        raise PermissionError("rich GitHub collection approval scope is invalid")
    if (
        not isinstance(approval["approval_id"], str)
        or not _CODE.fullmatch(approval["approval_id"])
        or not isinstance(approval["approved_by"], str)
        or not _CODE.fullmatch(approval["approved_by"])
        or type(approval["ttl_days"]) is not int
        or not 1 <= approval["ttl_days"] <= 3
    ):
        raise PermissionError("rich GitHub collection approval values are invalid")
    approved_at = _protected_timestamp(approval["approved_at"], "GitHub approval timestamp")
    approval_expires = _protected_timestamp(approval["expires_at"], "GitHub approval expiry")
    if (
        approved_at > current or current >= approval_expires
        or approval_expires <= approved_at
        or approval_expires - approved_at > timedelta(days=approval["ttl_days"])
        or approval_expires - approved_at > timedelta(days=3)
    ):
        raise PermissionError("rich GitHub collection approval is expired or overlong")
    if (
        approval["event_key"] != getattr(state, "event_key")
        or approval["event_definition_sha256"] != getattr(state, "event_definition_sha256")
        or not hmac.compare_digest(
            str(approval["github_authorization_sha256"]),
            current_authorization_sha256,
        )
    ):
        raise PermissionError("rich GitHub collection approval binding is stale")
    event_approval = getattr(state, "snapshot")().get("event_approval")
    if (
        isinstance(event_approval, dict)
        and isinstance(event_approval.get("actor_code"), str)
        and approval["approved_by"] != event_approval["actor_code"]
    ):
        raise PermissionError("rich GitHub collection approver does not match event authority")

    snapshot = getattr(state, "snapshot")()
    slots = snapshot.get("source_slots")
    application_slot = slots.get("applications") if isinstance(slots, dict) else None
    if not isinstance(application_slot, dict):
        raise PermissionError("current application source is missing")
    filename = application_slot.get("path")
    source_file_sha256 = application_slot.get("sha256")
    if (
        not isinstance(filename, str) or Path(filename).name != filename
        or not isinstance(source_file_sha256, str) or not _HASH.fullmatch(source_file_sha256)
    ):
        raise PermissionError("current application source binding is invalid")
    application_bytes = _read_protected_file(
        destination_descriptor, ("protected", "uploads", filename),
        "current application source", max_bytes=25 * 1024 * 1024,
    )
    observed_source_sha256 = hashlib.sha256(application_bytes).hexdigest()
    if (
        not hmac.compare_digest(observed_source_sha256, source_file_sha256)
        or not isinstance(approval["source_file_sha256"], str)
        or not hmac.compare_digest(approval["source_file_sha256"], source_file_sha256)
    ):
        raise PermissionError("rich GitHub application source hash drifted")

    applications = list(_application_rows_from_bytes(
        application_bytes, event_definition=getattr(state, "event_definition"),
    ))
    candidates: list[dict[str, str]] = []
    candidate_subjects: set[str] = set()
    for raw in applications:
        external_id = str(raw.get("external_id") or "").strip()
        profile = str(raw.get("github") or "").strip()
        if not profile:
            continue
        if not external_id:
            raise ValueError("rich GitHub applicant identifier is missing")
        subject_ref = pseudonymous_id(
            external_id, secret=pseudonym_secret, key_version="v1",
        )
        if subject_ref in candidate_subjects:
            raise ValueError("rich GitHub candidate subjects are duplicated")
        candidate_subjects.add(subject_ref)
        candidates.append({
            "profile_sha256": hashlib.sha256(profile.encode("utf-8")).hexdigest(),
            "source_record_ref": "source:application:" + hmac.new(
                pseudonym_secret, external_id.encode("utf-8"), hashlib.sha256,
            ).hexdigest()[:24],
            "subject_ref": subject_ref,
        })
    identity_corpus = _rich_github_import_identity_corpus(state, applications)
    all_subject_identity_literals = _application_subject_identity_literals(
        applications, pseudonym_secret=pseudonym_secret,
    )
    subject_identity_literals = {
        subject: all_subject_identity_literals[subject]
        for subject in candidate_subjects
        if subject in all_subject_identity_literals
    }
    if set(subject_identity_literals) != candidate_subjects:
        raise PermissionError("rich GitHub subject identity mapping is incomplete")
    candidates.sort(key=lambda item: item["subject_ref"])
    if (
        type(approval["max_profiles"]) is not int
        or approval["max_profiles"] != len(candidates)
        or type(approval["max_physical_requests"]) is not int
        or approval["max_physical_requests"] != len(candidates) * 11
        or not isinstance(approval["candidate_set_sha256"], str)
        or not hmac.compare_digest(
            approval["candidate_set_sha256"], _canonical_hash(candidates),
        )
    ):
        raise PermissionError("rich GitHub candidate set does not match current applicants")

    stage_value = _decode_protected_json(
        source_stage_bytes, "rich GitHub source stage",
    )
    if not isinstance(stage_value, dict) or set(stage_value) != _RICH_GITHUB_STAGE_KEYS:
        raise ValueError("protected rich GitHub stage keys are invalid")
    approval_sha256 = _canonical_hash(approval)
    if (
        stage_value["stage"] != "github"
        or stage_value["stage_output_version"] != "protected-stage-output-v1"
        or not isinstance(stage_value["approval_sha256"], str)
        or not hmac.compare_digest(stage_value["approval_sha256"], approval_sha256)
    ):
        raise PermissionError("protected rich GitHub stage approval binding is invalid")
    stage_created = _protected_timestamp(stage_value["created_at"], "GitHub stage timestamp")
    stage_expires = _protected_timestamp(stage_value["expires_at"], "GitHub stage expiry")
    if (
        stage_created < approved_at or stage_created > current
        or current >= stage_expires or stage_expires <= stage_created
        or stage_expires > approval_expires
        or stage_expires - stage_created > timedelta(days=approval["ttl_days"])
    ):
        raise PermissionError("protected rich GitHub stage retention is invalid")
    records = stage_value["records"]
    if not isinstance(records, list):
        raise ValueError("protected rich GitHub stage records are invalid")
    record_subjects: set[str] = set()
    source_rich_subject_count = 0
    for record in records:
        subject_ref, has_rich_evidence = _validate_rich_github_record(
            record, now=current, allow_repository_resanitization=True,
        )
        if subject_ref in record_subjects:
            raise ValueError("protected rich GitHub subjects are duplicated")
        record_subjects.add(subject_ref)
        source_rich_subject_count += int(has_rich_evidence)
    if record_subjects != candidate_subjects:
        raise PermissionError("protected rich GitHub subjects do not match current applicants")
    result = source_stage.result
    if (
        not isinstance(result, dict)
        or result.get("record_count") != len(records)
        or not isinstance(result.get("output_hash"), str)
    ):
        raise PermissionError("protected rich GitHub stage does not match its pipeline receipt")
    canonical_source_output_hash = _canonical_hash(records)
    pipeline_output_hash = str(result["output_hash"])
    legacy_records_snapshot: _LegacyRichGitHubRecordsSnapshot | None = None
    if hmac.compare_digest(pipeline_output_hash, canonical_source_output_hash):
        source_receipt_scheme = _CANONICAL_RICH_GITHUB_RECEIPT_SCHEME
    else:
        try:
            legacy_records_snapshot = _read_legacy_rich_github_records_snapshot(
                source_descriptor,
                approval=approval,
                records=records,
                pipeline_output_hash=pipeline_output_hash,
            )
        except _LegacyRichGitHubReceiptUnavailable as error:
            raise PermissionError(
                "protected rich GitHub stage does not match its pipeline receipt",
            ) from error
        source_receipt_scheme = _LEGACY_RICH_GITHUB_RECEIPT_SCHEME

    projected_records: list[dict[str, object]] = []
    rich_subject_count = 0
    redaction_count = 0
    normalization_count = 0
    for record in records:
        projected, has_rich_evidence, redactions, normalizations = (
            _project_rich_github_record(
                record,
                now=current,
                run_wide_identity_literals=identity_corpus,
                subject_identity_literals=subject_identity_literals,
            )
        )
        projected_records.append(projected)
        rich_subject_count += int(has_rich_evidence)
        redaction_count += redactions
        normalization_count += normalizations
    if rich_subject_count != source_rich_subject_count:
        raise PermissionError("rich GitHub projection changed subject coverage")
    destination_stage_value = dict(stage_value)
    destination_stage_value["records"] = projected_records
    destination_stage_projected_bytes = (
        json.dumps(
            destination_stage_value,
            allow_nan=False,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ) + "\n"
    ).encode("utf-8")
    source_stage_sha256 = hashlib.sha256(source_stage_bytes).hexdigest()
    destination_stage_sha256 = hashlib.sha256(
        destination_stage_projected_bytes,
    ).hexdigest()
    destination_output_hash = _canonical_hash(projected_records)

    def install() -> None:
        _atomic_replace_protected_file(
            destination_descriptor, ("protected", "stages"), "github.json",
            destination_stage_projected_bytes, label="operator GitHub stage",
        )

    source_guard_calls = 0
    observed_source_drift: PermissionError | None = None

    def transaction_source_guard() -> None:
        """Pin source files before commit and enforce the same snapshot after it."""
        nonlocal source_guard_calls, observed_source_drift
        source_root_guard()
        try:
            _assert_protected_file_snapshot(
                source_descriptor, ("pipeline-state.json",),
                "rich GitHub source pipeline state", max_bytes=4 * 1024 * 1024,
                expected_payload=source_pipeline_bytes,
                expected_metadata=source_pipeline_metadata,
            )
            _assert_protected_file_snapshot(
                source_descriptor, ("protected", "stages", "github.json"),
                "rich GitHub source stage", max_bytes=25 * 1024 * 1024,
                expected_payload=source_stage_bytes,
                expected_metadata=source_stage_metadata,
            )
            _assert_protected_file_snapshot(
                source_descriptor, ("collection-approval.json",),
                "rich GitHub collection approval", max_bytes=64 * 1024,
                expected_payload=approval_bytes,
                expected_metadata=approval_metadata,
            )
            if legacy_records_snapshot is not None:
                _assert_legacy_rich_github_records_snapshot(
                    source_descriptor,
                    approval=approval,
                    records=records,
                    pipeline_output_hash=pipeline_output_hash,
                    expected=legacy_records_snapshot,
                )
        except PermissionError as error:
            if observed_source_drift is None:
                observed_source_drift = error
        source_guard_calls += 1
        # The operator's first guard is the precommit boundary. Defer a drift
        # found there until its postcommit guard so the existing transaction
        # rolls back destination bytes and leaves GitHub failed, not complete.
        if source_guard_calls >= 2 and observed_source_drift is not None:
            raise observed_source_drift

    try:
        getattr(state, "install_imported_github_stage")(
            installer=install,
            source_guard=transaction_source_guard,
            destination_root_descriptor=destination_descriptor,
            expected_root_identity=destination_identity,
            output_hash=destination_output_hash,
            record_count=len(projected_records),
        )
    except BaseException:
        try:
            _atomic_replace_protected_file(
                destination_descriptor, ("protected", "stages"), "github.json",
                destination_stage_bytes, label="operator GitHub stage rollback",
            )
        except BaseException as rollback_error:
            raise PermissionError(
                "rich GitHub import failed and destination rollback did not complete",
            ) from rollback_error
        raise
    return {
        "destination_output_hash": destination_output_hash,
        "destination_stage_sha256": destination_stage_sha256,
        "normalization_count": normalization_count,
        "record_count": len(projected_records),
        "receipt_version": "protected-rich-github-stage-import-v2",
        "redaction_count": redaction_count,
        "rich_subject_count": rich_subject_count,
        "source_output_hash": pipeline_output_hash,
        "source_receipt_scheme": source_receipt_scheme,
        "source_stage_sha256": source_stage_sha256,
    }


def _validate_classification_dimensions(value: object) -> None:
    if not isinstance(value, Mapping) or set(value) != _CLASSIFICATION_DIMENSIONS:
        raise ValueError("corrected classification dimensions are incomplete")
    for dimension, result in value.items():
        if not isinstance(result, Mapping) or set(result) != {
            "confidence", "evidence_refs", "labels", "state",
        }:
            raise ValueError(f"corrected classification dimensions are invalid: {dimension}")
        labels = result["labels"]
        confidence = result["confidence"]
        evidence_refs = result["evidence_refs"]
        if (
            not isinstance(labels, list) or not labels
            or any(not isinstance(label, str) or not _CODE.fullmatch(label) for label in labels)
            or len(set(labels)) != len(labels)
            or isinstance(confidence, bool) or not isinstance(confidence, (int, float))
            or not 0 <= float(confidence) <= 1
            or not isinstance(evidence_refs, list)
            or any(
                not isinstance(reference, str)
                or not re.fullmatch(r"evidence:[a-z_]+:[0-9a-f]{64}", reference)
                for reference in evidence_refs
            )
            or result["state"] not in {"observed", "unknown"}
        ):
            raise ValueError(f"corrected classification dimensions are invalid: {dimension}")
        if result["state"] == "unknown" and (
            float(confidence) != 0 or labels not in (["unknown"], ["insufficient_evidence"])
        ):
            raise ValueError(f"corrected classification dimensions are invalid: {dimension}")


@dataclass(frozen=True)
class ReviewDecision:
    case_code: str
    case_hash: str
    action: str
    selected_code: str | None = None
    corrected_output: Mapping[str, object] | None = None
    actor_code: str | None = None
    decided_at: str | None = None

    def __post_init__(self) -> None:
        _code(self.case_code, "case_code")
        if not _HASH.fullmatch(self.case_hash):
            raise ValueError("case_hash must be SHA-256")
        _code(self.action, "action")
        if self.selected_code is not None:
            _code(self.selected_code, "selected_code")
        if self.actor_code is not None:
            _code(self.actor_code, "actor_code")
        if self.decided_at is not None:
            try:
                parsed = datetime.fromisoformat(self.decided_at.replace("Z", "+00:00"))
            except ValueError as error:
                raise ValueError("decided_at is invalid") from error
            if parsed.tzinfo is None:
                raise ValueError("decided_at requires a timezone")
        if self.corrected_output is not None and not isinstance(self.corrected_output, Mapping):
            raise ValueError("corrected_output must be an object")

    def to_dict(self) -> dict[str, object]:
        return {
            "action": self.action,
            "actor_code": self.actor_code,
            "case_code": self.case_code,
            "case_hash": self.case_hash,
            "corrected_output": dict(self.corrected_output) if self.corrected_output is not None else None,
            "decided_at": self.decided_at,
            "selected_code": self.selected_code,
        }

    @classmethod
    def from_dict(cls, value: object) -> "ReviewDecision":
        if not isinstance(value, dict) or set(value) != {
            "action", "actor_code", "case_code", "case_hash", "corrected_output",
            "decided_at", "selected_code",
        }:
            raise ValueError("review decision keys are invalid")
        return cls(**value)


@dataclass(frozen=True)
class ReviewCase:
    case_code: str
    case_hash: str
    kind: str
    subject_code: str
    reason_codes: tuple[str, ...]
    candidate_codes: tuple[str, ...]
    version: str
    status: str = "open"
    decision: ReviewDecision | None = None

    def __post_init__(self) -> None:
        _code(self.case_code, "case_code")
        if not _HASH.fullmatch(self.case_hash):
            raise ValueError("case_hash must be SHA-256")
        if self.kind not in _KINDS:
            raise ValueError("review case kind is invalid")
        _code(self.subject_code, "subject_code")
        _code(self.version, "version")
        if not self.reason_codes or len(set(self.reason_codes)) != len(self.reason_codes):
            raise ValueError("review case requires unique reasons")
        for value in self.reason_codes:
            _code(value, "reason_code")
        if len(set(self.candidate_codes)) != len(self.candidate_codes):
            raise ValueError("review candidate codes must be unique")
        for value in self.candidate_codes:
            _code(value, "candidate_code")
        if self.status not in {"open", "resolved"}:
            raise ValueError("review case status is invalid")
        if (self.status == "open") != (self.decision is None):
            raise ValueError("review case status and decision do not agree")
        if self.decision is not None and (
            self.decision.case_code != self.case_code
            or self.decision.case_hash != self.case_hash
        ):
            raise ValueError("review decision is not bound to its case")

    @classmethod
    def create(
        cls, *, kind: str, subject_code: str, reason_codes: tuple[str, ...],
        candidate_codes: tuple[str, ...], source_hashes: Mapping[str, str], version: str,
    ) -> "ReviewCase":
        if kind not in _KINDS:
            raise ValueError("review case kind is invalid")
        _code(subject_code, "subject_code")
        _code(version, "version")
        normalized_hashes: dict[str, str] = {}
        for key, value in source_hashes.items():
            if not isinstance(key, str) or not _SOURCE_CODE.fullmatch(key):
                raise ValueError("source_code must be a machine-readable code")
            normalized_hashes[key] = value
            if not _HASH.fullmatch(value):
                raise ValueError("source hash must be SHA-256")
        material = {
            "candidate_codes": list(candidate_codes),
            "kind": kind,
            "reason_codes": list(reason_codes),
            "source_hashes": dict(sorted(normalized_hashes.items())),
            "subject_code": subject_code,
            "version": version,
        }
        case_hash = _canonical_hash(material)
        return cls(
            case_code=f"{kind}_{case_hash[:16]}", case_hash=case_hash, kind=kind,
            subject_code=subject_code, reason_codes=reason_codes,
            candidate_codes=candidate_codes, version=version,
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "candidate_codes": list(self.candidate_codes),
            "case_code": self.case_code,
            "case_hash": self.case_hash,
            "decision": self.decision.to_dict() if self.decision is not None else None,
            "kind": self.kind,
            "reason_codes": list(self.reason_codes),
            "status": self.status,
            "subject_code": self.subject_code,
            "version": self.version,
        }

    @classmethod
    def from_dict(cls, value: object) -> "ReviewCase":
        if not isinstance(value, dict) or set(value) != {
            "candidate_codes", "case_code", "case_hash", "decision", "kind",
            "reason_codes", "status", "subject_code", "version",
        }:
            raise ValueError("review case keys are invalid")
        decision = value["decision"]
        return cls(
            case_code=value["case_code"], case_hash=value["case_hash"], kind=value["kind"],
            subject_code=value["subject_code"], reason_codes=tuple(value["reason_codes"]),
            candidate_codes=tuple(value["candidate_codes"]), version=value["version"],
            status=value["status"],
            decision=ReviewDecision.from_dict(decision) if decision is not None else None,
        )


class ReviewRepository:
    """Persist case-bound decisions and invalidate them on evidence-version drift."""

    VERSION = "release-review-cases-v1"

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._cases: dict[str, ReviewCase] = {}
        if self.path.exists():
            self._load()

    def _load(self) -> None:
        payload = json.loads(self.path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict) or set(payload) != {"cases", "repository_version"}:
            raise ValueError("review repository keys are invalid")
        if payload["repository_version"] != self.VERSION or not isinstance(payload["cases"], list):
            raise ValueError("review repository version or cases are invalid")
        cases = [ReviewCase.from_dict(item) for item in payload["cases"]]
        if len({item.case_code for item in cases}) != len(cases):
            raise ValueError("review case codes must be unique")
        self._cases = {item.case_code: item for item in cases}

    def _persist(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.path.parent.chmod(0o700)
        payload = {
            "cases": [self._cases[key].to_dict() for key in sorted(self._cases)],
            "repository_version": self.VERSION,
        }
        temporary = self.path.with_name(self.path.name + ".tmp")
        temporary.write_text(
            json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        temporary.chmod(0o600)
        temporary.replace(self.path)

    def replace(self, cases: Iterable[ReviewCase]) -> None:
        materialized = tuple(cases)
        if len({item.case_code for item in materialized}) != len(materialized):
            raise ValueError("review case codes must be unique")
        refreshed: dict[str, ReviewCase] = {}
        for item in materialized:
            previous = self._cases.get(item.case_code)
            refreshed[item.case_code] = (
                previous
                if previous is not None and previous.case_hash == item.case_hash
                else item
            )
        self._cases = refreshed
        self._persist()

    def replace_for_kinds(
        self, kinds: Iterable[str], cases: Iterable[ReviewCase],
    ) -> None:
        selected = frozenset(kinds)
        if not selected or any(kind not in _KINDS for kind in selected):
            raise ValueError("review case kind is invalid")
        materialized = tuple(cases)
        if any(item.kind not in selected for item in materialized):
            raise ValueError("review refresh contains an unselected case kind")
        preserved = tuple(
            item for item in self._cases.values() if item.kind not in selected
        )
        self.replace((*preserved, *materialized))

    def list(self, *, kind: str | None = None) -> tuple[ReviewCase, ...]:
        if kind is not None and kind not in _KINDS:
            raise ValueError("review case kind is invalid")
        return tuple(
            self._cases[key] for key in sorted(self._cases)
            if kind is None or self._cases[key].kind == kind
        )

    def decide(
        self, decision: ReviewDecision, *, actor_code: str, decided_at: datetime,
    ) -> None:
        _code(actor_code, "actor_code")
        if decided_at.tzinfo is None:
            raise ValueError("decided_at requires a timezone")
        current = self._cases.get(decision.case_code)
        if current is None:
            raise ValueError("unknown review case")
        if current.case_hash != decision.case_hash:
            raise ValueError("stale review case")
        if current.status != "open":
            raise ValueError("review case is already resolved")
        self._validate_decision(current, decision)
        attributable = replace(
            decision,
            actor_code=actor_code,
            decided_at=decided_at.isoformat().replace("+00:00", "Z"),
        )
        self._cases[current.case_code] = replace(
            current, status="resolved", decision=attributable,
        )
        self._persist()

    @staticmethod
    def _validate_decision(case: ReviewCase, decision: ReviewDecision) -> None:
        if case.kind == "identity":
            if decision.action not in {"approve", "keep_separate", "quarantine"}:
                raise ValueError("identity review action is invalid")
            if decision.action == "approve":
                if decision.selected_code not in case.candidate_codes:
                    raise ValueError("identity approval must select an offered candidate")
            elif decision.selected_code is not None:
                raise ValueError("identity non-link decision cannot select a candidate")
        elif case.kind == "team":
            if decision.action != "link" or decision.selected_code not in case.candidate_codes:
                raise ValueError("team review must select an offered project")
        else:
            if decision.action not in {"approved", "corrected", "rejected"}:
                raise ValueError("classification review action is invalid")
            if decision.action == "corrected" and decision.corrected_output is None:
                raise ValueError("corrected classification requires structured output")
            if decision.action != "corrected" and decision.corrected_output is not None:
                raise ValueError("classification output is only valid for a correction")
            if decision.action == "corrected":
                _validate_classification_dimensions(decision.corrected_output)

    def assert_resolved(self, *kinds: str) -> None:
        for kind in kinds:
            if kind not in _KINDS:
                raise ValueError("review case kind is invalid")
            if any(item.kind == kind and item.status == "open" for item in self._cases.values()):
                raise PermissionError(f"{kind} review remains open")

    def authoritative_classification_cases(self) -> tuple[ReviewCase, ...]:
        """Return the richest current classification review path."""

        cases = self.list(kind="classification")
        rich = tuple(
            case for case in cases
            if case.version == "rich_semantic_review_v1"
        )
        return rich or cases

    def assert_authoritative_classification_resolved(self) -> None:
        """Require the richest current classification path to be resolved.

        A complete rich-semantic run supersedes the earlier deterministic review
        queue. Population coverage is verified separately by the rich aggregate
        builder before release artifacts are written.
        """

        if any(
            case.status == "open"
            for case in self.authoritative_classification_cases()
        ):
            raise PermissionError("classification review remains open")


Operation = Callable[[], Sequence[Mapping[str, object]]]
_OPERATION_STAGES = (
    "privacy_cleanup", "reconcile", "github", "public_pages", "coresignal",
    "classification", "aggregate", "report", "publish",
)


def _pseudonymous_code(prefix: str, value: str, secret: bytes) -> str:
    _code(prefix, "pseudonym_prefix")
    if not secret:
        raise ValueError("pseudonym secret is required")
    digest = hmac.new(secret, value.encode("utf-8"), hashlib.sha256).hexdigest()[:24]
    return f"{prefix}_{digest}"


@dataclass(frozen=True)
class ReviewPlan:
    cases: tuple[ReviewCase, ...]
    bindings: Mapping[str, object]


@dataclass(frozen=True)
class ReconciliationInputs:
    applications: tuple[Mapping[str, object], ...]
    preference_records: tuple[object, ...]
    submission_records: tuple[object, ...]
    preferences: Mapping[str, Mapping[str, object]]
    projects: Mapping[str, Mapping[str, object]]


def plan_source_reviews(
    *, applications: Iterable[Mapping[str, object]],
    preference_records: Iterable[object], submission_records: Iterable[object],
    preferences: Mapping[str, Mapping[str, object]],
    projects: Mapping[str, Mapping[str, object]],
    source_hashes: Mapping[str, str], pseudonym_secret: bytes,
) -> ReviewPlan:
    """Plan real identity and team cases without putting direct identifiers in cases."""
    from community_os.real_report import normalize_team_name

    application_rows = tuple(dict(item) for item in applications)
    application_by_email: dict[str, str] = {}
    application_by_name: dict[str, list[str]] = {}
    application_codes: dict[str, str] = {}
    for application in application_rows:
        external_id = str(application.get("external_id") or "").strip()
        email = str(application.get("email") or "").strip().casefold()
        if not external_id or not email or email in application_by_email:
            raise ValueError("applications require unique identifiers and emails")
        application_by_email[email] = external_id
        normalized_name = normalize_team_name(application.get("name"))
        if normalized_name:
            application_by_name.setdefault(normalized_name, []).append(external_id)
        application_codes[external_id] = _pseudonymous_code(
            "person", external_id, pseudonym_secret,
        )

    cases: list[ReviewCase] = []
    exact_person_links: dict[str, str] = {}
    identity_subjects: dict[str, object] = {}
    seen_source_refs: set[str] = set()
    for source_kind, records in (
        ("preference", tuple(preference_records)),
        ("submission", tuple(submission_records)),
    ):
        for record in records:
            source_ref = str(getattr(record, "external_id", "")).strip()
            if not source_ref or source_ref in seen_source_refs:
                raise ValueError("membership source references must be unique")
            seen_source_refs.add(source_ref)
            email = str(getattr(record, "email", "")).strip().casefold()
            exact = application_by_email.get(email)
            if exact is not None:
                exact_person_links[source_ref] = exact
                continue
            normalized_name = normalize_team_name(getattr(record, "name", ""))
            candidate_ids = tuple(application_by_name.get(normalized_name, ()))
            candidate_codes = tuple(application_codes[value] for value in candidate_ids)
            subject_code = _pseudonymous_code(
                "member", f"{source_kind}:{source_ref}", pseudonym_secret,
            )
            identity_subjects[subject_code] = {
                "candidate_map": dict(zip(candidate_codes, candidate_ids, strict=True)),
                "source_ref": source_ref,
                "source_kind": source_kind,
            }
            cases.append(ReviewCase.create(
                kind="identity", subject_code=subject_code,
                reason_codes=("email_mismatch",), candidate_codes=candidate_codes,
                source_hashes=source_hashes, version="identity_rules_v1",
            ))

    projects_by_normalized: dict[str, list[str]] = {}
    for project in projects:
        projects_by_normalized.setdefault(normalize_team_name(project), []).append(project)
    project_codes = {
        project: _pseudonymous_code("project", project, pseudonym_secret)
        for project in projects
    }
    exact_team_links: dict[str, str] = {}
    team_subjects: dict[str, object] = {}
    used_projects: set[str] = set()
    for preference, value in preferences.items():
        track = str(value.get("track") or "")
        exact = [
            project for project in projects_by_normalized.get(normalize_team_name(preference), ())
            if str(projects[project].get("track") or "") == track and project not in used_projects
        ]
        if len(exact) == 1:
            exact_team_links[preference] = exact[0]
            used_projects.add(exact[0])
            continue
        candidates = tuple(
            project for project, project_value in projects.items()
            if str(project_value.get("track") or "") == track and project not in used_projects
        )
        candidate_codes = tuple(project_codes[project] for project in candidates)
        subject_code = _pseudonymous_code("team", preference, pseudonym_secret)
        team_subjects[subject_code] = {
            "candidate_map": dict(zip(candidate_codes, candidates, strict=True)),
            "preference_team": preference,
            "track": track,
        }
        cases.append(ReviewCase.create(
            kind="team", subject_code=subject_code,
            reason_codes=("ambiguous_match",), candidate_codes=candidate_codes,
            source_hashes=source_hashes, version="team_rules_v1",
        ))

    return ReviewPlan(
        cases=tuple(sorted(cases, key=lambda item: item.case_code)),
        bindings={
            "exact_person_links": exact_person_links,
            "exact_team_links": exact_team_links,
            "identity_subjects": identity_subjects,
            "team_subjects": team_subjects,
        },
    )


def _load_reconciliation_inputs(state: object) -> ReconciliationInputs:
    from community_os.real_report import _application_rows, _group_final_sources

    snapshot = getattr(state, "snapshot")()
    uploads = Path(getattr(state, "protected_uploads"))
    slots = snapshot["source_slots"]
    try:
        applications_path = uploads / str(slots["applications"]["path"])
        preferences_path = uploads / str(slots["preferences"]["path"])
        submissions_path = uploads / str(slots["submissions"]["path"])
    except (KeyError, TypeError) as error:
        raise PermissionError("four validated protected sources are required") from error
    preference_records, submission_records, preferences, projects = _group_final_sources(
        preferences_path,
        submissions_path,
        event_definition=state.event_definition,
    )
    return ReconciliationInputs(
        applications=tuple(_application_rows(
            applications_path,
            event_definition=state.event_definition,
        )),
        preference_records=tuple(preference_records),
        submission_records=tuple(submission_records),
        preferences=preferences,
        projects=projects,
    )


def build_reconcile_service(
    state: object, *, pseudonym_secret: bytes,
    source_loader: Callable[[object], ReconciliationInputs] = _load_reconciliation_inputs,
) -> Operation:
    """Create the deterministic reconciliation operation used by the protected registry."""
    if not pseudonym_secret:
        raise ValueError("pseudonym secret is required")

    def reconcile() -> list[dict[str, object]]:
        snapshot = getattr(state, "snapshot")()
        slots = snapshot["source_slots"]
        source_hashes = _review_case_source_hashes(state, {
            str(key): str(value["sha256"]) for key, value in slots.items()
        })
        inputs = source_loader(state)
        plan = plan_source_reviews(
            applications=inputs.applications,
            preference_records=inputs.preference_records,
            submission_records=inputs.submission_records,
            preferences=inputs.preferences,
            projects=inputs.projects,
            source_hashes=source_hashes,
            pseudonym_secret=pseudonym_secret,
        )
        repository: ReviewRepository = getattr(state, "review_repository")
        repository.replace_for_kinds(("identity", "team"), plan.cases)
        _persist_review_bindings(state, plan.bindings)
        identity_count = sum(item.kind == "identity" for item in plan.cases)
        team_count = sum(item.kind == "team" for item in plan.cases)
        return [{
            "identity_cases": identity_count,
            "state": "needs_review" if plan.cases else "complete",
            "team_cases": team_count,
        }]

    return reconcile


def _current_review_source_hashes(state: object) -> dict[str, str | None]:
    snapshot = getattr(state, "snapshot")()
    slots = snapshot.get("source_slots")
    roles = tuple(str(role) for role in getattr(state, "source_slots"))
    if (
        not isinstance(slots, dict)
        or len(roles) != len(set(roles))
        or not set(slots).issubset(roles)
    ):
        raise PermissionError("operator source roles do not match the event definition")
    hashes: dict[str, str | None] = {}
    for role in roles:
        slot = slots.get(role)
        if slot is None:
            # Bind pre-approval state exactly. Event approval separately rejects
            # null for required roles, while optional roles must stay explicit.
            hashes[role] = None
            continue
        digest = slot.get("sha256") if isinstance(slot, dict) else None
        if not isinstance(digest, str) or not _HASH.fullmatch(digest):
            raise PermissionError(f"operator source hash is invalid: {role}")
        hashes[role] = digest
    return hashes


def _current_event_approval_sha256(state: object) -> str | None:
    if hasattr(state, "event_approval_sha256"):
        digest = getattr(state, "event_approval_sha256")
        if digest is None:
            return None
    else:
        snapshot = getattr(state, "snapshot")()
        if not isinstance(snapshot, dict):
            raise PermissionError("operator event approval binding is invalid")
        approval = snapshot.get("event_approval")
        if approval is None:
            return None
        digest = approval.get("sha256") if isinstance(approval, dict) else None
    if not isinstance(digest, str) or not _HASH.fullmatch(digest):
        raise PermissionError("operator event approval binding is invalid")
    return digest


def _review_case_source_hashes(
    state: object, source_hashes: Mapping[str, str],
) -> dict[str, str]:
    """Bind a review case to its event, approval, and exact source evidence."""

    reserved = {"event_key", "event_definition", "event_approval"}
    if not isinstance(source_hashes, Mapping) or reserved.intersection(source_hashes):
        raise ValueError("review case source hashes contain reserved context keys")
    event_key = getattr(state, "event_key", None)
    definition_sha256 = getattr(state, "event_definition_sha256", None)
    if (
        not isinstance(event_key, str)
        or not _EVENT_KEY.fullmatch(event_key)
        or not isinstance(definition_sha256, str)
        or not _HASH.fullmatch(definition_sha256)
    ):
        raise PermissionError("operator event binding is invalid")
    approval_sha256 = _current_event_approval_sha256(state)
    return {
        **dict(source_hashes),
        "event_approval": approval_sha256 or _NO_EVENT_APPROVAL_SHA256,
        "event_definition": definition_sha256,
        "event_key": hashlib.sha256(event_key.encode("utf-8")).hexdigest(),
    }


def _review_binding_envelope(
    state: object, bindings: Mapping[str, object],
) -> dict[str, object]:
    if not isinstance(bindings, Mapping):
        raise ValueError("review bindings are invalid")
    event_key = getattr(state, "event_key", None)
    definition_sha256 = getattr(state, "event_definition_sha256", None)
    if (
        not isinstance(event_key, str)
        or not _EVENT_KEY.fullmatch(event_key)
        or not isinstance(definition_sha256, str)
        or not _HASH.fullmatch(definition_sha256)
    ):
        raise PermissionError("operator event binding is invalid")
    return {
        "bindings": dict(bindings),
        "bindings_version": _REVIEW_BINDINGS_VERSION,
        "event_approval_sha256": _current_event_approval_sha256(state),
        "event_definition_sha256": definition_sha256,
        "event_key": event_key,
        "source_hashes": _current_review_source_hashes(state),
    }


def _persist_review_bindings(
    state: object, bindings: Mapping[str, object],
) -> None:
    path = Path(getattr(state, "root")) / "protected" / "review-bindings.json"
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.parent.chmod(0o700)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(
        json.dumps(
            _review_binding_envelope(state, bindings),
            ensure_ascii=True, sort_keys=True, separators=(",", ":"),
            allow_nan=False,
        ) + "\n",
        encoding="utf-8",
    )
    temporary.chmod(0o600)
    temporary.replace(path)


def _reject_duplicate_review_binding_keys(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"review bindings contain duplicate key: {key}")
        result[key] = value
    return result


def _reject_nonfinite_review_binding(value: str) -> None:
    raise ValueError(f"review bindings contain non-finite value: {value}")


def _load_review_bindings(state: object) -> dict[str, object]:
    path = Path(getattr(state, "root")) / "protected" / "review-bindings.json"
    try:
        payload = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_review_binding_keys,
            parse_constant=_reject_nonfinite_review_binding,
        )
    except (OSError, json.JSONDecodeError) as error:
        raise PermissionError("protected review bindings are missing or unreadable") from error
    if (
        not isinstance(payload, dict)
        or set(payload) != _REVIEW_BINDING_KEYS
        or payload.get("bindings_version") != _REVIEW_BINDINGS_VERSION
        or not isinstance(payload.get("bindings"), dict)
        or not isinstance(payload.get("source_hashes"), dict)
    ):
        raise ValueError("review bindings are invalid")
    event_key = getattr(state, "event_key")
    definition_sha256 = getattr(state, "event_definition_sha256")
    stored_event_key = payload["event_key"]
    stored_definition_sha256 = payload["event_definition_sha256"]
    stored_approval_sha256 = payload["event_approval_sha256"]
    if (
        not isinstance(stored_event_key, str)
        or not _EVENT_KEY.fullmatch(stored_event_key)
        or not isinstance(event_key, str)
        or not hmac.compare_digest(stored_event_key, event_key)
    ):
        raise PermissionError("review bindings event key does not match")
    if (
        not isinstance(stored_definition_sha256, str)
        or not _HASH.fullmatch(stored_definition_sha256)
        or not isinstance(definition_sha256, str)
        or not hmac.compare_digest(stored_definition_sha256, definition_sha256)
    ):
        raise PermissionError("review bindings event definition does not match")
    current_approval_sha256 = _current_event_approval_sha256(state)
    if stored_approval_sha256 is None and current_approval_sha256 is None:
        pass
    elif (
        not isinstance(stored_approval_sha256, str)
        or not _HASH.fullmatch(stored_approval_sha256)
        or not isinstance(current_approval_sha256, str)
        or not hmac.compare_digest(
            stored_approval_sha256, current_approval_sha256,
        )
    ):
        raise PermissionError("review bindings event approval does not match")
    source_hashes = payload["source_hashes"]
    assert isinstance(source_hashes, dict)
    current_source_hashes = _current_review_source_hashes(state)
    if set(source_hashes) != set(current_source_hashes) or any(
        source_hashes[role] != current_source_hashes[role]
        for role in current_source_hashes
    ):
        raise PermissionError("review bindings source hashes do not match")
    return dict(payload["bindings"])


def _load_observed_attendance(
    state: object,
    *,
    application_loader: Callable[[object], Iterable[Mapping[str, object]]] | None = None,
    attendance_loader: Callable[[object], Iterable[object]] | None = None,
) -> dict[str, int]:
    definition = getattr(state, "event_definition", None)
    if definition is None:
        raise PermissionError("event definition is required for attendance review")
    applied_stage = definition.funnel_stage("applied")
    accepted_stage = definition.funnel_stage("accepted")
    present_stage = definition.funnel_stage("present")
    if (
        applied_stage.source_role != "applications"
        or applied_stage.match != "any_row"
        or accepted_stage.source_role != "attendance"
        or accepted_stage.match != "value_in"
        or accepted_stage.field is None
        or present_stage.source_role != "attendance"
        or present_stage.match != "non_empty"
        or present_stage.field is None
    ):
        raise PermissionError("event funnel is unsupported by the attendance reviewer")

    if attendance_loader is None:
        from community_os.operator_pipeline import SourceSlot, records_from_source

        snapshot = getattr(state, "snapshot")()
        slots = snapshot.get("source_slots", {})
        attendance = slots.get("attendance") if isinstance(slots, dict) else None
        if not isinstance(attendance, dict):
            raise PermissionError("validated attendance source is required")
        path = Path(getattr(state, "protected_uploads")) / str(attendance["path"])
        records = tuple(records_from_source(
            path,
            SourceSlot.LUMA,
            source=definition.source("attendance"),
        ))
    else:
        records = tuple(attendance_loader(state))

    def field_value(record: object, field: str) -> str:
        payload = getattr(record, "payload", None)
        value = payload.get(field) if isinstance(payload, Mapping) else None
        if value is None:
            value = getattr(record, field, None)
        return str(value or "").strip()

    applications = tuple(
        (application_loader or _load_applications)(state)
    )
    accepted_values = {
        value.casefold() for value in accepted_stage.accepted_values
    }
    return {
        "applied": len(applications),
        "going_accepted": sum(
            field_value(record, accepted_stage.field).casefold() in accepted_values
            for record in records
        ),
        "on_site_builders": sum(
            bool(field_value(record, present_stage.field)) for record in records
        ),
    }


def build_reviewed_override(
    state: object, *, generated_at: str,
    inputs: ReconciliationInputs | None = None,
    observed_attendance: Mapping[str, int] | None = None,
) -> dict[str, object]:
    """Project only current, case-bound human decisions into the private real-release override."""
    try:
        timestamp = datetime.fromisoformat(generated_at.replace("Z", "+00:00"))
    except (AttributeError, ValueError) as error:
        raise ValueError("generated_at is invalid") from error
    if timestamp.tzinfo is None:
        raise ValueError("generated_at requires a timezone")
    reviews: ReviewRepository = getattr(state, "review_repository")
    reviews.assert_resolved("identity", "team")
    reviews.assert_authoritative_classification_resolved()
    bindings = _load_review_bindings(state)
    source_inputs = inputs or _load_reconciliation_inputs(state)
    observed = dict(observed_attendance or _load_observed_attendance(state))
    if set(observed) != {"applied", "going_accepted", "on_site_builders"}:
        raise ValueError("observed attendance fields are invalid")

    person_links = dict(bindings.get("exact_person_links", {}))
    quarantined: set[str] = set()
    identity_subjects = bindings.get("identity_subjects", {})
    if not isinstance(identity_subjects, dict):
        raise ValueError("identity review bindings are invalid")
    for case in reviews.list(kind="identity"):
        subject = identity_subjects.get(case.subject_code)
        if not isinstance(subject, dict) or case.decision is None:
            raise ValueError("identity review binding is missing")
        source_ref = str(subject.get("source_ref") or "")
        candidates = subject.get("candidate_map")
        if not source_ref or not isinstance(candidates, dict):
            raise ValueError("identity review binding is invalid")
        if case.decision.action == "approve":
            selected = candidates.get(case.decision.selected_code)
            if not isinstance(selected, str) or not selected:
                raise ValueError("identity decision target is not bound")
            person_links[source_ref] = selected
        else:
            quarantined.add(source_ref)

    reviewed_team_links: dict[str, str] = {}
    team_subjects = bindings.get("team_subjects", {})
    if not isinstance(team_subjects, dict):
        raise ValueError("team review bindings are invalid")
    for case in reviews.list(kind="team"):
        subject = team_subjects.get(case.subject_code)
        if not isinstance(subject, dict) or case.decision is None:
            raise ValueError("team review binding is missing")
        candidates = subject.get("candidate_map")
        preference = str(subject.get("preference_team") or "")
        if not preference or not isinstance(candidates, dict):
            raise ValueError("team review binding is invalid")
        selected = candidates.get(case.decision.selected_code)
        if not isinstance(selected, str) or not selected:
            raise ValueError("team decision target is not bound")
        reviewed_team_links[preference] = selected
    from community_os.real_report import match_teams

    team_links = match_teams(
        source_inputs.preferences, source_inputs.projects,
        reviewed_links=reviewed_team_links,
    )
    classifications = reviews.authoritative_classification_cases()
    if any(
        case.decision is None or (
            case.decision.action == "rejected"
            and case.version != "rich_semantic_review_v1"
        )
        for case in classifications
    ):
        raise PermissionError("rejected or missing classification review blocks release")
    classification_provenance: dict[str, object] = {
        "classifier_version": "deterministic-rules-v1", "model": "none",
        "prompt_version": "not_applicable", "processor_approval_hash": None,
    }
    stage_path = Path(getattr(state, "root")) / "protected" / "stages" / "classification.json"
    if stage_path.is_file():
        try:
            stage_payload = json.loads(stage_path.read_text(encoding="utf-8"))
            stage_records = stage_payload["records"]
        except (OSError, KeyError, TypeError, json.JSONDecodeError) as error:
            raise PermissionError("classification provenance is unreadable") from error
        if not isinstance(stage_records, list) or not stage_records:
            raise PermissionError("classification provenance is missing")
        provenance = {
            (
                str(record.get("classifier_version") or ""),
                str(record.get("model") or "none"),
                str(record.get("prompt_version") or "not_applicable"),
                record.get("processor_approval_hash"),
            )
            for record in stage_records if isinstance(record, Mapping)
        }
        if len(provenance) != 1:
            raise PermissionError("classification provenance is inconsistent")
        classifier_version, model, prompt_version, processor_hash = provenance.pop()
        if classifier_version == "semantic-v1":
            if (
                not model or model == "none" or not prompt_version
                or not _HASH.fullmatch(str(processor_hash or ""))
            ):
                raise PermissionError("semantic classification provenance is incomplete")
        elif classifier_version != "deterministic-rules-v1":
            raise PermissionError("classification provenance version is unsupported")
        classification_provenance = {
            "classifier_version": classifier_version, "model": model,
            "prompt_version": prompt_version,
            "processor_approval_hash": processor_hash,
        }

    snapshot = getattr(state, "snapshot")()
    reviewed_state = snapshot.get("reviewed_values", {})
    if not isinstance(reviewed_state, dict):
        raise ValueError("reviewed source values are invalid")
    source_snapshot_sha256 = getattr(state, "source_snapshot_sha256")()
    event_key = str(getattr(state, "event_key"))
    corrections: list[dict[str, object]] = []
    reviewed_values: list[dict[str, object]] = []
    for field in ("going_accepted", "on_site_builders"):
        decision = reviewed_state.get(field)
        if not isinstance(decision, dict) or set(decision) != {
            "decision", "reason_code", "reviewed_value",
            "source_snapshot_sha256", "source_value",
        }:
            raise PermissionError(f"reviewed source value is required: {field}")
        expected_decision = (
            "approved"
            if decision["source_value"] == decision["reviewed_value"]
            else "corrected"
        )
        if (
            decision["decision"] != expected_decision
            or decision["source_value"] != observed[field]
            or decision["source_snapshot_sha256"] != source_snapshot_sha256
        ):
            raise PermissionError(f"reviewed source value is stale or inconsistent: {field}")
        reviewed_values.append({
            "decision": expected_decision,
            "field": field,
            "reason": decision["reason_code"],
            "reviewed_value": decision["reviewed_value"],
            "source_value": decision["source_value"],
            "stable_key": f"event:{event_key}:{field}",
        })
        if expected_decision == "corrected":
            corrections.append({
                "stable_key": f"event:{event_key}:{field}",
                "field": field,
                "source_value": decision["source_value"],
                "corrected_value": decision["reviewed_value"],
                "reason": decision["reason_code"],
                "evidence_note": "Accountable owner supplied a reviewed aggregate correction",
            })
    operational_state = snapshot.get("operational_facts", {})
    if not isinstance(operational_state, dict):
        raise ValueError("reviewed operational facts are invalid")
    operational_facts: list[dict[str, object]] = []
    for key, fact in sorted(operational_state.items()):
        if not isinstance(fact, dict) or set(fact) != {
            "funnel_stage", "reason_code", "source_snapshot_sha256", "unit", "value",
        }:
            raise ValueError("reviewed operational fact is invalid")
        if (
            fact["funnel_stage"] is not False
            or fact["source_snapshot_sha256"] != source_snapshot_sha256
        ):
            raise PermissionError("reviewed operational fact is stale or entered the funnel")
        operational_facts.append({
            "funnel_stage": False,
            "note": "Separate reviewed operational fact, excluded from the attendance funnel",
            "reason": fact["reason_code"],
            "stable_key": f"event:{event_key}:{key}",
            "unit": fact["unit"],
            "value": fact["value"],
        })

    return {
        "classification_review": {
            **classification_provenance,
            "headline_categories": [],
            "note": "Every uncertain or consequential classification was case-bound and reviewed",
            "reviewed_at": generated_at,
            "reviewer": getattr(state, "operator_code"),
            "spot_check_count": len(classifications),
            "status": "approved",
        },
        "corrections": corrections,
        "operational_facts": operational_facts,
        "operator": getattr(state, "operator_code"),
        "override_version": "operator-reviewed-release-v1",
        "person_link_evidence": "Case-bound identity decisions and exact normalized email only",
        "person_links": dict(sorted(person_links.items())),
        "quarantine_reason": "Human decision preserved uncertain membership outside aggregates",
        "quarantined_refs": sorted(quarantined),
        "reviewed_values": reviewed_values,
        "team_link_evidence": "Exact normalized team names or case-bound same-track decisions",
        "team_links": dict(sorted(team_links.items())),
        "timestamp": generated_at,
    }


def _load_applications(state: object) -> tuple[Mapping[str, object], ...]:
    from community_os.real_report import _application_rows

    snapshot = getattr(state, "snapshot")()
    slot = snapshot["source_slots"].get("applications")
    if not isinstance(slot, dict):
        raise PermissionError("validated applications source is required")
    path = Path(getattr(state, "protected_uploads")) / str(slot["path"])
    return tuple(_application_rows(
        path,
        event_definition=state.event_definition,
    ))


def _protected_stage_records(state: object, stage: str) -> tuple[dict[str, object], ...]:
    path = Path(getattr(state, "root")) / "protected" / "stages" / f"{stage}.json"
    if not path.is_file():
        return ()
    if stage in {"github", "public_pages", "coresignal", "classification"}:
        pipeline = getattr(state, "pipeline", None)
        if pipeline is not None:
            status = pipeline.stage(stage).status.value
            if status == "locked":
                raise PermissionError(f"protected {stage} authorization is revoked")
            if status != "complete":
                return ()
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise PermissionError(f"protected {stage} output is unreadable") from error
    if (
        not isinstance(payload, dict)
        or payload.get("stage") != stage
        or payload.get("stage_output_version") != "protected-stage-output-v1"
        or not isinstance(payload.get("records"), list)
        or any(not isinstance(item, dict) for item in payload["records"])
    ):
        raise ValueError(f"protected {stage} output is invalid")
    if stage in {"github", "public_pages", "coresignal", "classification"}:
        try:
            expiry = datetime.fromisoformat(str(payload["expires_at"]).replace("Z", "+00:00"))
        except (KeyError, TypeError, ValueError) as error:
            raise PermissionError(f"protected {stage} retention is invalid") from error
        clock = getattr(state, "_release_operation_clock", None)
        current = clock() if callable(clock) else datetime.now(UTC)
        if current.tzinfo is None:
            raise PermissionError(f"protected {stage} retention clock is invalid")
        if expiry.tzinfo is None or expiry <= current:
            raise PermissionError(f"protected {stage} output is expired")
    return tuple(dict(item) for item in payload["records"])


def load_reviewed_classification_projection(
    state: object, *, pseudonym_secret: bytes,
    application_loader: Callable[[object], Iterable[Mapping[str, object]]] = _load_applications,
) -> dict[str, dict[str, set[str]]]:
    """Load the current case-bound classification output for aggregate generation."""
    from community_os.enrichment.state import pseudonymous_id

    records = _protected_stage_records(state, "classification")
    if not records:
        raise PermissionError("protected classification output is missing")
    by_subject: dict[str, dict[str, object]] = {}
    for record in records:
        subject_ref = str(record.get("subject_ref") or "")
        if not subject_ref or subject_ref in by_subject:
            raise ValueError("classification subjects are missing or duplicated")
        dimensions = record.get("dimensions")
        _validate_classification_dimensions(dimensions)
        by_subject[subject_ref] = record
    bindings = _load_review_bindings(state)
    subjects = bindings.get("classification_subjects", {})
    if not isinstance(subjects, dict):
        raise ValueError("classification review bindings are invalid")
    cases_by_subject = {
        case.subject_code: case
        for case in getattr(state, "review_repository").list(kind="classification")
    }
    projection: dict[str, dict[str, set[str]]] = {}
    applications = tuple(dict(item) for item in application_loader(state))
    for application in applications:
        external_id = str(application.get("external_id") or "").strip()
        subject_ref = pseudonymous_id(
            external_id, secret=pseudonym_secret, key_version="v1",
        )
        record = by_subject.pop(subject_ref, None)
        if record is None:
            raise ValueError("classification output does not match the applicant population")
        dimensions = record["dimensions"]
        bound_case = next(
            (
                cases_by_subject.get(subject_code)
                for subject_code, binding in subjects.items()
                if isinstance(binding, dict) and binding.get("subject_ref") == subject_ref
            ),
            None,
        )
        if record.get("review_state") == "pending":
            if bound_case is None or bound_case.status != "resolved" or bound_case.decision is None:
                raise PermissionError("classification review remains open")
            if bound_case.decision.action == "rejected":
                raise PermissionError("rejected classification blocks aggregate generation")
            if bound_case.decision.action == "corrected":
                dimensions = bound_case.decision.corrected_output
                _validate_classification_dimensions(dimensions)
        assert isinstance(dimensions, Mapping)
        projection[external_id] = {
            dimension: set(result["labels"])
            for dimension, result in dimensions.items()
            if isinstance(result, Mapping)
        }
    if by_subject:
        raise ValueError("classification output contains unknown subjects")
    return projection


def build_adapter_service(
    state: object, *, stage: str, field: str, pseudonym_secret: bytes,
    adapter_factory: Callable[[Callable[[object], bool]], object],
    application_loader: Callable[[object], Iterable[Mapping[str, object]]] = _load_applications,
) -> Operation:
    """Build one applicant-source-bound network stage without exposing identifiers."""
    if stage not in {"github", "public_pages", "coresignal"}:
        raise ValueError("adapter stage is invalid")
    if field not in {"github", "portfolio", "linkedin"}:
        raise ValueError("adapter source field is invalid")
    if not pseudonym_secret:
        raise ValueError("pseudonym secret is required")

    def enrich() -> list[dict[str, object]]:
        from community_os.enrichment.gates import CoresignalGate, PublicSourceGate
        from community_os.enrichment.state import pseudonymous_id
        from community_os.enrichment.transport import ApplicantSuppliedValue

        pipeline_state = getattr(state, "pipeline")
        stage_record = pipeline_state.stage(stage)
        if stage_record.authorization_record is None:
            raise PermissionError(f"{stage} authorization record is missing")
        authorization = (
            CoresignalGate.from_record(stage_record.authorization_record)
            if stage == "coresignal"
            else PublicSourceGate.from_record(stage_record.authorization_record)
        )
        applications = sorted(
            (dict(item) for item in application_loader(state)),
            key=lambda item: str(item.get("external_id") or ""),
        )
        references: list[tuple[str, ApplicantSuppliedValue]] = []
        allowed: set[tuple[str, str]] = set()
        for application in applications:
            external_id = str(application.get("external_id") or "").strip()
            value = str(application.get(field) or "").strip()
            if not external_id or not value:
                continue
            source_digest = hmac.new(
                pseudonym_secret, external_id.encode("utf-8"), hashlib.sha256,
            ).hexdigest()[:24]
            reference = ApplicantSuppliedValue(
                value=value,
                source_record_ref=f"source:application:{source_digest}",
            )
            references.append((external_id, reference))
            allowed.add((reference.source_record_ref, reference.value))

        def verify(reference: object) -> bool:
            return bool(
                isinstance(reference, ApplicantSuppliedValue)
                and (reference.source_record_ref, reference.value) in allowed
            )

        adapter = adapter_factory(verify)
        results: list[dict[str, object]] = []
        try:
            for external_id, reference in references:
                operation = getattr(adapter, "enrich", None)
                if not callable(operation):
                    raise ValueError("adapter factory did not return an enrichment adapter")
                subject_ref = pseudonymous_id(
                    external_id, secret=pseudonym_secret, key_version="v1",
                )
                result = operation(
                    reference, state=pipeline_state, authorization=authorization,
                    subject_ref=subject_ref,
                )
                if not isinstance(result, Mapping) or "subject_ref" in result:
                    raise ValueError("adapter returned an invalid protected result")
                results.append({"subject_ref": subject_ref, **dict(result)})
        except Exception as error:
            cleanup = getattr(adapter, "discard_transient", None)
            if not callable(cleanup):
                raise
            try:
                cleanup()
            except Exception as cleanup_error:
                raise PermissionError(f"{stage} failed and transient cleanup did not complete") from cleanup_error
            raise error
        return results

    return enrich


def _rich_identity_corpus(
    applications: Sequence[Mapping[str, object]], inputs: ReconciliationInputs,
) -> tuple[str, ...]:
    """Return only high-confidence direct run-wide identity literals."""
    literals: set[str] = set(_application_identity_corpus(applications))
    for record in inputs.submission_records:
        for field in ("external_id", "name", "email", "team_name", "submission_title"):
            value = str(getattr(record, field, "") or "").strip()
            if value:
                literals.add(value)
    if not literals:
        raise PermissionError("rich semantic identity corpus is empty")
    return tuple(sorted(literals, key=lambda value: (value.casefold(), value)))


def _rich_github_import_identity_corpus(
    state: object,
    applications: Sequence[Mapping[str, object]],
) -> tuple[str, ...]:
    """Use every available event identity source at the GitHub projection boundary."""
    snapshot = getattr(state, "snapshot")()
    slots = snapshot.get("source_slots") if isinstance(snapshot, Mapping) else None
    if not isinstance(slots, Mapping):
        raise PermissionError("current source bindings are missing")
    complete_event_sources = {
        "applications", "attendance", "preferences", "submissions",
    }
    if (
        complete_event_sources.issubset(slots)
        and isinstance(snapshot.get("event_approval"), Mapping)
    ):
        return _rich_identity_corpus(
            applications,
            _load_reconciliation_inputs(state),
        )
    return _application_identity_corpus(applications)


def rich_semantic_subject_ref(external_id: str, *, secret: bytes) -> str:
    """Derive the stable private case reference shared by review and population paths."""

    if not isinstance(external_id, str) or not external_id.strip():
        raise ValueError("rich semantic external identifier is required")
    if not isinstance(secret, bytes) or len(secret) < 16:
        raise ValueError("rich semantic pseudonym secret is invalid")
    return "case:v1:" + hmac.new(
        secret, f"rich:{external_id.strip()}".encode("utf-8"), hashlib.sha256,
    ).hexdigest()


def _resolved_person_links(state: object) -> tuple[dict[str, str], frozenset[str]]:
    """Resolve only exact or explicitly approved source-person bindings."""
    bindings = _load_review_bindings(state)
    links = dict(bindings.get("exact_person_links", {}))
    quarantined: set[str] = set()
    subjects = bindings.get("identity_subjects", {})
    if not isinstance(subjects, dict):
        raise ValueError("identity review bindings are invalid")
    for case in getattr(state, "review_repository").list(kind="identity"):
        binding = subjects.get(case.subject_code)
        if not isinstance(binding, dict) or case.decision is None:
            raise PermissionError("identity review remains unresolved")
        source_ref = str(binding.get("source_ref") or "")
        candidates = binding.get("candidate_map")
        if not source_ref or not isinstance(candidates, dict):
            raise ValueError("identity review binding is invalid")
        if case.decision.action == "approve":
            selected = candidates.get(case.decision.selected_code)
            if not isinstance(selected, str) or not selected:
                raise ValueError("identity decision target is not bound")
            links[source_ref] = selected
        else:
            quarantined.add(source_ref)
    return links, frozenset(quarantined)


def _devpost_technology_codes(value: object) -> list[str]:
    text = str(value or "").casefold()
    rules = {
        "android": ("android",), "applied_ai": ("openai", "artificial intelligence", " ai "),
        "blockchain": ("blockchain", "solidity", "web3"), "cloud": ("aws", "azure", "gcp"),
        "data": ("pandas", "data science"), "databases": ("postgres", "mongodb", "sql"),
        "devops": ("docker", "kubernetes", "terraform"), "dotnet": (".net", "c#"),
        "go": ("golang",), "ios": ("ios",), "javascript_typescript": (
            "javascript", "typescript", "react", "node", "next.js",
        ),
        "jvm": ("java", "kotlin"), "llm": ("llm", "openai", "gpt"),
        "machine_learning": ("machine learning", "pytorch", "tensorflow"),
        "mobile": ("flutter", "react native"), "no_code": ("bubble", "no-code"),
        "php": ("php",), "python": ("python",), "robotics": ("robot",),
        "ruby": ("ruby",), "rust": ("rust",), "shell": ("bash", "shell"),
        "speech": ("speech", "voice"), "swift": ("swift",),
        "web": ("web", "react", "next.js"),
        "web_backend": ("django", "fastapi", "express", "node"),
        "web_frontend": ("react", "vue", "angular", "next.js"),
    }
    padded = f" {text} "
    return sorted(
        code for code, needles in rules.items()
        if any(needle in padded for needle in needles)
    )[:12]


def _semantic_applications_and_cohort_membership(
    state: object,
    applications: Sequence[Mapping[str, object]],
    *,
    attendance_loader: Callable[[object], Iterable[object]] | None,
) -> tuple[tuple[dict[str, object], ...], dict[str, dict[str, bool]]]:
    """Resolve exact application membership from the reviewed event source rows."""

    from community_os.identity import normalize_email

    definition = getattr(state, "event_definition", None)
    if definition is None:
        raise PermissionError("event definition is required for semantic cohort ordering")
    accepted_stage = definition.funnel_stage("accepted")
    present_stage = definition.funnel_stage("present")
    if (
        accepted_stage.source_role != "attendance"
        or accepted_stage.match != "value_in"
        or accepted_stage.field is None
        or present_stage.source_role != "attendance"
        or present_stage.match != "non_empty"
        or present_stage.field is None
    ):
        raise PermissionError("event funnel is unsupported for semantic cohort ordering")

    if attendance_loader is None:
        from community_os.operator_pipeline import SourceSlot, records_from_source

        snapshot = getattr(state, "snapshot")()
        slots = snapshot.get("source_slots", {})
        attendance_slot = slots.get("attendance") if isinstance(slots, Mapping) else None
        filename = attendance_slot.get("path") if isinstance(attendance_slot, Mapping) else None
        if not isinstance(filename, str) or Path(filename).name != filename:
            raise PermissionError("validated attendance source is required for semantic cohort ordering")
        attendance_path = Path(getattr(state, "protected_uploads")) / filename
        attendance_records = tuple(records_from_source(
            attendance_path,
            SourceSlot.LUMA,
            source=definition.source("attendance"),
        ))
    else:
        attendance_records = tuple(attendance_loader(state))

    def record_value(record: object, field: str) -> str:
        payload = getattr(record, "payload", None)
        value = payload.get(field) if isinstance(payload, Mapping) else None
        if value is None:
            value = getattr(record, field, None)
        return str(value or "").strip()

    ordered_applications: list[dict[str, object]] = []
    application_emails: dict[str, str] = {}
    seen_external_ids: set[str] = set()
    for raw in applications:
        application = dict(raw)
        external_id = str(application.get("external_id") or "").strip()
        email = normalize_email(str(application.get("email") or ""))
        if not external_id or external_id in seen_external_ids:
            raise ValueError("rich semantic application identifiers are missing or duplicated")
        if not email or email in application_emails:
            raise PermissionError("rich semantic application emails are missing or duplicated")
        seen_external_ids.add(external_id)
        application_emails[email] = external_id
        ordered_applications.append(application)

    accepted_values = {
        value.casefold() for value in accepted_stage.accepted_values
    }
    attendance_state: dict[str, tuple[bool, bool]] = {}
    for record in attendance_records:
        email = normalize_email(
            str(getattr(record, "applicant_identity", "") or record_value(record, "email")),
        )
        if not email:
            raise PermissionError("semantic attendance email is missing")
        if email in attendance_state:
            raise PermissionError("semantic attendance emails are duplicated")
        accepted = record_value(record, accepted_stage.field).casefold() in accepted_values
        present = bool(record_value(record, present_stage.field))
        if present and not accepted:
            raise PermissionError("present applicant is not accepted by the event funnel")
        attendance_state[email] = (present, accepted)

    membership_by_external_id = {
        external_id: {
            "applied": True,
            "accepted": attendance_state.get(email, (False, False))[1],
            "present": attendance_state.get(email, (False, False))[0],
        }
        for email, external_id in application_emails.items()
    }
    return tuple(ordered_applications), membership_by_external_id


def derive_semantic_application_cohort_membership(
    state: object,
    applications: Sequence[Mapping[str, object]],
    *,
    attendance_loader: Callable[[object], Iterable[object]] | None,
) -> dict[str, dict[str, bool]]:
    """Return deterministic exact All, Accepted, and Present membership by source id."""

    _applications, membership = _semantic_applications_and_cohort_membership(
        state,
        applications,
        attendance_loader=attendance_loader,
    )
    return membership


def _order_semantic_applications_for_production(
    state: object,
    applications: Sequence[Mapping[str, object]],
    *,
    attendance_loader: Callable[[object], Iterable[object]] | None,
) -> tuple[dict[str, object], ...]:
    """Prioritize attributable present and accepted applicants for bounded runs."""

    ordered_applications, membership = _semantic_applications_and_cohort_membership(
        state,
        applications,
        attendance_loader=attendance_loader,
    )
    priority_by_external_id = {
        external_id: (
            0 if row["present"] else 1 if row["accepted"] else 2
        )
        for external_id, row in membership.items()
    }
    return tuple(sorted(
        ordered_applications,
        key=lambda application: (
            priority_by_external_id[str(application["external_id"]).strip()],
            str(application["external_id"]).strip(),
        ),
    ))


def build_rich_semantic_proposal_service(
    state: object, *, base_classification: Operation, pseudonym_secret: bytes,
    provider_factory: Callable[[tuple[str, ...]], object],
    cache: object, clock: Callable[[], datetime],
    application_loader: Callable[[object], Iterable[Mapping[str, object]]] = _load_applications,
    reconciliation_loader: Callable[[object], ReconciliationInputs] = _load_reconciliation_inputs,
    attendance_loader: Callable[[object], Iterable[object]] | None = None,
    career_evidence_loader: _CareerEvidenceLoader | None = None,
    run_mode: str | None = None,
    run_model: str | None = None,
    run_reasoning_effort: str | None = None,
    run_max_concurrency: int | None = None,
    input_cost_per_million_usd_micros: int | None = None,
    output_cost_per_million_usd_micros: int | None = None,
) -> Operation:
    """Add private rich semantic review proposals while preserving legacy output."""
    if not callable(base_classification) or not callable(provider_factory) or not callable(clock):
        raise TypeError("rich semantic service dependencies must be callable")
    if not pseudonym_secret:
        raise ValueError("pseudonym secret is required")
    run_values = (
        run_model, run_reasoning_effort,
        run_max_concurrency,
        input_cost_per_million_usd_micros,
        output_cost_per_million_usd_micros,
    )
    if run_mode is None:
        if any(value is not None for value in run_values):
            raise ValueError("semantic run binding requires an explicit run mode")
    elif (
        run_mode not in {"canary", "full"}
        or not isinstance(run_model, str) or not run_model
        or not isinstance(run_reasoning_effort, str)
        or (
            run_max_concurrency is not None
            and (
                isinstance(run_max_concurrency, bool)
                or not isinstance(run_max_concurrency, int)
                or not 1 <= run_max_concurrency <= 72
            )
        )
        or any(
            isinstance(value, bool) or not isinstance(value, int) or value < 0
            for value in (
                input_cost_per_million_usd_micros,
                output_cost_per_million_usd_micros,
            )
        )
    ):
        raise ValueError("semantic production run binding is incomplete")
    max_concurrency = 1 if run_max_concurrency is None else run_max_concurrency

    def classify() -> Sequence[Mapping[str, object]]:
        from community_os.enrichment.openai_rich_semantic_assessment import (
            RetryableRichSemanticOutputError, rich_semantic_schema_sha256,
        )
        from community_os.enrichment.classification import ProcessorApproval
        from community_os.enrichment.github_content_evidence import RICH_PROJECT_FIELDS
        from community_os.enrichment.profile_semantic_evidence import (
            build_application_evidence, build_devpost_evidence,
        )
        from community_os.enrichment.rich_semantic_assessment import (
            MODEL_ALLOWLIST, PROFILE_ALLOWED_KEYS, PROMPT_VERSION, REASONING_ALLOWLIST,
            RichSemanticAssessor, validate_profile_evidence,
            validate_rich_semantic_assessment,
        )
        from community_os.enrichment.state import pseudonymous_id
        from community_os.enrichment.semantic_taxonomy import (
            empty_semantic_taxonomy,
        )

        created = clock()
        if created.tzinfo is None or created.utcoffset() is None:
            raise ValueError("rich semantic clock must be timezone-aware")
        stage = getattr(state, "pipeline").stage("classification")
        approval_sha256 = getattr(stage, "authorization_hash", None)
        approval_record = getattr(stage, "authorization_record", None)
        try:
            approval = ProcessorApproval.from_record(approval_record)
            expected_approval_sha256 = approval.authorization_hash(now=created)
            if (
                not isinstance(approval_sha256, str)
                or not _HASH.fullmatch(approval_sha256)
                or not hmac.compare_digest(approval_sha256, expected_approval_sha256)
            ):
                raise PermissionError("semantic processor approval hash does not match")
            approval.authorize_payload(
                purpose="rich_semantic_assessment",
                payload_version=PROMPT_VERSION,
                field_allowlist=PROFILE_ALLOWED_KEYS.union(RICH_PROJECT_FIELDS),
                now=created,
            )
        except (PermissionError, TypeError, ValueError) as error:
            raise PermissionError(
                "rich semantic processor approval does not authorize the current payload"
            ) from error
        applications = tuple(sorted(
            (dict(item) for item in application_loader(state)),
            key=lambda item: str(item.get("external_id") or ""),
        ))
        if run_mode is not None:
            applications = _order_semantic_applications_for_production(
                state,
                applications,
                attendance_loader=attendance_loader,
            )
        inputs = reconciliation_loader(state)
        corpus = _rich_identity_corpus(applications, inputs)
        subject_identity_literals = _application_subject_identity_literals(
            applications, pseudonym_secret=pseudonym_secret,
        )
        store = getattr(state, "rich_semantic_reviews")

        subject_by_application: dict[str, str] = {}
        case_subject_by_application: dict[str, str] = {}
        for application in applications:
            external_id = str(application.get("external_id") or "").strip()
            if not external_id:
                raise ValueError("rich semantic application identifier is required")
            if external_id in subject_by_application:
                raise ValueError("rich semantic application identifiers are duplicated")
            subject_by_application[external_id] = pseudonymous_id(
                external_id, secret=pseudonym_secret, key_version="v1",
            )
            case_subject_by_application[external_id] = rich_semantic_subject_ref(
                external_id, secret=pseudonym_secret,
            )

        ledger = None
        selected_case_subjects = tuple(case_subject_by_application.values())
        if run_mode is not None:
            from community_os.enrichment.semantic_run_ledger import (
                ProtectedSemanticRunLedger, SemanticRunBinding,
            )
            from community_os.enrichment.rich_semantic_assessment import (
                SEMANTIC_NORMALIZATION_VERSION,
            )

            review_context = getattr(store, "review_context_hashes", None)
            if not isinstance(review_context, Mapping):
                raise PermissionError("semantic production review context is missing")
            ledger = ProtectedSemanticRunLedger(
                Path(getattr(state, "root")) / "protected" / "rich-semantic-run",
                binding=SemanticRunBinding(
                    approval_sha256=str(approval_sha256),
                    event_context_sha256=_canonical_hash(dict(review_context)),
                    input_cost_per_million_usd_micros=int(
                        input_cost_per_million_usd_micros,
                    ),
                    model=str(run_model),
                    normalization_version=SEMANTIC_NORMALIZATION_VERSION,
                    output_cost_per_million_usd_micros=int(
                        output_cost_per_million_usd_micros,
                    ),
                    prompt_version=PROMPT_VERSION,
                    reasoning_effort=str(run_reasoning_effort),
                    schema_sha256=rich_semantic_schema_sha256(),
                ),
                ordered_subject_refs=selected_case_subjects,
                clock=clock,
            )
            # Full mode validates the exact five-subject receipt before the
            # legacy classifier or provider factory can mutate state.
            selected_case_subjects = ledger.subjects_for_mode(run_mode)

        repository = getattr(state, "review_repository")
        prior_rich_cases = tuple(
            case for case in repository.list(kind="classification")
            if case.version == "rich_semantic_review_v1"
        )
        if run_mode == "canary":
            legacy_records: Sequence[Mapping[str, object]] = ()
        else:
            legacy_records = base_classification()
            if (
                isinstance(legacy_records, (str, bytes))
                or not isinstance(legacy_records, Sequence)
            ):
                raise ValueError("base classification returned invalid records")
            if prior_rich_cases:
                current_nonrich = tuple(
                    case for case in repository.list(kind="classification")
                    if case.version != "rich_semantic_review_v1"
                )
                repository.replace_for_kinds(
                    ("classification",), (*current_nonrich, *prior_rich_cases),
                )

        existing_rich_by_subject = {
            case.subject_code: case
            for case in repository.list(kind="classification")
            if case.version == "rich_semantic_review_v1"
        }

        def semantic_subject_code(case_subject: str) -> str:
            return "semantic_" + hashlib.sha256(
                case_subject.encode("ascii"),
            ).hexdigest()[:24]

        selected_set = frozenset(selected_case_subjects)
        pending_applications: list[dict[str, object]] = []
        interrupted_without_case: list[str] = []
        processed_without_case: list[str] = []
        failed_without_case: list[str] = []
        for application in applications:
            external_id = str(application["external_id"]).strip()
            case_subject = case_subject_by_application[external_id]
            if case_subject not in selected_set:
                continue
            existing = existing_rich_by_subject.get(
                semantic_subject_code(case_subject),
            )
            recovery = (
                ledger.recovery_receipt(case_subject)
                if ledger is not None else None
            )
            recovering_interrupted_usage = (
                isinstance(recovery, Mapping)
                and recovery.get("previous_state") == "reserved"
            )
            if existing is not None and not recovering_interrupted_usage:
                if ledger is not None:
                    ledger.record_existing(case_subject)
                continue
            if ledger is not None:
                subject_state = ledger.subject_state(case_subject)
                if subject_state == "reserved":
                    interrupted_without_case.append(case_subject)
                    continue
                if subject_state == "failed":
                    failed_without_case.append(case_subject)
                    continue
                if subject_state is not None:
                    processed_without_case.append(case_subject)
                    continue
            pending_applications.append(application)
        if interrupted_without_case:
            raise PermissionError(
                "semantic run has interrupted reserved subjects; explicit recovery is required",
            )

        github_by_subject: dict[str, dict[str, object]] = {}
        if pending_applications:
            for record in _protected_stage_records(state, "github"):
                subject = str(record.get("subject_ref") or "")
                if not subject or subject in github_by_subject:
                    raise ValueError("protected rich GitHub subjects are missing or duplicated")
                github_by_subject[subject] = record

        links, quarantined = (
            _resolved_person_links(state) if pending_applications
            else ({}, frozenset())
        )
        devpost_by_application: dict[str, list[dict[str, object]]] = {}
        for record in inputs.submission_records:
            source_ref = str(getattr(record, "external_id", "") or "").strip()
            application_id = links.get(source_ref)
            if not source_ref or source_ref in quarantined or application_id is None:
                continue
            payload = getattr(record, "payload", {})
            if not isinstance(payload, Mapping):
                raise ValueError("Devpost source payload is invalid")
            text = " ".join(filter(None, (
                str(getattr(record, "submission_title", "") or "").strip(),
                str(payload.get("About The Project") or "").strip(),
            )))
            submitted = bool(str(payload.get("Project Submitted At") or "").strip())
            devpost_by_application.setdefault(application_id, []).append({
                "project_text": text,
                "technology_codes": _devpost_technology_codes(payload.get("Built With")),
                "submission_state": "submitted" if submitted else "draft",
                "demo_state": "observed" if bool(getattr(record, "demo_present", False)) else "absent",
            })

        subject_set = frozenset(
            subject_by_application[str(application["external_id"]).strip()]
            for application in pending_applications
        )
        career_by_subject: Mapping[str, Sequence[Mapping[str, object]]] = {}
        if career_evidence_loader is not None and subject_set:
            career_by_subject = career_evidence_loader(
                subject_set, identity_literals=corpus,
            )
            if not isinstance(career_by_subject, Mapping) or any(
                key not in subject_set for key in career_by_subject
            ):
                raise ValueError("career evidence population is invalid")

        created_text = created.astimezone(UTC).isoformat().replace("+00:00", "Z")
        expires_text = (created.astimezone(UTC) + timedelta(days=3)).isoformat().replace(
            "+00:00", "Z",
        )

        @dataclass(frozen=True)
        class SemanticWorkItem:
            assessor: object | None
            cached_metadata: Mapping[str, object] | None
            case_subject: str
            derived_identity_literals: tuple[str, ...]
            empty_assessment: Mapping[str, object] | None
            evidence: Mapping[str, object]
            model: object
            prepared: object | None
            request_byte_count: int
            request_sha256: str
            source_family_counts: Mapping[str, int]
            subject_corpus: tuple[str, ...]

        work_items: list[SemanticWorkItem] = []

        def submit_assessment(
            item: SemanticWorkItem,
            assessment: Mapping[str, object],
            metadata: Mapping[str, object] | None,
        ) -> None:
            _assert_no_identity_literals(assessment, corpus)
            _assert_no_subject_identity_literals(
                assessment, item.derived_identity_literals,
            )
            store.submit({
                "approval_sha256": approval_sha256,
                "assessment": assessment,
                "created_at": created_text,
                "evidence": item.evidence,
                "evidence_sha256": _canonical_hash(item.evidence),
                "expires_at": expires_text,
                "model": item.model,
                "model_sha256": _canonical_hash(item.model),
                "prompt_sha256": _canonical_hash(PROMPT_VERSION),
                "prompt_version": PROMPT_VERSION,
                "schema_sha256": rich_semantic_schema_sha256(),
                "source_coverage": sorted(
                    family for family, packets in item.evidence.items() if packets
                ),
                "subject_ref": item.case_subject,
            }, known_identity_literals=item.subject_corpus)
            if ledger is None:
                return
            if metadata is None:
                ledger.record_empty(
                    item.case_subject,
                    request_sha256=item.request_sha256,
                    request_byte_count=item.request_byte_count,
                    source_family_counts=item.source_family_counts,
                )
                return
            if (
                metadata["request_sha256"] != item.request_sha256
                or metadata["request_byte_count"] != item.request_byte_count
                or metadata["source_family_counts"] != item.source_family_counts
            ):
                raise PermissionError("semantic request metadata binding drift")
            usage = metadata["usage"]
            ledger.complete(
                item.case_subject,
                cache_status=str(metadata["cache_status"]),
                input_tokens=int(usage["input_tokens"]),
                model_version=str(metadata["model_version"]),
                output_tokens=int(usage["output_tokens"]),
            )
            if item.assessor is not None and item.prepared is not None:
                item.assessor.acknowledge_prepared_usage(item.prepared)

        for application in pending_applications:
            external_id = str(application["external_id"]).strip()
            subject = subject_by_application[external_id]
            derived_identity_literals = subject_identity_literals.get(subject)
            if derived_identity_literals is None:
                raise PermissionError(
                    "rich semantic subject identity binding is missing",
                )
            subject_corpus = corpus + derived_identity_literals
            github = github_by_subject.get(subject, {})
            projects = github.get("rich_project_evidence", [])
            if not isinstance(projects, list):
                raise ValueError("protected rich GitHub project evidence is invalid")
            evidence = validate_profile_evidence({
                "projects": projects,
                "application": build_application_evidence(
                    experience=str(application.get("experience") or ""),
                    achievement=str(application.get("impressive_thing") or ""),
                    identity_literals=subject_corpus,
                ),
                "devpost": build_devpost_evidence(
                    projects=devpost_by_application.get(external_id, [])[:3],
                    identity_literals=subject_corpus,
                ),
                "career": [dict(item) for item in career_by_subject.get(subject, ())],
            })
            # Scan before cache lookup and before durable proposal storage. The
            # provider repeats this immediately before any outbound request.
            _assert_no_identity_literals(evidence, corpus)
            _assert_no_subject_identity_literals(
                evidence, derived_identity_literals,
            )
            request = json.dumps(
                evidence, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
            request_sha256 = hashlib.sha256(request).hexdigest()
            source_family_counts = {
                family: len(evidence[family])
                for family in ("application", "career", "devpost", "projects")
            }
            case_subject = case_subject_by_application[external_id]
            assessor = None
            prepared = None
            cached_metadata = None
            empty_assessment = None
            provider_model: object = run_model
            if any(evidence.values()):
                provider = provider_factory(subject_corpus)
                provider_model = getattr(provider, "model", None)
                provider_effort = getattr(provider, "reasoning_effort", None)
                if (
                    provider_model not in MODEL_ALLOWLIST
                    or provider_effort not in REASONING_ALLOWLIST
                    or (
                        ledger is not None
                        and (
                            provider_model != run_model
                            or provider_effort != run_reasoning_effort
                        )
                    )
                ):
                    raise PermissionError(
                        "rich semantic provider posture is not allowlisted",
                    )
                identity_corpus_sha256 = _canonical_hash(
                    sorted(subject_corpus),
                )
                assessor = RichSemanticAssessor(
                    provider=provider, cache=cache, clock=clock, retention_days=3,
                    model=provider_model, reasoning_effort=provider_effort,
                    privacy_context_sha256=identity_corpus_sha256,
                )
                if ledger is None:
                    assessment = assessor.assess(evidence)
                    item = SemanticWorkItem(
                        assessor=None, cached_metadata=None,
                        case_subject=case_subject,
                        derived_identity_literals=derived_identity_literals,
                        empty_assessment=None, evidence=evidence,
                        model=provider_model, prepared=None,
                        request_byte_count=len(request),
                        request_sha256=request_sha256,
                        source_family_counts=source_family_counts,
                        subject_corpus=subject_corpus,
                    )
                    submit_assessment(item, assessment, None)
                    continue
                prepared, cached_metadata = assessor.prepare_with_metadata(evidence)
            else:
                empty_assessment = validate_rich_semantic_assessment({
                    "builder_level": "insufficient",
                    "career_summary": "",
                    "cross_source_confidence": "low",
                    "evidence_refs": [],
                    "execution_scope": "unknown",
                    "external_validation": "none",
                    "originality": "unknown",
                    "product_maturity": "unknown",
                    "project_summary": "",
                    "rationale": "insufficient evidence.",
                    "reason_codes": ["insufficient_evidence"],
                    "review_state": "human_review_required",
                    "semantic_taxonomy": empty_semantic_taxonomy(),
                    "technical_depth": "unknown",
                }, evidence=evidence)
                if ledger is None:
                    item = SemanticWorkItem(
                        assessor=None, cached_metadata=None,
                        case_subject=case_subject,
                        derived_identity_literals=derived_identity_literals,
                        empty_assessment=empty_assessment, evidence=evidence,
                        model=provider_model, prepared=None,
                        request_byte_count=len(request),
                        request_sha256=request_sha256,
                        source_family_counts=source_family_counts,
                        subject_corpus=subject_corpus,
                    )
                    submit_assessment(item, empty_assessment, None)
                    continue
            work_items.append(SemanticWorkItem(
                assessor=assessor, cached_metadata=cached_metadata,
                case_subject=case_subject,
                derived_identity_literals=derived_identity_literals,
                empty_assessment=empty_assessment, evidence=evidence,
                model=provider_model, prepared=prepared,
                request_byte_count=len(request), request_sha256=request_sha256,
                source_family_counts=source_family_counts,
                subject_corpus=subject_corpus,
            ))

        provider_concurrency = max_concurrency if run_mode == "full" else 1
        for offset in range(0, len(work_items), provider_concurrency):
            batch = work_items[offset : offset + provider_concurrency]
            reserved: list[SemanticWorkItem] = []
            for item in batch:
                reservation = ledger.reserve(
                    item.case_subject,
                    request_sha256=item.request_sha256,
                    request_byte_count=item.request_byte_count,
                    source_family_counts=item.source_family_counts,
                )
                if reservation == "reserved":
                    reserved.append(item)
            first_error: Exception | None = None
            provider_items: list[SemanticWorkItem] = []
            for item in reserved:
                if item.empty_assessment is not None:
                    try:
                        submit_assessment(item, item.empty_assessment, None)
                    except Exception as error:
                        first_error = first_error or error
                elif item.cached_metadata is not None:
                    try:
                        submit_assessment(
                            item,
                            item.cached_metadata["assessment"],
                            item.cached_metadata,
                        )
                    except Exception as error:
                        first_error = first_error or error
                else:
                    provider_items.append(item)
            if provider_items:
                with ThreadPoolExecutor(
                    max_workers=min(provider_concurrency, len(provider_items)),
                    thread_name_prefix="semantic-provider",
                ) as executor:
                    futures = {
                        executor.submit(
                            item.assessor.request_prepared_with_metadata,
                            item.prepared,
                        ): item
                        for item in provider_items
                    }
                    for future in as_completed(futures):
                        item = futures[future]
                        try:
                            raw_result = future.result()
                            metadata = item.assessor.finalize_prepared_with_metadata(
                                item.prepared, raw_result,
                            )
                            submit_assessment(
                                item, metadata["assessment"], metadata,
                            )
                        except RetryableRichSemanticOutputError as error:
                            if error.usage is not None:
                                try:
                                    ledger.record_failed(
                                        item.case_subject,
                                        failure_code=error.failure_code,
                                        input_tokens=error.usage["input_tokens"],
                                        model_version=error.model_version,
                                        output_tokens=error.usage["output_tokens"],
                                    )
                                except (KeyError, TypeError, ValueError):
                                    pass
                            first_error = first_error or error
                        except Exception as error:
                            first_error = first_error or error
            if first_error is not None:
                raise first_error
        if ledger is not None:
            interrupted = tuple(
                subject for subject in selected_case_subjects
                if ledger.subject_state(subject) == "reserved"
            )
            if failed_without_case:
                raise PermissionError(
                    "semantic run has failed subjects; automatic retry is forbidden",
                )
            if processed_without_case:
                raise PermissionError(
                    "semantic run has processed subjects without current review proposals",
                )
            if interrupted:
                raise PermissionError(
                    "semantic run has interrupted reserved subjects; automatic retry is forbidden",
                )
            if run_mode == "canary":
                receipt = ledger.complete_canary()
                return [{
                    "canary_subject_count": int(receipt["canary_subject_count"]),
                    "interrupted_subject_count": 0,
                    "state": "complete",
                }]
        return legacy_records

    return classify


_CORESIGNAL_SENIORITY_LABELS = {
    "founder": "founder", "junior": "junior", "mid": "mid_level",
    "mid_level": "mid_level", "senior": "senior",
    "lead": "lead_staff_executive", "staff": "lead_staff_executive",
    "principal": "lead_staff_executive", "executive": "lead_staff_executive",
    "director": "lead_staff_executive", "head": "lead_staff_executive",
}


def _incremental_coresignal_overlay(
    state: object, *, applications: Sequence[Mapping[str, object]],
    coresignal_records: Mapping[str, Mapping[str, object]], pseudonym_secret: bytes,
) -> list[dict[str, object]] | None:
    """Merge normalized Coresignal facts into a previously reviewed projection."""
    from community_os.enrichment.state import pseudonymous_id

    path = Path(getattr(state, "root")) / "protected" / "stages" / "classification.json"
    pipeline = getattr(state, "pipeline", None)
    if (
        not coresignal_records or not path.is_file() or pipeline is None
        or pipeline.stage("classification").status.value == "complete"
    ):
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        expiry = datetime.fromisoformat(str(payload["expires_at"]).replace("Z", "+00:00"))
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise PermissionError("reviewed base classification is unreadable") from error
    clock = getattr(state, "_release_operation_clock", None)
    current = clock() if callable(clock) else datetime.now(UTC)
    if (
        not isinstance(payload, dict)
        or payload.get("stage") != "classification"
        or payload.get("stage_output_version") != "protected-stage-output-v1"
        or not isinstance(payload.get("records"), list)
        or expiry.tzinfo is None or expiry <= current
    ):
        raise PermissionError("reviewed base classification is invalid or expired")
    repository = getattr(state, "review_repository")
    repository.assert_resolved("classification")
    expected: dict[str, str] = {}
    for application in applications:
        external_id = str(application.get("external_id") or "").strip()
        if not external_id:
            raise ValueError("classification application identifier is required")
        subject_ref = pseudonymous_id(
            external_id, secret=pseudonym_secret, key_version="v1",
        )
        if subject_ref in expected:
            raise ValueError("classification application subjects are duplicated")
        expected[subject_ref] = external_id
    base: dict[str, dict[str, object]] = {}
    for item in payload["records"]:
        if not isinstance(item, dict):
            raise ValueError("reviewed base classification record is invalid")
        subject_ref = str(item.get("subject_ref") or "")
        if not subject_ref or subject_ref in base:
            raise ValueError("reviewed base classification subjects are missing or duplicated")
        _validate_classification_dimensions(item.get("dimensions"))
        base[subject_ref] = dict(item)
    if set(base) != set(expected):
        raise ValueError("reviewed base classification population does not match applications")
    if not set(coresignal_records).issubset(base):
        raise ValueError("Coresignal subjects are outside the reviewed applicant population")

    bindings = _load_review_bindings(state)
    classification_bindings = bindings.get("classification_subjects", {})
    if not isinstance(classification_bindings, dict):
        raise ValueError("classification review bindings are invalid")
    existing_cases = {
        case.subject_code: case for case in repository.list(kind="classification")
    }
    refreshed_cases = dict(existing_cases)
    overlay_version = "coresignal_structured_overlay_v1"

    for subject_ref, source in sorted(coresignal_records.items()):
        required = {
            "company_category", "evidence_ref", "founder_history", "seniority",
            "state", "subject_ref", "title_category",
        }
        if set(source) != required or source.get("subject_ref") != subject_ref:
            raise ValueError("Coresignal overlay record is invalid")
        if (
            source.get("state") != "observed"
            or not isinstance(source.get("founder_history"), bool)
            or not re.fullmatch(r"evidence:coresignal:[0-9a-f]{64}", str(source.get("evidence_ref")))
        ):
            raise ValueError("Coresignal overlay record is invalid")
        normalized = {
            key: source[key]
            for key in (
                "company_category", "founder_history", "seniority", "title_category",
            )
        }
        fingerprint = _canonical_hash(normalized)
        record = dict(base[subject_ref])
        prior_overlay = record.get("incremental_overlay")
        if isinstance(prior_overlay, Mapping) and prior_overlay.get("fingerprint") == fingerprint:
            continue
        external_id = expected[subject_ref]
        subject_code = _pseudonymous_code("class", external_id, pseudonym_secret)
        existing_case = existing_cases.get(subject_code)
        effective_dimensions = record["dimensions"]
        if (
            existing_case is not None
            and existing_case.decision is not None
            and existing_case.decision.action == "corrected"
        ):
            effective_dimensions = existing_case.decision.corrected_output
            _validate_classification_dimensions(effective_dimensions)
        dimensions = {
            key: dict(value) for key, value in effective_dimensions.items()
        }
        evidence_ref = str(source["evidence_ref"])
        changed_dimensions: set[str] = set()
        new_reasons: set[str] = set()

        def add_label(dimension: str, label: str) -> None:
            item = dimensions[dimension]
            labels = set(str(value) for value in item["labels"])
            labels.discard("unknown")
            labels.discard("insufficient_evidence")
            labels.add(label)
            references = set(str(value) for value in item["evidence_refs"])
            references.add(evidence_ref)
            item.update({
                "confidence": max(float(item["confidence"]), 0.8),
                "evidence_refs": sorted(references), "labels": sorted(labels),
                "state": "observed",
            })
            changed_dimensions.add(dimension)

        company = str(source["company_category"]).casefold()
        if company in {"startup", "scaleup", "venture_backed_startup"}:
            add_label("professional_identity", "startup_operator")
        seniority = _CORESIGNAL_SENIORITY_LABELS.get(str(source["seniority"]).casefold())
        if seniority is not None:
            existing = set(str(value) for value in dimensions["seniority"]["labels"])
            observed = existing.difference({"unknown"})
            if observed and observed != {seniority}:
                new_reasons.add("conflicting_evidence")
            dimensions["seniority"]["labels"] = [seniority]
            dimensions["seniority"]["confidence"] = 0.8
            dimensions["seniority"]["state"] = "observed"
            dimensions["seniority"]["evidence_refs"] = sorted(
                set(dimensions["seniority"]["evidence_refs"]).union({evidence_ref})
            )
            changed_dimensions.add("seniority")
        if source["title_category"] == "software_engineering":
            add_label("functional_role", "engineering")
        if source["founder_history"] is True:
            add_label("professional_identity", "founder_cofounder")
            add_label("builder_evidence", "founded_company")
            dimensions["seniority"].update({
                "confidence": 0.8, "evidence_refs": sorted(
                    set(dimensions["seniority"]["evidence_refs"]).union({evidence_ref})
                ), "labels": ["founder"], "state": "observed",
            })
            changed_dimensions.add("seniority")
            new_reasons.add("consequential_claim")

        if not changed_dimensions:
            record["incremental_overlay"] = {
                "base_record_sha256": _canonical_hash(base[subject_ref]),
                "fingerprint": fingerprint, "provider": "coresignal",
                "version": overlay_version,
            }
            base[subject_ref] = record
            continue
        record["dimensions"] = dimensions
        record["incremental_overlay"] = {
            "base_record_sha256": _canonical_hash(base[subject_ref]),
            "fingerprint": fingerprint, "provider": "coresignal",
            "version": overlay_version,
        }
        if (
            existing_case is not None
            and existing_case.decision is not None
            and existing_case.decision.action == "corrected"
        ):
            new_reasons.add("prior_human_correction")
        if new_reasons:
            reasons = set(str(value) for value in record.get("review_reasons", ()))
            reasons.update(new_reasons)
            record["review_reasons"] = sorted(reasons)
            record["review_state"] = "pending"
            review_case = ReviewCase.create(
                kind="classification", subject_code=subject_code,
                reason_codes=tuple(sorted(reasons)), candidate_codes=(),
                source_hashes=_review_case_source_hashes(state, {
                    "base": _canonical_hash(base[subject_ref]),
                    "coresignal": fingerprint,
                }),
                version=overlay_version,
            )
            refreshed_cases[subject_code] = review_case
            classification_bindings[subject_code] = {
                "external_id": external_id, "subject_ref": subject_ref,
            }
        base[subject_ref] = record

    repository.replace_for_kinds(("classification",), refreshed_cases.values())
    bindings["classification_subjects"] = classification_bindings
    _persist_review_bindings(state, bindings)
    return [base[key] for key in sorted(base)]


def build_local_classification_service(
    state: object, *, pseudonym_secret: bytes,
    semantic_classifier: object | None = None,
    evidence_vault: object | None = None,
    application_loader: Callable[[object], Iterable[Mapping[str, object]]] = _load_applications,
) -> Operation:
    """Build local signals, optionally applying an approved semantic processor."""
    if not pseudonym_secret:
        raise ValueError("pseudonym secret is required")

    def classify() -> list[dict[str, object]]:
        from community_os.enrichment.state import pseudonymous_id
        from community_os.real_report import classify_application

        bindings_path = Path(getattr(state, "root")) / "protected" / "review-bindings.json"
        existing_bindings = (
            _load_review_bindings(state) if bindings_path.exists() else {}
        )
        applications = sorted(
            (dict(item) for item in application_loader(state)),
            key=lambda item: str(item.get("external_id") or ""),
        )
        enrichment: dict[str, dict[str, dict[str, object]]] = {}
        enrichment_hashes: dict[str, str] = {}
        for stage in ("github", "public_pages", "coresignal"):
            stage_records = _protected_stage_records(state, stage)
            mapped: dict[str, dict[str, object]] = {}
            for item in stage_records:
                subject = str(item.get("subject_ref") or "")
                if not subject or subject in mapped:
                    raise ValueError(f"protected {stage} subjects are missing or duplicated")
                mapped[subject] = item
            enrichment[stage] = mapped
            if stage_records:
                stage_path = Path(getattr(state, "root")) / "protected" / "stages" / f"{stage}.json"
                enrichment_hashes[stage] = hashlib.sha256(stage_path.read_bytes()).hexdigest()
        incremental = _incremental_coresignal_overlay(
            state, applications=applications,
            coresignal_records=enrichment["coresignal"],
            pseudonym_secret=pseudonym_secret,
        )
        if incremental is not None:
            return incremental
        snapshot = getattr(state, "snapshot")()
        application_slot = snapshot.get("source_slots", {}).get("applications")
        source_hash = (
            str(application_slot.get("sha256"))
            if isinstance(application_slot, Mapping) and _HASH.fullmatch(str(application_slot.get("sha256")))
            else _canonical_hash(applications)
        )
        records: list[dict[str, object]] = []
        cases: list[ReviewCase] = []
        classification_subjects: dict[str, object] = {}
        unknown_labels = {"unknown", "insufficient_evidence"}
        consequential_labels = {"founder_cofounder", "founder"}

        for application in applications:
            external_id = str(application.get("external_id") or "").strip()
            if not external_id:
                raise ValueError("classification application identifier is required")
            subject_ref = pseudonymous_id(
                external_id, secret=pseudonym_secret, key_version="v1",
            )
            subject_code = _pseudonymous_code("class", external_id, pseudonym_secret)
            evidence_hash = hmac.new(
                pseudonym_secret, f"application:{external_id}".encode("utf-8"), hashlib.sha256,
            ).hexdigest()
            evidence_ref = f"evidence:application:{evidence_hash}"
            augmented = dict(application)
            public_page = enrichment["public_pages"].get(subject_ref)
            if public_page is not None:
                if evidence_vault is not None:
                    from community_os.enrichment.public_pages import extract_visible_text

                    reader = getattr(evidence_vault, "read", None)
                    if not callable(reader):
                        raise TypeError("evidence vault must expose read")
                    text = extract_visible_text(reader(
                        str(public_page.get("evidence_ref") or ""),
                        source="public_pages", subject_ref=subject_ref,
                    ))
                else:
                    text = str(public_page.get("text") or "")[:4000]
                augmented["impressive_thing"] = " ".join((
                    str(augmented.get("impressive_thing") or ""), text,
                )).strip()
            raw = classify_application(augmented)
            dimension_evidence = {
                dimension: {evidence_ref} for dimension in _CLASSIFICATION_DIMENSIONS
            }
            if public_page is not None:
                reference = str(public_page.get("evidence_ref") or "")
                if reference:
                    for values in dimension_evidence.values():
                        values.add(reference)
            github = enrichment["github"].get(subject_ref)
            if github is not None:
                reference = str(github.get("evidence_ref") or "")
                raw["builder_evidence"].add("github_supplied")
                observed_github = github.get("state") == "observed"
                if observed_github and int(github.get("recently_active_repos") or 0) > 0:
                    raw["builder_evidence"].add("active_github")
                technology_codes = github.get("technology_codes", []) if observed_github else []
                if not isinstance(technology_codes, list) or any(
                    not isinstance(value, str) for value in technology_codes
                ):
                    raise ValueError("protected GitHub technology codes are invalid")
                capability_map = {
                    "javascript_typescript": "frontend", "web_frontend": "frontend",
                    "data_notebook": "data", "dart": "mobile", "swift": "mobile",
                    "python": "backend", "go": "backend", "jvm": "backend", "dotnet": "backend",
                    "php": "backend", "ruby": "backend", "rust": "backend",
                    "systems": "backend",
                }
                for technology in technology_codes:
                    capability = capability_map.get(technology)
                    if capability is not None:
                        raw["capabilities"].add(capability)
                if reference:
                    dimension_evidence["builder_evidence"].add(reference)
                    if technology_codes:
                        dimension_evidence["capabilities"].add(reference)
            coresignal = enrichment["coresignal"].get(subject_ref)
            if coresignal is not None:
                reference = str(coresignal.get("evidence_ref") or "")
                if bool(coresignal.get("founder_history")):
                    raw["professional_identity"].add("founder_cofounder")
                    raw["seniority"] = {"founder"}
                    raw["builder_evidence"].add("founded_company")
                company = str(coresignal.get("company_category") or "").casefold()
                if company in {"startup", "scaleup", "venture_backed_startup"}:
                    raw["professional_identity"].add("startup_operator")
                seniority = str(coresignal.get("seniority") or "").casefold()
                seniority_map = {
                    "founder": "founder", "junior": "junior", "mid": "mid_level",
                    "mid_level": "mid_level", "senior": "senior", "lead": "lead_staff_executive",
                    "staff": "lead_staff_executive", "principal": "lead_staff_executive",
                    "executive": "lead_staff_executive", "director": "lead_staff_executive",
                    "head": "lead_staff_executive",
                }
                if seniority in seniority_map:
                    raw["seniority"] = {seniority_map[seniority]}
                if coresignal.get("title_category") == "software_engineering":
                    raw["functional_role"].add("engineering")
                if reference:
                    for dimension in (
                        "professional_identity", "seniority", "functional_role", "builder_evidence",
                    ):
                        dimension_evidence[dimension].add(reference)
            for dimension, unknown_label in (
                ("professional_identity", "insufficient_evidence"),
                ("seniority", "unknown"), ("functional_role", "unknown"),
                ("builder_evidence", "insufficient_evidence"),
                ("capabilities", "unknown"), ("domains", "unknown"),
            ):
                if len(raw[dimension]) > 1:
                    raw[dimension].discard(unknown_label)
            dimensions: dict[str, object] = {}
            reasons: set[str] = set()
            for dimension in sorted(_CLASSIFICATION_DIMENSIONS):
                labels = sorted(str(value) for value in raw[dimension])
                unknown = bool(set(labels).intersection(unknown_labels))
                if unknown:
                    reasons.update({"low_confidence", "unknown_state"})
                if set(labels).intersection(consequential_labels):
                    reasons.add("consequential_claim")
                dimensions[dimension] = {
                    "confidence": 0.0 if unknown else 0.8,
                    "evidence_refs": [] if unknown else sorted(dimension_evidence[dimension]),
                    "labels": labels,
                    "state": "unknown" if unknown else "observed",
                }
            if semantic_classifier is None:
                record = {
                    "classifier_version": "deterministic-rules-v1",
                    "dimensions": dimensions,
                    "review_reasons": sorted(reasons),
                    "review_state": "pending" if reasons else "approved",
                    "subject_ref": subject_ref,
                    "taxonomy_version": "talent-taxonomy-v1",
                }
                case_version = "deterministic_rules_v1"
            else:
                from community_os.enrichment.classification import ClassificationInput

                occupation_codes = sorted({
                    f"{prefix}_{label}"
                    for dimension, prefix in (
                        ("professional_identity", "identity"),
                        ("functional_role", "role"),
                        ("employer_pedigree", "employer"),
                        ("capabilities", "capability"),
                        ("domains", "domain"),
                    )
                    for label in raw[dimension]
                })
                seniority = sorted(str(value) for value in raw["seniority"])
                builder_codes = {
                    "builder_" + str(label) for label in raw["builder_evidence"]
                }
                if github is not None:
                    repositories = int(github.get("public_repos") or 0)
                    builder_codes.add(
                        "github_repos_none" if repositories == 0
                        else "github_repos_few" if repositories < 6
                        else "github_repos_many"
                    )
                    age = int(github.get("account_age_days") or 0)
                    builder_codes.add(
                        "github_account_new" if age < 365
                        else "github_account_established"
                    )
                if public_page is not None:
                    builder_codes.add("public_page_observed")
                if coresignal is not None:
                    builder_codes.update({
                        "coresignal_company_" + str(coresignal.get("company_category") or "unknown"),
                        "coresignal_title_" + str(coresignal.get("title_category") or "unknown"),
                    })
                    if bool(coresignal.get("founder_history")):
                        builder_codes.add("coresignal_founder_history")
                references = sorted({
                    reference
                    for values in dimension_evidence.values()
                    for reference in values
                })
                classify_semantically = getattr(semantic_classifier, "classify", None)
                if not callable(classify_semantically):
                    raise TypeError("semantic classifier must expose classify")
                record = classify_semantically(ClassificationInput(
                    subject_ref=subject_ref,
                    signals={
                        "occupation_codes": occupation_codes or ["unknown"],
                        "experience_band": seniority[0] if len(seniority) == 1 else "unknown",
                        "builder_codes": sorted(builder_codes),
                    },
                    evidence_refs=tuple(references),
                ))
                if not isinstance(record, dict):
                    raise ValueError("semantic classifier returned an invalid record")
                reasons = set(str(value) for value in record.get("review_reasons", ()))
                case_version = str(record.get("classifier_version") or "semantic_v1").replace("-", "_")
            records.append(record)
            if reasons:
                review_case = ReviewCase.create(
                    kind="classification", subject_code=subject_code,
                    reason_codes=tuple(sorted(reasons)), candidate_codes=(),
                    source_hashes=_review_case_source_hashes(
                        state,
                        {"applications": source_hash, **enrichment_hashes},
                    ),
                    version=case_version,
                )
                cases.append(review_case)
                classification_subjects[subject_code] = {
                    "external_id": external_id,
                    "subject_ref": subject_ref,
                }

        repository = getattr(state, "review_repository")
        repository.replace_for_kinds(("classification",), cases)
        existing_bindings["classification_subjects"] = classification_subjects
        _persist_review_bindings(state, existing_bindings)
        return records

    return classify


class ProductionOperationRegistry:
    """Bind real protected sources, review barriers, cleanup, and stage services."""

    def __init__(
        self, *, root: Path, uploads_root: Path,
        source_files: Mapping[str, Path], source_hashes: Mapping[str, str],
        reviews: ReviewRepository, services: Mapping[str, Operation],
        caches: Sequence[object], clock: Callable[[], datetime] | None = None,
        retention_days: Mapping[str, int] | None = None,
        retention_invalidator: Callable[[Sequence[str]], None] | None = None,
        retention_persister: Callable[[str, datetime], None] | None = None,
    ) -> None:
        self.root = root
        self.uploads_root = uploads_root
        self.source_files = dict(source_files)
        self.source_hashes = dict(source_hashes)
        self.reviews = reviews
        self.services = dict(services)
        self.caches = tuple(caches)
        self.clock = clock or (lambda: datetime.now(UTC))
        self.retention_days = dict(retention_days or {})
        self.retention_invalidator = retention_invalidator
        self.retention_persister = retention_persister
        if set(self.services) != set(_OPERATION_STAGES):
            raise ValueError("production operation services are incomplete")
        if not self.source_files or set(self.source_files) != set(self.source_hashes):
            raise ValueError("protected source files and hashes do not match")
        for source, digest in self.source_hashes.items():
            _code(source, "source_code")
            if not _HASH.fullmatch(digest):
                raise ValueError("protected source hash must be SHA-256")
        if any(
            stage not in {"github", "public_pages", "coresignal", "classification"}
            or isinstance(days, bool) or not isinstance(days, int) or not 1 <= days <= 365
            for stage, days in self.retention_days.items()
        ):
            raise ValueError("raw enrichment retention configuration is invalid")
        if self.clock().tzinfo is None:
            raise ValueError("production operation clock must be timezone-aware")

    @classmethod
    def from_operator_state(
        cls, state: object, *, services: Mapping[str, Operation],
        caches: Sequence[object], clock: Callable[[], datetime] | None = None,
        retention_days: Mapping[str, int] | None = None,
        retention_invalidator: Callable[[Sequence[str]], None] | None = None,
        retention_persister: Callable[[str, datetime], None] | None = None,
    ) -> "ProductionOperationRegistry":
        root = Path(getattr(state, "root"))
        uploads_root = Path(getattr(state, "protected_uploads"))
        snapshot = getattr(state, "snapshot")()
        slots = snapshot["source_slots"]
        if not isinstance(slots, dict) or not slots:
            raise PermissionError("validated protected sources are missing")
        source_files: dict[str, Path] = {}
        source_hashes: dict[str, str] = {}
        for source, value in slots.items():
            if not isinstance(value, dict) or set(value) != {
                "path", "row_count", "sha256", "state",
            }:
                raise ValueError("protected source record is invalid")
            path = uploads_root / str(value["path"])
            source_files[str(source)] = path
            source_hashes[str(source)] = str(value["sha256"])
        registry = cls(
            root=root, uploads_root=uploads_root,
            source_files=source_files, source_hashes=source_hashes,
            reviews=getattr(state, "review_repository"), services=services,
            caches=caches, clock=clock, retention_days=retention_days,
            retention_invalidator=retention_invalidator,
            retention_persister=retention_persister,
        )
        setattr(state, "_release_operation_clock", registry.clock)
        return registry

    @staticmethod
    def _sha256(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
        return digest.hexdigest()

    def _verify_sources(self, sources: Iterable[str]) -> None:
        root = self.uploads_root.resolve()
        for source in sources:
            path = self.source_files[source]
            try:
                resolved = path.resolve(strict=True)
                resolved.relative_to(root)
            except (FileNotFoundError, ValueError) as error:
                raise PermissionError("protected source path is missing or outside storage") from error
            if not resolved.is_file() or not __import__("hmac").compare_digest(
                self._sha256(resolved), self.source_hashes[source],
            ):
                raise PermissionError(f"protected source hash drift: {source}")

    def _persist(self, stage: str, records: Sequence[Mapping[str, object]]) -> None:
        directory = self.root / "protected" / "stages"
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        directory.chmod(0o700)
        path = directory / f"{stage}.json"
        temporary = path.with_name(path.name + ".tmp")
        created_at = self.clock().astimezone(UTC)
        prior_expiry: datetime | None = None
        if stage == "classification" and path.is_file():
            try:
                prior_payload = json.loads(path.read_text(encoding="utf-8"))
                candidate = datetime.fromisoformat(
                    str(prior_payload["expires_at"]).replace("Z", "+00:00")
                )
                if candidate.tzinfo is not None and candidate > created_at:
                    prior_expiry = candidate
            except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError):
                prior_expiry = None
        expiry = (
            created_at + timedelta(days=self.retention_days[stage])
            if stage in self.retention_days else None
        )
        if prior_expiry is not None and (expiry is None or prior_expiry < expiry):
            expiry = prior_expiry
        payload = {
            "created_at": created_at.isoformat().replace("+00:00", "Z"),
            "expires_at": (
                expiry.isoformat().replace("+00:00", "Z")
                if expiry is not None else None
            ),
            "records": [dict(item) for item in records],
            "stage": stage,
            "stage_output_version": "protected-stage-output-v1",
        }
        temporary.write_text(
            json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        temporary.chmod(0o600)
        temporary.replace(path)
        if expiry is not None and self.retention_persister is not None:
            try:
                self.retention_persister(stage, expiry)
            except Exception:
                path.unlink(missing_ok=True)
                raise

    def _run_bound_service(
        self, stage: str, service: Operation,
    ) -> list[dict[str, object]]:
        if stage != "privacy_cleanup":
            self._verify_sources(self.source_files)
        if stage in {"github", "public_pages", "coresignal", "classification"}:
            self.reviews.assert_resolved("identity", "team")
        elif stage == "aggregate":
            self.reviews.assert_resolved("identity", "team")
            self.reviews.assert_authoritative_classification_resolved()
        raw = service()
        if isinstance(raw, (str, bytes)) or not isinstance(raw, Sequence):
            raise ValueError("stage service must return a sequence of records")
        records: list[dict[str, object]] = []
        for item in raw:
            if not isinstance(item, Mapping):
                raise ValueError("stage service returned a non-record")
            records.append(dict(item))
        return records

    def _run_service(self, stage: str) -> list[dict[str, object]]:
        return self._run_bound_service(stage, self.services[stage])

    def nonpersisting_callback(self, stage: str, service: Operation) -> Operation:
        """Apply classification barriers without writing a completed stage output."""

        if stage != "classification":
            raise ValueError("only classification canary execution may be nonpersisting")
        if not callable(service):
            raise TypeError("nonpersisting stage service must be callable")

        def run() -> list[dict[str, object]]:
            return self._run_bound_service(stage, service)

        return run

    def _cleanup(self) -> list[dict[str, object]]:
        if self.retention_days and self.retention_invalidator is None:
            raise PermissionError("expired enrichment requires derived-state invalidation")
        deleted = 0
        for cache in self.caches:
            cleanup = getattr(cache, "delete_expired", None)
            if not callable(cleanup):
                raise ValueError("configured cache has no physical cleanup operation")
            count = cleanup()
            if isinstance(count, bool) or not isinstance(count, int) or count < 0:
                raise ValueError("cache cleanup returned an invalid deletion count")
            deleted += count
        raw_deleted = 0
        expired_stages: list[str] = []
        stage_root = self.root / "protected" / "stages"
        for stage in self.retention_days:
            path = stage_root / f"{stage}.json"
            temporary = path.with_name(path.name + ".tmp")
            if temporary.exists():
                temporary.unlink()
                raw_deleted += 1
            if not path.exists():
                continue
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
                expiry = datetime.fromisoformat(str(payload["expires_at"]).replace("Z", "+00:00"))
                expired = expiry.tzinfo is None or expiry <= self.clock()
            except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError):
                expired = True
            if expired:
                path.unlink(missing_ok=True)
                raw_deleted += 1
                expired_stages.append(stage)
        if expired_stages:
            assert self.retention_invalidator is not None
            self.retention_invalidator(tuple(expired_stages))
        summary = {"cache_entries_deleted": deleted, "state": "complete"}
        if raw_deleted:
            summary["raw_enrichment_deleted"] = raw_deleted
        records = [summary]
        records.extend(self._run_service("privacy_cleanup"))
        self._persist("privacy_cleanup", records)
        return records

    def _callback(self, stage: str) -> Operation:
        def run() -> list[dict[str, object]]:
            records = self._run_service(stage)
            self._persist(stage, records)
            return records

        return run

    def callbacks(self) -> dict[str, Operation]:
        return {
            stage: (self._cleanup if stage == "privacy_cleanup" else self._callback(stage))
            for stage in _OPERATION_STAGES
        }
