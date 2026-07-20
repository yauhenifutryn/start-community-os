"""Durable stage state, pseudonyms, and incident-safe audit records."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
import hashlib
import hmac
import json
from pathlib import Path
import re
from typing import Mapping


class StageStatus(StrEnum):
    ALLOWED = "allowed"
    LOCKED = "locked"
    RUNNING = "running"
    FAILED = "failed"
    COMPLETE = "complete"


_STAGE_PATTERN = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
_REASON_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_:-]{0,127}$")
_AUDIT_PROPERTIES = frozenset({"stage", "status", "attempt", "reason_code"})
_SENSITIVE_KEY_PARTS = ("email", "name", "token", "secret", "url", "payload", "prompt", "response")
_GATED_STAGES = frozenset({"github", "public_pages", "coresignal", "classification"})


def pseudonymous_id(value: str, *, secret: bytes, key_version: str) -> str:
    """Return a deterministic keyed identifier that cannot be reversed without the key."""
    canonical = value.strip().casefold()
    if not canonical:
        raise ValueError("pseudonymous identifier input is required")
    if not secret:
        raise ValueError("pseudonymous identifier secret is required")
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,32}", key_version):
        raise ValueError("invalid pseudonym key version")
    digest = hmac.new(secret, canonical.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"pid:{key_version}:{digest}"


def sanitize_audit_event(event: str, properties: Mapping[str, object]) -> dict[str, object]:
    """Build a small allowlisted event, rejecting fields likely to contain personal data."""
    if not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", event):
        raise ValueError("invalid audit event name")
    for key in properties:
        lowered = str(key).casefold()
        if any(part in lowered for part in _SENSITIVE_KEY_PARTS):
            raise ValueError(f"sensitive audit property is forbidden: {key}")
        if key not in _AUDIT_PROPERTIES:
            raise ValueError(f"audit property is not allowlisted: {key}")
    sanitized: dict[str, object] = {}
    for key, value in properties.items():
        if not isinstance(value, (str, int, bool)) or isinstance(value, float):
            raise ValueError(f"audit property must be a scalar: {key}")
        text = str(value)
        if "@" in text or "://" in text or len(text) > 128:
            raise ValueError(f"sensitive audit property value is forbidden: {key}")
        if isinstance(value, str) and not _REASON_PATTERN.fullmatch(value):
            raise ValueError(f"audit property value must be a machine-readable code: {key}")
        sanitized[key] = value
    return {"event": event, "properties": sanitized}


@dataclass(frozen=True)
class StageRecord:
    status: StageStatus
    attempts: int = 0
    result: dict[str, object] | None = None
    reason_code: str | None = None
    authorization_hash: str | None = None
    authorization_record: dict[str, object] | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "attempts": self.attempts,
            "authorization_hash": self.authorization_hash,
            "authorization_record": self.authorization_record,
            "reason_code": self.reason_code,
            "result": self.result,
            "status": self.status.value,
        }


class PipelineState:
    """Persist a fail-closed stage state machine as canonical JSON."""

    VERSION = "enrichment-state-v1"

    def __init__(
        self, path: Path, stages: Mapping[str, StageRecord],
        audit_events: list[dict[str, object]] | None = None,
    ) -> None:
        self.path = path
        self._stages = dict(stages)
        self._audit_events = list(audit_events or [])

    @classmethod
    def create(cls, path: str | Path, stages: Mapping[str, StageStatus]) -> "PipelineState":
        if not stages:
            raise ValueError("at least one pipeline stage is required")
        records: dict[str, StageRecord] = {}
        for name, status in stages.items():
            cls._validate_stage_name(name)
            if status not in {StageStatus.ALLOWED, StageStatus.LOCKED}:
                raise ValueError("new stages must begin allowed or locked")
            if name in _GATED_STAGES and status is not StageStatus.LOCKED:
                raise ValueError(f"{name} must begin locked")
            records[name] = StageRecord(status)
        state = cls(Path(path), records)
        state._persist()
        return state

    @classmethod
    def load(cls, path: str | Path) -> "PipelineState":
        source = Path(path)
        payload = json.loads(source.read_text(encoding="utf-8"))
        if set(payload) != {"audit_events", "state_version", "stages"}:
            raise ValueError("pipeline state keys do not match the supported schema")
        if payload["state_version"] != cls.VERSION:
            raise ValueError("unsupported pipeline state version")
        records: dict[str, StageRecord] = {}
        for name, value in payload["stages"].items():
            cls._validate_stage_name(name)
            if set(value) != {
                "attempts", "authorization_hash", "authorization_record", "reason_code",
                "result", "status",
            }:
                raise ValueError("pipeline stage keys do not match the supported schema")
            attempts = value["attempts"]
            if isinstance(attempts, bool) or not isinstance(attempts, int):
                raise ValueError("pipeline stage attempts must be an integer")
            record = StageRecord(
                StageStatus(value["status"]), attempts, value["result"],
                value["reason_code"], value["authorization_hash"],
                value["authorization_record"],
            )
            cls._validate_record(name, record)
            records[name] = record
        audit_events: list[dict[str, object]] = []
        if not isinstance(payload["audit_events"], list):
            raise ValueError("audit events must be a list")
        for value in payload["audit_events"]:
            if not isinstance(value, dict) or set(value) != {"event", "properties"}:
                raise ValueError("audit event keys do not match the supported schema")
            if not isinstance(value["event"], str) or not isinstance(value["properties"], dict):
                raise ValueError("audit event has invalid types")
            audit_events.append(sanitize_audit_event(value["event"], value["properties"]))
        return cls(source, records, audit_events)

    @staticmethod
    def _validate_stage_name(name: str) -> None:
        if not _STAGE_PATTERN.fullmatch(name):
            raise ValueError("invalid pipeline stage name")

    def stage(self, name: str) -> StageRecord:
        try:
            return self._stages[name]
        except KeyError as error:
            raise ValueError(f"unknown pipeline stage: {name}") from error

    def refresh(self) -> None:
        """Replace in-memory state with the latest validated on-disk snapshot."""

        latest = self.load(self.path)
        self._stages = latest._stages
        self._audit_events = latest._audit_events

    @classmethod
    def _validate_record(cls, name: str, record: StageRecord) -> None:
        if record.attempts < 0:
            raise ValueError("pipeline stage attempts cannot be negative")
        if record.authorization_hash is not None and not re.fullmatch(
            r"[0-9a-f]{64}", record.authorization_hash
        ):
            raise ValueError("pipeline stage authorization hash is invalid")
        needs_authorization = name in _GATED_STAGES and record.status is not StageStatus.LOCKED
        if needs_authorization and (
            record.authorization_hash is None or record.authorization_record is None
        ):
            raise ValueError(f"{name} stage lacks bound authorization")
        if name in _GATED_STAGES and needs_authorization:
            from community_os.enrichment.classification import ProcessorApproval
            from community_os.enrichment.gates import CoresignalGate, PublicSourceGate

            try:
                if name == "coresignal":
                    gate = CoresignalGate.from_record(record.authorization_record)
                    expected_hash = gate.authorization_hash(name)
                elif name == "classification":
                    gate = ProcessorApproval.from_record(record.authorization_record)
                    expected_hash = gate.authorization_hash()
                else:
                    gate = PublicSourceGate.from_record(record.authorization_record)
                    expected_hash = gate.authorization_hash(name)
            except (PermissionError, TypeError, ValueError) as error:
                raise ValueError(f"{name} stage authorization record is invalid") from error
            if not hmac.compare_digest(record.authorization_hash, expected_hash):
                raise ValueError(f"{name} stage authorization hash does not match its record")
        if name in _GATED_STAGES and not needs_authorization and (
            record.authorization_hash is not None or record.authorization_record is not None
        ):
            raise ValueError(f"locked {name} stage cannot carry authorization")
        if name not in _GATED_STAGES and (
            record.authorization_hash is not None or record.authorization_record is not None
        ):
            raise ValueError("pipeline stage has authorization for the wrong provider")
        if record.status in {StageStatus.ALLOWED, StageStatus.LOCKED}:
            valid = record.attempts == 0 and record.reason_code is None and record.result is None
        elif record.status is StageStatus.RUNNING:
            valid = record.attempts >= 1 and record.reason_code is None and record.result is None
        elif record.status is StageStatus.FAILED:
            valid = (
                record.attempts >= 1
                and isinstance(record.reason_code, str)
                and bool(_REASON_PATTERN.fullmatch(record.reason_code))
                and record.result is None
            )
        else:
            valid = (
                record.attempts >= 1
                and record.reason_code is None
                and cls._valid_result(record.result)
            )
        if not valid:
            raise ValueError(f"pipeline stage {name} has an impossible state record")

    @staticmethod
    def _valid_result(result: object) -> bool:
        if not isinstance(result, dict) or set(result) != {"output_hash", "record_count"}:
            return False
        output_hash = result["output_hash"]
        record_count = result["record_count"]
        return (
            isinstance(output_hash, str)
            and bool(re.fullmatch(r"[0-9a-f]{64}", output_hash))
            and isinstance(record_count, int)
            and not isinstance(record_count, bool)
            and record_count >= 0
        )

    def unlock(self, name: str, authorization: object | None = None, *, now: object | None = None) -> None:
        current = self.stage(name)
        if current.status is not StageStatus.LOCKED:
            raise ValueError("only a locked stage can be allowed")
        authorization_hash = None
        authorization_record = None
        if name == "coresignal":
            from datetime import datetime
            from community_os.enrichment.gates import CoresignalGate

            if not isinstance(authorization, CoresignalGate) or not isinstance(now, datetime):
                raise PermissionError("Coresignal transition requires bound authorization and time")
            authorization_hash = authorization.authorization_hash(name, now=now)
            authorization_record = authorization.to_record()
        elif name in {"github", "public_pages"}:
            from datetime import datetime
            from community_os.enrichment.gates import PublicSourceGate

            if not isinstance(authorization, PublicSourceGate) or not isinstance(now, datetime):
                raise PermissionError(f"{name} transition requires bound authorization and time")
            authorization_hash = authorization.authorization_hash(name, now=now)
            authorization_record = authorization.to_record()
        elif name == "classification":
            from datetime import datetime
            from community_os.enrichment.classification import ProcessorApproval

            if not isinstance(authorization, ProcessorApproval) or not isinstance(now, datetime):
                raise PermissionError("classification transition requires processor approval and time")
            authorization_hash = authorization.authorization_hash(now=now)
            authorization_record = authorization.to_record()
        self._replace(
            name, StageRecord(
                StageStatus.ALLOWED, current.attempts,
                authorization_hash=authorization_hash,
                authorization_record=authorization_record,
            )
        )

    def lock(self, name: str) -> None:
        """Revoke a gated stage and erase every persisted authorization or result."""
        if name not in _GATED_STAGES:
            raise ValueError("only a gated stage can be locked")
        current = self.stage(name)
        if current.status is StageStatus.LOCKED:
            return
        self._replace(name, StageRecord(StageStatus.LOCKED))

    def start(self, name: str) -> None:
        current = self.stage(name)
        if current.status is StageStatus.LOCKED:
            raise ValueError(f"stage {name} is locked")
        if current.status is StageStatus.COMPLETE:
            raise ValueError(f"stage {name} is complete and cannot rerun")
        if current.status is not StageStatus.ALLOWED:
            raise ValueError(f"stage {name} must be allowed before starting")
        if name in _GATED_STAGES and current.authorization_hash is None:
            raise PermissionError(f"{name} cannot start without bound authorization")
        self._replace(
            name, StageRecord(
                StageStatus.RUNNING, current.attempts + 1,
                authorization_hash=current.authorization_hash,
                authorization_record=current.authorization_record,
            )
        )

    def resume(self, name: str) -> None:
        current = self.stage(name)
        if current.status is not StageStatus.FAILED:
            raise ValueError(f"only a failed stage can resume: {name}")
        self._replace(
            name, StageRecord(
                StageStatus.RUNNING, current.attempts + 1,
                authorization_hash=current.authorization_hash,
                authorization_record=current.authorization_record,
            )
        )

    def fail(self, name: str, reason_code: str) -> None:
        current = self.stage(name)
        if current.status is not StageStatus.RUNNING:
            raise ValueError("only a running stage can fail")
        if not _REASON_PATTERN.fullmatch(reason_code):
            raise ValueError("failure requires a sanitized reason code")
        self._replace(
            name, StageRecord(
                StageStatus.FAILED, current.attempts, reason_code=reason_code,
                authorization_hash=current.authorization_hash,
                authorization_record=current.authorization_record,
            )
        )

    def complete(self, name: str, result: Mapping[str, object]) -> None:
        current = self.stage(name)
        if current.status is not StageStatus.RUNNING:
            raise ValueError("only a running stage can complete")
        materialized = dict(result)
        if not self._valid_result(materialized):
            raise ValueError("stage result does not match the deterministic summary schema")
        self._replace(
            name, StageRecord(
                StageStatus.COMPLETE, current.attempts, materialized,
                authorization_hash=current.authorization_hash,
                authorization_record=current.authorization_record,
            )
        )

    def invalidate(self, names: tuple[str, ...] | list[str]) -> None:
        """Return stale stages to their authorized runnable state.

        Gated stages retain their machine-bound authorization. Locked stages stay
        locked. A running stage cannot be invalidated because its caller must
        first finish or fail the in-flight mutation under the operator lock.
        """
        for name in names:
            current = self.stage(name)
            if current.status is StageStatus.RUNNING:
                raise RuntimeError(f"cannot invalidate running stage: {name}")
            if current.status in {StageStatus.ALLOWED, StageStatus.LOCKED}:
                continue
            self._replace(
                name,
                StageRecord(
                    StageStatus.ALLOWED, 0,
                    authorization_hash=current.authorization_hash,
                    authorization_record=current.authorization_record,
                ),
            )

    def recover_interrupted(self) -> tuple[str, ...]:
        """Convert crash-persisted running stages into explicit resumable failures."""
        recovered: list[str] = []
        for name in sorted(self._stages):
            current = self._stages[name]
            if current.status is not StageStatus.RUNNING:
                continue
            self._replace(
                name,
                StageRecord(
                    StageStatus.FAILED, current.attempts,
                    reason_code="interrupted",
                    authorization_hash=current.authorization_hash,
                    authorization_record=current.authorization_record,
                ),
            )
            recovered.append(name)
        return tuple(recovered)

    def _replace(self, name: str, record: StageRecord) -> None:
        self._validate_record(name, record)
        self._stages[name] = record
        properties: dict[str, object] = {
            "stage": name, "status": record.status.value, "attempt": record.attempts,
        }
        if record.reason_code:
            properties["reason_code"] = record.reason_code
        self._audit_events.append(sanitize_audit_event("stage_transition", properties))
        self._persist()

    def to_dict(self) -> dict[str, object]:
        return {
            "audit_events": self._audit_events,
            "state_version": self.VERSION,
            "stages": {name: self._stages[name].to_dict() for name in sorted(self._stages)},
        }

    def _persist(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.path.parent.chmod(0o700)
        temporary = self.path.with_name(self.path.name + ".tmp")
        temporary.write_text(
            json.dumps(self.to_dict(), ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        temporary.chmod(0o600)
        temporary.replace(self.path)
