"""Approval-bound, content-free receipts for production semantic runs."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import UTC, datetime
import hashlib
import hmac
import json
from pathlib import Path
import re
from typing import Callable, Mapping, Sequence


_HASH = re.compile(r"^[0-9a-f]{64}$")
_SUBJECT = re.compile(r"^case:v1:[0-9a-f]{64}$")
_SOURCE_FAMILIES = ("application", "career", "devpost", "projects")
_FINAL_STATES = frozenset({"completed", "empty", "existing"})
_FAILED_CODES = frozenset({
    "output_token_limit",
    "semantic_output_invalid",
    "semantic_output_invalid_json",
    "semantic_output_invalid_normalization",
    "semantic_output_invalid_validation",
})
_CACHE_STATES = frozenset({
    "hit", "miss", "not_applicable_empty", "not_applicable_existing",
})


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _timestamp(value: datetime) -> str:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("semantic run ledger timestamp requires a timezone")
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _token_cost(tokens: int, rate: int) -> int:
    return (tokens * rate + 999_999) // 1_000_000


@dataclass(frozen=True)
class SemanticRunBinding:
    """Immutable approval, provider, prompt, and price identity for one run."""

    approval_sha256: str
    event_context_sha256: str
    input_cost_per_million_usd_micros: int
    model: str
    normalization_version: str
    output_cost_per_million_usd_micros: int
    prompt_version: str
    reasoning_effort: str
    schema_sha256: str

    def __post_init__(self) -> None:
        if any(
            not isinstance(value, str) or not _HASH.fullmatch(value)
            for value in (
                self.approval_sha256, self.event_context_sha256,
                self.schema_sha256,
            )
        ):
            raise ValueError("semantic run hash binding is invalid")
        if (
            not isinstance(self.model, str) or not self.model
            or not isinstance(self.normalization_version, str)
            or not self.normalization_version
            or not isinstance(self.prompt_version, str) or not self.prompt_version
            or self.reasoning_effort not in {"none", "low", "medium", "high"}
        ):
            raise ValueError("semantic run provider binding is invalid")
        for value in (
            self.input_cost_per_million_usd_micros,
            self.output_cost_per_million_usd_micros,
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError("semantic run price binding is invalid")

    def to_record(self) -> dict[str, object]:
        return asdict(self)

    @property
    def sha256(self) -> str:
        return _sha256(self.to_record())


class ProtectedSemanticRunLedger:
    """Persist only pseudonymous run state and billable usage receipts."""

    VERSION = "rich-semantic-production-run-v1"
    SUBJECT_VERSION = "rich-semantic-production-subject-v1"
    CANARY_VERSION = "rich-semantic-production-canary-v1"
    RECOVERY_VERSION = "rich-semantic-production-recovery-v1"
    CANARY_SIZE = 5

    def __init__(
        self, root: str | Path, *, binding: SemanticRunBinding,
        ordered_subject_refs: Sequence[str], clock: Callable[[], datetime],
    ) -> None:
        self.root = Path(root).absolute()
        if self.root.is_symlink():
            raise PermissionError("semantic run ledger root must not be a symlink")
        if not isinstance(binding, SemanticRunBinding) or not callable(clock):
            raise TypeError("semantic run ledger dependencies are invalid")
        subjects = tuple(ordered_subject_refs)
        if (
            len(subjects) < self.CANARY_SIZE
            or len(subjects) != len(set(subjects))
            or any(not isinstance(item, str) or not _SUBJECT.fullmatch(item) for item in subjects)
        ):
            raise ValueError("semantic run subject population is invalid")
        current = clock()
        _timestamp(current)
        self.binding = binding
        self.ordered_subject_refs = subjects
        self.clock = clock
        self.subjects = self.root / "subjects"
        self.recoveries = self.root / "recoveries"
        for directory in (self.root, self.subjects, self.recoveries):
            directory.mkdir(parents=True, exist_ok=True, mode=0o700)
            directory.chmod(0o700)
        self._bind_or_validate()
        self._validate_all_subject_records()
        if self.canary_path.exists():
            self._load_canary_receipt()

    @property
    def binding_path(self) -> Path:
        return self.root / "binding.json"

    @property
    def canary_path(self) -> Path:
        return self.root / "canary-receipt.json"

    @property
    def population_sha256(self) -> str:
        return _sha256(list(self.ordered_subject_refs))

    @staticmethod
    def _write(path: Path, value: Mapping[str, object]) -> None:
        temporary = path.with_name(path.name + ".tmp")
        temporary.write_bytes(_canonical(value) + b"\n")
        temporary.chmod(0o600)
        temporary.replace(path)
        path.chmod(0o600)

    @staticmethod
    def _read(path: Path, message: str) -> dict[str, object]:
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise PermissionError(message) from error
        if not isinstance(value, dict):
            raise PermissionError(message)
        return value

    def _bind_or_validate(self) -> None:
        expected = {
            "binding": self.binding.to_record(),
            "binding_sha256": self.binding.sha256,
            "ledger_version": self.VERSION,
            "population_count": len(self.ordered_subject_refs),
            "population_sha256": self.population_sha256,
        }
        if not self.binding_path.exists():
            self._write(self.binding_path, expected)
            return
        current = self._read(
            self.binding_path, "semantic run ledger binding is unreadable",
        )
        if (
            current.get("ledger_version") != self.VERSION
            or current.get("binding_sha256") != _sha256(current.get("binding"))
        ):
            raise PermissionError("semantic run ledger binding was tampered")
        if (
            current.get("binding") != self.binding.to_record()
            or not hmac.compare_digest(
                str(current.get("binding_sha256") or ""), self.binding.sha256,
            )
        ):
            raise PermissionError("semantic run binding drift")
        if (
            current.get("population_count") != len(self.ordered_subject_refs)
            or current.get("population_sha256") != self.population_sha256
        ):
            raise PermissionError("semantic run population drift")

    def _subject_path(self, subject_ref: str) -> Path:
        if subject_ref not in self.ordered_subject_refs:
            raise PermissionError("semantic run subject is outside the approved population")
        return self.subjects / f"{hashlib.sha256(subject_ref.encode('ascii')).hexdigest()}.json"

    def _recovery_path(self, subject_ref: str) -> Path:
        if subject_ref not in self.ordered_subject_refs:
            raise PermissionError("semantic run subject is outside the approved population")
        digest = hashlib.sha256(subject_ref.encode("ascii")).hexdigest()
        return self.recoveries / f"{digest}.json"

    @staticmethod
    def _source_counts(value: object) -> dict[str, int]:
        if (
            not isinstance(value, Mapping)
            or set(value) != set(_SOURCE_FAMILIES)
            or any(
                isinstance(value[family], bool)
                or not isinstance(value[family], int)
                or value[family] < 0
                for family in _SOURCE_FAMILIES
            )
        ):
            raise ValueError("semantic run source-family counts are invalid")
        return {family: int(value[family]) for family in _SOURCE_FAMILIES}

    def _load_subject(self, subject_ref: str) -> dict[str, object] | None:
        path = self._subject_path(subject_ref)
        if not path.exists():
            return None
        value = self._read(path, "semantic run subject receipt is unreadable")
        digest = value.pop("record_sha256", None)
        if (
            not isinstance(digest, str) or not _HASH.fullmatch(digest)
            or not hmac.compare_digest(digest, _sha256(value))
            or value.get("record_version") != self.SUBJECT_VERSION
            or value.get("binding_sha256") != self.binding.sha256
            or value.get("subject_ref") != subject_ref
        ):
            raise PermissionError("semantic run subject receipt was tampered")
        state = value.get("state")
        if state == "reserved":
            expected = {
                "binding_sha256", "record_version", "request_byte_count",
                "request_sha256", "reserved_at", "source_family_counts", "state",
                "subject_ref",
            }
            retry_bound = set(value) == expected | {"recovery_receipt_sha256"}
            if set(value) != expected and not retry_bound:
                raise PermissionError("semantic run subject receipt was tampered")
            if retry_bound and (
                not isinstance(value.get("recovery_receipt_sha256"), str)
                or not _HASH.fullmatch(str(value["recovery_receipt_sha256"]))
            ):
                raise PermissionError("semantic run subject receipt was tampered")
        elif state in _FINAL_STATES:
            expected = {
                "binding_sha256", "cache_status", "completed_at",
                "cost_usd_micros", "input_tokens", "model", "model_version",
                "normalization_version", "output_tokens", "prompt_version",
                "reasoning_effort", "record_version", "request_byte_count",
                "request_sha256", "source_family_counts", "state", "subject_ref",
            }
            if set(value) != expected:
                raise PermissionError("semantic run subject receipt was tampered")
        elif state == "failed":
            expected = {
                "binding_sha256", "cost_usd_micros", "failed_at",
                "failure_code", "input_tokens", "model", "model_version",
                "normalization_version", "output_tokens", "prompt_version",
                "reasoning_effort", "record_version", "request_byte_count",
                "request_sha256", "source_family_counts", "state", "subject_ref",
            }
            if set(value) != expected:
                raise PermissionError("semantic run subject receipt was tampered")
        else:
            raise PermissionError("semantic run subject receipt was tampered")
        request_sha256 = value.get("request_sha256")
        request_bytes = value.get("request_byte_count")
        if (
            not isinstance(request_sha256, str) or not _HASH.fullmatch(request_sha256)
            or isinstance(request_bytes, bool) or not isinstance(request_bytes, int)
            or request_bytes < 0
        ):
            raise PermissionError("semantic run subject receipt was tampered")
        try:
            value["source_family_counts"] = self._source_counts(
                value.get("source_family_counts"),
            )
        except ValueError as error:
            raise PermissionError("semantic run subject receipt was tampered") from error
        if state in _FINAL_STATES or state == "failed":
            if (
                (state in _FINAL_STATES and value.get("cache_status") not in _CACHE_STATES)
                or value.get("model") != self.binding.model
                or value.get("reasoning_effort") != self.binding.reasoning_effort
                or value.get("prompt_version") != self.binding.prompt_version
                or value.get("normalization_version") != self.binding.normalization_version
                or (
                    state == "failed"
                    and (
                        value.get("failure_code") not in _FAILED_CODES
                        or value.get("model_version") != self.binding.model
                    )
                )
            ):
                raise PermissionError("semantic run subject receipt was tampered")
            for field in ("input_tokens", "output_tokens", "cost_usd_micros"):
                if (
                    isinstance(value.get(field), bool)
                    or not isinstance(value.get(field), int)
                    or value[field] < 0
                ):
                    raise PermissionError("semantic run subject receipt was tampered")
            expected_cost = _token_cost(
                int(value["input_tokens"]),
                self.binding.input_cost_per_million_usd_micros,
            ) + _token_cost(
                int(value["output_tokens"]),
                self.binding.output_cost_per_million_usd_micros,
            )
            if value["cost_usd_micros"] != expected_cost:
                raise PermissionError("semantic run subject receipt was tampered")
        return value

    def _write_subject(self, value: Mapping[str, object]) -> dict[str, object]:
        record = dict(value)
        path = self._subject_path(str(record["subject_ref"]))
        self._write(path, {**record, "record_sha256": _sha256(record)})
        return record

    def _validate_all_subject_records(self) -> None:
        expected_paths = {
            self._subject_path(subject_ref): subject_ref
            for subject_ref in self.ordered_subject_refs
        }
        for path in self.subjects.glob("*.json"):
            subject_ref = expected_paths.get(path)
            if subject_ref is None:
                raise PermissionError("semantic run subject receipt is outside the population")
            self._load_subject(subject_ref)
        expected_recovery_paths = {
            self._recovery_path(subject_ref): subject_ref
            for subject_ref in self.ordered_subject_refs
        }
        for path in self.recoveries.glob("*.json"):
            subject_ref = expected_recovery_paths.get(path)
            if subject_ref is None:
                raise PermissionError("semantic run recovery receipt is outside the population")
            self.recovery_receipt(subject_ref)

    def subject_state(self, subject_ref: str) -> str | None:
        value = self._load_subject(subject_ref)
        return None if value is None else str(value["state"])

    def reserve(
        self, subject_ref: str, *, request_sha256: str,
        request_byte_count: int, source_family_counts: Mapping[str, int],
    ) -> str:
        if (
            not isinstance(request_sha256, str) or not _HASH.fullmatch(request_sha256)
            or isinstance(request_byte_count, bool) or not isinstance(request_byte_count, int)
            or request_byte_count < 0
        ):
            raise ValueError("semantic run request binding is invalid")
        counts = self._source_counts(source_family_counts)
        current = self._load_subject(subject_ref)
        recovery = self.recovery_receipt(subject_ref)
        if current is None and recovery is not None and (
            recovery["replacement_request_sha256"] != request_sha256
            or recovery["replacement_request_byte_count"] != request_byte_count
            or recovery["replacement_source_family_counts"] != counts
        ):
            raise PermissionError("semantic run request binding drift")
        if current is not None:
            if (
                current["request_sha256"] != request_sha256
                or current["request_byte_count"] != request_byte_count
                or current["source_family_counts"] != counts
            ):
                raise PermissionError("semantic run request binding drift")
            return "interrupted" if current["state"] == "reserved" else "processed"
        reserved = {
            "binding_sha256": self.binding.sha256,
            "record_version": self.SUBJECT_VERSION,
            "request_byte_count": request_byte_count,
            "request_sha256": request_sha256,
            "reserved_at": _timestamp(self.clock()),
            "source_family_counts": counts,
            "state": "reserved",
            "subject_ref": subject_ref,
        }
        if recovery is not None:
            reserved["recovery_receipt_sha256"] = _sha256(recovery)
        self._write_subject(reserved)
        return "reserved"

    def recovery_receipt(self, subject_ref: str) -> dict[str, object] | None:
        """Load one append-only, content-free recovery authorization."""

        path = self._recovery_path(subject_ref)
        if not path.exists():
            return None
        value = self._read(path, "semantic run recovery receipt is unreadable")
        digest = value.pop("receipt_sha256", None)
        expected = {
            "authorized_at", "binding_sha256",
            "cumulative_prior_cost_usd_micros", "previous_record",
            "previous_record_sha256", "previous_state", "recovery_version",
            "replacement_request_byte_count", "replacement_request_sha256",
            "replacement_source_family_counts",
            "request_byte_count", "request_sha256", "source_family_counts",
            "state", "subject_ref",
        }
        previous = value.get("previous_record")
        if not isinstance(previous, dict):
            raise PermissionError("semantic run recovery receipt was tampered")
        previous_material = dict(previous)
        previous_digest = previous_material.pop("record_sha256", None)
        try:
            counts = self._source_counts(value.get("source_family_counts"))
            replacement_counts = self._source_counts(
                value.get("replacement_source_family_counts"),
            )
        except ValueError as error:
            raise PermissionError("semantic run recovery receipt was tampered") from error
        if (
            set(value) != expected
            or not isinstance(digest, str) or not _HASH.fullmatch(digest)
            or not hmac.compare_digest(digest, _sha256(value))
            or value.get("recovery_version") != self.RECOVERY_VERSION
            or value.get("state") != "retry_authorized"
            or value.get("binding_sha256") != self.binding.sha256
            or value.get("subject_ref") != subject_ref
            or value.get("previous_state") not in {"completed", "failed", "reserved"}
            or previous.get("state") != value.get("previous_state")
            or previous.get("subject_ref") != subject_ref
            or previous.get("binding_sha256") != self.binding.sha256
            or not isinstance(previous_digest, str)
            or not _HASH.fullmatch(previous_digest)
            or not hmac.compare_digest(previous_digest, _sha256(previous_material))
            or value.get("previous_record_sha256") != previous_digest
            or value.get("request_sha256") != previous.get("request_sha256")
            or value.get("request_byte_count") != previous.get("request_byte_count")
            or counts != previous.get("source_family_counts")
            or not isinstance(value.get("replacement_request_sha256"), str)
            or not _HASH.fullmatch(str(value["replacement_request_sha256"]))
            or isinstance(value.get("replacement_request_byte_count"), bool)
            or not isinstance(value.get("replacement_request_byte_count"), int)
            or int(value["replacement_request_byte_count"]) < 0
            or value.get("cumulative_prior_cost_usd_micros")
            != (
                previous.get("cost_usd_micros")
                if previous.get("state") in {"completed", "failed"} else 0
            )
        ):
            raise PermissionError("semantic run recovery receipt was tampered")
        value["source_family_counts"] = counts
        value["replacement_source_family_counts"] = replacement_counts
        return value

    def retry_once(
        self, subject_ref: str, *, expected_state: str,
        replacement_request_sha256: str | None = None,
        replacement_request_byte_count: int | None = None,
        replacement_source_family_counts: Mapping[str, int] | None = None,
    ) -> dict[str, object]:
        """Authorize one exact retry while preserving the prior receipt in-ledger."""

        if expected_state not in {"completed", "failed", "reserved"}:
            raise ValueError("semantic run retry state is invalid")
        current = self._load_subject(subject_ref)
        existing = self.recovery_receipt(subject_ref)
        if existing is not None:
            previous = existing["previous_record"]
            if (
                current is not None
                and current.get("state") == expected_state
                and _sha256(current) == previous.get("record_sha256")
            ):
                self._retire_canary_for_retry(subject_ref)
                self._subject_path(subject_ref).unlink()
                return existing
            raise PermissionError("semantic run one-time retry was already used")
        if current is None or current.get("state") != expected_state:
            raise PermissionError("semantic run retry state changed")
        replacements = (
            replacement_request_sha256,
            replacement_request_byte_count,
            replacement_source_family_counts,
        )
        if any(value is not None for value in replacements):
            if (
                expected_state != "completed"
                or any(value is None for value in replacements)
                or not isinstance(replacement_request_sha256, str)
                or not _HASH.fullmatch(replacement_request_sha256)
                or isinstance(replacement_request_byte_count, bool)
                or not isinstance(replacement_request_byte_count, int)
                or replacement_request_byte_count < 0
            ):
                raise ValueError("semantic run replacement request binding is invalid")
            replacement_counts = self._source_counts(
                replacement_source_family_counts,
            )
        else:
            replacement_request_sha256 = str(current["request_sha256"])
            replacement_request_byte_count = int(current["request_byte_count"])
            replacement_counts = self._source_counts(current["source_family_counts"])
        previous_sha256 = _sha256(current)
        receipt = {
            "authorized_at": _timestamp(self.clock()),
            "binding_sha256": self.binding.sha256,
            "cumulative_prior_cost_usd_micros": (
                int(current["cost_usd_micros"])
                if expected_state in {"completed", "failed"} else 0
            ),
            "previous_record": {**current, "record_sha256": previous_sha256},
            "previous_record_sha256": previous_sha256,
            "previous_state": expected_state,
            "recovery_version": self.RECOVERY_VERSION,
            "replacement_request_byte_count": replacement_request_byte_count,
            "replacement_request_sha256": replacement_request_sha256,
            "replacement_source_family_counts": replacement_counts,
            "request_byte_count": int(current["request_byte_count"]),
            "request_sha256": str(current["request_sha256"]),
            "source_family_counts": self._source_counts(
                current["source_family_counts"],
            ),
            "state": "retry_authorized",
            "subject_ref": subject_ref,
        }
        self._retire_canary_for_retry(subject_ref)
        self._write(
            self._recovery_path(subject_ref),
            {**receipt, "receipt_sha256": _sha256(receipt)},
        )
        self._subject_path(subject_ref).unlink()
        return receipt

    def _retire_canary_for_retry(self, subject_ref: str) -> None:
        if subject_ref not in self._canary_subjects() or not self.canary_path.exists():
            return
        self._load_canary_receipt()
        self.canary_path.unlink()

    def _final_record(
        self, subject_ref: str, *, state: str, cache_status: str,
        input_tokens: int, model_version: str, output_tokens: int,
        request_byte_count: int, request_sha256: str,
        source_family_counts: Mapping[str, int],
    ) -> dict[str, object]:
        if (
            state not in _FINAL_STATES or cache_status not in _CACHE_STATES
            or not isinstance(model_version, str) or not model_version
        ):
            raise ValueError("semantic run completion metadata is invalid")
        for value in (input_tokens, output_tokens):
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError("semantic run token usage is invalid")
        return {
            "binding_sha256": self.binding.sha256,
            "cache_status": cache_status,
            "completed_at": _timestamp(self.clock()),
            "cost_usd_micros": _token_cost(
                input_tokens, self.binding.input_cost_per_million_usd_micros,
            ) + _token_cost(
                output_tokens, self.binding.output_cost_per_million_usd_micros,
            ),
            "input_tokens": input_tokens,
            "model": self.binding.model,
            "model_version": model_version,
            "normalization_version": self.binding.normalization_version,
            "output_tokens": output_tokens,
            "prompt_version": self.binding.prompt_version,
            "reasoning_effort": self.binding.reasoning_effort,
            "record_version": self.SUBJECT_VERSION,
            "request_byte_count": request_byte_count,
            "request_sha256": request_sha256,
            "source_family_counts": self._source_counts(source_family_counts),
            "state": state,
            "subject_ref": subject_ref,
        }

    def complete(
        self, subject_ref: str, *, cache_status: str, input_tokens: int,
        model_version: str, output_tokens: int,
    ) -> dict[str, object]:
        current = self._load_subject(subject_ref)
        if current is None or current["state"] != "reserved":
            raise PermissionError("semantic run subject was not reserved")
        record = self._final_record(
            subject_ref, state="completed", cache_status=cache_status,
            input_tokens=input_tokens, model_version=model_version,
            output_tokens=output_tokens,
            request_byte_count=int(current["request_byte_count"]),
            request_sha256=str(current["request_sha256"]),
            source_family_counts=current["source_family_counts"],
        )
        return self._write_subject(record)

    def record_failed(
        self, subject_ref: str, *, failure_code: str, input_tokens: int,
        model_version: str, output_tokens: int,
    ) -> dict[str, object]:
        """Finalize a known provider failure without retaining provider content."""

        current = self._load_subject(subject_ref)
        if current is None or current["state"] != "reserved":
            raise PermissionError("semantic run subject was not reserved")
        if failure_code not in _FAILED_CODES or model_version != self.binding.model:
            raise ValueError("semantic run failure metadata is not trusted")
        for value in (input_tokens, output_tokens):
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError("semantic run failure usage is not trusted")
        return self._write_subject({
            "binding_sha256": self.binding.sha256,
            "cost_usd_micros": _token_cost(
                input_tokens, self.binding.input_cost_per_million_usd_micros,
            ) + _token_cost(
                output_tokens, self.binding.output_cost_per_million_usd_micros,
            ),
            "failed_at": _timestamp(self.clock()),
            "failure_code": failure_code,
            "input_tokens": input_tokens,
            "model": self.binding.model,
            "model_version": model_version,
            "normalization_version": self.binding.normalization_version,
            "output_tokens": output_tokens,
            "prompt_version": self.binding.prompt_version,
            "reasoning_effort": self.binding.reasoning_effort,
            "record_version": self.SUBJECT_VERSION,
            "request_byte_count": int(current["request_byte_count"]),
            "request_sha256": str(current["request_sha256"]),
            "source_family_counts": current["source_family_counts"],
            "state": "failed",
            "subject_ref": subject_ref,
        })

    def record_empty(
        self, subject_ref: str, *, request_sha256: str,
        request_byte_count: int, source_family_counts: Mapping[str, int],
    ) -> dict[str, object]:
        current = self._load_subject(subject_ref)
        if current is None:
            self.reserve(
                subject_ref, request_sha256=request_sha256,
                request_byte_count=request_byte_count,
                source_family_counts=source_family_counts,
            )
            current = self._load_subject(subject_ref)
        else:
            self.reserve(
                subject_ref, request_sha256=request_sha256,
                request_byte_count=request_byte_count,
                source_family_counts=source_family_counts,
            )
        if current is not None and current["state"] == "empty":
            return current
        if current is None or current["state"] != "reserved":
            raise PermissionError("semantic run empty subject is not safely resumable")
        return self._write_subject(self._final_record(
            subject_ref, state="empty", cache_status="not_applicable_empty",
            input_tokens=0, model_version=self.binding.model, output_tokens=0,
            request_byte_count=request_byte_count, request_sha256=request_sha256,
            source_family_counts=source_family_counts,
        ))

    def record_existing(self, subject_ref: str) -> dict[str, object]:
        current = self._load_subject(subject_ref)
        if current is not None and current["state"] in _FINAL_STATES:
            return current
        if current is not None:
            raise PermissionError(
                "semantic run existing subject cannot replace a non-final receipt",
            )
        empty_hash = hashlib.sha256(b"").hexdigest()
        return self._write_subject(self._final_record(
            subject_ref, state="existing",
            cache_status="not_applicable_existing", input_tokens=0,
            model_version=self.binding.model, output_tokens=0,
            request_byte_count=0, request_sha256=empty_hash,
            source_family_counts={family: 0 for family in _SOURCE_FAMILIES},
        ))

    def _canary_subjects(self) -> tuple[str, ...]:
        return self.ordered_subject_refs[: self.CANARY_SIZE]

    def complete_canary(self) -> dict[str, object]:
        interrupted = tuple(
            subject_ref for subject_ref in self._canary_subjects()
            if self.subject_state(subject_ref) == "reserved"
        )
        if interrupted:
            raise PermissionError("semantic run canary has interrupted subjects")
        records = [self._load_subject(subject_ref) for subject_ref in self._canary_subjects()]
        if any(record is None or record["state"] not in _FINAL_STATES for record in records):
            raise PermissionError("semantic run canary is incomplete")
        record_hashes = [_sha256(record) for record in records]
        receipt = {
            "binding_sha256": self.binding.sha256,
            "canary_completed_at": _timestamp(self.clock()),
            "canary_record_sha256s": record_hashes,
            "canary_subject_count": self.CANARY_SIZE,
            "canary_subjects_sha256": _sha256(list(self._canary_subjects())),
            "canary_version": self.CANARY_VERSION,
            "population_sha256": self.population_sha256,
        }
        self._write(
            self.canary_path,
            {**receipt, "receipt_sha256": _sha256(receipt)},
        )
        return receipt

    def _load_canary_receipt(self) -> dict[str, object]:
        value = self._read(
            self.canary_path, "semantic run canary receipt is unreadable",
        )
        digest = value.pop("receipt_sha256", None)
        expected_fields = {
            "binding_sha256", "canary_completed_at", "canary_record_sha256s",
            "canary_subject_count", "canary_subjects_sha256", "canary_version",
            "population_sha256",
        }
        records = [self._load_subject(subject_ref) for subject_ref in self._canary_subjects()]
        if (
            set(value) != expected_fields
            or not isinstance(digest, str) or not _HASH.fullmatch(digest)
            or not hmac.compare_digest(digest, _sha256(value))
            or value.get("canary_version") != self.CANARY_VERSION
            or value.get("binding_sha256") != self.binding.sha256
            or value.get("population_sha256") != self.population_sha256
            or value.get("canary_subject_count") != self.CANARY_SIZE
            or value.get("canary_subjects_sha256") != _sha256(list(self._canary_subjects()))
            or value.get("canary_record_sha256s") != [_sha256(record) for record in records]
            or any(record is None or record["state"] not in _FINAL_STATES for record in records)
        ):
            raise PermissionError("semantic run canary receipt was tampered or drifted")
        return value

    def subjects_for_mode(self, mode: str) -> tuple[str, ...]:
        if mode == "canary":
            return self._canary_subjects()
        if mode == "full":
            if not self.canary_path.is_file():
                raise PermissionError("semantic run full mode requires an exact canary receipt")
            self._load_canary_receipt()
            return self.ordered_subject_refs
        raise ValueError("semantic run mode must be canary or full")

    def unprocessed_subjects(self, mode: str) -> tuple[str, ...]:
        return tuple(
            subject_ref for subject_ref in self.subjects_for_mode(mode)
            if self.subject_state(subject_ref) is None
        )

    def interrupted_subjects(self) -> tuple[str, ...]:
        return tuple(
            subject_ref for subject_ref in self.ordered_subject_refs
            if self.subject_state(subject_ref) == "reserved"
        )

    def failed_subjects(self) -> tuple[str, ...]:
        return tuple(
            subject_ref for subject_ref in self.ordered_subject_refs
            if self.subject_state(subject_ref) == "failed"
        )
