"""Short-lived, protected storage for raw provider evidence."""

from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta
import hashlib
import json
from pathlib import Path
import re
from typing import Callable, Mapping


_SOURCES = frozenset({"github", "public_pages", "coresignal"})
_PURPOSES = {source: "talent_classification" for source in _SOURCES}
_PID = re.compile(r"^pid:[A-Za-z0-9._-]{1,32}:[0-9a-f]{64}$")
_EVIDENCE = re.compile(r"^evidence:(?:github|public_page|coresignal):[a-z0-9]{64,128}$")
_HASH = re.compile(r"^[0-9a-f]{64}$")


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValueError("evidence timestamps require a timezone")
    return value.astimezone(UTC)


def _timestamp(value: datetime) -> str:
    return _utc(value).isoformat().replace("+00:00", "Z")


def _canonical(value: Mapping[str, object]) -> bytes:
    return (json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False,
    ) + "\n").encode("utf-8")


class ProtectedEvidenceVault:
    """Retain raw evidence for at most 24 hours, then leave only a receipt."""

    VERSION = "protected-raw-evidence-v1"
    RECEIPT_VERSION = "protected-evidence-deletion-v1"
    MAX_TTL = timedelta(hours=24)
    MAX_BYTES = 262_144

    def __init__(self, root: str | Path, *, clock: Callable[[], datetime]) -> None:
        self.root = Path(root)
        self.clock = clock
        if self.root.name != "raw-evidence" or self.root.parent.name != "protected":
            raise ValueError("raw evidence must use the protected/raw-evidence storage scope")
        self.records = self.root / "records"
        self.receipts = self.root / "receipts"
        for directory in (self.root, self.records, self.receipts):
            directory.mkdir(parents=True, exist_ok=True, mode=0o700)
            directory.chmod(0o700)
        self._recover_pending_receipts()

    @staticmethod
    def _asset_id(evidence_ref: str) -> str:
        return hashlib.sha256(evidence_ref.encode("utf-8")).hexdigest()

    def _record_path(self, evidence_ref: str) -> Path:
        return self.records / f"{self._asset_id(evidence_ref)}.json"

    def _receipt_path(self, asset_id: str) -> Path:
        if not _HASH.fullmatch(asset_id):
            raise ValueError("evidence asset identifier is invalid")
        return self.receipts / f"{asset_id}.json"

    @staticmethod
    def _write(path: Path, payload: Mapping[str, object]) -> None:
        temporary = path.with_name(path.name + ".tmp")
        temporary.write_bytes(_canonical(payload))
        temporary.chmod(0o600)
        temporary.replace(path)
        path.chmod(0o600)

    def capture(
        self, *, source: str, purpose: str, subject_ref: str, evidence_ref: str,
        provider_version: str, content_type: str, payload: bytes, ttl: timedelta,
    ) -> None:
        if source not in _SOURCES or _PURPOSES.get(source) != purpose:
            raise ValueError("raw evidence source or purpose is not allowlisted")
        if not _PID.fullmatch(subject_ref) or not _EVIDENCE.fullmatch(evidence_ref):
            raise ValueError("raw evidence references must be pseudonymous and opaque")
        if not isinstance(provider_version, str) or not re.fullmatch(r"[a-z0-9][a-z0-9._-]{2,80}", provider_version):
            raise ValueError("raw evidence provider version is invalid")
        if not isinstance(content_type, str) or not re.fullmatch(r"[a-z0-9.+-]+/[a-z0-9.+-]+", content_type.casefold()):
            raise ValueError("raw evidence content type is invalid")
        if not isinstance(payload, bytes) or not payload or len(payload) > self.MAX_BYTES:
            raise ValueError("raw evidence payload is empty or exceeds the byte limit")
        if not isinstance(ttl, timedelta) or ttl <= timedelta(0) or ttl > self.MAX_TTL:
            raise ValueError("raw evidence TTL must be positive and no longer than 24 hours")
        now = _utc(self.clock())
        asset_id = self._asset_id(evidence_ref)
        envelope = {
            "asset_id": asset_id,
            "captured_at": _timestamp(now),
            "content_type": content_type.casefold(),
            "deletion_state": "retained",
            "evidence_ref": evidence_ref,
            "expires_at": _timestamp(now + ttl),
            "payload_base64": base64.b64encode(payload).decode("ascii"),
            "payload_sha256": hashlib.sha256(payload).hexdigest(),
            "provider_version": provider_version,
            "purpose": purpose,
            "record_version": self.VERSION,
            "source": source,
            "subject_ref": subject_ref,
        }
        path = self._record_path(evidence_ref)
        if path.exists():
            existing = self._load(path)
            if (
                existing.get("payload_sha256") != envelope["payload_sha256"]
                or existing.get("source") != source
                or existing.get("subject_ref") != subject_ref
            ):
                raise PermissionError("raw evidence changed before reviewed projection")
            return
        if self._receipt_path(asset_id).exists():
            raise PermissionError("deleted raw evidence cannot be recreated for the same reference")
        self._write(path, envelope)

    def _load(self, path: Path) -> dict[str, object]:
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise PermissionError("raw evidence is unreadable") from error
        required = {
            "asset_id", "captured_at", "content_type", "deletion_state", "evidence_ref",
            "expires_at", "payload_base64", "payload_sha256", "provider_version", "purpose",
            "record_version", "source", "subject_ref",
        }
        if not isinstance(value, dict) or set(value) != required or value.get("record_version") != self.VERSION:
            raise PermissionError("raw evidence envelope is invalid")
        try:
            captured = datetime.fromisoformat(str(value["captured_at"]).replace("Z", "+00:00"))
            expiry = datetime.fromisoformat(str(value["expires_at"]).replace("Z", "+00:00"))
        except ValueError as error:
            raise PermissionError("raw evidence envelope is invalid") from error
        evidence_ref = str(value["evidence_ref"])
        asset_id = str(value["asset_id"])
        if (
            value.get("deletion_state") != "retained"
            or value.get("source") not in _SOURCES
            or value.get("purpose") != _PURPOSES.get(str(value.get("source")))
            or not _PID.fullmatch(str(value.get("subject_ref")))
            or not _EVIDENCE.fullmatch(evidence_ref)
            or not _HASH.fullmatch(asset_id)
            or asset_id != self._asset_id(evidence_ref)
            or path.stem != asset_id
            or not _HASH.fullmatch(str(value.get("payload_sha256")))
            or captured.tzinfo is None or expiry.tzinfo is None
            or _utc(expiry) <= _utc(captured)
            or _utc(expiry) - _utc(captured) > self.MAX_TTL
        ):
            raise PermissionError("raw evidence envelope is invalid")
        return value

    def _recover_pending_receipts(self) -> None:
        for temporary in self.receipts.glob("*.tmp"):
            temporary.unlink(missing_ok=True)
        for path in sorted(self.receipts.glob("*.json")):
            try:
                receipt = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as error:
                raise PermissionError("evidence deletion receipt is unreadable") from error
            self._validate_receipt(path, receipt)
            state = receipt.get("deletion_state")
            if state == "deleted":
                continue
            if state != "pending" or receipt.get("deleted_at") is not None:
                raise PermissionError("evidence deletion receipt state is invalid")
            record = self.records / path.name
            record.unlink(missing_ok=True)
            receipt["deleted_at"] = _timestamp(self.clock())
            receipt["deletion_state"] = "deleted"
            self._write(path, receipt)

    def _validate_receipt(self, path: Path, receipt: object) -> None:
        required = {
            "asset_id", "captured_at", "deleted_at", "deletion_state", "expires_at",
            "payload_sha256", "projection_sha256", "provider_version", "purpose",
            "reason", "receipt_version", "source",
        }
        if not isinstance(receipt, dict) or set(receipt) != required:
            raise PermissionError("evidence deletion receipt is invalid")
        asset_id = str(receipt.get("asset_id"))
        source = str(receipt.get("source"))
        state = receipt.get("deletion_state")
        projection = receipt.get("projection_sha256")
        reason = str(receipt.get("reason"))
        if (
            receipt.get("receipt_version") != self.RECEIPT_VERSION
            or not _HASH.fullmatch(asset_id)
            or path.stem != asset_id
            or source not in _SOURCES.union({"unreadable"})
            or receipt.get("purpose") != "talent_classification"
            or not _HASH.fullmatch(str(receipt.get("payload_sha256")))
            or not re.fullmatch(r"[a-z][a-z0-9_]{2,63}", reason)
            or state not in {"pending", "deleted"}
            or (projection is not None and not _HASH.fullmatch(str(projection)))
            or (reason == "reviewed_projection") != (projection is not None)
        ):
            raise PermissionError("evidence deletion receipt is invalid")
        captured: datetime | None = None
        if source == "unreadable":
            if (
                receipt.get("captured_at") is not None
                or receipt.get("expires_at") is not None
                or receipt.get("provider_version") != "unreadable"
            ):
                raise PermissionError("evidence deletion receipt is invalid")
        else:
            try:
                captured = datetime.fromisoformat(str(receipt["captured_at"]).replace("Z", "+00:00"))
                expiry = datetime.fromisoformat(str(receipt["expires_at"]).replace("Z", "+00:00"))
            except ValueError as error:
                raise PermissionError("evidence deletion receipt is invalid") from error
            if (
                captured.tzinfo is None or expiry.tzinfo is None
                or _utc(expiry) <= _utc(captured)
                or _utc(expiry) - _utc(captured) > self.MAX_TTL
                or not isinstance(receipt.get("provider_version"), str)
                or not re.fullmatch(r"[a-z0-9][a-z0-9._-]{2,80}", str(receipt["provider_version"]))
            ):
                raise PermissionError("evidence deletion receipt is invalid")
        deleted_at = receipt.get("deleted_at")
        if state == "pending" and deleted_at is not None:
            raise PermissionError("evidence deletion receipt is invalid")
        if state == "deleted":
            try:
                deleted = datetime.fromisoformat(str(deleted_at).replace("Z", "+00:00"))
            except ValueError as error:
                raise PermissionError("evidence deletion receipt is invalid") from error
            if (
                deleted.tzinfo is None
                or (captured is not None and _utc(deleted) < _utc(captured))
            ):
                raise PermissionError("evidence deletion receipt is invalid")

    def read(self, evidence_ref: str, *, source: str, subject_ref: str) -> bytes:
        path = self._record_path(evidence_ref)
        if not path.is_file():
            raise PermissionError("raw evidence is unavailable")
        envelope = self._load(path)
        if envelope.get("source") != source or envelope.get("subject_ref") != subject_ref:
            raise PermissionError("raw evidence binding does not match")
        try:
            expiry = datetime.fromisoformat(str(envelope["expires_at"]).replace("Z", "+00:00"))
        except ValueError as error:
            self._delete_path(path, reason="invalid_envelope", projection_sha256=None)
            raise PermissionError("raw evidence expiry is invalid") from error
        if _utc(expiry) <= _utc(self.clock()):
            self._delete_path(path, reason="ttl_expired", projection_sha256=None)
            raise PermissionError("raw evidence expired before reviewed projection")
        try:
            payload = base64.b64decode(str(envelope["payload_base64"]), validate=True)
        except (ValueError, TypeError) as error:
            self._delete_path(path, reason="invalid_envelope", projection_sha256=None)
            raise PermissionError("raw evidence payload is invalid") from error
        if hashlib.sha256(payload).hexdigest() != envelope.get("payload_sha256"):
            self._delete_path(path, reason="invalid_envelope", projection_sha256=None)
            raise PermissionError("raw evidence payload integrity failed")
        return payload

    def delete(self, evidence_ref: str, *, reason: str, projection_sha256: str | None = None) -> dict[str, object] | None:
        return self._delete_path(
            self._record_path(evidence_ref), reason=reason,
            projection_sha256=projection_sha256,
        )

    def _delete_path(
        self, path: Path, *, reason: str, projection_sha256: str | None,
    ) -> dict[str, object] | None:
        if not re.fullmatch(r"[a-z][a-z0-9_]{2,63}", reason):
            raise ValueError("evidence deletion reason is invalid")
        if projection_sha256 is not None and not _HASH.fullmatch(projection_sha256):
            raise ValueError("reviewed projection hash is invalid")
        if not path.exists():
            return None
        try:
            envelope = self._load(path)
        except PermissionError:
            return self._delete_unreadable(
                path, reason=reason, projection_sha256=projection_sha256,
            )
        asset_id = str(envelope["asset_id"])
        receipt_path = self._receipt_path(asset_id)
        receipt = {
            "asset_id": asset_id,
            "captured_at": envelope["captured_at"],
            "deleted_at": None,
            "deletion_state": "pending",
            "expires_at": envelope["expires_at"],
            "payload_sha256": envelope["payload_sha256"],
            "projection_sha256": projection_sha256,
            "provider_version": envelope["provider_version"],
            "purpose": envelope["purpose"],
            "reason": reason,
            "receipt_version": self.RECEIPT_VERSION,
            "source": envelope["source"],
        }
        self._write(receipt_path, receipt)
        path.unlink()
        receipt["deleted_at"] = _timestamp(self.clock())
        receipt["deletion_state"] = "deleted"
        self._write(receipt_path, receipt)
        return receipt

    def _delete_unreadable(
        self, path: Path, *, reason: str, projection_sha256: str | None,
    ) -> dict[str, object]:
        raw = path.read_bytes()
        asset_id = path.stem if _HASH.fullmatch(path.stem) else hashlib.sha256(path.name.encode()).hexdigest()
        now = _timestamp(self.clock())
        receipt = {
            "asset_id": asset_id, "captured_at": None, "deleted_at": None,
            "deletion_state": "pending", "expires_at": None,
            "payload_sha256": hashlib.sha256(raw).hexdigest(),
            "projection_sha256": projection_sha256, "provider_version": "unreadable",
            "purpose": "talent_classification", "reason": reason,
            "receipt_version": self.RECEIPT_VERSION, "source": "unreadable",
        }
        receipt_path = self._receipt_path(asset_id)
        self._write(receipt_path, receipt)
        path.unlink(missing_ok=True)
        receipt["deleted_at"] = now
        receipt["deletion_state"] = "deleted"
        self._write(receipt_path, receipt)
        return receipt

    def delete_all(
        self, *, reason: str, projection_sha256: str | None = None,
    ) -> list[dict[str, object]]:
        receipts: list[dict[str, object]] = []
        for temporary in self.records.glob("*.tmp"):
            temporary.unlink(missing_ok=True)
        for path in sorted(self.records.glob("*.json")):
            receipt = self._delete_path(
                path, reason=reason, projection_sha256=projection_sha256,
            )
            if receipt is not None:
                receipts.append(receipt)
        if any(self.records.iterdir()):
            raise PermissionError("raw evidence cleanup did not complete")
        return receipts

    def delete_source(self, source: str, *, reason: str) -> list[dict[str, object]]:
        if source not in _SOURCES:
            raise ValueError("raw evidence source is not allowlisted")
        receipts: list[dict[str, object]] = []
        # Interrupted atomic writes do not contain a safely readable source
        # binding. Delete every such temporary fail-closed during any source
        # revocation instead of retaining unknown raw provider evidence.
        for temporary in self.records.glob("*.tmp"):
            temporary.unlink(missing_ok=True)
        for path in sorted(self.records.glob("*.json")):
            try:
                envelope = self._load(path)
            except PermissionError:
                receipt = self._delete_unreadable(
                    path, reason=reason, projection_sha256=None,
                )
                receipts.append(receipt)
                continue
            if envelope.get("source") == source:
                receipt = self._delete_path(
                    path, reason=reason, projection_sha256=None,
                )
                if receipt is not None:
                    receipts.append(receipt)
        return receipts

    def purge_expired(self) -> list[dict[str, object]]:
        receipts: list[dict[str, object]] = []
        for temporary in self.records.glob("*.tmp"):
            temporary.unlink(missing_ok=True)
        for path in sorted(self.records.glob("*.json")):
            try:
                envelope = self._load(path)
            except PermissionError:
                receipts.append(self._delete_unreadable(
                    path, reason="invalid_envelope", projection_sha256=None,
                ))
                continue
            try:
                expiry = datetime.fromisoformat(str(envelope["expires_at"]).replace("Z", "+00:00"))
            except ValueError:
                expiry = _utc(self.clock())
            if expiry.tzinfo is None or _utc(expiry) <= _utc(self.clock()):
                receipt = self._delete_path(path, reason="ttl_expired", projection_sha256=None)
                if receipt is not None:
                    receipts.append(receipt)
        return receipts
