"""Canonical, expiring, file-backed cache for protected enrichment payloads."""

from __future__ import annotations

from datetime import UTC, datetime
import hashlib
import json
from pathlib import Path
import re
from typing import Callable, Mapping


_KEY = re.compile(r"^[a-z0-9_-]{1,48}:[0-9a-f]{64}$")


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False,
    ).encode("utf-8")


def _reject_constant(value: str) -> object:
    raise ValueError(f"non-finite JSON value is forbidden: {value}")


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValueError("cache timestamps require a timezone")
    return value.astimezone(UTC)


class CanonicalJsonCache:
    """Store minimized JSON in one protected file per deterministic cache key."""

    VERSION = "enrichment-cache-v1"

    def __init__(self, root: str | Path, *, clock: Callable[[], datetime]) -> None:
        self.root = Path(root)
        self.clock = clock
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.root.chmod(0o700)

    def key(self, namespace: str, version: str, inputs: Mapping[str, object]) -> str:
        if not re.fullmatch(r"[a-z][a-z0-9_-]{0,47}", namespace):
            raise ValueError("invalid cache namespace")
        digest = hashlib.sha256(_canonical({"inputs": inputs, "version": version})).hexdigest()
        return f"{namespace}:{digest}"

    def _path(self, key: str) -> Path:
        if not _KEY.fullmatch(key):
            raise ValueError("invalid cache key")
        return self.root / (key.replace(":", "-") + ".json")

    def set(self, key: str, value: Mapping[str, object], *, expires_at: datetime) -> None:
        now = _utc(self.clock())
        expiry = _utc(expires_at)
        if expiry <= now:
            raise ValueError("cache expiry must be in the future")
        payload = {
            "cache_version": self.VERSION,
            "created_at": now.isoformat().replace("+00:00", "Z"),
            "expires_at": expiry.isoformat().replace("+00:00", "Z"),
            "key": key,
            "value": dict(value),
        }
        encoded = _canonical(payload) + b"\n"
        destination = self._path(key)
        temporary = destination.with_suffix(".tmp")
        temporary.write_bytes(encoded)
        temporary.chmod(0o600)
        temporary.replace(destination)

    def get(self, key: str) -> dict[str, object] | None:
        path = self._path(key)
        if not path.exists():
            return None
        try:
            payload = json.loads(path.read_text(encoding="utf-8"), parse_constant=_reject_constant)
            if set(payload) != {"cache_version", "created_at", "expires_at", "key", "value"}:
                raise ValueError("cache envelope is invalid")
            if payload["cache_version"] != self.VERSION or payload["key"] != key:
                raise ValueError("cache envelope does not match key")
            created = datetime.fromisoformat(str(payload["created_at"]).replace("Z", "+00:00"))
            expiry = datetime.fromisoformat(str(payload["expires_at"]).replace("Z", "+00:00"))
            if created.tzinfo is None or expiry.tzinfo is None or _utc(expiry) <= _utc(created):
                raise ValueError("cache timestamps are invalid")
            if _utc(expiry) <= _utc(self.clock()):
                path.unlink(missing_ok=True)
                return None
            if not isinstance(payload["value"], dict):
                raise ValueError("cache value must be an object")
            return dict(payload["value"])
        except (OSError, json.JSONDecodeError, TypeError, ValueError) as error:
            raise ValueError("cache entry is unreadable") from error

    def delete_expired(self) -> int:
        removed = 0
        # A process crash can strand the atomic-write temporary after personal
        # cache data has been written but before replace(). It has no reliable
        # retention envelope, so cleanup must delete it fail-safe.
        for path in self.root.glob("*.tmp"):
            path.unlink(missing_ok=True)
            removed += 1
        for path in self.root.glob("*.json"):
            try:
                payload = json.loads(path.read_text(encoding="utf-8"), parse_constant=_reject_constant)
                expiry = datetime.fromisoformat(str(payload["expires_at"]).replace("Z", "+00:00"))
                if _utc(expiry) <= _utc(self.clock()):
                    path.unlink(missing_ok=True)
                    removed += 1
            except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError):
                path.unlink(missing_ok=True)
                removed += 1
        return removed

    def delete_all(self) -> int:
        """Delete every transient cache entry, including interrupted writes."""
        removed = 0
        for pattern in ("*.json", "*.tmp"):
            for path in self.root.glob(pattern):
                path.unlink(missing_ok=True)
                removed += 1
        return removed
