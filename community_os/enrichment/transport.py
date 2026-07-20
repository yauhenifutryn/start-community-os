"""Injected HTTP contract with pinned public DNS, bounded redirects, and total deadlines."""

from __future__ import annotations

from dataclasses import dataclass
import http.client
import ipaddress
import re
import socket
import ssl
import time
from typing import Callable, Mapping, Protocol, TypeVar
from urllib.parse import urljoin, urlparse, urlunparse, unquote


@dataclass(frozen=True)
class HttpResponse:
    status: int
    headers: Mapping[str, str]
    body: bytes
    url: str


@dataclass(frozen=True)
class ApplicantSuppliedValue:
    """A value coupled to its persisted applicant-source evidence reference."""

    value: str
    source_record_ref: str

    def __post_init__(self) -> None:
        if not self.value.strip():
            raise ValueError("applicant-supplied value is required")
        if not re.fullmatch(r"source:application:[a-z0-9_-]{1,64}", self.source_record_ref):
            raise ValueError("applicant source record reference is required")


class Transport(Protocol):
    def request(
        self, method: str, url: str, *, headers: dict[str, str], timeout: float, max_bytes: int,
    ) -> HttpResponse: ...


class RetryableTransportError(RuntimeError):
    pass


class ResponseTooLargeError(ValueError):
    """A response exceeded the caller's explicit byte ceiling."""


class RateLimitError(RetryableTransportError):
    def __init__(self, message: str, *, retry_after: float) -> None:
        super().__init__(message)
        self.retry_after = retry_after


@dataclass(frozen=True)
class RetryPolicy:
    max_attempts: int = 3
    base_delay: float = 1.0
    max_delay: float = 8.0

    def __post_init__(self) -> None:
        if self.max_attempts < 1 or self.max_attempts > 5:
            raise ValueError("retry attempts must be between 1 and 5")
        if self.base_delay <= 0 or self.max_delay < self.base_delay:
            raise ValueError("invalid retry delay bounds")


_T = TypeVar("_T")


def call_with_retry(
    operation: Callable[[], _T], policy: RetryPolicy, sleeper: Callable[[float], None],
) -> _T:
    for attempt in range(1, policy.max_attempts + 1):
        try:
            return operation()
        except RetryableTransportError as error:
            if attempt == policy.max_attempts:
                raise
            delay = error.retry_after if isinstance(error, RateLimitError) else policy.base_delay * (2 ** (attempt - 1))
            sleeper(min(policy.max_delay, max(policy.base_delay, delay)))
    raise RuntimeError("unreachable retry state")


def canonical_public_url(url: str) -> str:
    """Canonicalize a public HTTPS URL and reject ambiguous host encodings."""
    parsed = urlparse(url.strip())
    if "%" in parsed.netloc:
        raise ValueError("percent-encoded hosts are forbidden")
    if parsed.scheme.casefold() != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("public page must be an unauthenticated HTTPS URL")
    if parsed.fragment:
        raise ValueError("URL fragments are forbidden")
    if parsed.port not in (None, 443):
        raise ValueError("public page URL uses a forbidden port")
    hostname = unquote(parsed.hostname).casefold().rstrip(".")
    if hostname == "localhost" or hostname.endswith(".localhost"):
        raise ValueError("local addresses are forbidden")
    numeric_labels = hostname.split(".")
    if hostname.isdigit() or all(label.isdigit() for label in numeric_labels) or any(
        label.casefold().startswith("0x") or (len(label) > 1 and label.startswith("0") and label.isdigit())
        for label in hostname.split(".")
    ):
        raise ValueError("ambiguous numeric host encoding is forbidden")
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        address = None
    if address is not None and not address.is_global:
        raise ValueError("private, local, reserved, or non-global addresses are forbidden")
    netloc = f"[{hostname}]" if ":" in hostname else hostname
    path = parsed.path or "/"
    return urlunparse(("https", netloc, path, "", parsed.query, ""))


def _public_addresses(hostname: str, resolver: Callable[[str], list[str]]) -> list[str]:
    addresses = resolver(hostname)
    if not addresses:
        raise ValueError("public page host could not be resolved")
    unique: list[str] = []
    for value in addresses:
        address = ipaddress.ip_address(value)
        if not address.is_global:
            raise ValueError("private, local, reserved, or non-global addresses are forbidden")
        if str(address) not in unique:
            unique.append(str(address))
    return unique


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, hostname: str, address: str, timeout: float) -> None:
        super().__init__(hostname, timeout=timeout, context=ssl.create_default_context())
        self._pinned_address = address

    def connect(self) -> None:
        raw = socket.create_connection((self._pinned_address, self.port), self.timeout)
        self.sock = self._context.wrap_socket(raw, server_hostname=self.host)


def _resolve(hostname: str) -> list[str]:
    try:
        return [item[4][0] for item in socket.getaddrinfo(hostname, 443, type=socket.SOCK_STREAM)]
    except socket.gaierror as error:
        raise ValueError("public page host could not be resolved") from error


class PinnedHttpsTransport:
    """HTTPS transport that pins validated DNS, prevalidates redirects, and caps total time."""

    def __init__(
        self, *, resolver: Callable[[str], list[str]] = _resolve,
        connection_factory: Callable[[str, str, float], object] = _PinnedHTTPSConnection,
        monotonic: Callable[[], float] = time.monotonic, max_redirects: int = 3,
    ) -> None:
        self.resolver = resolver
        self.connection_factory = connection_factory
        self.monotonic = monotonic
        self.max_redirects = max_redirects

    def request(
        self, method: str, url: str, *, headers: dict[str, str], timeout: float, max_bytes: int,
    ) -> HttpResponse:
        if method != "GET" or timeout <= 0 or max_bytes < 1:
            raise ValueError("transport accepts only bounded GET requests")
        deadline = self.monotonic() + timeout
        current = canonical_public_url(url)
        original_host = urlparse(current).hostname
        request_headers = dict(headers)
        for redirect_count in range(self.max_redirects + 1):
            parsed = urlparse(current)
            hostname = str(parsed.hostname)
            addresses = _public_addresses(hostname, self.resolver)
            remaining = deadline - self.monotonic()
            if remaining <= 0:
                raise TimeoutError("request exceeded total deadline")
            connection = self.connection_factory(hostname, addresses[0], remaining)
            try:
                target = parsed.path or "/"
                if parsed.query:
                    target += "?" + parsed.query
                connection.request(method, target, headers={**request_headers, "Host": hostname})
                response = connection.getresponse()
                response_headers = {str(key): str(value) for key, value in response.getheaders()}
                if response.status in {301, 302, 303, 307, 308}:
                    if redirect_count == self.max_redirects:
                        raise ValueError("redirect limit exceeded")
                    location = response_headers.get("Location")
                    if not location:
                        raise ValueError("redirect response omitted Location")
                    candidate = canonical_public_url(urljoin(current, location))
                    candidate_host = urlparse(candidate).hostname
                    sensitive_headers = {
                        "authorization", "proxy-authorization", "cookie",
                        "apikey", "x-api-key",
                    }
                    has_credentials = any(
                        key.casefold() in sensitive_headers for key in request_headers
                    )
                    if has_credentials and candidate_host != original_host:
                        raise ValueError("cross-origin authenticated redirect is forbidden")
                    # Validate DNS before the next connection is created.
                    _public_addresses(str(candidate_host), self.resolver)
                    current = candidate
                    continue
                chunks: list[bytes] = []
                total = 0
                while True:
                    remaining = deadline - self.monotonic()
                    if remaining <= 0:
                        raise TimeoutError("request exceeded total deadline")
                    sock = getattr(connection, "sock", None)
                    if sock is not None:
                        sock.settimeout(remaining)
                    chunk = response.read(min(65536, max_bytes + 1 - total))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    total += len(chunk)
                    if total > max_bytes:
                        raise ResponseTooLargeError("response exceeds byte limit")
                return HttpResponse(response.status, response_headers, b"".join(chunks), current)
            except (OSError, http.client.HTTPException) as error:
                raise RetryableTransportError("upstream request failed") from error
            finally:
                connection.close()
        raise ValueError("redirect limit exceeded")
