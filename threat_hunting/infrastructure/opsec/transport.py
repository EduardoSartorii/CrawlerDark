"""Concrete transports implementing the Transport port.

Responsibility
--------------
Provide the real network adapter (:class:`HttpxTransport`) that applies an
:class:`OpsecProfile` (proxy, UA rotation, rate limit, retries/backoff) and a
:class:`RateLimiter` helper. ``httpx`` is imported lazily so the core/tests run
even when it is not installed; an :class:`OfflineTransport` fallback is provided
for environments without network access or the library.
"""

from __future__ import annotations

import random
import time
from typing import Any

from threat_hunting.core.application.ports.transport import TransportResponse
from threat_hunting.core.domain.exceptions import OpsecError
from threat_hunting.infrastructure.opsec.profile import OpsecProfile


class RateLimiter:
    """Simple monotonic-clock rate limiter enforcing a minimum interval."""

    def __init__(self, min_interval: float, *, clock: Any = time.monotonic, sleep: Any = time.sleep) -> None:
        self._min_interval = min_interval
        self._clock = clock
        self._sleep = sleep
        self._last = 0.0

    def wait(self) -> None:
        """Block until at least ``min_interval`` has passed since the last call."""
        now = self._clock()
        elapsed = now - self._last
        if self._last and elapsed < self._min_interval:
            self._sleep(self._min_interval - elapsed)
        self._last = self._clock()


class HttpxTransport:
    """Transport adapter over ``httpx`` applying an OPSEC profile."""

    def __init__(self, profile: OpsecProfile, *, client: Any = None) -> None:
        self._profile = profile
        self._limiter = RateLimiter(profile.rate_limit.min_interval)
        self._client = client  # allow injection for testing
        self._owns_client = client is None

    def _ensure_client(self) -> Any:
        if self._client is not None:
            return self._client
        try:
            import httpx  # imported lazily; optional at runtime
        except ImportError as exc:  # pragma: no cover - exercised only w/o httpx
            raise OpsecError("httpx is required for HttpxTransport") from exc
        proxies = self._profile.proxies() or None
        self._client = httpx.Client(
            timeout=self._profile.timeout_seconds,
            verify=self._profile.verify_tls,
            proxies=proxies,
            follow_redirects=True,
        )
        return self._client

    def _headers(self, extra: dict[str, str] | None) -> dict[str, str]:
        headers = {"User-Agent": random.choice(self._profile.user_agents)}
        if extra:
            headers.update(extra)
        return headers

    def get(self, url: str, **kwargs: Any) -> TransportResponse:
        """Perform a rate-limited GET with retries/backoff under the profile."""
        return self.request("GET", url, **kwargs)

    def request(self, method: str, url: str, **kwargs: Any) -> TransportResponse:
        """Perform a request applying rate limiting, retries and backoff."""
        client = self._ensure_client()
        headers = self._headers(kwargs.pop("headers", None))
        attempts = self._profile.max_retries + 1
        last_error: Exception | None = None
        for attempt in range(attempts):
            self._limiter.wait()
            try:
                response = client.request(method, url, headers=headers, **kwargs)
            except Exception as exc:  # network errors -> retry with backoff
                last_error = exc
            else:
                return TransportResponse(
                    status_code=response.status_code,
                    text=getattr(response, "text", ""),
                    headers={k: v for k, v in getattr(response, "headers", {}).items()},
                    url=str(getattr(response, "url", url)),
                )
            if attempt < attempts - 1:
                time.sleep(self._profile.backoff_factor * (2**attempt))
        raise OpsecError(f"request to {url} failed after {attempts} attempts: {last_error}")

    def close(self) -> None:
        """Close the underlying client if this transport owns it."""
        if self._client is not None and self._owns_client:
            close = getattr(self._client, "close", None)
            if callable(close):
                close()


class OfflineTransport:
    """Fallback transport used when no network egress is available.

    It never touches the network; every request returns a deterministic 503 so
    connectors can still run their pipeline logic in restricted environments and
    tests without hanging on sockets.
    """

    def __init__(self, profile: OpsecProfile | None = None) -> None:
        self._profile = profile or OpsecProfile()

    def get(self, url: str, **kwargs: Any) -> TransportResponse:
        return self.request("GET", url, **kwargs)

    def request(self, method: str, url: str, **kwargs: Any) -> TransportResponse:
        return TransportResponse(status_code=503, text="offline transport", url=url)

    def close(self) -> None:  # noqa: D401
        return None
