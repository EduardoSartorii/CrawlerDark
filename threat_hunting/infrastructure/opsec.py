"""OPSEC transport layer independent from connectors."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

import httpx

from threat_hunting.infrastructure.config import OpsecProfile, PlatformSettings


@dataclass
class RateLimiter:
    """Simple per-profile rate limiter."""

    rate_limit_per_minute: int
    _last_request: float = field(default=0.0)

    def wait(self) -> None:
        """Sleep long enough to satisfy the configured request budget."""

        if self.rate_limit_per_minute <= 0:
            return
        interval = 60.0 / self.rate_limit_per_minute
        elapsed = time.monotonic() - self._last_request
        if elapsed < interval:
            time.sleep(interval - elapsed)
        self._last_request = time.monotonic()


class HttpxOpsecTransport:
    """HTTP transport with proxies, user-agent, retries, and backoff."""

    def __init__(self, profile: OpsecProfile) -> None:
        self.profile = profile
        self.rate_limiter = RateLimiter(profile.rate_limit_per_minute)
        proxies = profile.socks_proxy or profile.https_proxy or profile.http_proxy
        self.client = httpx.Client(proxy=proxies, headers={"User-Agent": profile.user_agent}, timeout=30.0)

    def request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        """Perform an HTTP request according to the OPSEC profile."""

        last_error: Exception | None = None
        for attempt in range(self.profile.retries + 1):
            self.rate_limiter.wait()
            try:
                response = self.client.request(method, url, **kwargs)
                response.raise_for_status()
                return response
            except Exception as exc:  # pragma: no cover - exercised by integration environments
                last_error = exc
                if attempt >= self.profile.retries:
                    break
                time.sleep(self.profile.backoff_seconds * (2**attempt))
        assert last_error is not None
        raise last_error


class OpsecTransportFactory:
    """Factory for connector-specific OPSEC transports."""

    def __init__(self, settings: PlatformSettings) -> None:
        self.settings = settings

    def __call__(self, connector_name: str, config: dict[str, Any]) -> HttpxOpsecTransport:
        """Create transport for a connector name."""

        profile_name = config.get("opsec_profile") or self.settings.connector_opsec_profiles.get(connector_name, "default")
        return HttpxOpsecTransport(self.settings.opsec_profiles[profile_name])
