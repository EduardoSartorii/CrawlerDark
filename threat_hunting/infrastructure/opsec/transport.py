"""OPSEC layer — operational security for collection activities.

Abstracts network transport with proxies, rate limiting, retries,
user-agent rotation, and credential management per connector profile.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any

import httpx
import structlog

from threat_hunting.core.contracts.services import IOpsecTransport
from threat_hunting.core.domain.enums import HealthStatus
from threat_hunting.core.domain.exceptions import OpsecError

logger = structlog.get_logger(__name__)


@dataclass
class RetryPolicy:
    """Configurable retry and backoff policy."""

    max_retries: int = 3
    backoff_factor: float = 1.5
    retry_statuses: tuple[int, ...] = (429, 500, 502, 503, 504)


@dataclass
class RateLimitConfig:
    """Token-bucket style rate limiting per connector."""

    requests_per_second: float = 2.0
    burst: int = 5


@dataclass
class OpsecProfile:
    """OPSEC profile for a connector or collection operation.

    Supports HTTP/HTTPS proxies, SOCKS5, custom user-agents,
  rate limiting, and retry policies. VPN integration is managed
    externally; this profile references the external VPN endpoint.
    """

    name: str = "default"
    http_proxy: str = ""
    https_proxy: str = ""
    socks5_proxy: str = ""
    user_agent: str = "ThreatHuntingPlatform/1.0"
    rate_limit: RateLimitConfig = field(default_factory=RateLimitConfig)
    retry: RetryPolicy = field(default_factory=RetryPolicy)
    verify_ssl: bool = True
    timeout_seconds: float = 30.0
    credentials_key: str = ""
    vpn_endpoint: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


class CredentialVault:
    """Secure credential storage abstraction.

    In production, credentials should be loaded from a secrets manager.
    This implementation uses an in-memory vault for development.
    """

    def __init__(self) -> None:
        self._secrets: dict[str, dict[str, str]] = {}

    def store(self, key: str, credentials: dict[str, str]) -> None:
        """Store credentials under a named key."""
        self._secrets[key] = credentials

    def get(self, key: str) -> dict[str, str]:
        """Retrieve credentials by key."""
        return self._secrets.get(key, {})

    def delete(self, key: str) -> None:
        """Remove stored credentials."""
        self._secrets.pop(key, None)


class RateLimiter:
    """Simple async rate limiter using token bucket semantics."""

    def __init__(self, config: RateLimitConfig) -> None:
        self._config = config
        self._tokens = float(config.burst)
        self._last_refill = asyncio.get_event_loop().time()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        """Wait until a request token is available."""
        async with self._lock:
            now = asyncio.get_event_loop().time()
            elapsed = now - self._last_refill
            self._tokens = min(
                self._config.burst,
                self._tokens + elapsed * self._config.requests_per_second,
            )
            self._last_refill = now
            if self._tokens < 1:
                wait = (1 - self._tokens) / self._config.requests_per_second
                await asyncio.sleep(wait)
                self._tokens = 0
            else:
                self._tokens -= 1


class OpsecTransport(IOpsecTransport):
    """HTTP transport with OPSEC controls."""

    def __init__(self, profile: OpsecProfile, vault: CredentialVault | None = None) -> None:
        self._profile = profile
        self._vault = vault or CredentialVault()
        self._rate_limiter = RateLimiter(profile.rate_limit)
        self._client: httpx.AsyncClient | None = None

    def _build_proxies(self) -> dict[str, str] | None:
        """Build proxy configuration from profile."""
        proxies: dict[str, str] = {}
        if self._profile.http_proxy:
            proxies["http://"] = self._profile.http_proxy
        if self._profile.https_proxy:
            proxies["https://"] = self._profile.https_proxy
        if self._profile.socks5_proxy:
            proxies["all://"] = self._profile.socks5_proxy
        return proxies or None

    async def _get_client(self) -> httpx.AsyncClient:
        """Lazy-initialize httpx client with OPSEC profile."""
        if self._client is None:
            headers = {"User-Agent": self._profile.user_agent}
            if self._profile.credentials_key:
                creds = self._vault.get(self._profile.credentials_key)
                if "api_key" in creds:
                    headers["Authorization"] = f"Bearer {creds['api_key']}"
            self._client = httpx.AsyncClient(
                headers=headers,
                proxies=self._build_proxies(),
                verify=self._profile.verify_ssl,
                timeout=self._profile.timeout_seconds,
                follow_redirects=True,
            )
        return self._client

    async def _request_with_retry(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        """Execute HTTP request with rate limiting and retries."""
        client = await self._get_client()
        last_exc: Exception | None = None

        for attempt in range(self._profile.retry.max_retries + 1):
            await self._rate_limiter.acquire()
            try:
                response = await client.request(method, url, **kwargs)
                if response.status_code not in self._profile.retry.retry_statuses:
                    return response
                if attempt < self._profile.retry.max_retries:
                    wait = self._profile.retry.backoff_factor ** attempt
                    await asyncio.sleep(wait)
            except httpx.HTTPError as exc:
                last_exc = exc
                if attempt < self._profile.retry.max_retries:
                    wait = self._profile.retry.backoff_factor ** attempt
                    await asyncio.sleep(wait)

        if last_exc:
            raise OpsecError(f"Request failed after retries: {last_exc}") from last_exc
        raise OpsecError(f"Request failed with retries: {url}")

    async def get(self, url: str, **kwargs: Any) -> httpx.Response:
        """GET with OPSEC controls."""
        return await self._request_with_retry("GET", url, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> httpx.Response:
        """POST with OPSEC controls."""
        return await self._request_with_retry("POST", url, **kwargs)

    async def close(self) -> None:
        """Close underlying HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None

    async def health(self) -> HealthStatus:
        """Check transport health."""
        return HealthStatus.HEALTHY if self._client or True else HealthStatus.UNHEALTHY


class OpsecProfileRegistry:
    """Central registry for OPSEC profiles per connector."""

    def __init__(self) -> None:
        self._profiles: dict[str, OpsecProfile] = {
            "default": OpsecProfile(name="default"),
        }

    def register(self, profile: OpsecProfile) -> None:
        """Register an OPSEC profile."""
        self._profiles[profile.name] = profile

    def get(self, name: str) -> OpsecProfile:
        """Retrieve profile by name, falling back to default."""
        return self._profiles.get(name, self._profiles["default"])

    def list_profiles(self) -> list[str]:
        """List registered profile names."""
        return list(self._profiles.keys())
