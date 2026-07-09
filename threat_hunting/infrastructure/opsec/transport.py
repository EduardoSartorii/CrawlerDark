"""OPSEC transport layer — independent of connectors.

Responsibility
--------------
Abstract network transport with proxy (HTTP/HTTPS/SOCKS5), VPN-ready
profiles, configurable User-Agents, rate limiting, retries/backoff and
credential vault references. Connectors never configure proxies directly.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

import httpx
import structlog
from tenacity import AsyncRetrying, retry_if_exception_type, stop_after_attempt, wait_exponential

from threat_hunting.core.application.ports import (
    CredentialVaultPort,
    OpsecTransportPort,
    RateLimiterPort,
)
from threat_hunting.core.domain.value_objects import OpsecProfile

logger = structlog.get_logger(__name__)


class InMemoryCredentialVault(CredentialVaultPort):
    """Simple credential vault — replace with HashiCorp/AWS Secrets in prod."""

    def __init__(self, secrets: dict[str, dict[str, str]] | None = None) -> None:
        self._secrets = secrets or {}

    async def get(self, ref: str) -> dict[str, str]:
        # refs like vault://social/reddit
        key = ref.replace("vault://", "")
        if key not in self._secrets:
            logger.warning("vault.miss", ref=ref)
            return {}
        return dict(self._secrets[key])


class TokenBucketRateLimiter(RateLimiterPort):
    """Per-key token-bucket rate limiter."""

    def __init__(self) -> None:
        self._locks: dict[str, asyncio.Lock] = {}
        self._tokens: dict[str, float] = {}
        self._last: dict[str, float] = {}

    async def acquire(self, key: str, *, rps: float) -> None:
        if rps <= 0:
            return
        if key not in self._locks:
            self._locks[key] = asyncio.Lock()
            self._tokens[key] = rps
            self._last[key] = time.monotonic()
        async with self._locks[key]:
            now = time.monotonic()
            elapsed = now - self._last[key]
            self._tokens[key] = min(rps, self._tokens[key] + elapsed * rps)
            self._last[key] = now
            if self._tokens[key] < 1.0:
                wait = (1.0 - self._tokens[key]) / rps
                await asyncio.sleep(wait)
                self._tokens[key] = 0.0
                self._last[key] = time.monotonic()
            else:
                self._tokens[key] -= 1.0


class HttpxOpsecTransport(OpsecTransportPort):
    """httpx-based OPSEC transport with proxy, UA, retries and rate limits."""

    def __init__(
        self,
        *,
        rate_limiter: RateLimiterPort | None = None,
        vault: CredentialVaultPort | None = None,
    ) -> None:
        self._rate_limiter = rate_limiter or TokenBucketRateLimiter()
        self._vault = vault or InMemoryCredentialVault()
        self._clients: dict[str, httpx.AsyncClient] = {}

    def _client_for(self, profile: OpsecProfile) -> httpx.AsyncClient:
        if profile.name not in self._clients:
            proxies = profile.proxy
            headers = {"User-Agent": profile.user_agent, **profile.headers}
            # httpx 0.28 uses proxy= singular
            kwargs: dict[str, Any] = {
                "headers": headers,
                "timeout": profile.timeout_seconds,
                "verify": profile.verify_tls,
                "follow_redirects": True,
            }
            if proxies:
                kwargs["proxy"] = proxies
            self._clients[profile.name] = httpx.AsyncClient(**kwargs)
        return self._clients[profile.name]

    async def _auth_headers(self, profile: OpsecProfile) -> dict[str, str]:
        if not profile.credentials_ref:
            return {}
        creds = await self._vault.get(profile.credentials_ref)
        headers: dict[str, str] = {}
        if "token" in creds:
            headers["Authorization"] = f"Bearer {creds['token']}"
        elif "api_key" in creds:
            headers["X-API-Key"] = creds["api_key"]
        elif "username" in creds and "password" in creds:
            # Basic auth handled via httpx auth if needed; expose as header hint
            import base64

            token = base64.b64encode(
                f"{creds['username']}:{creds['password']}".encode()
            ).decode()
            headers["Authorization"] = f"Basic {token}"
        return headers

    async def request(
        self, method: str, url: str, *, profile: OpsecProfile, **kwargs: Any
    ) -> httpx.Response:
        await self._rate_limiter.acquire(profile.name, rps=profile.rate_limit_rps)
        client = self._client_for(profile)
        auth_headers = await self._auth_headers(profile)
        headers = {**auth_headers, **(kwargs.pop("headers", {}) or {})}

        async for attempt in AsyncRetrying(
            stop=stop_after_attempt(profile.max_retries),
            wait=wait_exponential(multiplier=profile.backoff_factor, min=1, max=60),
            retry=retry_if_exception_type((httpx.TransportError, httpx.TimeoutException)),
            reraise=True,
        ):
            with attempt:
                logger.debug(
                    "opsec.request",
                    method=method,
                    url=url,
                    profile=profile.name,
                    attempt=attempt.retry_state.attempt_number,
                )
                response = await client.request(method, url, headers=headers, **kwargs)
                response.raise_for_status()
                return response
        raise RuntimeError("unreachable")  # pragma: no cover

    async def get(self, url: str, *, profile: OpsecProfile, **kwargs: Any) -> httpx.Response:
        return await self.request("GET", url, profile=profile, **kwargs)

    async def post(self, url: str, *, profile: OpsecProfile, **kwargs: Any) -> httpx.Response:
        return await self.request("POST", url, profile=profile, **kwargs)

    async def aclose(self) -> None:
        for client in self._clients.values():
            await client.aclose()
        self._clients.clear()


__all__ = [
    "HttpxOpsecTransport",
    "InMemoryCredentialVault",
    "TokenBucketRateLimiter",
]
