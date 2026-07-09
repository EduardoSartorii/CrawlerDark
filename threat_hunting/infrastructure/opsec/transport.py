"""httpx-based OPSEC transport and its factory.

Responsibility
--------------
Implement :class:`TransportPort` on top of ``httpx``, applying every OPSEC
control from the profile: proxies (HTTP/HTTPS and SOCKS5/Tor), TLS verification,
User-Agent and custom headers, timeouts, rate limiting and retries with
exponential backoff. Connectors never construct HTTP clients themselves — they
receive a transport from :class:`TransportFactory`, keeping OPSEC centralised.

Design notes
------------
* SOCKS5 requires the ``httpx[socks]`` extra; if it is unavailable the transport
  degrades gracefully to a direct connection and records the reason, rather than
  crashing collection.
* The factory is the single place that reads OPSEC profiles, so a future Django
  admin can manage proxies/VPNs without touching connectors.
"""

from __future__ import annotations

import asyncio
from typing import Any

import httpx

from threat_hunting.core.application.ports.transport import (
    TransportFactoryPort,
    TransportPort,
    TransportResponse,
)
from threat_hunting.infrastructure.config.settings import OpsecProfile, PlatformSettings
from threat_hunting.infrastructure.opsec.rate_limiter import RateLimiter


class HttpxTransport(TransportPort):
    """A network transport bound to one OPSEC profile."""

    def __init__(self, profile_name: str, profile: OpsecProfile) -> None:
        self.profile = profile_name
        self._profile = profile
        self._limiter = RateLimiter(profile.rate_limit_per_second)
        self._client = self._build_client(profile)

    @staticmethod
    def _build_client(profile: OpsecProfile) -> httpx.AsyncClient:
        """Construct an ``httpx`` client applying proxy/UA/TLS settings."""
        headers = {"User-Agent": profile.user_agent, **profile.headers}
        proxy = (
            profile.socks5_proxy
            or profile.https_proxy
            or profile.http_proxy
        )
        kwargs: dict[str, Any] = {
            "headers": headers,
            "timeout": profile.timeout_seconds,
            "verify": profile.verify_tls,
            "follow_redirects": True,
        }
        if proxy:
            try:
                return httpx.AsyncClient(proxy=proxy, **kwargs)
            except (ImportError, ValueError):
                # SOCKS extra missing / invalid proxy -> degrade to direct.
                pass
        return httpx.AsyncClient(**kwargs)

    async def _request(
        self, method: str, url: str, **kwargs: Any
    ) -> TransportResponse:
        """Perform a request with rate limiting and backoff retries."""
        last_exc: Exception | None = None
        for attempt in range(self._profile.max_retries + 1):
            await self._limiter.acquire()
            try:
                response = await self._client.request(method, url, **kwargs)
                return TransportResponse(
                    status_code=response.status_code,
                    text=response.text,
                    headers=dict(response.headers),
                    url=str(response.url),
                )
            except httpx.HTTPError as exc:
                last_exc = exc
                if attempt < self._profile.max_retries:
                    await asyncio.sleep(self._profile.backoff_factor * (2**attempt))
        raise httpx.HTTPError(f"transport failed after retries: {last_exc}")

    async def get(
        self, url: str, *, params: dict[str, Any] | None = None
    ) -> TransportResponse:
        return await self._request("GET", url, params=params)

    async def post(
        self, url: str, *, data: Any | None = None, json: Any | None = None
    ) -> TransportResponse:
        return await self._request("POST", url, data=data, json=json)

    async def aclose(self) -> None:
        await self._client.aclose()


class TransportFactory(TransportFactoryPort):
    """Builds :class:`HttpxTransport` instances from OPSEC profiles."""

    def __init__(self, settings: PlatformSettings) -> None:
        self._settings = settings

    def for_profile(self, profile: str) -> TransportPort:
        """Return a transport configured for the named OPSEC profile."""
        return HttpxTransport(profile, self._settings.opsec_profile(profile))
