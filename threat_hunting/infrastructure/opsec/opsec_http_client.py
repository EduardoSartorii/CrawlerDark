"""OpsecHTTPClient — cliente httpx configurado por perfil OPSEC.

Suporta:
* HTTP(S) e SOCKS5 proxies (via httpx[socks]);
* User-Agent rotativo;
* Rate limit por host;
* Retry com backoff exponencial + jitter (respeitando 429/5xx);
* Timeout configurável;
* Circuit-breaker minimalista (aberto após N falhas consecutivas).

Implementa ``HTTPClientPort``.
"""

from __future__ import annotations

import asyncio
import random
import time
from collections import defaultdict
from typing import Any
from urllib.parse import urlparse

import httpx

from ..config.schemas import OpsecProfile
from .rate_limiter import AsyncRateLimiter


class _CircuitBreaker:
    """Fecha após ``cooldown`` segundos de silêncio de erros."""

    def __init__(self, threshold: int = 5, cooldown: float = 60.0) -> None:
        self._threshold = threshold
        self._cooldown = cooldown
        self._fails: dict[str, int] = defaultdict(int)
        self._opened_at: dict[str, float] = {}

    def is_open(self, host: str) -> bool:
        opened = self._opened_at.get(host)
        if opened is None:
            return False
        if time.monotonic() - opened >= self._cooldown:
            self._opened_at.pop(host, None)
            self._fails[host] = 0
            return False
        return True

    def record_success(self, host: str) -> None:
        self._fails[host] = 0
        self._opened_at.pop(host, None)

    def record_failure(self, host: str) -> None:
        self._fails[host] += 1
        if self._fails[host] >= self._threshold:
            self._opened_at[host] = time.monotonic()


class OpsecHTTPClient:
    """HTTP client OPSEC-aware.

    Um cliente httpx é criado por perfil; requisições respeitam rate limit e
    aplicam retry/backoff. Compatível com o Protocol ``HTTPClientPort``.
    """

    def __init__(self, profile: OpsecProfile, *, name: str = "default") -> None:
        self._profile = profile
        self._name = name
        limiter = AsyncRateLimiter(profile.rate_limit_per_second)
        self._rate_limiters: dict[str, AsyncRateLimiter] = defaultdict(lambda: limiter)
        self._breaker = _CircuitBreaker()
        transport_kwargs: dict[str, Any] = {
            "timeout": httpx.Timeout(profile.timeout_seconds),
            "follow_redirects": True,
            "verify": True,
        }
        if profile.proxy:
            transport_kwargs["proxy"] = profile.proxy
        self._client = httpx.AsyncClient(**transport_kwargs)

    # --- API pública --------------------------------------------------------

    async def get(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self._request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> httpx.Response:
        return await self._request("POST", url, **kwargs)

    async def close(self) -> None:
        await self._client.aclose()

    # --- Internos -----------------------------------------------------------

    def _headers_for_request(self, override: dict[str, str] | None) -> dict[str, str]:
        headers = dict(self._profile.headers)
        if self._profile.user_agents:
            headers["User-Agent"] = random.choice(self._profile.user_agents)
        if override:
            headers.update(override)
        return headers

    async def _request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        host = urlparse(url).hostname or ""
        if host and self._breaker.is_open(host):
            raise httpx.HTTPError(f"Circuit open for host {host}")
        await self._rate_limiters[host].acquire()

        override_headers: dict[str, str] | None = kwargs.pop("headers", None)
        headers = self._headers_for_request(override_headers)

        last_exc: Exception | None = None
        for attempt in range(self._profile.retries + 1):
            try:
                response = await self._client.request(method, url, headers=headers, **kwargs)
            except (httpx.HTTPError, OSError) as exc:
                last_exc = exc
                self._breaker.record_failure(host)
            else:
                if response.status_code in (429, 500, 502, 503, 504):
                    last_exc = httpx.HTTPStatusError(
                        f"Retryable status {response.status_code}",
                        request=response.request,
                        response=response,
                    )
                    self._breaker.record_failure(host)
                else:
                    self._breaker.record_success(host)
                    return response
            await self._sleep_backoff(attempt)
        assert last_exc is not None
        raise last_exc

    async def _sleep_backoff(self, attempt: int) -> None:
        base = self._profile.backoff_seconds * (2 ** attempt)
        jitter = random.uniform(0.0, self._profile.jitter_seconds)
        await asyncio.sleep(base + jitter)
