"""
OPSEC HTTP Client.

Wraps httpx.AsyncClient with OPSEC profile settings:
rate limiting, proxy routing, user-agent rotation, retry with backoff.

All connectors use this client — never raw httpx directly.
This ensures consistent security posture across all collection operations.

Design Pattern: Decorator / Facade — wraps httpx with OPSEC logic
"""

from __future__ import annotations

import asyncio
import time
from collections import deque
from typing import Any

import httpx
import structlog

from .profiles import OpsecProfile

logger = structlog.get_logger(__name__)


class RateLimiter:
    """
    Token-bucket rate limiter for HTTP requests.
    Thread-safe for asyncio coroutines.
    """

    def __init__(self, requests_per_minute: int) -> None:
        self._rpm = requests_per_minute
        self._interval = 60.0 / requests_per_minute
        self._timestamps: deque[float] = deque()

    async def acquire(self) -> None:
        """Block until a request slot is available."""
        now = time.monotonic()
        # Remove timestamps older than 60 seconds
        while self._timestamps and now - self._timestamps[0] > 60.0:
            self._timestamps.popleft()

        if len(self._timestamps) >= self._rpm:
            # Wait until oldest request expires
            sleep_for = 60.0 - (now - self._timestamps[0]) + 0.01
            if sleep_for > 0:
                await asyncio.sleep(sleep_for)

        self._timestamps.append(time.monotonic())


class OpsecHttpClient:
    """
    OPSEC-aware async HTTP client.

    Provides:
        - Automatic proxy routing based on profile
        - User-agent rotation
        - Rate limiting
        - Retry with exponential backoff
        - Structured request logging
    """

    def __init__(self, profile: OpsecProfile) -> None:
        self._profile = profile
        self._rate_limiter = RateLimiter(profile.rate_limit.requests_per_minute)
        self._client: httpx.AsyncClient | None = None

    def _build_client(self) -> httpx.AsyncClient:
        """Build an httpx client from the OPSEC profile."""
        proxy_dict = self._profile.get_proxy_dict()
        headers = {
            "User-Agent": self._profile.get_random_user_agent(),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            **self._profile.headers,
        }

        return httpx.AsyncClient(
            headers=headers,
            proxy=proxy_dict.get("https://") if proxy_dict else None,
            verify=self._profile.verify_ssl,
            timeout=httpx.Timeout(self._profile.timeout_seconds),
            follow_redirects=self._profile.follow_redirects,
            max_redirects=self._profile.max_redirects,
            http2=True,
        )

    async def __aenter__(self) -> "OpsecHttpClient":
        self._client = self._build_client()
        await self._client.__aenter__()
        return self

    async def __aexit__(self, *args: Any) -> None:
        if self._client:
            await self._client.__aexit__(*args)
            self._client = None

    async def get(
        self,
        url: str,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        **kwargs: Any,
    ) -> httpx.Response:
        """Rate-limited GET with retry and OPSEC profile applied."""
        return await self._request("GET", url, params=params, headers=headers, **kwargs)

    async def post(
        self,
        url: str,
        data: Any = None,
        json: Any = None,
        headers: dict[str, str] | None = None,
        **kwargs: Any,
    ) -> httpx.Response:
        """Rate-limited POST with retry and OPSEC profile applied."""
        return await self._request(
            "POST", url, data=data, json=json, headers=headers, **kwargs
        )

    async def _request(
        self,
        method: str,
        url: str,
        **kwargs: Any,
    ) -> httpx.Response:
        """Execute request with rate limiting and retry logic."""
        if self._client is None:
            raise RuntimeError("OpsecHttpClient must be used as async context manager")

        await self._rate_limiter.acquire()

        rl = self._profile.rate_limit
        last_exception: Exception | None = None

        for attempt in range(rl.max_retries + 1):
            if attempt > 0:
                delay = min(
                    rl.min_delay_seconds * (rl.backoff_factor ** attempt),
                    rl.max_delay_seconds * 4,
                )
                logger.debug(
                    "http.retry",
                    method=method,
                    url=url,
                    attempt=attempt,
                    delay=delay,
                )
                await asyncio.sleep(delay)

            try:
                # Rotate user-agent on each retry
                if attempt > 0:
                    self._client.headers["User-Agent"] = (
                        self._profile.get_random_user_agent()
                    )

                response = await self._client.request(method, url, **kwargs)

                # Honor Retry-After header
                if (
                    response.status_code == 429
                    and rl.respect_retry_after
                ):
                    retry_after = float(
                        response.headers.get("Retry-After", rl.min_delay_seconds * 2)
                    )
                    logger.warning("http.rate_limited", url=url, retry_after=retry_after)
                    await asyncio.sleep(retry_after)
                    continue

                logger.debug(
                    "http.response",
                    method=method,
                    url=url,
                    status=response.status_code,
                    attempt=attempt,
                )
                return response

            except (httpx.TimeoutException, httpx.ConnectError) as exc:
                last_exception = exc
                logger.warning(
                    "http.request_failed",
                    method=method,
                    url=url,
                    attempt=attempt,
                    error=str(exc),
                )

        raise last_exception or RuntimeError(f"All retries exhausted for {url}")
