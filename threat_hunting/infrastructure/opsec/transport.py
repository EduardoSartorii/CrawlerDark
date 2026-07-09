"""Network transport and secret adapters for operational security.

The OPSEC layer centralizes proxies, user agents, retries, backoff and credential
lookup so individual connectors cannot accidentally bypass collection posture.
"""

from __future__ import annotations

import os
import time
from collections.abc import Callable
from typing import Any

import httpx

from threat_hunting.infrastructure.config.settings import OpsecProfile


class SecretsProvider:
    """Resolve secrets by reference from environment variables."""

    def get(self, reference: str | None) -> str | None:
        """Return a secret value without exposing it in connector config."""

        if not reference:
            return None
        return os.getenv(reference)


class RetryingHttpClient:
    """Small retry wrapper around ``httpx.Client``."""

    def __init__(self, client: httpx.Client, retries: int, backoff_seconds: float) -> None:
        self._client = client
        self._retries = retries
        self._backoff_seconds = backoff_seconds

    def get(self, url: str, **kwargs: Any) -> httpx.Response:
        """Execute a GET request with retry and backoff policy."""

        return self._request(lambda: self._client.get(url, **kwargs))

    def post(self, url: str, **kwargs: Any) -> httpx.Response:
        """Execute a POST request with retry and backoff policy."""

        return self._request(lambda: self._client.post(url, **kwargs))

    def close(self) -> None:
        """Close the underlying HTTP client."""

        self._client.close()

    def _request(self, operation: Callable[[], httpx.Response]) -> httpx.Response:
        last_error: Exception | None = None
        for attempt in range(self._retries + 1):
            try:
                response = operation()
                response.raise_for_status()
                return response
            except (httpx.HTTPError, httpx.TimeoutException) as exc:
                last_error = exc
                if attempt >= self._retries:
                    break
                time.sleep(self._backoff_seconds * (2**attempt))
        if last_error is None:
            raise RuntimeError("HTTP request failed without an exception")
        raise last_error


class HttpTransportFactory:
    """Factory that builds connector HTTP transports from OPSEC profiles."""

    def build(self, profile: OpsecProfile) -> RetryingHttpClient:
        """Create an HTTP client honoring proxy and user-agent settings."""

        proxy = profile.socks_proxy or profile.https_proxy or profile.http_proxy
        client = httpx.Client(
            headers={"User-Agent": profile.user_agent},
            proxy=proxy,
            timeout=30.0,
            follow_redirects=True,
        )
        return RetryingHttpClient(
            client=client,
            retries=profile.retries,
            backoff_seconds=profile.backoff_seconds,
        )
