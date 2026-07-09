"""Independent OPSEC transport layer for connector network operations."""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass
from typing import Any

import httpx

from threat_hunting.core.contracts import CredentialProviderPort, OpsecTransportPort
from threat_hunting.infrastructure.config import OpsecProfileConfig


@dataclass(slots=True)
class InMemoryCredentialProvider(CredentialProviderPort):
    """Simple credential provider for local development/testing."""

    secrets: dict[str, str]

    def get_secret(self, name: str) -> str:
        return self.secrets[name]


class OpsecTransport(OpsecTransportPort):
    """HTTP transport with profile-driven proxy/retry/rate-limit controls."""

    def __init__(
        self,
        profiles: dict[str, OpsecProfileConfig],
        credential_provider: CredentialProviderPort | None = None,
    ) -> None:
        self._profiles = profiles
        self._credential_provider = credential_provider
        self._request_counter: dict[str, int] = defaultdict(int)

    def get(self, url: str, profile_name: str, **kwargs: Any) -> httpx.Response:
        """Send GET request through OPSEC profile policies."""
        profile = self._profiles[profile_name]
        self._enforce_rate_limit(profile)
        proxies = self._build_proxies(profile)
        headers = dict(kwargs.pop("headers", {}))
        headers.setdefault("User-Agent", profile.user_agent)
        timeout = kwargs.pop("timeout", 20.0)

        last_error: Exception | None = None
        for attempt in range(profile.retries):
            try:
                with httpx.Client(
                    proxy=proxies.get("https://") or proxies.get("http://"),
                    verify=profile.verify_tls,
                    timeout=timeout,
                ) as client:
                    response = client.get(url, headers=headers, **kwargs)
                    response.raise_for_status()
                    return response
            except Exception as exc:  # noqa: BLE001
                last_error = exc
                sleep_time = profile.backoff_seconds * (attempt + 1)
                time.sleep(sleep_time)
        assert last_error is not None
        raise last_error

    def _build_proxies(self, profile: OpsecProfileConfig) -> dict[str, str]:
        proxies: dict[str, str] = {}
        if profile.http_proxy:
            proxies["http://"] = profile.http_proxy
        if profile.https_proxy:
            proxies["https://"] = profile.https_proxy
        if profile.socks5_proxy:
            proxies["http://"] = profile.socks5_proxy
            proxies["https://"] = profile.socks5_proxy
        return proxies

    def _enforce_rate_limit(self, profile: OpsecProfileConfig) -> None:
        key = profile.name
        self._request_counter[key] += 1
        modulo = profile.rate_limit_per_minute
        if modulo > 0 and self._request_counter[key] % modulo == 0:
            time.sleep(60.0 / modulo)
