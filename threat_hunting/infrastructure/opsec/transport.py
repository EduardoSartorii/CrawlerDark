"""OPSEC transport adapter.

Provides profile-based proxy, user-agent, retry, and timeout policies.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

import httpx

from threat_hunting.core.contracts import TransportPort


@dataclass(slots=True)
class OPSECProfile:
    """Network profile for connectors."""

    name: str
    proxy_http: str | None = None
    proxy_https: str | None = None
    proxy_socks5: str | None = None
    user_agent: str = "ThreatHuntingPlatform/1.0"
    rate_limit_per_second: float = 2.0
    retries: int = 3
    backoff_seconds: float = 1.0
    timeout_seconds: float = 30.0


class OPSECTransport(TransportPort):
    """HTTP transport enforcing OPSEC policies per profile."""

    def __init__(self, profiles: dict[str, OPSECProfile], default_profile: str = "default") -> None:
        self._profiles = profiles
        self._default_profile = default_profile
        self._last_request_ts: dict[str, float] = {}

    def get(self, url: str, *, profile: str | None = None, headers: dict[str, str] | None = None) -> Any:
        return self._request("GET", url, profile=profile, headers=headers)

    def post(
        self,
        url: str,
        *,
        profile: str | None = None,
        headers: dict[str, str] | None = None,
        json_payload: dict[str, Any] | None = None,
    ) -> Any:
        return self._request("POST", url, profile=profile, headers=headers, json_payload=json_payload)

    def _request(
        self,
        method: str,
        url: str,
        *,
        profile: str | None = None,
        headers: dict[str, str] | None = None,
        json_payload: dict[str, Any] | None = None,
    ) -> httpx.Response:
        selected = self._profiles.get(profile or self._default_profile) or OPSECProfile(name="fallback")
        self._rate_limit(selected)
        request_headers = {"User-Agent": selected.user_agent, **(headers or {})}
        retries = max(1, selected.retries)
        for attempt in range(retries):
            try:
                proxies = self._build_proxies(selected)
                with httpx.Client(timeout=selected.timeout_seconds, proxy=proxies) as client:
                    response = client.request(method, url, headers=request_headers, json=json_payload)
                    response.raise_for_status()
                    return response
            except Exception:
                if attempt >= retries - 1:
                    raise
                sleep_seconds = selected.backoff_seconds * (2**attempt)
                time.sleep(sleep_seconds)
        msg = "Unexpected OPSEC transport error"
        raise RuntimeError(msg)

    def _rate_limit(self, profile: OPSECProfile) -> None:
        now = time.time()
        interval = 1.0 / max(0.1, profile.rate_limit_per_second)
        last_call = self._last_request_ts.get(profile.name, 0.0)
        wait_for = interval - (now - last_call)
        if wait_for > 0:
            time.sleep(wait_for)
        self._last_request_ts[profile.name] = time.time()

    def _build_proxies(self, profile: OPSECProfile) -> str | None:
        if profile.proxy_socks5:
            return profile.proxy_socks5
        if profile.proxy_https:
            return profile.proxy_https
        if profile.proxy_http:
            return profile.proxy_http
        return None
