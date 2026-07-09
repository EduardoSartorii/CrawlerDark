"""
OpsecLayer — Centralized OPSEC Management
==========================================

Provides a unified interface for all OPSEC concerns:
    - Proxy selection (HTTP, HTTPS, SOCKS5)
    - User-Agent rotation
    - Rate limiting per connector
    - Retry/backoff management
    - Credential injection
    - TOR / VPN routing

Architecture:
    - The OpsecLayer is a cross-cutting concern, injected into connectors.
    - Connectors never manage their own sessions or proxies.
    - Each connector is assigned an OpsecProfile by name.
    - Profiles are defined in config/settings.yaml and loaded at startup.
    - No connector knows about the OPSEC implementation — only the interface.

Security design:
    - Credentials are never logged.
    - Proxy credentials are injected at the session level (not in URLs).
    - The OpsecLayer is the single point of control for all outbound traffic.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Any

import httpx

from threat_hunting.infrastructure.opsec.rate_limiter import RateLimiter


# A bank of realistic browser user-agents for rotation.
_USER_AGENT_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.0.0",
]


@dataclass
class OpsecProfile:
    """
    Named OPSEC configuration profile.

    Profiles are defined in config/settings.yaml (opsec.profiles.*).
    Each connector references one profile by name.
    """

    name: str
    proxy: str | None = None
    user_agent: str | None = None
    rotate_user_agent: bool = False
    timeout: int = 30
    max_retries: int = 3
    backoff_factor: float = 2.0
    verify_ssl: bool = True
    rate_limit_rps: float = 2.0
    extra_headers: dict[str, str] = field(default_factory=dict)

    @property
    def effective_user_agent(self) -> str:
        """Return a (possibly rotated) User-Agent string."""
        if self.rotate_user_agent or not self.user_agent:
            return random.choice(_USER_AGENT_POOL)  # noqa: S311
        return self.user_agent

    @property
    def httpx_timeout(self) -> httpx.Timeout:
        return httpx.Timeout(
            connect=min(self.timeout, 10),
            read=self.timeout,
            write=self.timeout,
            pool=5.0,
        )

    @property
    def httpx_transport(self) -> httpx.AsyncHTTPTransport | None:
        """Return an httpx transport with proxy if configured."""
        if not self.proxy:
            return None
        return httpx.AsyncHTTPTransport(proxy=self.proxy)


class OpsecLayer:
    """
    Central OPSEC management layer.

    Instantiated once at startup and injected into all connectors.
    Manages profiles, rate limiters, and session factories.
    """

    def __init__(self, profiles: dict[str, OpsecProfile]) -> None:
        self._profiles = profiles
        self._rate_limiters: dict[str, RateLimiter] = {
            name: RateLimiter(profile.rate_limit_rps)
            for name, profile in profiles.items()
        }

    @classmethod
    def from_config(cls, opsec_config: dict[str, Any]) -> "OpsecLayer":
        """Factory: build OpsecLayer from the 'opsec' section of settings.yaml."""
        profiles: dict[str, OpsecProfile] = {}
        for name, cfg in opsec_config.get("profiles", {}).items():
            profiles[name] = OpsecProfile(
                name=name,
                proxy=cfg.get("proxy"),
                user_agent=cfg.get("user_agent"),
                rotate_user_agent=cfg.get("rotate_user_agent", False),
                timeout=cfg.get("timeout", 30),
                max_retries=cfg.get("max_retries", 3),
                backoff_factor=cfg.get("backoff_factor", 2.0),
                verify_ssl=cfg.get("verify_ssl", True),
                rate_limit_rps=cfg.get("rate_limit_rps", 2.0),
                extra_headers=cfg.get("extra_headers", {}),
            )
        if not profiles:
            profiles["standard"] = OpsecProfile(name="standard")
        return cls(profiles)

    def get_profile(self, name: str = "standard") -> OpsecProfile:
        """Return a named OPSEC profile, falling back to 'standard'."""
        return self._profiles.get(name, self._profiles.get("standard", OpsecProfile(name="standard")))

    def get_rate_limiter(self, profile_name: str = "standard") -> RateLimiter:
        """Return the rate limiter for a given profile."""
        return self._rate_limiters.get(
            profile_name, self._rate_limiters.get("standard", RateLimiter(2.0))
        )

    def build_session(self, profile_name: str = "standard") -> httpx.AsyncClient:
        """
        Build an httpx.AsyncClient configured with the named OPSEC profile.

        The caller is responsible for closing the session (use as async context manager).

        Args:
            profile_name: Name of the OPSEC profile to apply.

        Returns:
            Configured httpx.AsyncClient.
        """
        profile = self.get_profile(profile_name)
        headers = {
            "User-Agent": profile.effective_user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            **profile.extra_headers,
        }

        transport = profile.httpx_transport
        kwargs: dict[str, Any] = {
            "headers": headers,
            "timeout": profile.httpx_timeout,
            "verify": profile.verify_ssl,
            "follow_redirects": True,
        }
        if transport:
            kwargs["transport"] = transport

        return httpx.AsyncClient(**kwargs)

    async def throttle(self, profile_name: str = "standard") -> None:
        """Apply rate limiting for the given profile before an HTTP request."""
        await self.get_rate_limiter(profile_name).acquire()
