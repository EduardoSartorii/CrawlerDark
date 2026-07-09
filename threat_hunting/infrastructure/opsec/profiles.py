"""
OPSEC Profiles.

Defines per-connector security profiles controlling proxy, rate limiting,
and identity (user-agent) settings. All configuration is data — no hardcoded values.

Profile Resolution Order:
    1. Connector-specific profile (exact match by connector_id)
    2. Source-type profile (e.g., "dark_web")
    3. Default profile

Design Pattern: Strategy Pattern — each profile is a strategy configuration
"""

from __future__ import annotations

import random
from typing import Any

from pydantic import BaseModel, Field, SecretStr


class ProxyConfig(BaseModel):
    """Proxy configuration for a single proxy endpoint."""

    url: str = Field(..., description="Proxy URL (http://, https://, socks5://)")
    username: SecretStr | None = None
    password: SecretStr | None = None
    is_tor: bool = False
    country: str | None = None
    is_active: bool = True

    @property
    def proxy_url(self) -> str:
        """Full proxy URL with optional credentials."""
        if self.username and self.password:
            from urllib.parse import urlparse, urlunparse
            parsed = urlparse(self.url)
            netloc = (
                f"{self.username.get_secret_value()}"
                f":{self.password.get_secret_value()}"
                f"@{parsed.hostname}"
                + (f":{parsed.port}" if parsed.port else "")
            )
            return urlunparse(parsed._replace(netloc=netloc))
        return self.url


# Common user-agent pool for spoofing
_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.5; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0",
]


class RateLimitConfig(BaseModel):
    """Rate limiting configuration for a connector profile."""

    requests_per_minute: int = Field(default=30, ge=1)
    requests_per_hour: int = Field(default=500, ge=1)
    min_delay_seconds: float = Field(default=1.0, ge=0.0)
    max_delay_seconds: float = Field(default=5.0, ge=0.0)
    max_retries: int = Field(default=3, ge=0)
    backoff_factor: float = Field(default=2.0, ge=1.0)
    respect_retry_after: bool = True


class OpsecProfile(BaseModel):
    """
    Security profile for a connector.

    Controls all network-level security settings.
    Profiles are loaded from configuration (YAML/env) — never hardcoded.
    """

    profile_id: str
    proxies: list[ProxyConfig] = Field(default_factory=list)
    user_agents: list[str] = Field(default_factory=lambda: list(_USER_AGENTS))
    rate_limit: RateLimitConfig = Field(default_factory=RateLimitConfig)
    verify_ssl: bool = True
    timeout_seconds: int = 30
    follow_redirects: bool = True
    max_redirects: int = 10
    headers: dict[str, str] = Field(default_factory=dict)
    cookies: dict[str, str] = Field(default_factory=dict)
    use_tor: bool = False
    extra: dict[str, Any] = Field(default_factory=dict)

    def get_random_user_agent(self) -> str:
        """Pick a random user-agent from the pool."""
        return random.choice(self.user_agents) if self.user_agents else _USER_AGENTS[0]

    def get_active_proxy(self) -> ProxyConfig | None:
        """Get first active proxy, or None if no proxies configured."""
        active = [p for p in self.proxies if p.is_active]
        return random.choice(active) if active else None

    def get_proxy_dict(self) -> dict[str, str] | None:
        """Return httpx-compatible proxy dict or None."""
        proxy = self.get_active_proxy()
        if proxy is None:
            return None
        url = proxy.proxy_url
        return {"http://": url, "https://": url}

    @classmethod
    def default(cls) -> "OpsecProfile":
        """Default profile with no proxies and conservative rate limits."""
        return cls(profile_id="default")

    @classmethod
    def dark_web(cls, tor_proxy_url: str = "socks5://127.0.0.1:9050") -> "OpsecProfile":
        """Profile for dark web connectors — routes through Tor."""
        return cls(
            profile_id="dark_web",
            proxies=[ProxyConfig(url=tor_proxy_url, is_tor=True)],
            use_tor=True,
            verify_ssl=False,
            rate_limit=RateLimitConfig(
                requests_per_minute=5,
                requests_per_hour=100,
                min_delay_seconds=3.0,
                max_delay_seconds=10.0,
            ),
        )
