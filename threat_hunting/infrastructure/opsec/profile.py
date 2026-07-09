"""OPSEC profile model.

Responsibility
--------------
Describe, as data, how a connector should reach the network: proxies, VPN hint,
User-Agent rotation, rate limit and retry/backoff policy, and a reference to
credentials resolved from the environment (never stored in the file). Profiles
are centralised in ``config/opsec.yml`` and selected per connector.
"""

from __future__ import annotations

import os

from pydantic import BaseModel, Field


class RateLimit(BaseModel):
    """Token-bucket style rate limit for a profile."""

    requests: int = Field(default=10, ge=1, description="Max requests per window.")
    per_seconds: float = Field(default=1.0, gt=0, description="Window length in seconds.")

    @property
    def min_interval(self) -> float:
        """Minimum seconds between two consecutive requests."""
        return self.per_seconds / self.requests


class OpsecProfile(BaseModel):
    """Per-connector operational-security transport configuration."""

    name: str = "default"
    http_proxy: str | None = None
    https_proxy: str | None = None
    socks5_proxy: str | None = Field(
        default=None, description="e.g. socks5://127.0.0.1:9050 for Tor."
    )
    vpn_hint: str | None = Field(
        default=None, description="Name of an externally-managed VPN this profile expects."
    )
    user_agents: list[str] = Field(
        default_factory=lambda: [
            "Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
        ]
    )
    rate_limit: RateLimit = Field(default_factory=RateLimit)
    timeout_seconds: float = Field(default=30.0, gt=0)
    max_retries: int = Field(default=3, ge=0)
    backoff_factor: float = Field(default=0.5, ge=0)
    verify_tls: bool = True
    credential_env: str | None = Field(
        default=None,
        description="Environment variable holding a secret/token for this profile.",
    )

    def resolve_credential(self) -> str | None:
        """Resolve the credential from the environment (never persisted in config)."""
        if not self.credential_env:
            return None
        return os.environ.get(self.credential_env)

    def proxies(self) -> dict[str, str]:
        """Build a proxy mapping suitable for httpx from the configured proxies."""
        mapping: dict[str, str] = {}
        if self.socks5_proxy:
            # SOCKS5 (e.g. Tor) applies to every scheme.
            mapping["all://"] = self.socks5_proxy
            return mapping
        if self.http_proxy:
            mapping["http://"] = self.http_proxy
        if self.https_proxy:
            mapping["https://"] = self.https_proxy
        return mapping
