"""Unit tests for OPSEC transport."""

import pytest

from threat_hunting.infrastructure.opsec.transport import (
    CredentialVault,
    OpsecProfile,
    OpsecTransport,
    RateLimiter,
    RateLimitConfig,
)


def test_credential_vault():
    vault = CredentialVault()
    vault.store("github", {"api_key": "secret123"})
    assert vault.get("github")["api_key"] == "secret123"
    vault.delete("github")
    assert vault.get("github") == {}


@pytest.mark.asyncio
async def test_rate_limiter():
    limiter = RateLimiter(RateLimitConfig(requests_per_second=100.0, burst=10))
    await limiter.acquire()
    await limiter.acquire()


def test_opsec_profile_defaults():
    profile = OpsecProfile(name="test")
    assert profile.user_agent == "ThreatHuntingPlatform/1.0"
    assert profile.rate_limit.requests_per_second == 2.0
