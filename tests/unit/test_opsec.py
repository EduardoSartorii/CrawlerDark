"""Unit tests for the OPSEC layer."""

from __future__ import annotations

import pytest

from threat_hunting.core.application.ports.transport import TransportResponse
from threat_hunting.core.domain.exceptions import OpsecError
from threat_hunting.infrastructure.opsec.manager import OpsecManager
from threat_hunting.infrastructure.opsec.profile import OpsecProfile, RateLimit
from threat_hunting.infrastructure.opsec.transport import (
    HttpxTransport,
    OfflineTransport,
    RateLimiter,
)


def test_profile_proxies_socks5_takes_precedence():
    profile = OpsecProfile(
        socks5_proxy="socks5://127.0.0.1:9050", http_proxy="http://p:8080"
    )
    assert profile.proxies() == {"all://": "socks5://127.0.0.1:9050"}


def test_profile_http_https_proxies():
    profile = OpsecProfile(http_proxy="http://p:8080", https_proxy="http://p:8443")
    assert profile.proxies() == {"http://": "http://p:8080", "https://": "http://p:8443"}


def test_profile_credential_from_env(monkeypatch):
    monkeypatch.setenv("MY_TOKEN", "s3cret")
    profile = OpsecProfile(credential_env="MY_TOKEN")
    assert profile.resolve_credential() == "s3cret"
    assert OpsecProfile().resolve_credential() is None


def test_rate_limit_min_interval():
    assert RateLimit(requests=4, per_seconds=2.0).min_interval == 0.5


def test_rate_limiter_sleeps_between_calls():
    slept: list[float] = []
    clock = iter([0.0, 0.1])
    limiter = RateLimiter(1.0, clock=lambda: next(clock), sleep=slept.append)
    limiter.wait()
    limiter.wait()
    assert slept and slept[0] == pytest.approx(0.9)


def test_manager_selects_profile_and_offline_transport():
    manager = OpsecManager(
        profiles={"tor": OpsecProfile(name="tor", socks5_proxy="socks5://127.0.0.1:9050")},
        connector_profiles={"darkweb": "tor"},
        offline=True,
    )
    assert manager.profile_for("darkweb").name == "tor"
    transport = manager.transport_for("darkweb")
    assert isinstance(transport, OfflineTransport)
    assert transport.get("http://x").status_code == 503


class _FakeResponse:
    def __init__(self, status_code=200):
        self.status_code = status_code
        self.text = "ok"
        self.headers = {"h": "v"}
        self.url = "http://x"


class _FakeClient:
    def __init__(self, fail_times=0):
        self._fail_times = fail_times
        self.calls = 0

    def request(self, method, url, **kwargs):
        self.calls += 1
        if self.calls <= self._fail_times:
            raise ConnectionError("boom")
        return _FakeResponse()


def test_httpx_transport_retries_then_succeeds():
    client = _FakeClient(fail_times=1)
    profile = OpsecProfile(max_retries=3, backoff_factor=0.0)
    transport = HttpxTransport(profile, client=client)
    response = transport.get("http://x")
    assert isinstance(response, TransportResponse)
    assert response.ok
    assert client.calls == 2


def test_httpx_transport_raises_after_exhausting_retries():
    client = _FakeClient(fail_times=10)
    profile = OpsecProfile(max_retries=1, backoff_factor=0.0)
    transport = HttpxTransport(profile, client=client)
    with pytest.raises(OpsecError):
        transport.get("http://x")
