"""Tests for health checks, metrics fallback and transport retry/backoff."""

from __future__ import annotations

import httpx
import pytest

from threat_hunting.infrastructure.config.settings import OpsecProfile, PlatformSettings
from threat_hunting.infrastructure.connectors.registry import ConnectorRegistry
from threat_hunting.infrastructure.observability.health import HealthChecker
from threat_hunting.infrastructure.observability.metrics import Metrics
from threat_hunting.infrastructure.opsec.transport import HttpxTransport


def test_metrics_noop_when_disabled() -> None:
    metrics = Metrics(enabled=False)
    # Must accept the full fluent API without raising.
    metrics.findings_total.labels("c", "high").inc()
    metrics.exports_total.labels("misp").inc()
    metrics.pipeline_duration.labels("c").observe(0.1)
    metrics.serve(0)  # no-op


async def test_health_checker_reports_connectors() -> None:
    settings = PlatformSettings()
    registry = ConnectorRegistry(settings=settings).discover()
    report = await HealthChecker(registry).check()
    assert "sample" in report.connectors
    assert report.healthy is True


async def test_transport_retries_then_succeeds(monkeypatch) -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] < 3:
            raise httpx.ConnectError("boom", request=request)
        return httpx.Response(200, text="ok")

    profile = OpsecProfile(max_retries=3, backoff_factor=0.0, rate_limit_per_second=0)
    transport = HttpxTransport("test", profile)
    # Swap the real client for one backed by a controllable mock transport.
    transport._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))

    response = await transport.get("http://example.test")
    assert response.ok is True
    assert calls["n"] == 3
    await transport.aclose()


async def test_transport_raises_after_exhausting_retries() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("down", request=request)

    profile = OpsecProfile(max_retries=1, backoff_factor=0.0, rate_limit_per_second=0)
    transport = HttpxTransport("test", profile)
    transport._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    with pytest.raises(httpx.HTTPError):
        await transport.post("http://example.test", json={"a": 1})
    await transport.aclose()
