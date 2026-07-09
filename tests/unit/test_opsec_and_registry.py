"""Testes das camadas OPSEC e do ConnectorRegistry."""

from __future__ import annotations

import asyncio
import time

import pytest

from threat_hunting.core.domain.exceptions import ConnectorNotFoundError
from threat_hunting.infrastructure.connectors import ConnectorRegistry, register_connector
from threat_hunting.infrastructure.connectors.base import BaseConnector
from threat_hunting.infrastructure.opsec import AsyncRateLimiter, EnvCredentials


class TestAsyncRateLimiter:
    async def test_limits_calls_to_configured_rate(self):
        limiter = AsyncRateLimiter(rate_per_second=10)  # 100ms interval
        start = time.perf_counter()
        for _ in range(3):
            await limiter.acquire()
        elapsed = time.perf_counter() - start
        # 3 calls at 10/s → ~200ms mínimo
        assert elapsed >= 0.15


class TestConnectorRegistry:
    def test_discover_registers_reference_connectors(self):
        ConnectorRegistry.discover()
        names = ConnectorRegistry.names()
        for expected in ["rss", "threatfox", "urlhaus", "github", "reddit", "generic_http"]:
            assert expected in names

    def test_get_missing_raises(self):
        with pytest.raises(ConnectorNotFoundError):
            ConnectorRegistry.get("does-not-exist-xyz")

    def test_register_conflicting_class_raises(self):
        class A(BaseConnector):
            async def collect(self):
                if False:
                    yield  # pragma: no cover
            async def parse(self, payload): return {}
            async def normalize(self, parsed): raise NotImplementedError

        class B(BaseConnector):
            async def collect(self):
                if False:
                    yield  # pragma: no cover
            async def parse(self, payload): return {}
            async def normalize(self, parsed): raise NotImplementedError

        ConnectorRegistry.register("__conflict_test__", A)
        with pytest.raises(ValueError):
            ConnectorRegistry.register("__conflict_test__", B)
        # cleanup
        del ConnectorRegistry._registry["__conflict_test__"]  # type: ignore[attr-defined]


class TestEnvCredentials:
    def test_require_missing_raises(self, monkeypatch):
        monkeypatch.delenv("__NONE_HERE__", raising=False)
        with pytest.raises(KeyError):
            EnvCredentials().require("__NONE_HERE__")

    def test_get_default(self):
        assert EnvCredentials().get("__NONE_HERE__", "fallback") == "fallback"
