"""Unit tests for the OPSEC rate limiter, transport factory and event bus."""

from __future__ import annotations

import time

import pytest

from threat_hunting.core.domain.entities import Finding
from threat_hunting.core.domain.events import FindingPersisted, FindingScored
from threat_hunting.infrastructure.config.settings import PlatformSettings
from threat_hunting.infrastructure.events.in_memory_bus import InMemoryEventBus
from threat_hunting.infrastructure.opsec.rate_limiter import RateLimiter
from threat_hunting.infrastructure.opsec.transport import TransportFactory


async def test_rate_limiter_throttles() -> None:
    limiter = RateLimiter(rate_per_second=10, capacity=1)
    start = time.monotonic()
    for _ in range(3):
        await limiter.acquire()
    assert time.monotonic() - start >= 0.15


async def test_rate_limiter_disabled_is_noop() -> None:
    limiter = RateLimiter(rate_per_second=0)
    await limiter.acquire()  # must not block


def test_transport_factory_builds_for_profile() -> None:
    settings = PlatformSettings()
    transport = TransportFactory(settings).for_profile("default")
    assert transport.profile == "default"


def test_event_bus_dispatches_by_type_and_isolates_failures() -> None:
    bus = InMemoryEventBus()
    received: list[str] = []

    def good(event) -> None:
        received.append(event.name)

    def bad(event) -> None:
        raise RuntimeError("boom")

    bus.subscribe(FindingScored, bad)
    bus.subscribe(FindingScored, good)
    finding = Finding(title="t", source="s", connector="c")
    bus.publish(FindingScored(finding=finding))
    bus.publish(FindingPersisted(finding=finding))  # no subscriber -> ignored
    assert received == ["FindingScored"]
