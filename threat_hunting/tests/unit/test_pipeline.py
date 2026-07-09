"""Unit tests for pipeline and event bus."""

import pytest

from threat_hunting.core.domain.events import FindingDetected, ConnectorExecuted
from threat_hunting.infrastructure.pipelines.event_bus import InProcessEventBus


@pytest.mark.asyncio
async def test_event_bus_publish():
    bus = InProcessEventBus()
    received = []

    async def handler(event):
        received.append(event)

    bus.subscribe("finding.detected", handler)

    from threat_hunting.core.domain.entities import Finding
    from threat_hunting.core.domain.enums import SourceType

    finding = Finding(title="Test", source=SourceType.API, connector="test")
    await bus.publish(FindingDetected(finding=finding))

    assert len(received) == 1
    assert received[0].finding.title == "Test"


@pytest.mark.asyncio
async def test_event_bus_wildcard():
    bus = InProcessEventBus()
    received = []

    async def handler(event):
        received.append(event)

    bus.subscribe("*", handler)
    await bus.publish(ConnectorExecuted(connector="reddit", findings_count=5, duration_seconds=1.0))
    assert len(received) == 1
