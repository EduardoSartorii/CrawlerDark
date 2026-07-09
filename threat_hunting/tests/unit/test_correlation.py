"""Unit tests for correlation engine."""

import pytest

from threat_hunting.core.domain.entities import Finding, Indicator
from threat_hunting.core.domain.enums import IndicatorType, SourceType
from threat_hunting.infrastructure.correlation.engine import CorrelationEngine


class MockFindingRepo:
    def __init__(self, findings):
        self._findings = findings

    async def list_all(self, limit=500, offset=0):
        return self._findings


class MockCorrelationRepo:
    def __init__(self):
        self.saved = []

    async def save(self, link):
        self.saved.append(link)
        return link

    async def find_by_source(self, sid):
        return []

    async def find_by_target(self, tid):
        return []


@pytest.mark.asyncio
async def test_correlation_shared_ioc():
    f1 = Finding(
        title="A", source=SourceType.API, connector="test",
        indicators=[Indicator(type=IndicatorType.IP, value="1.2.3.4")],
    )
    f2 = Finding(
        title="B", source=SourceType.DARKWEB, connector="darkweb",
        indicators=[Indicator(type=IndicatorType.IP, value="1.2.3.4")],
    )
    engine = CorrelationEngine(MockCorrelationRepo(), MockFindingRepo([f1, f2]))
    result, links = await engine.correlate(f1)
    assert len(links) >= 1
