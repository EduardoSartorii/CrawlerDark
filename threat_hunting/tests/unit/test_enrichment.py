"""Unit tests for enrichment engine."""

import pytest

from threat_hunting.core.domain.entities import Finding, Indicator
from threat_hunting.core.domain.enums import IndicatorType, SourceType
from threat_hunting.infrastructure.enrichment.engine import EnrichmentEngine


@pytest.mark.asyncio
async def test_enrichment_local():
    engine = EnrichmentEngine()
    finding = Finding(
        title="Test",
        source=SourceType.API,
        connector="test",
        indicators=[Indicator(type=IndicatorType.IP, value="8.8.8.8")],
    )
    result = await engine.enrich(finding)
    assert "enrichment" in result.metadata
    assert "8.8.8.8" in result.metadata["enrichment"]
