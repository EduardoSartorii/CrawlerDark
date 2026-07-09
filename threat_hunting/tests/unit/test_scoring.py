"""Unit tests for scoring engine."""

import pytest

from threat_hunting.core.domain.entities import Finding, Indicator
from threat_hunting.core.domain.enums import IndicatorType, Severity, SourceType


@pytest.mark.asyncio
async def test_scoring_with_indicators(scoring_engine):
    finding = Finding(
        title="IOC finding",
        description="multiple indicators",
        source=SourceType.DARKWEB,
        connector="darkweb",
        indicators=[
            Indicator(type=IndicatorType.IP, value="1.2.3.4"),
            Indicator(type=IndicatorType.EMAIL, value="test@example.com"),
        ],
    )
    result = await scoring_engine.score(finding)
    assert result.score > 0
    assert result.confidence > 0


@pytest.mark.asyncio
async def test_scoring_credential_keywords(scoring_engine):
    finding = Finding(
        title="Leak",
        description="password leak credentials exposed",
        source=SourceType.DARKWEB,
        connector="darkweb",
    )
    result = await scoring_engine.score(finding)
    assert result.score >= 20.0
