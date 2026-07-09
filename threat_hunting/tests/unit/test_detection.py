"""Unit tests for detection engine."""

import pytest

from threat_hunting.core.domain.entities import Finding, Indicator
from threat_hunting.core.domain.enums import IndicatorType, Severity, SourceType


@pytest.mark.asyncio
async def test_keyword_detection(detection_engine):
    finding = Finding(
        title="Alert",
        description="password leak in database",
        source=SourceType.DARKWEB,
        connector="darkweb",
    )
    result, matched = await detection_engine.detect(finding)
    assert "leak_kw" in matched
    assert result.severity == Severity.HIGH


@pytest.mark.asyncio
async def test_no_match(detection_engine):
    finding = Finding(
        title="Normal post",
        description="nothing suspicious here",
        source=SourceType.SOCIAL,
        connector="reddit",
    )
    result, matched = await detection_engine.detect(finding)
    assert len(matched) == 0
