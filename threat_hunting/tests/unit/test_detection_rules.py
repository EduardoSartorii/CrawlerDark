"""Unit tests for detection engine rule types."""

import pytest

from threat_hunting.core.domain.entities import DetectionRule, Finding, Indicator
from threat_hunting.core.domain.enums import IndicatorType, Severity, SourceType
from threat_hunting.infrastructure.detections.engine import DetectionEngine
from threat_hunting.tests.conftest import InMemoryRuleRepo, InMemoryWatchlistRepo


@pytest.mark.asyncio
async def test_regex_rule():
    engine = DetectionEngine(
        InMemoryRuleRepo([DetectionRule(
            name="card", rule_type="regex", pattern=r"\d{4}-\d{4}-\d{4}-\d{4}",
            severity=Severity.CRITICAL,
        )]),
        InMemoryWatchlistRepo(),
    )
    finding = Finding(
        title="Card", description="4111-1111-1111-1111",
        source=SourceType.DARKWEB, connector="test",
    )
    result, matched = await engine.detect(finding)
    assert "card" in matched


@pytest.mark.asyncio
async def test_ioc_match_rule():
    engine = DetectionEngine(
        InMemoryRuleRepo([DetectionRule(
            name="ioc", rule_type="ioc_match", pattern="1.2.3.4",
        )]),
        InMemoryWatchlistRepo(),
    )
    finding = Finding(
        title="IOC", source=SourceType.API, connector="test",
        indicators=[Indicator(type=IndicatorType.IP, value="1.2.3.4")],
    )
    result, matched = await engine.detect(finding)
    assert "ioc" in matched


@pytest.mark.asyncio
async def test_blacklist_rule():
    engine = DetectionEngine(
        InMemoryRuleRepo([DetectionRule(
            name="bl", rule_type="blacklist", pattern="malware",
        )]),
        InMemoryWatchlistRepo(),
    )
    finding = Finding(
        title="Bad", description="contains malware",
        source=SourceType.API, connector="test",
    )
    _, matched = await engine.detect(finding)
    assert "bl" in matched


@pytest.mark.asyncio
async def test_heuristic_rule():
    engine = DetectionEngine(
        InMemoryRuleRepo([DetectionRule(
            name="heur", rule_type="heuristic", pattern="",
            metadata={"min_indicators": 2},
        )]),
        InMemoryWatchlistRepo(),
    )
    finding = Finding(
        title="Many IOCs", source=SourceType.API, connector="test",
        indicators=[
            Indicator(type=IndicatorType.IP, value="1.1.1.1"),
            Indicator(type=IndicatorType.IP, value="2.2.2.2"),
        ],
    )
    _, matched = await engine.detect(finding)
    assert "heur" in matched


@pytest.mark.asyncio
async def test_composite_rule():
    engine = DetectionEngine(
        InMemoryRuleRepo([DetectionRule(
            name="comp", rule_type="composite", pattern="",
            metadata={"conditions": ["leak", "password"], "operator": "and"},
        )]),
        InMemoryWatchlistRepo(),
    )
    finding = Finding(
        title="Composite", description="password leak detected",
        source=SourceType.DARKWEB, connector="test",
    )
    _, matched = await engine.detect(finding)
    assert "comp" in matched
