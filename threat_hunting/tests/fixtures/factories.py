"""
Test Factories.

Provides factory functions and factory_boy factories for creating
domain entities in tests. Avoids duplicating test setup code.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from ...core.domain.entities.finding import Finding, FindingStatus
from ...core.domain.entities.indicator import Indicator, IndicatorType
from ...core.domain.entities.rule import DetectionRule, RuleType, RuleAction
from ...core.domain.entities.keyword import Keyword, KeywordType, KeywordCategory
from ...core.domain.entities.threat_actor import ThreatActor, ActorType
from ...core.domain.value_objects import Score, Severity, ThreatCategory
from ...core.domain.value_objects.severity import SeverityLevel
from ...core.domain.value_objects.source_type import SourceType


def make_finding(
    title: str = "Test Finding",
    source: str = "test-source",
    connector: str = "test",
    category: ThreatCategory = ThreatCategory.MALWARE,
    source_type: SourceType = SourceType.SOCIAL_MEDIA,
    score_value: float = 5.0,
    confidence: float = 0.7,
    raw_data: str = "test raw data",
    tags: list[str] | None = None,
    **kwargs,
) -> Finding:
    """Create a test Finding with sensible defaults."""
    finding = Finding.create(
        title=title,
        source=source,
        connector=connector,
        category=category,
        source_type=source_type,
        raw_data=raw_data,
        tags=tags or ["test"],
        **kwargs,
    )
    finding.apply_score(Score(value=score_value, confidence=confidence))
    return finding


def make_indicator(
    value: str = "192.168.1.1",
    ioc_type: IndicatorType = IndicatorType.IP_V4,
    confidence: float = 0.8,
    source: str = "test",
) -> Indicator:
    """Create a test Indicator."""
    return Indicator(
        value=value,
        ioc_type=ioc_type,
        confidence=confidence,
        source=source,
    )


def make_detection_rule(
    name: str = "Test Rule",
    rule_type: RuleType = RuleType.REGEX,
    pattern: str = r"test_pattern",
    score_boost: float = 2.0,
    is_active: bool = True,
) -> DetectionRule:
    """Create a test DetectionRule."""
    return DetectionRule(
        name=name,
        rule_type=rule_type,
        pattern=pattern,
        score_boost=score_boost,
        action=RuleAction.BOOST_SCORE,
        is_active=is_active,
    )


def make_keyword(
    value: str = "test_keyword",
    keyword_type: KeywordType = KeywordType.EXACT,
    category: KeywordCategory = KeywordCategory.BRAND,
    weight: float = 1.5,
) -> Keyword:
    """Create a test Keyword."""
    return Keyword(
        value=value,
        keyword_type=keyword_type,
        category=category,
        weight=weight,
    )


def make_threat_actor(
    name: str = "TestAPT",
    actor_type: ActorType = ActorType.APT,
    aliases: list[str] | None = None,
) -> ThreatActor:
    """Create a test ThreatActor."""
    return ThreatActor(
        name=name,
        actor_type=actor_type,
        aliases=aliases or ["TestGroup42"],
        confidence=0.9,
    )
