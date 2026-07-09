"""Detection, scoring, correlation, and deduplication tests."""

from __future__ import annotations

from threat_hunting.core.domain.entities import Finding, Indicator, IndicatorType
from threat_hunting.core.domain.rules import DetectionRule, RuleType, ScoringProfile
from threat_hunting.correlation.engine import IndicatorCorrelationEngine
from threat_hunting.deduplication.engine import HashSimilarityDeduplicationEngine
from threat_hunting.detections.engine import ConfigurableDetectionEngine
from threat_hunting.scoring.engine import WeightedScoringEngine


def test_detection_rules_are_loaded_from_data() -> None:
    """Detection engine should match dynamic regex and keyword rules."""

    finding = Finding(
        title="Leak",
        description="VIP admin@acme.test password exposed",
        source="github",
        connector="github",
        category="code",
    )
    engine = ConfigurableDetectionEngine(
        [
            DetectionRule(name="password", type=RuleType.KEYWORD, values=["password"], tags=["credential"]),
            DetectionRule(name="email", type=RuleType.REGEX, pattern=r"admin@acme\.test", tags=["vip"]),
        ]
    )

    matches = engine.evaluate(finding)

    assert {match.rule_name for match in matches} == {"password", "email"}


def test_scoring_maps_weights_to_severity() -> None:
    """Scoring engine should use configurable weights and thresholds."""

    finding = Finding(
        title="Leak",
        description="credential",
        source="github",
        connector="github",
        category="code",
        indicators=[Indicator(type=IndicatorType.EMAIL, value="admin@acme.test")],
    )
    matches = ConfigurableDetectionEngine(
        [DetectionRule(name="credential", type=RuleType.KEYWORD, values=["credential"], weight=70, tags=["credential"])]
    ).evaluate(finding)

    scored = WeightedScoringEngine(ScoringProfile(weights={"keyword": 1.0, "sensitive_match": 5.0})).score(
        finding, matches
    )

    assert scored.score >= 75
    assert scored.severity.value == "high"
    assert scored.metadata["detections"][0]["rule_name"] == "credential"


def test_correlation_and_deduplication_use_shared_indicators() -> None:
    """Correlation should link related findings and dedup should reject repeats."""

    first = Finding(
        title="First",
        description="example",
        source="telegram",
        connector="telegram",
        category="social",
        indicators=[Indicator(type=IndicatorType.DOMAIN, value="acme.test")],
    )
    second = Finding(
        title="Second",
        description="different",
        source="github",
        connector="github",
        category="code",
        indicators=[Indicator(type=IndicatorType.DOMAIN, value="acme.test")],
    )

    correlated = IndicatorCorrelationEngine().correlate(second, [first])

    assert correlated.relationships[0].relationship_type == "shared_domain"
    assert HashSimilarityDeduplicationEngine().is_duplicate(second, [first])
