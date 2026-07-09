"""Unit tests for scoring, deduplication and correlation engines."""

from __future__ import annotations

from threat_hunting.core.domain.entities.finding import FindingBuilder
from threat_hunting.core.domain.enums import IndicatorType, Severity
from threat_hunting.core.domain.value_objects.indicator import Indicator
from threat_hunting.core.domain.value_objects.score import DetectionMatch
from threat_hunting.infrastructure.correlation.engine import CorrelationEngine
from threat_hunting.infrastructure.deduplication.engine import DeduplicationEngine
from threat_hunting.infrastructure.normalizers.finding_normalizer import FindingNormalizer
from threat_hunting.infrastructure.scoring.engine import ScoringEngine
from threat_hunting.infrastructure.scoring.weights import ScoringWeights


def _finding(title, text, indicators=()):
    builder = FindingBuilder(title, "c", "s").description(text)
    for ind in indicators:
        builder.add_indicator(ind)
    finding = builder.build()
    return FindingNormalizer().normalize(finding)


def test_scoring_uses_detection_and_ioc_quantity():
    finding = _finding("t", "x", [Indicator(type=IndicatorType.IPV4, value="1.1.1.1")])
    finding.add_detection(DetectionMatch(rule_id="r", rule_type="keyword", matched="x", weight=40))
    engine = ScoringEngine(ScoringWeights())
    score = engine.score(finding)
    assert score.value > 40
    assert "ioc_quantity" in score.breakdown
    assert finding.severity in (Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL)


def test_scoring_source_reputation_multiplier():
    finding = _finding("t", "x")
    finding.metadata["source_type"] = "dark_web"
    finding.add_detection(DetectionMatch(rule_id="r", rule_type="ioc", matched="x", weight=40))
    score = ScoringEngine().score(finding)
    assert "source_reputation" in score.breakdown


def test_scoring_recurrence_bonus():
    finding = _finding("t", "x")
    finding.add_detection(DetectionMatch(rule_id="r", rule_type="ioc", matched="x", weight=10))
    score = ScoringEngine().score(finding, recurrence=True)
    assert score.breakdown.get("recurrence") == ScoringWeights().recurrence_bonus


def test_dedup_removes_exact_duplicates():
    a = _finding("same", "identical content here")
    b = _finding("same", "identical content here")
    unique, removed = DeduplicationEngine().deduplicate([a, b])
    assert len(unique) == 1
    assert removed == 1


def test_dedup_merges_by_shared_indicators():
    ind = Indicator(type=IndicatorType.IPV4, value="9.9.9.9")
    a = _finding("a", "alpha text one", [ind])
    b = _finding("b", "beta text two totally different", [ind])
    unique, removed = DeduplicationEngine().deduplicate([a, b])
    assert removed == 1
    assert "9.9.9.9" in " ".join(k for f in unique for k in f.indicator_keys)


def test_dedup_cross_run_known_fingerprints():
    a = _finding("x", "seen before content")
    engine = DeduplicationEngine()
    engine.deduplicate([a])
    unique, removed = engine.deduplicate([_finding("x", "seen before content")])
    assert unique == []
    assert removed == 1


def test_correlation_builds_campaign():
    ind = Indicator(type=IndicatorType.DOMAIN, value="shared.com")
    a = _finding("a", "text a", [ind])
    b = _finding("b", "text b", [ind])
    campaigns = CorrelationEngine().correlate([a, b])
    assert len(campaigns) == 1
    assert len(campaigns[0].finding_ids) == 2
    assert a.relationships  # shared_indicator relationship added
