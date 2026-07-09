"""
Unit tests for domain value objects.

Tests cover immutability, factory methods, comparison operators,
and business rules embedded in value objects.
"""

from __future__ import annotations

import pytest

from ....core.domain.value_objects import Score, Severity, ThreatCategory
from ....core.domain.value_objects.severity import SeverityLevel
from ....core.domain.value_objects.source_type import SourceType


class TestScore:
    """Tests for Score value object."""

    def test_score_clamps_to_max(self):
        s = Score(value=15.0, confidence=1.0)
        assert s.value == 10.0

    def test_score_clamps_to_min(self):
        s = Score(value=-5.0, confidence=1.0)
        assert s.value == 0.0

    def test_confidence_clamps_to_1(self):
        s = Score(value=5.0, confidence=2.0)
        assert s.confidence == 1.0

    def test_adjusted_score(self):
        s = Score(value=8.0, confidence=0.5)
        assert s.adjusted == pytest.approx(4.0)

    def test_zero_factory(self):
        s = Score.zero()
        assert s.value == 0.0
        assert s.confidence == 0.0
        assert s.adjusted == 0.0

    def test_maximum_factory(self):
        s = Score.maximum()
        assert s.value == 10.0
        assert s.adjusted == 10.0

    def test_boost_creates_new_score(self):
        s = Score(value=5.0, confidence=1.0)
        s2 = s.boost(2.0)
        assert s2.value == 7.0
        assert s.value == 5.0  # Original unchanged

    def test_boost_caps_at_10(self):
        s = Score(value=9.0, confidence=1.0)
        s2 = s.boost(5.0)
        assert s2.value == 10.0

    def test_penalize_creates_new_score(self):
        s = Score(value=5.0, confidence=1.0)
        s2 = s.penalize(2.0)
        assert s2.value == 3.0

    def test_comparison_operators(self):
        low = Score(value=3.0, confidence=1.0)
        high = Score(value=8.0, confidence=1.0)
        assert low < high
        assert high > low
        assert low <= low

    def test_combine_weighted_avg(self):
        scores = [
            Score(value=6.0, confidence=0.8),
            Score(value=4.0, confidence=0.4),
        ]
        combined = Score.combine(scores)
        assert 4.0 < combined.value < 6.0

    def test_combine_max_strategy(self):
        scores = [Score(value=3.0, confidence=1.0), Score(value=8.0, confidence=1.0)]
        combined = Score.combine(scores, strategy="max")
        assert combined.value == 8.0

    def test_is_above_threshold(self):
        assert Score(value=6.0, confidence=1.0).is_above_threshold is True
        assert Score(value=4.0, confidence=0.5).is_above_threshold is False


class TestSeverity:
    """Tests for Severity value object."""

    def test_from_score_info(self):
        s = Severity.from_score(0.0)
        assert s.level == SeverityLevel.INFO

    def test_from_score_critical(self):
        s = Severity.from_score(9.5)
        assert s.level == SeverityLevel.CRITICAL

    def test_from_string_case_insensitive(self):
        s = Severity.from_string("high")
        assert s.level == SeverityLevel.HIGH

    def test_from_string_invalid_raises(self):
        with pytest.raises(ValueError):
            Severity.from_string("super-critical")

    def test_comparison(self):
        low = Severity.low()
        high = Severity.high()
        assert low < high
        assert high > low

    def test_is_at_least(self):
        high = Severity.high()
        assert high.is_at_least(Severity.medium()) is True
        assert high.is_at_least(Severity.critical()) is False

    def test_immutability(self):
        s = Severity.medium()
        with pytest.raises(Exception):
            s.level = SeverityLevel.CRITICAL  # Should raise (frozen)

    def test_equality(self):
        s1 = Severity.high()
        s2 = Severity.high()
        assert s1 == s2

    def test_hash_consistency(self):
        s1 = Severity.medium()
        s2 = Severity.medium()
        assert hash(s1) == hash(s2)


class TestThreatCategory:
    """Tests for ThreatCategory value object."""

    def test_high_value_categories(self):
        assert ThreatCategory.CREDENTIAL_LEAK.is_high_value is True
        assert ThreatCategory.SOCIAL_MEDIA.is_high_value is False

    def test_mitre_tactic_mapping(self):
        assert ThreatCategory.PHISHING.mitre_tactic is not None
        assert "Initial Access" in ThreatCategory.PHISHING.mitre_tactic

    def test_string_enum(self):
        assert str(ThreatCategory.MALWARE) == "malware"


class TestSourceType:
    """Tests for SourceType value object."""

    def test_trust_weight_virustotal(self):
        assert SourceType.VIRUSTOTAL.trust_weight >= 0.9

    def test_trust_weight_social_media(self):
        assert SourceType.SOCIAL_MEDIA.trust_weight < 0.5

    def test_requires_opsec_dark_web(self):
        assert SourceType.DARK_WEB.requires_opsec is True

    def test_requires_opsec_social_media(self):
        assert SourceType.SOCIAL_MEDIA.requires_opsec is False
