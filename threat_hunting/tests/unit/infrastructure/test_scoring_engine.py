"""
Unit tests for the Scoring Engine.

Tests cover:
    - Base score application
    - Category multipliers
    - Bonus contributions (VIP, brand, threat actor, IOC count)
    - Source trust factor
    - Score capping at 10.0
    - Breakdown audit trail
"""

from __future__ import annotations

import pytest

from ....core.domain.value_objects import ThreatCategory
from ....core.domain.value_objects.source_type import SourceType
from ....infrastructure.scoring.engine import ScoringEngine, ScoringWeights
from ...fixtures.factories import make_finding


class TestScoringEngine:
    """Tests for the Scoring Engine."""

    def _engine(self) -> ScoringEngine:
        return ScoringEngine()

    def test_score_increases_for_credential_category(self):
        finding = make_finding(
            category=ThreatCategory.CREDENTIAL_LEAK,
            source_type=SourceType.PASTE_SITE,
            score_value=3.0,
        )
        engine = self._engine()
        score, _ = engine.score(finding)
        # Category multiplier (2.5) × trust weight (0.5) × base (3.0) + bonuses
        assert score.value > 3.0

    def test_vip_match_bonus_applied(self):
        finding = make_finding(score_value=2.0)
        engine = self._engine()
        score, breakdown = engine.score(finding, matched_vips=["CEO John Smith"])
        assert "vip_match" in breakdown.bonus_contributions

    def test_threat_actor_bonus_applied(self):
        finding = make_finding(score_value=2.0)
        engine = self._engine()
        score, breakdown = engine.score(finding, matched_threat_actor="Lazarus Group")
        assert "threat_actor" in breakdown.bonus_contributions
        assert finding.threat_actor == "Lazarus Group"

    def test_brand_match_bonus_applied(self):
        finding = make_finding(score_value=2.0)
        engine = self._engine()
        score, breakdown = engine.score(finding, matched_brands=["ACME Corp"])
        assert "brand_match" in breakdown.bonus_contributions
        assert "ACME Corp" in finding.affected_brands

    def test_score_capped_at_10(self):
        finding = make_finding(score_value=9.5)
        engine = self._engine()
        score, _ = engine.score(
            finding,
            matched_vips=["CEO", "CFO"],
            matched_threat_actor="APT28",
            matched_brands=["Corp1"],
            matched_keywords=["credential", "password", "leak"],
        )
        assert score.value <= 10.0

    def test_breakdown_explains_score(self):
        finding = make_finding(score_value=3.0)
        engine = self._engine()
        _, breakdown = engine.score(finding)
        explanation = breakdown.explain()
        assert "Base score" in explanation
        assert "Final" in explanation

    def test_dark_web_source_bonus(self):
        finding = make_finding(
            score_value=3.0,
            source_type=SourceType.DARK_WEB,
        )
        engine = self._engine()
        _, breakdown = engine.score(finding)
        assert "dark_web_source" in breakdown.bonus_contributions

    def test_ioc_density_bonus(self):
        finding = make_finding(score_value=3.0)
        # Simulate IOC count
        finding.indicator_ids = ["ioc1", "ioc2", "ioc3", "ioc4", "ioc5"]
        engine = self._engine()
        _, breakdown = engine.score(finding)
        assert "ioc_density" in breakdown.bonus_contributions

    def test_configure_weights(self):
        engine = self._engine()
        engine.configure({"vip_match_bonus": 5.0})
        # Verify reconfigured weight is applied
        finding = make_finding(score_value=2.0)
        _, breakdown = engine.score(finding, matched_vips=["VIP1"])
        assert breakdown.bonus_contributions.get("vip_match", 0) == pytest.approx(5.0)
