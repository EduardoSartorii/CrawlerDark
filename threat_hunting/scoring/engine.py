"""Configurable scoring engine."""

from __future__ import annotations

from typing import Any

from threat_hunting.core.contracts import StageContext
from threat_hunting.domain.entities import ScoringPolicy, WatchlistProfile
from threat_hunting.scoring.strategies import ScoreStrategy


class WeightedScoringEngine:
    """Combines multiple scoring strategies with configurable weights."""

    def __init__(
        self,
        *,
        policy: ScoringPolicy,
        watchlist: WatchlistProfile,
        strategies: list[ScoreStrategy],
    ) -> None:
        self._policy = policy
        self._watchlist = watchlist
        self._strategies = strategies

    def run(self, items: list[dict[str, Any]], context: StageContext) -> list[dict[str, Any]]:
        """Compute score and confidence for each finding candidate."""
        scored: list[dict[str, Any]] = []
        total_weight = sum(abs(weight) for weight in self._policy.weights.values()) or 1.0
        for item in items:
            final_score = 0.0
            for strategy in self._strategies:
                final_score += strategy.score(item, self._policy, self._watchlist)
            normalized_score = max(0.0, min(100.0, final_score))
            confidence = max(10.0, min(100.0, (normalized_score / total_weight) * 100))
            severity = self._severity_from_score(normalized_score)
            scored.append({**item, "score": normalized_score, "confidence": confidence, "severity": severity})
        return scored

    def _severity_from_score(self, score: float) -> str:
        if score >= 90:
            return "critical"
        if score >= 70:
            return "high"
        if score >= 40:
            return "medium"
        if score >= 20:
            return "low"
        return "info"
