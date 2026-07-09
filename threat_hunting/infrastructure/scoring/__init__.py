"""Configurable scoring engine.

Turns a finding's detection matches, indicators and context into a single
explainable 0-100 :class:`Score`. Every weight is configuration data
(:class:`ScoringWeights`), never hardcoded, so analysts can tune the model
without code changes.
"""

from threat_hunting.infrastructure.scoring.weights import ScoringWeights
from threat_hunting.infrastructure.scoring.engine import ScoringEngine

__all__ = ["ScoringWeights", "ScoringEngine"]
