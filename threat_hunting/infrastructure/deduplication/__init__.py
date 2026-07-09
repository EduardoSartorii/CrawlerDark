"""Deduplication engine.

Removes duplicate findings using interchangeable strategies (content hash,
shared indicators, textual similarity). Strategies implement a common protocol
and are composed by :class:`DeduplicationEngine`.
"""

from threat_hunting.infrastructure.deduplication.engine import DeduplicationEngine
from threat_hunting.infrastructure.deduplication.strategies import (
    HashStrategy,
    IndicatorStrategy,
    SimilarityStrategy,
)

__all__ = [
    "DeduplicationEngine",
    "HashStrategy",
    "IndicatorStrategy",
    "SimilarityStrategy",
]
