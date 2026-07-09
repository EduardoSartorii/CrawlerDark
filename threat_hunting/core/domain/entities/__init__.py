"""Domain entities: objects with a stable identity and a lifecycle.

Unlike value objects, entities are identified by their ``id`` and evolve over
time (e.g. a :class:`Finding` accumulates indicators, score and relationships as
it flows through the pipeline).
"""

from threat_hunting.core.domain.entities.raw_item import RawItem
from threat_hunting.core.domain.entities.finding import Finding, FindingBuilder
from threat_hunting.core.domain.entities.threat_actor import ThreatActor
from threat_hunting.core.domain.entities.campaign import Campaign
from threat_hunting.core.domain.entities.watchlist import (
    Keyword,
    Watchlist,
    KeywordType,
)

__all__ = [
    "RawItem",
    "Finding",
    "FindingBuilder",
    "ThreatActor",
    "Campaign",
    "Keyword",
    "Watchlist",
    "KeywordType",
]
