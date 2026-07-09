"""Keyword provider port.

Responsibility
--------------
Expose the managed monitoring terms (keywords, VIPs, brands, threat actors,
watchlists) to the detection/scoring engines without coupling them to *where*
those terms come from (YAML today, Django admin/database tomorrow).
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol, runtime_checkable

from threat_hunting.core.domain.entities.threat_actor import ThreatActor
from threat_hunting.core.domain.entities.watchlist import Watchlist


@runtime_checkable
class KeywordProvider(Protocol):
    """Contract exposing watchlists and threat actors to the engines."""

    def watchlists(self) -> Sequence[Watchlist]:
        """Return all enabled watchlists."""
        ...

    def threat_actors(self) -> Sequence[ThreatActor]:
        """Return all monitored threat actors."""
        ...
