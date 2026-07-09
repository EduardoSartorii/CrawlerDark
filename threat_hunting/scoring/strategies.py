"""Scoring strategies (Strategy Pattern)."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from threat_hunting.domain.entities import ScoringPolicy, WatchlistProfile


class ScoreStrategy(ABC):
    """Strategy contract for score contribution."""

    signal_name: str

    @abstractmethod
    def score(self, item: dict[str, Any], policy: ScoringPolicy, watchlist: WatchlistProfile) -> float:
        """Compute score contribution."""


class SignalPresenceStrategy(ScoreStrategy):
    """Score strategy based on signal presence in matched signals."""

    def __init__(self, signal_name: str) -> None:
        self.signal_name = signal_name

    def score(self, item: dict[str, Any], policy: ScoringPolicy, watchlist: WatchlistProfile) -> float:
        signals = {str(signal).lower() for signal in item.get("signals", [])}
        if self.signal_name.lower() in signals:
            return policy.weight_for(self.signal_name)
        return 0.0


class VipMatchStrategy(ScoreStrategy):
    """Score strategy for VIP mentions."""

    signal_name = "vip_match"

    def score(self, item: dict[str, Any], policy: ScoringPolicy, watchlist: WatchlistProfile) -> float:
        text = f"{item.get('title', '')} {item.get('description', '')}".lower()
        if any(vip.lower() in text for vip in watchlist.vips):
            return policy.weight_for(self.signal_name)
        return 0.0


class ThreatActorMatchStrategy(ScoreStrategy):
    """Score strategy for threat actor matches."""

    signal_name = "threat_actor_match"

    def score(self, item: dict[str, Any], policy: ScoringPolicy, watchlist: WatchlistProfile) -> float:
        actor = str(item.get("normalized_data", {}).get("threat_actor", "")).lower()
        if actor and actor in {value.lower() for value in watchlist.threat_actors}:
            return policy.weight_for(self.signal_name)
        return 0.0
