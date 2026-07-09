"""Keyword providers.

Responsibility
--------------
Supply watchlists and threat actors to the detection/scoring engines. Two
adapters implement the same core ``KeywordProvider`` port:

* :class:`InMemoryKeywordProvider` -- explicit lists (tests / programmatic use).
* :class:`YamlKeywordProvider` -- loads from a YAML document so terms are data.

A future Django-backed provider implements the identical port over the database
without any engine change.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from threat_hunting.core.domain.entities.threat_actor import ThreatActor
from threat_hunting.core.domain.entities.watchlist import Keyword, KeywordType, Watchlist
from threat_hunting.core.domain.exceptions import ConfigurationError


class InMemoryKeywordProvider:
    """Programmatic keyword provider backed by in-memory lists."""

    def __init__(
        self,
        watchlists: Sequence[Watchlist] = (),
        threat_actors: Sequence[ThreatActor] = (),
    ) -> None:
        self._watchlists = list(watchlists)
        self._actors = list(threat_actors)

    def watchlists(self) -> Sequence[Watchlist]:
        """Return enabled watchlists."""
        return [w for w in self._watchlists if w.enabled]

    def threat_actors(self) -> Sequence[ThreatActor]:
        """Return monitored threat actors."""
        return list(self._actors)


class YamlKeywordProvider:
    """Keyword provider that loads watchlists/actors from a YAML file."""

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self._watchlists: list[Watchlist] = []
        self._actors: list[ThreatActor] = []
        self._loaded = False

    def _load(self) -> None:
        if self._loaded:
            return
        import yaml

        if not self._path.exists():
            raise ConfigurationError(f"watchlist file not found: {self._path}")
        data = yaml.safe_load(self._path.read_text(encoding="utf-8")) or {}

        for wl in data.get("watchlists", []):
            keywords = [
                Keyword(
                    term=kw["term"],
                    type=KeywordType(kw.get("type", "generic")),
                    weight=float(kw.get("weight", 10.0)),
                    case_sensitive=bool(kw.get("case_sensitive", False)),
                    enabled=bool(kw.get("enabled", True)),
                )
                for kw in wl.get("keywords", [])
            ]
            self._watchlists.append(
                Watchlist(
                    name=wl["name"],
                    description=wl.get("description", ""),
                    keywords=keywords,
                    enabled=bool(wl.get("enabled", True)),
                )
            )

        for actor in data.get("threat_actors", []):
            self._actors.append(
                ThreatActor(
                    name=actor["name"],
                    aliases=actor.get("aliases", []),
                    description=actor.get("description", ""),
                    motivation=actor.get("motivation"),
                    country=actor.get("country"),
                    tags=actor.get("tags", []),
                )
            )
        self._loaded = True

    def watchlists(self) -> Sequence[Watchlist]:
        """Return enabled watchlists loaded from YAML."""
        self._load()
        return [w for w in self._watchlists if w.enabled]

    def threat_actors(self) -> Sequence[ThreatActor]:
        """Return threat actors loaded from YAML."""
        self._load()
        return list(self._actors)
