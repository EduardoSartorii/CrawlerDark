"""Rule and watchlist repository ports.

Responsibility
--------------
Abstract the source of detection rules and hunting targets. Rules and watchlists
are configuration-driven (YAML today, a database/Django admin tomorrow), so the
engines depend on these ports rather than on any concrete loader.
"""

from __future__ import annotations

import abc

from threat_hunting.core.domain.watchlist import Watchlist


class DetectionRule(abc.ABC):
    """A single loaded detection rule (Strategy).

    Concrete rules (regex, keyword, IOC, YARA, Sigma) live in infrastructure and
    implement :meth:`evaluate`.
    """

    #: Rule identifier (unique within a rule set).
    id: str = "abstract"
    #: Rule type discriminator (``regex``/``keyword``/``ioc``/``yara``/...).
    kind: str = "abstract"
    #: Points contributed to the score when the rule fires.
    weight: float = 0.0

    @abc.abstractmethod
    def evaluate(self, text: str) -> bool:
        """Return whether the rule fires against the given text."""


class RuleRepositoryPort(abc.ABC):
    """Provides the active set of detection rules."""

    @abc.abstractmethod
    def load(self) -> list[DetectionRule]:
        """Return all enabled detection rules."""


class WatchlistRepositoryPort(abc.ABC):
    """Provides the active hunting targets."""

    @abc.abstractmethod
    def load(self) -> list[Watchlist]:
        """Return all enabled watchlists."""
