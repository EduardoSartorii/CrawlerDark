"""
IUnitOfWork Port
================

The Unit of Work pattern provides transactional consistency across multiple
repository operations. The application layer uses the UoW to group mutations
that must succeed or fail atomically.

Design:
    - async context manager protocol (__aenter__ / __aexit__).
    - commit() persists all pending changes.
    - rollback() discards pending changes.
    - All repositories are accessed through the UoW to share the same session.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from threat_hunting.core.domain.ports.repositories import (
        IConnectorConfigRepository,
        IFindingRepository,
        IIndicatorRepository,
        IKeywordRepository,
        IRuleRepository,
        IThreatActorRepository,
        IVIPRepository,
    )


class IUnitOfWork(ABC):
    """Abstract Unit of Work."""

    findings: "IFindingRepository"
    indicators: "IIndicatorRepository"
    keywords: "IKeywordRepository"
    vips: "IVIPRepository"
    threat_actors: "IThreatActorRepository"
    rules: "IRuleRepository"
    connector_configs: "IConnectorConfigRepository"

    @abstractmethod
    async def __aenter__(self) -> "IUnitOfWork": ...

    @abstractmethod
    async def __aexit__(self, exc_type: type | None, exc: Exception | None, tb: object) -> None: ...

    @abstractmethod
    async def commit(self) -> None:
        """Persist all pending changes."""

    @abstractmethod
    async def rollback(self) -> None:
        """Discard all pending changes."""
