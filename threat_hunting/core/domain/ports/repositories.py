"""Repository ports (interfaces genéricas + concretas por agregado)."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from typing import Protocol, TypeVar, runtime_checkable
from uuid import UUID

from ..entities import (
    DetectionRule,
    Finding,
    Indicator,
    Job,
    ThreatActor,
    WatchlistItem,
)

T = TypeVar("T")


@runtime_checkable
class RepositoryPort(Protocol[T]):
    async def get(self, id: UUID) -> T | None: ...
    async def add(self, entity: T) -> None: ...
    async def update(self, entity: T) -> None: ...
    async def list(self, *, limit: int = 100, offset: int = 0) -> Sequence[T]: ...


@runtime_checkable
class FindingRepositoryPort(RepositoryPort[Finding], Protocol):
    async def find_by_dedup_hash(self, dedup_hash: str) -> Finding | None: ...

    async def find_recent(self, *, limit: int = 500) -> Sequence[Finding]: ...

    async def find_unexported(
        self, target: str, *, min_score: float = 0.0, limit: int = 200
    ) -> Sequence[Finding]: ...


@runtime_checkable
class IndicatorRepositoryPort(RepositoryPort[Indicator], Protocol):
    async def find_by_value(self, value: str) -> Sequence[Indicator]: ...


@runtime_checkable
class ThreatActorRepositoryPort(RepositoryPort[ThreatActor], Protocol):
    async def find_by_alias(self, alias: str) -> ThreatActor | None: ...


@runtime_checkable
class WatchlistRepositoryPort(RepositoryPort[WatchlistItem], Protocol):
    async def all_enabled(self) -> Sequence[WatchlistItem]: ...

    async def bulk_replace(self, items: Iterable[WatchlistItem]) -> None: ...


@runtime_checkable
class DetectionRuleRepositoryPort(RepositoryPort[DetectionRule], Protocol):
    async def all_enabled(self) -> Sequence[DetectionRule]: ...


@runtime_checkable
class JobRepositoryPort(RepositoryPort[Job], Protocol):
    async def find_by_connector(self, connector: str, *, limit: int = 50) -> Sequence[Job]: ...
