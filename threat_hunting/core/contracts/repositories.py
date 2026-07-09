"""Repository port interfaces.

Implementations live in infrastructure/storage and infrastructure/database.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING
from uuid import UUID

if TYPE_CHECKING:
    from threat_hunting.core.domain.entities import (
        AuditLog,
        ConnectorConfig,
        CorrelationLink,
        DetectionRule,
        ExportJob,
        Finding,
        ScoreProfile,
        WatchlistEntry,
    )


class IFindingRepository(ABC):
    """Persistence port for Finding aggregate."""

    @abstractmethod
    async def save(self, finding: Finding) -> Finding:
        """Persist or update a finding."""

    @abstractmethod
    async def get_by_id(self, finding_id: UUID) -> Finding | None:
        """Retrieve finding by primary key."""

    @abstractmethod
    async def list_all(self, limit: int = 100, offset: int = 0) -> list[Finding]:
        """List findings with pagination."""

    @abstractmethod
    async def find_by_connector(self, connector: str, limit: int = 100) -> list[Finding]:
        """Query findings by originating connector."""

    @abstractmethod
    async def find_by_hash(self, content_hash: str) -> Finding | None:
        """Lookup finding by deduplication hash."""

    @abstractmethod
    async def delete(self, finding_id: UUID) -> bool:
        """Remove a finding."""


class IWatchlistRepository(ABC):
    """Persistence port for watchlist entries."""

    @abstractmethod
    async def save(self, entry: WatchlistEntry) -> WatchlistEntry:
        """Persist watchlist entry."""

    @abstractmethod
    async def list_enabled(self, watchlist_type: str | None = None) -> list[WatchlistEntry]:
        """List active watchlist entries, optionally filtered by type."""

    @abstractmethod
    async def delete(self, entry_id: UUID) -> bool:
        """Remove watchlist entry."""


class IDetectionRuleRepository(ABC):
    """Persistence port for detection rules."""

    @abstractmethod
    async def list_enabled(self) -> list[DetectionRule]:
        """Load all active detection rules."""

    @abstractmethod
    async def save(self, rule: DetectionRule) -> DetectionRule:
        """Persist detection rule."""


class IScoreProfileRepository(ABC):
    """Persistence port for scoring profiles."""

    @abstractmethod
    async def get_default(self) -> ScoreProfile:
        """Retrieve the active default scoring profile."""

    @abstractmethod
    async def save(self, profile: ScoreProfile) -> ScoreProfile:
        """Persist scoring profile."""


class ICorrelationRepository(ABC):
    """Persistence port for correlation links."""

    @abstractmethod
    async def save(self, link: CorrelationLink) -> CorrelationLink:
        """Persist correlation link."""

    @abstractmethod
    async def find_by_source(self, source_id: UUID) -> list[CorrelationLink]:
        """Find correlations originating from a finding."""

    @abstractmethod
    async def find_by_target(self, target_id: str) -> list[CorrelationLink]:
        """Find correlations pointing to an entity."""


class IConnectorConfigRepository(ABC):
    """Persistence port for connector configurations."""

    @abstractmethod
    async def get(self, name: str) -> ConnectorConfig | None:
        """Retrieve connector config by name."""

    @abstractmethod
    async def list_all(self) -> list[ConnectorConfig]:
        """List all connector configurations."""

    @abstractmethod
    async def save(self, config: ConnectorConfig) -> ConnectorConfig:
        """Persist connector configuration."""

    @abstractmethod
    async def set_enabled(self, name: str, enabled: bool) -> ConnectorConfig:
        """Enable or disable a connector."""


class IAuditRepository(ABC):
    """Persistence port for audit logs."""

    @abstractmethod
    async def append(self, log: AuditLog) -> AuditLog:
        """Append immutable audit entry."""

    @abstractmethod
    async def list_recent(self, limit: int = 100) -> list[AuditLog]:
        """Retrieve recent audit entries."""


class IExportJobRepository(ABC):
    """Persistence port for export jobs."""

    @abstractmethod
    async def save(self, job: ExportJob) -> ExportJob:
        """Persist export job."""

    @abstractmethod
    async def list_pending(self) -> list[ExportJob]:
        """List jobs awaiting processing."""


class IUnitOfWork(ABC):
    """Unit of Work pattern for atomic transactions."""

    findings: IFindingRepository
    watchlists: IWatchlistRepository
    rules: IDetectionRuleRepository
    correlations: ICorrelationRepository
    audit: IAuditRepository

    @abstractmethod
    async def __aenter__(self) -> IUnitOfWork:
        """Begin transaction context."""

    @abstractmethod
    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Commit or rollback transaction."""

    @abstractmethod
    async def commit(self) -> None:
        """Commit pending changes."""

    @abstractmethod
    async def rollback(self) -> None:
        """Rollback pending changes."""
