"""
Finding Repository Interface.

Extends the generic repository with Finding-specific query contracts.
These specialized methods reflect the core query patterns of the CTI platform.

Architectural Note:
    Method signatures here define the API that use cases depend on.
    No SQL, ORM, or Elasticsearch logic appears here — that lives in infrastructure.
"""

from __future__ import annotations

from abc import abstractmethod
from datetime import datetime

from ..entities.finding import Finding, FindingStatus
from ..value_objects import ThreatCategory
from .base import AbstractRepository, FilterSpec, Page, PageSpec


class AbstractFindingRepository(AbstractRepository[Finding]):
    """
    Port for Finding persistence operations.

    Concrete adapters: SQLAlchemyFindingRepository, ElasticsearchFindingRepository
    """

    @abstractmethod
    async def get_by_fingerprint(self, fingerprint: str) -> Finding | None:
        """
        Retrieve a finding by its deduplication fingerprint.
        Used by the Deduplication Engine to prevent duplicate findings.
        """

    @abstractmethod
    async def find_by_connector(
        self,
        connector_id: str,
        since: datetime | None = None,
        page: PageSpec | None = None,
    ) -> Page[Finding]:
        """Get all findings produced by a specific connector."""

    @abstractmethod
    async def find_by_category(
        self,
        category: ThreatCategory,
        page: PageSpec | None = None,
    ) -> Page[Finding]:
        """Get findings by threat category."""

    @abstractmethod
    async def find_by_status(
        self,
        status: FindingStatus,
        page: PageSpec | None = None,
    ) -> Page[Finding]:
        """Get findings by lifecycle status."""

    @abstractmethod
    async def find_by_indicator(self, indicator_id: str) -> list[Finding]:
        """Get all findings associated with a specific IOC."""

    @abstractmethod
    async def find_by_score_range(
        self,
        min_score: float,
        max_score: float = 10.0,
        page: PageSpec | None = None,
    ) -> Page[Finding]:
        """Get findings within a score range (for threshold-based export)."""

    @abstractmethod
    async def find_for_export(
        self,
        min_score: float,
        exclude_exported: bool = True,
    ) -> list[Finding]:
        """Get findings that qualify for export (score ≥ threshold, not yet exported)."""

    @abstractmethod
    async def find_by_tag(self, tag: str, page: PageSpec | None = None) -> Page[Finding]:
        """Search findings by tag."""

    @abstractmethod
    async def search(
        self, query: str, filters: FilterSpec | None = None, page: PageSpec | None = None
    ) -> Page[Finding]:
        """Full-text search across finding content."""

    @abstractmethod
    async def get_stats(self) -> dict[str, int]:
        """Aggregated statistics: counts per category, severity, status, connector."""
