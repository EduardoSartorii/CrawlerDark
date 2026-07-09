"""
Indicator Repository Interface.

Specialized query methods for IOC lookups.
The Correlation Engine uses bulk lookups to find shared IOCs across findings.
"""

from __future__ import annotations

from abc import abstractmethod

from ..entities.indicator import Indicator, IndicatorType
from .base import AbstractRepository, Page, PageSpec


class AbstractIndicatorRepository(AbstractRepository[Indicator]):
    """Port for Indicator (IOC) persistence operations."""

    @abstractmethod
    async def get_by_value(self, value: str, ioc_type: IndicatorType) -> Indicator | None:
        """Lookup an IOC by its value and type (the natural key)."""

    @abstractmethod
    async def get_by_values(self, values: list[str]) -> list[Indicator]:
        """Bulk lookup IOCs by value (type-agnostic)."""

    @abstractmethod
    async def find_active(
        self, ioc_type: IndicatorType | None = None, page: PageSpec | None = None
    ) -> Page[Indicator]:
        """Get all active (non-expired, non-whitelisted) IOCs."""

    @abstractmethod
    async def find_by_finding(self, finding_id: str) -> list[Indicator]:
        """Get all IOCs linked to a specific finding."""

    @abstractmethod
    async def find_whitelisted(self) -> list[Indicator]:
        """Get all whitelisted IOCs (used to filter detection output)."""

    @abstractmethod
    async def bulk_upsert(self, indicators: list[Indicator]) -> list[Indicator]:
        """Bulk insert or update IOCs — used after enrichment pass."""
