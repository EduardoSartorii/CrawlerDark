"""
Base Repository Interface (Port).

Defines the abstract contract for all data access operations in the platform.
Repositories are the primary boundary between domain and infrastructure.

Architectural Notes:
    - These are PORTS (Hexagonal Architecture) — pure Python ABCs with no DB code
    - Concrete adapters (SQLAlchemy, Elasticsearch, etc.) live in infrastructure/
    - Domain services and use cases depend ONLY on these interfaces
    - The Unit of Work pattern coordinates multiple repositories in a transaction
    - Generic[T] typing enables IDE completion and type safety across all repos

Design Pattern: Repository Pattern + Generic Repository
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Generic, TypeVar

from ..entities.base import BaseEntity

T = TypeVar("T", bound=BaseEntity)


class RepositoryError(Exception):
    """Base class for repository errors."""


class EntityNotFoundError(RepositoryError):
    """Raised when an entity cannot be found by ID."""

    def __init__(self, entity_type: str, entity_id: str) -> None:
        super().__init__(f"{entity_type} with id '{entity_id}' not found")
        self.entity_type = entity_type
        self.entity_id = entity_id


class DuplicateEntityError(RepositoryError):
    """Raised when attempting to insert a duplicate entity."""


class FilterSpec(dict[str, Any]):
    """
    Type-safe filter specification for repository queries.
    Supports simple equality filters and operator-prefixed filters.

    Examples:
        FilterSpec({"status": "new", "score__gte": 5.0, "category": "malware"})
    """


class SortSpec:
    """Sort specification for repository queries."""

    def __init__(self, field: str, ascending: bool = True) -> None:
        self.field = field
        self.ascending = ascending


class PageSpec:
    """Pagination specification."""

    def __init__(self, page: int = 1, page_size: int = 50) -> None:
        self.page = max(1, page)
        self.page_size = min(500, max(1, page_size))

    @property
    def offset(self) -> int:
        return (self.page - 1) * self.page_size

    @property
    def limit(self) -> int:
        return self.page_size


class Page(Generic[T]):
    """Paginated result container."""

    def __init__(
        self,
        items: list[T],
        total: int,
        spec: PageSpec,
    ) -> None:
        self.items = items
        self.total = total
        self.page = spec.page
        self.page_size = spec.page_size

    @property
    def has_next(self) -> bool:
        return self.page * self.page_size < self.total

    @property
    def has_previous(self) -> bool:
        return self.page > 1

    @property
    def total_pages(self) -> int:
        return max(1, (self.total + self.page_size - 1) // self.page_size)


class AbstractRepository(ABC, Generic[T]):
    """
    Generic abstract repository.

    All domain repositories inherit from this to get standard CRUD contracts.
    Infrastructure adapters provide concrete implementations.
    """

    @abstractmethod
    async def get_by_id(self, entity_id: str) -> T | None:
        """Retrieve an entity by its UUID. Returns None if not found."""

    @abstractmethod
    async def get_by_id_or_raise(self, entity_id: str) -> T:
        """Retrieve an entity by UUID or raise EntityNotFoundError."""

    @abstractmethod
    async def save(self, entity: T) -> T:
        """Persist a new entity. Raises DuplicateEntityError if already exists."""

    @abstractmethod
    async def update(self, entity: T) -> T:
        """Update an existing entity. Raises EntityNotFoundError if not found."""

    @abstractmethod
    async def save_or_update(self, entity: T) -> T:
        """Insert or update (upsert) an entity."""

    @abstractmethod
    async def delete(self, entity_id: str) -> None:
        """Soft or hard delete by ID."""

    @abstractmethod
    async def list(
        self,
        filters: FilterSpec | None = None,
        sort: SortSpec | None = None,
        page: PageSpec | None = None,
    ) -> Page[T]:
        """List entities with optional filtering, sorting and pagination."""

    @abstractmethod
    async def count(self, filters: FilterSpec | None = None) -> int:
        """Count entities matching optional filters."""

    @abstractmethod
    async def exists(self, entity_id: str) -> bool:
        """Check if an entity exists."""
