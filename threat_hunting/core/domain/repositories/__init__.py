"""Domain repository interfaces (ports) — no infrastructure code here."""

from .base import (
    AbstractRepository,
    DuplicateEntityError,
    EntityNotFoundError,
    FilterSpec,
    Page,
    PageSpec,
    RepositoryError,
    SortSpec,
)
from .finding_repository import AbstractFindingRepository
from .indicator_repository import AbstractIndicatorRepository
from .unit_of_work import AbstractUnitOfWork

__all__ = [
    "AbstractRepository",
    "AbstractFindingRepository",
    "AbstractIndicatorRepository",
    "AbstractUnitOfWork",
    "FilterSpec",
    "SortSpec",
    "PageSpec",
    "Page",
    "RepositoryError",
    "EntityNotFoundError",
    "DuplicateEntityError",
]
