"""
Domain Exception Hierarchy
===========================

All exceptions in the platform derive from DomainError.
This allows callers to handle platform errors uniformly while
still being able to catch specific exception types.

Architecture:
    Domain exceptions carry structured context (not just strings).
    Infrastructure translates external exceptions (httpx, sqlalchemy, etc.)
    into the appropriate domain exception before re-raising.
"""

from __future__ import annotations

from typing import Any


class DomainError(Exception):
    """Base class for all platform exceptions."""

    def __init__(self, message: str, context: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.context: dict[str, Any] = context or {}

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(message={self.message!r}, context={self.context})"


class ConnectorError(DomainError):
    """Raised by connectors when collection encounters an error."""


class ConnectorNotFoundError(DomainError):
    """Raised when a requested connector is not registered."""


class CollectionError(DomainError):
    """Raised when data collection fails at runtime."""


class ParseError(DomainError):
    """Raised when a parser cannot process the raw content."""


class ExtractionError(DomainError):
    """Raised when the extractor cannot identify artifacts in parsed content."""


class NormalizationError(DomainError):
    """Raised when normalization into the Finding model fails."""


class DetectionError(DomainError):
    """Raised when the Detection Engine encounters a fatal error evaluating rules."""


class ScoringError(DomainError):
    """Raised when the Scoring Engine cannot compute a score."""


class CorrelationError(DomainError):
    """Raised by the Correlation Engine."""


class DeduplicationError(DomainError):
    """Raised by the Deduplication Engine."""


class EnrichmentError(DomainError):
    """Raised by the Enrichment Engine or any enricher."""


class PersistenceError(DomainError):
    """Raised when a storage operation fails."""


class ExportError(DomainError):
    """Raised when an exporter cannot deliver a Finding to its destination."""


class ValidationError(DomainError):
    """Raised when a domain object fails business-rule validation."""


class ConfigurationError(DomainError):
    """Raised when the platform is misconfigured."""


class OpsecError(DomainError):
    """Raised by the OPSEC layer (proxy failure, credential missing, etc.)."""


class RuleLoadError(DomainError):
    """Raised when a detection rule cannot be loaded or compiled."""


class EntityNotFoundError(DomainError):
    """Raised when an expected entity does not exist in storage."""

    def __init__(self, entity_type: str, entity_id: str) -> None:
        super().__init__(
            f"{entity_type} with id={entity_id!r} not found",
            context={"entity_type": entity_type, "entity_id": entity_id},
        )


class DuplicateEntityError(DomainError):
    """Raised when attempting to create an entity that already exists."""

    def __init__(self, entity_type: str, key: str) -> None:
        super().__init__(
            f"{entity_type} already exists: {key!r}",
            context={"entity_type": entity_type, "key": key},
        )
