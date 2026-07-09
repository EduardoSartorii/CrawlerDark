"""Domain and platform exception hierarchy.

Responsibility
--------------
Define a single, well-typed exception tree so every layer can raise and catch
errors semantically instead of leaking third-party exceptions across
boundaries. Infrastructure adapters translate library-specific errors into
these domain-meaningful types, keeping the core free of vendor coupling.
"""

from __future__ import annotations


class ThreatHuntingError(Exception):
    """Base class for every error raised by the platform."""


class DomainError(ThreatHuntingError):
    """A business-rule / invariant violation in the domain layer."""


class ValidationError(DomainError):
    """A value object or entity failed validation."""


class ConnectorError(ThreatHuntingError):
    """Base class for connector-related failures."""


class ConnectorNotFoundError(ConnectorError):
    """Requested connector is not registered/discovered."""


class ConnectorDisabledError(ConnectorError):
    """Requested connector exists but is disabled by configuration."""


class ConnectionFailedError(ConnectorError):
    """The connector could not establish a connection to its source."""


class CollectionError(ConnectorError):
    """The connector failed while collecting raw items."""


class PipelineError(ThreatHuntingError):
    """A pipeline stage failed."""

    def __init__(self, stage: str, message: str) -> None:
        self.stage = stage
        super().__init__(f"[{stage}] {message}")


class StorageError(ThreatHuntingError):
    """Persistence backend failure."""


class ExportError(ThreatHuntingError):
    """Exporter failure."""


class OpsecError(ThreatHuntingError):
    """OPSEC transport / policy failure."""


class ConfigurationError(ThreatHuntingError):
    """Invalid or missing configuration."""
