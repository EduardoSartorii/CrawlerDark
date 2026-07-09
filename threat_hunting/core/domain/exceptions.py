"""Domain-level exceptions.

Responsibility
--------------
Provide a small, meaningful exception hierarchy so that application and
infrastructure code can distinguish domain/business errors from technical
failures. Infrastructure adapters translate technical exceptions (HTTP, DB)
into these where a business meaning exists.
"""

from __future__ import annotations


class ThreatHuntingError(Exception):
    """Root of the platform exception hierarchy."""


class DomainValidationError(ThreatHuntingError):
    """A domain invariant was violated."""


class ConnectorError(ThreatHuntingError):
    """A connector failed to connect, collect, parse or normalise."""


class ConnectorNotFoundError(ThreatHuntingError):
    """A requested connector is not registered/discoverable."""


class PipelineError(ThreatHuntingError):
    """A pipeline stage failed irrecoverably."""


class ExporterError(ThreatHuntingError):
    """An exporter failed to emit a finding."""


class ConfigurationError(ThreatHuntingError):
    """The platform configuration is missing or invalid."""
