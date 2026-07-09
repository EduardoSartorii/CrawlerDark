"""Custom exceptions for consistent error boundaries."""


class ThreatHuntingError(Exception):
    """Base platform exception."""


class ConnectorNotFoundError(ThreatHuntingError):
    """Raised when a requested connector is not registered."""


class ConnectorExecutionError(ThreatHuntingError):
    """Raised when connector execution fails."""


class PipelineStageError(ThreatHuntingError):
    """Raised when pipeline stage processing fails."""


class ConfigurationError(ThreatHuntingError):
    """Raised for invalid runtime configuration."""
