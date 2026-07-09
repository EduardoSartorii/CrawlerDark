"""Domain exceptions.

Typed exceptions allow the application layer to handle business rule
violations without depending on infrastructure error types.
"""


class ThreatHuntingError(Exception):
    """Base exception for all domain and application errors."""


class ConnectorError(ThreatHuntingError):
    """Raised when a connector operation fails."""


class ConnectorNotFoundError(ConnectorError):
    """Raised when requested connector is not registered."""


class ConnectorDisabledError(ConnectorError):
    """Raised when attempting to run a disabled connector."""


class PipelineError(ThreatHuntingError):
    """Raised when a pipeline stage fails irrecoverably."""


class DetectionError(ThreatHuntingError):
    """Raised when detection engine encounters invalid rules."""


class StorageError(ThreatHuntingError):
    """Raised when persistence operations fail."""


class ExportError(ThreatHuntingError):
    """Raised when export to external system fails."""


class OpsecError(ThreatHuntingError):
    """Raised when OPSEC transport configuration is invalid."""


class ConfigurationError(ThreatHuntingError):
    """Raised when platform configuration is invalid or missing."""
