"""Domain-specific exceptions.

Exceptions live in the core so application services can communicate failures
without depending on HTTP clients, database drivers or CLI frameworks.
"""


class ThreatHuntingError(Exception):
    """Base error for recoverable platform failures."""


class ConnectorError(ThreatHuntingError):
    """Raised when a connector cannot collect or normalize source data."""


class PipelineError(ThreatHuntingError):
    """Raised when a pipeline stage fails to process a finding."""


class RepositoryError(ThreatHuntingError):
    """Raised when a persistence adapter cannot fulfill a repository contract."""
