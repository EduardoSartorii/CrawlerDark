"""Domain value objects — immutable, identity-free business concepts."""

from .category import ThreatCategory
from .score import Score
from .severity import Severity, SeverityLevel
from .source_type import SourceType

__all__ = [
    "ThreatCategory",
    "Score",
    "Severity",
    "SeverityLevel",
    "SourceType",
]
