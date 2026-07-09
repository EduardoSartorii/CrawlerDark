"""
Engine Ports
============

Interface contracts for the five processing engines in the pipeline.
Each engine operates on a Finding and returns an enriched Finding.
Engines are stateless by design — state is carried by the Finding.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from threat_hunting.core.domain.entities.finding import Finding


class IDetectionEngine(ABC):
    """Evaluates detection rules against a Finding."""

    @abstractmethod
    async def run(self, finding: "Finding") -> "Finding":
        """Apply all enabled detection rules.

        Adds DetectionResult entries to finding.detection_results.
        Tags the finding with matched rule names.

        Args:
            finding: The Finding to evaluate.

        Returns:
            The Finding with detection results attached.

        Raises:
            DetectionError: On fatal engine error.
        """


class IScoringEngine(ABC):
    """Computes a risk score for a Finding."""

    @abstractmethod
    async def score(self, finding: "Finding") -> "Finding":
        """Compute and assign a risk score.

        Calls finding.set_score() with the computed Score.
        Derives severity automatically from the score value.

        Args:
            finding: The Finding to score.

        Returns:
            The Finding with score and severity assigned.

        Raises:
            ScoringError: On fatal engine error.
        """


class ICorrelationEngine(ABC):
    """Correlates a Finding with other Findings and entities."""

    @abstractmethod
    async def correlate(self, finding: "Finding") -> "Finding":
        """Search for related Findings and link them.

        Adds Relationship entries to finding.relationships.
        Assigns finding.correlation_group when appropriate.

        Args:
            finding: The Finding to correlate.

        Returns:
            The Finding with relationships populated.

        Raises:
            CorrelationError: On fatal engine error.
        """


class IDeduplicationEngine(ABC):
    """Detects and marks duplicate Findings."""

    @abstractmethod
    async def deduplicate(self, finding: "Finding") -> "Finding":
        """Check for duplicates and mark the Finding if one exists.

        Calls finding.mark_duplicate() when a duplicate is found.

        Args:
            finding: The Finding to check.

        Returns:
            The Finding, possibly with duplicate_of set.

        Raises:
            DeduplicationError: On fatal engine error.
        """


class IEnrichmentEngine(ABC):
    """Enriches Indicators attached to a Finding."""

    @abstractmethod
    async def enrich(self, finding: "Finding") -> "Finding":
        """Fetch additional context for the Finding's indicators.

        Enriches each Indicator referenced by the Finding.

        Args:
            finding: The Finding to enrich.

        Returns:
            The Finding with its indicators enriched.

        Raises:
            EnrichmentError: On fatal engine error.
        """
