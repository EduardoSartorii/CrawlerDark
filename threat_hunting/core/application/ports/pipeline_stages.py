"""Pipeline-stage ports (one contract per decoupled stage).

Responsibility
--------------
Each processing stage of the pipeline is expressed as its own port so that any
stage can be replaced, disabled or re-ordered independently. The pipeline
orchestrator depends only on these interfaces (Command pattern: each stage is a
self-contained operation on a ``Finding``).
"""

from __future__ import annotations

import abc
from collections.abc import Sequence

from threat_hunting.core.application.dto import RawRecord
from threat_hunting.core.domain.entities import Finding, Indicator


class ParserPort(abc.ABC):
    """Clean and structure raw content prior to extraction."""

    @abc.abstractmethod
    def parse(self, record: RawRecord) -> RawRecord:
        """Return a record with cleaned ``content`` and enriched metadata."""


class ExtractorPort(abc.ABC):
    """Extract indicators (IOCs) from parsed content."""

    @abc.abstractmethod
    def extract(self, record: RawRecord) -> list[Indicator]:
        """Return the indicators found in the record's content."""


class NormalizerPort(abc.ABC):
    """Produce/refine the canonical ``normalized_data`` of a finding."""

    @abc.abstractmethod
    def normalize(self, finding: Finding, record: RawRecord) -> Finding:
        """Populate ``finding.normalized_data`` and canonical fields."""


class DetectionEnginePort(abc.ABC):
    """Evaluate a finding against dynamically loaded detection rules."""

    @abc.abstractmethod
    def detect(self, finding: Finding) -> Finding:
        """Attach matched-rule tags/metadata; may drop non-matching findings."""

    @abc.abstractmethod
    def matches(self, finding: Finding) -> bool:
        """Return whether the finding matched at least one rule."""


class ScoringEnginePort(abc.ABC):
    """Assign a configurable, explainable score to a finding."""

    @abc.abstractmethod
    def score(self, finding: Finding) -> Finding:
        """Compute and set ``finding.score``/``severity`` with an audit trail."""


class CorrelationEnginePort(abc.ABC):
    """Infer relationships between a finding and prior intelligence."""

    @abc.abstractmethod
    def correlate(
        self, finding: Finding, context: Sequence[Finding]
    ) -> Finding:
        """Attach relationships linking the finding to the given context."""


class DeduplicationEnginePort(abc.ABC):
    """Detect and flag duplicate findings."""

    @abc.abstractmethod
    def is_duplicate(self, finding: Finding, context: Sequence[Finding]) -> bool:
        """Return whether ``finding`` duplicates something already seen."""

    @abc.abstractmethod
    def register(self, finding: Finding) -> None:
        """Remember a finding so future duplicates can be detected."""


class EnrichmentEnginePort(abc.ABC):
    """Add contextual intelligence to a finding/indicators."""

    @abc.abstractmethod
    def enrich(self, finding: Finding) -> Finding:
        """Return the finding enriched with additional context."""
