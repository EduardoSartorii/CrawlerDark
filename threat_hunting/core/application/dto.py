"""Application data-transfer objects.

Responsibility
--------------
Carry data *between* layers and *through* the pipeline without leaking
infrastructure types into the domain.

* ``RawRecord`` is the raw unit a connector emits (before it becomes a Finding).
* ``PipelineContext`` is the mutable envelope threaded through the pipeline
  stages, accumulating results and preserving auditability.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from threat_hunting.core.domain.entities import Finding


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(slots=True)
class RawRecord:
    """A raw item collected by a connector, prior to parsing/normalisation.

    Parameters
    ----------
    source:
        Human-readable origin (e.g. ``"reddit:r/netsec"``).
    connector:
        The connector name that produced the record.
    content:
        The raw textual payload (HTML, JSON string, post body, ...).
    url:
        Optional canonical URL of the item.
    metadata:
        Arbitrary connector-specific metadata (author, timestamps, ...).
    raw:
        The original structured payload as returned by the source.
    """

    source: str
    connector: str
    content: str = ""
    url: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)
    collected_at: datetime = field(default_factory=_utcnow)


@dataclass(slots=True)
class PipelineResult:
    """Outcome of a full pipeline run for a single connector."""

    connector: str
    collected: int = 0
    persisted: int = 0
    duplicates: int = 0
    exported: int = 0
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def merge(self, other: "PipelineResult") -> "PipelineResult":
        """Aggregate another result into this one (used by ``run all``)."""
        self.collected += other.collected
        self.persisted += other.persisted
        self.duplicates += other.duplicates
        self.exported += other.exported
        self.findings.extend(other.findings)
        self.errors.extend(other.errors)
        return self
