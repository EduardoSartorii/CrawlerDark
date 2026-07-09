"""RunSummary DTO.

Responsibility
--------------
Carry the outcome of a collection run back to the caller (CLI, scheduler,
future API) in a serialisable, presentation-agnostic shape.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from threat_hunting.core.domain.enums import Severity


class RunSummary(BaseModel):
    """Aggregated result of running the pipeline for one or more connectors."""

    run_id: str
    connectors: list[str] = Field(default_factory=list)
    findings_collected: int = 0
    findings_persisted: int = 0
    findings_exported: int = 0
    duplicates_removed: int = 0
    high_severity: int = 0
    by_severity: dict[str, int] = Field(default_factory=dict)
    errors: list[str] = Field(default_factory=list)
    duration_seconds: float = 0.0

    def register_severity(self, severity: Severity) -> None:
        """Increment the per-severity histogram and the high-severity counter."""
        self.by_severity[severity.value] = self.by_severity.get(severity.value, 0) + 1
        if severity in (Severity.HIGH, Severity.CRITICAL):
            self.high_severity += 1
