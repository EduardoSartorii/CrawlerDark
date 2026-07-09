"""Data Transfer Objects for use-case inputs/outputs.

DTOs cross the application boundary (e.g. CLI ↔ use case). They are plain
Pydantic models with no behaviour, keeping the transport concern separate from
the domain entities.
"""

from threat_hunting.core.application.dto.run_summary import RunSummary

__all__ = ["RunSummary"]
