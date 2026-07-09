"""Command objects used by CLI, scheduler, and future web/API adapters."""

from __future__ import annotations

from pydantic import BaseModel, Field


class RunHuntCommand(BaseModel):
    """Command to execute one connector group or connector name."""

    target: str = "all"
    export: bool = True
    limit: int | None = Field(default=None, ge=1)


class ToggleConnectorCommand(BaseModel):
    """Command to enable or disable a connector."""

    connector_name: str
    enabled: bool


class ExportCommand(BaseModel):
    """Command to export persisted findings through a named exporter."""

    exporter_name: str
    minimum_score: float = Field(default=0.0, ge=0.0, le=100.0)
