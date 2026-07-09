"""
Application Commands.

Commands represent intent to change system state.
Each command is a Pydantic model (immutable data transfer object).
Commands are handled by Command Handlers in the handlers module.

Design Pattern: Command Pattern (CQRS write side)
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class BaseCommand(BaseModel):
    """Base class for all application commands."""

    model_config = ConfigDict(frozen=True)


class CreateFindingCommand(BaseCommand):
    """Command: Create a new Finding from collected raw data."""

    title: str
    description: str = ""
    source: str
    connector: str
    category: str
    source_type: str
    raw_data: str = ""
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    source_url: str | None = None
    source_id: str | None = None


class RunConnectorCommand(BaseCommand):
    """Command: Execute a specific connector's collection cycle."""

    connector_id: str
    dry_run: bool = False
    limit: int | None = None


class RunPipelineCommand(BaseCommand):
    """Command: Execute the full collection pipeline for a connector group."""

    group: str = "all"
    dry_run: bool = False
    parallel: bool = True


class ExportFindingsCommand(BaseCommand):
    """Command: Export findings to an external platform."""

    destination: str
    min_score: float = 5.0
    finding_ids: list[str] = Field(default_factory=list)
    dry_run: bool = False


class UpdateConnectorStatusCommand(BaseCommand):
    """Command: Enable or disable a connector."""

    connector_id: str
    enabled: bool


class ConfirmFindingCommand(BaseCommand):
    """Command: Analyst confirms a finding as true positive."""

    finding_id: str
    analyst: str
    notes: str = ""


class MarkFalsePositiveCommand(BaseCommand):
    """Command: Analyst dismisses a finding as false positive."""

    finding_id: str
    analyst: str
    reason: str
