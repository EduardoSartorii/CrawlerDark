"""Application commands (Command Pattern).

Responsibility
--------------
Encapsulate user/system intentions as immutable command objects.
Handlers execute commands; CLI and scheduler only create commands.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class Command(BaseModel):
    """Base command."""

    model_config = ConfigDict(frozen=True)


class RunHuntCommand(Command):
    """Execute hunt for one connector, a group, or all."""

    connector: str  # name | group (social, darkweb) | "all"
    options: dict[str, Any] = Field(default_factory=dict)
    dry_run: bool = False
    export_on_threshold: bool = True


class EnableConnectorCommand(Command):
    name: str


class DisableConnectorCommand(Command):
    name: str


class RunSchedulerCommand(Command):
    once: bool = False


class ExportFindingsCommand(Command):
    format: str
    finding_ids: list[str] = Field(default_factory=list)
    limit: int = 100
    options: dict[str, Any] = Field(default_factory=dict)


class ScoreTestCommand(Command):
    """Test scoring against a sample finding payload."""

    payload: dict[str, Any] = Field(default_factory=dict)
    text: str = ""


class HealthCheckCommand(Command):
    component: str | None = None


__all__ = [
    "Command",
    "RunHuntCommand",
    "EnableConnectorCommand",
    "DisableConnectorCommand",
    "RunSchedulerCommand",
    "ExportFindingsCommand",
    "ScoreTestCommand",
    "HealthCheckCommand",
]
