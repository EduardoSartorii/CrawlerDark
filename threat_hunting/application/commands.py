"""Command pattern implementation used by CLI and scheduler."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any


@dataclass(slots=True)
class Command:
    """Base command marker."""


@dataclass(slots=True)
class RunHuntCommand(Command):
    """Execute hunt for one connector or logical group."""

    target: str


@dataclass(slots=True)
class ToggleConnectorCommand(Command):
    """Enable or disable a connector in runtime config."""

    connector_name: str
    enabled: bool


@dataclass(slots=True)
class ExportFindingsCommand(Command):
    """Trigger exporter for selected destination."""

    target: str
    limit: int = 100


@dataclass(slots=True)
class RunSchedulerCommand(Command):
    """Execute scheduler loop once."""


@dataclass(slots=True)
class ScoreTestCommand(Command):
    """Run a synthetic scoring check."""


class CommandBus:
    """In-memory command bus for decoupled command dispatch."""

    def __init__(self) -> None:
        self._handlers: dict[type[Command], Callable[[Command], Any]] = {}

    def register(self, command_type: type[Command], handler: Callable[[Any], Any]) -> None:
        """Register command handler."""
        self._handlers[command_type] = handler

    def execute(self, command: Command) -> Any:
        """Execute command through mapped handler."""
        handler = self._handlers.get(type(command))
        if not handler:
            msg = f"No handler registered for {type(command).__name__}"
            raise ValueError(msg)
        return handler(command)
