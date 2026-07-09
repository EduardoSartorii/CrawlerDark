"""Application commands implementing the Command pattern.

Each command represents an intent from CLI, scheduler, or future Django admin.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from uuid import UUID


@dataclass(frozen=True)
class RunConnectorCommand:
    """Execute collection pipeline for a single connector."""

    connector_name: str
    keywords: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class RunConnectorGroupCommand:
    """Execute collection for a connector group (e.g., social, darkweb)."""

    group_name: str


@dataclass(frozen=True)
class RunAllConnectorsCommand:
    """Execute all enabled connectors."""

    pass


@dataclass(frozen=True)
class EnableConnectorCommand:
    """Enable a connector."""

    connector_name: str


@dataclass(frozen=True)
class DisableConnectorCommand:
    """Disable a connector."""

    connector_name: str


@dataclass(frozen=True)
class ExportCommand:
    """Export findings to external system."""

    export_format: str
    finding_ids: list[UUID] = field(default_factory=list)
    filters: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ScoreTestCommand:
    """Test scoring engine with sample finding."""

    sample_data: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class SchedulerRunCommand:
    """Start the APScheduler daemon."""

    pass
