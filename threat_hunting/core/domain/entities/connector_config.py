"""
ConnectorConfig Entity
======================

Stores the runtime configuration for a connector instance.
Separating configuration from the connector implementation allows:
- enabling/disabling connectors without code changes;
- per-connector OPSEC profile assignment;
- credential management through the SecretManager;
- scheduler job attachment;
- audit trail of configuration changes.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field, field_validator

from threat_hunting.core.domain.value_objects.source import SourceType


class ConnectorConfig(BaseModel):
    """Runtime configuration for a single connector."""

    model_config = {"validate_assignment": True}

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    connector_id: str
    name: str
    source_type: SourceType
    is_enabled: bool = True
    opsec_profile: str = "standard"
    credentials: dict[str, str] = Field(default_factory=dict)
    params: dict[str, Any] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)
    schedule: str | None = None
    last_run: datetime | None = None
    last_success: datetime | None = None
    last_error: str | None = None
    run_count: int = 0
    error_count: int = 0
    findings_produced: int = 0
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @field_validator("connector_id", "name")
    @classmethod
    def must_not_be_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("Field must not be empty")
        return v.strip()

    def record_run(self, findings_count: int = 0, error: str | None = None) -> None:
        """Update statistics after a connector run."""
        self.run_count += 1
        self.last_run = datetime.now(timezone.utc)
        self.updated_at = datetime.now(timezone.utc)
        if error:
            self.error_count += 1
            self.last_error = error
        else:
            self.last_success = datetime.now(timezone.utc)
            self.findings_produced += findings_count

    def __repr__(self) -> str:
        return f"ConnectorConfig(id={self.connector_id!r}, enabled={self.is_enabled})"
