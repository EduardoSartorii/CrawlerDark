"""Governance and operational domain entities.

Responsibility
--------------
Watchlist, ThreatActor, Campaign, HuntJob and ConnectorConfig aggregates
support monitoring configuration, attribution, job tracking and connector
lifecycle. Prepared for future Django admin mapping.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from threat_hunting.core.domain.enums import (
    ConnectorStatus,
    HuntJobStatus,
    WatchlistType,
)
from threat_hunting.core.domain.value_objects import Confidence, utc_now


class Watchlist(BaseModel):
    """Named collection of monitored entries (keywords, VIPs, IOCs, etc.)."""

    model_config = ConfigDict(validate_assignment=True)

    id: str = Field(default_factory=lambda: __import__("uuid").uuid4().hex)
    name: str
    type: WatchlistType
    entries: list[str] = Field(default_factory=list)
    enabled: bool = True
    description: str = ""
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)
    metadata: dict[str, Any] = Field(default_factory=dict)

    def add_entry(self, entry: str) -> None:
        cleaned = entry.strip()
        if cleaned and cleaned not in self.entries:
            self.entries.append(cleaned)
            self.updated_at = utc_now()

    def remove_entry(self, entry: str) -> None:
        if entry in self.entries:
            self.entries.remove(entry)
            self.updated_at = utc_now()

    def contains(self, value: str, *, case_sensitive: bool = False) -> bool:
        if case_sensitive:
            return value in self.entries
        lower = value.lower()
        return any(e.lower() == lower for e in self.entries)


class ThreatActor(BaseModel):
    """Threat actor attribution entity."""

    model_config = ConfigDict(validate_assignment=True)

    id: str = Field(default_factory=lambda: __import__("uuid").uuid4().hex)
    name: str
    aliases: list[str] = Field(default_factory=list)
    ttps: list[str] = Field(default_factory=list)
    confidence: Confidence = Field(default_factory=Confidence)
    description: str = ""
    countries: list[str] = Field(default_factory=list)
    malware_families: list[str] = Field(default_factory=list)
    enabled: bool = True
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)

    def matches_name(self, text: str) -> bool:
        haystack = text.lower()
        names = [self.name.lower(), *[a.lower() for a in self.aliases]]
        return any(n in haystack for n in names if n)


class Campaign(BaseModel):
    """Correlated campaign grouping findings, actors and IOCs."""

    model_config = ConfigDict(validate_assignment=True)

    id: str = Field(default_factory=lambda: __import__("uuid").uuid4().hex)
    name: str
    description: str = ""
    finding_ids: list[str] = Field(default_factory=list)
    actor_ids: list[str] = Field(default_factory=list)
    ioc_values: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    first_seen: datetime = Field(default_factory=utc_now)
    last_seen: datetime = Field(default_factory=utc_now)
    metadata: dict[str, Any] = Field(default_factory=dict)

    def link_finding(self, finding_id: str) -> None:
        if finding_id not in self.finding_ids:
            self.finding_ids.append(finding_id)
            self.last_seen = utc_now()


class HuntJob(BaseModel):
    """Unit of work representing a single hunt execution."""

    model_config = ConfigDict(validate_assignment=True)

    id: str = Field(default_factory=lambda: __import__("uuid").uuid4().hex)
    connector: str
    status: HuntJobStatus = HuntJobStatus.PENDING
    started_at: datetime | None = None
    finished_at: datetime | None = None
    findings_count: int = 0
    duplicates_count: int = 0
    errors_count: int = 0
    error_message: str | None = None
    stats: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)

    def start(self) -> None:
        self.status = HuntJobStatus.RUNNING
        self.started_at = utc_now()

    def complete(self, *, partial: bool = False) -> None:
        self.status = HuntJobStatus.PARTIAL if partial else HuntJobStatus.COMPLETED
        self.finished_at = utc_now()

    def fail(self, message: str) -> None:
        self.status = HuntJobStatus.FAILED
        self.error_message = message
        self.finished_at = utc_now()

    def record_finding(self, *, is_duplicate: bool = False) -> None:
        self.findings_count += 1
        if is_duplicate:
            self.duplicates_count += 1

    def record_error(self) -> None:
        self.errors_count += 1


class ConnectorConfig(BaseModel):
    """Runtime configuration for a connector (enable/disable, OPSEC, schedule)."""

    model_config = ConfigDict(validate_assignment=True)

    name: str
    enabled: bool = True
    status: ConnectorStatus = ConnectorStatus.ENABLED
    opsec_profile: str = "default"
    schedule: str | None = None  # cron expression
    options: dict[str, Any] = Field(default_factory=dict)
    category_group: str = "other"  # social, darkweb, threat_intel, …
    description: str = ""
    updated_at: datetime = Field(default_factory=utc_now)

    def enable(self) -> None:
        self.enabled = True
        self.status = ConnectorStatus.ENABLED
        self.updated_at = utc_now()

    def disable(self) -> None:
        self.enabled = False
        self.status = ConnectorStatus.DISABLED
        self.updated_at = utc_now()


__all__ = [
    "Watchlist",
    "ThreatActor",
    "Campaign",
    "HuntJob",
    "ConnectorConfig",
]
