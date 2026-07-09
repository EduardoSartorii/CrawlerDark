"""Storage backends — pluggable persistence adapters."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from uuid import UUID

import structlog

from threat_hunting.core.contracts.services import IStorageBackend
from threat_hunting.core.domain.entities import Finding
from threat_hunting.core.domain.enums import HealthStatus, StorageBackendType

logger = structlog.get_logger(__name__)


class JsonStorageBackend(IStorageBackend):
    """JSON file storage backend for development and testing."""

    def __init__(self, base_path: str = "data/findings") -> None:
        self._base_path = Path(base_path)
        self._base_path.mkdir(parents=True, exist_ok=True)

    async def save_finding(self, finding: Finding) -> Finding:
        path = self._base_path / f"{finding.id}.json"
        path.write_text(finding.model_dump_json(indent=2))
        logger.debug("storage.json.saved", finding_id=str(finding.id))
        return finding

    async def get_finding(self, finding_id: str) -> Finding | None:
        path = self._base_path / f"{finding_id}.json"
        if not path.exists():
            return None
        return Finding.model_validate_json(path.read_text())

    async def list_findings(self, limit: int = 100) -> list[Finding]:
        findings = []
        for path in sorted(self._base_path.glob("*.json"))[:limit]:
            findings.append(Finding.model_validate_json(path.read_text()))
        return findings

    async def health(self) -> HealthStatus:
        return HealthStatus.HEALTHY if self._base_path.exists() else HealthStatus.UNHEALTHY


class SqliteStorageBackend(IStorageBackend):
    """SQLite storage via SQLAlchemy repository delegation."""

    def __init__(self, finding_repo: Any) -> None:
        self._repo = finding_repo

    async def save_finding(self, finding: Finding) -> Finding:
        return await self._repo.save(finding)

    async def get_finding(self, finding_id: str) -> Finding | None:
        return await self._repo.get_by_id(UUID(finding_id))

    async def list_findings(self, limit: int = 100) -> list[Finding]:
        return await self._repo.list_all(limit=limit)

    async def health(self) -> HealthStatus:
        return HealthStatus.HEALTHY


class StorageFactory:
    """Factory for creating storage backends based on configuration."""

    @staticmethod
    def create(backend_type: str, **kwargs: Any) -> IStorageBackend:
        if backend_type == StorageBackendType.JSON.value:
            return JsonStorageBackend(kwargs.get("base_path", "data/findings"))
        if backend_type == StorageBackendType.SQLITE.value:
            return SqliteStorageBackend(kwargs["finding_repo"])
        if backend_type in (StorageBackendType.POSTGRESQL.value,):
            return SqliteStorageBackend(kwargs["finding_repo"])
        raise ValueError(f"Unsupported storage backend: {backend_type}")
