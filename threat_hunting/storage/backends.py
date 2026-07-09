"""Storage backend stubs — abstract backends beyond memory/SQLAlchemy.

Responsibility
--------------
Provide StorageBackendPort adapters for OpenSearch, Elasticsearch, Splunk,
JSON, Parquet, S3/Data Lake. Swap via DI without changing business rules.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Sequence

from threat_hunting.core.application.ports import StorageBackendPort
from threat_hunting.core.domain.entities import Finding
from threat_hunting.core.domain.enums import HealthState
from threat_hunting.core.domain.value_objects import HealthStatus, utc_now


class JsonFileStorageBackend(StorageBackendPort):
    """Persist findings as JSON files (one file or directory store)."""

    name = "json"

    def __init__(self, path: str = "data/findings.json") -> None:
        self._path = Path(path)
        self._findings: dict[str, dict[str, Any]] = {}

    async def initialize(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        if self._path.exists():
            data = json.loads(self._path.read_text(encoding="utf-8"))
            self._findings = {item["id"]: item for item in data}

    async def persist_finding(self, finding: Finding) -> None:
        self._findings[str(finding.id)] = finding.to_export_dict()
        self._path.write_text(
            json.dumps(list(self._findings.values()), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

    async def fetch_finding(self, finding_id: str) -> Finding | None:
        data = self._findings.get(finding_id)
        if not data:
            return None
        return Finding.model_validate(
            {
                **data,
                "id": {"value": data["id"]},
                "score": {"value": data["score"]},
                "confidence": {"value": data["confidence"]},
                "tags": [{"name": t} for t in data.get("tags", [])],
                "indicators": data.get("indicators", []),
                "metadata": data.get("metadata", {}),
            }
        )

    async def query_findings(self, **filters: Any) -> Sequence[Finding]:
        limit = int(filters.get("limit", 100))
        results = []
        for fid in list(self._findings.keys())[:limit]:
            f = await self.fetch_finding(fid)
            if f:
                results.append(f)
        return results

    async def health(self) -> HealthStatus:
        return HealthStatus(
            component="storage:json",
            state=HealthState.HEALTHY.value,
            message=str(self._path),
            checked_at=utc_now(),
        )

    async def close(self) -> None:
        return None


class ParquetStorageBackend(StorageBackendPort):
    """Parquet/Data Lake stub — writes JSONL sidecar until pyarrow is optional."""

    name = "parquet"

    def __init__(self, path: str = "data/lake/findings.jsonl") -> None:
        self._path = Path(path)

    async def initialize(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)

    async def persist_finding(self, finding: Finding) -> None:
        with self._path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(finding.to_export_dict()) + "\n")

    async def fetch_finding(self, finding_id: str) -> Finding | None:
        if not self._path.exists():
            return None
        for line in self._path.read_text(encoding="utf-8").splitlines():
            data = json.loads(line)
            if data.get("id") == finding_id:
                return None  # full reconstruct optional; use memory/SQL for reads
        return None

    async def query_findings(self, **filters: Any) -> Sequence[Finding]:
        return []

    async def health(self) -> HealthStatus:
        return HealthStatus(
            component="storage:parquet",
            state=HealthState.HEALTHY.value,
            message=str(self._path),
            checked_at=utc_now(),
        )

    async def close(self) -> None:
        return None


class OpenSearchStorageBackend(StorageBackendPort):
    """OpenSearch/Elasticsearch stub — offline bulk file writer."""

    name = "opensearch"

    def __init__(self, path: str = "data/opensearch_bulk.ndjson", index: str = "findings") -> None:
        self._path = Path(path)
        self._index = index

    async def initialize(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)

    async def persist_finding(self, finding: Finding) -> None:
        with self._path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps({"index": {"_index": self._index, "_id": str(finding.id)}}) + "\n")
            fh.write(json.dumps(finding.to_export_dict()) + "\n")

    async def fetch_finding(self, finding_id: str) -> Finding | None:
        return None

    async def query_findings(self, **filters: Any) -> Sequence[Finding]:
        return []

    async def health(self) -> HealthStatus:
        return HealthStatus(
            component="storage:opensearch",
            state=HealthState.HEALTHY.value,
            message=self._index,
            checked_at=utc_now(),
        )

    async def close(self) -> None:
        return None


class SplunkStorageBackend(StorageBackendPort):
    name = "splunk"

    def __init__(self, path: str = "data/splunk_hec.jsonl") -> None:
        self._path = Path(path)

    async def initialize(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)

    async def persist_finding(self, finding: Finding) -> None:
        with self._path.open("a", encoding="utf-8") as fh:
            fh.write(
                json.dumps(
                    {
                        "event": finding.to_export_dict(),
                        "sourcetype": "threat_hunting:finding",
                        "source": finding.connector,
                    }
                )
                + "\n"
            )

    async def fetch_finding(self, finding_id: str) -> Finding | None:
        return None

    async def query_findings(self, **filters: Any) -> Sequence[Finding]:
        return []

    async def health(self) -> HealthStatus:
        return HealthStatus(
            component="storage:splunk",
            state=HealthState.HEALTHY.value,
            message=str(self._path),
            checked_at=utc_now(),
        )

    async def close(self) -> None:
        return None


class S3StorageBackend(StorageBackendPort):
    """S3 / Data Lake stub — writes to local prefix mimicking object keys."""

    name = "s3"

    def __init__(self, prefix: str = "data/s3/findings") -> None:
        self._prefix = Path(prefix)

    async def initialize(self) -> None:
        self._prefix.mkdir(parents=True, exist_ok=True)

    async def persist_finding(self, finding: Finding) -> None:
        key = self._prefix / f"{finding.id.value}.json"
        key.write_text(json.dumps(finding.to_export_dict(), indent=2), encoding="utf-8")

    async def fetch_finding(self, finding_id: str) -> Finding | None:
        key = self._prefix / f"{finding_id}.json"
        if not key.exists():
            return None
        return None

    async def query_findings(self, **filters: Any) -> Sequence[Finding]:
        return []

    async def health(self) -> HealthStatus:
        return HealthStatus(
            component="storage:s3",
            state=HealthState.HEALTHY.value,
            message=str(self._prefix),
            checked_at=utc_now(),
        )

    async def close(self) -> None:
        return None


# Aliases for Elasticsearch / Data Lake
ElasticsearchStorageBackend = OpenSearchStorageBackend
DataLakeStorageBackend = ParquetStorageBackend


__all__ = [
    "JsonFileStorageBackend",
    "ParquetStorageBackend",
    "OpenSearchStorageBackend",
    "ElasticsearchStorageBackend",
    "SplunkStorageBackend",
    "S3StorageBackend",
    "DataLakeStorageBackend",
]
