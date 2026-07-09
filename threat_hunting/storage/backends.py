"""Storage ports and backend adapters.

Backends can be swapped without changing domain/application logic.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Protocol

from threat_hunting.core.contracts import StoragePort
from threat_hunting.domain.entities import Finding


class AbstractStorageAdapter(StoragePort):
    """Base storage adapter contract implementation."""

    backend_name = "abstract"

    def write_findings(self, findings: list[Finding]) -> None:
        raise NotImplementedError


class JsonStorageAdapter(AbstractStorageAdapter):
    """JSON storage backend for lightweight archival."""

    backend_name = "json"

    def __init__(self, output_path: str) -> None:
        self._output_path = Path(output_path)
        self._output_path.parent.mkdir(parents=True, exist_ok=True)

    def write_findings(self, findings: list[Finding]) -> None:
        payload = [finding.model_dump(mode="json") for finding in findings]
        with self._output_path.open("w", encoding="utf-8") as handler:
            json.dump(payload, handler, ensure_ascii=False, indent=2)


class SqliteStorageAdapter(AbstractStorageAdapter):
    """Placeholder for SQLite backend through repository/UoW path."""

    backend_name = "sqlite"

    def write_findings(self, findings: list[Finding]) -> None:
        return


class PostgreSQLStorageAdapter(AbstractStorageAdapter):
    """PostgreSQL adapter placeholder for future plug-in."""

    backend_name = "postgresql"

    def write_findings(self, findings: list[Finding]) -> None:
        return


class OpenSearchStorageAdapter(AbstractStorageAdapter):
    """OpenSearch adapter placeholder."""

    backend_name = "opensearch"

    def write_findings(self, findings: list[Finding]) -> None:
        return


class ElasticsearchStorageAdapter(AbstractStorageAdapter):
    """Elasticsearch adapter placeholder."""

    backend_name = "elasticsearch"

    def write_findings(self, findings: list[Finding]) -> None:
        return


class SplunkStorageAdapter(AbstractStorageAdapter):
    """Splunk adapter placeholder."""

    backend_name = "splunk"

    def write_findings(self, findings: list[Finding]) -> None:
        return


class ParquetStorageAdapter(AbstractStorageAdapter):
    """Parquet adapter placeholder."""

    backend_name = "parquet"

    def write_findings(self, findings: list[Finding]) -> None:
        return


class DataLakeStorageAdapter(AbstractStorageAdapter):
    """Data Lake adapter placeholder."""

    backend_name = "datalake"

    def write_findings(self, findings: list[Finding]) -> None:
        return


class S3StorageAdapter(AbstractStorageAdapter):
    """S3 adapter placeholder."""

    backend_name = "s3"

    def write_findings(self, findings: list[Finding]) -> None:
        return
