"""Storage backend abstractions prepared for multiple persistence targets."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Sequence

from threat_hunting.domain.entities import Finding


class StorageBackend(ABC):
    """Common storage backend interface used by repository adapters."""

    name: str

    @abstractmethod
    def save_findings(self, findings: Sequence[Finding]) -> None:
        """Persist findings collection."""


class SqliteBackend(StorageBackend):
    """SQLite backend placeholder."""

    name = "sqlite"

    def save_findings(self, findings: Sequence[Finding]) -> None:
        return None


class PostgreSqlBackend(StorageBackend):
    """PostgreSQL backend placeholder."""

    name = "postgresql"

    def save_findings(self, findings: Sequence[Finding]) -> None:
        return None


class OpenSearchBackend(StorageBackend):
    """OpenSearch backend placeholder."""

    name = "opensearch"

    def save_findings(self, findings: Sequence[Finding]) -> None:
        return None


class ElasticsearchBackend(StorageBackend):
    """Elasticsearch backend placeholder."""

    name = "elasticsearch"

    def save_findings(self, findings: Sequence[Finding]) -> None:
        return None


class SplunkBackend(StorageBackend):
    """Splunk backend placeholder."""

    name = "splunk"

    def save_findings(self, findings: Sequence[Finding]) -> None:
        return None


class JsonBackend(StorageBackend):
    """JSON backend placeholder."""

    name = "json"

    def save_findings(self, findings: Sequence[Finding]) -> None:
        return None


class ParquetBackend(StorageBackend):
    """Parquet backend placeholder."""

    name = "parquet"

    def save_findings(self, findings: Sequence[Finding]) -> None:
        return None


class DataLakeBackend(StorageBackend):
    """Data Lake backend placeholder."""

    name = "datalake"

    def save_findings(self, findings: Sequence[Finding]) -> None:
        return None


class S3Backend(StorageBackend):
    """S3 backend placeholder."""

    name = "s3"

    def save_findings(self, findings: Sequence[Finding]) -> None:
        return None
