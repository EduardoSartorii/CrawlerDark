"""Storage backend contracts for future adapters."""

from __future__ import annotations

from enum import StrEnum
from typing import Protocol

from threat_hunting.core.application.ports import FindingRepository


class StorageBackend(StrEnum):
    """Supported persistence backend identifiers."""

    SQLITE = "sqlite"
    POSTGRESQL = "postgresql"
    OPENSEARCH = "opensearch"
    ELASTICSEARCH = "elasticsearch"
    SPLUNK = "splunk"
    JSON = "json"
    PARQUET = "parquet"
    DATA_LAKE = "data_lake"
    S3 = "s3"


class StorageAdapter(Protocol):
    """Contract implemented by every storage backend adapter."""

    backend: StorageBackend
    repository: FindingRepository
