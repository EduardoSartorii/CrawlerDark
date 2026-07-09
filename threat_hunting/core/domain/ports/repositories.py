"""
Repository Ports
================

Abstract repository interfaces following the Repository Pattern.
Each aggregate root has its own repository contract.

Design principles:
    - Repositories are collection-like — they hide persistence details.
    - Queries return domain objects, never ORM models.
    - Repositories are async — all I/O is non-blocking.
    - Filtering is done via typed criteria dicts, not SQL strings.
    - The repository never exposes transaction management — that is the
      responsibility of the UnitOfWork.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from threat_hunting.core.domain.entities.connector_config import ConnectorConfig
    from threat_hunting.core.domain.entities.finding import Finding
    from threat_hunting.core.domain.entities.indicator import Indicator
    from threat_hunting.core.domain.entities.keyword import Keyword
    from threat_hunting.core.domain.entities.rule import Rule
    from threat_hunting.core.domain.entities.threat_actor import ThreatActor
    from threat_hunting.core.domain.entities.vip import VIP


class IFindingRepository(ABC):
    """Repository for the Finding aggregate."""

    @abstractmethod
    async def save(self, finding: "Finding") -> None: ...

    @abstractmethod
    async def get_by_id(self, finding_id: str) -> "Finding | None": ...

    @abstractmethod
    async def list(
        self,
        *,
        limit: int = 100,
        offset: int = 0,
        connector: str | None = None,
        severity: str | None = None,
        category: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        tags: list[str] | None = None,
        status: str | None = None,
        search: str | None = None,
    ) -> list["Finding"]: ...

    @abstractmethod
    async def count(self, criteria: dict[str, Any] | None = None) -> int: ...

    @abstractmethod
    async def delete(self, finding_id: str) -> None: ...

    @abstractmethod
    async def exists_by_hash(self, content_hash: str) -> bool:
        """Check for duplicate by content hash (deduplication support)."""

    @abstractmethod
    async def find_similar(self, finding: "Finding", threshold: float) -> list["Finding"]:
        """Return Findings similar to the given one (correlation support)."""


class IIndicatorRepository(ABC):
    """Repository for the Indicator aggregate."""

    @abstractmethod
    async def save(self, indicator: "Indicator") -> None: ...

    @abstractmethod
    async def get_by_id(self, indicator_id: str) -> "Indicator | None": ...

    @abstractmethod
    async def get_by_value(self, ioc_type: str, value: str) -> "Indicator | None": ...

    @abstractmethod
    async def list(
        self,
        *,
        limit: int = 100,
        offset: int = 0,
        ioc_type: str | None = None,
        since: datetime | None = None,
    ) -> list["Indicator"]: ...

    @abstractmethod
    async def count(self) -> int: ...


class IKeywordRepository(ABC):
    """Repository for Keyword entities."""

    @abstractmethod
    async def save(self, keyword: "Keyword") -> None: ...

    @abstractmethod
    async def get_by_id(self, keyword_id: str) -> "Keyword | None": ...

    @abstractmethod
    async def list_enabled(self) -> list["Keyword"]: ...

    @abstractmethod
    async def list_all(self) -> list["Keyword"]: ...

    @abstractmethod
    async def delete(self, keyword_id: str) -> None: ...


class IVIPRepository(ABC):
    """Repository for VIP entities."""

    @abstractmethod
    async def save(self, vip: "VIP") -> None: ...

    @abstractmethod
    async def get_by_id(self, vip_id: str) -> "VIP | None": ...

    @abstractmethod
    async def list_enabled(self) -> list["VIP"]: ...

    @abstractmethod
    async def list_all(self) -> list["VIP"]: ...

    @abstractmethod
    async def delete(self, vip_id: str) -> None: ...


class IThreatActorRepository(ABC):
    """Repository for ThreatActor entities."""

    @abstractmethod
    async def save(self, actor: "ThreatActor") -> None: ...

    @abstractmethod
    async def get_by_id(self, actor_id: str) -> "ThreatActor | None": ...

    @abstractmethod
    async def get_by_name(self, name: str) -> "ThreatActor | None": ...

    @abstractmethod
    async def list_all(self) -> list["ThreatActor"]: ...

    @abstractmethod
    async def delete(self, actor_id: str) -> None: ...


class IRuleRepository(ABC):
    """Repository for detection Rule entities."""

    @abstractmethod
    async def save(self, rule: "Rule") -> None: ...

    @abstractmethod
    async def get_by_id(self, rule_id: str) -> "Rule | None": ...

    @abstractmethod
    async def list_enabled(self, rule_type: str | None = None) -> list["Rule"]: ...

    @abstractmethod
    async def list_all(self) -> list["Rule"]: ...

    @abstractmethod
    async def delete(self, rule_id: str) -> None: ...


class IConnectorConfigRepository(ABC):
    """Repository for ConnectorConfig entities."""

    @abstractmethod
    async def save(self, config: "ConnectorConfig") -> None: ...

    @abstractmethod
    async def get_by_id(self, config_id: str) -> "ConnectorConfig | None": ...

    @abstractmethod
    async def get_by_connector_id(self, connector_id: str) -> "ConnectorConfig | None": ...

    @abstractmethod
    async def list_enabled(self) -> list["ConnectorConfig"]: ...

    @abstractmethod
    async def list_all(self) -> list["ConnectorConfig"]: ...
