"""Base connector contract implementation for all data source adapters."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Sequence
from typing import Any

from threat_hunting.core.contracts import ConnectorPort, OpsecTransportPort
from threat_hunting.domain.entities import ExecutionContext, Finding
from threat_hunting.normalizers.default_normalizer import DefaultNormalizer
from threat_hunting.parsers.default_parser import DefaultParser


class BaseConnector(ConnectorPort, ABC):
    """Base connector with shared parser/normalizer wiring."""

    name = "base"

    def __init__(
        self,
        transport: OpsecTransportPort | None = None,
        parser: DefaultParser | None = None,
        normalizer: DefaultNormalizer | None = None,
    ) -> None:
        self.transport = transport
        self._parser = parser or DefaultParser()
        self._normalizer = normalizer or DefaultNormalizer()
        self._is_connected = False

    @abstractmethod
    def connect(self) -> None:
        """Initialize source-specific sessions."""

    @abstractmethod
    def collect(self, context: ExecutionContext) -> Sequence[dict[str, Any]]:
        """Collect source raw documents."""

    def parse(self, raw_items: Sequence[dict[str, Any]]) -> Sequence[dict[str, Any]]:
        """Apply default parser strategy."""
        return self._parser.process(raw_items)

    def normalize(self, parsed_items: Sequence[dict[str, Any]]) -> Sequence[Finding]:
        """Apply default normalizer strategy."""
        return self._normalizer.process(parsed_items, connector_name=self.name)

    @abstractmethod
    def health(self) -> bool:
        """Source health state."""

    @abstractmethod
    def close(self) -> None:
        """Release source resources."""
