"""BaseConnector — classe base abstrata.

Todo connector concreto herda esta classe e implementa **no mínimo**:
    * ``async def collect(self)`` — assíncrono gerador de payloads.
    * ``async def parse(self, payload)`` — payload → dict.
    * ``async def normalize(self, parsed)`` — dict → ``Finding``.

Métodos padrão de ``connect``/``close``/``health`` já vêm implementados,
mas podem ser sobrescritos.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import AsyncIterator
from typing import Any

from ...core.domain.entities import Finding
from ..opsec.opsec_http_client import OpsecHTTPClient


class BaseConnector(ABC):
    """Contrato + utilidades comuns.

    Attributes:
        name: identificador canônico (deve casar com o registrado no registry).
        options: dicionário de configuração vindo de ``config/connectors.yaml``.
        http: cliente HTTP OPSEC-aware injetado pelo composition root.
    """

    name: str = ""
    default_source: str = ""
    default_category: str = "OTHER"

    def __init__(
        self,
        *,
        options: dict[str, Any] | None = None,
        http: OpsecHTTPClient | None = None,
    ) -> None:
        self.options = options or {}
        self.http = http
        self._connected = False

    async def connect(self) -> None:
        self._connected = True

    async def close(self) -> None:
        self._connected = False
        if self.http is not None:
            try:
                await self.http.close()
            except Exception:  # noqa: BLE001
                pass

    async def health(self) -> bool:
        return True

    # --- Contrato principal -------------------------------------------------

    @abstractmethod
    def collect(self) -> AsyncIterator[Any]:  # type: ignore[override]
        """Gerador assíncrono de payloads brutos."""

    @abstractmethod
    async def parse(self, payload: Any) -> dict[str, Any]: ...

    @abstractmethod
    async def normalize(self, parsed: dict[str, Any]) -> Finding: ...
