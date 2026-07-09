"""Comandos imutáveis. Interpretados pelo composition root."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class RunConnectorCommand:
    connector: str


@dataclass(frozen=True, slots=True)
class RunAllCommand:
    only_enabled: bool = True


@dataclass(frozen=True, slots=True)
class ExportFindingsCommand:
    exporter: str
    min_score: float = 0.0
    limit: int = 500
