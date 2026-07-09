"""Subpacote de configuração.

Responsabilidade
----------------
Centralizar o carregamento e a validação da configuração da plataforma a
partir de um arquivo YAML (``config.yaml``), expondo objetos tipados via
Pydantic para o restante do sistema.
"""

from __future__ import annotations

from phishing_intel.config.settings import (
    AppConfig,
    DatabaseConfig,
    LoggingConfig,
    MISPConfig,
    load_config,
)

__all__ = [
    "AppConfig",
    "DatabaseConfig",
    "LoggingConfig",
    "MISPConfig",
    "load_config",
]
