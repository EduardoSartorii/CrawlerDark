"""Configuração de logging estruturado da plataforma.

Arquitetura
-----------
Usa :mod:`structlog` sobre a stdlib ``logging`` para produzir logs
estruturados (JSON ou console legível). Todos os módulos obtêm loggers via
:func:`get_logger`, garantindo formato e contexto consistentes.

Responsabilidade do componente
------------------------------
* Registrar erros, exceções, IOCs extraídos, eventos enviados ao MISP e
  scores calculados de forma estruturada (chave/valor) para facilitar a
  ingestão por um SIEM.

Fluxo de execução
-----------------
``configure_logging(cfg)`` é chamado uma vez na inicialização; em seguida,
cada módulo chama ``get_logger(__name__)`` para obter um logger vinculado.
"""

from __future__ import annotations

import logging
import sys

import structlog

from phishing_intel.config.settings import LoggingConfig

# Flag interna para evitar reconfiguração acidental (idempotência).
_CONFIGURED = False


def configure_logging(config: LoggingConfig | None = None) -> None:
    """Configura o pipeline de logging estruturado.

    Args:
        config: Configuração de logging. Se ``None``, usa os padrões.

    A função é idempotente: chamá-la múltiplas vezes reconfigura os
    processadores, o que é útil em testes que alternam níveis/formatos.
    """
    global _CONFIGURED

    cfg = config or LoggingConfig()
    level = getattr(logging, cfg.level, logging.INFO)

    # Handler básico da stdlib — structlog encaminha a renderização final.
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=level,
        force=True,
    )

    # Processadores comuns: adicionam nível, logger, timestamp ISO e
    # informações de exceção quando presentes.
    processors: list = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.StackInfoRenderer(),
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.format_exc_info,
    ]

    # Renderer final: JSON para produção/coleta, console colorido em dev.
    if cfg.json_output:
        processors.append(structlog.processors.JSONRenderer())
    else:
        processors.append(structlog.dev.ConsoleRenderer())

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(level),
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )

    _CONFIGURED = True


def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    """Retorna um logger estruturado vinculado.

    Garante que o logging esteja configurado (com padrões) mesmo que
    :func:`configure_logging` ainda não tenha sido chamado explicitamente.

    Args:
        name: Nome do logger (normalmente ``__name__`` do módulo chamador).

    Returns:
        Um logger estruturado pronto para uso.
    """
    if not _CONFIGURED:
        configure_logging()
    return structlog.get_logger(name)
