"""Structured logging bootstrap.

Responsibility
--------------
Provide a single :func:`configure_logging` entry point that wires ``structlog``
on top of the standard library ``logging`` module. Every component obtains a
logger through :func:`get_logger`, guaranteeing consistent, structured output
(errors, exceptions, extracted IOCs, MISP events, computed scores, ...).

Execution flow
--------------
``configure_logging(level, fmt)`` is called once at process start-up (from the
CLI / orchestrator). Thereafter modules call ``get_logger(__name__)`` to obtain
a bound structlog logger.
"""

from __future__ import annotations

import logging
import sys
from typing import Any

import structlog


def configure_logging(level: str = "INFO", fmt: str = "console") -> None:
    """Configure structlog + stdlib logging.

    Parameters
    ----------
    level:
        Log level name (``"DEBUG"``, ``"INFO"``, ...).
    fmt:
        ``"json"`` for machine ingestion or ``"console"`` for humans.
    """

    numeric_level = getattr(logging, level.upper(), logging.INFO)

    # Base stdlib configuration; structlog renders the final record.
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=numeric_level,
        force=True,
    )

    # Processors shared by both renderers: add timestamp, level and logger name.
    shared_processors: list[Any] = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]

    # Choose the terminal renderer based on the requested format.
    if fmt == "json":
        renderer: Any = structlog.processors.JSONRenderer()
    else:
        renderer = structlog.dev.ConsoleRenderer(colors=False)

    structlog.configure(
        processors=shared_processors + [renderer],
        wrapper_class=structlog.make_filtering_bound_logger(numeric_level),
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    """Return a bound structlog logger.

    Using a thin wrapper (rather than importing structlog everywhere) keeps the
    logging backend swappable and the call-sites uniform.
    """

    return structlog.get_logger(name)
