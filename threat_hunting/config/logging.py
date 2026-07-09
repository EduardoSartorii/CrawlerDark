"""
Structured Logging Configuration.

Sets up structlog with JSON output for production and console output for development.
All platform components use this shared logging setup.

Features:
    - Structured JSON logs for production (machine-parseable)
    - Pretty console logs for development
    - Automatic context binding (connector, run_id, etc.)
    - OpenTelemetry trace ID injection
    - Log level configurable via environment variable
"""

from __future__ import annotations

import logging
import os
import sys
from typing import Any

import structlog


def configure_logging(
    level: str = "INFO",
    json_logs: bool = False,
    service_name: str = "threat-hunting",
) -> None:
    """
    Configure structlog for the entire platform.

    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        json_logs: True for JSON output (production), False for console (dev)
        service_name: Service name injected into all log records
    """
    log_level = getattr(logging, level.upper(), logging.INFO)

    # Shared processors for all output formats
    shared_processors: list[Any] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
    ]

    if json_logs:
        # Production: JSON output, machine-parseable
        processors = shared_processors + [
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ]
    else:
        # Development: pretty, human-readable console output
        processors = shared_processors + [
            structlog.dev.ConsoleRenderer(colors=True),
        ]

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    # Configure stdlib logging to route through structlog
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=log_level,
    )

    # Quiet noisy libraries
    for noisy_logger in ["httpx", "httpcore", "asyncio", "sqlalchemy.engine"]:
        logging.getLogger(noisy_logger).setLevel(logging.WARNING)

    # Add service context to all logs
    structlog.contextvars.bind_contextvars(service=service_name)


def get_logger(name: str) -> structlog.BoundLogger:
    """Get a named structlog logger."""
    return structlog.get_logger(name)
