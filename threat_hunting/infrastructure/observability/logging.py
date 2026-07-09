"""Structured logging (structlog).

Responsibility
--------------
Configure and expose structured, JSON-capable logging. ``structlog`` is used
when available; otherwise a thin stdlib-``logging`` shim provides the same
``logger.info("event", key=value)`` call style, so callers never branch on
whether structlog is installed.
"""

from __future__ import annotations

import logging
from typing import Any

_configured = False


def configure_logging(level: str = "INFO", json_output: bool = True) -> None:
    """Configure structlog (or stdlib fallback) once for the process."""
    global _configured
    if _configured:
        return
    logging.basicConfig(level=getattr(logging, level.upper(), logging.INFO), format="%(message)s")
    try:
        import structlog

        processors = [
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
        ]
        processors.append(
            structlog.processors.JSONRenderer()
            if json_output
            else structlog.dev.ConsoleRenderer()
        )
        structlog.configure(
            processors=processors,
            wrapper_class=structlog.make_filtering_bound_logger(
                getattr(logging, level.upper(), logging.INFO)
            ),
            logger_factory=structlog.PrintLoggerFactory(),
            cache_logger_on_first_use=True,
        )
    except ImportError:
        pass
    _configured = True


class _StdlibShim:
    """Minimal structlog-like adapter over stdlib logging (kwargs -> extras)."""

    def __init__(self, name: str) -> None:
        self._logger = logging.getLogger(name)

    def _emit(self, level: int, event: str, **kwargs: Any) -> None:
        extras = " ".join(f"{k}={v}" for k, v in kwargs.items())
        self._logger.log(level, "%s %s", event, extras)

    def debug(self, event: str, **kwargs: Any) -> None:
        self._emit(logging.DEBUG, event, **kwargs)

    def info(self, event: str, **kwargs: Any) -> None:
        self._emit(logging.INFO, event, **kwargs)

    def warning(self, event: str, **kwargs: Any) -> None:
        self._emit(logging.WARNING, event, **kwargs)

    def error(self, event: str, **kwargs: Any) -> None:
        self._emit(logging.ERROR, event, **kwargs)


def get_logger(name: str = "threat_hunting") -> Any:
    """Return a bound structlog logger, or a stdlib shim when unavailable."""
    try:
        import structlog

        return structlog.get_logger(name)
    except ImportError:
        return _StdlibShim(name)
