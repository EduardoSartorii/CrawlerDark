"""Setup do structlog com JSON e redaction de PII/segredos."""

from __future__ import annotations

import logging
from collections.abc import Iterable

import structlog

_REDACTION_MASK = "***REDACTED***"


def _redact_processor(redact_keys: set[str]):  # type: ignore[no-untyped-def]
    def processor(_logger, _name, event_dict):  # type: ignore[no-untyped-def]
        for key in list(event_dict.keys()):
            if key.lower() in redact_keys:
                event_dict[key] = _REDACTION_MASK
        return event_dict
    return processor


def configure_logging(
    level: str = "INFO",
    *,
    json_output: bool = True,
    redact_keys: Iterable[str] = (),
) -> None:
    logging.basicConfig(format="%(message)s", level=getattr(logging, level.upper(), logging.INFO))
    processors: list = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        _redact_processor({k.lower() for k in redact_keys}),
    ]
    if json_output:
        processors.append(structlog.processors.JSONRenderer())
    else:
        processors.append(structlog.dev.ConsoleRenderer())
    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(getattr(logging, level.upper())),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    return structlog.get_logger(name) if name else structlog.get_logger()
