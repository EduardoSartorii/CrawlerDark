"""OpenTelemetry tracing hooks.

Responsibility
--------------
Provide a tiny tracing facade with a ``span`` context manager. When the
OpenTelemetry SDK is present it produces real spans; otherwise it is a no-op, so
instrumented code paths are identical regardless of environment.
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator


class Tracer:
    """Facade over OpenTelemetry with a no-op fallback."""

    def __init__(self, service_name: str = "threat_hunting") -> None:
        self._tracer = self._try_tracer(service_name)

    @staticmethod
    def _try_tracer(service_name: str):
        try:
            from opentelemetry import trace
        except ImportError:
            return None
        return trace.get_tracer(service_name)

    @property
    def enabled(self) -> bool:
        """Whether a real OpenTelemetry tracer is active."""
        return self._tracer is not None

    @contextmanager
    def span(self, name: str, **attributes: str) -> Iterator[None]:
        """Start a span for ``name`` (no-op when OpenTelemetry is absent)."""
        if self._tracer is None:
            yield
            return
        with self._tracer.start_as_current_span(name) as span:  # pragma: no cover - needs SDK
            for key, value in attributes.items():
                span.set_attribute(key, value)
            yield
