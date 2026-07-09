"""Unit tests for observability helpers and settings loading."""

from __future__ import annotations

from threat_hunting.config.settings import Settings, load_settings
from threat_hunting.infrastructure.observability.health import HealthCheck
from threat_hunting.infrastructure.observability.logging import get_logger
from threat_hunting.infrastructure.observability.metrics import Metrics
from threat_hunting.infrastructure.observability.tracing import Tracer


def test_metrics_record_without_error():
    metrics = Metrics()
    metrics.findings_total.labels(connector="c", severity="high").inc()
    metrics.exports_total.labels(exporter="json").inc(2)
    # No exception is the assertion; value is inspectable in the fallback path.
    assert metrics is not None


def test_tracer_span_context_manager():
    tracer = Tracer()
    with tracer.span("op", attr="v"):
        pass


def test_logger_emits(capsys):
    logger = get_logger("t")
    logger.info("evt", key="value")


def test_health_check_aggregates_probes():
    check = HealthCheck()
    check.add_probe("ok", lambda: (True, "fine"))
    check.add_probe("bad", lambda: (False, "broken"))
    report = check.run()
    assert report.healthy is False
    names = {c.component for c in report.components}
    assert {"ok", "bad"} <= names


def test_health_probe_exception_is_captured():
    check = HealthCheck()

    def boom():
        raise RuntimeError("x")

    check.add_probe("boom", boom)
    report = check.run()
    assert report.healthy is False


def test_settings_defaults_and_env_override(monkeypatch):
    monkeypatch.setenv("TH_STORAGE_BACKEND", "memory")
    monkeypatch.setenv("TH_SCORE_THRESHOLD", "42")
    settings = Settings().apply_env_overrides()
    assert settings.storage.backend == "memory"
    assert settings.export.score_threshold == 42.0


def test_load_settings_from_yaml():
    settings = load_settings("config/settings.yml")
    assert settings.storage.backend in {"memory", "json", "sqlite"}
    assert "tor" in settings.opsec.profiles
