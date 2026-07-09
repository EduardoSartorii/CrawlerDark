"""Testes do ConfigLoader (YAML + resolução ${env:VAR})."""

from __future__ import annotations

from pathlib import Path

from threat_hunting.infrastructure.config import ConfigLoader


def test_loads_settings_from_repo_config():
    settings = ConfigLoader("config").load_settings()
    assert settings.app.name == "threat-hunting"
    assert "parse" in settings.pipeline.stages
    assert "default" in settings.opsec.profiles


def test_env_placeholder_resolution(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("MYSECRET_ABC", "s3cr3t")
    (tmp_path / "settings.yaml").write_text(
        """
app:
  name: t
  environment: development
  timezone: UTC
logging:
  level: INFO
  json: true
  redact_keys: []
storage:
  backend: sqlalchemy
  sqlalchemy:
    url: "sqlite:///:memory:"
    echo: false
    pool_size: 1
    max_overflow: 0
  json:
    root: ./data
observability:
  prometheus:
    enabled: false
    port: 9464
  opentelemetry:
    enabled: false
    endpoint: http://x
    service_name: t
opsec:
  default_profile: default
  profiles:
    default:
      proxy: null
      timeout_seconds: 1
      retries: 0
      backoff_seconds: 0
      jitter_seconds: 0
      rate_limit_per_second: 1
      user_agents: []
      headers: {}
scheduler:
  timezone: UTC
  jobs: []
exporters:
  autoexport_score_threshold: 80
  autoexport_targets: []
pipeline:
  stages: [parse]
  disabled: []
""",
        encoding="utf-8",
    )
    (tmp_path / "connectors.yaml").write_text(
        """
connectors:
  demo:
    type: rss
    enabled: true
    opsec_profile: default
    options:
      token: ${env:MYSECRET_ABC}
""",
        encoding="utf-8",
    )
    loader = ConfigLoader(tmp_path)
    _ = loader.load_settings()
    connectors = loader.load_connectors()
    assert connectors["demo"].options["token"] == "s3cr3t"
