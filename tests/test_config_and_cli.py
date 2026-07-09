"""Configuration and CLI tests."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from threat_hunting.cli.app import app
from threat_hunting.infrastructure.config import PlatformSettings


def test_default_config_loads_dynamic_rules() -> None:
    """YAML config should load connectors, OPSEC, rules, scoring, and exporters."""

    settings = PlatformSettings.from_yaml(Path("config/default.yml"))

    assert "github" in settings.connectors
    assert settings.opsec_profiles["tor"].socks_proxy == "socks5://127.0.0.1:9050"
    assert settings.detection_rules[0].name == "credential keyword"
    assert settings.scoring.auto_export_threshold == 70


def test_cli_run_github_executes_real_pipeline(tmp_path: Path) -> None:
    """CLI should run the Typer command through the application use case."""

    config = tmp_path / "config.yml"
    config.write_text(
        """
connectors:
  github:
    enabled: true
    items:
      - title: "ACME credential exposure"
        description: "api_key leaked for admin@acme.test"
detection_rules:
  - name: "credential"
    type: "keyword"
    values: ["api_key"]
    weight: 20
    tags: ["credential"]
scoring:
  base_score: 1
  auto_export_threshold: 100
  weights:
    keyword: 1
storage:
  backend: "json"
  path: "%s"
exporters: {}
        """
        % (tmp_path / "findings.json"),
        encoding="utf-8",
    )

    result = CliRunner().invoke(app, ["run", "github", "--config", str(config), "--no-export"])

    assert result.exit_code == 0
    assert "collected=1 target=github" in result.stdout


def test_cli_score_test_uses_requested_command_shape(tmp_path: Path) -> None:
    """CLI should support `hunt score test` command shape."""

    config = tmp_path / "config.yml"
    config.write_text(
        """
connectors:
  github:
    enabled: true
    items:
      - title: "Observation"
        description: "api_key"
detection_rules:
  - name: "credential"
    type: "keyword"
    values: ["api_key"]
    weight: 10
scoring:
  base_score: 0
  auto_export_threshold: 100
storage:
  backend: "memory"
exporters: {}
        """,
        encoding="utf-8",
    )

    result = CliRunner().invoke(app, ["score", "test", "--config", str(config)])

    assert result.exit_code == 0
    assert "score=" in result.stdout
