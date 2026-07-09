"""CLI and configuration integration tests."""

from pathlib import Path

from typer.testing import CliRunner

from threat_hunting.cli.main import app
from threat_hunting.infrastructure.config.settings import load_settings


def test_load_default_settings_contains_required_sections() -> None:
    """The default YAML defines connectors, OPSEC, detection and scoring."""

    settings = load_settings("config/default.yml")

    assert settings.connectors
    assert "default" in settings.opsec_profiles
    assert settings.detection_rules
    assert settings.score_policy.export_threshold > 0


def test_cli_score_test_runs_with_config() -> None:
    """The CLI score command runs the real extractor, detector and scorer."""

    result = CliRunner().invoke(app, ["score", "test", "--config", "config/default.yml"])

    assert result.exit_code == 0
    assert "VIP credential leak" in result.output
    assert "score" in result.output


def test_connector_disable_updates_yaml(tmp_path: Path) -> None:
    """Connector management commands mutate YAML configuration safely."""

    config_path = tmp_path / "config.yml"
    config_path.write_text(
        """
connectors:
  - name: reddit
    type: static
    source: reddit
    enabled: true
    config: {}
""",
        encoding="utf-8",
    )

    result = CliRunner().invoke(app, ["connector", "disable", "reddit", "--config", str(config_path)])

    assert result.exit_code == 0
    assert load_settings(config_path).connectors[0].enabled is False
