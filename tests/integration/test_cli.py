"""Integration tests for the Typer CLI via CliRunner."""

from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from threat_hunting.cli.main import app

runner = CliRunner()


@pytest.fixture
def config_file(tmp_path):
    """Write a temporary memory-backed settings file for isolated CLI runs."""
    cfg = tmp_path / "settings.yml"
    cfg.write_text(
        "storage:\n  backend: memory\n"
        "opsec:\n  offline: true\n"
        "watchlists_file: config/watchlists.yml\n",
        encoding="utf-8",
    )
    return str(cfg)


def test_cli_version():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert result.stdout.strip()


def test_cli_connector_list(config_file):
    result = runner.invoke(app, ["connector", "list", "-c", config_file])
    assert result.exit_code == 0
    assert "sample_paste" in result.stdout


def test_cli_connector_enable_disable(config_file):
    assert runner.invoke(app, ["connector", "disable", "reddit", "-c", config_file]).exit_code == 0
    assert runner.invoke(app, ["connector", "enable", "reddit", "-c", config_file]).exit_code == 0


def test_cli_run_outputs_summary(config_file):
    result = runner.invoke(app, ["run", "sample_paste", "-c", config_file])
    assert result.exit_code == 0
    # The summary is printed with indent=2 and begins with '{\n  "run_id"'.
    start = result.stdout.index('{\n  "run_id"')
    payload = json.loads(result.stdout[start:])
    assert payload["findings_collected"] == 3


def test_cli_score_test(config_file):
    result = runner.invoke(app, ["score", "test", "-c", config_file])
    assert result.exit_code == 0
    assert "run_id=" in result.stdout


def test_cli_scheduler_run(config_file):
    result = runner.invoke(
        app, ["scheduler", "run", "-t", "sample_paste", "--once", "-c", config_file]
    )
    assert result.exit_code == 0
    assert "sample_paste" in result.stdout


def test_cli_health(config_file):
    result = runner.invoke(app, ["health", "-c", config_file])
    assert result.exit_code == 0
    assert "components" in result.stdout
