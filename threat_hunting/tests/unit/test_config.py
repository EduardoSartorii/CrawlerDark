"""Unit tests for platform configuration."""

from pathlib import Path

from threat_hunting.config.settings import PlatformConfig


def test_config_defaults():
    config = PlatformConfig()
    assert config.database.url.startswith("sqlite")
    assert config.export.auto_export_threshold == 70.0


def test_config_from_yaml():
    config_path = Path(__file__).parent.parent.parent / "config" / "platform.yaml"
    config = PlatformConfig.from_yaml(config_path)
    assert "reddit" in config.connectors
