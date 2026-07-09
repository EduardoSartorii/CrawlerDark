"""Shared pytest fixtures for threat hunting platform tests."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml


@pytest.fixture()
def test_config_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Create isolated YAML config for each test execution."""
    config = {
        "environment": "test",
        "auto_export_threshold": 10,
        "opsec_profiles": [
            {
                "name": "default",
                "user_agent": "pytest-agent",
                "rate_limit_per_minute": 1000,
                "retries": 1,
                "backoff_seconds": 0.0,
                "verify_tls": True,
            }
        ],
        "enabled_connectors": {
            "reddit": True,
            "github": True,
            "telegram": True,
            "darkweb": True,
        },
        "dynamic_rules": [
            {
                "rule_id": "rule-keyword-credential",
                "name": "credential keyword",
                "rule_type": "keyword",
                "expression": "credential",
                "enabled": True,
            },
            {
                "rule_id": "rule-actor-darkspider",
                "name": "actor",
                "rule_type": "threat_actor_match",
                "expression": "darkspider",
                "enabled": True,
            },
        ],
    }
    config_path = tmp_path / "default.yml"
    config_path.write_text(yaml.safe_dump(config), encoding="utf-8")
    monkeypatch.setenv("THREAT_HUNTING_CONFIG", str(config_path))
    return config_path
