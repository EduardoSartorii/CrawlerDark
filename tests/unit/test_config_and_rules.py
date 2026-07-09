"""Unit tests for settings loading and YAML rule/watchlist repositories."""

from __future__ import annotations

import textwrap

from threat_hunting.infrastructure.config.settings import load_settings
from threat_hunting.infrastructure.detections.rule_repository import (
    YamlRuleRepository,
    YamlWatchlistRepository,
    build_rule,
)


def test_load_settings_yaml_and_env_override(tmp_path, monkeypatch) -> None:
    cfg = tmp_path / "settings.yml"
    cfg.write_text(
        textwrap.dedent(
            """
            storage:
              backend: json
              json_path: out.jsonl
            export:
              auto_export_threshold: 55.0
            """
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("TH_DETECTION_THRESHOLD", "3")
    settings = load_settings(cfg)
    assert settings.storage.backend == "json"
    assert settings.export.auto_export_threshold == 55.0
    assert settings.detection_threshold == 3.0


def test_load_settings_missing_file_uses_defaults(tmp_path) -> None:
    settings = load_settings(tmp_path / "nope.yml")
    assert settings.storage.backend == "sqlite"


def test_build_rule_kinds_and_disabled() -> None:
    assert build_rule({"kind": "regex", "id": "r", "pattern": "x", "weight": 1}).kind == "regex"
    assert build_rule({"kind": "keyword", "terms": ["a"]}).kind == "keyword"
    assert build_rule({"kind": "composite", "rules": [{"kind": "ioc"}]}).kind == "composite"
    assert build_rule({"kind": "keyword", "enabled": False, "terms": ["a"]}) is None
    assert build_rule({"kind": "unknown"}) is None


def test_yaml_rule_repository_loads_directory(tmp_path) -> None:
    (tmp_path / "r.yml").write_text(
        "rules:\n  - {id: k, kind: keyword, terms: [leak], weight: 5}\n",
        encoding="utf-8",
    )
    rules = YamlRuleRepository(tmp_path).load()
    assert len(rules) == 1 and rules[0].id == "k"


def test_yaml_watchlist_repository(tmp_path) -> None:
    (tmp_path / "wl.yml").write_text(
        textwrap.dedent(
            """
            watchlists:
              - name: brand
                category: brand_monitoring
                keywords: ["acme", {term: "corp", weight: 12}]
                actors:
                  - {name: LockBit3, aliases: [lockbit]}
            """
        ),
        encoding="utf-8",
    )
    watchlists = YamlWatchlistRepository(tmp_path / "wl.yml").load()
    assert watchlists[0].name == "brand"
    assert len(watchlists[0].keywords) == 2
    assert watchlists[0].actors[0].name == "LockBit3"
