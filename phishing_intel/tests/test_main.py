"""Testes da CLI principal (main.py) - fluxo principal e secundario."""

from __future__ import annotations

from pathlib import Path

import yaml

import main as main_module


def _write_config(tmp_path: Path) -> Path:
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        yaml.safe_dump(
            {
                "database": {"url": f"sqlite:///{tmp_path / 'test.db'}", "echo": False},
                "misp": {"url": "https://misp.test", "api_key": "K"},
                "logging": {"level": "INFO", "json_format": False},
                "brands": {"known_brands": []},
            }
        ),
        encoding="utf-8",
    )
    return config_path


def test_main_primary_flow_with_supplied_html(tmp_path: Path, sample_html: str, sample_js: str) -> None:
    """Fluxo principal: HTML e JS ja fornecidos, sem qualquer coleta ativa."""
    html_path = tmp_path / "page.html"
    html_path.write_text(sample_html, encoding="utf-8")
    js_path = tmp_path / "page.js"
    js_path.write_text(sample_js, encoding="utf-8")
    config_path = _write_config(tmp_path)

    result = main_module.main(
        [
            "--url",
            "https://phish.example/login",
            "--html-file",
            str(html_path),
            "--js-file",
            str(js_path),
            "--no-misp",
            "--no-network-enrichment",
            "--config",
            str(config_path),
        ]
    )

    assert result.report.evidence.source == "partner_supplied"
    assert result.campaign.campaign_id.startswith("CAMP-")
    assert result.misp_event_uuid is None


def test_main_secondary_flow_collects_html_when_missing(tmp_path: Path, monkeypatch, sample_html) -> None:
    """Fluxo secundario: HTML nao fornecido, plataforma deve coleta-lo ativamente."""
    config_path = _write_config(tmp_path)

    class _FakeCollected:
        html = sample_html
        final_url = "https://phish.example/login"
        status_code = 200

    monkeypatch.setattr(main_module, "fetch_html", lambda url, settings: _FakeCollected())

    result = main_module.main(
        [
            "--url",
            "https://phish.example/login",
            "--no-misp",
            "--no-network-enrichment",
            "--config",
            str(config_path),
        ]
    )

    assert result.report.evidence.source == "collected"
