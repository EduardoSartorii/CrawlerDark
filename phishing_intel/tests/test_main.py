"""Integration tests for the CLI entry point."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from phishing_intel import main


def _write_config(tmp_path: Path) -> Path:
    """Write a minimal offline config pointing evidence at tmp_path."""

    cfg = tmp_path / "config.yaml"
    cfg.write_text(
        "app:\n"
        "  allow_network: false\n"
        f"  evidence_dir: {tmp_path / 'evidence'}\n"
        "misp:\n"
        "  enabled: false\n"
        "database:\n"
        f"  url: sqlite:///{tmp_path / 'test.db'}\n",
        encoding="utf-8",
    )
    return cfg


def test_cli_inline_sample(tmp_path: Path, phishing_html: str, capsys) -> None:
    cfg = _write_config(tmp_path)
    html_file = tmp_path / "page.html"
    html_file.write_text(phishing_html, encoding="utf-8")

    exit_code = main.run(
        [
            "--config", str(cfg),
            "--url", "https://itau-secure.example/login",
            "--html-file", str(html_file),
            "--no-db",
        ]
    )
    assert exit_code == 0
    reports = json.loads(capsys.readouterr().out)
    assert reports[0]["target_brand"] == "itau"
    assert reports[0]["phishing_type"] == "credential_harvesting"
    assert reports[0]["tags"]


def test_cli_batch_input(tmp_path: Path, phishing_html: str, capsys) -> None:
    cfg = _write_config(tmp_path)
    batch = tmp_path / "samples.json"
    batch.write_text(
        json.dumps(
            [
                {"url": "https://a.example", "html": phishing_html},
                {"url": "https://b.example", "html": phishing_html},
            ]
        ),
        encoding="utf-8",
    )
    exit_code = main.run(["--config", str(cfg), "--input", str(batch)])
    assert exit_code == 0
    reports = json.loads(capsys.readouterr().out)
    assert len(reports) == 2


def test_cli_requires_url_or_input(tmp_path: Path) -> None:
    cfg = _write_config(tmp_path)
    with pytest.raises(SystemExit):
        main.run(["--config", str(cfg), "--no-db"])


def test_cli_entrypoint_wrapper(tmp_path: Path, phishing_html: str, mocker) -> None:
    # cli() wraps run() in SystemExit with the returned code.
    mocker.patch.object(main, "run", return_value=0)
    with pytest.raises(SystemExit) as exc:
        main.cli()
    assert exc.value.code == 0
