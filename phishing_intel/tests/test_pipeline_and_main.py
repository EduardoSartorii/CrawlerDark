"""Testes de integração do pipeline e da CLI."""

from __future__ import annotations

import json

from phishing_intel.models.infrastructure import (
    CertificateInfo,
    DnsRecords,
    InfrastructureInfo,
)
from phishing_intel.pipeline import AnalysisRequest, Pipeline
from phishing_intel import main as main_module


class _FakeMisp:
    """Cliente MISP falso que registra os payloads recebidos."""

    def __init__(self) -> None:
        self.pushed = []

    def push_event(self, payload):
        self.pushed.append(payload)
        return "1", "uuid-1"


def _build_pipeline(test_config, database, mocker, fake_misp=None):
    """Constrói um Pipeline com coletores mockados (offline)."""
    html_collector = mocker.Mock()
    html_collector.fetch.return_value = ("<html></html>", 200)

    ssl_collector = mocker.Mock()
    ssl_collector.collect.return_value = CertificateInfo(
        sha256_fingerprint="fp", serial_number="1", pem="PEM"
    )
    dns_collector = mocker.Mock()
    dns_collector.resolve.return_value = DnsRecords(domain="x")
    infra_collector = mocker.Mock()
    infra_collector.collect.return_value = InfrastructureInfo(
        ip="1.1.1.1", asn="AS100", hosting_provider="EvilHost"
    )

    return Pipeline(
        config=test_config,
        database=database,
        html_collector=html_collector,
        ssl_collector=ssl_collector,
        dns_collector=dns_collector,
        infra_collector=infra_collector,
        misp_client=fake_misp,
    )


def test_pipeline_main_flow_with_provided_html(
    test_config, database, mocker, sample_html, sample_js
):
    """Fluxo principal: HTML/JS fornecidos são analisados e correlacionados."""
    fake_misp = _FakeMisp()
    pipeline = _build_pipeline(test_config, database, mocker, fake_misp)
    result = pipeline.process(
        AnalysisRequest(
            url="https://livelo-fake.tld/login",
            html=sample_html,
            javascript=sample_js,
        )
    )
    assert result.analysis.brand.brand == "livelo"
    assert result.analysis.phishing_types  # objetivos detectados
    assert result.analysis.exfiltration  # destinos detectados
    assert result.campaign.campaign_id
    assert result.evidence_path  # evidências gravadas
    # Como o MISP (fake) está disponível, um evento foi criado.
    assert result.misp_event_uuid == "uuid-1"
    assert fake_misp.pushed


def test_pipeline_secondary_flow_collects_html(test_config, database, mocker):
    """Fluxo secundário: sem HTML, o coletor é acionado."""
    pipeline = _build_pipeline(test_config, database, mocker)
    pipeline.html_collector.fetch.return_value = (
        "<html><form action='/x'><input type='password' name='p'></form></html>",
        200,
    )
    result = pipeline.process(AnalysisRequest(url="https://x.tld"))
    assert pipeline.html_collector.fetch.called
    assert result.analysis.html_hash


def test_pipeline_infrastructure_collection(
    test_config, database, mocker, sample_html
):
    """Com coleta de infra habilitada, SSL/DNS/infra são consultados."""
    pipeline = _build_pipeline(test_config, database, mocker)
    result = pipeline.process(
        AnalysisRequest(
            url="https://x.tld", html=sample_html, collect_infrastructure=True
        )
    )
    assert result.infrastructure.asn == "AS100"
    assert result.certificate.sha256_fingerprint == "fp"
    assert pipeline.ssl_collector.collect.called


def test_pipeline_misp_idempotent(test_config, database, mocker, sample_html):
    """Reprocessar o mesmo kit não deve recriar o evento MISP."""
    fake_misp = _FakeMisp()
    pipeline = _build_pipeline(test_config, database, mocker, fake_misp)
    req = AnalysisRequest(url="https://a.tld", html=sample_html)
    pipeline.process(req)
    pipeline.process(AnalysisRequest(url="https://b.tld", html=sample_html))
    # O evento foi criado apenas uma vez (mesmo fingerprint de campanha).
    assert len(fake_misp.pushed) == 1


def test_pipeline_correlation_increases_score(
    test_config, database, mocker, sample_html
):
    """Reuso do mesmo kit deve elevar o Attribution Score na 2ª análise."""
    pipeline = _build_pipeline(test_config, database, mocker, _FakeMisp())
    first = pipeline.process(AnalysisRequest(url="https://a.tld", html=sample_html))
    second = pipeline.process(AnalysisRequest(url="https://b.tld", html=sample_html))
    assert second.campaign.score > first.campaign.score


def test_main_cli_end_to_end(tmp_path, sample_html, capsys):
    """A CLI deve analisar um arquivo HTML e emitir um resumo JSON."""
    html_file = tmp_path / "page.html"
    html_file.write_text(sample_html, encoding="utf-8")
    db_file = tmp_path / "cli.db"

    config_file = tmp_path / "config.yaml"
    config_file.write_text(
        f"database:\n  url: sqlite:///{db_file}\n"
        f"evidence:\n  storage_dir: {tmp_path / 'ev'}\n"
        "logging:\n  level: warning\n",
        encoding="utf-8",
    )

    exit_code = main_module.main(
        [
            "--url",
            "https://livelo-fake.tld/login",
            "--html-file",
            str(html_file),
            "--config",
            str(config_file),
        ]
    )
    assert exit_code == 0
    out = capsys.readouterr().out
    # O resumo é impresso como um bloco JSON indentado no final do stdout
    # (as linhas de log são objetos JSON de uma única linha). Localizamos o
    # início do bloco pela linha que contém apenas "{".
    lines = out.splitlines()
    # A abertura do bloco top-level é a única linha igual a "{" sem indentação
    # (as chaves aninhadas do JSON indentado começam com espaços).
    start = next(i for i, line in enumerate(lines) if line == "{")
    summary = json.loads("\n".join(lines[start:]))
    assert summary["target_brand"] == "livelo"
    assert summary["campaign_id"]
    assert summary["phishing_types"]


def test_main_requires_input(capsys):
    """Sem --url nem --html-file, a CLI deve encerrar com erro de uso."""
    try:
        main_module.main([])
    except SystemExit as exc:
        assert exc.code != 0
