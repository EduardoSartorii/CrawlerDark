"""Ponto de entrada da plataforma phishing_intel.

Responsabilidade do componente
-------------------------------
Prover a interface de linha de comando (CLI) que decide, para cada
incidente recebido, qual fluxo executar:

    * Fluxo principal: HTML/JS ja fornecidos pelo parceiro de CTI ->
      analise estatica direta, sem qualquer coleta ativa.
    * Fluxo secundario: HTML nao fornecido -> coleta minima (HTML, SSL,
      infraestrutura) e armazenamento de evidencias, seguido da mesma
      analise do fluxo principal.

Em ambos os casos, o pipeline completo (analise -> correlacao ->
persistencia -> enriquecimento MISP) e delegado a
``enrichment.campaign_builder.run_pipeline``.

Fluxo de execucao
------------------
1. Parseia argumentos de linha de comando.
2. Configura logging estruturado (``structlog``).
3. Carrega a configuracao tipada e inicializa o esquema do banco (bootstrap
   local; em producao, o esquema deve ser gerido via Alembic).
4. Resolve HTML/JS (fornecidos ou coletados) e dados auxiliares (SSL,
   infraestrutura).
5. Executa o pipeline e imprime um resumo estruturado do resultado.
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path
from urllib.parse import urlparse

import structlog

from collectors.html_collector import HtmlCollectionError, fetch_html
from collectors.infrastructure_collector import collect_infrastructure
from collectors.ssl_collector import SslCollectionError, collect_certificate
from config.settings import PhishingIntelSettings, get_settings
from database.session import init_db, session_scope
from enrichment.campaign_builder import PipelineResult, run_pipeline
from enrichment.misp_client import MispClient, MispClientError
from models.findings import InfrastructureFinding, SslCertificateFinding

logger = structlog.get_logger(__name__)


def _configure_logging(json_format: bool, level: str) -> None:
    """Configura o logging estruturado da plataforma (registro de auditoria)."""
    logging.basicConfig(level=level, format="%(message)s", stream=sys.stdout)
    renderer = structlog.processors.JSONRenderer() if json_format else structlog.dev.ConsoleRenderer()
    structlog.configure(
        processors=[
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.add_log_level,
            renderer,
        ],
        wrapper_class=structlog.make_filtering_bound_logger(logging.getLevelName(level)),
        logger_factory=structlog.PrintLoggerFactory(),
    )


def _resolve_html_and_js(
    url: str,
    html_path: Path | None,
    js_path: Path | None,
    settings: PhishingIntelSettings,
) -> tuple[str, str, str]:
    """Resolve o HTML/JS do incidente, executando o fluxo secundario se necessario.

    Returns:
        Tupla ``(html, javascript, source)``, onde ``source`` e
        ``"partner_supplied"`` quando o HTML foi fornecido via arquivo, ou
        ``"collected"`` quando a plataforma precisou coleta-lo ativamente.
    """
    javascript = js_path.read_text(encoding="utf-8", errors="ignore") if js_path else ""

    if html_path is not None:
        logger.info("fluxo_principal_iniciado", url=url, html_path=str(html_path))
        return html_path.read_text(encoding="utf-8", errors="ignore"), javascript, "partner_supplied"

    logger.warning("html_nao_fornecido_iniciando_fluxo_secundario", url=url)
    try:
        collected = fetch_html(url, settings.collectors)
    except HtmlCollectionError as exc:
        logger.error("falha_na_coleta_de_html", url=url, error=str(exc))
        raise
    return collected.html, javascript, "collected"


def _resolve_ssl(domain: str) -> SslCertificateFinding | None:
    """Coleta o certificado TLS do dominio, tolerando falhas (endpoint pode nao usar HTTPS)."""
    try:
        return collect_certificate(domain)
    except SslCollectionError as exc:
        logger.warning("certificado_ssl_indisponivel", domain=domain, error=str(exc))
        return None


def _resolve_infrastructure(domain: str) -> InfrastructureFinding | None:
    """Coleta os dados de infraestrutura de rede do dominio, tolerando falhas parciais."""
    try:
        return collect_infrastructure(domain)
    except Exception as exc:  # noqa: BLE001 - enriquecimento best-effort
        logger.warning("infraestrutura_indisponivel", domain=domain, error=str(exc))
        return None


def _build_misp_client(settings: PhishingIntelSettings, enabled: bool) -> MispClient | None:
    """Instancia o cliente MISP, retornando ``None`` quando desabilitado ou indisponivel.

    Regra de negocio: a indisponibilidade do MISP (rede, credenciais
    invalidas, servidor fora do ar) NUNCA deve impedir a analise/
    correlacao/persistencia local do incidente — o enriquecimento MISP e
    tratado como uma etapa best-effort, adicional ao valor entregue pela
    plataforma.
    """
    if not enabled:
        return None
    try:
        return MispClient(settings.misp)
    except MispClientError as exc:
        logger.warning("cliente_misp_indisponivel", error=str(exc))
        return None
    except Exception as exc:  # noqa: BLE001 - qualquer falha de conectividade/API do MISP e best-effort
        logger.warning("cliente_misp_indisponivel", error=str(exc))
        return None


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Define e parseia os argumentos de linha de comando da plataforma."""
    parser = argparse.ArgumentParser(
        prog="phishing-intel",
        description="Plataforma de Threat Intelligence para analise de campanhas de phishing.",
    )
    parser.add_argument("--url", required=True, help="URL suspeita recebida do parceiro de CTI.")
    parser.add_argument(
        "--html-file", type=Path, default=None, help="Caminho para o HTML ja coletado pelo parceiro."
    )
    parser.add_argument(
        "--js-file", type=Path, default=None, help="Caminho para o JavaScript ja coletado pelo parceiro."
    )
    parser.add_argument(
        "--no-misp", action="store_true", help="Pula o enriquecimento MISP (util para testes/dry-run)."
    )
    parser.add_argument(
        "--no-network-enrichment",
        action="store_true",
        help="Pula a coleta de certificado SSL e infraestrutura de rede.",
    )
    parser.add_argument("--config", type=Path, default=None, help="Caminho customizado para config.yaml.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> PipelineResult:
    """Ponto de entrada principal da CLI da plataforma phishing_intel."""
    args = _parse_args(argv)
    settings = get_settings() if args.config is None else PhishingIntelSettings.model_validate(
        __import__("yaml").safe_load(args.config.read_text(encoding="utf-8"))
    )

    _configure_logging(settings.logging.json_format, settings.logging.level)
    init_db(settings)

    domain = urlparse(args.url).netloc or args.url

    html, javascript, source = _resolve_html_and_js(args.url, args.html_file, args.js_file, settings)

    ssl_finding: SslCertificateFinding | None = None
    infrastructure_finding: InfrastructureFinding | None = None
    if not args.no_network_enrichment:
        ssl_finding = _resolve_ssl(domain)
        infrastructure_finding = _resolve_infrastructure(domain)

    misp_client = _build_misp_client(settings, enabled=not args.no_misp)

    with session_scope(settings) as session:
        result = run_pipeline(
            url=args.url,
            html=html,
            javascript=javascript,
            session=session,
            settings=settings,
            ssl_finding=ssl_finding,
            infrastructure_finding=infrastructure_finding,
            source=source,
            misp_client=misp_client,
        )

    logger.info(
        "pipeline_concluido",
        url=args.url,
        campaign_id=result.campaign.campaign_id,
        score=result.attribution.score,
        confidence=result.attribution.confidence.value,
        phishing_type=result.report.classification.phishing_type.value,
        target_brand=result.report.brand.target_brand,
        misp_event_uuid=result.misp_event_uuid,
    )
    return result


if __name__ == "__main__":
    main()
