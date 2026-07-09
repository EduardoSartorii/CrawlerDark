"""Ponto de entrada (CLI) da plataforma phishing_intel.

Arquitetura
-----------
Expõe uma interface de linha de comando que hidrata a configuração, prepara
o banco e executa o :class:`Pipeline` sobre os artefatos informados (HTML/JS
de arquivos ou coleta a partir da URL).

Responsabilidade do componente
------------------------------
Fazer o *bootstrapping* da aplicação e traduzir argumentos de CLI em uma
:class:`AnalysisRequest`. Nenhuma lógica de análise vive aqui.

Fluxo de execução
-----------------
``main()`` -> parse args -> ``load_config`` -> ``configure_logging`` ->
``Database.create_all`` -> ``Pipeline.process`` -> imprime resumo JSON.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from phishing_intel.config import load_config
from phishing_intel.database.session import Database
from phishing_intel.logging_config import configure_logging, get_logger
from phishing_intel.pipeline import AnalysisRequest, Pipeline

logger = get_logger(__name__)


def _build_parser() -> argparse.ArgumentParser:
    """Constrói o parser de argumentos da CLI.

    Returns:
        Um :class:`argparse.ArgumentParser` configurado.
    """
    parser = argparse.ArgumentParser(
        prog="phishing-intel",
        description=(
            "Plataforma de Threat Intelligence para análise, correlação e "
            "atribuição de campanhas de phishing."
        ),
    )
    parser.add_argument("--url", default="", help="URL suspeita a analisar.")
    parser.add_argument(
        "--html-file",
        default="",
        help="Caminho para arquivo HTML já coletado (fluxo principal).",
    )
    parser.add_argument(
        "--js-file",
        default="",
        help="Caminho para arquivo JavaScript já coletado (opcional).",
    )
    parser.add_argument(
        "--collect-infra",
        action="store_true",
        help="Coletar SSL/DNS/infraestrutura via rede (fluxo secundário).",
    )
    parser.add_argument(
        "--config",
        default="",
        help="Caminho para o arquivo de configuração YAML.",
    )
    return parser


def _read_file(path: str) -> str:
    """Lê um arquivo de texto, retornando string vazia se o caminho for vazio.

    Args:
        path: Caminho do arquivo (ou string vazia).

    Returns:
        Conteúdo do arquivo, ou string vazia.
    """
    if not path:
        return ""
    return Path(path).read_text(encoding="utf-8", errors="replace")


def run(args: argparse.Namespace) -> dict:
    """Executa o pipeline com base nos argumentos de CLI.

    Args:
        args: Argumentos já parseados.

    Returns:
        Um dicionário-resumo do resultado (pronto para serialização JSON).
    """
    config = load_config(args.config or None)
    configure_logging(config.logging)

    database = Database(config.database)
    database.create_all()

    request = AnalysisRequest(
        url=args.url,
        html=_read_file(args.html_file),
        javascript=_read_file(args.js_file),
        collect_infrastructure=args.collect_infra,
    )

    pipeline = Pipeline(config=config, database=database)
    result = pipeline.process(request)

    summary = {
        "url": result.analysis.url,
        "domain": result.analysis.domain,
        "html_hash": result.analysis.html_hash,
        "phishing_types": [t.value for t in result.analysis.phishing_types],
        "target_brand": result.campaign.target_brand,
        "exfiltration": [
            {"target": d.target, "kind": d.kind.value, "confidence": d.confidence}
            for d in result.analysis.exfiltration
        ],
        "campaign_id": result.campaign.campaign_id,
        "attribution_score": result.campaign.score,
        "confidence": result.campaign.confidence.value,
        "kit_fingerprint": result.fingerprint.campaign_fingerprint,
        "evidence_path": result.evidence_path,
        "misp_event_uuid": result.misp_event_uuid,
    }
    return summary


def main(argv: list[str] | None = None) -> int:
    """Função principal da CLI.

    Args:
        argv: Lista de argumentos (usa ``sys.argv`` se ``None``).

    Returns:
        Código de saída do processo (0 em sucesso).
    """
    parser = _build_parser()
    args = parser.parse_args(argv)

    # Regra de negócio: é preciso ter ao menos uma URL ou um HTML para analisar.
    if not args.url and not args.html_file:
        parser.error("informe --url e/ou --html-file para analisar.")

    summary = run(args)
    # Emite o resumo em JSON no stdout para facilitar automação/pipeline.
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
