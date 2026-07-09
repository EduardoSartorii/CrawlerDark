"""Armazenamento de evidências e cadeia de custódia (OPSEC).

Arquitetura
-----------
Persiste os artefatos brutos (HTML, JS) e um manifesto de auditoria em disco,
organizados por hash do HTML. Isso garante a preservação de artefatos e o
registro completo de auditoria exigidos por operações profissionais de CTI.

Responsabilidade do componente
------------------------------
* Separar coleta de análise: os coletores/orquestrador gravam evidências
  *antes* de analisar.
* Gerar um manifesto (timestamp, URL, hashes) para rastreabilidade.

Fluxo de execução
-----------------
``store(url, html, js)`` -> cria diretório por hash -> grava artefatos ->
grava ``manifest.json`` -> retorna o caminho do diretório de evidências.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from phishing_intel.logging_config import get_logger
from phishing_intel.utils import sha256_text

logger = get_logger(__name__)


class EvidenceStore:
    """Grava e organiza a cadeia de evidências em disco."""

    def __init__(self, base_dir: str = "evidence", enabled: bool = True) -> None:
        """Inicializa o armazenamento de evidências.

        Args:
            base_dir: Diretório raiz onde as evidências são gravadas.
            enabled: Se ``False``, o armazenamento opera em no-op (retorna
                caminhos vazios) — útil para execuções efêmeras/testes.
        """
        self.base_dir = Path(base_dir)
        self.enabled = enabled

    def store(
        self,
        url: str,
        html: str,
        javascript: str = "",
        analysis_summary: dict | None = None,
        certificate_pem: str = "",
    ) -> str:
        """Persiste os artefatos e o manifesto de auditoria.

        Args:
            url: URL de origem dos artefatos.
            html: HTML bruto.
            javascript: JavaScript bruto agregado.
            analysis_summary: Resumo da análise (opcional) para o manifesto.
            certificate_pem: PEM do certificado (opcional), preservado.

        Returns:
            Caminho absoluto do diretório de evidências criado, ou string
            vazia se o armazenamento estiver desabilitado.
        """
        if not self.enabled:
            return ""

        html_hash = sha256_text(html) if html else "no-html"
        # Um diretório por hash de HTML agrupa reuso do mesmo artefato.
        evidence_dir = self.base_dir / html_hash
        evidence_dir.mkdir(parents=True, exist_ok=True)

        # Grava artefatos brutos (preservação para reprodutibilidade).
        (evidence_dir / "page.html").write_text(html or "", encoding="utf-8")
        (evidence_dir / "script.js").write_text(javascript or "", encoding="utf-8")
        if certificate_pem:
            (evidence_dir / "certificate.pem").write_text(
                certificate_pem, encoding="utf-8"
            )

        # Manifesto de auditoria: timestamp, URL, hashes, resultado.
        manifest = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "url": url,
            "html_hash": html_hash,
            "js_hash": sha256_text(javascript) if javascript else "",
            "has_certificate": bool(certificate_pem),
            "analysis_summary": analysis_summary or {},
        }
        (evidence_dir / "manifest.json").write_text(
            json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8"
        )

        logger.info("evidence_stored", url=url, path=str(evidence_dir))
        return str(evidence_dir.resolve())
