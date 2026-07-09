"""Analisador de exfiltração.

Arquitetura
-----------
Consolida destinos de coleta a partir de duas fontes: (1) ``action`` dos
formulários (DOM) e (2) chamadas de rede/URLs do JavaScript. Cada destino é
classificado por canal e recebe um score de confiança.

Responsabilidade do componente
------------------------------
Produzir uma lista estruturada de :class:`ExfiltrationDestination` que
alimenta a atribuição de campanha e o enriquecimento MISP.

Fluxo de execução
-----------------
``analyze(dom, js)`` -> coleta candidatos -> classifica canal -> pontua ->
deduplica por alvo -> lista ordenada por confiança.
"""

from __future__ import annotations

from phishing_intel.logging_config import get_logger
from phishing_intel.models.findings import (
    DomStructure,
    ExfiltrationDestination,
    ExfiltrationKind,
    JavaScriptFindings,
)
from phishing_intel.utils import EMAIL_REGEX

logger = get_logger(__name__)

# Termos que indicam endpoints típicos de coleta (gate/result/save/log).
_COLLECTION_HINTS = ("gate", "result", "save", "log", "post", "send", "next")
# Domínios de mensageria comumente usados para exfiltração.
_MESSAGING_HINTS = ("t.me", "telegram", "discord", "api.telegram.org")


class ExfiltrationAnalyzer:
    """Detecta e classifica destinos de exfiltração de dados."""

    def analyze(
        self, dom: DomStructure, js: JavaScriptFindings
    ) -> list[ExfiltrationDestination]:
        """Detecta destinos de exfiltração a partir do DOM e do JS.

        Args:
            dom: Estrutura DOM (fornece ``action`` dos formulários).
            js: Achados de JavaScript (fornece chamadas de rede/URLs).

        Returns:
            Lista de destinos deduplicados por alvo, ordenada por confiança
            (maior primeiro).
        """
        # Usa dict para deduplicar por alvo mantendo o de maior confiança.
        destinations: dict[str, ExfiltrationDestination] = {}

        def _add(dest: ExfiltrationDestination) -> None:
            existing = destinations.get(dest.target)
            if existing is None or dest.confidence > existing.confidence:
                destinations[dest.target] = dest

        # (1) Formulários: o ``action`` é o destino primário de coleta.
        for form in dom.forms:
            action = form.action.strip()
            if not action or action in ("#", "javascript:void(0)"):
                continue
            _add(self._classify(action, source="form_action", base_confidence=80))

        # (2) JavaScript: fetch/XHR/axios/jQuery normalmente enviam os dados.
        network_sources = [
            ("fetch", js.fetch_urls, 75),
            ("xhr", js.xhr_urls, 75),
            ("axios", js.axios_urls, 75),
            ("jquery_ajax", js.jquery_ajax_urls, 70),
        ]
        for source, urls, base in network_sources:
            for url in urls:
                _add(self._classify(url, source=source, base_confidence=base))

        # (3) E-mails hardcoded no JS são canais de exfiltração por e-mail.
        for block in js.suspicious_strings:
            for email in EMAIL_REGEX.findall(block):
                _add(
                    ExfiltrationDestination(
                        target=email,
                        kind=ExfiltrationKind.EMAIL,
                        source="js_string",
                        confidence=60,
                    )
                )

        result = sorted(
            destinations.values(), key=lambda d: d.confidence, reverse=True
        )
        logger.info("exfiltration_analyzed", destinations=len(result))
        return result

    def _classify(
        self, target: str, source: str, base_confidence: int
    ) -> ExfiltrationDestination:
        """Classifica o canal de um destino e ajusta o score de confiança.

        Regras de negócio:
            * ``mailto:`` ou e-mail puro -> canal E-mail.
            * Domínios de mensageria -> canal Mensageria (alta confiança).
            * Endpoints com dicas de coleta (gate/result/...) -> API/HTTP com
              bônus de confiança.
            * Demais URLs http(s) -> HTTP genérico.

        Args:
            target: URL/endereço destino.
            source: Origem do sinal (para auditoria).
            base_confidence: Confiança inicial pela origem.

        Returns:
            Um :class:`ExfiltrationDestination` classificado e pontuado.
        """
        lowered = target.lower()
        confidence = base_confidence

        # Canal de e-mail.
        if lowered.startswith("mailto:") or EMAIL_REGEX.fullmatch(target):
            return ExfiltrationDestination(
                target=target.replace("mailto:", ""),
                kind=ExfiltrationKind.EMAIL,
                source=source,
                confidence=min(confidence + 5, 100),
            )

        # Canal de mensageria (Telegram/Discord).
        if any(hint in lowered for hint in _MESSAGING_HINTS):
            return ExfiltrationDestination(
                target=target,
                kind=ExfiltrationKind.MESSAGING,
                source=source,
                confidence=min(confidence + 15, 100),
            )

        # Endpoints com padrão de coleta reforçam a confiança e sugerem API.
        if any(hint in lowered for hint in _COLLECTION_HINTS):
            kind = ExfiltrationKind.API if "api" in lowered else ExfiltrationKind.HTTP
            return ExfiltrationDestination(
                target=target,
                kind=kind,
                source=source,
                confidence=min(confidence + 10, 100),
            )

        # URLs http(s) genéricas.
        if lowered.startswith(("http://", "https://")):
            kind = ExfiltrationKind.API if "/api" in lowered else ExfiltrationKind.HTTP
            return ExfiltrationDestination(
                target=target, kind=kind, source=source, confidence=confidence
            )

        # Caminho relativo ou esquema desconhecido -> customizado.
        return ExfiltrationDestination(
            target=target,
            kind=ExfiltrationKind.CUSTOM,
            source=source,
            confidence=max(confidence - 20, 10),
        )
