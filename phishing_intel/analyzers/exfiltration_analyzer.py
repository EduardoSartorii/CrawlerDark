"""Analisador de exfiltracao de dados (exfiltration_analyzer).

Responsabilidade do componente
-------------------------------
Consolidar os destinos de envio de dados identificados na analise de DOM
(``action`` de formularios) e na analise de JavaScript (chamadas de rede,
URLs hardcoded) em uma lista estruturada de destinos de exfiltracao,
classificando o canal utilizado (HTTP generico, API, E-mail, Mensageria ou
Customizado) e atribuindo um score de confianca a cada destino.

Fluxo de execucao
------------------
1. Coleta candidatos a partir de ``DomFinding.forms`` (action) e
   ``JavaScriptFinding.network_calls``/``hardcoded_urls``.
2. Classifica cada candidato em um :class:`ExfiltrationChannel` usando
   heuristicas de dominio/path conhecidos (webhooks de mensageria, ``mailto:``,
   paths ``/api/``).
3. Atribui confianca por destino considerando a origem do sinal (uma
   submissao de formulario com method POST tem confianca maior que uma URL
   hardcoded isolada em JS, que pode nunca ser efetivamente chamada).
"""

from __future__ import annotations

import re

from models.findings import DomFinding, ExfiltrationChannel, ExfiltrationDestination, ExfiltrationReport, JavaScriptFinding

_MESSAGING_DOMAINS = (
    "api.telegram.org",
    "discord.com/api/webhooks",
    "discordapp.com/api/webhooks",
    "graph.facebook.com",
    "api.whatsapp.com",
)

_API_PATH_PATTERN = re.compile(r"/api/|/v[0-9]+/|graphql", re.IGNORECASE)


def _classify_destination(url: str) -> ExfiltrationChannel:
    """Classifica o canal tecnico de um destino de exfiltracao com base na URL."""
    lowered = url.lower()
    if lowered.startswith("mailto:"):
        return ExfiltrationChannel.EMAIL
    if any(domain in lowered for domain in _MESSAGING_DOMAINS):
        return ExfiltrationChannel.MESSAGING
    if _API_PATH_PATTERN.search(lowered):
        return ExfiltrationChannel.API
    if lowered.startswith(("http://", "https://")):
        return ExfiltrationChannel.HTTP
    return ExfiltrationChannel.CUSTOM


def analyze_exfiltration(dom: DomFinding, javascript: JavaScriptFinding) -> ExfiltrationReport:
    """Consolida todos os destinos de exfiltracao identificados na pagina.

    Args:
        dom: Resultado da analise estrutural (para os ``action`` de forms).
        javascript: Resultado da analise de JavaScript (chamadas de rede e
            URLs hardcoded).

    Returns:
        :class:`ExfiltrationReport` com a lista de destinos deduplicados e
        um score de confianca global (media ponderada por destino).
    """
    destinations: dict[str, ExfiltrationDestination] = {}

    for form in dom.forms:
        if not form.action:
            continue
        channel = _classify_destination(form.action)
        confidence = 0.9 if form.method.upper() == "POST" else 0.6
        _merge_destination(
            destinations,
            form.action,
            channel,
            confidence,
            evidence=[f"form[method={form.method}] action={form.action}"],
        )

    for call in javascript.network_calls:
        if not call.destination:
            continue
        channel = _classify_destination(call.destination)
        _merge_destination(
            destinations,
            call.destination,
            channel,
            confidence=0.85,
            evidence=[f"{call.call_type} -> {call.destination}"],
        )

    for url in javascript.hardcoded_urls:
        channel = _classify_destination(url)
        _merge_destination(destinations, url, channel, confidence=0.4, evidence=[f"hardcoded_url:{url}"])

    destination_list = list(destinations.values())
    overall_confidence = (
        round(sum(dest.confidence for dest in destination_list) / len(destination_list), 2)
        if destination_list
        else 0.0
    )

    return ExfiltrationReport(destinations=destination_list, overall_confidence=overall_confidence)


def _merge_destination(
    destinations: dict[str, ExfiltrationDestination],
    url: str,
    channel: ExfiltrationChannel,
    confidence: float,
    evidence: list[str],
) -> None:
    """Mescla um novo candidato de destino, mantendo a maior confianca observada."""
    existing = destinations.get(url)
    if existing is None:
        destinations[url] = ExfiltrationDestination(
            url=url, channel=channel, confidence=confidence, evidence=evidence
        )
        return
    existing.confidence = max(existing.confidence, confidence)
    existing.evidence.extend(evidence)
