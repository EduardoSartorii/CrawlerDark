"""Correlacionador por fingerprint de kit (fingerprint_correlator).

Responsabilidade do componente
-------------------------------
Comparar o :class:`~models.findings.KitFingerprint` de um novo incidente
contra o historico persistido de fingerprints, produzindo sinais de
correlacao especificos para reuso de kit completo (``same_fingerprint``),
reuso apenas da estrutura DOM (``same_dom_pattern``) e reuso apenas dos
scripts/comportamento JavaScript (``same_javascript_pattern``).

Fluxo de execucao
------------------
1. Busca fingerprints existentes cujo ``campaign_fingerprint`` seja
   identico ao do novo incidente (reuso completo do kit).
2. Busca fingerprints existentes cujo ``dom_hash`` seja identico, mas cujo
   ``campaign_fingerprint`` difira (kit com mesmo layout, mas scripts ou
   assets trocados — indicativo de "kit modificado" pelo mesmo operador).
3. Para cada fingerprint correlacionado, resolve os sites associados via
   ``PhishingSiteRepository`` para popular ``related_site_url``.

Regra de negocio
----------------
``same_fingerprint`` (kit inteiro identico) e o sinal de MAIOR peso do
motor de atribuicao, pois representa a evidencia mais forte possivel de
reuso direto de infraestrutura de ataque.
"""

from __future__ import annotations

from database.repositories import FingerprintRepository, PhishingSiteRepository
from models.campaign import CorrelationSignal, CorrelationSignalType
from models.findings import KitFingerprint


def correlate_by_fingerprint(
    fingerprint: KitFingerprint,
    fingerprint_repo: FingerprintRepository,
    site_repo: PhishingSiteRepository,
) -> list[CorrelationSignal]:
    """Produz sinais de correlacao baseados em reuso de kit/DOM/scripts.

    Args:
        fingerprint: Fingerprint calculado para o incidente atual.
        fingerprint_repo: Repositorio de fingerprints persistidos.
        site_repo: Repositorio de sites de phishing (para resolver URLs
            relacionadas aos fingerprints encontrados).

    Returns:
        Lista de :class:`CorrelationSignal` (pode ser vazia, quando nao ha
        historico correlacionavel).
    """
    signals: list[CorrelationSignal] = []

    exact_matches = fingerprint_repo.find_by_campaign_fingerprint(fingerprint.campaign_fingerprint)
    for match in exact_matches:
        for site in site_repo.find_by_fingerprint_id(match.id):
            signals.append(
                CorrelationSignal(
                    signal_type=CorrelationSignalType.SAME_FINGERPRINT,
                    weight=0,  # o peso e aplicado pelo campaign_correlator, a partir da config.
                    matched_value=fingerprint.campaign_fingerprint,
                    related_site_url=site.url,
                )
            )

    dom_matches = fingerprint_repo.find_by_dom_hash(fingerprint.dom_sha256)
    for match in dom_matches:
        if match.campaign_fingerprint == fingerprint.campaign_fingerprint:
            continue  # ja contabilizado como same_fingerprint (evita double count).
        for site in site_repo.find_by_fingerprint_id(match.id):
            signals.append(
                CorrelationSignal(
                    signal_type=CorrelationSignalType.SAME_DOM_PATTERN,
                    weight=0,
                    matched_value=fingerprint.dom_sha256,
                    related_site_url=site.url,
                )
            )
        if match.script_hash == fingerprint.scripts_sha256:
            for site in site_repo.find_by_fingerprint_id(match.id):
                signals.append(
                    CorrelationSignal(
                        signal_type=CorrelationSignalType.SAME_JAVASCRIPT_PATTERN,
                        weight=0,
                        matched_value=fingerprint.scripts_sha256,
                        related_site_url=site.url,
                    )
                )

    return signals
