"""Gerador de fingerprint de kit de phishing (kit_fingerprint).

Responsabilidade do componente
-------------------------------
Combinar os artefatos estruturais de uma pagina (estrutura DOM, assets e
scripts) em tres hashes SHA256 independentes e, a partir deles, derivar um
identificador unico e estavel — o ``campaign_fingerprint`` — usado pelo
``fingerprint_correlator`` para reconhecer reuso do MESMO KIT em campanhas
distintas, mesmo apos alteracoes superficiais de conteudo (texto, dominio,
marca-alvo).

Fluxo de execucao
------------------
1. ``dom_sha256`` reaproveita o ``structural_hash`` ja calculado pelo
   ``dom_analyzer`` (arvore DOM normalizada, sem conteudo textual).
2. ``assets_sha256`` e calculado a partir dos nomes de arquivo/tipos de
   todos os assets referenciados, ordenados deterministicamente.
3. ``scripts_sha256`` combina os nomes de arquivos de scripts externos e os
   hashes de conteudo de scripts inline.
4. ``campaign_fingerprint`` e o SHA256 da concatenacao ordenada dos tres
   hashes anteriores.

Regra de negocio
----------------
Todos os componentes do fingerprint sao calculados de forma determinística
e independente de ordem de aparicao no HTML (listas sao sempre ordenadas
antes do hashing), garantindo que o mesmo kit produza o mesmo fingerprint
independentemente de reordenacoes triviais feitas pelo operador.
"""

from __future__ import annotations

import hashlib

from models.findings import DomFinding, JavaScriptFinding, KitFingerprint


def _hash_sorted_values(values: list[str]) -> str:
    """Calcula o SHA256 de uma lista de strings, apos ordenacao deterministica."""
    joined = "|".join(sorted(values))
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()


def _compute_assets_hash(dom: DomFinding) -> str:
    """Calcula o hash dos assets referenciados (por nome de arquivo + tipo)."""
    signatures = [f"{asset.asset_type}:{asset.filename or asset.url}" for asset in dom.assets]
    return _hash_sorted_values(signatures) if signatures else hashlib.sha256(b"").hexdigest()


def _compute_scripts_hash(dom: DomFinding, javascript: JavaScriptFinding) -> str:
    """Calcula o hash combinado de scripts externos (por nome) e inline (por conteudo)."""
    signatures: list[str] = []
    for script in dom.scripts:
        if script.is_inline and script.inline_content_hash:
            signatures.append(f"inline:{script.inline_content_hash}")
        elif script.filename:
            signatures.append(f"external:{script.filename}")
        elif script.src:
            signatures.append(f"external:{script.src}")
    if javascript.script_hash:
        signatures.append(f"combined_js:{javascript.script_hash}")
    return _hash_sorted_values(signatures) if signatures else hashlib.sha256(b"").hexdigest()


def generate_kit_fingerprint(dom: DomFinding, javascript: JavaScriptFinding) -> KitFingerprint:
    """Gera o fingerprint completo de um kit de phishing.

    Args:
        dom: Resultado da analise de DOM (fornece o hash estrutural e os
            assets referenciados).
        javascript: Resultado da analise de JavaScript (fornece o hash do
            script consolidado).

    Returns:
        :class:`KitFingerprint` com os tres hashes componentes e o
        ``campaign_fingerprint`` derivado.
    """
    dom_sha256 = dom.structural_hash or hashlib.sha256(b"").hexdigest()
    assets_sha256 = _compute_assets_hash(dom)
    scripts_sha256 = _compute_scripts_hash(dom, javascript)

    campaign_fingerprint = hashlib.sha256(
        "|".join(sorted([dom_sha256, assets_sha256, scripts_sha256])).encode("utf-8")
    ).hexdigest()

    return KitFingerprint(
        dom_sha256=dom_sha256,
        assets_sha256=assets_sha256,
        scripts_sha256=scripts_sha256,
        campaign_fingerprint=campaign_fingerprint,
    )
