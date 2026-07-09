"""Comparador multi-perfil de renderizacao (profile_comparator).

Responsabilidade do componente
-------------------------------
Comparar o DOM de uma mesma URL renderizado sob multiplos perfis de
navegador (Desktop Chrome/Edge/Firefox, Android Chrome, iPhone Safari) para
identificar kits de phishing que servem conteudo diferente para
desktop/mobile — tecnica comum de evasao de crawlers automatizados e de
segmentacao de vitimas (ex.: apenas o fluxo mobile solicita OTP via SMS).

Fluxo de execucao
------------------
1. ``build_profile_snapshot`` roda o ``dom_analyzer`` sobre o HTML coletado
   de cada perfil, reduzindo o resultado a um snapshot leve (hash
   estrutural, URLs de assets, hashes de scripts).
2. ``compare_profiles`` escolhe um perfil baseline (por padrao,
   ``desktop_chrome``) e calcula, para cada outro perfil, se o hash
   estrutural difere e qual e a diferenca de assets/scripts (diferenca
   simetrica de conjuntos).
"""

from __future__ import annotations

from analyzers.dom_analyzer import analyze_dom
from models.findings import DomFinding, ProfileDiffResult, ProfileDomSnapshot


def build_profile_snapshot(profile_name: str, html: str, base_url: str | None = None) -> ProfileDomSnapshot:
    """Constroi um snapshot leve de DOM para um unico perfil de renderizacao."""
    dom: DomFinding = analyze_dom(html, base_url=base_url)
    script_hashes = [
        script.inline_content_hash or script.filename or script.src or ""
        for script in dom.scripts
        if (script.inline_content_hash or script.filename or script.src)
    ]
    asset_urls = [asset.url for asset in dom.assets]
    return ProfileDomSnapshot(
        profile_name=profile_name,
        structural_hash=dom.structural_hash,
        asset_urls=asset_urls,
        script_hashes=script_hashes,
    )


def compare_profiles(
    snapshots: dict[str, ProfileDomSnapshot], baseline_profile: str = "desktop_chrome"
) -> list[ProfileDiffResult]:
    """Compara todos os perfis coletados contra um perfil baseline.

    Args:
        snapshots: Mapa ``nome_do_perfil -> ProfileDomSnapshot``.
        baseline_profile: Nome do perfil usado como referencia de
            comparacao (por padrao, Desktop Chrome).

    Returns:
        Lista de :class:`ProfileDiffResult`, uma entrada por perfil
        diferente do baseline presente em ``snapshots``.
    """
    baseline = snapshots.get(baseline_profile)
    if baseline is None:
        return []

    diffs: list[ProfileDiffResult] = []
    baseline_assets = set(baseline.asset_urls)
    baseline_scripts = set(baseline.script_hashes)

    for profile_name, snapshot in snapshots.items():
        if profile_name == baseline_profile:
            continue
        assets_diff = sorted(baseline_assets.symmetric_difference(snapshot.asset_urls))
        scripts_diff = sorted(baseline_scripts.symmetric_difference(snapshot.script_hashes))
        diffs.append(
            ProfileDiffResult(
                baseline_profile=baseline_profile,
                compared_profile=profile_name,
                dom_differs=snapshot.structural_hash != baseline.structural_hash,
                assets_diff=assets_diff,
                scripts_diff=scripts_diff,
            )
        )
    return diffs
