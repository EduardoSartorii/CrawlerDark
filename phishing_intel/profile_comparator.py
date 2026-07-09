"""Comparação multi-perfil (Desktop vs. Mobile).

Arquitetura
-----------
Recebe o HTML coletado sob diferentes perfis de renderização e produz diffs
de DOM, assets e scripts entre um perfil base (Desktop) e um perfil alvo
(Mobile), ajudando a detectar *cloaking* (conteúdo diferente por dispositivo).

Responsabilidade do componente
------------------------------
Identificar diferenças de conteúdo entre perfis e estruturar o resultado
para correlação futura.

Fluxo de execução
-----------------
``compare(profiles_html)`` -> analisa cada perfil -> calcula conjuntos de
assets/scripts e esqueleto DOM -> gera diffs -> :class:`ProfileComparison`.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from phishing_intel.analyzers.dom_analyzer import DomAnalyzer
from phishing_intel.collectors.html_collector import RENDER_PROFILES
from phishing_intel.logging_config import get_logger
from phishing_intel.utils import sha256_text

logger = get_logger(__name__)


@dataclass
class ProfileDiff:
    """Diferenças entre um perfil base e um perfil alvo."""

    base_profile: str
    target_profile: str
    dom_changed: bool = False
    assets_only_in_base: list[str] = field(default_factory=list)
    assets_only_in_target: list[str] = field(default_factory=list)
    scripts_only_in_base: list[str] = field(default_factory=list)
    scripts_only_in_target: list[str] = field(default_factory=list)


@dataclass
class ProfileComparison:
    """Resultado consolidado da comparação multi-perfil."""

    dom_hashes: dict[str, str] = field(default_factory=dict)
    diffs: list[ProfileDiff] = field(default_factory=list)
    # ``True`` se houver qualquer diferença de DOM entre desktop e mobile.
    cloaking_suspected: bool = False


class ProfileComparator:
    """Compara conteúdo coletado sob múltiplos perfis de renderização."""

    def __init__(self, dom_analyzer: DomAnalyzer | None = None) -> None:
        """Inicializa o comparador.

        Args:
            dom_analyzer: Analisador de DOM. Se ``None``, cria um padrão.
        """
        self.dom_analyzer = dom_analyzer or DomAnalyzer()

    def compare(self, profiles_html: dict[str, str]) -> ProfileComparison:
        """Compara o HTML coletado sob múltiplos perfis.

        Regra de negócio: o primeiro perfil ``desktop_*`` disponível é a
        base; cada perfil ``mobile`` é comparado contra ela. Diferenças de
        esqueleto DOM entre desktop e mobile sinalizam possível cloaking.

        Args:
            profiles_html: Mapa ``{nome_do_perfil: html}``.

        Returns:
            :class:`ProfileComparison` com hashes de DOM e diffs.
        """
        comparison = ProfileComparison()

        # Analisa cada perfil uma única vez e guarda estrutura + hash.
        structures = {}
        for profile, html in profiles_html.items():
            structure = self.dom_analyzer.analyze(html)
            structures[profile] = structure
            comparison.dom_hashes[profile] = sha256_text(
                structure.normalized_skeleton
            )

        base = self._pick_base_profile(profiles_html.keys())
        if base is None:
            return comparison

        for profile in profiles_html:
            if profile == base:
                continue
            diff = self._diff(base, profile, structures[base], structures[profile])
            comparison.diffs.append(diff)
            # Cloaking suspeito: DOM muda entre desktop (base) e mobile.
            if (
                diff.dom_changed
                and RENDER_PROFILES.get(profile)
                and RENDER_PROFILES[profile].platform == "mobile"
            ):
                comparison.cloaking_suspected = True

        logger.info(
            "profiles_compared",
            profiles=len(profiles_html),
            cloaking=comparison.cloaking_suspected,
        )
        return comparison

    def _pick_base_profile(self, profiles) -> str | None:
        """Escolhe o perfil base (primeiro desktop; senão, o primeiro)."""
        profiles = list(profiles)
        for profile in profiles:
            render = RENDER_PROFILES.get(profile)
            if render and render.platform == "desktop":
                return profile
        return profiles[0] if profiles else None

    def _diff(self, base_name, target_name, base_struct, target_struct) -> ProfileDiff:
        """Calcula o diff entre duas estruturas DOM."""
        base_assets = set(base_struct.assets)
        target_assets = set(target_struct.assets)
        base_scripts = set(base_struct.scripts_external)
        target_scripts = set(target_struct.scripts_external)

        return ProfileDiff(
            base_profile=base_name,
            target_profile=target_name,
            dom_changed=base_struct.normalized_skeleton
            != target_struct.normalized_skeleton,
            assets_only_in_base=sorted(base_assets - target_assets),
            assets_only_in_target=sorted(target_assets - base_assets),
            scripts_only_in_base=sorted(base_scripts - target_scripts),
            scripts_only_in_target=sorted(target_scripts - base_scripts),
        )
