"""Fingerprinting de kit de phishing.

Arquitetura
-----------
Deriva hashes SHA-256 estáveis a partir de três dimensões do site: estrutura
do DOM, conjunto de assets e conjunto de scripts. Combina-os (junto à
estrutura de diretórios) em um ``campaign_fingerprint`` composto.

Responsabilidade do componente
------------------------------
Gerar identidade técnica reutilizável que permite correlacionar campanhas
futuras que reutilizam o mesmo kit (mesmo esqueleto DOM, mesmos arquivos).

Fluxo de execução
-----------------
``fingerprint(dom)`` -> hash DOM (esqueleto) -> hash assets (nomes de arquivo)
-> hash scripts -> hash composto -> :class:`FingerprintBundle`.
"""

from __future__ import annotations

from phishing_intel.logging_config import get_logger
from phishing_intel.models.campaign import FingerprintBundle
from phishing_intel.models.findings import DomStructure
from phishing_intel.utils import file_name_from_path, sha256_list, sha256_text

logger = get_logger(__name__)


class KitFingerprinter:
    """Calcula fingerprints estruturais de kits de phishing."""

    def fingerprint(self, dom: DomStructure) -> FingerprintBundle:
        """Gera o bundle de fingerprints a partir da estrutura DOM.

        Args:
            dom: Estrutura DOM previamente extraída.

        Returns:
            :class:`FingerprintBundle` com hashes DOM/assets/scripts e o
            fingerprint composto de campanha.
        """
        # Hash do DOM: baseado apenas no esqueleto de tags (resiliente a
        # mudanças de texto, sensível à estrutura do kit).
        dom_hash = sha256_text(dom.normalized_skeleton)

        # Hash de assets: nomes de arquivo dos assets (normalizados).
        asset_names = [
            file_name_from_path(asset) for asset in dom.assets
        ]
        asset_names = [name for name in asset_names if name]
        asset_hash = sha256_list(asset_names)

        # Hash de scripts: nomes de scripts externos + assinatura dos inline.
        script_names = [
            file_name_from_path(src) for src in dom.scripts_external
        ]
        script_names = [name for name in script_names if name]
        # Inclui um marcador de quantidade de scripts inline para diferenciar
        # kits que injetam lógica embutida.
        inline_marker = [f"inline:{len(dom.scripts_inline)}"]
        script_hash = sha256_list(script_names + inline_marker)

        # Estrutura de diretórios: caminhos (sem host/arquivo) dos assets.
        directory_structure = self._extract_directories(dom)
        directory_hash = sha256_list(directory_structure)

        # Fingerprint composto: correlaciona campanhas ao longo do tempo.
        campaign_fingerprint = sha256_text(
            "|".join([dom_hash, asset_hash, script_hash, directory_hash])
        )

        bundle = FingerprintBundle(
            dom_hash=dom_hash,
            asset_hash=asset_hash,
            script_hash=script_hash,
            campaign_fingerprint=campaign_fingerprint,
            directory_structure=directory_structure,
        )
        logger.info(
            "kit_fingerprinted",
            dom_hash=dom_hash[:12],
            campaign_fingerprint=campaign_fingerprint[:12],
        )
        return bundle

    def _extract_directories(self, dom: DomStructure) -> list[str]:
        """Extrai a estrutura de diretórios dos assets/scripts.

        Regra de negócio: kits costumam manter a mesma árvore de pastas
        (ex.: ``/assets/js``, ``/css``); isso é um forte sinal de reuso.

        Returns:
            Lista ordenada e deduplicada de diretórios (sem o nome do arquivo).
        """
        directories: set[str] = set()
        for path in list(dom.assets) + list(dom.scripts_external) + list(dom.links):
            # Remove esquema+host mantendo apenas o caminho.
            clean = path.split("://", 1)[-1]
            if "/" in clean:
                clean = clean.split("/", 1)[-1]
            clean = clean.split("?", 1)[0].split("#", 1)[0]
            if "/" in clean:
                directory = clean.rsplit("/", 1)[0]
                if directory:
                    directories.add(directory)
        return sorted(directories)
