"""Detector de marca-alvo.

Arquitetura
-----------
Procura sinais de marcas conhecidas (bancos, fidelidade, marketplaces,
operadoras, fintechs) no texto visível, título, metatags, nomes de assets e
comentários. Cada marca tem um catálogo de palavras-chave e um setor.

Responsabilidade do componente
------------------------------
Produzir uma :class:`BrandDetection` (marca, setor, confiança, evidências)
que vira a tag MISP ``fraude:marca=<marca>`` e alimenta a correlação.

Fluxo de execução
-----------------
``detect(dom, text)`` -> agrega corpus -> pontua cada marca por número de
sinais -> retorna a marca de maior score (ou ``None``).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from phishing_intel.logging_config import get_logger
from phishing_intel.models.findings import BrandDetection, DomStructure
from phishing_intel.utils import normalize_text

logger = get_logger(__name__)


@dataclass(frozen=True)
class BrandSignature:
    """Assinatura de uma marca para detecção.

    Attributes:
        brand: Identificador normalizado (vira ``fraude:marca=<brand>``).
        sector: Setor da marca (bank, loyalty, marketplace, telecom, fintech).
        keywords: Termos que, se presentes, indicam a marca.
    """

    brand: str
    sector: str
    keywords: tuple[str, ...] = field(default_factory=tuple)


# Catálogo de marcas brasileiras/internacionais comuns em fraudes.
# Extensível: novas marcas podem ser adicionadas sem alterar a lógica.
BRAND_CATALOG: tuple[BrandSignature, ...] = (
    BrandSignature("itau", "bank", ("itau", "itaú", "itauunibanco", "iti")),
    BrandSignature("bradesco", "bank", ("bradesco", "bradescard", "next")),
    BrandSignature("santander", "bank", ("santander",)),
    BrandSignature("bb", "bank", ("banco do brasil", "bancodobrasil", "bb.com.br")),
    BrandSignature("caixa", "bank", ("caixa economica", "caixa econômica", "cef")),
    BrandSignature("nubank", "fintech", ("nubank", "nuconta", "roxinho")),
    BrandSignature("inter", "fintech", ("banco inter", "bancointer")),
    BrandSignature("c6", "fintech", ("c6 bank", "c6bank")),
    BrandSignature("picpay", "fintech", ("picpay",)),
    BrandSignature("mercadopago", "fintech", ("mercado pago", "mercadopago")),
    BrandSignature("livelo", "loyalty", ("livelo",)),
    BrandSignature("smiles", "loyalty", ("smiles",)),
    BrandSignature("latampass", "loyalty", ("latam pass", "latampass", "multiplus")),
    BrandSignature("dotz", "loyalty", ("dotz",)),
    BrandSignature(
        "mercadolivre",
        "marketplace",
        ("mercado livre", "mercadolivre", "mercadolibre"),
    ),
    BrandSignature("amazon", "marketplace", ("amazon",)),
    BrandSignature("magalu", "marketplace", ("magalu", "magazine luiza", "magazineluiza")),
    BrandSignature("vivo", "telecom", ("vivo", "telefonica", "telefônica")),
    BrandSignature("claro", "telecom", ("claro", "net claro")),
    BrandSignature("tim", "telecom", ("tim brasil", "tim.com.br")),
)


class BrandDetector:
    """Detecta a marca-alvo predominante de uma página de phishing."""

    def __init__(self, catalog: tuple[BrandSignature, ...] | None = None) -> None:
        """Inicializa o detector.

        Args:
            catalog: Catálogo de assinaturas de marca. Se ``None``, usa o
                catálogo padrão embutido.
        """
        self.catalog = catalog or BRAND_CATALOG

    def detect(self, dom: DomStructure, visible_text: str = "") -> BrandDetection | None:
        """Detecta a marca-alvo mais provável.

        Args:
            dom: Estrutura DOM (título, metatags, assets, comentários).
            visible_text: Texto visível extraído da página (opcional).

        Returns:
            A :class:`BrandDetection` de maior score, ou ``None`` se nenhuma
            marca conhecida for encontrada.
        """
        corpus = self._build_corpus(dom, visible_text)

        best: BrandDetection | None = None
        for signature in self.catalog:
            evidence = [kw for kw in signature.keywords if kw in corpus]
            if not evidence:
                continue
            # Confiança cresce com o número de sinais distintos encontrados.
            confidence = min(40 + 20 * len(evidence), 100)
            candidate = BrandDetection(
                brand=signature.brand,
                sector=signature.sector,
                confidence=confidence,
                evidence=evidence,
            )
            if best is None or candidate.confidence > best.confidence:
                best = candidate

        if best:
            logger.info(
                "brand_detected", brand=best.brand, confidence=best.confidence
            )
        else:
            logger.info("brand_not_detected")
        return best

    def _build_corpus(self, dom: DomStructure, visible_text: str) -> str:
        """Constrói o corpus normalizado usado na detecção.

        Agrega título, metatags, nomes de arquivo (assets/logos), comentários
        e o texto visível — todas as fontes citadas na especificação.
        """
        parts: list[str] = [dom.title, visible_text]
        parts.extend(dom.meta_tags.values())
        parts.extend(dom.file_names)
        parts.extend(dom.assets)
        parts.extend(dom.comments)
        return normalize_text(" ".join(p for p in parts if p))
