"""Detector de marca-alvo (brand_detector).

Responsabilidade do componente
-------------------------------
Identificar automaticamente qual instituicao (financeira, fidelidade,
marketplace, operadora, fintech) esta sendo impersonada por uma pagina de
phishing, combinando sinais textuais (titulo, metatags, comentarios,
texto visivel), nomes de assets (ex.: ``logo-itau.png``) e dominios
referenciados (links, actions de formulario, URLs externas) contra a base
de marcas conhecidas configurada em ``config.yaml`` (``brands.known_brands``).

Fluxo de execucao
------------------
1. Constroi um "corpus" textual normalizado (minusculas, sem acentos) a
   partir do HTML bruto (texto visivel) e dos metadados do ``DomFinding``.
2. Para cada marca conhecida, soma: (a) ocorrencias de palavras-chave no
   corpus textual, e (b) casamentos de dominio nas URLs referenciadas —
   este ultimo sinal recebe peso maior, pois phishing kits raramente
   referenciam o dominio real da marca-alvo a menos que estejam
   deliberadamente imitando recursos legitimos (ex.: favicon original).
3. A marca com maior score "vence"; a confianca e normalizada pelo score
   maximo teoricamente atingivel para aquela marca.
"""

from __future__ import annotations

import unicodedata
from urllib.parse import urlparse

from bs4 import BeautifulSoup

from config.settings import KnownBrand
from models.findings import BrandDetectionResult, DomFinding

_DOMAIN_MATCH_WEIGHT = 5
_KEYWORD_MATCH_WEIGHT = 1


def _strip_accents(text: str) -> str:
    """Remove acentuacao para tornar a busca por palavras-chave resiliente a pt-BR."""
    normalized = unicodedata.normalize("NFKD", text)
    return "".join(char for char in normalized if not unicodedata.combining(char))


def _extract_visible_text(html: str) -> str:
    """Extrai o texto visivel do HTML, descartando script/style."""
    soup = BeautifulSoup(html, "lxml")
    for irrelevant in soup(["script", "style"]):
        irrelevant.decompose()
    return soup.get_text(separator=" ", strip=True)


def _build_text_corpus(html: str, dom: DomFinding) -> str:
    """Concatena todos os sinais textuais disponiveis em um unico corpus normalizado."""
    parts = [
        _extract_visible_text(html),
        dom.title or "",
        " ".join(dom.meta_tags.values()),
        " ".join(dom.comments),
        " ".join(asset.filename or "" for asset in dom.assets),
        " ".join(dom.css_classes),
        " ".join(dom.html_ids),
    ]
    return _strip_accents(" ".join(parts).lower())


def _referenced_domains(dom: DomFinding) -> set[str]:
    """Coleta o conjunto de dominios referenciados por links/assets/forms/URLs externas."""
    candidate_urls = list(dom.links) + list(dom.external_urls) + [asset.url for asset in dom.assets]
    candidate_urls += [form.action for form in dom.forms if form.action]

    domains: set[str] = set()
    for url in candidate_urls:
        parsed = urlparse(url)
        if parsed.netloc:
            domains.add(parsed.netloc.lower())
    return domains


def detect_brand(html: str, dom: DomFinding, known_brands: list[KnownBrand]) -> BrandDetectionResult:
    """Detecta a marca-alvo mais provavel de uma pagina de phishing.

    Args:
        html: HTML bruto (usado para extrair texto visivel).
        dom: Resultado da analise de DOM (metadados, assets, links).
        known_brands: Base de marcas conhecidas configurada.

    Returns:
        :class:`BrandDetectionResult` com a marca vencedora (ou ``None`` se
        nenhum sinal for encontrado), sua categoria, confianca e as
        evidencias (palavras-chave/dominios) que motivaram a decisao.
    """
    if not known_brands:
        return BrandDetectionResult()

    corpus = _build_text_corpus(html, dom)
    referenced_domains = _referenced_domains(dom)

    best_result = BrandDetectionResult()
    best_score = 0

    for brand in known_brands:
        matched_keywords = [kw for kw in brand.keywords if _strip_accents(kw.lower()) in corpus]
        matched_domains = [
            domain
            for domain in brand.domains
            if any(domain.lower() in referenced or referenced in domain.lower() for referenced in referenced_domains)
        ]

        score = len(matched_keywords) * _KEYWORD_MATCH_WEIGHT + len(matched_domains) * _DOMAIN_MATCH_WEIGHT
        if score <= best_score:
            continue

        max_theoretical_score = len(brand.keywords) * _KEYWORD_MATCH_WEIGHT + len(brand.domains) * _DOMAIN_MATCH_WEIGHT
        confidence = min(1.0, score / max_theoretical_score) if max_theoretical_score else 0.0

        best_score = score
        best_result = BrandDetectionResult(
            target_brand=brand.name,
            category=brand.category,
            confidence=round(confidence, 2),
            matched_keywords=matched_keywords,
            matched_domains=matched_domains,
        )

    return best_result
