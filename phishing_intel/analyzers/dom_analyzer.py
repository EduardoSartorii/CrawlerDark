"""Analisador de estrutura DOM (HTML estatico).

Responsabilidade do componente
-------------------------------
Extrair, a partir do HTML bruto, todos os elementos estruturalmente
relevantes para deteccao de phishing: formularios (e seus campos, incluindo
ocultos), scripts (inline e externos), links, assets, URLs externas,
metatags e comentarios HTML. Alem disso, produz uma representacao
normalizada da arvore DOM e o respectivo hash estrutural (SHA256), que e o
principal insumo do ``kit_fingerprint``.

Fluxo de execucao
------------------
1. Parseia o HTML com BeautifulSoup (parser ``lxml``, tolerante a HTML
   malformado — comum em kits de phishing produzidos as pressas).
2. Extrai cada categoria de elemento em listas tipadas
   (``models.findings.DomFinding``).
3. Constroi uma representacao normalizada da arvore (apenas tags e atributos
   estruturais, sem texto/valores) e calcula o hash SHA256 correspondente.

Regra de negocio
----------------
A normalizacao IGNORA conteudo textual e valores de atributos "de dados"
(ex.: ``value``, ``placeholder`` traduzido) de proposito: o objetivo do
hash estrutural e reconhecer o MESMO KIT reutilizado em campanhas
diferentes, mesmo quando o operador troca textos, logos ou o dominio da
marca-alvo. Apenas a "forma" do DOM (tags, atributos estruturais como
``type``/``name``/``class``/``id`` e a hierarquia) compoe o hash.
"""

from __future__ import annotations

import hashlib
import logging
from urllib.parse import urlparse

from bs4 import BeautifulSoup, Comment
from bs4.element import Tag

from models.findings import AssetReference, DomFinding, FormFieldFinding, FormFinding, ScriptReference

logger = logging.getLogger(__name__)

_ASSET_EXTENSIONS = {
    ".png": "image",
    ".jpg": "image",
    ".jpeg": "image",
    ".gif": "image",
    ".svg": "image",
    ".webp": "image",
    ".ico": "image",
    ".css": "stylesheet",
    ".woff": "font",
    ".woff2": "font",
    ".ttf": "font",
    ".eot": "font",
}

# Atributos considerados "estruturais" (compoem o hash do kit). Atributos
# puramente de apresentacao dinamica (ex.: `style` inline com cores
# customizadas) sao deliberadamente excluidos para reduzir ruido.
_STRUCTURAL_ATTRIBUTES = ("type", "name", "class", "id", "rel", "method")


def _filename_from_url(url: str) -> str | None:
    """Extrai o nome de arquivo de uma URL, quando presente."""
    path = urlparse(url).path
    if not path or path.endswith("/"):
        return None
    return path.rsplit("/", maxsplit=1)[-1] or None


def _classify_asset(url: str) -> str:
    """Classifica o tipo de asset com base na extensao do arquivo."""
    lowered = url.lower()
    for extension, asset_type in _ASSET_EXTENSIONS.items():
        if lowered.endswith(extension):
            return asset_type
    return "unknown"


def _extract_forms(soup: BeautifulSoup) -> list[FormFinding]:
    """Extrai todos os formularios e seus campos (incluindo ocultos)."""
    forms: list[FormFinding] = []
    for form_tag in soup.find_all("form"):
        fields: list[FormFieldFinding] = []
        for field_tag in form_tag.find_all(["input", "textarea", "select"]):
            field_type = field_tag.get("type", "text") if field_tag.name == "input" else field_tag.name
            fields.append(
                FormFieldFinding(
                    name=field_tag.get("name"),
                    field_id=field_tag.get("id"),
                    field_type=(field_type or "text").lower(),
                    placeholder=field_tag.get("placeholder"),
                    label=_infer_label(field_tag),
                    is_hidden=(field_type or "").lower() == "hidden",
                    autocomplete=field_tag.get("autocomplete"),
                )
            )
        forms.append(
            FormFinding(
                action=form_tag.get("action"),
                method=(form_tag.get("method") or "GET").upper(),
                form_id=form_tag.get("id"),
                css_classes=form_tag.get("class", []),
                fields=fields,
            )
        )
    return forms


def _infer_label(field_tag: Tag) -> str | None:
    """Tenta inferir o texto de label associado a um campo de formulario.

    Regra de negocio: labels/placeholders sao o principal sinal textual
    usado pelo ``form_classifier`` para diferenciar, por exemplo, captura de
    CPF (identity theft) de captura de numero de cartao (card harvesting).
    """
    field_id = field_tag.get("id")
    if field_id:
        label_tag = field_tag.find_parent().find("label", attrs={"for": field_id})
        if label_tag and label_tag.text.strip():
            return label_tag.text.strip()
    parent_label = field_tag.find_parent("label")
    if parent_label and parent_label.text.strip():
        return parent_label.text.strip()
    return None


def _extract_scripts(soup: BeautifulSoup) -> list[ScriptReference]:
    """Extrai referencias de script, inline ou externas."""
    scripts: list[ScriptReference] = []
    for script_tag in soup.find_all("script"):
        src = script_tag.get("src")
        if src:
            scripts.append(ScriptReference(src=src, is_inline=False, filename=_filename_from_url(src)))
        else:
            content = script_tag.string or ""
            content_hash = hashlib.sha256(content.encode("utf-8", errors="ignore")).hexdigest()
            scripts.append(ScriptReference(is_inline=True, inline_content_hash=content_hash))
    return scripts


def _extract_assets(soup: BeautifulSoup) -> list[AssetReference]:
    """Extrai assets estaticos referenciados via ``img``, ``link`` e ``source``."""
    assets: list[AssetReference] = []
    for img_tag in soup.find_all("img"):
        src = img_tag.get("src")
        if src:
            assets.append(AssetReference(url=src, asset_type="image", filename=_filename_from_url(src)))
    for link_tag in soup.find_all("link"):
        href = link_tag.get("href")
        if href:
            assets.append(
                AssetReference(url=href, asset_type=_classify_asset(href), filename=_filename_from_url(href))
            )
    for source_tag in soup.find_all("source"):
        src = source_tag.get("src")
        if src:
            assets.append(
                AssetReference(url=src, asset_type=_classify_asset(src), filename=_filename_from_url(src))
            )
    return assets


def _extract_links(soup: BeautifulSoup) -> list[str]:
    """Extrai todos os links de navegacao (``<a href>``)."""
    return [a.get("href") for a in soup.find_all("a") if a.get("href")]


def _extract_external_urls(soup: BeautifulSoup, base_domain: str | None) -> list[str]:
    """Identifica URLs absolutas que apontam para dominios diferentes do analisado."""
    external: set[str] = set()
    for tag in soup.find_all(["a", "script", "link", "img", "form", "iframe"]):
        for attribute in ("href", "src", "action"):
            value = tag.get(attribute)
            if not value or not value.startswith(("http://", "https://")):
                continue
            parsed = urlparse(value)
            if base_domain and parsed.netloc and parsed.netloc != base_domain:
                external.add(value)
            elif not base_domain:
                external.add(value)
    return sorted(external)


def _extract_meta_tags(soup: BeautifulSoup) -> dict[str, str]:
    """Extrai metatags relevantes (``name``/``property`` -> ``content``)."""
    meta_tags: dict[str, str] = {}
    for meta_tag in soup.find_all("meta"):
        key = meta_tag.get("name") or meta_tag.get("property")
        content = meta_tag.get("content")
        if key and content is not None:
            meta_tags[key] = content
    return meta_tags


def _extract_comments(soup: BeautifulSoup) -> list[str]:
    """Extrai comentarios HTML (frequentemente contem metadados do kit, ex.: autor/versao)."""
    return [str(comment).strip() for comment in soup.find_all(string=lambda text: isinstance(text, Comment))]


def _extract_css_classes_and_ids(soup: BeautifulSoup) -> tuple[list[str], list[str]]:
    """Coleta o conjunto (deduplicado e ordenado) de classes CSS e IDs usados na pagina."""
    classes: set[str] = set()
    ids: set[str] = set()
    for tag in soup.find_all(True):
        for css_class in tag.get("class", []) or []:
            classes.add(css_class)
        html_id = tag.get("id")
        if html_id:
            ids.add(html_id)
    return sorted(classes), sorted(ids)


def _normalize_tag(tag: Tag) -> str:
    """Serializa um unico elemento em uma representacao estrutural normalizada."""
    attrs = []
    for attribute in _STRUCTURAL_ATTRIBUTES:
        value = tag.get(attribute)
        if value:
            normalized_value = ",".join(sorted(value)) if isinstance(value, list) else value
            attrs.append(f"{attribute}={normalized_value}")
    attrs_repr = ";".join(attrs)
    return f"<{tag.name} {attrs_repr}>"


def _build_normalized_structure(soup: BeautifulSoup) -> str:
    """Constroi a representacao normalizada da arvore DOM (pre-order traversal)."""
    root = soup.find("html") or soup
    parts: list[str] = []

    def _walk(node: Tag) -> None:
        parts.append(_normalize_tag(node))
        for child in node.find_all(True, recursive=False):
            _walk(child)

    if isinstance(root, Tag):
        _walk(root)
    return "".join(parts)


def analyze_dom(html: str, base_url: str | None = None) -> DomFinding:
    """Executa a analise estrutural completa de um documento HTML.

    Args:
        html: Conteudo HTML bruto a ser analisado.
        base_url: URL de origem do HTML, usada para diferenciar links
            internos de URLs externas.

    Returns:
        :class:`DomFinding` totalmente preenchido, incluindo o hash
        estrutural do DOM.
    """
    soup = BeautifulSoup(html, "lxml")
    base_domain = urlparse(base_url).netloc if base_url else None

    css_classes, html_ids = _extract_css_classes_and_ids(soup)
    normalized_structure = _build_normalized_structure(soup)
    structural_hash = hashlib.sha256(normalized_structure.encode("utf-8")).hexdigest()

    title_tag = soup.find("title")

    return DomFinding(
        forms=_extract_forms(soup),
        scripts=_extract_scripts(soup),
        links=_extract_links(soup),
        assets=_extract_assets(soup),
        external_urls=_extract_external_urls(soup, base_domain),
        meta_tags=_extract_meta_tags(soup),
        comments=_extract_comments(soup),
        css_classes=css_classes,
        html_ids=html_ids,
        title=title_tag.text.strip() if title_tag and title_tag.text else None,
        normalized_structure=normalized_structure,
        structural_hash=structural_hash,
    )
