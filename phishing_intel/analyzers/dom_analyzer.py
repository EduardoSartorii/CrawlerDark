"""Analisador de DOM.

Arquitetura
-----------
Usa BeautifulSoup (parser ``lxml``) para extrair uma representação
estruturada do DOM: formulários, inputs, campos ocultos, scripts, links,
assets, URLs externas, metatags, comentários, classes/IDs e nomes de arquivo.

Responsabilidade do componente
------------------------------
Produzir um :class:`DomStructure` normalizado e um esqueleto de tags que
serve de base para o hash estrutural (fingerprint).

Fluxo de execução
-----------------
``analyze(html, base_url)`` -> parse -> extrai cada categoria -> monta o
esqueleto normalizado -> :class:`DomStructure`.
"""

from __future__ import annotations

from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup, Comment

from phishing_intel.logging_config import get_logger
from phishing_intel.models.findings import DomForm, DomStructure
from phishing_intel.utils import extract_domain, file_name_from_path

logger = get_logger(__name__)

# Extensões consideradas "assets" estáticos da página.
_ASSET_EXTENSIONS = (
    ".js",
    ".css",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".ico",
    ".woff",
    ".woff2",
    ".ttf",
)


class DomAnalyzer:
    """Extrai a estrutura normalizada do DOM de uma página HTML."""

    def analyze(self, html: str, base_url: str = "") -> DomStructure:
        """Analisa o HTML e retorna a estrutura DOM normalizada.

        Args:
            html: Código HTML da página.
            base_url: URL base para resolver links relativos e distinguir
                URLs externas das internas.

        Returns:
            :class:`DomStructure` populado. HTML vazio retorna estrutura vazia.
        """
        structure = DomStructure()
        if not html:
            return structure

        soup = BeautifulSoup(html, "lxml")
        base_domain = extract_domain(base_url)

        structure.title = soup.title.get_text(strip=True) if soup.title else ""
        structure.forms = self._extract_forms(soup)
        self._extract_scripts(soup, structure, base_url, base_domain)
        self._extract_links_and_assets(soup, structure, base_url, base_domain)
        self._extract_meta(soup, structure)
        self._extract_comments(soup, structure)
        self._extract_classes_ids(soup, structure)
        structure.normalized_skeleton = self._build_skeleton(soup)

        logger.info(
            "dom_analyzed",
            forms=len(structure.forms),
            scripts_ext=len(structure.scripts_external),
            assets=len(structure.assets),
        )
        return structure

    def _extract_forms(self, soup: BeautifulSoup) -> list[DomForm]:
        """Extrai formulários e seus campos (inputs, labels, placeholders).

        Regra de negócio: capturar ``action``/``method`` e a natureza dos
        campos é essencial para a classificação de phishing e a detecção de
        destinos de exfiltração via formulário.
        """
        forms: list[DomForm] = []
        for form in soup.find_all("form"):
            dom_form = DomForm(
                action=(form.get("action") or "").strip(),
                method=(form.get("method") or "get").strip().lower(),
            )
            # Coleta inputs, selects e textareas como campos do formulário.
            for field in form.find_all(["input", "select", "textarea"]):
                name = (field.get("name") or field.get("id") or "").strip()
                ftype = (field.get("type") or field.name or "").strip().lower()
                if name:
                    dom_form.input_names.append(name)
                if ftype:
                    dom_form.input_types.append(ftype)
                if ftype == "hidden" and name:
                    dom_form.hidden_fields.append(name)
                placeholder = (field.get("placeholder") or "").strip()
                if placeholder:
                    dom_form.placeholders.append(placeholder)
            # Labels ajudam a inferir o objetivo (ex.: "CPF", "senha").
            for label in form.find_all("label"):
                text = label.get_text(strip=True)
                if text:
                    dom_form.labels.append(text)
            forms.append(dom_form)
        return forms

    def _extract_scripts(
        self,
        soup: BeautifulSoup,
        structure: DomStructure,
        base_url: str,
        base_domain: str,
    ) -> None:
        """Separa scripts inline de scripts externos e coleta nomes de arquivo."""
        for script in soup.find_all("script"):
            src = script.get("src")
            if src:
                resolved = urljoin(base_url, src) if base_url else src
                structure.scripts_external.append(resolved)
                fname = file_name_from_path(src)
                if fname:
                    structure.file_names.append(fname)
                self._register_external(resolved, base_domain, structure)
            else:
                content = script.get_text()
                if content and content.strip():
                    structure.scripts_inline.append(content)

    def _extract_links_and_assets(
        self,
        soup: BeautifulSoup,
        structure: DomStructure,
        base_url: str,
        base_domain: str,
    ) -> None:
        """Coleta links (``<a>``) e assets (``link``/``img``/``script``)."""
        # Links de navegação.
        for anchor in soup.find_all("a", href=True):
            href = anchor["href"].strip()
            resolved = urljoin(base_url, href) if base_url else href
            structure.links.append(resolved)
            self._register_external(resolved, base_domain, structure)

        # Assets estáticos: CSS (link), imagens (img) e outros recursos.
        for tag, attr in (("link", "href"), ("img", "src")):
            for element in soup.find_all(tag):
                value = element.get(attr)
                if not value:
                    continue
                resolved = urljoin(base_url, value) if base_url else value
                structure.assets.append(resolved)
                fname = file_name_from_path(value)
                if fname:
                    structure.file_names.append(fname)
                self._register_external(resolved, base_domain, structure)

        # Scripts externos também contam como assets.
        structure.assets.extend(structure.scripts_external)

    def _register_external(
        self, url: str, base_domain: str, structure: DomStructure
    ) -> None:
        """Registra uma URL como externa se apontar para outro domínio.

        Regra de negócio: URLs externas em uma página de phishing costumam
        indicar CDNs legítimas (mimetismo) ou o próprio destino de coleta.
        """
        if not url.lower().startswith(("http://", "https://")):
            return
        domain = extract_domain(url)
        if domain and base_domain and domain != base_domain:
            structure.external_urls.append(url)

    def _extract_meta(self, soup: BeautifulSoup, structure: DomStructure) -> None:
        """Extrai metatags relevantes (name/property -> content)."""
        for meta in soup.find_all("meta"):
            key = meta.get("name") or meta.get("property") or meta.get("charset")
            content = meta.get("content", "")
            if key:
                structure.meta_tags[key.lower()] = content

    def _extract_comments(
        self, soup: BeautifulSoup, structure: DomStructure
    ) -> None:
        """Extrai comentários HTML (podem revelar autor/kit/depuração)."""
        for comment in soup.find_all(string=lambda t: isinstance(t, Comment)):
            text = str(comment).strip()
            if text:
                structure.comments.append(text)

    def _extract_classes_ids(
        self, soup: BeautifulSoup, structure: DomStructure
    ) -> None:
        """Coleta classes CSS e IDs HTML (sinais de fingerprint de kit)."""
        classes: set[str] = set()
        ids: set[str] = set()
        for element in soup.find_all(True):
            for cls in element.get("class", []) or []:
                classes.add(cls)
            element_id = element.get("id")
            if element_id:
                ids.add(element_id)
        structure.css_classes = sorted(classes)
        structure.html_ids = sorted(ids)

    def _build_skeleton(self, soup: BeautifulSoup) -> str:
        """Constrói o esqueleto normalizado de tags do DOM.

        Regra de negócio: o esqueleto ignora textos e atributos, capturando
        apenas a *sequência de tags*. Isso torna o hash estrutural resiliente
        a mudanças cosméticas (textos), mas sensível à estrutura do kit.

        Returns:
            String com nomes de tags separados por ``>`` na ordem do documento.
        """
        tags = [element.name for element in soup.find_all(True)]
        return ">".join(tags)
