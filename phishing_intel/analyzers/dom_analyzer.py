"""DOM analyzer.

Component responsibility
------------------------
Perform a complete static analysis of an HTML document and emit a
:class:`~phishing_intel.models.findings.DOMAnalysis`. This is the backbone of
the primary (analysis-first) flow: everything downstream (form classification,
kit fingerprinting, brand detection) consumes its output.

Execution flow
--------------
``DOMAnalyzer.analyze(html, base_url)`` ->
  1. Parse the HTML with BeautifulSoup (lxml backend).
  2. Extract forms/inputs/hidden-fields/scripts/links/assets/meta/comments.
  3. Collect CSS classes, HTML ids and referenced filenames.
  4. Build a *normalised DOM skeleton* (tag structure only) and hash it to
     produce a stable ``structural_hash`` used for correlation.
"""

from __future__ import annotations

from typing import List, Optional

from bs4 import BeautifulSoup, Comment

from phishing_intel.logging_config import get_logger
from phishing_intel.models.findings import DOMAnalysis, FormField, FormInfo
from phishing_intel.utils import (
    dedupe_preserve_order,
    extract_domain,
    filename_from_url,
    is_external_url,
    sha256_text,
)

logger = get_logger(__name__)

# HTML attributes that reference external assets/resources.
_ASSET_ATTRS = {
    "img": "src",
    "script": "src",
    "link": "href",
    "iframe": "src",
    "source": "src",
    "video": "src",
    "audio": "src",
    "embed": "src",
    "object": "data",
}

# Tags whose presence/order defines the structural skeleton. Volatile content
# (text, attribute values) is deliberately excluded so cosmetic edits by an
# operator do not change the structural hash.
_STRUCTURAL_TAGS_IGNORED = {"br", "wbr"}


class DOMAnalyzer:
    """Static HTML/DOM analyzer."""

    def __init__(self, parser: str = "lxml") -> None:
        """Create the analyzer.

        Parameters
        ----------
        parser:
            BeautifulSoup parser backend. ``lxml`` is fast and lenient; falls
            back to the stdlib ``html.parser`` when lxml is unavailable.
        """

        self.parser = parser

    def _make_soup(self, html: str) -> BeautifulSoup:
        """Build a BeautifulSoup tree, degrading gracefully if lxml is absent."""

        try:
            return BeautifulSoup(html or "", self.parser)
        except Exception:  # pragma: no cover - defensive fallback
            logger.warning("dom.parser_fallback", requested=self.parser)
            return BeautifulSoup(html or "", "html.parser")

    def _label_for_field(self, soup: BeautifulSoup, field) -> Optional[str]:
        """Best-effort resolution of the human label associated with a field.

        Business rule: kits frequently phrase labels ("Senha", "CPF", "Token")
        that reveal the harvested data type, so we surface them for the form
        classifier. We check, in order: an explicit ``<label for=id>``, a
        wrapping ``<label>`` and finally the ``aria-label`` attribute.
        """

        field_id = field.get("id")
        if field_id:
            label = soup.find("label", attrs={"for": field_id})
            if label and label.get_text(strip=True):
                return label.get_text(strip=True)
        parent_label = field.find_parent("label")
        if parent_label and parent_label.get_text(strip=True):
            return parent_label.get_text(strip=True)
        return field.get("aria-label")

    def _extract_field(self, soup: BeautifulSoup, element) -> FormField:
        """Convert a BeautifulSoup input-like element into a ``FormField``."""

        field_type = (element.get("type") or "").lower() or None
        return FormField(
            tag=element.name,
            type=field_type,
            name=element.get("name"),
            id=element.get("id"),
            placeholder=element.get("placeholder"),
            label=self._label_for_field(soup, element),
            hidden=(field_type == "hidden"),
            value=element.get("value"),
        )

    def analyze(self, html: str, base_url: Optional[str] = None) -> DOMAnalysis:
        """Run the full DOM analysis.

        Parameters
        ----------
        html:
            Raw HTML document.
        base_url:
            The URL the HTML came from; used to distinguish internal from
            external references.

        Returns
        -------
        DOMAnalysis
        """

        soup = self._make_soup(html)
        base_domain = extract_domain(base_url) if base_url else None

        forms: List[FormInfo] = []
        hidden_fields: List[FormField] = []

        # --- Forms & their fields -------------------------------------------
        for form in soup.find_all("form"):
            fields: List[FormField] = []
            for element in form.find_all(["input", "select", "textarea"]):
                field = self._extract_field(soup, element)
                fields.append(field)
                if field.hidden:
                    hidden_fields.append(field)
            forms.append(
                FormInfo(
                    action=form.get("action"),
                    method=(form.get("method") or "get").lower(),
                    id=form.get("id"),
                    css_classes=form.get("class", []) or [],
                    fields=fields,
                )
            )

        # Also capture hidden inputs that live outside a <form>.
        for element in soup.find_all("input", attrs={"type": "hidden"}):
            if not element.find_parent("form"):
                hidden_fields.append(self._extract_field(soup, element))

        # --- Scripts --------------------------------------------------------
        scripts_inline: List[str] = []
        scripts_external: List[str] = []
        for script in soup.find_all("script"):
            src = script.get("src")
            if src:
                scripts_external.append(src)
            else:
                content = script.string or script.get_text()
                if content and content.strip():
                    scripts_inline.append(content)

        # --- Links ----------------------------------------------------------
        links = [a.get("href") for a in soup.find_all("a", href=True)]

        # --- Assets & external URLs ----------------------------------------
        assets: List[str] = []
        external_urls: List[str] = []
        for tag_name, attr in _ASSET_ATTRS.items():
            for tag in soup.find_all(tag_name):
                ref = tag.get(attr)
                if ref:
                    assets.append(ref)
        # External URLs are gathered from every href/src that leaves the domain.
        for ref in list(links) + assets + scripts_external:
            if ref and is_external_url(ref, base_domain):
                external_urls.append(ref)

        # --- Meta tags ------------------------------------------------------
        meta_tags: dict[str, str] = {}
        for meta in soup.find_all("meta"):
            key = meta.get("name") or meta.get("property") or meta.get("http-equiv")
            content = meta.get("content")
            if key and content is not None:
                meta_tags[key.lower()] = content

        # --- HTML comments --------------------------------------------------
        comments = [
            str(c).strip()
            for c in soup.find_all(string=lambda text: isinstance(text, Comment))
            if str(c).strip()
        ]

        # --- CSS classes & HTML ids ----------------------------------------
        css_classes: List[str] = []
        html_ids: List[str] = []
        for tag in soup.find_all(True):
            classes = tag.get("class")
            if classes:
                css_classes.extend(classes)
            tag_id = tag.get("id")
            if tag_id:
                html_ids.append(tag_id)

        # --- Referenced filenames ------------------------------------------
        filenames: List[str] = []
        for ref in assets + scripts_external + [x for x in links if x]:
            name = filename_from_url(ref)
            if name and "." in name:
                filenames.append(name)

        # --- Normalised DOM skeleton + structural hash ---------------------
        normalized_dom = self._normalize_dom(soup)
        structural_hash = sha256_text(normalized_dom)

        analysis = DOMAnalysis(
            forms=forms,
            hidden_fields=hidden_fields,
            scripts_inline=scripts_inline,
            scripts_external=dedupe_preserve_order(scripts_external),
            links=dedupe_preserve_order([x for x in links if x]),
            assets=dedupe_preserve_order(assets),
            external_urls=dedupe_preserve_order(external_urls),
            meta_tags=meta_tags,
            comments=comments,
            css_classes=dedupe_preserve_order(css_classes),
            html_ids=dedupe_preserve_order(html_ids),
            filenames=dedupe_preserve_order(filenames),
            title=(soup.title.get_text(strip=True) if soup.title else None),
            normalized_dom=normalized_dom,
            structural_hash=structural_hash,
        )

        logger.info(
            "dom.analyzed",
            forms=len(analysis.forms),
            scripts=len(analysis.scripts_inline) + len(analysis.scripts_external),
            assets=len(analysis.assets),
            structural_hash=structural_hash,
        )
        return analysis

    def _normalize_dom(self, soup: BeautifulSoup) -> str:
        """Produce a normalised, content-free skeleton of the DOM.

        The skeleton is the depth-annotated sequence of element tag names. It
        ignores text nodes and attribute *values* (which operators tweak often)
        while preserving the *structure* (which the underlying kit dictates).
        This makes the resulting hash resilient to cosmetic changes but
        sensitive to genuine template differences.
        """

        parts: List[str] = []

        def walk(node, depth: int) -> None:
            for child in getattr(node, "children", []):
                name = getattr(child, "name", None)
                if not name or name in _STRUCTURAL_TAGS_IGNORED:
                    continue
                parts.append(f"{depth}:{name}")
                walk(child, depth + 1)

        # Prefer <body> as the anchor; fall back to the whole document.
        root = soup.body or soup
        walk(root, 0)
        return "|".join(parts)
