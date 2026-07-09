"""
DOM static analyzer for phishing HTML pages.

Parses HTML structure to extract forms, scripts, links, assets,
metatags, and comments. Generates normalized DOM and structural hash.

Architectural Responsibility:
    Primary static analysis component for partner-provided HTML.
    Feeds form classification, kit fingerprinting, and brand detection.

Flow:
    1. Parse HTML with BeautifulSoup/lxml
    2. Extract all structural elements
    3. Normalize DOM tree
    4. Compute structural hash for correlation
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urljoin, urlparse

import structlog
from bs4 import BeautifulSoup, Comment

from phishing_intel.models.findings import (
    AssetFinding,
    DOMFinding,
    FormField,
    FormFinding,
    LinkFinding,
    ScriptFinding,
)
from phishing_intel.utils import sha256_hash

logger = structlog.get_logger(__name__)


class DOMAnalyzer:
    """
    Static DOM analysis engine for phishing pages.

    Extracts complete page structure for classification, fingerprinting,
    and IOC extraction without requiring live page interaction.
    """

    ASSET_TAGS = {
        "img": "image",
        "link": "stylesheet",
        "script": "script",
        "source": "media",
        "video": "video",
        "audio": "audio",
        "iframe": "iframe",
    }

    def __init__(self, base_url: str = "") -> None:
        """
        Initialize DOM analyzer.

        Args:
            base_url: Base URL for resolving relative links.
        """
        self.base_url = base_url

    def analyze(self, html: str, base_url: str | None = None) -> DOMFinding:
        """
        Perform complete DOM static analysis.

        Args:
            html: Raw HTML content.
            base_url: Optional override for relative URL resolution.

        Returns:
            Complete DOMFinding with all extracted elements.
        """
        if base_url:
            self.base_url = base_url

        logger.info("dom_analysis_start", base_url=self.base_url, html_length=len(html))

        soup = BeautifulSoup(html, "lxml")

        forms = self._extract_forms(soup)
        scripts = self._extract_scripts(soup)
        links = self._extract_links(soup)
        assets = self._extract_assets(soup)
        metatags = self._extract_metatags(soup)
        comments = self._extract_comments(soup)
        css_classes = self._extract_css_classes(soup)
        html_ids = self._extract_ids(soup)
        filenames = self._extract_filenames(assets, scripts, links)
        external_urls = self._extract_external_urls(links, assets, scripts)
        # Include form action URLs as potential external exfiltration endpoints
        for form in forms:
            if form.action and form.action.startswith("http"):
                parsed = urlparse(form.action)
                base_domain = urlparse(self.base_url).netloc if self.base_url else ""
                if parsed.netloc and parsed.netloc != base_domain:
                    external_urls.append(form.action)
        external_urls = sorted(set(external_urls))

        normalized = self._normalize_dom(soup)
        structural_hash = sha256_hash(normalized)

        finding = DOMFinding(
            forms=forms,
            scripts=scripts,
            links=links,
            assets=assets,
            external_urls=external_urls,
            metatags=metatags,
            html_comments=comments,
            css_classes=sorted(set(css_classes)),
            html_ids=sorted(set(html_ids)),
            filenames=sorted(set(filenames)),
            normalized_dom=normalized,
            structural_hash=structural_hash,
        )

        logger.info(
            "dom_analysis_complete",
            forms=len(forms),
            scripts=len(scripts),
            structural_hash=structural_hash,
        )
        return finding

    def _extract_forms(self, soup: BeautifulSoup) -> list[FormFinding]:
        """Extract all form elements with fields and attributes."""
        forms: list[FormFinding] = []
        for form in soup.find_all("form"):
            fields: list[FormField] = []
            form_classes: list[str] = []
            form_ids: list[str] = []

            if form.get("class"):
                form_classes = form.get("class", [])
            if form.get("id"):
                form_ids.append(form["id"])

            for inp in form.find_all(["input", "select", "textarea"]):
                label = ""
                if inp.get("id"):
                    label_el = form.find("label", attrs={"for": inp["id"]})
                    if label_el:
                        label = label_el.get_text(strip=True)

                field = FormField(
                    name=inp.get("name", ""),
                    field_type=inp.get("type", inp.name),
                    id=inp.get("id", ""),
                    placeholder=inp.get("placeholder", ""),
                    label=label,
                    css_class=" ".join(inp.get("class", [])),
                    is_hidden=inp.get("type") == "hidden",
                    autocomplete=inp.get("autocomplete", ""),
                )
                fields.append(field)

            action = form.get("action", "")
            if action and self.base_url:
                action = urljoin(self.base_url, action)

            forms.append(
                FormFinding(
                    action=action,
                    method=form.get("method", "GET").upper(),
                    fields=fields,
                    css_classes=form_classes,
                    html_ids=form_ids,
                )
            )
        return forms

    def _extract_scripts(self, soup: BeautifulSoup) -> list[ScriptFinding]:
        """Extract script tags with inline/external classification."""
        scripts: list[ScriptFinding] = []
        for script in soup.find_all("script"):
            src = script.get("src", "")
            if src and self.base_url:
                src = urljoin(self.base_url, src)

            content = script.string or ""
            scripts.append(
                ScriptFinding(
                    src=src,
                    inline=not bool(script.get("src")),
                    content_hash=sha256_hash(content) if content.strip() else "",
                    content_preview=content[:200] if content else "",
                )
            )
        return scripts

    def _extract_links(self, soup: BeautifulSoup) -> list[LinkFinding]:
        """Extract anchor links."""
        links: list[LinkFinding] = []
        for a in soup.find_all("a", href=True):
            href = a["href"]
            if self.base_url:
                href = urljoin(self.base_url, href)
            links.append(
                LinkFinding(href=href, text=a.get_text(strip=True)[:100], rel=a.get("rel", [""])[0] if a.get("rel") else "")
            )
        return links

    def _extract_assets(self, soup: BeautifulSoup) -> list[AssetFinding]:
        """Extract external assets (images, stylesheets, etc.)."""
        assets: list[AssetFinding] = []
        for tag_name, asset_type in self.ASSET_TAGS.items():
            for el in soup.find_all(tag_name):
                url_attr = "src" if tag_name != "link" else "href"
                url = el.get(url_attr, "")
                if not url:
                    continue
                if self.base_url:
                    url = urljoin(self.base_url, url)
                filename = urlparse(url).path.split("/")[-1] if url else ""
                assets.append(AssetFinding(url=url, asset_type=asset_type, filename=filename))
        return assets

    def _extract_metatags(self, soup: BeautifulSoup) -> dict[str, str]:
        """Extract meta tag name/content pairs."""
        metatags: dict[str, str] = {}
        for meta in soup.find_all("meta"):
            name = meta.get("name") or meta.get("property", "")
            content = meta.get("content", "")
            if name:
                metatags[name.lower()] = content
        return metatags

    def _extract_comments(self, soup: BeautifulSoup) -> list[str]:
        """Extract HTML comments (often contain kit markers)."""
        return [
            str(c).strip()
            for c in soup.find_all(string=lambda t: isinstance(t, Comment))
            if str(c).strip()
        ]

    def _extract_css_classes(self, soup: BeautifulSoup) -> list[str]:
        """Collect all CSS class names from page."""
        classes: list[str] = []
        for el in soup.find_all(True):
            if el.get("class"):
                classes.extend(el["class"])
        return classes

    def _extract_ids(self, soup: BeautifulSoup) -> list[str]:
        """Collect all HTML element IDs."""
        return [el["id"] for el in soup.find_all(id=True)]

    def _extract_filenames(
        self,
        assets: list[AssetFinding],
        scripts: list[ScriptFinding],
        links: list[LinkFinding],
    ) -> list[str]:
        """Extract filenames from URLs for kit fingerprinting."""
        filenames: list[str] = []
        for asset in assets:
            if asset.filename:
                filenames.append(asset.filename)
        for script in scripts:
            if script.src:
                fn = urlparse(script.src).path.split("/")[-1]
                if fn:
                    filenames.append(fn)
        return filenames

    def _extract_external_urls(
        self,
        links: list[LinkFinding],
        assets: list[AssetFinding],
        scripts: list[ScriptFinding],
    ) -> list[str]:
        """Identify URLs pointing to external domains."""
        if not self.base_url:
            return []

        base_domain = urlparse(self.base_url).netloc
        external: set[str] = set()

        all_urls = (
            [l.href for l in links]
            + [a.url for a in assets]
            + [s.src for s in scripts if s.src]
        )
        for url in all_urls:
            if not url or url.startswith(("#", "javascript:", "data:")):
                continue
            parsed = urlparse(url)
            if parsed.netloc and parsed.netloc != base_domain:
                external.add(url)
        return sorted(external)

    def _normalize_dom(self, soup: BeautifulSoup) -> str:
        """
        Generate normalized DOM structure for hashing.

        Strips dynamic content and normalizes whitespace to enable
        structural comparison across similar kit deployments.
        """
        # Clone and strip script contents for structural comparison
        normalized_soup = BeautifulSoup(str(soup), "lxml")
        for script in normalized_soup.find_all("script"):
            if script.string:
                script.string.replace_with("[SCRIPT]")

        text = normalized_soup.get_text(separator=" ", strip=True)
        text = re.sub(r"\s+", " ", text)
        return text.lower()
