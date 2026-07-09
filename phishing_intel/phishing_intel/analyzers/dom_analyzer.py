"""DOM analyzer for extracting phishing-relevant page structure."""

from __future__ import annotations

import hashlib
import re
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup, Comment

from phishing_intel.models.findings import DomAnalysisResult, DomForm


class DomAnalyzer:
    """Performs static DOM extraction and structure hashing."""

    def analyze(self, html: str, base_url: str | None = None) -> DomAnalysisResult:
        """Parse HTML and return normalized findings and structural hash."""

        soup = BeautifulSoup(html, "lxml")
        forms = [self._parse_form(form) for form in soup.find_all("form")]
        scripts = [script.get("src", "").strip() for script in soup.find_all("script") if script.get("src")]
        links = [anchor.get("href", "").strip() for anchor in soup.find_all("a") if anchor.get("href")]
        assets = self._extract_assets(soup)
        metatags = self._extract_metatags(soup)
        comments = [str(node).strip() for node in soup.find_all(string=lambda text: isinstance(text, Comment))]
        external_urls = self._collect_external_urls(base_url=base_url, values=scripts + links + assets)

        normalized_dom = self._normalize_dom(soup)
        dom_hash = hashlib.sha256(normalized_dom.encode("utf-8")).hexdigest()
        return DomAnalysisResult(
            forms=forms,
            scripts=scripts,
            links=links,
            assets=assets,
            external_urls=external_urls,
            metatags=metatags,
            comments=comments,
            normalized_dom=normalized_dom,
            dom_hash=dom_hash,
        )

    @staticmethod
    def _parse_form(form) -> DomForm:
        """Extract fields and metadata from one form node."""

        inputs = form.find_all("input")
        input_names = [field.get("name", "").strip() for field in inputs if field.get("name")]
        hidden_fields = [
            field.get("name", "").strip()
            for field in inputs
            if field.get("type", "").strip().lower() == "hidden" and field.get("name")
        ]
        classes = [css for css in form.get("class", []) if isinstance(css, str)]
        return DomForm(
            action=form.get("action"),
            method=form.get("method", "get").lower(),
            input_names=input_names,
            hidden_fields=hidden_fields,
            css_classes=classes,
            element_id=form.get("id"),
        )

    @staticmethod
    def _extract_assets(soup: BeautifulSoup) -> list[str]:
        """Extract asset paths from img/link/script tags."""

        assets: set[str] = set()
        for tag in soup.find_all(["img", "link", "script"]):
            for attr in ("src", "href"):
                value = tag.get(attr)
                if value:
                    assets.add(value.strip())
        return sorted(assets)

    @staticmethod
    def _extract_metatags(soup: BeautifulSoup) -> dict[str, str]:
        """Extract HTML metadata tags relevant for brand/kit detection."""

        meta: dict[str, str] = {}
        for tag in soup.find_all("meta"):
            name = tag.get("name") or tag.get("property")
            content = tag.get("content")
            if name and content:
                meta[name.strip().lower()] = content.strip()
        return meta

    @staticmethod
    def _normalize_dom(soup: BeautifulSoup) -> str:
        """Build stable DOM signature by normalizing volatile tokens."""

        payload = str(soup)
        payload = re.sub(r"\s+", " ", payload)
        payload = re.sub(r"\b\d{8,}\b", "<NUM>", payload)
        payload = re.sub(r"[a-f0-9]{16,}", "<HEX>", payload, flags=re.IGNORECASE)
        return payload.strip()

    @staticmethod
    def _collect_external_urls(base_url: str | None, values: list[str]) -> list[str]:
        """Normalize and keep only external URLs from extracted attributes."""

        urls = set()
        base_domain = urlparse(base_url).netloc if base_url else None
        for value in values:
            if not value:
                continue
            normalized = urljoin(base_url or "", value)
            parsed = urlparse(normalized)
            if parsed.scheme in {"http", "https"} and parsed.netloc:
                if base_domain and parsed.netloc == base_domain:
                    continue
                urls.add(normalized)
        return sorted(urls)
