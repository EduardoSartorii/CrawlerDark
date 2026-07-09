"""DOM analyzer for partner-supplied phishing HTML.

The analyzer extracts forms, fields, scripts, links, assets, metadata,
comments, CSS classes, HTML IDs, file names, external URLs, a normalized DOM,
and a structural hash. It intentionally does not fetch remote content.
"""

from __future__ import annotations

from pathlib import PurePosixPath
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup, Comment

from phishing_intel.models.findings import DomFinding, FormFieldFinding, FormFinding
from phishing_intel.utils import URL_RE, sha256_text


class DomAnalyzer:
    """Extract normalized phishing indicators from raw HTML."""

    def analyze(self, html: str, base_url: str | None = None) -> DomFinding:
        """Analyze HTML and return a normalized DOM finding."""

        soup = BeautifulSoup(html or "", "lxml")
        forms = [self._extract_form(form) for form in soup.find_all("form")]
        scripts = [self._absolute(src, base_url) for src in self._attrs(soup, "script", "src")]
        links = [self._absolute(href, base_url) for href in self._attrs(soup, "a", "href")]
        assets = sorted(
            {
                self._absolute(value, base_url)
                for tag, attr in (("img", "src"), ("link", "href"), ("source", "src"), ("video", "src"))
                for value in self._attrs(soup, tag, attr)
            }
        )
        external_urls = sorted(set(URL_RE.findall(html or "")) | set(scripts) | set(links) | set(assets))
        css_classes = sorted({item for tag in soup.find_all(True) for item in tag.get("class", [])})
        html_ids = sorted({tag.get("id") for tag in soup.find_all(True) if tag.get("id")})
        file_names = sorted({PurePosixPath(urlparse(value).path).name for value in external_urls if urlparse(value).path})
        normalized_dom = self._normalize_dom(soup)
        return DomFinding(
            forms=forms,
            scripts=scripts,
            links=links,
            assets=assets,
            external_urls=external_urls,
            metatags=self._metatags(soup),
            comments=[str(comment).strip() for comment in soup.find_all(string=lambda text: isinstance(text, Comment))],
            css_classes=css_classes,
            html_ids=html_ids,
            file_names=[name for name in file_names if name],
            normalized_dom=normalized_dom,
            dom_hash=sha256_text(normalized_dom),
        )

    def _extract_form(self, form: object) -> FormFinding:
        """Extract action, method, and field data from a form tag."""

        fields: list[FormFieldFinding] = []
        for field in form.find_all(["input", "textarea", "select"]):
            field_id = field.get("id")
            label = None
            if field_id:
                label_tag = form.find("label", attrs={"for": field_id})
                label = label_tag.get_text(" ", strip=True) if label_tag else None
            fields.append(
                FormFieldFinding(
                    name=field.get("name"),
                    field_type=field.get("type") or field.name,
                    placeholder=field.get("placeholder"),
                    label=label,
                    hidden=(field.get("type") == "hidden"),
                    css_classes=list(field.get("class", [])),
                    element_id=field_id,
                )
            )
        return FormFinding(
            action=form.get("action"),
            method=(form.get("method") or "get").lower(),
            css_classes=list(form.get("class", [])),
            element_id=form.get("id"),
            fields=fields,
        )

    def _attrs(self, soup: BeautifulSoup, tag: str, attr: str) -> list[str]:
        """Return non-empty attribute values for a tag/attribute pair."""

        return [item.get(attr) for item in soup.find_all(tag) if item.get(attr)]

    def _absolute(self, value: str, base_url: str | None) -> str:
        """Resolve relative URLs when a base URL is available."""

        return urljoin(base_url, value) if base_url else value

    def _metatags(self, soup: BeautifulSoup) -> dict[str, str]:
        """Return metadata keyed by name, property, charset, or http-equiv."""

        metadata: dict[str, str] = {}
        for tag in soup.find_all("meta"):
            key = tag.get("name") or tag.get("property") or tag.get("charset") or tag.get("http-equiv")
            value = tag.get("content") or tag.get("charset")
            if key and value:
                metadata[str(key).lower()] = str(value)
        return metadata

    def _normalize_dom(self, soup: BeautifulSoup) -> str:
        """Generate a stable structural DOM representation."""

        parts: list[str] = []
        for tag in soup.find_all(True):
            attrs = []
            for name in ("id", "class", "name", "type", "method", "action", "src", "href"):
                value = tag.get(name)
                if value:
                    attrs.append(f"{name}={','.join(value) if isinstance(value, list) else value}")
            parts.append(f"{tag.name}|{'|'.join(sorted(attrs))}")
        return "\n".join(parts)
