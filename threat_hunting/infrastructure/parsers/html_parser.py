"""HtmlTextParser.

Responsibility
--------------
Convert an HTML document into readable plain text and its ``<title>``, using
BeautifulSoup. Kept as a reusable helper so multiple connectors (websites,
blogs, dark-web pages) share one robust implementation instead of each rolling
its own.
"""

from __future__ import annotations


class HtmlTextParser:
    """Extracts title and visible text from an HTML string."""

    def parse(self, html: str) -> tuple[str, str]:
        """Return ``(title, text)`` extracted from the HTML document."""
        if not html:
            return "", ""
        from bs4 import BeautifulSoup

        soup = BeautifulSoup(html, "lxml")
        for tag in soup(["script", "style", "noscript"]):
            tag.decompose()
        title = soup.title.text.strip() if soup.title and soup.title.text else ""
        text = soup.get_text(" ", strip=True)
        return title, text
