"""HTML/plain-text parser.

Responsibility
--------------
Implement :class:`ParserPort`: strip markup and normalise whitespace so the
extractor and detection engines operate on clean text regardless of whether the
connector delivered HTML, XML or plain text. It never fetches anything — parsing
is a pure transformation of an already-collected record.
"""

from __future__ import annotations

import re

from bs4 import BeautifulSoup

from threat_hunting.core.application.dto import RawRecord
from threat_hunting.core.application.ports.pipeline_stages import ParserPort

_WHITESPACE = re.compile(r"[ \t\r\f\v]+")
_BLANK_LINES = re.compile(r"\n{3,}")
_HTML_HINT = re.compile(r"<[a-zA-Z/][^>]*>")


class HtmlTextParser(ParserPort):
    """Cleans HTML markup and collapses whitespace to plain text."""

    def parse(self, record: RawRecord) -> RawRecord:
        """Return the record with cleaned ``content`` and a length metric."""
        text = record.content or ""
        if _HTML_HINT.search(text):
            soup = BeautifulSoup(text, "lxml")
            for tag in soup(["script", "style", "noscript"]):
                tag.decompose()
            text = soup.get_text(separator="\n")
        text = _WHITESPACE.sub(" ", text)
        text = _BLANK_LINES.sub("\n\n", text).strip()
        record.content = text
        record.metadata.setdefault("content_length", len(text))
        return record
