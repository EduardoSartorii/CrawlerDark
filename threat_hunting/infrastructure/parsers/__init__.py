"""Parsers.

Utilities that turn source-specific payloads (HTML, feeds) into clean text.
The pipeline's parse stage delegates the *structuring* of a raw item into a
:class:`Finding` to the connector's ``parse`` method; these helpers support that
work (e.g. stripping HTML to text).
"""

from threat_hunting.infrastructure.parsers.html_parser import HtmlTextParser

__all__ = ["HtmlTextParser"]
