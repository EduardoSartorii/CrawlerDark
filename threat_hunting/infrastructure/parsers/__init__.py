"""Parsers reutilizáveis para conectores (HTML, JSON, RSS)."""

from .html_parser import HTMLParser
from .json_parser import JSONParser
from .rss_parser import RSSParser

__all__ = ["HTMLParser", "JSONParser", "RSSParser"]
