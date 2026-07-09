"""HTMLParser — utilidade de parse via BeautifulSoup."""

from __future__ import annotations

from typing import Any

from bs4 import BeautifulSoup


class HTMLParser:
    """Wrapper simples sobre BeautifulSoup para uso em conectores."""

    async def parse(self, payload: str | bytes) -> dict[str, Any]:
        soup = BeautifulSoup(payload, "lxml")
        title = soup.title.string.strip() if soup.title and soup.title.string else ""
        text = soup.get_text(" ", strip=True)
        links = [a.get("href") for a in soup.find_all("a", href=True)]
        return {"title": title, "text": text, "links": links}
