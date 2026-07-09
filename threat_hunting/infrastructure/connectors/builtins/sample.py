"""Self-contained sample connector (offline demo & smoke testing).

Responsibility
--------------
Emit deterministic, realistic-looking intelligence with no external dependency,
so the whole pipeline can be exercised end-to-end (``hunt run sample``) on any
machine and in CI. The synthetic corpus purposely contains IOCs, credentials,
Brazilian documents (CPF/CNPJ), a credit card, a crypto wallet and a threat-actor
mention so every downstream engine has something to act on.

This is a demo/testing source; it is enabled by default but produces obviously
synthetic data (``example.com``, test card numbers).
"""

from __future__ import annotations

from collections.abc import Sequence

from threat_hunting.core.application.dto import RawRecord
from threat_hunting.core.domain.enums import Category
from threat_hunting.infrastructure.connectors.base import BaseConnector

_CORPUS: list[dict[str, str]] = [
    {
        "title": "Alleged database leak mentioning ACME Corp executives",
        "body": (
            "A user on a dark web forum is selling a database allegedly "
            "belonging to ACME Corp. Sample records include "
            "john.doe@acme-corp.com:Password123 and admin@acme-corp.com:hunter2. "
            "Contact the actor LockBit3 on telegram @acme_leaks. "
            "Malicious C2 at 185.220.101.45 and payload hash "
            "44d88612fea8a8f36de82e1278abb02f. CPF 529.982.247-25 exposed."
        ),
    },
    {
        "title": "Paste containing credit card and wallet",
        "body": (
            "dump: card 4111 1111 1111 1111 exp 12/27; "
            "btc wallet 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa; "
            "CNPJ 11.222.333/0001-81; phishing kit at "
            "http://acme-corp-login.example.com/verify . CVE-2024-3094 referenced."
        ),
    },
    {
        "title": "Weekly OSINT digest (benign)",
        "body": (
            "This week in security: patch management best practices and a "
            "recap of a conference. No indicators of compromise were shared."
        ),
    },
]


class SampleConnector(BaseConnector):
    """Yields a fixed synthetic corpus for demos and smoke tests."""

    name = "sample"
    source = "sample:demo"
    default_category = Category.THREAT_HUNTING

    async def connect(self) -> None:  # noqa: D401 - no transport needed
        """Offline connector: no transport is acquired."""
        return None

    async def collect(self) -> Sequence[RawRecord]:
        """Return the synthetic corpus as raw records."""
        return [
            self._record(
                content=f"{item['title']}\n{item['body']}",
                url=f"https://example.com/sample/{index}",
                metadata={"title": item["title"], "index": index},
                raw=item,
            )
            for index, item in enumerate(_CORPUS)
        ]
