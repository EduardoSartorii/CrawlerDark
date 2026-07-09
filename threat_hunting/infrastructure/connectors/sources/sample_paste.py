"""Sample paste-site connector.

Responsibility
--------------
A fully self-contained connector that yields synthetic paste content laced with
realistic indicators (credentials, IPs, domains, hashes, cards, wallets, CPF).
It requires no network access, which makes it ideal for:

* end-to-end demonstrations of the whole pipeline offline;
* deterministic integration tests of detection/scoring/correlation/dedup.

It is a *real* connector (implements the full contract), not a mock — it simply
sources its raw items from an embedded corpus instead of the network.
"""

from __future__ import annotations

from collections.abc import Iterable

from threat_hunting.core.application.ports.connector import ConnectorMeta
from threat_hunting.core.domain.entities.raw_item import RawItem
from threat_hunting.core.domain.enums import Category, SourceType
from threat_hunting.infrastructure.connectors.base import BaseConnector

# Embedded corpus: each entry becomes one RawItem. Content is intentionally rich
# in indicators so downstream engines have something concrete to work on.
_CORPUS: tuple[dict[str, str], ...] = (
    {
        "title": "ACME Corp database dump - fresh leak",
        "content": (
            "Full dump of acme-corp.com customers. Sample creds: "
            "admin@acme-corp.com:P@ssw0rd123, john.doe@acme-corp.com:hunter2. "
            "C2 server at 45.133.1.55 resolving evil-acme[.]com. "
            "Payload md5 44d88612fea8a8f36de82e1278abb02f. "
            "Contact us on telegram @darkvendor. Threat actor: LockBit."
        ),
    },
    {
        "title": "Credit cards for sale - BR fullz",
        "content": (
            "Selling BR fullz. Card 4111111111111111 exp 12/27. "
            "CPF 529.982.247-25, CNPJ 11.222.333/0001-81. "
            "BTC wallet 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa. "
            "Mirror at hxxps://darkmarket[.]onion. Actor LockBit affiliate."
        ),
    },
    {
        "title": "Random dev notes",
        "content": "just testing my blog about python and coffee, nothing to see here.",
    },
    {
        # Near-duplicate of the first entry to exercise the dedup engine.
        "title": "ACME Corp database dump - fresh leak (mirror)",
        "content": (
            "Full dump of acme-corp.com customers. Sample creds: "
            "admin@acme-corp.com:P@ssw0rd123, john.doe@acme-corp.com:hunter2. "
            "C2 server at 45.133.1.55 resolving evil-acme[.]com. "
            "Payload md5 44d88612fea8a8f36de82e1278abb02f. Threat actor: LockBit."
        ),
    },
)


class SamplePasteConnector(BaseConnector):
    """Yields an embedded corpus of paste content for offline demos/tests."""

    meta = ConnectorMeta(
        name="sample_paste",
        source=SourceType.PASTE_SITE,
        category=Category.DATA_LEAK,
        description="Self-contained paste connector producing synthetic leak data.",
        groups=["paste", "demo", "leak"],
    )

    def collect(self) -> Iterable[RawItem]:
        """Yield one raw item per embedded corpus entry."""
        for index, entry in enumerate(_CORPUS):
            yield RawItem(
                connector=self.meta.name,
                source="paste://sample",
                url=f"paste://sample/{index}",
                title=entry["title"],
                content=entry["content"],
                payload={"index": str(index)},
            )
