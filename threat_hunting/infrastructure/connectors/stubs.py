"""Stub connectors for additional data sources.

Each connector follows the BaseConnector SDK and can be extended
with full API integration without modifying the core architecture.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

from threat_hunting.core.contracts.services import CollectionContext, ParsedData, RawPayload
from threat_hunting.core.domain.entities import FindingDraft
from threat_hunting.core.domain.enums import SourceType
from threat_hunting.infrastructure.connectors.base import BaseConnector


def _make_stub_connector(
    connector_name: str,
    source: SourceType,
    tag: str,
) -> type[BaseConnector]:
    """Factory for lightweight stub connectors."""

    class StubConnector(BaseConnector):
        name = connector_name
        source_type = source.value

        async def connect(self) -> None:
            self._connected = True

        async def collect(self, context: CollectionContext) -> AsyncIterator[RawPayload]:
            for kw in (context.keywords or ["intel"])[:3]:
                yield RawPayload(
                    data={"title": f"{connector_name}: {kw}", "content": f"Data from {connector_name}"},
                    source_uri=f"{connector_name}://collection",
                    metadata={"keyword": kw},
                )

        def parse(self, payload: RawPayload) -> ParsedData:
            return ParsedData(fields=payload.data, content=str(payload.data.get("content", "")))

        def normalize(self, parsed: ParsedData) -> FindingDraft:
            draft = self._default_normalize(parsed)
            draft.connector = connector_name
            draft.source = source
            draft.tags.append(tag)
            return draft

    StubConnector.__name__ = f"{connector_name.title().replace('_', '')}Connector"
    return StubConnector


FacebookConnector = _make_stub_connector("facebook", SourceType.SOCIAL, "facebook")
InstagramConnector = _make_stub_connector("instagram", SourceType.SOCIAL, "instagram")
XConnector = _make_stub_connector("x", SourceType.SOCIAL, "x")
DiscordConnector = _make_stub_connector("discord", SourceType.MESSAGING, "discord")
GitLabConnector = _make_stub_connector("gitlab", SourceType.CODE, "gitlab")
BlogsConnector = _make_stub_connector("blogs", SourceType.BLOG, "blogs")
PasteSitesConnector = _make_stub_connector("paste_sites", SourceType.PASTE, "paste")
NewsConnector = _make_stub_connector("news", SourceType.NEWS, "news")
ForumsConnector = _make_stub_connector("forums", SourceType.FORUM, "forums")
MarketplacesConnector = _make_stub_connector("marketplaces", SourceType.MARKETPLACE, "marketplaces")
FeedsConnector = _make_stub_connector("feeds", SourceType.FEED, "feeds")
ApisConnector = _make_stub_connector("apis", SourceType.API, "apis")
DeepWebConnector = _make_stub_connector("deepweb", SourceType.DEEPWEB, "deepweb")
MispConnector = _make_stub_connector("misp", SourceType.API, "misp")
OpenCtiConnector = _make_stub_connector("opencti", SourceType.API, "opencti")
ThreatFoxConnector = _make_stub_connector("threatfox", SourceType.API, "threatfox")
GreyNoiseConnector = _make_stub_connector("greynoise", SourceType.API, "greynoise")
VirusTotalConnector = _make_stub_connector("virustotal", SourceType.API, "virustotal")
AbuseIpdbConnector = _make_stub_connector("abuseipdb", SourceType.API, "abuseipdb")
ShodanConnector = _make_stub_connector("shodan", SourceType.API, "shodan")
CensysConnector = _make_stub_connector("censys", SourceType.API, "censys")
UrlHausConnector = _make_stub_connector("urlhaus", SourceType.API, "urlhaus")
AlienVaultOtxConnector = _make_stub_connector("alienvault_otx", SourceType.API, "otx")
