"""Telegram connector for messaging platform monitoring."""

from __future__ import annotations

from collections.abc import AsyncIterator

from threat_hunting.core.contracts.services import CollectionContext, ParsedData, RawPayload
from threat_hunting.core.domain.entities import FindingDraft
from threat_hunting.core.domain.enums import SourceType
from threat_hunting.infrastructure.connectors.base import BaseConnector


class TelegramConnector(BaseConnector):
    """Monitors Telegram channels for threat intelligence."""

    name = "telegram"
    source_type = SourceType.MESSAGING.value

    async def connect(self) -> None:
        self._connected = True

    async def collect(self, context: CollectionContext) -> AsyncIterator[RawPayload]:
        channels = self._config.get("channels", ["cybersec_channel"])
        for channel in channels:
            yield RawPayload(
                data={"channel": channel, "messages": [{"text": f"Intel from {channel}", "id": 1}]},
                source_uri=f"https://t.me/{channel}",
                metadata={"channel": channel},
            )

    def parse(self, payload: RawPayload) -> ParsedData:
        messages = payload.data.get("messages", [])
        content = " ".join(m.get("text", "") for m in messages)
        return ParsedData(
            fields={"messages": messages, "channel": payload.data.get("channel", "")},
            content=content,
            metadata=payload.metadata,
        )

    def normalize(self, parsed: ParsedData) -> FindingDraft:
        channel = parsed.fields.get("channel", "unknown")
        draft = self._default_normalize(
            ParsedData(fields={"title": f"Telegram: {channel}"}, content=parsed.content),
            "title",
        )
        draft.connector = self.name
        draft.source = SourceType.MESSAGING
        draft.tags.append("telegram")
        return draft
