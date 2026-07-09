"""PyMISP client abstraction for event and object enrichment."""

from __future__ import annotations

from typing import Any

try:
    from pymisp import MISPAttribute, MISPEvent, MISPObject, PyMISP
except Exception:  # pragma: no cover - optional runtime dependency during tests
    MISPAttribute = MISPEvent = MISPObject = object  # type: ignore[assignment]
    PyMISP = None  # type: ignore[assignment]


class MispClient:
    """Wraps PyMISP workflows used by phishing-intel enrichment."""

    def __init__(self, url: str, api_key: str, verify_tls: bool = True) -> None:
        if PyMISP is None:
            raise RuntimeError("PyMISP is not available. Install pymisp to enable MISP integration.")
        self.client = PyMISP(url, api_key, ssl=verify_tls)

    def create_event(self, info: str, distribution: int = 0, threat_level_id: int = 2) -> dict[str, Any]:
        """Create a MISP event and return normalized identifiers."""

        event = MISPEvent()
        event.info = info
        event.distribution = distribution
        event.threat_level_id = threat_level_id
        created = self.client.add_event(event, pythonify=True)
        return {"event_id": str(created.id), "event_uuid": str(created.uuid)}

    def add_attribute(self, event_id: str, attribute_type: str, value: str, category: str) -> None:
        """Add one typed IOC attribute to a MISP event."""

        attribute = MISPAttribute()
        attribute.type = attribute_type
        attribute.value = value
        attribute.category = category
        self.client.add_attribute(event_id, attribute)

    def add_phishing_campaign_object(self, event_id: str, payload: dict[str, str]) -> None:
        """Add custom phishing-campaign object with campaign context."""

        obj = MISPObject(name="phishing-campaign")
        for key, value in payload.items():
            obj.add_attribute(key, value=value)
        self.client.add_object(event_id, obj)

    def tag_event(self, event_id: str, tags: list[str]) -> None:
        """Apply local CTI taxonomy tags to a MISP event."""

        for tag in tags:
            self.client.tag(event_id, tag)
