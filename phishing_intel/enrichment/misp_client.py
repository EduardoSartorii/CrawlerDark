"""PyMISP integration for creating phishing intelligence events."""

from __future__ import annotations

from pymisp import ExpandedPyMISP, MISPEvent, MISPObject


class MispClient:
    """Create MISP events, attributes, tags, and phishing-campaign objects."""

    def __init__(self, url: str | None, api_key: str | None, verify_tls: bool = True, dry_run: bool = True) -> None:
        """Create a MISP client; dry-run mode returns payloads without network IO."""

        self.dry_run = dry_run
        self.client = None if dry_run else ExpandedPyMISP(url, api_key, verify_tls)

    def submit_event(self, payload: dict[str, object]) -> dict[str, object]:
        """Submit or return a MISP event payload."""

        if self.dry_run:
            return {"dry_run": True, "event": payload}
        event = MISPEvent()
        event.info = str(payload["info"])
        event.distribution = int(payload["distribution"])
        event.threat_level_id = int(payload["threat_level_id"])
        event.analysis = int(payload["analysis"])
        for tag in payload.get("tags", []):
            event.add_tag(str(tag))
        for attribute in payload.get("attributes", []):
            event.add_attribute(attribute["type"], attribute["value"])
        for object_payload in payload.get("objects", []):
            misp_object = MISPObject(str(object_payload["name"]))
            for relation, value in object_payload["attributes"].items():
                if value is not None:
                    misp_object.add_attribute(relation, value=str(value))
            event.add_object(misp_object)
        created = self.client.add_event(event)
        return {"dry_run": False, "event": created}
