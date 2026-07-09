"""Infrastructure correlation helpers."""

from __future__ import annotations

from phishing_intel.models.infrastructure import InfrastructureFinding


class InfrastructureCorrelator:
    """Compare infrastructure reuse between incidents."""

    def compare(self, left: InfrastructureFinding, right: InfrastructureFinding) -> dict[str, bool]:
        """Return field-level infrastructure matches."""

        return {
            "same_ip": bool(left.ip and left.ip == right.ip),
            "same_asn": bool(left.asn and left.asn == right.asn),
            "same_provider": bool(left.hosting_provider and left.hosting_provider == right.hosting_provider),
            "same_country": bool(left.country and left.country == right.country),
        }
