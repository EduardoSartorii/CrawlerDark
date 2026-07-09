"""Infrastructure correlator for ASN/provider/certificate reuse signals."""

from __future__ import annotations

from phishing_intel.models.infrastructure import InfrastructureProfile, SslMetadata


class InfrastructureCorrelator:
    """Calculates infrastructure overlap between incidents."""

    def correlate(
        self,
        current_infra: InfrastructureProfile,
        historical_infra: list[InfrastructureProfile],
        current_ssl: SslMetadata | None,
        historical_ssl: list[SslMetadata],
    ) -> dict[str, bool]:
        """Return boolean matches used by campaign attribution scoring."""

        same_asn = any(
            current_infra.asn and candidate.asn and current_infra.asn == candidate.asn for candidate in historical_infra
        )
        same_provider = any(
            current_infra.provider
            and candidate.provider
            and current_infra.provider.lower() == candidate.provider.lower()
            for candidate in historical_infra
        )
        same_certificate = False
        if current_ssl:
            same_certificate = any(
                current_ssl.sha256_fingerprint == cert.sha256_fingerprint or current_ssl.serial_number == cert.serial_number
                for cert in historical_ssl
            )

        return {
            "same_asn": same_asn,
            "same_provider": same_provider,
            "same_certificate": same_certificate,
        }
