"""Additional tests for coverage of collectors, correlators, and main."""

import tempfile
from unittest.mock import MagicMock, patch

import pytest

from phishing_intel.collectors.infrastructure_collector import InfrastructureCollector
from phishing_intel.collectors.ssl_collector import SSLCollector
from phishing_intel.correlators.fingerprint_correlator import FingerprintCorrelator
from phishing_intel.correlators.infrastructure_correlator import InfrastructureCorrelator
from phishing_intel.database.repositories import FingerprintRepository
from phishing_intel.database.session import get_session, init_db
from phishing_intel.main import PhishingIntelPlatform
from phishing_intel.models.findings import InfrastructureFinding, KitFingerprint
from phishing_intel.models.infrastructure import (
    CertificateRecord,
    FingerprintRecord,
    InfrastructureRecord,
)
from phishing_intel.tests.fixtures.sample_html import SAMPLE_PHISHING_HTML
from phishing_intel.utils import load_config


@pytest.fixture
def db_session():
    """Temporary database session for correlator tests."""
    with tempfile.NamedTemporaryFile(suffix=".db") as f:
        init_db(f"sqlite:///{f.name}")
        with get_session() as session:
            yield session


class TestInfrastructureModels:
    def test_certificate_record(self):
        rec = CertificateRecord(serial_number="abc123", issuer="CA")
        assert rec.serial_number == "abc123"

    def test_infrastructure_record(self):
        rec = InfrastructureRecord(ip="1.2.3.4", asn="AS1234")
        assert rec.ip == "1.2.3.4"

    def test_fingerprint_record(self):
        rec = FingerprintRecord(campaign_fingerprint="fp123")
        assert rec.campaign_fingerprint == "fp123"


class TestSSLCollector:
    def test_parse_cert_date_none(self):
        assert SSLCollector._parse_cert_date(None) is None

    def test_parse_cert_date_invalid(self):
        assert SSLCollector._parse_cert_date("invalid") is None

    @patch("phishing_intel.collectors.ssl_collector.socket.create_connection")
    def test_collect_failure(self, mock_conn):
        mock_conn.side_effect = OSError("connection failed")
        result = SSLCollector().collect("nonexistent.invalid")
        assert result is None


class TestInfrastructureCollector:
    @patch.object(InfrastructureCollector, "_whois_lookup")
    def test_collect_with_ip(self, mock_whois):
        mock_whois.return_value = {
            "asn": "AS1234",
            "organization": "Test Org",
            "description": "Test Provider",
            "country": "BR",
        }
        collector = InfrastructureCollector()
        with patch.object(collector.dns_collector, "collect") as mock_dns:
            mock_dns.return_value = {"resolved_ips": ["1.2.3.4"]}
            result = collector.collect("https://evil.com")
            assert result.ip == "1.2.3.4"
            assert result.asn == "AS1234"

    def test_whois_lookup_failure(self):
        collector = InfrastructureCollector()
        result = collector._whois_lookup("invalid")
        assert result == {} or "asn" in result


class TestFingerprintCorrelatorMatches:
    def test_find_matches(self):
        with tempfile.NamedTemporaryFile(suffix=".db") as f:
            init_db(f"sqlite:///{f.name}")
            with get_session() as session:
                fp = KitFingerprint(campaign_fingerprint="test_fp_match")
                FingerprintRepository(session).create(fp.model_dump(), "https://old.com")

            correlator = FingerprintCorrelator()
            matches = correlator.find_matches(fp)
            assert len(matches) == 1
            assert matches[0]["match_type"] == "campaign_fingerprint"


class TestInfrastructureCorrelatorFind:
    def test_find_related_empty(self):
        correlator = InfrastructureCorrelator()
        infra = InfrastructureFinding(ip="9.9.9.9", asn="AS9999")
        related = correlator.find_related(infra)
        assert isinstance(related, list)


class TestMainMultiProfile:
    @patch.object(PhishingIntelPlatform, "analyze")
    @patch.object(PhishingIntelPlatform, "__init__", lambda self, config_path=None: None)
    def test_multi_profile_diff(self, mock_analyze):
        platform = PhishingIntelPlatform()
        platform.config = load_config()
        platform.html_collector = MagicMock()
        platform.dom_analyzer = __import__(
            "phishing_intel.analyzers.dom_analyzer", fromlist=["DOMAnalyzer"]
        ).DOMAnalyzer()
        platform.audit_logger = MagicMock()
        platform.evidence_store = MagicMock()

        platform.html_collector.collect_multi_profile.return_value = {
            "desktop_chrome": {"html": SAMPLE_PHISHING_HTML},
            "android_chrome": {"html": "<html><body>mobile only</body></html>"},
        }
        mock_analyze.return_value = {"url": "https://test.com"}

        result = platform.analyze_multi_profile("https://test.com")
        assert "profile_diffs" in result
        assert len(result["profile_diffs"]) > 0
