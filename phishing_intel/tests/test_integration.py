"""Integration tests for the full analysis pipeline."""

import tempfile

import pytest

from phishing_intel.main import PhishingIntelPlatform
from phishing_intel.tests.fixtures.sample_html import SAMPLE_PHISHING_HTML


@pytest.fixture
def platform():
    """Create platform instance with temp storage."""
    with tempfile.TemporaryDirectory() as tmpdir:
        import phishing_intel.utils as utils

        config = utils.load_config()
        config["database"] = {"url": f"sqlite:///{tmpdir}/test.db", "echo": False}
        config["evidence"] = {"storage_path": f"{tmpdir}/evidence"}
        config["audit"] = {"storage_path": f"{tmpdir}/audit"}
        config["misp"]["api_key"] = ""

        # Write temp config
        import yaml

        config_path = f"{tmpdir}/config.yaml"
        with open(config_path, "w") as f:
            yaml.dump(config, f)

        plat = PhishingIntelPlatform(config_path=config_path)
        yield plat


class TestIntegrationPipeline:
    def test_full_analysis_with_html(self, platform):
        report = platform.analyze(
            url="https://phish.example.com",
            html=SAMPLE_PHISHING_HTML,
            export_misp=True,
        )
        assert report["url"] == "https://phish.example.com"
        assert report["html_hash"]
        assert report["phishing_type"] == "credential_harvesting"
        assert report["brand"] == "itau"
        assert report["campaign_id"].startswith("CAMP-")
        assert report["kit_fingerprint"]
        assert report["misp_event"] is not None

    def test_analysis_persists_evidence(self, platform):
        platform.analyze(
            url="https://phish.example.com",
            html=SAMPLE_PHISHING_HTML,
            export_misp=False,
        )
        evidence_files = list(platform.evidence_store.storage_path.iterdir())
        assert len(evidence_files) > 0

    def test_analysis_creates_audit_log(self, platform):
        platform.analyze(
            url="https://phish.example.com",
            html=SAMPLE_PHISHING_HTML,
            export_misp=False,
        )
        assert platform.audit_logger.log_file.exists()

    def test_second_analysis_correlation(self, platform):
        report1 = platform.analyze(
            url="https://phish1.example.com",
            html=SAMPLE_PHISHING_HTML,
            export_misp=False,
        )
        report2 = platform.analyze(
            url="https://phish2.example.com",
            html=SAMPLE_PHISHING_HTML,
            export_misp=False,
        )
        # Same HTML should produce fingerprint match signal
        assert report2["attribution_score"] >= report1["attribution_score"]

    def test_ioc_extraction(self, platform):
        report = platform.analyze(
            url="https://phish.example.com",
            html=SAMPLE_PHISHING_HTML,
            export_misp=False,
        )
        iocs = report["iocs"]
        assert len(iocs["urls"]) > 0
