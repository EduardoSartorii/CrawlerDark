"""Testes de configuração e utilitários."""

from __future__ import annotations

import pytest

from phishing_intel.config import load_config
from phishing_intel.config.settings import AppConfig, LoggingConfig
from phishing_intel import utils


def test_load_config_defaults_when_missing(tmp_path):
    """Carregar de um caminho inexistente deve retornar padrões válidos."""
    config = load_config(tmp_path / "nao_existe.yaml")
    assert isinstance(config, AppConfig)
    assert config.database.url.startswith("sqlite")
    assert config.misp.enabled is False


def test_load_config_reads_yaml(tmp_path):
    """A configuração deve refletir os valores do YAML."""
    yaml_file = tmp_path / "c.yaml"
    yaml_file.write_text(
        "database:\n  url: sqlite:///x.db\nlogging:\n  level: debug\n  json: false\n",
        encoding="utf-8",
    )
    config = load_config(yaml_file)
    assert config.database.url == "sqlite:///x.db"
    assert config.logging.level == "DEBUG"
    assert config.logging.json_output is False


def test_env_overrides_misp(tmp_path, monkeypatch):
    """Variáveis de ambiente devem sobrepor segredos do MISP."""
    monkeypatch.setenv("MISP_URL", "https://misp.local")
    monkeypatch.setenv("MISP_KEY", "secret-key")
    monkeypatch.setenv("MISP_ENABLED", "true")
    monkeypatch.setenv("DATABASE_URL", "sqlite:///env.db")
    config = load_config(tmp_path / "missing.yaml")
    assert config.misp.url == "https://misp.local"
    assert config.misp.key == "secret-key"
    assert config.misp.enabled is True
    assert config.database.url == "sqlite:///env.db"


def test_logging_level_validation():
    """Nível de log inválido deve levantar erro de validação."""
    with pytest.raises(ValueError):
        LoggingConfig(level="TRACE")


def test_logging_level_normalized():
    """Nível de log deve ser normalizado para maiúsculas."""
    assert LoggingConfig(level="info").level == "INFO"


def test_sha256_helpers_are_stable():
    """Os hashes devem ser determinísticos e independentes de ordem em listas."""
    assert utils.sha256_text("a") == utils.sha256_text("a")
    assert utils.sha256_list(["b", "a"]) == utils.sha256_list(["a", "b"])
    assert utils.sha256_bytes(b"x") == utils.sha256_bytes(b"x")


@pytest.mark.parametrize(
    "url,expected",
    [
        ("https://Login.Bank.com/x?y=1", "login.bank.com"),
        ("bank.com/path", "bank.com"),
        ("", ""),
    ],
)
def test_extract_domain(url, expected):
    """A extração de domínio deve lidar com esquema, path e string vazia."""
    assert utils.extract_domain(url) == expected


def test_file_name_from_path():
    """O nome de arquivo deve ignorar querystring e fragment."""
    assert utils.file_name_from_path("/a/b/app.min.js?v=1#x") == "app.min.js"
    assert utils.file_name_from_path("") == ""


def test_normalize_text():
    """A normalização deve colapsar espaços e aplicar lowercase."""
    assert utils.normalize_text("  Foo   BAR  ") == "foo bar"
