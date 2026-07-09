# phishing_intel

Plataforma profissional de **Cyber Threat Intelligence (CTI)** focada em
**análise, classificação, correlação, enriquecimento e atribuição** de
campanhas de phishing recebidas de parceiros de CTI.

O objetivo não é apenas coletar IOCs, mas identificar **campanhas,
operadores, infraestruturas reutilizadas, fingerprints de kits, métodos de
exfiltração e relações históricas entre incidentes**.

## Fluxos de operação

- **Fluxo principal** (artefatos já fornecidos pelo parceiro): recebe HTML e
  JavaScript já coletados → executa análise estática completa → correlaciona
  → enriquece o MISP.
- **Fluxo secundário** (HTML ausente): obtém o HTML → armazena evidências →
  segue o fluxo principal.

A plataforma **prioriza a análise dos artefatos recebidos** e não depende da
coleta para funcionar.

## Arquitetura

```
phishing_intel/
├── collectors/          # Coleta (fluxo secundário): html, ssl, dns, infra
├── analyzers/           # Análise estática: dom, js, form, exfiltração, kit, brand
├── correlators/         # Correlação de campanhas + Attribution Score
├── enrichment/          # MISP client, taxonomias fraude:*, campaign builder
├── database/            # SQLAlchemy: models, session, repositories, migrations
├── models/              # Modelos de domínio (Pydantic): findings, campaign, infra
├── config/              # Configuração declarativa (config.yaml)
├── tests/               # Testes unitários e de integração (pytest)
├── pipeline.py          # Orquestração fim-a-fim
├── evidence.py          # Cadeia de evidências / OPSEC
├── profile_comparator.py# Comparação multi-perfil (Desktop vs. Mobile)
├── main.py              # CLI
└── pyproject.toml
```

## Stack

Python 3.12+, Poetry, Pydantic, SQLAlchemy, Alembic, PyMISP, Requests,
BeautifulSoup4, lxml, cryptography, dnspython, ipwhois, PyYAML, structlog,
pytest.

## Instalação

```bash
cd phishing_intel
poetry install
```

Ou, com `pip`:

```bash
pip install pydantic sqlalchemy alembic pymisp requests beautifulsoup4 \
    lxml cryptography dnspython ipwhois pyyaml structlog
```

## Configuração

Edite `config/config.yaml`. Segredos (URL/chave do MISP, `DATABASE_URL`)
devem, preferencialmente, vir de variáveis de ambiente:

```bash
export MISP_URL="https://misp.example.org"
export MISP_KEY="<api-key>"
export MISP_ENABLED=true
export DATABASE_URL="postgresql+psycopg://user:pass@host/db"
```

## Uso (CLI)

Analisar um HTML já coletado (fluxo principal):

```bash
python -m phishing_intel.main \
  --url "https://phishing.exemplo/login" \
  --html-file page.html \
  --js-file script.js
```

Coletar o HTML e a infraestrutura (fluxo secundário):

```bash
python -m phishing_intel.main --url "https://phishing.exemplo" --collect-infra
```

A CLI imprime um resumo JSON com marca-alvo, objetivos, destinos de
exfiltração, `campaign_id`, Attribution Score e nível de confiança.

## Attribution Score

O motor de correlação pondera sinais compartilhados entre incidentes:

| Sinal        | Peso padrão | Confiança |
|--------------|-------------|-----------|
| fingerprint  | 40          | alto      |
| certificado  | 25          | alto      |
| ASN          | 15          | médio     |
| provedor     | 10          | médio     |
| marca        | 10          | médio     |

Faixas: **0-39** baixa, **40-69** média, **70-100** alta confiança.

## Migrações de banco (Alembic)

```bash
cd phishing_intel
alembic upgrade head          # aplica o esquema
alembic revision --autogenerate -m "mudanca"  # gera nova migração
```

## Testes

```bash
cd phishing_intel
pytest                         # roda a suíte com cobertura
```

Cobertura atual: **> 80%** (unitários + integração, com fixtures e mocking).
