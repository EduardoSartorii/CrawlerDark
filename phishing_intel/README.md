# phishing_intel

Plataforma profissional de **Threat Intelligence** para analise estatica, classificacao,
correlacao, enriquecimento e atribuicao de campanhas de phishing recebidas por parceiros
de CTI.

O objetivo da plataforma nao e apenas coletar IOCs, e sim identificar **campanhas**,
**operadores**, **infraestruturas reutilizadas**, **fingerprints de kits**, **metodos de
exfiltracao** e **relacoes historicas entre incidentes**.

## Fluxos de operacao

* **Fluxo principal** — o parceiro de CTI ja fornece HTML, JavaScript, IOCs preliminares,
  capturas de tela e metadados de deteccao. A plataforma executa a analise estatica
  diretamente sobre os artefatos recebidos, sem qualquer coleta ativa.
* **Fluxo secundario** — quando o HTML nao e fornecido, a plataforma coleta o artefato
  minimamente necessario (HTML, certificado TLS, infraestrutura de rede), preserva a
  evidencia (cadeia de custodia) e segue com a mesma analise do fluxo principal.

Em ambos os casos, o pipeline e: **analise -> persistencia -> correlacao -> enriquecimento
MISP**, orquestrado por `enrichment/campaign_builder.py` e exposto via `main.py`.

## Arquitetura

```
phishing_intel/
├── collectors/          # Coleta ativa (fluxo secundario): HTML, SSL, DNS, infraestrutura
├── analyzers/            # Analise estatica: DOM, JavaScript, classificacao, exfiltracao,
│                         # fingerprint de kit, deteccao de marca, comparacao multi-perfil
├── correlators/          # Motor de correlacao e Attribution Score
├── enrichment/           # Taxonomias/tags, cliente MISP, orquestracao do pipeline
├── database/             # Modelos SQLAlchemy, sessao, repositorios
├── models/               # Modelos de dominio Pydantic (findings, campaign, infrastructure)
├── config/               # config.yaml + settings tipadas
├── alembic/               # Migracoes de esquema
├── tests/                # Suite de testes (pytest)
└── main.py               # CLI / ponto de entrada
```

Cada modulo documenta, em seu docstring de topo, sua **responsabilidade arquitetural** e
**fluxo de execucao** — consulte o codigo-fonte para o detalhamento completo.

## Stack tecnologica

Python 3.12+, Poetry, Pydantic, SQLAlchemy 2.0, Alembic, PyMISP, Requests,
BeautifulSoup4 + lxml, cryptography, dnspython, ipwhois, PyYAML, pytest, structlog.

## Instalacao

```bash
poetry install
```

## Configuracao

Edite `config/config.yaml` (banco de dados, URL/API key do MISP, pesos de correlacao,
perfis de renderizacao, base de marcas conhecidas). Segredos podem ser sobrescritos via
variaveis de ambiente com o prefixo `PHISHING_INTEL_`, por exemplo:

```bash
export PHISHING_INTEL_MISP__API_KEY="sua-chave-aqui"
export PHISHING_INTEL_MISP__URL="https://misp.suaorganizacao.com"
```

## Uso

### Fluxo principal (HTML/JS ja fornecidos pelo parceiro)

```bash
poetry run python main.py \
    --url "https://phishing-suspeito.example/login" \
    --html-file evidencias/pagina.html \
    --js-file evidencias/pagina.js
```

### Fluxo secundario (coleta ativa quando HTML nao e fornecido)

```bash
poetry run python main.py --url "https://phishing-suspeito.example/login"
```

### Flags uteis

* `--no-misp` — pula o enriquecimento MISP (dry-run local).
* `--no-network-enrichment` — pula a coleta de certificado SSL/infraestrutura de rede.
* `--config` — caminho customizado para `config.yaml`.

## Banco de dados

O esquema e criado automaticamente (`init_db`) em ambientes de avaliacao. Em producao,
utilize Alembic:

```bash
poetry run alembic upgrade head
```

## Testes

```bash
poetry run pytest --cov --cov-report=term-missing
```

Cobertura minima exigida: 80% (configurada em `pyproject.toml`, `[tool.coverage.report]`).

## Lint

```bash
poetry run ruff check .
```
