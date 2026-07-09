# Developing

## Pré-requisitos

- Python 3.12+
- Poetry (recomendado) ou `pip install -e .` em virtualenv

## Setup

```bash
poetry install
cp .env.example .env
poetry run hunt init                    # cria SQLite + seeds watchlists
poetry run pytest                       # roda testes
poetry run hunt connector list          # lista conectores
poetry run hunt score test              # smoke test do pipeline
poetry run hunt run all                 # roda todos habilitados
poetry run hunt scheduler run           # inicia scheduler em foreground
```

## Estrutura

Veja `../ARCHITECTURE.md` para o diagrama completo.

## Adicionando um conector

1. Crie um arquivo em `threat_hunting/infrastructure/connectors/implementations/mysource.py`.
2. Herde de `BaseConnector` e decore com `@register_connector("mysource")`.
3. Implemente `collect / parse / normalize` (opcionalmente `health`, `close`).
4. Adicione uma seção em `config/connectors.yaml`.
5. Rode `poetry run hunt run mysource`.

## Adicionando uma regra de detecção

- Regex → edite `config/rules/regex.yaml`.
- YARA → coloque `.yar` em `config/rules/yara/`.
- Sigma (keywords) → coloque `.yml` em `config/rules/sigma/`.
- Watchlist → edite `config/watchlists.yaml`, depois `hunt init` para sincronizar.

## Adicionando um exporter

1. Implemente `ExporterPort` em `threat_hunting/infrastructure/exporters/mytarget.py`.
2. Registre em `ExporterFactory._build_one`.
3. Adicione entrada em `config/exporters.yaml`.

## Fluxo do pipeline

```
Connector → Parse → Normalize → Extract → Canonicalize
        → Detect → Score → Correlate → Deduplicate
        → Enrich → Persist → Export
```

Cada estágio é uma implementação de `PipelineStage`. A ordem é definida em
`config/settings.yaml → pipeline.stages`.

## Testes

```bash
poetry run pytest -q
poetry run pytest --cov=threat_hunting --cov-report=term
```

Os testes de integração usam SQLite in-memory e `respx` para mockar HTTP.

## Migrations

```bash
poetry run alembic upgrade head              # aplica
poetry run alembic revision -m "msg" --autogenerate    # nova
```
