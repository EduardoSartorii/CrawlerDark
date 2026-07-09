# Threat Hunting Platform

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)

Plataforma corporativa de **Cyber Threat Intelligence Collection & Analysis** para
descoberta automática de ameaças, vazamentos, campanhas maliciosas, IOCs,
monitoramento de marca, VIP monitoring, dark/deep web monitoring, credential /
card / leak / document hunting, correlação, enriquecimento e exportação.

> Este repositório contém a nova plataforma em `threat_hunting/` e mantém o
> legado (`main.py`, `frameworks/`, `utils/`) apenas por retro-compatibilidade
> operacional. O ponto de entrada oficial é a CLI **`hunt`**.

## Visão geral

- **Clean Architecture + Hexagonal + DDD**. O core não conhece infraestrutura.
- **Plugin Pattern** para conectores, engines e exportadores.
- **Event-Driven** interno via barramento in-memory.
- **OPSEC-first** — todo tráfego passa por proxies/UA/rate-limit configuráveis.
- **Pipeline determinístico**:
  `Connector → Parser → Extractor → Normalizer → Detection → Scoring →
  Correlation → Deduplication → Enrichment → Persistence → Export`.
- **Storage plugável** (SQLite/Postgres via SQLAlchemy 2, JSON, extensível).
- **Exporters** para MISP, OpenCTI, Splunk, OpenSearch, STIX 2.1, TAXII,
  Webhook, JSON, CSV.
- **Observabilidade** com structlog + Prometheus + OpenTelemetry.
- **CLI** completa (`hunt run`, `hunt connector`, `hunt scheduler`,
  `hunt export`, `hunt score`, `hunt health`).

Consulte **[`ARCHITECTURE.md`](ARCHITECTURE.md)** para o blueprint arquitetural
detalhado (decisões, patterns, entidades, contratos, estrutura e fluxo).

## Instalação

```bash
poetry install
cp .env.example .env             # preencha se for usar integrações
poetry run alembic upgrade head  # cria o schema SQLite default
```

## Uso rápido

```bash
poetry run hunt --help                # lista comandos
poetry run hunt connector list        # conectores registrados + status
poetry run hunt run threatfox         # roda um conector específico
poetry run hunt run all               # roda todos os habilitados
poetry run hunt scheduler run         # inicia o scheduler
poetry run hunt export misp           # exporta findings pendentes
poetry run hunt score test            # roda o motor de score com input textual
poetry run hunt health                # health-check consolidado
```

## Estrutura

```
threat_hunting/
├── core/              # domain + application (não conhece infra)
├── infrastructure/    # connectors, engines, storage, exporters, opsec, ...
├── cli/               # Typer app
├── database/          # Alembic
├── api/  web/         # placeholders (FastAPI e Django futuros)
├── config/            # YAMLs
└── tests/             # unit + integration
```

## Adicionando um novo conector

```python
from threat_hunting.infrastructure.connectors.base import BaseConnector
from threat_hunting.infrastructure.connectors.registry import register_connector

@register_connector("mysource")
class MySourceConnector(BaseConnector):
    async def collect(self): ...
    async def parse(self, payload): ...
    async def normalize(self, parsed): ...
    async def health(self): ...
```

Basta colocar o arquivo em
`threat_hunting/infrastructure/connectors/implementations/` e o auto-discovery
o registra. Adicione uma seção correspondente em `config/connectors.yaml`.

## Testes

```bash
poetry run pytest
```

## Licença

GPL-3.0-only. Consulte [`LICENSE`](LICENSE).
