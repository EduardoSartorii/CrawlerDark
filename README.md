# Threat Hunting Collection Platform

Plataforma corporativa modular para Threat Hunting, OSINT, Brand Monitoring, VIP Monitoring,
Dark/Deep Web monitoring, IOC hunting, correlação e exportação para ecossistema CTI.

## Arquitetura

- Clean Architecture + Hexagonal Architecture
- Domain Driven Design
- Event Driven
- SOLID
- Repository Pattern + Unit of Work
- Strategy, Factory, Builder, Adapter, Command, Observer e Plugin Pattern

Documentação arquitetural completa em `docs/architecture.md`.

## Pipeline canônico

1. Connector
2. Parser
3. Extractor
4. Normalizer
5. Detection Engine
6. Scoring Engine
7. Correlation Engine
8. Deduplication Engine
9. Enrichment Engine
10. Persistence
11. Export

## Stack

- Python 3.12+
- Poetry
- Pydantic v2
- SQLAlchemy 2 / Alembic
- httpx / BeautifulSoup4 / lxml
- PyMISP
- Redis
- APScheduler
- structlog
- Typer
- Dependency Injector
- OpenTelemetry
- Prometheus Client
- pytest

## CLI

Comandos principais:

- `hunt run reddit`
- `hunt run github`
- `hunt run telegram`
- `hunt run social`
- `hunt run darkweb`
- `hunt run all`
- `hunt connector enable reddit`
- `hunt connector disable reddit`
- `hunt scheduler run`
- `hunt export misp`
- `hunt export splunk`
- `hunt export elastic`
- `hunt score test`

## Configuração

Arquivo central: `config/default.yml`

- Perfis OPSEC por conector
- Regras dinâmicas de detecção
- Pesos de scoring
- Conectores habilitados
- Threshold de auto-export para MISP

## Testes

```bash
poetry install
poetry run pytest
```

## Licença

GNU General Public License (GPL).
