# Responsabilidade dos arquivos implementados

## Core
- `core/contracts.py`: portas hexagonais e contratos do núcleo.
- `core/events.py`: eventos de domínio e barramento in-memory (observer).
- `core/exceptions.py`: exceções semânticas da plataforma.

## Domain
- `domain/entities.py`: entidades canônicas (`Finding`, regras, watchlists, scoring policy).

## Application
- `application/commands.py`: Command Pattern para execução de casos de uso.
- `application/builders.py`: Builder Pattern para criação de `Finding`.
- `application/factories.py`: Factory Pattern para conectores/exportadores.
- `application/observers.py`: observers de logging e métricas.
- `application/use_cases.py`: orquestração dos casos de uso.
- `application/container.py`: composição de dependências com Dependency Injector.

## Connectors / Plugins
- `connectors/base.py`: SDK obrigatório para qualquer novo conector.
- `connectors/reddit.py`: conector Reddit.
- `connectors/github.py`: conector GitHub.
- `connectors/telegram.py`: conector Telegram.
- `plugins/manager.py`: descoberta automática de conectores.

## Pipeline e Engines
- `pipelines/orchestrator.py`: fluxo completo da pipeline (end-to-end).
- `parsers/default_parser.py`: estágio de parsing.
- `extractors/indicator_extractor.py`: extração de IOCs.
- `normalizers/default_normalizer.py`: normalização para schema canônico.
- `detections/engine.py`: motor de detecção dinâmico.
- `scoring/strategies.py`: estratégias de score.
- `scoring/engine.py`: motor de score com pesos configuráveis.
- `correlation/engine.py`: correlação de entidades.
- `deduplication/engine.py`: deduplicação por fingerprint.
- `enrichment/engine.py`: enriquecimento contextual.

## Persistência e Exportação
- `database/models.py`: schema SQLAlchemy de findings.
- `database/session.py`: criação de engine e session factory.
- `storage/repository.py`: Repository + Unit of Work.
- `storage/backends.py`: contratos/adapters de storage multi-backend.
- `exporters/implementations.py`: exportadores (JSON/CSV/MISP/OpenCTI/Splunk/OpenSearch/Webhook/REST/STIX/TAXII).
- `integrations/misp_adapter.py`: adapter MISP.
- `integrations/opencti_adapter.py`: adapter OpenCTI (placeholder).

## Cross-cutting
- `infrastructure/opsec/transport.py`: camada OPSEC (proxy, retry, backoff, rate limit, user-agent).
- `infrastructure/observability/logging.py`: logging estruturado.
- `infrastructure/observability/metrics.py`: métricas Prometheus.
- `infrastructure/observability/tracing.py`: tracing OpenTelemetry.
- `infrastructure/observability/health.py`: health checks.
- `scheduler/service.py`: agendador com APScheduler.

## Delivery
- `cli/app.py`: CLI Typer (`hunt run`, `connector`, `scheduler`, `export`, `score`).
- `api/__init__.py`: ponto de entrada futuro para API.
- `web/django_ready.md`: guia de preparação Django Admin.

## Configuração
- `config/settings.py`: carregamento de YAML com Pydantic v2.
- `config/settings.yml`: runtime settings.
- `config/watchlists.yml`: watchlists e ativos monitorados.
- `config/detection_rules.yml`: regras de detecção dinâmicas.
- `config/scoring.yml`: pesos e threshold.
- `config/opsec.yml`: perfis OPSEC.
