# Threat Hunting Platform — Arquitetura de Referência

> Plataforma corporativa de **Cyber Threat Intelligence** para descoberta automática
> de ameaças, vazamentos, campanhas maliciosas, IOCs, monitoramento de marca,
> VIP monitoring, dark/deep web monitoring, credential/card/leak/document hunting,
> correlação, enriquecimento e exportação para plataformas de TI (MISP, OpenCTI,
> Splunk, OpenSearch, STIX/TAXII, Webhook).

---

## 1. Domínio da aplicação

O domínio é **Threat Intelligence Collection & Analysis**. A linguagem ubíqua da
plataforma é derivada de padrões consagrados do setor (MITRE, MISP, STIX 2.1):

| Termo               | Significado no domínio                                                              |
|---------------------|-------------------------------------------------------------------------------------|
| **Finding**         | Descoberta atômica gerada pela plataforma (agregado raiz).                          |
| **Connector**       | Fonte de coleta plugável (Reddit, MISP, Telegram, ThreatFox, ...).                  |
| **Indicator (IOC)** | Observável técnico (IP, domínio, hash, url, email, wallet, cartão, cred, ...).      |
| **Artifact**        | Evidência anexa a um finding (screenshot, HTML bruto, arquivo).                     |
| **Threat Actor**    | Ator ameaça catalogado (LockBit, APT29, ...).                                       |
| **Campaign**        | Operação/campanha correlacionada.                                                   |
| **Relationship**    | Aresta tipada entre dois nós (finding, actor, campaign, indicator).                 |
| **Watchlist**       | Coleção monitorada (VIPs, marcas, domínios, keywords, YARA, Sigma, Regex).          |
| **Detection Rule**  | Regra aplicada pelo Detection Engine (Regex/YARA/Sigma/Keyword/IOC/Composta).       |
| **Score**           | Valor ponderado 0–100 atribuído pelo Scoring Engine.                                |
| **Category**        | Classificação do finding (`LEAK`, `CREDENTIAL`, `CARD`, `MALWARE`, `BRAND`, ...).   |
| **Severity**        | `INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`.                                        |
| **Confidence**      | Grau de certeza 0–100.                                                              |

---

## 2. Decisões arquiteturais

### 2.1 Clean Architecture + Hexagonal + DDD

- **Core** (`threat_hunting.core.domain`) contém apenas linguagem de negócio:
  entidades, value objects, agregados, eventos e **portas** (interfaces
  abstratas). Não conhece SQLAlchemy, httpx, Redis, Django ou qualquer
  detalhe de infra.
- **Application** (`threat_hunting.core.application`) orquestra use cases,
  define DTOs e implementa o **pipeline** que compõe as etapas do fluxo.
  Depende apenas do domínio (via ports).
- **Infrastructure** (`threat_hunting.infrastructure.*`) implementa os
  *adapters* (conectores, engines, storage, exporters, observabilidade,
  scheduler). Todo o mundo externo entra por aqui.
- **Presentation** (`threat_hunting.cli`, futura `web/`, futura `api/`)
  consome apenas a application layer via *composition root* (DI container).

A regra de dependência é estritamente unidirecional:

```
presentation → application → domain ← infrastructure
```

### 2.2 Event-Driven

Cada etapa do pipeline publica eventos no *event bus* interno
(`FindingCreated`, `RuleMatched`, `ScoreComputed`, `FindingCorrelated`,
`FindingExported`, ...). Observadores registram-se para reagir (ex:
alerta MISP automático quando `score >= threshold`).

### 2.3 Plugin Pattern

Conectores, parsers, extractors, detectores, scorers, correlators,
enrichers, storages e exporters são **plugáveis via entry points** e
via *auto-discovery* de módulos (`ConnectorRegistry.discover()`).
Novos conectores não modificam o core — apenas herdam de `BaseConnector`
e são registrados via `@register_connector("name")`.

### 2.4 Configuração declarativa

Toda a plataforma é dirigida por **YAML** (`config/*.yaml`) validado por
Pydantic V2. Nenhuma regra é hardcoded. Chaves sensíveis são resolvidas
via `env:` (variáveis de ambiente) ou Vault-like providers.

### 2.5 OPSEC como cross-cutting concern

Rede é acessada exclusivamente através de `OpsecHTTPClient`, com perfis
(`default`, `tor`, `residential-us`, ...) que definem proxy, headers,
rate limit, retry/backoff, jitter, TLS. Conectores nunca falam com
`httpx` diretamente.

### 2.6 Repository + Unit of Work

Persistência via `FindingRepository`, `IndicatorRepository`,
`ThreatActorRepository`, `WatchlistRepository`, `RuleRepository`,
`JobRepository` — todas interfaces. `UnitOfWork` garante atomicidade
e publicação de eventos após commit.

### 2.7 Strategy / Factory / Builder / Adapter / Command / Observer

- **Strategy**: detectores, scorers, correladores.
- **Factory**: `ConnectorFactory`, `ExporterFactory`, `StorageFactory`.
- **Builder**: `FindingBuilder`, `IndicatorBuilder`, `RuleSetBuilder`.
- **Adapter**: cada exportador é um adapter para um sistema externo.
- **Command**: comandos da CLI e ações do scheduler.
- **Observer**: event bus + hooks.

---

## 3. Design Patterns aplicados (mapa)

| Padrão                | Onde aparece                                                    |
|-----------------------|-----------------------------------------------------------------|
| Repository            | `core/domain/ports/repositories.py` e impls em `infrastructure/storage` |
| Unit of Work          | `core/application/uow.py`, `infrastructure/storage/sqlalchemy/uow.py`    |
| Factory               | `infrastructure/connectors/factory.py`, `exporters/factory.py`  |
| Strategy              | `infrastructure/detections`, `scoring`, `correlation`           |
| Builder               | `core/domain/builders/finding_builder.py`                       |
| Adapter               | `infrastructure/exporters/*`                                    |
| Command               | `cli/commands/*` + `core/application/commands/*`                |
| Observer / Pub–Sub    | `core/application/events/bus.py`                                |
| Plugin / Registry     | `infrastructure/connectors/registry.py`                         |
| Dependency Injection  | `composition_root.py` (dependency-injector)                     |
| Chain of Responsibility | pipeline stages em `core/application/pipeline`                |

---

## 4. Entidades e Value Objects

### 4.1 Value Objects (imutáveis, comparados por valor)

- `Severity(Enum)` — INFO / LOW / MEDIUM / HIGH / CRITICAL
- `Confidence(int 0–100)`
- `Score(float 0–100)`
- `Category(Enum)` — LEAK / CREDENTIAL / CARD / DOCUMENT / MALWARE / BRAND / VIP / IOC / RANSOMWARE / PHISHING / DARKWEB / SOCIAL / NEWS / OTHER
- `IndicatorType(Enum)` — IP / DOMAIN / URL / EMAIL / HASH_MD5 / HASH_SHA1 / HASH_SHA256 / CVE / ASN / CERTIFICATE / WALLET_BTC / WALLET_ETH / CARD_PAN / CPF / CNPJ / USERNAME / TELEGRAM_HANDLE / GITHUB_HANDLE
- `SourceRef` — nome canônico da fonte + connector + collected_at + url original
- `TLP(Enum)` — WHITE / GREEN / AMBER / RED

### 4.2 Entidades

- `Finding` (agregado raiz)
- `Indicator`
- `Artifact`
- `Relationship`
- `TimelineEvent`
- `ThreatActor`
- `Campaign`
- `WatchlistItem`
- `DetectionRule`
- `Job` (execução de connector/pipeline)

### 4.3 Modelo Finding (contrato canônico)

```python
Finding(
    id: UUID,
    title: str,
    description: str,
    source: SourceRef,           # onde foi encontrado
    connector: str,              # id do connector
    category: Category,
    severity: Severity,
    score: Score,
    confidence: Confidence,
    tlp: TLP,
    created_at: datetime,
    updated_at: datetime,
    raw_data: dict,              # cru retornado pelo parser
    normalized_data: dict,       # após normalizer
    metadata: dict,              # livre
    tags: set[str],
    artifacts: list[Artifact],
    indicators: list[Indicator],
    relationships: list[Relationship],
    timeline: list[TimelineEvent],
)
```

---

## 5. Contratos (Ports)

Definidos em `core/domain/ports/`:

- `ConnectorPort` — `connect / collect / parse / normalize / health / close`
- `ParserPort`, `ExtractorPort`, `NormalizerPort`
- `DetectionEnginePort`, `ScoringEnginePort`, `CorrelationEnginePort`,
  `DeduplicationEnginePort`, `EnrichmentEnginePort`
- `RepositoryPort[T]` (genérico)
- `UnitOfWorkPort`
- `ExporterPort`
- `EventBusPort`
- `ClockPort` (para testabilidade determinística)
- `HTTPClientPort` (OPSEC)
- `CredentialsPort`
- `SchedulerPort`

Nenhum implementação vive dentro do domínio.

---

## 6. Estrutura completa do projeto

```
threat_hunting/
├── __init__.py
├── composition_root.py           # DI container global
├── core/
│   ├── domain/
│   │   ├── entities/             # Finding, Indicator, Artifact, ThreatActor, ...
│   │   ├── value_objects/        # Severity, Score, Confidence, Category, ...
│   │   ├── events/               # Domain events
│   │   ├── exceptions.py
│   │   ├── builders/             # FindingBuilder, ...
│   │   └── ports/                # Interfaces (repositórios, engines, http, ...)
│   └── application/
│       ├── use_cases/            # RunConnector, RunPipeline, ExportFindings, ...
│       ├── pipeline/             # Orchestrator + Stage base + concrete stages
│       ├── dto/                  # Data Transfer Objects
│       ├── commands/             # Command Pattern
│       ├── events/               # Event bus in-memory
│       └── uow.py
├── infrastructure/
│   ├── opsec/                    # HTTP client, proxy pools, UA, rate limit, retry
│   ├── connectors/
│   │   ├── base.py               # BaseConnector
│   │   ├── registry.py           # Registry + auto-discovery
│   │   ├── factory.py
│   │   └── implementations/
│   │       ├── rss.py
│   │       ├── reddit.py
│   │       ├── github.py
│   │       ├── threatfox.py
│   │       ├── generic_http.py
│   │       ├── paste_site.py
│   │       ├── darkweb_leak.py
│   │       ├── misp.py
│   │       ├── otx.py
│   │       ├── urlhaus.py
│   │       ├── shodan.py
│   │       └── ...
│   ├── parsers/                  # HTMLParser, JSONParser, RSSParser, ...
│   ├── extractors/               # IOCExtractor, CredentialExtractor, CardExtractor, WalletExtractor, DocExtractor
│   ├── normalizers/              # canonicalização de campos
│   ├── detections/               # regex, yara, sigma, keyword, ioc, composite
│   ├── scoring/                  # WeightedScoringEngine (configurável via YAML)
│   ├── correlation/              # graph-based correlator
│   ├── deduplication/            # hashing + fuzzy
│   ├── enrichment/               # geoip, whois, dns, threatfox, misp lookup
│   ├── storage/
│   │   ├── sqlalchemy/           # engine, models, repositórios, UoW
│   │   ├── json_backend/         # backend para JSON/parquet local
│   │   └── factory.py
│   ├── exporters/                # json, csv, misp, opencti, splunk, opensearch, webhook, stix, taxii
│   ├── scheduler/                # APScheduler wrapper
│   ├── observability/            # structlog, prometheus, otel
│   ├── config/                   # loaders YAML → pydantic settings
│   └── plugins/                  # entry-point discovery
├── cli/                          # Typer app
│   ├── app.py
│   └── commands/                 # run.py, connector.py, export.py, scheduler.py, score.py, ...
├── api/                          # (placeholder) FastAPI futura
├── web/                          # (placeholder) Django futuro
├── database/                     # Alembic migrations
├── config/                       # YAMLs: settings, connectors, keywords, rules, scoring
├── tests/
│   ├── unit/
│   └── integration/
└── docs/
```

---

## 7. Fluxo completo (pipeline)

```
                       ┌───────────────────────┐
                       │      SCHEDULER        │ (cron/interval jobs, APScheduler)
                       └──────────┬────────────┘
                                  │ dispatch(RunConnectorCommand)
                                  ▼
   ┌────────────────┐   ┌───────────────────────────────────────┐
   │      CLI       │──►│           APPLICATION USE CASE        │
   │  (Typer)       │   │        RunConnectorPipeline           │
   └────────────────┘   └──────────────────┬────────────────────┘
                                            │
                                            ▼
   ┌─────────────┐   ┌───────────┐   ┌───────────┐   ┌─────────────┐   ┌──────────┐
   │  Connector  │──►│  Parser   │──►│ Extractor │──►│ Normalizer  │──►│Detection │
   │ (plugin)    │   │           │   │  (IOCs)   │   │  (canonical)│   │  Engine  │
   └─────────────┘   └───────────┘   └───────────┘   └─────────────┘   └────┬─────┘
                                                                             │
                                                                             ▼
   ┌───────────────┐   ┌─────────────┐   ┌─────────────────┐   ┌──────────────┐
   │   Scoring     │──►│ Correlation │──►│ Deduplication   │──►│  Enrichment  │
   └───────────────┘   └─────────────┘   └─────────────────┘   └──────┬───────┘
                                                                       │
                                                                       ▼
                                              ┌────────────────────────────────┐
                                              │      Persistence (UoW)         │
                                              │  Findings / Indicators / ...   │
                                              └──────────────┬─────────────────┘
                                                             │  commit → events
                                                             ▼
                                              ┌────────────────────────────────┐
                                              │            Exporters           │
                                              │  MISP / OpenCTI / STIX / etc.  │
                                              └────────────────────────────────┘

Cross-cutting:
   OPSEC (proxy/UA/rate/retry)  │ Observability (structlog + Prometheus + OTel)
   Event Bus (in-memory pub/sub)│ Configuration (pydantic-settings + YAML)
   DI Container (dependency-injector)
```

Cada estágio implementa `PipelineStage.run(context) -> context`. O
`PipelineOrchestrator` é responsável apenas por compor os estágios na
ordem definida em `config/pipeline.yaml` (permitindo reordenar/desligar
estágios sem alterar código).

---

## 8. Extensibilidade

Adicionar um novo conector requer apenas:

```python
# threat_hunting/infrastructure/connectors/implementations/mysource.py
from threat_hunting.infrastructure.connectors.base import BaseConnector
from threat_hunting.infrastructure.connectors.registry import register_connector

@register_connector("mysource")
class MySourceConnector(BaseConnector):
    async def collect(self): ...
    async def parse(self, payload): ...
    async def normalize(self, parsed): ...
    async def health(self): ...
```

Adicionando `mysource:` no `config/connectors.yaml` o scheduler o executa.
Zero mudança no core.

Adicionar um novo exportador, detector, scorer ou storage segue o mesmo
padrão de registro por decorator + auto-discovery.

---

## 9. Segurança / OPSEC

- Nenhum segredo em código. `SecretStr` (Pydantic) + env vars + `.env`.
- Rede sempre via `OpsecHTTPClient` (SOCKS5 para Tor, HTTP(S) para
  residenciais).
- User-Agents rotacionados.
- Rate limit por host (`aiolimiter`-like custom).
- Retries com backoff exponencial + jitter.
- Circuit-breaker por host.
- Logging estruturado com *redaction* de PII/credenciais.
- TLP awareness em exportações.

---

## 10. Observabilidade

- `structlog` com processors JSON.
- Métricas Prometheus (`threat_hunting_findings_total`,
  `threat_hunting_connector_duration_seconds`,
  `threat_hunting_pipeline_errors_total`, ...).
- Tracing OpenTelemetry por stage do pipeline.
- Health checks agregados (`/healthz` futuro na API, `hunt health` CLI).

---

## 11. Roadmap de implementação (arquivo por arquivo)

1. Bootstrap: `pyproject.toml`, `README.md`, `Makefile`, `.gitignore`, `config/*.yaml`.
2. Domain: value objects → entidades → builders → eventos → exceções → ports.
3. Application: DTOs → event bus → UoW abstrato → pipeline base → use cases.
4. Infrastructure OPSEC → connectors base/registry → parsers/extractors/normalizers.
5. Engines: detection → scoring → correlation → deduplication → enrichment.
6. Storage SQLAlchemy (SQLite default, Postgres compatível) + JSON backend.
7. Exporters: JSON, CSV, MISP, STIX, Webhook, OpenCTI, Splunk, OpenSearch.
8. Scheduler + Observability + Composition root.
9. Reference connectors: RSS, Generic HTTP, GitHub, Reddit, ThreatFox,
   Paste, Dark Web leak site.
10. CLI Typer completa.
11. Alembic + migrations.
12. Tests.

Somente após este blueprint arquitetural o código é escrito.
