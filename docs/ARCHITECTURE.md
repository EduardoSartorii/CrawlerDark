# Threat Hunting Collection Platform — Arquitetura

## 1. Visão Geral

Plataforma corporativa de **Threat Hunting Collection** para descoberta automática de ameaças, vazamentos, campanhas maliciosas, IOCs, monitoramento de marca, VIP Monitoring e Dark Web Monitoring.

A arquitetura segue **Clean Architecture**, **DDD**, **Hexagonal Architecture** e **Event-Driven Design**, garantindo que o **Core nunca conheça infraestrutura**.

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           CLI / Scheduler / API (futuro Django)         │
├─────────────────────────────────────────────────────────────────────────┤
│                         Application Layer                               │
│   Commands │ Queries │ Handlers │ Pipeline Orchestrator │ Events        │
├─────────────────────────────────────────────────────────────────────────┤
│                           Domain Layer (Core)                           │
│   Entities │ Value Objects │ Domain Services │ Repository Interfaces    │
│   Events │ Policies │ Specifications                                      │
├─────────────────────────────────────────────────────────────────────────┤
│                        Infrastructure Layer                             │
│ Connectors │ Parsers │ Storage │ Exporters │ OPSEC │ Observability      │
└─────────────────────────────────────────────────────────────────────────┘
```

## 2. Domínio da Aplicação

### Bounded Contexts

| Contexto | Responsabilidade |
|----------|------------------|
| **Collection** | Coleta via conectores, pipeline de processamento |
| **Intelligence** | Findings, IOCs, artefatos, correlações |
| **Detection** | Regras dinâmicas (regex, YARA, sigma, keywords, IOC) |
| **Scoring** | Pontuação configurável de findings |
| **Correlation** | Ligação entre entidades (domínios, IPs, actors, campaigns) |
| **Deduplication** | Eliminação de duplicatas por hash/similaridade |
| **Enrichment** | Enriquecimento via APIs externas (VT, GreyNoise, etc.) |
| **Export** | Exportação para MISP, OpenCTI, Splunk, STIX/TAXII |
| **Watchlist** | Keywords, VIPs, marcas, domínios, threat actors |
| **OPSEC** | Proxies, rate limiting, credenciais, perfis por conector |
| **Audit** | Trilha de auditoria de execuções e exportações |

### Linguagem Ubíqua

- **Finding**: unidade central de inteligência coletada e processada
- **Connector**: adaptador de fonte externa (Reddit, GitHub, Dark Web, etc.)
- **Pipeline Stage**: etapa desacoplada do fluxo de processamento
- **Watchlist**: lista de termos/entidades monitoradas
- **Indicator**: IOC extraído (IP, domínio, hash, email, etc.)
- **Artifact**: evidência associada ao finding (screenshot, arquivo, URL)
- **Rule**: regra de detecção carregada dinamicamente
- **Score Profile**: perfil de pesos para scoring

## 3. Entidades de Domínio

### Finding (Agregado Raiz)

```python
Finding:
  id: UUID
  title: str
  description: str
  source: SourceType
  connector: str
  category: FindingCategory
  severity: Severity
  score: float
  confidence: float
  created_at: datetime
  updated_at: datetime
  raw_data: dict
  normalized_data: dict
  metadata: dict
  tags: list[str]
  artifacts: list[Artifact]
  indicators: list[Indicator]
  relationships: list[Relationship]
  timeline: list[TimelineEvent]
```

### Outras Entidades

- **ConnectorConfig**: configuração de conector (enabled, schedule, opsec_profile)
- **WatchlistEntry**: entrada de watchlist (keyword, VIP, brand, domain, etc.)
- **DetectionRule**: regra carregada dinamicamente (regex, yara, sigma, composite)
- **ScoreWeight**: peso configurável para dimensão de scoring
- **CorrelationLink**: vínculo entre findings/entidades
- **ExportJob**: job de exportação com status e destino
- **AuditLog**: registro de auditoria imutável
- **OpsecProfile**: perfil de segurança operacional por conector

### Value Objects

- `Severity` (info, low, medium, high, critical)
- `IndicatorType` (ip, domain, url, hash, email, cpf, cnpj, card, wallet, etc.)
- `SourceType` (social, darkweb, feed, api, paste, forum, marketplace)
- `ConnectorHealth` (healthy, degraded, unhealthy)
- `DedupKey` (hash composto para deduplicação)

## 4. Contratos (Ports)

### Repository Interfaces (Core)

```python
IFindingRepository          # CRUD + query de findings
IWatchlistRepository        # Gerenciamento de watchlists
IDetectionRuleRepository    # Regras dinâmicas
IScoreProfileRepository     # Perfis de scoring
ICorrelationRepository      # Links de correlação
IConnectorConfigRepository  # Config de conectores
IAuditRepository            # Auditoria
IUnitOfWork                 # Transação atômica
```

### Service Interfaces (Core)

```python
IConnector                  # SDK base de conectores
IParser                     # Parsing de raw data
IExtractor                  # Extração de entidades
INormalizer                 # Normalização para modelo Finding
IDetectionEngine            # Motor de detecção
IScoringEngine              # Motor de scoring
ICorrelationEngine          # Motor de correlação
IDeduplicationEngine        # Motor de deduplicação
IEnrichmentEngine           # Motor de enriquecimento
IStorageBackend             # Persistência abstrata
IExporter                   # Exportação abstrata
IOpsecTransport             # Transporte com OPSEC
IEventBus                   # Barramento de eventos
```

## 5. Design Patterns

| Pattern | Aplicação |
|---------|-----------|
| **Repository** | Abstração de persistência (Finding, Watchlist, Rules) |
| **Unit of Work** | Transações atômicas em persistência |
| **Strategy** | Engines (detection, scoring, dedup), storage backends, exporters |
| **Factory** | Criação de conectores, parsers, pipeline stages |
| **Builder** | Construção de Finding, Pipeline, Export payloads |
| **Adapter** | Conectores externos, storage backends, integrações MISP/VT |
| **Command** | CLI commands (RunConnector, Export, EnableConnector) |
| **Observer** | Event bus para findings detectados, exports, alertas |
| **Plugin** | Auto-discovery de conectores via entry points |
| **Dependency Injection** | Container central (dependency-injector) |
| **Specification** | Filtros de query no domínio |
| **Chain of Responsibility** | Pipeline stages encadeadas |

## 6. Estrutura do Projeto

```
threat_hunting/
├── core/
│   ├── domain/           # Entidades, VOs, eventos, exceções
│   ├── application/      # Commands, handlers, DTOs, services
│   └── contracts/        # Ports (interfaces ABC)
├── infrastructure/
│   ├── connectors/       # Implementações de conectores
│   ├── parsers/          # Parsers por tipo de fonte
│   ├── extractors/       # Extração de IOCs, credenciais, etc.
│   ├── normalizers/      # Normalização para Finding
│   ├── detections/       # Motor de detecção + rule loaders
│   ├── scoring/          # Motor de scoring
│   ├── correlation/      # Motor de correlação
│   ├── deduplication/    # Motor de deduplicação
│   ├── enrichment/       # Enriquecimento via APIs
│   ├── pipelines/        # Orquestrador do pipeline
│   ├── scheduler/        # APScheduler jobs
│   ├── plugins/          # Plugin discovery
│   ├── storage/          # SQLite, PostgreSQL, JSON, etc.
│   ├── exporters/        # MISP, Splunk, STIX, etc.
│   ├── integrations/   # Clientes HTTP para APIs externas
│   ├── opsec/            # Proxies, rate limit, credenciais
│   ├── observability/    # Tracing, metrics, health
│   └── database/         # SQLAlchemy models, Alembic
├── cli/                  # Typer CLI
├── api/                  # Preparação para API REST (futuro)
├── web/                  # Preparação para Django admin (futuro)
├── config/               # YAML configs
└── tests/                # Unit + integration tests
```

## 7. Fluxo da Aplicação

### Pipeline de Coleta

```
CLI: hunt run <connector>
        │
        ▼
┌──────────────┐
│  Connector   │ connect() → collect() → raw payloads
└──────┬───────┘
       ▼
┌──────────────┐
│   Parser     │ parse() → structured data
└──────┬───────┘
       ▼
┌──────────────┐
│  Extractor   │ extract() → entities, IOCs, credentials
└──────┬───────┘
       ▼
┌──────────────┐
│ Normalizer   │ normalize() → Finding (draft)
└──────┬───────┘
       ▼
┌──────────────┐
│  Detection   │ apply rules → tagged Finding
└──────┬───────┘
       ▼
┌──────────────┐
│   Scoring    │ calculate score → scored Finding
└──────┬───────┘
       ▼
┌──────────────┐
│ Correlation  │ link related entities
└──────┬───────┘
       ▼
┌──────────────┐
│ Deduplication│ filter duplicates
└──────┬───────┘
       ▼
┌──────────────┐
│ Enrichment   │ enrich via external APIs
└──────┬───────┘
       ▼
┌──────────────┐
│ Persistence  │ save via IStorageBackend
└──────┬───────┘
       ▼
┌──────────────┐
│   Export     │ if score > threshold → MISP/auto-export
└──────────────┘
```

### Event Flow

```
FindingDetected → ScoringCompleted → CorrelationFound → FindingPersisted → ExportTriggered
```

Cada evento é publicado no `IEventBus` e consumido por observers (audit, metrics, auto-export).

## 8. SDK de Conectores

```python
class BaseConnector(ABC):
    name: str
    source_type: SourceType

    async def connect(self) -> None: ...
    async def collect(self, context: CollectionContext) -> AsyncIterator[RawPayload]: ...
    def parse(self, payload: RawPayload) -> ParsedData: ...
    def normalize(self, parsed: ParsedData) -> FindingDraft: ...
    async def health(self) -> ConnectorHealth: ...
    async def close(self) -> None: ...
```

- Auto-discovery via `importlib.metadata` entry points (`threat_hunting.connectors`)
- Nenhum conector modifica o Core
- OPSEC injetado via `IOpsecTransport`

## 9. Decisões Arquiteturais

| Decisão | Justificativa |
|---------|---------------|
| Async-first (httpx) | Conectores I/O-bound, escalabilidade |
| Pydantic V2 para DTOs | Validação rigorosa, serialização |
| SQLAlchemy 2 + Alembic | ORM maduro, migrations versionadas |
| Dependency Injector | DI explícita, testabilidade |
| structlog | Logging estruturado para SIEM |
| OpenTelemetry + Prometheus | Observabilidade production-grade |
| YAML para config | Legível, versionável, sem hardcode |
| Entry points para plugins | Extensibilidade sem alterar core |
| Event bus in-process | Desacoplamento sem complexidade de message broker inicial |
| Preparação Django | Interfaces de repositório compatíveis com Django ORM futuro |

## 10. OPSEC Layer

Camada independente que abstrai transporte de rede:

- `OpsecProfile`: proxy HTTP/SOCKS5, user-agent, rate limits, retry policy
- `CredentialVault`: credenciais criptografadas por conector
- `RateLimiter`: token bucket por conector/fonte
- `TransportFactory`: cria httpx.AsyncClient configurado por perfil

## 11. Storage Abstraction

`IStorageBackend` com implementações plugáveis:

- SQLite (default dev)
- PostgreSQL (produção)
- JSON files
- OpenSearch/Elasticsearch
- S3/Parquet (data lake)

Troca de backend via config, zero impacto no Core.

## 12. Preparação Django

- Repositórios implementam interfaces do Core
- Models SQLAlchemy mapeáveis para Django ORM
- Admin views futuras consumirão mesmos use cases da Application Layer
- Permissões e multi-tenancy preparados via `TenantId` no domínio
