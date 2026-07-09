# Pipeline

Mandatory order (business rule):

```
Connector → Parser → Extractor → Normalizer → Detection → Scoring →
Correlation → Deduplication → Enrichment → Persistence → Export (events)
```

Implemented by `PipelineOrchestrator` in `core/application/pipeline/orchestrator.py`.

Each stage is a Strategy injected via DI. Auto-MISP export fires on
`ScoreThresholdExceeded` when score ≥ configured threshold.
