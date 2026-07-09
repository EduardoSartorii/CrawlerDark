# Phishing Intelligence Platform

Plataforma de Threat Intelligence para análise estática de phishing, correlação de campanhas e enriquecimento no MISP.

## Capacidades

- Ingestão de URL, HTML e JavaScript coletados por parceiros.
- Análise de DOM, JavaScript, exfiltração, classificação de objetivo e marca alvo.
- Fingerprinting de kits e correlação histórica de campanhas.
- Persistência de evidências e histórico em banco SQLAlchemy.
- Enriquecimento de eventos MISP com atributos e objeto customizado `phishing-campaign`.

## Execução

1. Instale dependências:
   - `poetry install`
2. Execute o pipeline:
   - `poetry run python -m phishing_intel.main --url https://example.test/phish`
3. Rode os testes:
   - `poetry run pytest`
