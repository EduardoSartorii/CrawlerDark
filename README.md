# Phishing Intel

Plataforma profissional de Cyber Threat Intelligence para análise estática,
classificação, correlação, enriquecimento MISP e atribuição de campanhas de
phishing recebidas por parceiros de CTI.

## Fluxo principal

1. Recebe URL, HTML e JavaScript já coletados por parceiros.
2. Analisa DOM, formulários, assets, scripts, IOC's e destinos de exfiltração.
3. Gera fingerprints de kit e campanha.
4. Correlaciona com histórico persistido em SQLAlchemy.
5. Monta evento, atributos, tags locais e objeto `phishing-campaign` para MISP.
6. Preserva evidências brutas e resultado analítico em `evidence/<campaign_id>/`.

## Responsabilidade dos módulos

- `collectors/`: coleta secundária de HTML, DNS, SSL e infraestrutura quando artefatos não são fornecidos.
- `analyzers/`: análise estática de DOM, JavaScript, formulários, exfiltração, marcas e fingerprints.
- `correlators/`: atribuição por pesos para fingerprint, certificado, ASN, provedor, DOM, JavaScript e marca.
- `enrichment/`: mapeamento de taxonomias locais, construção de payload MISP e envio via PyMISP.
- `database/`: modelos SQLAlchemy, sessão transacional e repositório de histórico.
- `models/`: contratos Pydantic para achados, campanhas, infraestrutura e certificados.
- `config/`: configuração YAML de banco, evidências, MISP e perfis de renderização.

## Instalação

```bash
poetry install
```

## Uso

```bash
poetry run python main.py \
  --url https://phish.example/login \
  --html-file samples/page.html \
  --js-file samples/page.js
```

Para analisar somente artefatos locais sem coleta secundária:

```bash
poetry run python main.py --html-file samples/page.html --js-file samples/page.js --no-fetch
```

Por padrão, MISP roda em `dry_run`. Configure `phishing_intel/config/config.yaml`
para envio real.

## Testes

```bash
poetry run pytest
```

A cobertura mínima configurada é 80%.
