# Threat Hunting Collection Platform

Plataforma corporativa de Threat Hunting Collection para OSINT, Brand Monitoring,
VIP Monitoring, Dark Web/Deep Web Monitoring, Credential Hunting, IOC Hunting,
Leak Hunting, Campaign Discovery, correlação, enriquecimento, scoring,
persistência, exportação e auditoria.

O projeto agora segue Clean Architecture, Domain Driven Design, Hexagonal
Architecture, Event Driven Architecture e Plugin Pattern. O core não conhece
detalhes de infraestrutura; conectores, storage, exportadores, scheduler, CLI,
observabilidade e integrações são adapters substituíveis.

## Arquitetura

A documentação completa está em [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

Pipeline obrigatório:

`Connector -> Parser -> Extractor -> Normalizer -> Detection Engine -> Scoring Engine -> Correlation Engine -> Deduplication Engine -> Enrichment Engine -> Persistence -> Export`

## Stack

- Python 3.12+
- Poetry
- Pydantic V2
- SQLAlchemy 2 + Alembic
- httpx, BeautifulSoup4, lxml
- PyMISP
- Redis-ready architecture
- APScheduler
- structlog
- PyYAML
- pytest
- Typer
- Dependency Injector
- OpenTelemetry
- Prometheus Client

## Comandos CLI

```bash
poetry install
poetry run hunt run reddit
poetry run hunt run github
poetry run hunt run telegram
poetry run hunt run social
poetry run hunt run darkweb
poetry run hunt run all
poetry run hunt connector enable reddit
poetry run hunt connector disable reddit
poetry run hunt scheduler run
poetry run hunt export misp
poetry run hunt export splunk
poetry run hunt export elastic
poetry run hunt score test
```

## Configuração

As regras de detecção, scoring, conectores, OPSEC, storage, exportadores e jobs
ficam em [`config/default.yml`](config/default.yml). Nenhuma regra de negócio de
detecção fica hardcoded.

## Testes

```bash
poetry run pytest
```

---

## Conteúdo legado

As anotações abaixo pertencem ao crawler original e foram preservadas como
referência histórica.

# New Features!

  - Captura de tela do vazamento
 


### Trheat Actors monitorados

- Egregor
- Ragnar
- Avaddon
- Darkside
- Dopple
- Ransomexx
- Ranzyleak


### 🔧 Configurando o TOR

Precisamos configurar o tor para podermos utilizar o proxy ao realizar o scraping, neste caso eu utilizei o ubuntu.

Instalando o TOR:
```
sudo apt update
sudo apt install torbrowser-launcher
```

Vamos criar um arquivo chamado tor_port_0:
```
SOCKSPort 9050
ControlPort 9051
DataDirectory *Escolha um diretorio para salvar exemplo: /usr/etc/tor*
```

Execute o comando para dar inicio ao nó:

```
tor -f tor_port_0
```
### 🔧 Instalando o requirements.txt

```
pip3 install -r requirements.txt
```
### ⚙️ Configurando o framework do MISP em frameworks/mispadd.py

Na linha 5 e 6 do código devemos adicionar a chave de autenticação da API do MISP e a url de comunicação com o MISP:

```
self.key_misp = 'CHAVE-DO-MISP'
self.url_misp = "URL-DO-MISP"
```
Na linha 20 devemos adicionar o número do evento ao qual iremos adicionar os atributos.

```
self.misp.add_object('EVENT-ID', self.misp_object)
```

## ⚙️ Executando o script

Para executar o script bastar passar o parametro -f onion como abaixo:

```
python3 main.py -f onion
```

### 🔩 Logs e Screenshots

Todo arquivo de log gerado sera salvo com a extensão *.json:

```
utils/log
```
Toda screenshot será salva e enviada para o misp pelo diretorio:

```
utils/screenshot
```


### Tech

Linguagens utilizadas:

* [TOR] - Browser keep identity secure
* [Python] - evented I/O for the backend

## ✒️ Autores

* **Eduardo Sartori** - *Desenvolvimento* - [EduardoSartorii](https://github.com/EduardoSartorii/)

## 📄 Licença

Este projeto está sob a licença (GNU GENERAL PUBLIC LICENSE) - veja o arquivo [LICENSE.md](https://github.com/EduardoSartorii/CrawlerDark/blob/main/LICENSE) para detalhes.

⌨️ com ❤️ por [Eduaro Sartori](https://github.com/EduardoSartorii/) 😊
