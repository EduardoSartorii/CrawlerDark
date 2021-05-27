# Crawler News

[![N|Solid](https://uploaddeimagens.com.br/images/003/091/892/original/dark.png)](https://nodesource.com/products/nsolid)

Busca de vazamentos na Dark Web

  - Busca em onion de Threat actor
  - Adiciona informação no MISP

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
