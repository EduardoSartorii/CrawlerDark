"""Camada de coleta (fluxo secundario) da plataforma phishing_intel.

Responsabilidade do componente
-------------------------------
Fornecer os artefatos brutos (HTML, certificado TLS, dados de DNS e de
infraestrutura de rede) SOMENTE quando o parceiro de CTI nao os enviar
previamente. Esta camada e estritamente separada da camada de analise
(``analyzers/``): coletores nunca interpretam o conteudo coletado, apenas o
obtem e o entregam para armazenamento de evidencias e posterior analise.

Fluxo de execucao
------------------
O fluxo principal da plataforma (HTML/JS ja fornecidos pelo parceiro) NAO
invoca estes coletores. Eles sao usados exclusivamente no fluxo secundario,
quando ``main.py`` detecta que o HTML nao foi fornecido para uma URL
suspeita recebida.
"""
