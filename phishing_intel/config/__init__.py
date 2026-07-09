"""Pacote de configuracao da plataforma phishing_intel.

Responsabilidade do componente
-------------------------------
Centralizar o carregamento e a validacao de toda a configuracao operacional
da plataforma (banco de dados, MISP, coletores, pesos de correlacao e base
de marcas conhecidas), expondo um unico ponto de acesso tipado
(:class:`~phishing_intel.config.settings.PhishingIntelSettings`) para o
restante da aplicacao.

Fluxo de execucao
------------------
1. ``config.yaml`` e lido do disco (ou de um caminho customizado).
2. Variaveis de ambiente com prefixo ``PHISHING_INTEL_`` podem sobrescrever
   qualquer valor sensivel (ex.: chave de API do MISP), evitando o
   versionamento de segredos em texto plano.
3. O resultado e validado com Pydantic e cacheado em memoria para reuso.
"""

from config.settings import PhishingIntelSettings, get_settings

__all__ = ["PhishingIntelSettings", "get_settings"]
