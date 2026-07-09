"""Camada de enriquecimento e integracao MISP da plataforma phishing_intel.

Responsabilidade do componente
-------------------------------
Traduzir o resultado da analise/correlacao de um incidente em taxonomias e
tags locais (``taxonomy_mapper``), objetos/eventos/atributos MISP
(``misp_client``) e orquestrar o pipeline completo de ponta a ponta
(``campaign_builder``): analise -> correlacao -> persistencia -> MISP.
"""
