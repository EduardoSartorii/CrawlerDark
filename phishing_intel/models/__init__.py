"""Modelos de dominio (Pydantic) da plataforma phishing_intel.

Responsabilidade do componente
-------------------------------
Este pacote define os contratos de dados que trafegam entre coletores,
analisadores, correlacionadores e a camada de enriquecimento MISP. Todos os
modelos usam Pydantic para validacao e serializacao, garantindo que dados
malformados provenientes de HTML/JS hostil (fornecidos por parceiros de CTI)
sejam normalizados antes de alcancar o banco de dados ou o MISP.
"""
