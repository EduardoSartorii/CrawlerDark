"""Motor de correlacao de campanhas da plataforma phishing_intel.

Responsabilidade do componente
-------------------------------
Comparar os achados de um novo incidente contra o historico persistido
(``database/repositories.py``) para produzir sinais de correlacao
(:class:`models.campaign.CorrelationSignal`), que sao entao combinados pelo
``campaign_correlator`` em um Attribution Score (0-100) e um nivel de
confianca (baixa/media/alta).

Fluxo de execucao
------------------
``fingerprint_correlator`` e ``infrastructure_correlator`` produzem sinais
especializados por dominio (kit reutilizado, infraestrutura reutilizada);
``campaign_correlator`` os agrega, aplica os pesos configurados em
``config.yaml`` e decide se o incidente pertence a uma campanha existente
ou inicia uma nova.
"""
