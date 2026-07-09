"""Camada de analise estatica da plataforma phishing_intel.

Responsabilidade do componente
-------------------------------
Concentrar toda a inteligencia de analise estatica de artefatos de
phishing: estrutura DOM, comportamento de JavaScript, classificacao do tipo
de ataque, destinos de exfiltracao, fingerprint de kit e deteccao de marca-
alvo. Esta e a camada nucleo da plataforma — o valor de CTI entregue nao
esta na coleta, mas na profundidade desta analise.

Fluxo de execucao
------------------
``enrichment/campaign_builder.py`` orquestra a execucao sequencial de cada
analisador sobre o HTML/JS recebido (fornecido pelo parceiro ou coletado),
consolidando os resultados em um unico ``models.findings.AnalysisReport``.
"""
