"""Camada de persistencia da plataforma phishing_intel.

Responsabilidade do componente
-------------------------------
Prover os modelos ORM (SQLAlchemy), a fabrica de sessoes e os repositorios
que encapsulam todo o acesso a dados. Nenhuma outra camada da aplicacao deve
executar SQL ou manipular sessoes SQLAlchemy diretamente — apenas atraves
dos repositorios expostos aqui, mantendo a regra de separacao entre coleta,
analise e persistencia (requisito de OPSEC/cadeia de evidencias).
"""
