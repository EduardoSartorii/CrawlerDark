.PHONY: install install-dev test lint format typecheck migrate run-scheduler run-connector clean

install:
	poetry install --only main

install-dev:
	poetry install

test:
	poetry run pytest

test-fast:
	poetry run pytest -x -q --no-cov

lint:
	poetry run ruff check threat_hunting tests

format:
	poetry run ruff format threat_hunting tests
	poetry run ruff check --fix threat_hunting tests

typecheck:
	poetry run mypy threat_hunting

migrate:
	poetry run alembic upgrade head

run-scheduler:
	poetry run hunt scheduler run

clean:
	find . -type d -name __pycache__ -exec rm -rf {} +
	rm -rf .pytest_cache .ruff_cache .mypy_cache htmlcov .coverage
