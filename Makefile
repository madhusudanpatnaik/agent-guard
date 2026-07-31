.PHONY: install dev seed serve test cover lint typecheck ci verify docker migrate migration clean

VENV ?= .venv
PY := $(VENV)/bin/python
PIP := $(VENV)/bin/pip
# Prefer 3.12 for the widest wheel coverage; fall back to whatever python3 is.
BOOTSTRAP_PY := $(shell command -v python3.12 || command -v python3)

install:
	$(BOOTSTRAP_PY) -m venv $(VENV)
	$(PIP) install -U pip
	$(PIP) install -r requirements.txt
	$(PIP) install -e ".[dev]"

seed:
	$(VENV)/bin/agentops seed

serve:
	$(VENV)/bin/agentops serve --reload

test:
	$(VENV)/bin/pytest

cover:
	$(VENV)/bin/pytest --cov=agentops --cov-report=term-missing

lint:
	$(VENV)/bin/ruff check agentops sdk examples tests scripts

typecheck:
	$(VENV)/bin/mypy agentops --ignore-missing-imports

ci: lint typecheck test

verify:
	$(VENV)/bin/agentops verify

docker:
	docker compose up --build

migrate:
	$(VENV)/bin/alembic upgrade head

migration:
	$(VENV)/bin/alembic revision --autogenerate -m "$(msg)"

clean:
	rm -rf $(VENV) *.db .pytest_cache .ruff_cache __pycache__ agentops/__pycache__
