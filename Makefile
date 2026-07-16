# BugFund CRS — convenience targets.
# Requires Python 3.11+, Docker, and (for some targets) `make`.
# Most targets assume an active virtualenv with `pip install -e ".[dev]"` run.

.PHONY: install migrate migrations sandbox-images api worker beat test lint smoke up down clean

# Install the project in editable mode with dev extras.
install:
	pip install -e ".[dev]"

# Apply all Alembic migrations to head.
migrate:
	alembic upgrade head

# Create a new autogenerate migration. Usage: make migrations m="add findings table"
migrations:
	alembic revision --autogenerate -m "$(m)"

# Build the three hardened sandbox image tiers under execution_engine/images.
# base    : stripped, non-root base image
# harness : per-target-type test harness image
# targets : target ingestion / packaging image
sandbox-images:
	docker build -t bugfund/sandbox-base:latest    execution_engine/images/base
	docker build -t bugfund/sandbox-harness:latest execution_engine/images/harness
	docker build -t bugfund/sandbox-target:latest  execution_engine/images/targets

# Run the control plane API with hot reload.
api:
	uvicorn control_plane.api.main:app --reload --port 8000

# Run the Celery worker (campaigns + sandbox queues).
worker:
	celery -A control_plane.tasks.celery_app worker -l info -Q campaigns,sandbox

# Run Celery beat (periodic reaper / budget sweeps / checkpoint GC).
beat:
	celery -A control_plane.tasks.celery_app beat -l info

# Run the test suite (pytest, async-aware per pyproject.toml).
test:
	pytest

# Lint + format check (ruff).
lint:
	ruff check .
	ruff format --check .

# Submit a demo target and launch a campaign against the local API.
# Best-effort: prints a helpful message if the API isn't up yet.
smoke:
	python -m scripts.seed_demo

# Bring up the full stack via Docker Compose.
up:
	docker compose up -d

# Tear down the full stack.
down:
	docker compose down

# Remove transient Python caches and any *.patched trees.
clean:
	rm -rf $$(find . -type d -name "__pycache__")
	rm -rf .pytest_cache .ruff_cache .mypy_cache
	rm -rf $$(find . -type d -name "*.patched")
