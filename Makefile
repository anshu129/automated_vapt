.PHONY: dev install test lint typecheck migrate upgrade downgrade docker-up docker-down

install:
	pip install -e ".[dev]"

dev:
	uvicorn vapt_platform.main:app --reload --host 0.0.0.0 --port 8000

test:
	pytest tests/ -v --tb=short

lint:
	ruff check src tests
	ruff format --check src tests

format:
	ruff format src tests
	ruff check --fix src tests

typecheck:
	mypy src/vapt_platform

migrate:
	alembic revision --autogenerate -m "$(msg)"

upgrade:
	alembic upgrade head

downgrade:
	alembic downgrade -1

docker-up:
	docker compose up -d

docker-down:
	docker compose down

seed:
	python -m vapt_platform.scripts.seed
