.PHONY: up down migrate test lint

up:
	docker compose up -d --wait

down:
	docker compose down

migrate:
	uv run alembic upgrade head

test:
	uv run pytest

lint:
	uv run ruff check .
	uv run ruff format --check .
