"""Smoke test: migrations create all expected tables in a dedicated test database."""

import pytest
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import OperationalError

from alembic import command
from cybersage.config import get_settings
from cybersage.store.models import Base

TEST_DB = "cybersage_test"


@pytest.fixture(scope="module")
def test_db_url(monkeypatch_module) -> str:
    admin_url = make_url(get_settings().database_url).set(database="postgres")
    try:
        admin = create_engine(admin_url, isolation_level="AUTOCOMMIT")
        with admin.connect() as conn:
            exists = conn.execute(
                text("SELECT 1 FROM pg_database WHERE datname = :n"), {"n": TEST_DB}
            ).scalar()
            if not exists:
                conn.execute(text(f'CREATE DATABASE "{TEST_DB}"'))
        admin.dispose()
    except OperationalError as exc:
        pytest.skip(
            f"Postgres unreachable ({admin_url.render_as_string(False)}); run `make up`: {exc}"
        )
    url = admin_url.set(database=TEST_DB).render_as_string(hide_password=False)
    monkeypatch_module.setenv("DATABASE_URL", url)
    get_settings.cache_clear()
    yield url
    get_settings.cache_clear()


@pytest.fixture(scope="module")
def monkeypatch_module():
    with pytest.MonkeyPatch.context() as mp:
        yield mp


def test_migrations_create_all_tables(test_db_url: str) -> None:
    engine = create_engine(test_db_url)
    with engine.begin() as conn:
        conn.execute(text("DROP SCHEMA public CASCADE; CREATE SCHEMA public"))

    command.upgrade(Config("alembic.ini"), "head")

    inspector = inspect(engine)
    assert set(Base.metadata.tables) <= set(inspector.get_table_names())
    with engine.connect() as conn:
        assert conn.execute(text("SELECT 1 FROM pg_extension WHERE extname='vector'")).scalar()
    engine.dispose()
