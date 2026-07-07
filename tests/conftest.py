"""Test fixtures."""

import uuid

import pytest
import pytest_asyncio
from sqlalchemy import select

from vapt_platform.config.settings import get_settings
from vapt_platform.db.session import init_db, reset_engine, session_scope
from vapt_platform.db.tables.models import CapabilityProvider


@pytest.fixture(autouse=True)
def _reset_engine(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SCAN_START_INLINE_EXECUTION", "true")
    monkeypatch.setenv("SCAN_PIPELINE_MAX_ITERATIONS", "20")
    monkeypatch.setenv("SCAN_PIPELINE_MAX_TASKS", "50")
    get_settings.cache_clear()
    reset_engine()
    yield
    get_settings.cache_clear()
    reset_engine()


@pytest_asyncio.fixture
async def db_session():
    await init_db("sqlite+aiosqlite:///:memory:")
    async with session_scope() as session:
        from vapt_platform.scripts.seed import seed_data

        await seed_data(session)
        providers = (
            await session.execute(select(CapabilityProvider))
        ).scalars().all()
        for provider in providers:
            provider.enabled = provider.provider_name.startswith("fake-")
        await session.commit()
        yield session


@pytest.fixture
def correlation_id() -> uuid.UUID:
    return uuid.uuid4()
