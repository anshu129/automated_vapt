"""Test fixtures."""

import uuid

import pytest
import pytest_asyncio

from vapt_platform.db.session import init_db, reset_engine, session_scope


@pytest.fixture(autouse=True)
def _reset_engine() -> None:
    reset_engine()
    yield
    reset_engine()


@pytest_asyncio.fixture
async def db_session():
    await init_db("sqlite+aiosqlite:///:memory:")
    async with session_scope() as session:
        from vapt_platform.scripts.seed import seed_data

        await seed_data(session)
        await session.commit()
        yield session


@pytest.fixture
def correlation_id() -> uuid.UUID:
    return uuid.uuid4()
