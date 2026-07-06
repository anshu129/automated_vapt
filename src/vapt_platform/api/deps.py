"""FastAPI dependencies."""

import uuid
from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession

from vapt_platform.db.session import get_db_session

__all__ = ["get_session", "get_correlation_id"]


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    async for session in get_db_session():
        yield session


def get_correlation_id() -> uuid.UUID:
    return uuid.uuid4()
