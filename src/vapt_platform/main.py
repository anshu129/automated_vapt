"""FastAPI application."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from vapt_platform.api.routes import core, health, ui
from vapt_platform.config.settings import get_settings
from vapt_platform.logging.setup import setup_logging

_WEB_DIR = Path(__file__).parent / "web"


async def _startup_seed() -> None:
    """Initialise and seed the database when SEED_ON_STARTUP is enabled."""
    from sqlalchemy import select

    from vapt_platform.db.session import init_db, session_scope
    from vapt_platform.db.tables.models import CapabilityProvider
    from vapt_platform.scripts.seed import seed_data

    settings = get_settings()
    await init_db()
    async with session_scope() as session:
        await seed_data(session)
        if not settings.use_fake_fallback:
            providers = (await session.execute(select(CapabilityProvider))).scalars().all()
            for provider in providers:
                if provider.provider_name.startswith("fake-") or provider.provider_name in {
                    "puredns",
                    "massdns",
                }:
                    provider.enabled = False


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    setup_logging(settings.log_level)
    if settings.seed_on_startup:
        await _startup_seed()
    yield


def create_app() -> FastAPI:
    app = FastAPI(
        title="VAPT Platform",
        description="Authorized vulnerability assessment correlation platform",
        version="0.1.0",
        lifespan=lifespan,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.middleware("http")
    async def correlation_middleware(request: Request, call_next):  # type: ignore[no-untyped-def]
        response = await call_next(request)
        return response

    app.include_router(health.router)
    app.include_router(core.router, prefix="/api/v1")
    app.include_router(ui.router, prefix="/api/v1")
    if _WEB_DIR.is_dir():
        app.mount("/", StaticFiles(directory=str(_WEB_DIR), html=True), name="web")
    return app


app = create_app()
