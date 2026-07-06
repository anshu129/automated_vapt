"""FastAPI application."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

from vapt_platform.api.routes import core, health
from vapt_platform.config.settings import get_settings
from vapt_platform.logging.setup import setup_logging


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    setup_logging(get_settings().log_level)
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
    return app


app = create_app()
