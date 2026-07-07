"""Health endpoints."""

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from vapt_platform.api.deps import get_session
from vapt_platform.config.settings import get_settings
from vapt_platform.services.schema_compatibility_detector import SchemaCompatibilityDetector

router = APIRouter(tags=["health"])


@router.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/ready")
async def ready(session: AsyncSession = Depends(get_session)) -> dict[str, str]:
    await session.execute(text("SELECT 1"))
    return {"status": "ready"}


@router.get("/diagnostics/schema")
async def schema_diagnostics(session: AsyncSession = Depends(get_session)) -> dict:
    settings = get_settings()
    connection = await session.connection()
    report = await connection.run_sync(
        lambda sync_conn: SchemaCompatibilityDetector().inspect(sync_conn)
    )
    return {
        "phase8_sqlite_migration_hardening_enabled": settings.phase8_sqlite_migration_hardening_enabled,
        "phase9_sqlite_migration_command_enabled": settings.phase9_sqlite_migration_command_enabled,
        "artifact_backend": settings.report_artifact_backend,
        "phase9_artifact_backend_enabled": settings.phase9_artifact_backend_enabled,
        "phase9_staleness_polling_enabled": settings.phase9_staleness_polling_enabled,
        "phase9_plan_splitting_enabled": settings.phase9_plan_splitting_enabled,
        "phase9_integrity_audit_enabled": settings.phase9_integrity_audit_enabled,
        "schema": report.to_dict(),
    }
