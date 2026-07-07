"""Web UI support routes: background scan launch, job status, AI validation."""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from vapt_platform.api.deps import get_session
from vapt_platform.db.tables.models import Project, Scan
from vapt_platform.services import scan_jobs
from vapt_platform.services.ai_validation import AIValidationService

router = APIRouter(tags=["ui"])


class ScanLaunch(BaseModel):
    host: str = Field(min_length=1, description="Host, domain, IP, or URL to assess")
    name: str | None = None
    run_ai: bool = True
    time_budget_minutes: int = Field(default=30, ge=1, le=240)


@router.post("/ui/scans")
async def launch_ui_scan(body: ScanLaunch) -> dict[str, Any]:
    return await scan_jobs.create_and_launch(
        body.host,
        name=body.name,
        run_ai=body.run_ai,
        time_budget_minutes=body.time_budget_minutes,
    )


@router.get("/ui/jobs")
async def list_ui_jobs() -> dict[str, Any]:
    jobs = scan_jobs.list_jobs()
    return {"items": jobs, "total": len(jobs)}


@router.get("/ui/jobs/{job_id}")
async def get_ui_job(job_id: str) -> dict[str, Any]:
    job = scan_jobs.get_job(job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    return job


@router.get("/ui/scans")
async def list_ui_scans(session: AsyncSession = Depends(get_session)) -> dict[str, Any]:
    scans = list(
        (await session.execute(select(Scan).order_by(Scan.created_at.desc()))).scalars().all()
    )
    project_ids = {scan.project_id for scan in scans}
    projects: dict[uuid.UUID, Project] = {}
    if project_ids:
        rows = list(
            (await session.execute(select(Project).where(Project.id.in_(project_ids))))
            .scalars()
            .all()
        )
        projects = {project.id: project for project in rows}
    return {
        "items": [
            {
                "id": str(scan.id),
                "name": scan.name,
                "status": scan.status,
                "project_id": str(scan.project_id),
                "project_name": (
                    projects[scan.project_id].name if scan.project_id in projects else None
                ),
                "created_at": scan.created_at.isoformat() if scan.created_at else None,
                "started_at": scan.started_at.isoformat() if scan.started_at else None,
            }
            for scan in scans
        ],
        "total": len(scans),
    }


@router.post("/scans/{scan_id}/ai-validate")
async def run_ai_validation(
    scan_id: uuid.UUID, session: AsyncSession = Depends(get_session)
) -> dict[str, Any]:
    summary = await AIValidationService(session).run(scan_id)
    await session.commit()
    return summary.as_dict()
