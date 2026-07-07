"""Web UI support routes: background scan launch, job status, AI validation."""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from vapt_platform.api.deps import get_session
from vapt_platform.db.tables.models import CapabilityProvider, Observation, Project, Scan
from vapt_platform.services import scan_jobs
from vapt_platform.services.ai_validation import AIValidationService
from vapt_platform.services.mcp_validation import McpValidationService
from vapt_platform.tools.manifest import load_tool_manifests, resolve_tool_binary
from vapt_platform.validators.registry import build_validation_connectors

router = APIRouter(tags=["ui"])


class ScanLaunch(BaseModel):
    host: str = Field(min_length=1, description="Host, domain, IP, or URL to assess")
    name: str | None = None
    run_ai: bool = True
    run_mcp: bool = True
    run_mcp_active: bool = False
    time_budget_minutes: int = Field(default=30, ge=1, le=240)
    username: str | None = None
    password: str | None = None


class ToolToggle(BaseModel):
    tool: str
    enabled: bool


class McpValidateRequest(BaseModel):
    active_allowed: bool = False
    username: str | None = None
    password: str | None = None


class FullValidateRequest(BaseModel):
    active_allowed: bool = False
    username: str | None = None
    password: str | None = None


@router.post("/ui/scans")
async def launch_ui_scan(body: ScanLaunch) -> dict[str, Any]:
    return await scan_jobs.create_and_launch(
        body.host,
        name=body.name,
        run_ai=body.run_ai,
        run_mcp=body.run_mcp,
        run_mcp_active=body.run_mcp_active,
        time_budget_minutes=body.time_budget_minutes,
        username=body.username,
        password=body.password,
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


@router.get("/ui/tools")
async def list_ui_tools(session: AsyncSession = Depends(get_session)) -> dict[str, Any]:
    """List tools grouped by capability group with availability and enabled state."""
    providers = list((await session.execute(select(CapabilityProvider))).scalars().all())
    enabled_by_tool: dict[str, bool] = {}
    for provider in providers:
        # A tool is considered enabled if any of its capability providers is enabled.
        enabled_by_tool[provider.provider_name] = (
            enabled_by_tool.get(provider.provider_name, False) or provider.enabled
        )
    manifests = load_tool_manifests()
    groups: dict[str, list[dict[str, Any]]] = {}
    for name, spec in sorted(manifests.items()):
        if name not in enabled_by_tool:
            continue
        available = resolve_tool_binary(spec.binary) is not None
        groups.setdefault(spec.capability_group, []).append(
            {
                "tool": name,
                "binary": spec.binary,
                "capability_group": spec.capability_group,
                "capabilities": spec.capabilities,
                "safety_class": spec.safety_class,
                "cost_tier": spec.cost_tier,
                "available": available,
                "enabled": enabled_by_tool[name],
                "requires_api_key": spec.requires_api_key,
            }
        )
    return {
        "groups": [
            {"capability_group": group, "tools": tools}
            for group, tools in sorted(groups.items())
        ],
        "total": sum(len(tools) for tools in groups.values()),
    }


@router.post("/ui/tools/toggle")
async def toggle_ui_tool(
    body: ToolToggle, session: AsyncSession = Depends(get_session)
) -> dict[str, Any]:
    providers = list(
        (
            await session.execute(
                select(CapabilityProvider).where(
                    CapabilityProvider.provider_name == body.tool
                )
            )
        )
        .scalars()
        .all()
    )
    if not providers:
        raise HTTPException(404, f"No providers found for tool: {body.tool}")
    for provider in providers:
        provider.enabled = body.enabled
    await session.commit()
    return {"tool": body.tool, "enabled": body.enabled, "providers_updated": len(providers)}


@router.post("/scans/{scan_id}/ai-validate")
async def run_ai_validation(
    scan_id: uuid.UUID, session: AsyncSession = Depends(get_session)
) -> dict[str, Any]:
    summary = await AIValidationService(session).run(scan_id)
    await session.commit()
    return summary.as_dict()


@router.get("/ui/validation-connectors")
async def list_validation_connectors() -> dict[str, Any]:
    """List configured validation connectors and whether each is reachable."""
    items = []
    for connector in build_validation_connectors():
        items.append(
            {
                "name": connector.name,
                "safety_class": connector.safety_class,
                "active": getattr(connector, "active", False),
                "available": connector.is_available(),
            }
        )
    return {"items": items, "total": len(items)}


@router.post("/scans/{scan_id}/mcp-validate")
async def run_mcp_validation(
    scan_id: uuid.UUID,
    body: McpValidateRequest | None = None,
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    active_allowed = bool(body.active_allowed) if body else False
    username = body.username if body else None
    password = body.password if body else None
    summary = await McpValidationService(session).validate_scan(
        scan_id,
        active_allowed=active_allowed,
        username=username,
        password=password,
    )
    await session.commit()
    return summary.to_dict()


@router.post("/scans/{scan_id}/full-validate")
async def run_full_validation(
    scan_id: uuid.UUID,
    body: FullValidateRequest | None = None,
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    """Run AI advisory + assignment, then all available tool validators (nuclei, Burp, sqlmap)."""
    active_allowed = bool(body.active_allowed) if body else False
    username = body.username if body else None
    password = body.password if body else None
    ai_summary = await AIValidationService(session).run(scan_id)
    mcp_summary = await McpValidationService(session).validate_scan(
        scan_id,
        active_allowed=active_allowed,
        username=username,
        password=password,
    )
    await session.commit()
    return {
        "scan_id": str(scan_id),
        "ai": ai_summary.as_dict(),
        "mcp": mcp_summary.to_dict(),
        "note": (
            "Full validation complete: AI advisory + all configured tool connectors. "
            "Nothing is auto-confirmed — review validation tasks and generate a report."
        ),
    }


@router.post("/hypotheses/{hypothesis_id}/mcp-validate")
async def run_mcp_validation_for_hypothesis(
    hypothesis_id: uuid.UUID,
    body: McpValidateRequest | None = None,
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    active_allowed = bool(body.active_allowed) if body else False
    username = body.username if body else None
    password = body.password if body else None
    try:
        summary = await McpValidationService(session).validate_hypothesis(
            hypothesis_id,
            active_allowed=active_allowed,
            username=username,
            password=password,
        )
    except ValueError as exc:
        raise HTTPException(404, str(exc)) from exc
    await session.commit()
    return summary.to_dict()


@router.get("/scans/{scan_id}/mcp-validation")
async def get_mcp_validation(
    scan_id: uuid.UUID, session: AsyncSession = Depends(get_session)
) -> dict[str, Any]:
    observations = list(
        (
            await session.execute(
                select(Observation)
                .where(
                    Observation.scan_id == scan_id,
                    Observation.observation_type.in_(
                        ["MCP_VALIDATION_RUN", "MCP_VALIDATION_FINDING"]
                    ),
                )
                .order_by(Observation.first_seen.desc())
            )
        )
        .scalars()
        .all()
    )
    runs = [
        {
            "id": str(o.id),
            "connector": o.source_id,
            "asset_id": str(o.subject_asset_id) if o.subject_asset_id else None,
            "confidence": o.confidence,
            **(o.payload or {}),
        }
        for o in observations
        if o.observation_type == "MCP_VALIDATION_RUN"
    ]
    findings = [
        {
            "id": str(o.id),
            "connector": o.source_id,
            "asset_id": str(o.subject_asset_id) if o.subject_asset_id else None,
            **(o.payload or {}),
        }
        for o in observations
        if o.observation_type == "MCP_VALIDATION_FINDING"
    ]
    return {"runs": runs, "findings": findings, "total_runs": len(runs)}
