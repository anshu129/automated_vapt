"""Project and scan API routes."""

import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from vapt_platform.api.deps import get_session
from vapt_platform.capabilities.registry import CapabilityRegistry
from vapt_platform.db.tables.models import (
    AssessmentCompletionRecord,
    Asset,
    AssetTestMatrix,
    AssetVulnerabilityApplicability,
    CapabilityProvider,
    Event,
    Hypothesis,
    RawArtifact,
    SurfaceCoverageRecord,
    Task,
    TaskRun,
    TestPlan,
    TestRequirement,
    ValidationTask,
    VulnerabilityClass,
)
from vapt_platform.domain.enums import CompletionStatus, TestRequirementCoverageStatus
from vapt_platform.domain.exceptions import EntityNotFoundError
from vapt_platform.engines.assessment import AssessmentCompletionEvaluator
from vapt_platform.engines.surface_completeness import SurfaceCompletenessEngine
from vapt_platform.engines.vulnerability_applicability import VulnerabilityApplicabilityEngine
from vapt_platform.parameters.references import (
    flatten_parameters,
    load_parameter_references,
    parameter_count,
    reference_for_tool,
)
from vapt_platform.planning.discovery_gain import MarginalDiscoveryGainEngine
from vapt_platform.services.core import ProjectService, ScanService, ValidationService
from vapt_platform.tools.manifest import load_tool_manifests, resolve_tool_binary

router = APIRouter(tags=["core"])


class ProjectCreate(BaseModel):
    name: str
    description: str | None = None


class ScopeRuleInput(BaseModel):
    rule_type: str
    pattern: str
    assessment_mode: str = "ACTIVE"
    priority: int = 10


class ScanCreate(BaseModel):
    name: str
    scope_rules: list[ScopeRuleInput] = Field(default_factory=list)


class ValidationResultInput(BaseModel):
    outcome: str
    analyst_notes: str = ""
    evidence_ids: list[str] = Field(default_factory=list)
    recorded_by: str = "analyst"


class AcceptGapsInput(BaseModel):
    asset_id: str
    dimensions: list[str] = Field(default_factory=list)
    accepted_by: str = "analyst"
    reason: str = ""


@router.post("/projects")
async def create_project(
    body: ProjectCreate, session: AsyncSession = Depends(get_session)
) -> dict[str, Any]:
    svc = ProjectService(session)
    project = await svc.create(body.name, body.description)
    await session.commit()
    return {"id": str(project.id), "name": project.name}


@router.get("/projects/{project_id}")
async def get_project(
    project_id: uuid.UUID, session: AsyncSession = Depends(get_session)
) -> dict[str, Any]:
    try:
        project = await ProjectService(session).get(project_id)
    except EntityNotFoundError as e:
        raise HTTPException(404, str(e)) from e
    return {"id": str(project.id), "name": project.name, "description": project.description}


@router.post("/scans")
async def create_scan(
    body: ScanCreate,
    project_id: uuid.UUID = Query(...),
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    svc = ScanService(session)
    scan = await svc.create(
        project_id,
        body.name,
        [r.model_dump() for r in body.scope_rules],
    )
    await session.commit()
    return {"id": str(scan.id), "status": scan.status, "name": scan.name}


@router.get("/scans/{scan_id}")
async def get_scan(
    scan_id: uuid.UUID, session: AsyncSession = Depends(get_session)
) -> dict[str, Any]:
    try:
        scan = await ScanService(session).get(scan_id)
    except EntityNotFoundError as e:
        raise HTTPException(404, str(e)) from e
    return {
        "id": str(scan.id),
        "status": scan.status,
        "name": scan.name,
        "started_at": scan.started_at.isoformat() if scan.started_at else None,
    }


@router.post("/scans/{scan_id}/start")
async def start_scan(
    scan_id: uuid.UUID, session: AsyncSession = Depends(get_session)
) -> dict[str, Any]:
    scan = await ScanService(session).start(scan_id)
    await session.commit()
    return {"id": str(scan.id), "status": scan.status}


@router.post("/scans/{scan_id}/run-ready")
async def run_ready_scan_tasks(
    scan_id: uuid.UUID,
    limit: int = Query(1, ge=0, le=1000),
    target: str | None = Query(None),
    tool: str | None = Query(None),
    username: str | None = Query(None),
    password: str | None = Query(None),
    timeout_seconds: int | None = Query(None, alias="timeout", ge=0),
    verbose: bool = Query(False),
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    result = await ScanService(session).run_ready_tasks(
        scan_id,
        limit=limit,
        target_filter=target,
        provider_filter=tool,
        username=username,
        password=password,
        timeout_seconds=timeout_seconds,
        verbose=verbose,
    )
    await session.commit()
    return result


@router.post("/scans/{scan_id}/run-tools")
async def run_scan_tools(
    scan_id: uuid.UUID,
    tools: str = Query(..., description="Comma-separated tool names, or all"),
    target: str = Query(..., description="URL, hostname, or IP to run tools against"),
    username: str | None = Query(None),
    password: str | None = Query(None),
    timeout_seconds: int | None = Query(None, alias="timeout", ge=0),
    verbose: bool = Query(False),
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    try:
        result = await ScanService(session).run_tools(
            scan_id,
            [item.strip() for item in tools.split(",") if item.strip()],
            target,
            username=username,
            password=password,
            timeout_seconds=timeout_seconds,
            verbose=verbose,
        )
    except EntityNotFoundError as e:
        raise HTTPException(404, str(e)) from e
    await session.commit()
    return result


@router.post("/scans/{scan_id}/pause")
async def pause_scan(
    scan_id: uuid.UUID, session: AsyncSession = Depends(get_session)
) -> dict[str, str]:
    scan = await ScanService(session).pause(scan_id)
    await session.commit()
    return {"id": str(scan.id), "status": scan.status}


@router.post("/scans/{scan_id}/resume")
async def resume_scan(
    scan_id: uuid.UUID, session: AsyncSession = Depends(get_session)
) -> dict[str, str]:
    scan = await ScanService(session).resume(scan_id)
    await session.commit()
    return {"id": str(scan.id), "status": scan.status}


@router.post("/scans/{scan_id}/cancel")
async def cancel_scan(
    scan_id: uuid.UUID, session: AsyncSession = Depends(get_session)
) -> dict[str, str]:
    scan = await ScanService(session).cancel(scan_id)
    await session.commit()
    return {"id": str(scan.id), "status": scan.status}


@router.get("/scans/{scan_id}/assets")
async def list_assets(
    scan_id: uuid.UUID, session: AsyncSession = Depends(get_session)
) -> dict[str, Any]:
    stmt = select(Asset).where(Asset.scan_id == scan_id)
    assets = list((await session.execute(stmt)).scalars().all())
    return {
        "items": [
            {
                "id": str(a.id),
                "asset_type": a.asset_type,
                "display_name": a.display_name,
                "normalized_key": a.normalized_key,
                "confidence": a.confidence,
            }
            for a in assets
        ],
        "total": len(assets),
    }


@router.get("/scans/{scan_id}/events")
async def list_events(
    scan_id: uuid.UUID, session: AsyncSession = Depends(get_session)
) -> dict[str, Any]:
    stmt = select(Event).where(Event.scan_id == scan_id).order_by(Event.sequence_number)
    events = list((await session.execute(stmt)).scalars().all())
    return {
        "items": [
            {"id": str(e.id), "event_type": e.event_type, "sequence_number": e.sequence_number}
            for e in events
        ],
        "total": len(events),
    }


@router.get("/scans/{scan_id}/tasks")
async def list_tasks(
    scan_id: uuid.UUID, session: AsyncSession = Depends(get_session)
) -> dict[str, Any]:
    stmt = select(Task).where(Task.scan_id == scan_id)
    tasks = list((await session.execute(stmt)).scalars().all())
    return {
        "items": [
            {
                "id": str(t.id),
                "capability": t.capability,
                "status": t.status,
                "normalized_target": t.normalized_target,
                "parameter_decision": (t.parameters or {}).get("parameter_decision"),
            }
            for t in tasks
        ],
        "total": len(tasks),
    }


@router.get("/tasks/{task_id}/parameter-decision")
async def task_parameter_decision(
    task_id: uuid.UUID, session: AsyncSession = Depends(get_session)
) -> dict[str, Any]:
    task = await session.get(Task, task_id)
    if not task:
        raise HTTPException(404, "Task not found")
    decision = (task.parameters or {}).get("parameter_decision")
    if not decision:
        return {
            "task_id": str(task.id),
            "capability": task.capability,
            "parameter_decision": None,
            "message": "No parameter decision recorded (fake adapter or pre-execution task)",
        }
    return {
        "task_id": str(task.id),
        "capability": task.capability,
        "normalized_target": task.normalized_target,
        "parameter_decision": decision,
    }


@router.get("/capabilities")
async def list_capabilities(session: AsyncSession = Depends(get_session)) -> dict[str, Any]:
    registry = CapabilityRegistry(session)
    providers = await registry.list_providers()
    return {
        "providers": [
            {
                "id": p.id,
                "capability": p.capability_code,
                "provider_name": p.provider_name,
                "cost_tier": p.cost_tier,
                "binary": p.binary_name,
                "binary_available": p.binary_available,
            }
            for p in providers
        ]
    }


@router.get("/tools/readiness")
async def tool_readiness() -> dict[str, Any]:
    manifests = load_tool_manifests()
    items = []
    for name, spec in sorted(manifests.items()):
        source = resolve_tool_binary(spec.binary)
        items.append(
            {
                "tool": name,
                "binary": spec.binary,
                "available": source is not None,
                "source": source,
                "enabled": spec.enabled,
                "capabilities": spec.capabilities,
                "safety_class": spec.safety_class,
                "cost_tier": spec.cost_tier,
            }
        )
    return {
        "items": items,
        "available": sum(1 for item in items if item["available"]),
        "total": len(items),
    }


@router.get("/tools/parameter-references")
async def list_tool_parameter_references() -> dict[str, Any]:
    refs = load_parameter_references()
    return {
        "items": [
            {
                "tool": name,
                "category": spec.get("_category"),
                "summary": spec.get("summary"),
                "official_docs": spec.get("official_docs", []),
                "parameter_count": spec.get("_parameter_count") or parameter_count(spec),
                "has_full_catalog": bool(spec.get("parameter_groups")),
            }
            for name, spec in sorted(refs.items())
        ],
        "total": len(refs),
    }


@router.get("/tools/{tool_name}/parameter-reference")
async def get_tool_parameter_reference(tool_name: str) -> dict[str, Any]:
    spec = reference_for_tool(tool_name)
    if not spec:
        raise HTTPException(404, f"No parameter reference for tool: {tool_name}")
    return {
        "tool": tool_name,
        "category": spec.get("_category"),
        "tool_version": spec.get("tool_version"),
        "usage": spec.get("usage"),
        "summary": spec.get("summary"),
        "official_docs": spec.get("official_docs", []),
        "examples": spec.get("examples", []),
        "platform_manifest_base_args": spec.get("platform_manifest_base_args"),
        "parameter_groups": spec.get("parameter_groups"),
        "parameters": spec.get("parameters") or flatten_parameters(spec),
        "parameter_count": spec.get("_parameter_count") or parameter_count(spec),
    }


@router.get("/scans/{scan_id}/report")
async def scan_report(
    scan_id: uuid.UUID, session: AsyncSession = Depends(get_session)
) -> dict[str, Any]:
    assets = list((await session.execute(select(Asset).where(Asset.scan_id == scan_id))).scalars().all())
    tasks = list((await session.execute(select(Task).where(Task.scan_id == scan_id))).scalars().all())
    events = list((await session.execute(select(Event).where(Event.scan_id == scan_id))).scalars().all())
    surfaces = list(
        (
            await session.execute(
                select(SurfaceCoverageRecord).where(SurfaceCoverageRecord.scan_id == scan_id)
            )
        )
        .scalars()
        .all()
    )
    applicability = list(
        (
            await session.execute(
                select(AssetVulnerabilityApplicability).where(
                    AssetVulnerabilityApplicability.scan_id == scan_id
                )
            )
        )
        .scalars()
        .all()
    )
    matrices = list(
        (
            await session.execute(select(AssetTestMatrix).where(AssetTestMatrix.scan_id == scan_id))
        )
        .scalars()
        .all()
    )
    completion = await AssessmentCompletionEvaluator(session).evaluate(scan_id)
    await session.flush()

    class_map = {
        vc.id: vc.class_code
        for vc in (await session.execute(select(VulnerabilityClass))).scalars().all()
    }
    surface_by_asset = {str(row.asset_id): row for row in surfaces}
    applicable_rows = [
        row
        for row in applicability
        if row.applicability_state in {"APPLICABLE", "POSSIBLY_APPLICABLE"}
    ]
    task_counts: dict[str, int] = {}
    for task in tasks:
        task_counts[task.status] = task_counts.get(task.status, 0) + 1

    provider_ids = {task.capability_provider_id for task in tasks if task.capability_provider_id}
    providers = {}
    if provider_ids:
        provider_rows = list(
            (
                await session.execute(
                    select(CapabilityProvider).where(CapabilityProvider.id.in_(provider_ids))
                )
            )
            .scalars()
            .all()
        )
        providers = {provider.id: provider for provider in provider_rows}

    task_ids = [task.id for task in tasks]
    task_runs = []
    artifact_by_run: dict[str, list[RawArtifact]] = {}
    if task_ids:
        task_runs = list(
            (
                await session.execute(select(TaskRun).where(TaskRun.task_id.in_(task_ids)))
            )
            .scalars()
            .all()
        )
        run_ids = [run.id for run in task_runs]
        if run_ids:
            artifacts = list(
                (
                    await session.execute(
                        select(RawArtifact).where(RawArtifact.task_run_id.in_(run_ids))
                    )
                )
                .scalars()
                .all()
            )
            for artifact in artifacts:
                artifact_by_run.setdefault(str(artifact.task_run_id), []).append(artifact)
    runs_by_task: dict[str, list[TaskRun]] = {}
    for run in task_runs:
        runs_by_task.setdefault(str(run.task_id), []).append(run)

    def last_run_for(task: Task) -> TaskRun | None:
        runs = runs_by_task.get(str(task.id), [])
        return runs[-1] if runs else None

    def last_artifact_for(task: Task) -> RawArtifact | None:
        run = last_run_for(task)
        if not run:
            return None
        artifacts = artifact_by_run.get(str(run.id), [])
        return artifacts[-1] if artifacts else None

    matrix_summaries = []
    for matrix in matrices:
        reqs = list(
            (
                await session.execute(
                    select(TestRequirement).where(TestRequirement.matrix_id == matrix.id)
                )
            )
            .scalars()
            .all()
        )
        matrix_summaries.append(
            {
                "asset_id": str(matrix.asset_id),
                "requirements": [
                    {
                        "class_code": class_map.get(req.vulnerability_class_id),
                        "coverage_status": req.coverage_status,
                        "testing_mode": req.testing_mode,
                        "next_action": req.next_action,
                    }
                    for req in reqs
                    if req.applicability_state in {"APPLICABLE", "POSSIBLY_APPLICABLE"}
                ],
            }
        )

    return {
        "scan_id": str(scan_id),
        "summary": {
            "assets": len(assets),
            "tasks": len(tasks),
            "events": len(events),
            "applicable_requirements": len(applicable_rows),
            "completion_status": completion.status,
            "task_status_counts": task_counts,
        },
        "assets": [
            {
                "id": str(asset.id),
                "type": asset.asset_type,
                "name": asset.display_name,
                "key": asset.normalized_key,
                "surface_status": (
                    surface_by_asset[str(asset.id)].overall_status
                    if str(asset.id) in surface_by_asset
                    else None
                ),
            }
            for asset in assets
        ],
        "tasks": [
            {
                "id": str(task.id),
                "capability": task.capability,
                "status": task.status,
                "target": task.normalized_target,
                "provider": (
                    providers[task.capability_provider_id].provider_name
                    if task.capability_provider_id in providers
                    else None
                ),
                "execution_profile": task.execution_profile_id,
                "used_fake_fallback": any(
                    (artifact.metadata_ or {}).get("fallback") == "fake"
                    for run in runs_by_task.get(str(task.id), [])
                    for artifact in artifact_by_run.get(str(run.id), [])
                ),
                "last_exit_code": (
                    last_run_for(task).exit_code
                    if last_run_for(task)
                    else None
                ),
                "last_error_summary": (
                    last_run_for(task).error_summary
                    if last_run_for(task)
                    else None
                ),
                "stderr_preview": (
                    (last_artifact_for(task).metadata_ or {}).get("stderr_preview")
                    if last_artifact_for(task)
                    else None
                ),
                "stdout_preview": (
                    (last_artifact_for(task).content or "")[:1000]
                    if last_artifact_for(task)
                    else None
                ),
            }
            for task in tasks
        ],
        "applicability": [
            {
                "asset_id": str(row.asset_id),
                "class_code": class_map.get(row.vulnerability_class_id),
                "state": row.applicability_state,
                "confidence": row.confidence,
                "rule_ids": row.rule_ids,
            }
            for row in applicable_rows
        ],
        "test_matrix": matrix_summaries,
        "completion": {
            "status": completion.status,
            "blocking_items": completion.blocking_items,
            "metrics": completion.metrics,
        },
    }


@router.get("/scans/{scan_id}/discovery-gain")
async def discovery_gain(
    scan_id: uuid.UUID, session: AsyncSession = Depends(get_session)
) -> dict[str, Any]:
    metrics = await MarginalDiscoveryGainEngine(session).get_metrics(str(scan_id))
    return {
        "items": [
            {
                "capability": m.capability_code,
                "provider_id": str(m.provider_id) if m.provider_id else None,
                "unique_assets": m.unique_asset_count,
                "raw_observations": m.raw_observation_count,
                "historical_unique_gain": m.historical_unique_gain,
            }
            for m in metrics
        ]
    }


@router.get("/scans/{scan_id}/surface-coverage")
async def scan_surface_coverage(
    scan_id: uuid.UUID,
    asset_type: str | None = Query(None),
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    engine = SurfaceCompletenessEngine(session)
    completion = (
        await session.execute(
            select(AssessmentCompletionRecord).where(
                AssessmentCompletionRecord.scan_id == scan_id
            )
        )
    ).scalar_one_or_none()
    accepted = (completion.accepted_gaps if completion else None) or {}
    records = await engine.compute_scan_summary(scan_id, asset_type=asset_type)
    items: list[dict[str, Any]] = []
    for record in records:
        requirements = await engine.missing_requirements(
            record.asset_id, scan_id, accepted_gaps=accepted
        )
        items.append(
            {
                "asset_id": str(record.asset_id),
                "asset_type": record.asset_type,
                "overall_status": record.overall_status,
                "gap_count": record.gap_count,
                "dimensions": record.dimensions,
                "blocking_gaps": [
                    {
                        "dimension": r.dimension,
                        "status": r.status,
                        "reason": r.reason,
                        "eligible_capabilities": r.eligible_capabilities,
                    }
                    for r in requirements
                    if r.blocking
                ],
                "gaps": engine.gaps_payload(record.asset_id, requirements)["gaps"],
            }
        )
    return {"items": items, "total": len(items)}


@router.post("/scans/{scan_id}/accepted-gaps")
async def accept_surface_gaps(
    scan_id: uuid.UUID,
    body: AcceptGapsInput,
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    stmt = select(AssessmentCompletionRecord).where(
        AssessmentCompletionRecord.scan_id == scan_id
    )
    record = (await session.execute(stmt)).scalar_one_or_none()
    if not record:
        record = AssessmentCompletionRecord(
            scan_id=scan_id, status=CompletionStatus.INCOMPLETE.value
        )
        session.add(record)
    accepted = dict(record.accepted_gaps or {})
    existing = set(accepted.get(body.asset_id, []))
    existing.update(body.dimensions)
    accepted[body.asset_id] = sorted(existing)
    record.accepted_gaps = accepted
    record.evaluated_by = body.accepted_by
    await session.flush()
    completion = await AssessmentCompletionEvaluator(session).evaluate(scan_id)
    await session.commit()
    return {
        "scan_id": str(scan_id),
        "asset_id": body.asset_id,
        "accepted_dimensions": accepted[body.asset_id],
        "completion_status": completion.status,
    }


@router.get("/assets/{asset_id}/surface-coverage")
async def asset_surface_coverage(
    asset_id: uuid.UUID, session: AsyncSession = Depends(get_session)
) -> dict[str, Any]:
    stmt = select(SurfaceCoverageRecord).where(SurfaceCoverageRecord.asset_id == asset_id)
    record = (await session.execute(stmt)).scalar_one_or_none()
    if not record:
        raise HTTPException(404, "Surface coverage not found")
    return {
        "asset_id": str(asset_id),
        "overall_status": record.overall_status,
        "dimensions": record.dimensions,
        "gap_count": record.gap_count,
    }


@router.get("/assets/{asset_id}/vulnerability-applicability")
async def asset_applicability(
    asset_id: uuid.UUID, session: AsyncSession = Depends(get_session)
) -> dict[str, Any]:
    asset = await session.get(Asset, asset_id)
    if not asset:
        raise HTTPException(404, "Asset not found")
    stmt = select(AssetVulnerabilityApplicability).where(
        AssetVulnerabilityApplicability.asset_id == asset_id
    )
    rows = list((await session.execute(stmt)).scalars().all())
    if not rows and asset.scan_id:
        engine = VulnerabilityApplicabilityEngine(session)
        rows = await engine.compute(asset.scan_id, asset_id)
        await session.flush()

    class_map = {
        vc.id: vc.class_code
        for vc in (
            await session.execute(select(VulnerabilityClass))
        ).scalars().all()
    }
    return {
        "asset_id": str(asset_id),
        "items": [
            {
                "vulnerability_class_id": str(r.vulnerability_class_id),
                "class_code": class_map.get(r.vulnerability_class_id),
                "state": r.applicability_state,
                "confidence": r.confidence,
                "rule_ids": r.rule_ids,
                "explanation": r.explanation,
                "supporting_evidence_ids": r.supporting_evidence_ids,
            }
            for r in rows
        ],
    }


@router.get("/scans/{scan_id}/vulnerability-applicability")
async def scan_vulnerability_applicability(
    scan_id: uuid.UUID,
    state: str | None = Query(None),
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    stmt = select(AssetVulnerabilityApplicability).where(
        AssetVulnerabilityApplicability.scan_id == scan_id
    )
    if state:
        stmt = stmt.where(AssetVulnerabilityApplicability.applicability_state == state)
    rows = list((await session.execute(stmt)).scalars().all())
    class_map = {
        vc.id: vc.class_code
        for vc in (await session.execute(select(VulnerabilityClass))).scalars().all()
    }
    return {
        "scan_id": str(scan_id),
        "items": [
            {
                "asset_id": str(r.asset_id),
                "vulnerability_class_id": str(r.vulnerability_class_id),
                "class_code": class_map.get(r.vulnerability_class_id),
                "state": r.applicability_state,
                "confidence": r.confidence,
                "rule_ids": r.rule_ids,
                "explanation": r.explanation,
            }
            for r in rows
        ],
        "total": len(rows),
    }


@router.get("/assets/{asset_id}/test-matrix")
async def asset_test_matrix(
    asset_id: uuid.UUID, session: AsyncSession = Depends(get_session)
) -> dict[str, Any]:
    stmt = select(AssetTestMatrix).where(AssetTestMatrix.asset_id == asset_id)
    matrix = (await session.execute(stmt)).scalar_one_or_none()
    if not matrix:
        raise HTTPException(404, "Test matrix not found")
    req_stmt = select(TestRequirement).where(TestRequirement.matrix_id == matrix.id)
    reqs = list((await session.execute(req_stmt)).scalars().all())
    class_map = {
        vc.id: vc.class_code
        for vc in (await session.execute(select(VulnerabilityClass))).scalars().all()
    }
    return {
        "matrix_id": str(matrix.id),
        "asset_id": str(matrix.asset_id),
        "rule_version": matrix.rule_version,
        "requirements": [
            {
                "id": str(r.id),
                "vulnerability_class_id": str(r.vulnerability_class_id),
                "class_code": class_map.get(r.vulnerability_class_id),
                "applicability_state": r.applicability_state,
                "coverage_status": r.coverage_status,
                "testing_mode": r.testing_mode,
                "next_action": r.next_action,
                "required_evidence": r.required_evidence,
                "eligible_capabilities": r.eligible_capabilities,
                "confidence": r.confidence,
            }
            for r in sorted(
                reqs,
                key=lambda row: class_map.get(row.vulnerability_class_id) or "",
            )
        ],
    }


@router.get("/scans/{scan_id}/test-matrix")
async def scan_test_matrix(
    scan_id: uuid.UUID, session: AsyncSession = Depends(get_session)
) -> dict[str, Any]:
    stmt = select(AssetTestMatrix).where(AssetTestMatrix.scan_id == scan_id)
    matrices = list((await session.execute(stmt)).scalars().all())
    uncovered_statuses = {
        TestRequirementCoverageStatus.NOT_TESTED.value,
        TestRequirementCoverageStatus.PARTIALLY_TESTED.value,
        TestRequirementCoverageStatus.INCONCLUSIVE.value,
    }
    items: list[dict[str, Any]] = []
    for matrix in matrices:
        reqs = list(
            (
                await session.execute(
                    select(TestRequirement).where(TestRequirement.matrix_id == matrix.id)
                )
            )
            .scalars()
            .all()
        )
        status_counts: dict[str, int] = {}
        for req in reqs:
            status_counts[req.coverage_status] = status_counts.get(req.coverage_status, 0) + 1
        items.append(
            {
                "asset_id": str(matrix.asset_id),
                "matrix_id": str(matrix.id),
                "requirements_count": len(reqs),
                "uncovered_count": sum(
                    1 for req in reqs if req.coverage_status in uncovered_statuses
                ),
                "status_counts": status_counts,
            }
        )
    return {"items": items, "total": len(items)}


@router.get("/scans/{scan_id}/test-plans")
async def list_test_plans(
    scan_id: uuid.UUID, session: AsyncSession = Depends(get_session)
) -> dict[str, Any]:
    stmt = select(TestPlan).where(TestPlan.scan_id == scan_id)
    plans = list((await session.execute(stmt)).scalars().all())
    return {
        "items": [
            {"id": str(p.id), "testing_mode": p.testing_mode, "status": p.status} for p in plans
        ]
    }


@router.get("/test-plans/{plan_id}")
async def get_test_plan(
    plan_id: uuid.UUID, session: AsyncSession = Depends(get_session)
) -> dict[str, Any]:
    plan = await session.get(TestPlan, plan_id)
    if not plan:
        raise HTTPException(404, "Test plan not found")
    return {
        "id": str(plan.id),
        "testing_mode": plan.testing_mode,
        "status": plan.status,
        "safety_class": plan.safety_class,
        "required_capabilities": plan.required_capabilities,
    }


@router.post("/test-plans/{plan_id}/approve")
async def approve_test_plan(
    plan_id: uuid.UUID, session: AsyncSession = Depends(get_session)
) -> dict[str, str]:
    plan = await session.get(TestPlan, plan_id)
    if not plan:
        raise HTTPException(404, "Test plan not found")
    plan.status = "APPROVED"
    await session.commit()
    return {"id": str(plan.id), "status": plan.status}


@router.post("/test-plans/{plan_id}/cancel")
async def cancel_test_plan(
    plan_id: uuid.UUID, session: AsyncSession = Depends(get_session)
) -> dict[str, str]:
    plan = await session.get(TestPlan, plan_id)
    if not plan:
        raise HTTPException(404, "Test plan not found")
    plan.status = "CANCELLED"
    await session.commit()
    return {"id": str(plan.id), "status": plan.status}


@router.get("/scans/{scan_id}/hypotheses")
async def list_hypotheses(
    scan_id: uuid.UUID, session: AsyncSession = Depends(get_session)
) -> dict[str, Any]:
    stmt = select(Hypothesis).where(Hypothesis.scan_id == scan_id)
    hyps = list((await session.execute(stmt)).scalars().all())
    return {
        "items": [
            {"id": str(h.id), "title": h.title, "status": h.status, "confidence": h.confidence}
            for h in hyps
        ]
    }


@router.get("/hypotheses/{hypothesis_id}")
async def get_hypothesis(
    hypothesis_id: uuid.UUID, session: AsyncSession = Depends(get_session)
) -> dict[str, Any]:
    hyp = await session.get(Hypothesis, hypothesis_id)
    if not hyp:
        raise HTTPException(404, "Hypothesis not found")
    return {
        "id": str(hyp.id),
        "title": hyp.title,
        "description": hyp.description,
        "status": hyp.status,
        "validation_requirements": hyp.validation_requirements,
    }


@router.get("/scans/{scan_id}/validation-backlog")
async def validation_backlog(
    scan_id: uuid.UUID, session: AsyncSession = Depends(get_session)
) -> dict[str, Any]:
    stmt = select(ValidationTask).where(ValidationTask.scan_id == scan_id)
    tasks = list((await session.execute(stmt)).scalars().all())
    return {
        "items": [
            {
                "id": str(t.id),
                "validation_goal": t.validation_goal,
                "status": t.status,
                "testing_mode": t.testing_mode,
            }
            for t in tasks
        ]
    }


@router.post("/validation-tasks/{task_id}/result")
async def record_validation(
    task_id: uuid.UUID,
    body: ValidationResultInput,
    session: AsyncSession = Depends(get_session),
) -> dict[str, str]:
    svc = ValidationService(session)
    result = await svc.record_result(
        task_id, body.outcome, body.analyst_notes, body.evidence_ids, body.recorded_by
    )
    await session.commit()
    return {"validation_result_id": str(result.id), "outcome": result.outcome}


@router.get("/scans/{scan_id}/completion-status")
async def completion_status(
    scan_id: uuid.UUID, session: AsyncSession = Depends(get_session)
) -> dict[str, Any]:
    record = await AssessmentCompletionEvaluator(session).evaluate(scan_id)
    await session.commit()
    return {
        "status": record.status,
        "blocking_items": record.blocking_items,
        "completion_reasons": record.completion_reasons,
        "accepted_gaps": record.accepted_gaps,
        "metrics": record.metrics,
    }
