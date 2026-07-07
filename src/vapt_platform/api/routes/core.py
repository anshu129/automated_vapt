"""Project and scan API routes."""

import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from vapt_platform.api.deps import get_session
from vapt_platform.capabilities.registry import CapabilityRegistry
from vapt_platform.db.tables.models import (
    AIEnrichment,
    AssessmentCompletionRecord,
    Asset,
    AssetTestMatrix,
    AssetVulnerabilityApplicability,
    CapabilityProvider,
    ConfirmedFinding,
    CredentialReference,
    Event,
    EvidenceLink,
    EvidencePackage,
    Hypothesis,
    RawArtifact,
    Relationship,
    SurfaceCoverageRecord,
    Task,
    TaskRun,
    TestExecution,
    TestPlan,
    TestRequirement,
    ValidationResult,
    ValidationTask,
    Verdict,
    VulnerabilityClass,
)
from vapt_platform.domain.enums import CompletionStatus, TestRequirementCoverageStatus
from vapt_platform.domain.exceptions import EntityNotFoundError
from vapt_platform.engines.assessment import AssessmentCompletionEvaluator, TestPlanner
from vapt_platform.engines.surface_completeness import SurfaceCompletenessEngine
from vapt_platform.engines.vulnerability_applicability import VulnerabilityApplicabilityEngine
from vapt_platform.enrichment.mistral import MistralEnrichmentService
from vapt_platform.config.settings import get_settings
from vapt_platform.services.completion_serialization import CompletionSerializationService
from vapt_platform.services.report_snapshot_service import ReportSnapshotService
from vapt_platform.services.report_staleness_polling_service import ReportStalenessPollingService
from vapt_platform.services.report_staleness_service import ReportStalenessService
from vapt_platform.services.schema_compatibility_detector import SchemaCompatibilityDetector
from vapt_platform.services.test_plan_uniqueness_policy import TestPlanUniquenessPolicy
from vapt_platform.parameters.references import (
    flatten_parameters,
    load_parameter_references,
    parameter_count,
    reference_for_tool,
)
from vapt_platform.planning.discovery_gain import MarginalDiscoveryGainEngine
from vapt_platform.services.automated_validation import AutomatedValidationOrchestrator
from vapt_platform.services.core import ProjectService, ScanService, ValidationService
from vapt_platform.services.credentials import (
    CredentialContextService,
    auth_context_metadata,
    binding_metadata,
    credential_metadata,
)
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


class CredentialReferenceInput(BaseModel):
    project_id: uuid.UUID
    credential_type: str
    secret_backend_reference: str
    label: str | None = None
    role_name: str | None = None
    expiry: datetime | None = None
    allowed_capabilities: list[str] = Field(default_factory=list)


class CredentialBindingInput(BaseModel):
    scope_rule_id: uuid.UUID | None = None
    asset_id: uuid.UUID | None = None
    application_id: uuid.UUID | None = None
    url_prefix: str | None = None
    assessment_mode: str = "CREDENTIALED"


class AuthenticationContextInput(BaseModel):
    asset_id: uuid.UUID
    scan_id: uuid.UUID | None = None
    session_established: bool = True
    session_expires_at: datetime | None = None
    coverage_dimensions: list[str] = Field(default_factory=lambda: ["AUTHENTICATED"])
    coverage_status: dict[str, str] = Field(default_factory=dict)


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


@router.post("/credentials")
async def create_credential_reference(
    body: CredentialReferenceInput,
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    service = CredentialContextService(session)
    try:
        credential = await service.create_reference(
            body.project_id,
            body.credential_type,
            body.secret_backend_reference,
            label=body.label,
            role_name=body.role_name,
            expiry=body.expiry,
            allowed_capabilities=body.allowed_capabilities,
        )
    except EntityNotFoundError as exc:
        raise HTTPException(404, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    await session.commit()
    return credential_metadata(credential)


@router.get("/projects/{project_id}/credentials")
async def list_project_credentials(
    project_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    credentials = await CredentialContextService(session).list_project_references(project_id)
    return {
        "items": [credential_metadata(credential) for credential in credentials],
        "total": len(credentials),
        "secret_values_excluded": True,
    }


@router.get("/credentials/{credential_id}")
async def get_credential_reference(
    credential_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    credential = await session.get(CredentialReference, credential_id)
    if not credential:
        raise HTTPException(404, "Credential reference not found")
    return credential_metadata(credential)


@router.post("/credentials/{credential_id}/bindings")
async def bind_credential_scope(
    credential_id: uuid.UUID,
    body: CredentialBindingInput,
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    service = CredentialContextService(session)
    try:
        binding = await service.create_binding(
            credential_id,
            scope_rule_id=body.scope_rule_id,
            asset_id=body.asset_id,
            application_id=body.application_id,
            url_prefix=body.url_prefix,
            assessment_mode=body.assessment_mode,
        )
    except EntityNotFoundError as exc:
        raise HTTPException(404, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    await session.commit()
    return binding_metadata(binding)


@router.post("/credentials/{credential_id}/auth-contexts")
async def establish_authentication_context(
    credential_id: uuid.UUID,
    body: AuthenticationContextInput,
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    service = CredentialContextService(session)
    try:
        context = await service.bind_session(
            credential_id,
            body.asset_id,
            scan_id=body.scan_id,
            session_established=body.session_established,
            session_expires_at=body.session_expires_at,
            coverage_dimensions=body.coverage_dimensions,
            coverage_status=body.coverage_status,
        )
    except EntityNotFoundError as exc:
        raise HTTPException(404, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    await session.commit()
    return auth_context_metadata(context)


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
    settings = get_settings()
    payload: dict[str, Any] = {
        "id": str(scan.id),
        "status": scan.status,
        "scan_status": scan.status,
        "name": scan.name,
        "started_at": scan.started_at.isoformat() if scan.started_at else None,
    }
    if settings.phase6_status_sync_enabled:
        completion_payload = await CompletionSerializationService(session).build_payload(scan_id)
        payload["job_status"] = completion_payload.get("job_status")
        payload["assessment_status"] = completion_payload.get("assessment_status")
        payload["assessment_completion"] = completion_payload
        payload["latest_transition"] = completion_payload.get("latest_transition")
    if settings.phase7_report_snapshots_enabled:
        latest = await ReportSnapshotService(session).latest_snapshot(scan_id)
        if latest:
            payload["latest_report_snapshot"] = latest.to_dict()
    return payload


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
                "metadata": a.metadata_,
                "first_seen": a.first_seen.isoformat() if a.first_seen else None,
                "last_seen": a.last_seen.isoformat() if a.last_seen else None,
            }
            for a in assets
        ],
        "total": len(assets),
    }


@router.get("/scans/{scan_id}/relationships")
async def list_relationships(
    scan_id: uuid.UUID, session: AsyncSession = Depends(get_session)
) -> dict[str, Any]:
    rels = list(
        (await session.execute(select(Relationship).where(Relationship.scan_id == scan_id)))
        .scalars()
        .all()
    )
    asset_ids = {rel.source_asset_id for rel in rels} | {rel.target_asset_id for rel in rels}
    assets = {}
    if asset_ids:
        rows = list(
            (await session.execute(select(Asset).where(Asset.id.in_(asset_ids)))).scalars().all()
        )
        assets = {asset.id: asset for asset in rows}
    return {
        "items": [
            {
                "id": str(rel.id),
                "relationship_type": rel.relationship_type,
                "source_asset_id": str(rel.source_asset_id),
                "target_asset_id": str(rel.target_asset_id),
                "source": _asset_ref(assets.get(rel.source_asset_id)),
                "target": _asset_ref(assets.get(rel.target_asset_id)),
                "confidence": rel.confidence,
                "active": rel.active,
                "evidence_ids": rel.evidence_ids,
            }
            for rel in rels
        ],
        "total": len(rels),
    }


@router.get("/scans/{scan_id}/events")
async def list_events(
    scan_id: uuid.UUID, session: AsyncSession = Depends(get_session)
) -> dict[str, Any]:
    stmt = select(Event).where(Event.scan_id == scan_id).order_by(Event.sequence_number)
    events = list((await session.execute(stmt)).scalars().all())
    return {
        "items": [
            {
                "id": str(e.id),
                "event_type": e.event_type,
                "sequence_number": e.sequence_number,
                "payload": e.payload,
                "correlation_id": str(e.correlation_id),
                "causation_id": str(e.causation_id) if e.causation_id else None,
            }
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
    scan_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    *,
    snapshot_id: uuid.UUID | None = Query(None),
    force_regenerate: bool = Query(False),
) -> dict[str, Any]:
    settings = get_settings()
    snapshot_svc = ReportSnapshotService(session)
    regenerate = force_regenerate if isinstance(force_regenerate, bool) else False

    if isinstance(snapshot_id, uuid.UUID):
        snap = await snapshot_svc.fetch_snapshot(snapshot_id)
        if not snap or snap.scan_id != scan_id:
            raise HTTPException(404, "Snapshot not found")
        try:
            report = await snapshot_svc.load_artifact(snap)
        except FileNotFoundError as exc:
            raise HTTPException(404, str(exc)) from exc
        report["report_delivery"] = {
            "source": "snapshot",
            "snapshot_id": str(snapshot_id),
            "replayable": True,
            "content_hash": snap.content_hash,
        }
        return report

    if (
        not regenerate
        and settings.phase8_report_artifact_storage_enabled
        and settings.phase8_report_staleness_detection_enabled
    ):
        latest_meta = await snapshot_svc.latest_snapshot(scan_id)
        if (
            latest_meta
            and latest_meta.replayable
            and latest_meta.freshness_status == "FRESH"
            and latest_meta.artifact_reference
        ):
            snap = await snapshot_svc.fetch_snapshot(uuid.UUID(latest_meta.id))
            if snap:
                try:
                    report = await snapshot_svc.load_artifact(snap)
                    report["report_delivery"] = {
                        "source": "snapshot",
                        "snapshot_id": latest_meta.id,
                        "replayable": True,
                        "content_hash": latest_meta.content_hash,
                    }
                    return report
                except FileNotFoundError:
                    pass

    assets = list(
        (await session.execute(select(Asset).where(Asset.scan_id == scan_id))).scalars().all()
    )
    tasks = list(
        (await session.execute(select(Task).where(Task.scan_id == scan_id))).scalars().all()
    )
    events = list(
        (await session.execute(select(Event).where(Event.scan_id == scan_id))).scalars().all()
    )
    relationships = list(
        (await session.execute(select(Relationship).where(Relationship.scan_id == scan_id)))
        .scalars()
        .all()
    )
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
        (await session.execute(select(AssetTestMatrix).where(AssetTestMatrix.scan_id == scan_id)))
        .scalars()
        .all()
    )
    plans = list(
        (await session.execute(select(TestPlan).where(TestPlan.scan_id == scan_id))).scalars().all()
    )
    plan_ids = [plan.id for plan in plans]
    test_executions = (
        list(
            (
                await session.execute(
                    select(TestExecution).where(TestExecution.test_plan_id.in_(plan_ids))
                )
            )
            .scalars()
            .all()
        )
        if plan_ids
        else []
    )
    validation_tasks = list(
        (await session.execute(select(ValidationTask).where(ValidationTask.scan_id == scan_id)))
        .scalars()
        .all()
    )
    validation_task_ids = [task.id for task in validation_tasks]
    validation_results = (
        list(
            (
                await session.execute(
                    select(ValidationResult).where(
                        ValidationResult.validation_task_id.in_(validation_task_ids)
                    )
                )
            )
            .scalars()
            .all()
        )
        if validation_task_ids
        else []
    )
    evidence_links = list(
        (await session.execute(select(EvidenceLink).where(EvidenceLink.scan_id == scan_id)))
        .scalars()
        .all()
    )
    hypotheses = list(
        (await session.execute(select(Hypothesis).where(Hypothesis.scan_id == scan_id)))
        .scalars()
        .all()
    )
    verdicts = list(
        (await session.execute(select(Verdict).where(Verdict.scan_id == scan_id))).scalars().all()
    )
    findings = list(
        (await session.execute(select(ConfirmedFinding).where(ConfirmedFinding.scan_id == scan_id)))
        .scalars()
        .all()
    )
    ai_enrichments = list(
        (await session.execute(select(AIEnrichment).where(AIEnrichment.scan_id == scan_id)))
        .scalars()
        .all()
    )
    completion = await AssessmentCompletionEvaluator(session).evaluate(scan_id)
    settings = get_settings()
    completion_sections: dict[str, Any] = {}
    if settings.phase6_report_completion_payload:
        completion_sections = await CompletionSerializationService(session).build_report_sections(
            scan_id
        )
    credential_service = CredentialContextService(session)
    auth_coverage = await credential_service.get_auth_coverage(scan_id)
    role_coverage = await credential_service.get_role_coverage(scan_id)
    await session.flush()

    asset_by_id = {asset.id: asset for asset in assets}
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
            (await session.execute(select(TaskRun).where(TaskRun.task_id.in_(task_ids))))
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
                        "id": str(req.id),
                        "class_code": class_map.get(req.vulnerability_class_id),
                        "coverage_status": req.coverage_status,
                        "testing_mode": req.testing_mode,
                        "next_action": req.next_action,
                        "scope_granularity": req.scope_granularity,
                        "is_legacy_merged": req.is_legacy_merged,
                        "parameter_scopes": (req.reasoning_trace or {}).get(
                            "parameter_scopes", []
                        ),
                        "scope_dimensions": req.scope_dimensions or {},
                    }
                    for req in reqs
                    if req.applicability_state in {"APPLICABLE", "POSSIBLY_APPLICABLE"}
                ],
            }
        )

    report_body = {
        "scan_id": str(scan_id),
        "summary": {
            "assets": len(assets),
            "tasks": len(tasks),
            "events": len(events),
            "relationships": len(relationships),
            "applicable_requirements": len(applicable_rows),
            "test_plans": len(plans),
            "test_executions": len(test_executions),
            "validation_backlog": len(validation_tasks),
            "validation_results": len(validation_results),
            "evidence_links": len(evidence_links),
            "hypotheses": len(hypotheses),
            "verdicts": len(verdicts),
            "confirmed_findings": len(findings),
            "ai_enrichments": len(ai_enrichments),
            "authenticated_assets": sum(
                1 for item in auth_coverage["items"] if item["session_established"]
            ),
            "authorized_roles": role_coverage["total"],
            "completion_status": completion.status,
            "task_status_counts": task_counts,
        },
        "assets": [
            {
                "id": str(asset.id),
                "type": asset.asset_type,
                "name": asset.display_name,
                "key": asset.normalized_key,
                "metadata": asset.metadata_,
                "surface_status": (
                    surface_by_asset[str(asset.id)].overall_status
                    if str(asset.id) in surface_by_asset
                    else None
                ),
            }
            for asset in assets
        ],
        "relationships": [
            {
                "id": str(rel.id),
                "type": rel.relationship_type,
                "source": _asset_ref(asset_by_id.get(rel.source_asset_id)),
                "target": _asset_ref(asset_by_id.get(rel.target_asset_id)),
                "confidence": rel.confidence,
                "active": rel.active,
            }
            for rel in relationships
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
                "last_exit_code": (last_run_for(task).exit_code if last_run_for(task) else None),
                "last_error_summary": (
                    last_run_for(task).error_summary if last_run_for(task) else None
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
        "test_plans": [
            {
                "id": str(plan.id),
                "hypothesis_id": (str(plan.hypothesis_id) if plan.hypothesis_id else None),
                "testing_mode": plan.testing_mode,
                "status": plan.status,
                "asset_ids": plan.asset_ids,
                "vulnerability_class_ids": plan.vulnerability_class_ids,
                "required_capabilities": plan.required_capabilities,
                "safety_class": plan.safety_class,
                "authorization_requirement": plan.authorization_requirement,
            }
            for plan in plans
        ],
        "test_executions": [
            {
                "id": str(execution.id),
                "test_plan_id": str(execution.test_plan_id),
                "task_run_id": (str(execution.task_run_id) if execution.task_run_id else None),
                "provider_id": (str(execution.provider_id) if execution.provider_id else None),
                "template_id": execution.template_id,
                "status": execution.status,
                "result_summary": execution.result_summary,
                "evidence_ids": execution.evidence_ids,
                "executed_at": (
                    execution.executed_at.isoformat() if execution.executed_at else None
                ),
            }
            for execution in test_executions
        ],
        "validation_backlog": [
            {
                "id": str(task.id),
                "hypothesis_id": (str(task.hypothesis_id) if task.hypothesis_id else None),
                "test_plan_id": str(task.test_plan_id) if task.test_plan_id else None,
                "evidence_package_id": (
                    str(task.evidence_package_id) if task.evidence_package_id else None
                ),
                "asset_ids": task.asset_ids,
                "validation_goal": task.validation_goal,
                "testing_mode": task.testing_mode,
                "status": task.status,
            }
            for task in validation_tasks
        ],
        "validation_results": [
            {
                "id": str(result.id),
                "validation_task_id": str(result.validation_task_id),
                "outcome": result.outcome,
                "analyst_notes": result.analyst_notes,
                "evidence_ids": result.evidence_ids,
                "recorded_by": result.recorded_by,
                "recorded_at": (result.recorded_at.isoformat() if result.recorded_at else None),
            }
            for result in validation_results
        ],
        "evidence_links": [
            {
                "id": str(link.id),
                "source_type": link.source_type,
                "source_id": str(link.source_id),
                "target_type": link.target_type,
                "target_id": str(link.target_id),
                "link_type": link.link_type,
                "weight": link.weight,
                "provenance": link.provenance,
                "created_at": (link.created_at.isoformat() if link.created_at else None),
            }
            for link in evidence_links
        ],
        "hypotheses": [
            {
                "id": str(hypothesis.id),
                "title": hypothesis.title,
                "description": hypothesis.description,
                "hypothesis_type": hypothesis.hypothesis_type,
                "affected_asset_ids": hypothesis.affected_asset_ids,
                "supporting_evidence_ids": hypothesis.supporting_evidence_ids,
                "contradicting_evidence_ids": hypothesis.contradicting_evidence_ids,
                "confidence": hypothesis.confidence,
                "status": hypothesis.status,
                "test_plan_id": (str(hypothesis.test_plan_id) if hypothesis.test_plan_id else None),
                "verdict_id": (str(hypothesis.verdict_id) if hypothesis.verdict_id else None),
            }
            for hypothesis in hypotheses
        ],
        "verdicts": [
            {
                "id": str(verdict.id),
                "hypothesis_id": str(verdict.hypothesis_id),
                "test_plan_id": (str(verdict.test_plan_id) if verdict.test_plan_id else None),
                "validation_result_id": (
                    str(verdict.validation_result_id) if verdict.validation_result_id else None
                ),
                "status": verdict.status,
                "confidence": verdict.confidence,
                "supporting_evidence_ids": verdict.supporting_evidence_ids,
                "contradicting_evidence_ids": verdict.contradicting_evidence_ids,
                "rule_ids": verdict.rule_ids,
                "explanation": verdict.explanation,
            }
            for verdict in verdicts
        ],
        "confirmed_findings": [
            {
                "id": str(finding.id),
                "hypothesis_id": (str(finding.hypothesis_id) if finding.hypothesis_id else None),
                "validation_result_id": str(finding.validation_result_id),
                "title": finding.title,
                "description": finding.description,
                "affected_asset_ids": finding.affected_asset_ids,
                "cve_ids": finding.cve_ids,
                "cwe_ids": finding.cwe_ids,
                "source_severity": finding.source_severity,
                "contextual_priority": finding.contextual_priority,
                "evidence_ids": finding.evidence_ids,
                "confirmed_by": finding.confirmed_by,
                "confirmed_at": (
                    finding.confirmed_at.isoformat() if finding.confirmed_at else None
                ),
            }
            for finding in findings
        ],
        "ai_enrichments": [_ai_enrichment_item(enrichment) for enrichment in ai_enrichments],
        "auth_coverage": auth_coverage,
        "role_coverage": role_coverage,
        "completion": {
            "status": completion.status,
            "blocking_items": completion.blocking_items,
            "metrics": completion.metrics,
        },
        **completion_sections,
    }
    snapshot_row = await snapshot_svc.create_snapshot(
        scan_id, report_body, generated_by="scan_report"
    )
    if snapshot_row:
        report_body["report_snapshot"] = {
            "id": str(snapshot_row.id),
            "report_version": snapshot_row.report_version,
            "content_hash": snapshot_row.content_hash,
            "completion_version": snapshot_row.completion_version,
            "artifact_reference": snapshot_row.artifact_reference,
            "replayable": snapshot_row.replayable,
            "created_at": (
                snapshot_row.created_at.isoformat() if snapshot_row.created_at else None
            ),
        }
    report_body["report_delivery"] = {
        "source": "regenerated",
        "snapshot_id": str(snapshot_row.id) if snapshot_row else None,
        "replayable": bool(snapshot_row and snapshot_row.replayable),
        "force_regenerate": regenerate,
    }
    await session.commit()
    return report_body


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
            select(AssessmentCompletionRecord).where(AssessmentCompletionRecord.scan_id == scan_id)
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
    stmt = select(AssessmentCompletionRecord).where(AssessmentCompletionRecord.scan_id == scan_id)
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
        for vc in (await session.execute(select(VulnerabilityClass))).scalars().all()
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


@router.get("/vulnerability-classes")
async def vulnerability_classes(
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    classes = list(
        (
            await session.execute(
                select(VulnerabilityClass).where(VulnerabilityClass.active.is_(True))
            )
        )
        .scalars()
        .all()
    )
    return {
        "taxonomy_version": max(
            (vulnerability_class.taxonomy_version for vulnerability_class in classes),
            default="1.0",
        ),
        "items": [
            {
                "id": str(vulnerability_class.id),
                "class_code": vulnerability_class.class_code,
                "name": vulnerability_class.name,
                "description": vulnerability_class.description,
                "related_cwe_ids": vulnerability_class.related_cwe_ids,
                "typical_evidence_types": vulnerability_class.typical_evidence_types,
                "default_testing_mode": vulnerability_class.default_testing_mode,
                "taxonomy_version": vulnerability_class.taxonomy_version,
            }
            for vulnerability_class in sorted(classes, key=lambda item: item.class_code)
        ],
        "total": len(classes),
        "coverage_note": (
            "The catalog enumerates test classes; it does not claim that every "
            "possible implementation-specific vulnerability is knowable in advance."
        ),
    }


@router.get("/scans/{scan_id}/vulnerability-coverage")
async def scan_vulnerability_coverage(
    scan_id: uuid.UUID, session: AsyncSession = Depends(get_session)
) -> dict[str, Any]:
    classes = list(
        (
            await session.execute(
                select(VulnerabilityClass).where(VulnerabilityClass.active.is_(True))
            )
        )
        .scalars()
        .all()
    )
    assets = list(
        (await session.execute(select(Asset).where(Asset.scan_id == scan_id))).scalars().all()
    )
    matrices = list(
        (await session.execute(select(AssetTestMatrix).where(AssetTestMatrix.scan_id == scan_id)))
        .scalars()
        .all()
    )
    matrix_ids = [matrix.id for matrix in matrices]
    requirements = (
        list(
            (
                await session.execute(
                    select(TestRequirement).where(TestRequirement.matrix_id.in_(matrix_ids))
                )
            )
            .scalars()
            .all()
        )
        if matrix_ids
        else []
    )
    matrix_asset = {matrix.id: matrix.asset_id for matrix in matrices}
    asset_map = {asset.id: asset for asset in assets}
    closed_statuses = {
        TestRequirementCoverageStatus.NOT_APPLICABLE.value,
        TestRequirementCoverageStatus.TESTED_NO_EVIDENCE.value,
        TestRequirementCoverageStatus.CONFIRMED_ISSUE.value,
    }
    class_items = []
    for vulnerability_class in sorted(classes, key=lambda item: item.class_code):
        cells = [
            requirement
            for requirement in requirements
            if requirement.vulnerability_class_id == vulnerability_class.id
        ]
        applicability_counts: dict[str, int] = {}
        coverage_counts: dict[str, int] = {}
        next_action_counts: dict[str, int] = {}
        open_assets = []
        for cell in cells:
            applicability_counts[cell.applicability_state] = (
                applicability_counts.get(cell.applicability_state, 0) + 1
            )
            coverage_counts[cell.coverage_status] = coverage_counts.get(cell.coverage_status, 0) + 1
            next_action_counts[cell.next_action] = next_action_counts.get(cell.next_action, 0) + 1
            if cell.coverage_status not in closed_statuses:
                asset_id = matrix_asset.get(cell.matrix_id)
                asset = asset_map.get(asset_id) if asset_id else None
                open_assets.append(
                    {
                        "asset_id": str(asset_id) if asset_id else None,
                        "asset_type": asset.asset_type if asset else None,
                        "asset_name": asset.display_name if asset else None,
                        "applicability_state": cell.applicability_state,
                        "coverage_status": cell.coverage_status,
                        "testing_mode": cell.testing_mode,
                        "next_action": cell.next_action,
                    }
                )
        class_items.append(
            {
                "vulnerability_class_id": str(vulnerability_class.id),
                "class_code": vulnerability_class.class_code,
                "name": vulnerability_class.name,
                "default_testing_mode": vulnerability_class.default_testing_mode,
                "typical_evidence_types": vulnerability_class.typical_evidence_types,
                "matrix_cells": len(cells),
                "applicability_counts": applicability_counts,
                "coverage_counts": coverage_counts,
                "next_action_counts": next_action_counts,
                "open_assets": open_assets,
            }
        )
    open_requirements = [
        requirement
        for requirement in requirements
        if requirement.coverage_status not in closed_statuses
    ]
    return {
        "scan_id": str(scan_id),
        "catalog_classes": len(classes),
        "assets": len(assets),
        "assets_with_test_matrix": len(matrices),
        "matrix_cells": len(requirements),
        "closed_cells": len(requirements) - len(open_requirements),
        "open_cells": len(open_requirements),
        "classes": class_items,
        "coverage_note": (
            "Open cells are explicit assessment obligations, not confirmed "
            "vulnerabilities. Confirmation requires a verdict and evidence."
        ),
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


@router.get("/scans/{scan_id}/auth-coverage")
async def scan_auth_coverage(
    scan_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    return await CredentialContextService(session).get_auth_coverage(scan_id)


@router.get("/scans/{scan_id}/role-coverage")
async def scan_role_coverage(
    scan_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    return await CredentialContextService(session).get_role_coverage(scan_id)


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
    class_map = {
        vc.id: vc.class_code
        for vc in (await session.execute(select(VulnerabilityClass))).scalars().all()
    }
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
                "requirements": [
                    {
                        "id": str(req.id),
                        "vulnerability_class_id": str(req.vulnerability_class_id),
                        "class_code": class_map.get(req.vulnerability_class_id),
                        "applicability_state": req.applicability_state,
                        "coverage_status": req.coverage_status,
                        "testing_mode": req.testing_mode,
                        "next_action": req.next_action,
                        "eligible_capabilities": req.eligible_capabilities,
                        "required_evidence": req.required_evidence,
                        "confidence": req.confidence,
                    }
                    for req in sorted(
                        reqs,
                        key=lambda row: class_map.get(row.vulnerability_class_id) or "",
                    )
                ],
            }
        )
    return {"items": items, "total": len(items)}


def _test_plan_item(p: TestPlan) -> dict[str, Any]:
    return {
        "id": str(p.id),
        "hypothesis_id": str(p.hypothesis_id) if p.hypothesis_id else None,
        "testing_mode": p.testing_mode,
        "status": p.status,
        "asset_ids": p.asset_ids,
        "vulnerability_class_ids": p.vulnerability_class_ids,
        "required_capabilities": p.required_capabilities,
        "safety_class": p.safety_class,
        "authorization_requirement": p.authorization_requirement,
        "uniqueness_key": p.uniqueness_key,
        "planning_fingerprint": p.planning_fingerprint,
        "plan_granularity": p.plan_granularity,
        "split_from_plan_id": str(p.split_from_plan_id) if p.split_from_plan_id else None,
        "split_reason_codes": list(p.split_reason_codes or []),
        "split_policy_version": p.split_policy_version,
    }


@router.get("/scans/{scan_id}/test-plans")
async def list_test_plans(
    scan_id: uuid.UUID, session: AsyncSession = Depends(get_session)
) -> dict[str, Any]:
    stmt = select(TestPlan).where(TestPlan.scan_id == scan_id)
    plans = list((await session.execute(stmt)).scalars().all())
    return {
        "items": [_test_plan_item(p) for p in plans],
        "total": len(plans),
    }


@router.post("/scans/{scan_id}/test-plans/generate")
async def generate_test_plans(
    scan_id: uuid.UUID, session: AsyncSession = Depends(get_session)
) -> dict[str, Any]:
    planner = TestPlanner(session)
    plans = await planner.plan_scan(scan_id)
    await session.commit()
    return {
        "scan_id": str(scan_id),
        "created": len(plans),
        "items": [_test_plan_item(plan) for plan in plans],
    }


@router.post("/scans/{scan_id}/test-plans/execute-automated")
async def execute_automated_test_plans(
    scan_id: uuid.UUID, session: AsyncSession = Depends(get_session)
) -> dict[str, Any]:
    try:
        results = await AutomatedValidationOrchestrator(session).execute_scan(scan_id)
    except ValueError as exc:
        raise HTTPException(404, str(exc)) from exc
    await session.commit()
    return {
        "scan_id": str(scan_id),
        "attempted": len(results),
        "executed": sum(1 for result in results if result.execution_id),
        "items": [
            {
                "plan_id": str(result.plan_id),
                "execution_id": (str(result.execution_id) if result.execution_id else None),
                "task_id": str(result.task_id) if result.task_id else None,
                "task_run_id": (str(result.task_run_id) if result.task_run_id else None),
                "status": result.status,
                "finding_candidates": result.finding_candidates,
                "reused_task": result.reused_task,
                "reason": result.reason,
            }
            for result in results
        ],
    }


@router.get("/scans/{scan_id}/test-executions")
async def list_test_executions(
    scan_id: uuid.UUID, session: AsyncSession = Depends(get_session)
) -> dict[str, Any]:
    plan_ids = [
        plan.id
        for plan in (await session.execute(select(TestPlan).where(TestPlan.scan_id == scan_id)))
        .scalars()
        .all()
    ]
    executions = (
        list(
            (
                await session.execute(
                    select(TestExecution).where(TestExecution.test_plan_id.in_(plan_ids))
                )
            )
            .scalars()
            .all()
        )
        if plan_ids
        else []
    )
    return {
        "items": [
            {
                "id": str(execution.id),
                "test_plan_id": str(execution.test_plan_id),
                "task_run_id": (str(execution.task_run_id) if execution.task_run_id else None),
                "provider_id": (str(execution.provider_id) if execution.provider_id else None),
                "template_id": execution.template_id,
                "status": execution.status,
                "result_summary": execution.result_summary,
                "evidence_ids": execution.evidence_ids,
                "executed_at": (
                    execution.executed_at.isoformat() if execution.executed_at else None
                ),
            }
            for execution in executions
        ],
        "total": len(executions),
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
        "hypothesis_id": str(plan.hypothesis_id) if plan.hypothesis_id else None,
        "testing_mode": plan.testing_mode,
        "status": plan.status,
        "safety_class": plan.safety_class,
        "authorization_requirement": plan.authorization_requirement,
        "asset_ids": plan.asset_ids,
        "vulnerability_class_ids": plan.vulnerability_class_ids,
        "required_capabilities": plan.required_capabilities,
        "evidence_requirements": plan.evidence_requirements,
        "completion_conditions": plan.completion_conditions,
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
            {
                "id": str(h.id),
                "title": h.title,
                "description": h.description,
                "hypothesis_type": h.hypothesis_type,
                "affected_asset_ids": h.affected_asset_ids,
                "supporting_evidence_ids": h.supporting_evidence_ids,
                "contradicting_evidence_ids": h.contradicting_evidence_ids,
                "confidence": h.confidence,
                "status": h.status,
                "test_plan_id": str(h.test_plan_id) if h.test_plan_id else None,
                "verdict_id": str(h.verdict_id) if h.verdict_id else None,
            }
            for h in hyps
        ],
        "total": len(hyps),
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
        "hypothesis_type": hyp.hypothesis_type,
        "affected_asset_ids": hyp.affected_asset_ids,
        "supporting_evidence_ids": hyp.supporting_evidence_ids,
        "contradicting_evidence_ids": hyp.contradicting_evidence_ids,
        "correlation_rule_ids": hyp.correlation_rule_ids,
        "confidence": hyp.confidence,
        "status": hyp.status,
        "validation_requirements": hyp.validation_requirements,
        "test_plan_id": str(hyp.test_plan_id) if hyp.test_plan_id else None,
        "verdict_id": str(hyp.verdict_id) if hyp.verdict_id else None,
    }


@router.get("/scans/{scan_id}/verdicts")
async def list_verdicts(
    scan_id: uuid.UUID, session: AsyncSession = Depends(get_session)
) -> dict[str, Any]:
    verdicts = list(
        (await session.execute(select(Verdict).where(Verdict.scan_id == scan_id))).scalars().all()
    )
    return {
        "items": [
            {
                "id": str(verdict.id),
                "hypothesis_id": str(verdict.hypothesis_id),
                "test_plan_id": (str(verdict.test_plan_id) if verdict.test_plan_id else None),
                "validation_result_id": (
                    str(verdict.validation_result_id) if verdict.validation_result_id else None
                ),
                "status": verdict.status,
                "confidence": verdict.confidence,
                "supporting_evidence_ids": verdict.supporting_evidence_ids,
                "contradicting_evidence_ids": verdict.contradicting_evidence_ids,
                "rule_ids": verdict.rule_ids,
                "explanation": verdict.explanation,
                "issued_at": (verdict.issued_at.isoformat() if verdict.issued_at else None),
            }
            for verdict in verdicts
        ],
        "total": len(verdicts),
    }


@router.get("/scans/{scan_id}/confirmed-findings")
async def list_confirmed_findings(
    scan_id: uuid.UUID, session: AsyncSession = Depends(get_session)
) -> dict[str, Any]:
    findings = list(
        (await session.execute(select(ConfirmedFinding).where(ConfirmedFinding.scan_id == scan_id)))
        .scalars()
        .all()
    )
    return {
        "items": [
            {
                "id": str(finding.id),
                "hypothesis_id": (str(finding.hypothesis_id) if finding.hypothesis_id else None),
                "validation_result_id": str(finding.validation_result_id),
                "title": finding.title,
                "description": finding.description,
                "affected_asset_ids": finding.affected_asset_ids,
                "cve_ids": finding.cve_ids,
                "cwe_ids": finding.cwe_ids,
                "source_severity": finding.source_severity,
                "contextual_priority": finding.contextual_priority,
                "evidence_ids": finding.evidence_ids,
                "confirmed_by": finding.confirmed_by,
                "confirmed_at": (
                    finding.confirmed_at.isoformat() if finding.confirmed_at else None
                ),
            }
            for finding in findings
        ],
        "total": len(findings),
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
                "hypothesis_id": (str(t.hypothesis_id) if t.hypothesis_id else None),
                "test_plan_id": str(t.test_plan_id) if t.test_plan_id else None,
                "evidence_package_id": (
                    str(t.evidence_package_id) if t.evidence_package_id else None
                ),
                "asset_ids": t.asset_ids,
                "validation_goal": t.validation_goal,
                "required_evidence": t.required_evidence,
                "suggested_safe_checks": t.suggested_safe_checks,
                "status": t.status,
                "testing_mode": t.testing_mode,
            }
            for t in tasks
        ]
    }


@router.get("/scans/{scan_id}/evidence-packages")
async def evidence_packages(
    scan_id: uuid.UUID, session: AsyncSession = Depends(get_session)
) -> dict[str, Any]:
    packages = list(
        (await session.execute(select(EvidencePackage).where(EvidencePackage.scan_id == scan_id)))
        .scalars()
        .all()
    )
    return {
        "items": [
            {
                "id": str(package.id),
                "hypothesis_id": str(package.hypothesis_id) if package.hypothesis_id else None,
                "validation_task_id": (
                    str(package.validation_task_id) if package.validation_task_id else None
                ),
                "package_data": package.package_data,
                "created_at": package.created_at.isoformat() if package.created_at else None,
            }
            for package in packages
        ],
        "total": len(packages),
    }


@router.get("/scans/{scan_id}/validation-results")
async def list_validation_results(
    scan_id: uuid.UUID, session: AsyncSession = Depends(get_session)
) -> dict[str, Any]:
    tasks = list(
        (await session.execute(select(ValidationTask).where(ValidationTask.scan_id == scan_id)))
        .scalars()
        .all()
    )
    task_ids = [task.id for task in tasks]
    results = (
        list(
            (
                await session.execute(
                    select(ValidationResult).where(
                        ValidationResult.validation_task_id.in_(task_ids)
                    )
                )
            )
            .scalars()
            .all()
        )
        if task_ids
        else []
    )
    task_by_id = {task.id: task for task in tasks}
    return {
        "items": [
            {
                "id": str(result.id),
                "validation_task_id": str(result.validation_task_id),
                "hypothesis_id": (
                    str(task_by_id[result.validation_task_id].hypothesis_id)
                    if task_by_id[result.validation_task_id].hypothesis_id
                    else None
                ),
                "test_plan_id": (
                    str(task_by_id[result.validation_task_id].test_plan_id)
                    if task_by_id[result.validation_task_id].test_plan_id
                    else None
                ),
                "outcome": result.outcome,
                "analyst_notes": result.analyst_notes,
                "evidence_ids": result.evidence_ids,
                "recorded_by": result.recorded_by,
                "recorded_at": (result.recorded_at.isoformat() if result.recorded_at else None),
            }
            for result in results
        ],
        "total": len(results),
    }


@router.get("/scans/{scan_id}/evidence-links")
async def list_evidence_links(
    scan_id: uuid.UUID, session: AsyncSession = Depends(get_session)
) -> dict[str, Any]:
    links = list(
        (await session.execute(select(EvidenceLink).where(EvidenceLink.scan_id == scan_id)))
        .scalars()
        .all()
    )
    return {
        "items": [
            {
                "id": str(link.id),
                "source_type": link.source_type,
                "source_id": str(link.source_id),
                "target_type": link.target_type,
                "target_id": str(link.target_id),
                "link_type": link.link_type,
                "weight": link.weight,
                "provenance": link.provenance,
                "created_at": (link.created_at.isoformat() if link.created_at else None),
            }
            for link in links
        ],
        "total": len(links),
    }


@router.post("/scans/{scan_id}/ai-enrichments/coverage")
async def enrich_scan_coverage(
    scan_id: uuid.UUID, session: AsyncSession = Depends(get_session)
) -> dict[str, Any]:
    enrichment = await MistralEnrichmentService(session).enrich_vulnerability_coverage(scan_id)
    await session.commit()
    return _ai_enrichment_item(enrichment)


@router.get("/scans/{scan_id}/ai-enrichments")
async def list_ai_enrichments(
    scan_id: uuid.UUID, session: AsyncSession = Depends(get_session)
) -> dict[str, Any]:
    enrichments = list(
        (await session.execute(select(AIEnrichment).where(AIEnrichment.scan_id == scan_id)))
        .scalars()
        .all()
    )
    return {
        "items": [_ai_enrichment_item(item) for item in enrichments],
        "total": len(enrichments),
        "advisory_only": True,
    }


@router.post("/validation-tasks/{task_id}/result")
async def record_validation(
    task_id: uuid.UUID,
    body: ValidationResultInput,
    session: AsyncSession = Depends(get_session),
) -> dict[str, str]:
    svc = ValidationService(session)
    try:
        result = await svc.record_result(
            task_id, body.outcome, body.analyst_notes, body.evidence_ids, body.recorded_by
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    await session.commit()
    return {"validation_result_id": str(result.id), "outcome": result.outcome}


@router.get("/scans/{scan_id}/completion-status")
async def completion_status(
    scan_id: uuid.UUID, session: AsyncSession = Depends(get_session)
) -> dict[str, Any]:
    record = await AssessmentCompletionEvaluator(session).evaluate(scan_id)
    await session.commit()
    payload = await CompletionSerializationService(session).build_payload(scan_id)
    return {
        "status": record.status,
        "assessment_status": record.status,
        "job_status": payload.get("job_status"),
        "scan_status": payload.get("scan_status"),
        "blocking_items": record.blocking_items,
        "completion_reasons": record.completion_reasons,
        "accepted_gaps": record.accepted_gaps,
        "metrics": record.metrics,
        "reason_codes": record.reason_codes,
        "pending_work_summary": record.pending_work_summary,
        "bound_reached": record.bound_reached,
        "evaluation_version": record.evaluation_version,
        "assessment_completion": payload,
        "assessment_completion_history": payload.get("history", []),
        "summary": payload.get("summary"),
    }


@router.get("/scans/{scan_id}/assessment-state")
async def assessment_state(
    scan_id: uuid.UUID,
    job_status: str | None = Query(None),
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    """Normalized assessment completion payload for UI and report consumers."""
    payload = await CompletionSerializationService(session).build_payload(
        scan_id, job_status=job_status
    )
    settings = get_settings()
    if settings.phase7_report_snapshots_enabled:
        latest = await ReportSnapshotService(session).latest_snapshot(scan_id)
        if latest:
            payload["latest_report_snapshot"] = latest.to_dict()
    return payload


@router.get("/scans/{scan_id}/report-freshness")
async def report_freshness(
    scan_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    *,
    force: bool = Query(False),
    allow_full_hash: bool = Query(False),
) -> dict[str, Any]:
    from vapt_platform.config.settings import get_settings

    settings = get_settings()
    if settings.phase9_staleness_polling_enabled:
        result = await ReportStalenessPollingService(session).poll(
            scan_id, force=force, allow_full_hash=allow_full_hash
        )
    else:
        result = await ReportStalenessService(session).evaluate(
            scan_id, allow_full_hash=allow_full_hash
        )
    latest = await ReportSnapshotService(session).latest_snapshot(scan_id)
    payload = result.to_dict()
    payload["polling_enabled"] = settings.phase9_staleness_polling_enabled
    if latest:
        payload["latest_report_snapshot"] = latest.to_dict()
    return payload


@router.get("/scans/{scan_id}/report-snapshots/{snapshot_id}/artifact")
async def replay_report_snapshot(
    scan_id: uuid.UUID,
    snapshot_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    svc = ReportSnapshotService(session)
    snap = await svc.fetch_snapshot(snapshot_id)
    if not snap or snap.scan_id != scan_id:
        raise HTTPException(404, "Snapshot not found")
    try:
        report = await svc.load_artifact(snap)
    except FileNotFoundError as exc:
        raise HTTPException(404, str(exc)) from exc
    report["report_delivery"] = {
        "source": "snapshot",
        "snapshot_id": str(snapshot_id),
        "replayable": snap.replayable,
        "content_hash": snap.content_hash,
    }
    return report


@router.get("/scans/{scan_id}/report-snapshots")
async def list_report_snapshots(
    scan_id: uuid.UUID,
    limit: int = Query(20, ge=1, le=100),
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    items = await ReportSnapshotService(session).list_snapshots(scan_id, limit=limit)
    return {"items": [item.to_dict() for item in items], "total": len(items)}


@router.get("/scans/{scan_id}/report-retention")
async def report_retention_candidates(
    scan_id: uuid.UUID, session: AsyncSession = Depends(get_session)
) -> dict[str, Any]:
    from vapt_platform.services.report_artifact_retention_service import (
        ReportArtifactRetentionService,
    )

    candidates = await ReportArtifactRetentionService(session).list_candidates(scan_id)
    return {"scan_id": str(scan_id), "candidates": [c.to_dict() for c in candidates]}


@router.post("/scans/{scan_id}/report-retention/cleanup")
async def report_retention_cleanup(
    scan_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    *,
    dry_run: bool = Query(True),
) -> dict[str, Any]:
    from vapt_platform.services.report_artifact_retention_service import (
        ReportArtifactRetentionService,
    )

    result = await ReportArtifactRetentionService(session).cleanup(scan_id, dry_run=dry_run)
    if not dry_run:
        await session.commit()
    return result.to_dict()


@router.get("/scans/{scan_id}/report-integrity")
async def report_integrity_audit(
    scan_id: uuid.UUID, session: AsyncSession = Depends(get_session)
) -> dict[str, Any]:
    from vapt_platform.services.report_artifact_integrity_service import (
        ReportArtifactIntegrityService,
    )

    summary = await ReportArtifactIntegrityService(session).audit_scan(scan_id)
    await session.commit()
    return summary.to_dict()


@router.post("/admin/schema-migrate")
async def admin_schema_migrate(
    session: AsyncSession = Depends(get_session),
    *,
    dry_run: bool = Query(True),
) -> dict[str, Any]:
    from vapt_platform.services.sqlite_migration_command import SqliteMigrationCommand

    connection = await session.connection()
    result = await connection.run_sync(
        lambda sync_conn: SqliteMigrationCommand()
        .migrate_test_requirements(sync_conn, dry_run=dry_run)
        .to_dict()
    )
    if not dry_run:
        await session.commit()
    return result


@router.get("/diagnostics/operations")
async def operations_diagnostics(session: AsyncSession = Depends(get_session)) -> dict[str, Any]:
    from vapt_platform.config.settings import get_settings
    from vapt_platform.services.schema_compatibility_detector import SchemaCompatibilityDetector

    settings = get_settings()
    connection = await session.connection()
    schema = await connection.run_sync(
        lambda sync_conn: SchemaCompatibilityDetector().inspect(sync_conn).to_dict()
    )
    return {
        "artifact_backend": settings.report_artifact_backend,
        "phase9_artifact_backend_enabled": settings.phase9_artifact_backend_enabled,
        "phase9_artifact_retention_enabled": settings.phase9_artifact_retention_enabled,
        "phase9_staleness_polling_enabled": settings.phase9_staleness_polling_enabled,
        "phase9_plan_splitting_enabled": settings.phase9_plan_splitting_enabled,
        "phase9_integrity_audit_enabled": settings.phase9_integrity_audit_enabled,
        "retention_policy": {
            "max_versions_per_scan": settings.report_artifact_max_versions_per_scan,
            "ttl_days": settings.report_artifact_ttl_days,
            "keep_latest": settings.report_artifact_keep_latest,
            "keep_terminal": settings.report_artifact_keep_terminal,
        },
        "schema": schema,
    }


def _asset_ref(asset: Asset | None) -> dict[str, Any] | None:
    if not asset:
        return None
    return {
        "id": str(asset.id),
        "asset_type": asset.asset_type,
        "display_name": asset.display_name,
        "normalized_key": asset.normalized_key,
    }


def _ai_enrichment_item(enrichment: AIEnrichment) -> dict[str, Any]:
    return {
        "id": str(enrichment.id),
        "scan_id": str(enrichment.scan_id),
        "enrichment_type": enrichment.enrichment_type,
        "target_entity_type": enrichment.target_entity_type,
        "target_entity_id": str(enrichment.target_entity_id),
        "provider": enrichment.provider,
        "prompt_template_version": enrichment.prompt_template_version,
        "model_config": enrichment.model_config,
        "input_artifact_hash": enrichment.input_artifact_hash,
        "output": enrichment.output,
        "validation_status": enrichment.validation_status,
        "cached": enrichment.cached,
        "created_at": (enrichment.created_at.isoformat() if enrichment.created_at else None),
        "advisory_only": True,
    }
