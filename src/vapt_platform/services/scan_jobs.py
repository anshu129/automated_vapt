"""In-memory background scan job runner for the web UI.

Runs a full assessment (reconnaissance -> planning -> AI/automated validation
and assignment) as a non-blocking background task so the UI stays responsive
during long (multi-minute) scans. Scans run to natural completion rather than
being cut off at an artificial limit; a soft time budget is recorded for
display only.
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import time
import uuid
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse

from vapt_platform.config.settings import get_settings
from vapt_platform.db.session import session_scope
from vapt_platform.engines.assessment import TestPlanner
from vapt_platform.services.ai_validation import AIValidationService
from vapt_platform.services.core import ProjectService, ScanService
from vapt_platform.services.full_assessment import FullAssessmentService
from vapt_platform.services.mcp_validation import McpValidationService
from vapt_platform.validators.base import with_auth_url

_JOBS: dict[str, dict[str, Any]] = {}


def _now() -> str:
    return datetime.now(UTC).isoformat()


def get_job(job_id: str) -> dict[str, Any] | None:
    return _JOBS.get(job_id)


def list_jobs() -> list[dict[str, Any]]:
    return sorted(_JOBS.values(), key=lambda job: job.get("created_at", ""), reverse=True)


def _set(job_id: str, **fields: Any) -> None:
    job = _JOBS.get(job_id)
    if job is not None:
        job.update(fields)
        job["updated_at"] = _now()


def _normalize_scan_id(scan_id: str) -> str:
    return scan_id.replace("-", "")


def notify_recon_tool_event(
    scan_id: str,
    *,
    event: str,
    capability: str,
    provider: str | None,
    target: str | None = None,
    exit_code: int | None = None,
    duration_s: float | None = None,
    task_status: str | None = None,
    error: str | None = None,
    command: str | None = None,
) -> None:
    """Update in-memory job progress for UI polling during reconnaissance."""
    wanted = _normalize_scan_id(scan_id)
    for job in _JOBS.values():
        if _normalize_scan_id(str(job.get("scan_id", ""))) != wanted:
            continue
        progress = dict(job.get("progress") or {})
        recon = dict(progress.get("recon") or {})
        if event == "start":
            recon["current_tool"] = {
                "capability": capability,
                "provider": provider,
                "target": target,
                "command": command,
            }
        else:
            completed = list(recon.get("completed_tools") or [])
            completed.append(
                {
                    "capability": capability,
                    "provider": provider,
                    "exit_code": exit_code,
                    "duration_s": duration_s,
                    "status": task_status,
                    "error": (error or "")[:200] or None,
                }
            )
            recon["completed_tools"] = completed[-30:]
            recon["tools_completed"] = len(completed)
            recon.pop("current_tool", None)
        progress["recon"] = recon
        job["progress"] = progress
        job["updated_at"] = _now()
        break


def infer_scope_rules(host: str) -> tuple[list[dict[str, Any]], str, str | None]:
    """Return (scope_rules, hostname_or_ip, url) for a raw host/URL input."""
    raw = host.strip()
    url: str | None = None
    if raw.startswith(("http://", "https://")):
        url = raw
        parsed = urlparse(raw)
        host_part = parsed.hostname or raw
    else:
        host_part = raw.split("/")[0]

    rules: list[dict[str, Any]] = []
    try:
        ipaddress.ip_address(host_part)
        rules.append({"rule_type": "IP_ADDRESS", "pattern": host_part, "priority": 100})
    except ValueError:
        rules.append({"rule_type": "HOSTNAME", "pattern": host_part, "priority": 100})
    if url:
        rules.append({"rule_type": "URL_PREFIX", "pattern": url.rstrip("/"), "priority": 90})
    else:
        rules.append(
            {
                "rule_type": "URL_PREFIX",
                "pattern": f"https://{host_part}",
                "priority": 80,
            }
        )
    return rules, host_part, url


async def create_and_launch(
    host: str,
    name: str | None = None,
    run_ai: bool = True,
    run_mcp: bool = True,
    run_mcp_active: bool = False,
    time_budget_minutes: int = 30,
    username: str | None = None,
    password: str | None = None,
) -> dict[str, Any]:
    target_host = host.strip()
    if username and password and target_host.startswith(("http://", "https://")):
        target_host = with_auth_url(target_host, username, password)
    scope_rules, host_part, url = infer_scope_rules(target_host)
    scan_name = name or f"{host_part} assessment"

    async with session_scope() as session:
        project = await ProjectService(session).create(
            f"{host_part} (UI scan)",
            f"Web UI initiated assessment for {host}",
        )
        scan = await ScanService(session).create(project.id, scan_name, scope_rules)
        project_id = str(project.id)
        scan_id = str(scan.id)

    job_id = str(uuid.uuid4())
    _JOBS[job_id] = {
        "job_id": job_id,
        "scan_id": scan_id,
        "project_id": project_id,
        "host": host,
        "target": host_part,
        "url": url,
        "name": scan_name,
        "status": "QUEUED",
        "phase": "queued",
        "run_ai": run_ai,
        "run_mcp": run_mcp,
        "run_mcp_active": run_mcp_active,
        "has_credentials": bool(username and password),
        "time_budget_minutes": time_budget_minutes,
        "progress": {},
        "error": None,
        "created_at": _now(),
        "updated_at": _now(),
        "elapsed_seconds": 0,
        "_username": username,
        "_password": password,
    }

    asyncio.create_task(
        _run_job(
            job_id,
            uuid.UUID(scan_id),
            run_ai,
            run_mcp=run_mcp,
            run_mcp_active=run_mcp_active,
            username=username,
            password=password,
        )
    )
    safe = dict(_JOBS[job_id])
    safe.pop("_username", None)
    safe.pop("_password", None)
    return safe


async def _heartbeat(job_id: str, started: float) -> None:
    """Keep elapsed_seconds fresh during long-running phases."""
    try:
        while True:
            await asyncio.sleep(3)
            job = _JOBS.get(job_id)
            if not job or job.get("status") in {"COMPLETED", "FAILED"}:
                return
            _set(job_id, elapsed_seconds=round(time.monotonic() - started, 1))
    except asyncio.CancelledError:
        return


async def _run_job(
    job_id: str,
    scan_id: uuid.UUID,
    run_ai: bool,
    run_mcp: bool = True,
    run_mcp_active: bool = False,
    username: str | None = None,
    password: str | None = None,
) -> None:
    started = time.monotonic()
    heartbeat = asyncio.create_task(_heartbeat(job_id, started))

    def tick() -> None:
        _set(job_id, elapsed_seconds=round(time.monotonic() - started, 1))

    try:
        _set(job_id, status="RUNNING", phase="reconnaissance")
        async with session_scope() as session:
            await ScanService(session).start(scan_id)
        tick()

        async with session_scope() as session:
            refresh = await FullAssessmentService(session).prepare_for_planning(scan_id)
        _set(
            job_id,
            phase="planning",
            progress={
                **_JOBS[job_id]["progress"],
                "recon": "done",
                "assessment_refresh": refresh.to_dict(),
            },
        )
        async with session_scope() as session:
            plans = await TestPlanner(session).plan_scan(scan_id)
        _set(
            job_id,
            progress={
                **_JOBS[job_id]["progress"],
                "planning": "done",
                "test_plans": len(plans),
            },
        )
        tick()

        settings = get_settings()
        if settings.full_assessment_v2:
            _set(job_id, phase="capability_routing")
            async with session_scope() as session:
                routing = await FullAssessmentService(session).execute_automated_plans(
                    scan_id,
                    active_validation_allowed=run_mcp_active,
                    username=username,
                    password=password,
                )
                await session.commit()
            _set(
                job_id,
                progress={
                    **_JOBS[job_id]["progress"],
                    "capability_routing": "done",
                    "routed_plans_attempted": routing.plans_attempted,
                    "routed_plans_executed": routing.plans_executed,
                    "routed_plans_blocked": routing.plans_blocked,
                },
            )
        tick()

        if run_ai:
            _set(job_id, phase="ai_validation")
            async with session_scope() as session:
                summary = await AIValidationService(session).run(scan_id)
            _set(
                job_id,
                progress={
                    **_JOBS[job_id]["progress"],
                    "ai_validation": "done",
                    "automated_executed": summary.automated_executed,
                    "finding_candidates": summary.finding_candidates,
                    "assignments": len(summary.assignments),
                    "advisory_provider": summary.advisory_provider,
                },
            )
        tick()

        if run_mcp and settings.use_legacy_mcp_validation:
            _set(job_id, phase="tool_validation")
            async with session_scope() as session:
                mcp_summary = await McpValidationService(session).validate_scan(
                    scan_id,
                    active_allowed=run_mcp_active,
                    username=username,
                    password=password,
                )
                await session.commit()
            _set(
                job_id,
                progress={
                    **_JOBS[job_id]["progress"],
                    "tool_validation": "done",
                    "mcp_connectors": mcp_summary.connectors,
                    "mcp_corroborated": mcp_summary.corroborated,
                    "mcp_tasks_created": mcp_summary.tasks_created,
                    "mcp_skipped": mcp_summary.skipped,
                },
            )
        tick()
        async with session_scope() as session:
            completion = await FullAssessmentService(session).finalize_assessment(
                scan_id, job_id=job_id
            )
            await FullAssessmentService(session).sync_scan_lifecycle_on_job_end(
                scan_id, job_status="COMPLETED"
            )
            await session.commit()
        _set(
            job_id,
            status="COMPLETED",
            phase="completed",
            assessment_status=completion.assessment_status,
            assessment_reason_codes=completion.reason_codes,
            bound_reached=completion.bound_reached,
            pending_work_count=completion.pending_work_count,
        )
    except Exception as exc:  # noqa: BLE001 - surface any failure to the UI
        async with session_scope() as session:
            try:
                completion = await FullAssessmentService(session).evaluate_completion(
                    scan_id, job_id=job_id
                )
                await session.commit()
                assessment_status = completion.assessment_status
                reason_codes = completion.reason_codes
            except Exception:
                assessment_status = "INCOMPLETE"
                reason_codes = []
        _set(
            job_id,
            status="FAILED",
            phase="failed",
            error=f"{type(exc).__name__}: {exc}",
            assessment_status=assessment_status,
            assessment_reason_codes=reason_codes,
        )
    finally:
        tick()
        heartbeat.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await heartbeat


async def shutdown() -> None:
    for task in list(asyncio.all_tasks()):
        if task is asyncio.current_task():
            continue
        with contextlib.suppress(Exception):
            task.cancel()
