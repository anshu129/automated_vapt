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
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from vapt_platform.db.session import session_scope
from vapt_platform.engines.assessment import TestPlanner
from vapt_platform.services.ai_validation import AIValidationService
from vapt_platform.services.core import ProjectService, ScanService

_JOBS: dict[str, dict[str, Any]] = {}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def get_job(job_id: str) -> dict[str, Any] | None:
    return _JOBS.get(job_id)


def list_jobs() -> list[dict[str, Any]]:
    return sorted(_JOBS.values(), key=lambda job: job.get("created_at", ""), reverse=True)


def _set(job_id: str, **fields: Any) -> None:
    job = _JOBS.get(job_id)
    if job is not None:
        job.update(fields)
        job["updated_at"] = _now()


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
    time_budget_minutes: int = 30,
) -> dict[str, Any]:
    scope_rules, host_part, url = infer_scope_rules(host)
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
        "time_budget_minutes": time_budget_minutes,
        "progress": {},
        "error": None,
        "created_at": _now(),
        "updated_at": _now(),
        "elapsed_seconds": 0,
    }

    asyncio.create_task(_run_job(job_id, uuid.UUID(scan_id), run_ai))
    return dict(_JOBS[job_id])


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


async def _run_job(job_id: str, scan_id: uuid.UUID, run_ai: bool) -> None:
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
            assets = await ScanService(session).get(scan_id)  # touch to ensure scan exists
            _ = assets
        _set(
            job_id,
            phase="planning",
            progress={**_JOBS[job_id]["progress"], "recon": "done"},
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
        _set(job_id, status="COMPLETED", phase="completed")
    except Exception as exc:  # noqa: BLE001 - surface any failure to the UI
        _set(job_id, status="FAILED", phase="failed", error=f"{type(exc).__name__}: {exc}")
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
