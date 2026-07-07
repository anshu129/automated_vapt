"""Phase 9 staleness polling unit tests."""

from __future__ import annotations

import pytest

from vapt_platform.db.tables.models import AssessmentCompletionRecord, ReportSnapshot
from vapt_platform.domain.enums import CompletionStatus
from vapt_platform.domain.report_artifact import ReportStalenessStatus
from vapt_platform.services.core import ProjectService, ScanService
from vapt_platform.services.report_hashing import compute_live_fingerprint_hash
from vapt_platform.services.report_staleness_polling_service import ReportStalenessPollingService
from vapt_platform.services.report_staleness_service import ReportStalenessService


async def _scan(db_session):
    project = await ProjectService(db_session).create("P9 poll")
    return await ScanService(db_session).create(project.id, "poll scan", [])


@pytest.mark.asyncio
async def test_fresh_scan_remains_fresh(db_session) -> None:
    scan = await _scan(db_session)
    record = AssessmentCompletionRecord(
        scan_id=scan.id,
        status=CompletionStatus.INCOMPLETE.value,
        evaluation_version="phase5-v1",
    )
    db_session.add(record)
    await db_session.flush()
    live = await ReportStalenessService(db_session).build_live_fingerprint(scan.id)
    fp_hash = compute_live_fingerprint_hash(live)
    db_session.add(
        ReportSnapshot(
            scan_id=scan.id,
            report_version="phase7-v1",
            completion_version="phase5-v1",
            content_hash="content",
            fingerprint_hash=fp_hash,
            assessment_status=CompletionStatus.INCOMPLETE.value,
        )
    )
    await db_session.commit()
    ReportStalenessPollingService.clear_cache(scan.id)
    result = await ReportStalenessPollingService(db_session).poll(scan.id, force=True)
    assert result.status == ReportStalenessStatus.FRESH.value


@pytest.mark.asyncio
async def test_state_change_marks_stale(db_session) -> None:
    scan = await _scan(db_session)
    db_session.add(
        ReportSnapshot(
            scan_id=scan.id,
            report_version="phase7-v1",
            completion_version="phase5-v1",
            content_hash="content",
            fingerprint_hash="old",
            assessment_status=CompletionStatus.INCOMPLETE.value,
        )
    )
    db_session.add(
        AssessmentCompletionRecord(
            scan_id=scan.id,
            status=CompletionStatus.BLOCKED.value,
            evaluation_version="phase5-v1",
        )
    )
    await db_session.commit()
    ReportStalenessPollingService.clear_cache(scan.id)
    result = await ReportStalenessPollingService(db_session).poll(scan.id, force=True)
    assert result.status == ReportStalenessStatus.STALE.value


@pytest.mark.asyncio
async def test_cached_poll_uses_cache(db_session) -> None:
    scan = await _scan(db_session)
    svc = ReportStalenessPollingService(db_session)
    ReportStalenessPollingService.clear_cache(scan.id)
    first = await svc.poll(scan.id, force=True)
    second = await svc.poll(scan.id, force=False)
    assert first.status == second.status
