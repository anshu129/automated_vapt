"""Phase 8 report staleness unit tests."""

from __future__ import annotations

import pytest

from vapt_platform.db.tables.models import AssessmentCompletionRecord, ReportSnapshot
from vapt_platform.domain.enums import CompletionStatus
from vapt_platform.domain.report_artifact import ReportStalenessStatus
from vapt_platform.services.core import ProjectService, ScanService
from vapt_platform.services.report_staleness_service import ReportStalenessService


async def _scan(db_session):
    project = await ProjectService(db_session).create("P8 stale")
    return await ScanService(db_session).create(project.id, "stale scan", [])


@pytest.mark.asyncio
async def test_no_snapshot_unknown(db_session) -> None:
    scan = await _scan(db_session)
    result = await ReportStalenessService(db_session).evaluate(scan.id)
    assert result.status == ReportStalenessStatus.UNKNOWN.value


@pytest.mark.asyncio
async def test_assessment_change_marks_stale(db_session) -> None:
    scan = await _scan(db_session)
    db_session.add(
        ReportSnapshot(
            scan_id=scan.id,
            report_version="phase7-v1",
            completion_version="phase5-v1",
            generation_version="phase8-v1",
            content_hash="abc",
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
    result = await ReportStalenessService(db_session).evaluate(scan.id)
    assert result.status == ReportStalenessStatus.STALE.value
    assert "assessment_status_changed" in result.reasons


@pytest.mark.asyncio
async def test_no_meaningful_change_can_remain_fresh(db_session) -> None:
    scan = await _scan(db_session)
    from vapt_platform.services.report_hashing import compute_live_fingerprint_hash

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
            generation_version="phase9-v1",
            content_hash="full-report-hash",
            fingerprint_hash=fp_hash,
            assessment_status=CompletionStatus.INCOMPLETE.value,
            live_hash_at_generation=None,
        )
    )
    await db_session.commit()
    result = await ReportStalenessService(db_session).evaluate(scan.id)
    assert result.status == ReportStalenessStatus.FRESH.value
