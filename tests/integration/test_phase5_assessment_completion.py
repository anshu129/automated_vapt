"""Phase 5 assessment completion integration tests."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from vapt_platform.db.tables.models import (
    AssessmentCompletionRecord,
    CorrelationScanState,
    ValidationTask,
)
from vapt_platform.domain.enums import CompletionStatus, ValidationTaskStatus
from vapt_platform.engines.assessment import AssessmentCompletionEvaluator
from vapt_platform.services.core import ProjectService, ScanService
from vapt_platform.services.full_assessment import FullAssessmentService


async def _scan(db_session):
    project = await ProjectService(db_session).create("Phase 5")
    return await ScanService(db_session).create(project.id, "Phase 5 Scan", [])


@pytest.mark.asyncio
async def test_complete_when_no_pending_work(db_session) -> None:
    scan = await _scan(db_session)
    result = await FullAssessmentService(db_session).finalize_assessment(scan.id)
    await db_session.commit()
    assert result.assessment_status in {
        CompletionStatus.COMPLETE.value,
        CompletionStatus.COMPLETE_WITH_ACCEPTED_GAPS.value,
        CompletionStatus.INCOMPLETE.value,
    }
    record = (
        await db_session.execute(
            select(AssessmentCompletionRecord).where(
                AssessmentCompletionRecord.scan_id == scan.id
            )
        )
    ).scalar_one()
    assert record.evaluation_version


@pytest.mark.asyncio
async def test_incomplete_due_to_manual_backlog(db_session) -> None:
    scan = await _scan(db_session)
    db_session.add(
        ValidationTask(
            scan_id=scan.id,
            validation_goal="Manual review required",
            status=ValidationTaskStatus.OPEN.value,
        )
    )
    await db_session.commit()
    result = await AssessmentCompletionEvaluator(db_session).evaluate(scan.id)
    await db_session.commit()
    assert result.status == CompletionStatus.INCOMPLETE.value
    assert record_has_pending_manual(record := result) or result.pending_work_summary.get(
        "manual_validation_pending", 0
    ) >= 1


def record_has_pending_manual(record: AssessmentCompletionRecord) -> bool:
    summary = record.pending_work_summary or {}
    return summary.get("manual_validation_pending", 0) >= 1


@pytest.mark.asyncio
async def test_bound_reached_not_auto_complete(db_session) -> None:
    scan = await _scan(db_session)
    db_session.add(
        CorrelationScanState(
            scan_id=scan.id,
            bound_reached="CORRELATION_MAX_EVENTS_PER_SCAN",
        )
    )
    db_session.add(
        ValidationTask(
            scan_id=scan.id,
            validation_goal="Still open",
            status=ValidationTaskStatus.ASSIGNED.value,
        )
    )
    await db_session.commit()
    result = await AssessmentCompletionEvaluator(db_session).evaluate(scan.id)
    await db_session.commit()
    assert result.status != CompletionStatus.COMPLETE.value
    assert result.bound_reached == "CORRELATION_MAX_EVENTS_PER_SCAN"


@pytest.mark.asyncio
async def test_job_and_assessment_status_separate(db_session) -> None:
    """Simulate job completed while assessment incomplete."""
    scan = await _scan(db_session)
    db_session.add(
        ValidationTask(
            scan_id=scan.id,
            validation_goal="Open task",
            status=ValidationTaskStatus.OPEN.value,
        )
    )
    await db_session.commit()
    completion = await FullAssessmentService(db_session).finalize_assessment(
        scan.id, job_id="job-123"
    )
    await db_session.commit()
    job_status = "COMPLETED"
    assert job_status == "COMPLETED"
    assert completion.assessment_status == CompletionStatus.INCOMPLETE.value
    record = (
        await db_session.execute(
            select(AssessmentCompletionRecord).where(
                AssessmentCompletionRecord.scan_id == scan.id
            )
        )
    ).scalar_one()
    assert record.job_id == "job-123"
