"""Phase 6 completion history unit tests."""

from __future__ import annotations

import pytest
from sqlalchemy import func, select

from vapt_platform.db.tables.models import AssessmentCompletionHistory, AssessmentCompletionRecord
from vapt_platform.domain.assessment_completion import AssessmentCompletionResult, PendingAssessmentWork
from vapt_platform.domain.enums import CompletionStatus
from vapt_platform.services.assessment_completion_evaluator import AssessmentCompletionEvaluatorService
from vapt_platform.services.completion_history_service import CompletionHistoryService
from vapt_platform.services.core import ProjectService, ScanService


async def _scan(db_session):
    project = await ProjectService(db_session).create("Phase 6 History", "History tests")
    return await ScanService(db_session).create(project.id, "History Scan", [])


@pytest.mark.asyncio
async def test_transition_creates_history_row(db_session) -> None:
    scan = await _scan(db_session)
    svc = CompletionHistoryService(db_session)
    result = AssessmentCompletionResult(
        assessment_status=CompletionStatus.COMPLETE.value,
        reason_codes=["NO_ACTIONABLE_WORK_REMAINS"],
    )
    row = await svc.record_transition(
        scan_id=scan.id,
        previous_status=CompletionStatus.INCOMPLETE.value,
        new_status=CompletionStatus.COMPLETE.value,
        result=result,
        job_id="job-a",
    )
    await db_session.commit()
    assert row is not None
    count = (
        await db_session.execute(
            select(func.count())
            .select_from(AssessmentCompletionHistory)
            .where(AssessmentCompletionHistory.scan_id == scan.id)
        )
    ).scalar_one()
    assert count == 1


@pytest.mark.asyncio
async def test_noop_transition_does_not_create_history(db_session) -> None:
    scan = await _scan(db_session)
    svc = CompletionHistoryService(db_session)
    result = AssessmentCompletionResult(assessment_status=CompletionStatus.INCOMPLETE.value)
    assert (
        await svc.record_transition(
            scan_id=scan.id,
            previous_status=CompletionStatus.INCOMPLETE.value,
            new_status=CompletionStatus.INCOMPLETE.value,
            result=result,
        )
        is None
    )
    await db_session.commit()
    count = (
        await db_session.execute(
            select(func.count())
            .select_from(AssessmentCompletionHistory)
            .where(AssessmentCompletionHistory.scan_id == scan.id)
        )
    ).scalar_one()
    assert count == 0


@pytest.mark.asyncio
async def test_repeated_same_status_does_not_duplicate_history(db_session) -> None:
    scan = await _scan(db_session)
    evaluator = AssessmentCompletionEvaluatorService(db_session)
    await evaluator.evaluate(scan.id)
    await db_session.commit()
    count_after_first = (
        await db_session.execute(
            select(func.count())
            .select_from(AssessmentCompletionHistory)
            .where(AssessmentCompletionHistory.scan_id == scan.id)
        )
    ).scalar_one()
    await evaluator.evaluate(scan.id)
    await db_session.commit()
    count_after_second = (
        await db_session.execute(
            select(func.count())
            .select_from(AssessmentCompletionHistory)
            .where(AssessmentCompletionHistory.scan_id == scan.id)
        )
    ).scalar_one()
    assert count_after_second == count_after_first


@pytest.mark.asyncio
async def test_meaningful_transition_updates_record_and_history(db_session) -> None:
    scan = await _scan(db_session)
    record = AssessmentCompletionRecord(
        scan_id=scan.id,
        status=CompletionStatus.INCOMPLETE.value,
    )
    db_session.add(record)
    await db_session.commit()

    evaluator = AssessmentCompletionEvaluatorService(db_session)
    result = AssessmentCompletionResult(
        assessment_status=CompletionStatus.BLOCKED.value,
        reason_codes=["REQUIRED_CREDENTIALS_MISSING"],
        pending_work=PendingAssessmentWork(authenticated_coverage_pending=1),
        blocking_conditions=["missing auth"],
    )
    await evaluator._persist_record(scan.id, result, record, "job-b", {"missing_auth_context": True})
    await db_session.commit()

    refreshed = (
        await db_session.execute(
            select(AssessmentCompletionRecord).where(AssessmentCompletionRecord.scan_id == scan.id)
        )
    ).scalar_one()
    assert refreshed.status == CompletionStatus.BLOCKED.value
    history = (
        await db_session.execute(
            select(AssessmentCompletionHistory).where(
                AssessmentCompletionHistory.scan_id == scan.id
            )
        )
    ).scalars().all()
    assert len(history) == 1
    assert history[0].previous_status == CompletionStatus.INCOMPLETE.value
    assert history[0].new_status == CompletionStatus.BLOCKED.value
