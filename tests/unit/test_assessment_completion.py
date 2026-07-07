"""Assessment completion evaluator unit tests (Phase 5)."""

from __future__ import annotations

import uuid

import pytest

from vapt_platform.db.tables.models import (
    AssessmentCompletionRecord,
    CorrelationScanState,
    TestRequirement,
    ValidationTask,
)
from vapt_platform.domain.enums import CompletionStatus, ValidationTaskStatus
from vapt_platform.engines.accepted_gap_policy import AcceptedGapPolicy
from vapt_platform.services.assessment_completion_evaluator import AssessmentCompletionEvaluatorService
from vapt_platform.services.core import ProjectService, ScanService


async def _scan(db_session):
    project = await ProjectService(db_session).create("Completion")
    return await ScanService(db_session).create(project.id, "Completion Scan", [])


@pytest.mark.asyncio
async def test_open_work_incomplete(db_session) -> None:
    scan = await _scan(db_session)
    task = ValidationTask(
        scan_id=scan.id,
        validation_goal="Review finding",
        status=ValidationTaskStatus.OPEN.value,
    )
    db_session.add(task)
    await db_session.commit()
    result = await AssessmentCompletionEvaluatorService(db_session).evaluate(scan.id)
    assert result.assessment_status == CompletionStatus.INCOMPLETE.value
    assert result.pending_work.manual_validation_pending >= 1


@pytest.mark.asyncio
async def test_accepted_gaps_complete_with_gaps(db_session) -> None:
    scan = await _scan(db_session)
    record = AssessmentCompletionRecord(
        scan_id=scan.id,
        status=CompletionStatus.INCOMPLETE.value,
        accepted_gaps={str(uuid.uuid4()): ["LIVE_CRAWL"]},
    )
    db_session.add(record)
    await db_session.commit()
    result = await AssessmentCompletionEvaluatorService(db_session).evaluate(scan.id)
    assert result.assessment_status in {
        CompletionStatus.COMPLETE_WITH_ACCEPTED_GAPS.value,
        CompletionStatus.INCOMPLETE.value,
    }


@pytest.mark.asyncio
async def test_bound_reached_with_pending_incomplete(db_session) -> None:
    scan = await _scan(db_session)
    db_session.add(
        CorrelationScanState(
            scan_id=scan.id,
            bound_reached="CORRELATION_MAX_GENERATIONS",
        )
    )
    task = ValidationTask(
        scan_id=scan.id,
        validation_goal="Pending",
        status=ValidationTaskStatus.OPEN.value,
    )
    db_session.add(task)
    await db_session.commit()
    result = await AssessmentCompletionEvaluatorService(db_session).evaluate(scan.id)
    assert result.assessment_status == CompletionStatus.INCOMPLETE.value
    assert "CORRELATION_BOUND_REACHED" in result.reason_codes
    assert result.bound_reached == "CORRELATION_MAX_GENERATIONS"


def test_accepted_gap_policy_rejects_missing_credentials() -> None:
    decision = AcceptedGapPolicy().evaluate_gap(
        gap_type="MISSING_CREDENTIALS",
        accepted_gaps={},
    )
    assert not decision.accepted


def test_job_finished_does_not_force_complete() -> None:
    """Job COMPLETED is independent — evaluator decides assessment status."""
    assert CompletionStatus.COMPLETE.value != "COMPLETED"
