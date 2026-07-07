"""Phase 7 latest transition denormalization unit tests."""

from __future__ import annotations

import pytest
from sqlalchemy import select

from vapt_platform.db.tables.models import AssessmentCompletionRecord
from vapt_platform.domain.assessment_completion import AssessmentCompletionResult
from vapt_platform.domain.enums import CompletionStatus
from vapt_platform.services.completion_history_service import CompletionHistoryService
from vapt_platform.services.core import ProjectService, ScanService


async def _scan(db_session):
    project = await ProjectService(db_session).create("Phase 7 Transition")
    return await ScanService(db_session).create(project.id, "Transition scan", [])


@pytest.mark.asyncio
async def test_latest_transition_updates_on_meaningful_change(db_session) -> None:
    scan = await _scan(db_session)
    record = AssessmentCompletionRecord(
        scan_id=scan.id,
        status=CompletionStatus.INCOMPLETE.value,
    )
    db_session.add(record)
    await db_session.commit()

    svc = CompletionHistoryService(db_session)
    result = AssessmentCompletionResult(
        assessment_status=CompletionStatus.BLOCKED.value,
        reason_codes=["REQUIRED_CREDENTIALS_MISSING"],
    )
    await svc.record_transition(
        scan_id=scan.id,
        previous_status=CompletionStatus.INCOMPLETE.value,
        new_status=CompletionStatus.BLOCKED.value,
        result=result,
    )
    await db_session.commit()

    refreshed = (
        await db_session.execute(
            select(AssessmentCompletionRecord).where(AssessmentCompletionRecord.scan_id == scan.id)
        )
    ).scalar_one()
    assert refreshed.latest_transition_summary is not None
    assert refreshed.latest_transition_summary["new_status"] == CompletionStatus.BLOCKED.value
    assert refreshed.latest_transition_at is not None


@pytest.mark.asyncio
async def test_noop_does_not_update_latest_transition(db_session) -> None:
    scan = await _scan(db_session)
    record = AssessmentCompletionRecord(
        scan_id=scan.id,
        status=CompletionStatus.INCOMPLETE.value,
        latest_transition_summary={"new_status": "INCOMPLETE"},
    )
    db_session.add(record)
    await db_session.commit()
    before = record.latest_transition_at

    svc = CompletionHistoryService(db_session)
    result = AssessmentCompletionResult(assessment_status=CompletionStatus.INCOMPLETE.value)
    await svc.record_transition(
        scan_id=scan.id,
        previous_status=CompletionStatus.INCOMPLETE.value,
        new_status=CompletionStatus.INCOMPLETE.value,
        result=result,
    )
    await db_session.commit()

    refreshed = (
        await db_session.execute(
            select(AssessmentCompletionRecord).where(AssessmentCompletionRecord.scan_id == scan.id)
        )
    ).scalar_one()
    assert refreshed.latest_transition_at == before
