"""Phase 6 completion serialization unit tests."""

from __future__ import annotations

import uuid

import pytest

from vapt_platform.domain.assessment_completion import (
    AssessmentCompletionResult,
    CompletionReasonCode,
    PendingAssessmentWork,
)
from vapt_platform.domain.enums import CompletionStatus
from vapt_platform.services.completion_serialization import CompletionSerializationService
from vapt_platform.services.core import ProjectService, ScanService
from vapt_platform.services.full_assessment import FullAssessmentService


async def _scan(db_session):
    project = await ProjectService(db_session).create("Phase 6", "Serialization tests")
    return await ScanService(db_session).create(project.id, "Phase 6 Scan", [])


def test_to_report_dict_preserves_fields() -> None:
    result = AssessmentCompletionResult(
        assessment_status=CompletionStatus.INCOMPLETE.value,
        reason_codes=[CompletionReasonCode.PENDING_MANUAL_VALIDATION],
        accepted_gaps={"asset-1": ["AUTHENTICATED_AREA_COVERAGE"]},
        bound_reached="CORRELATION_MAX_EVENTS_PER_SCAN",
        pending_work=PendingAssessmentWork(manual_validation_pending=2),
    )
    report = result.to_report_dict()
    assert report["assessment_status"] == CompletionStatus.INCOMPLETE.value
    assert CompletionReasonCode.PENDING_MANUAL_VALIDATION in report["reason_codes"]
    assert report["accepted_gaps"]["asset-1"] == ["AUTHENTICATED_AREA_COVERAGE"]
    assert report["bound_reached"] == "CORRELATION_MAX_EVENTS_PER_SCAN"
    assert report["pending_work"]["manual_validation_pending"] == 2


@pytest.mark.asyncio
async def test_serialization_includes_history_when_present(db_session) -> None:
    scan = await _scan(db_session)
    first = await FullAssessmentService(db_session).finalize_assessment(scan.id, job_id="job-1")
    await db_session.commit()
    from vapt_platform.db.tables.models import AssessmentCompletionRecord
    from sqlalchemy import select

    record = (
        await db_session.execute(
            select(AssessmentCompletionRecord).where(AssessmentCompletionRecord.scan_id == scan.id)
        )
    ).scalar_one()
    record.status = CompletionStatus.BLOCKED.value
    await db_session.flush()
    second = await FullAssessmentService(db_session).evaluate_completion(scan.id, job_id="job-2")
    await db_session.commit()

    payload = await CompletionSerializationService(db_session).build_payload(
        scan.id, result=second, job_status="COMPLETED"
    )
    assert payload["job_status"] == "COMPLETED"
    assert payload["assessment_status"] == second.assessment_status
    assert isinstance(payload["history"], list)
    assert len(payload["history"]) >= 1
    assert payload["summary"]["headline"]


@pytest.mark.asyncio
async def test_overview_payload_separate_job_and_assessment(db_session) -> None:
    scan = await _scan(db_session)
    await FullAssessmentService(db_session).finalize_assessment(scan.id)
    await db_session.commit()
    payload = await CompletionSerializationService(db_session).build_payload(
        scan.id, job_status="COMPLETED"
    )
    assert payload["job_status"] == "COMPLETED"
    assert payload["assessment_status"]
    assert payload["scan_status"]
    assert payload["summary"]["job_status"] == "COMPLETED"
    assert payload["summary"]["assessment_status"] == payload["assessment_status"]
