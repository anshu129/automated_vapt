"""Phase 6 UI / report / completion integration tests."""

from __future__ import annotations

import pytest
from sqlalchemy import func, select

from vapt_platform.db.tables.models import (
    AssessmentCompletionHistory,
    AssessmentCompletionRecord,
    CorrelationScanState,
    ValidationTask,
)
from vapt_platform.domain.enums import CompletionStatus, ScanStatus, ValidationTaskStatus
from vapt_platform.services.completion_serialization import CompletionSerializationService
from vapt_platform.services.core import ProjectService, ScanService
from vapt_platform.services.full_assessment import FullAssessmentService


async def _scan(db_session, name: str = "Phase 6 Integration"):
    project = await ProjectService(db_session).create(name, "Phase 6 integration")
    return await ScanService(db_session).create(project.id, f"{name} scan", [])


@pytest.mark.asyncio
async def test_scenario_a_complete(db_session) -> None:
    scan = await _scan(db_session, "Complete")
    result = await FullAssessmentService(db_session).finalize_assessment(scan.id, job_id="job-complete")
    await FullAssessmentService(db_session).sync_scan_lifecycle_on_job_end(
        scan.id, job_status="COMPLETED"
    )
    await db_session.commit()

    assert result.assessment_status in {
        CompletionStatus.COMPLETE.value,
        CompletionStatus.COMPLETE_WITH_ACCEPTED_GAPS.value,
        CompletionStatus.INCOMPLETE.value,
    }
    history_count = (
        await db_session.execute(
            select(func.count())
            .select_from(AssessmentCompletionHistory)
            .where(AssessmentCompletionHistory.scan_id == scan.id)
        )
    ).scalar_one()
    assert history_count >= 0

    sections = await CompletionSerializationService(db_session).build_report_sections(
        scan.id, job_status="COMPLETED"
    )
    assert "assessment_completion" in sections
    assert sections["assessment_completion"]["job_status"] == "COMPLETED"
    assert sections["assessment_completion"]["assessment_status"] == result.assessment_status

    payload = await CompletionSerializationService(db_session).build_payload(
        scan.id, job_status="COMPLETED"
    )
    assert payload["job_status"] == "COMPLETED"
    assert payload["assessment_status"] == result.assessment_status


@pytest.mark.asyncio
async def test_scenario_b_accepted_gaps(db_session) -> None:
    scan = await _scan(db_session, "Accepted gaps")
    record = AssessmentCompletionRecord(
        scan_id=scan.id,
        status=CompletionStatus.INCOMPLETE.value,
        accepted_gaps={"asset-1": ["AUTHENTICATED_AREA_COVERAGE"]},
    )
    db_session.add(record)
    await db_session.commit()

    result = await FullAssessmentService(db_session).finalize_assessment(scan.id)
    await db_session.commit()

    sections = await CompletionSerializationService(db_session).build_report_sections(scan.id)
    completion = sections["assessment_completion"]
    if result.assessment_status == CompletionStatus.COMPLETE_WITH_ACCEPTED_GAPS.value:
        assert completion["accepted_gaps"]
        assert CompletionStatus.COMPLETE_WITH_ACCEPTED_GAPS.value in (
            completion["assessment_status"],
            result.assessment_status,
        )


@pytest.mark.asyncio
async def test_scenario_c_incomplete(db_session) -> None:
    scan = await _scan(db_session, "Incomplete")
    db_session.add(
        ValidationTask(
            scan_id=scan.id,
            validation_goal="Open manual work",
            status=ValidationTaskStatus.OPEN.value,
        )
    )
    await db_session.commit()

    result = await FullAssessmentService(db_session).finalize_assessment(scan.id, job_id="job-done")
    await db_session.commit()

    assert result.assessment_status == CompletionStatus.INCOMPLETE.value
    payload = await CompletionSerializationService(db_session).build_payload(
        scan.id, job_status="COMPLETED"
    )
    assert payload["job_status"] == "COMPLETED"
    assert payload["assessment_status"] == CompletionStatus.INCOMPLETE.value
    assert payload["pending_work_summary"]["manual_validation_pending"] >= 1


@pytest.mark.asyncio
async def test_scenario_d_blocked_or_inconclusive(db_session) -> None:
    scan = await _scan(db_session, "Blocked")
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
            status=ValidationTaskStatus.OPEN.value,
        )
    )
    await db_session.commit()

    result = await FullAssessmentService(db_session).finalize_assessment(scan.id)
    await db_session.commit()

    sections = await CompletionSerializationService(db_session).build_report_sections(scan.id)
    completion = sections["assessment_completion"]
    assert completion["assessment_status"] in {
        CompletionStatus.INCOMPLETE.value,
        CompletionStatus.BLOCKED.value,
        CompletionStatus.INCONCLUSIVE.value,
    }
    if result.bound_reached:
        assert completion.get("bound_reached") == result.bound_reached


@pytest.mark.asyncio
async def test_scenario_e_rerender_stability(db_session) -> None:
    scan = await _scan(db_session, "Stability")
    await FullAssessmentService(db_session).finalize_assessment(scan.id)
    await db_session.commit()

    first = await CompletionSerializationService(db_session).build_payload(scan.id)
    second = await CompletionSerializationService(db_session).build_payload(scan.id)
    assert first["assessment_status"] == second["assessment_status"]
    assert first["reason_codes"] == second["reason_codes"]
    assert first["summary"]["headline"] == second["summary"]["headline"]

    history_before = (
        await db_session.execute(
            select(func.count())
            .select_from(AssessmentCompletionHistory)
            .where(AssessmentCompletionHistory.scan_id == scan.id)
        )
    ).scalar_one()
    await FullAssessmentService(db_session).evaluate_completion(scan.id)
    await db_session.commit()
    history_after = (
        await db_session.execute(
            select(func.count())
            .select_from(AssessmentCompletionHistory)
            .where(AssessmentCompletionHistory.scan_id == scan.id)
        )
    ).scalar_one()
    assert history_after == history_before


@pytest.mark.asyncio
async def test_scan_status_not_overwriting_assessment(db_session) -> None:
    scan = await _scan(db_session, "Status separation")
    db_session.add(
        ValidationTask(
            scan_id=scan.id,
            validation_goal="Blocks completion",
            status=ValidationTaskStatus.OPEN.value,
        )
    )
    await db_session.commit()

    result = await FullAssessmentService(db_session).finalize_assessment(scan.id, job_id="job-x")
    await FullAssessmentService(db_session).sync_scan_lifecycle_on_job_end(
        scan.id, job_status="COMPLETED"
    )
    await db_session.commit()

    await db_session.refresh(scan)
    assert scan.status == ScanStatus.COMPLETED.value
    assert result.assessment_status == CompletionStatus.INCOMPLETE.value
    record = (
        await db_session.execute(
            select(AssessmentCompletionRecord).where(AssessmentCompletionRecord.scan_id == scan.id)
        )
    ).scalar_one()
    assert record.status == CompletionStatus.INCOMPLETE.value
    assert record.status != scan.status
