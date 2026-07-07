"""Phase 7 integration — requirement granularity and report audit."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import func, select

from vapt_platform.db.tables.models import (
    Asset,
    AssetTestMatrix,
    AssessmentCompletionRecord,
    ReportSnapshot,
    TestRequirement,
    VulnerabilityClass,
)
from vapt_platform.domain.correlation_rule import CorrelationResult, CorrelationResultType
from vapt_platform.domain.enums import CompletionStatus
from vapt_platform.engines.assessment import TestMatrixEngine, TestPlanner
from vapt_platform.services.completion_history_service import CompletionHistoryService
from vapt_platform.services.completion_serialization import CompletionSerializationService
from vapt_platform.services.core import ProjectService, ScanService
from vapt_platform.services.correlation_result_applier import CorrelationResultApplier
from vapt_platform.services.report_snapshot_service import ReportSnapshotService


async def _scan_with_asset(db_session):
    project = await ProjectService(db_session).create("Phase 7 Integration")
    scan = await ScanService(db_session).create(project.id, "P7 scan", [])
    asset = Asset(
        scan_id=scan.id,
        project_id=scan.project_id,
        asset_type="WEB_APPLICATION",
        display_name="https://app.example.com",
        normalized_key="https://app.example.com",
    )
    db_session.add(asset)
    await db_session.flush()
    return scan, asset


async def _scan_only(db_session):
    project = await ProjectService(db_session).create("Phase 7 Integration")
    return await ScanService(db_session).create(project.id, "P7 scan", [])


def _requirement_result(asset_id: uuid.UUID, *, parameter_name: str = "") -> CorrelationResult:
    return CorrelationResult(
        result_type=CorrelationResultType.TEST_REQUIREMENT_CANDIDATE.value,
        rule_id="CORR-PARAM-001",
        rule_version="1.0",
        confidence=0.8,
        reason_codes=["PARAM_GAP"],
        payload={
            "asset_id": str(asset_id),
            "vulnerability_class": "INJECTION_CLASS",
            "endpoint_ref": "/search",
            "parameter_name": parameter_name,
            "parameter_location": "query",
            "capability_group": "INJECTION_VALIDATION",
        },
    )


@pytest.mark.asyncio
async def test_scenario_a_parameter_scoped_requirements_distinct(db_session) -> None:
    scan, asset = await _scan_with_asset(db_session)
    applier = CorrelationResultApplier(db_session)
    event_id = uuid.uuid4()

    await applier.apply(
        scan_id=scan.id,
        event_id=event_id,
        result=_requirement_result(asset.id, parameter_name="id"),
    )
    await applier.apply(
        scan_id=scan.id,
        event_id=uuid.uuid4(),
        result=_requirement_result(asset.id, parameter_name="q"),
    )
    await db_session.commit()

    matrix = (
        await db_session.execute(
            select(AssetTestMatrix).where(
                AssetTestMatrix.scan_id == scan.id,
                AssetTestMatrix.asset_id == asset.id,
            )
        )
    ).scalar_one()
    reqs = list(
        (
            await db_session.execute(
                select(TestRequirement).where(TestRequirement.matrix_id == matrix.id)
            )
        )
        .scalars()
        .all()
    )
    param_reqs = [r for r in reqs if r.scope_granularity == "PARAMETER"]
    assert len(param_reqs) >= 2
    keys = {r.uniqueness_key for r in param_reqs}
    assert len(keys) == 2

    plans = await TestPlanner(db_session).plan_scan(scan.id)
    await db_session.commit()
    assert len(plans) >= 2


@pytest.mark.asyncio
async def test_scenario_b_equivalent_requirement_reuse(db_session) -> None:
    scan, asset = await _scan_with_asset(db_session)
    applier = CorrelationResultApplier(db_session)
    result = _requirement_result(asset.id, parameter_name="id")
    summary1 = await applier.apply(scan_id=scan.id, event_id=uuid.uuid4(), result=result)
    summary2 = await applier.apply(scan_id=scan.id, event_id=uuid.uuid4(), result=result)
    await db_session.commit()
    assert summary2.duplicate_suppression_count >= 1 or len(summary1.created_test_requirement_ids) == 0


@pytest.mark.asyncio
async def test_scenario_c_report_snapshots_retained(db_session) -> None:
    scan = await _scan_only(db_session)
    svc = ReportSnapshotService(db_session)
    base = {
        "scan_id": str(scan.id),
        "summary": {"assets": 1},
        "assessment_completion": {"assessment_status": "INCOMPLETE", "reason_codes": []},
    }
    first = await svc.create_snapshot(scan.id, base)
    changed = {
        **base,
        "assessment_completion": {
            "assessment_status": CompletionStatus.BLOCKED.value,
            "reason_codes": ["REQUIRED_CREDENTIALS_MISSING"],
        },
    }
    second = await svc.create_snapshot(scan.id, changed)
    await db_session.commit()
    assert first and second
    assert first.content_hash != second.content_hash
    snapshots = await svc.list_snapshots(scan.id)
    assert len(snapshots) == 2


@pytest.mark.asyncio
async def test_scenario_d_latest_transition_in_payload(db_session) -> None:
    scan = await _scan_only(db_session)
    record = AssessmentCompletionRecord(
        scan_id=scan.id,
        status=CompletionStatus.INCOMPLETE.value,
    )
    db_session.add(record)
    await db_session.commit()

    from vapt_platform.domain.assessment_completion import AssessmentCompletionResult

    await CompletionHistoryService(db_session).record_transition(
        scan_id=scan.id,
        previous_status=CompletionStatus.INCOMPLETE.value,
        new_status=CompletionStatus.COMPLETE.value,
        result=AssessmentCompletionResult(
            assessment_status=CompletionStatus.COMPLETE.value,
            reason_codes=["NO_ACTIONABLE_WORK_REMAINS"],
        ),
    )
    await db_session.commit()

    payload = await CompletionSerializationService(db_session).build_payload(scan.id)
    assert payload.get("latest_transition") is not None
    assert payload["latest_transition"]["new_status"] == CompletionStatus.COMPLETE.value


@pytest.mark.asyncio
async def test_scenario_e_report_metadata_with_history(db_session) -> None:
    scan = await _scan_only(db_session)
    record = AssessmentCompletionRecord(
        scan_id=scan.id,
        status=CompletionStatus.INCOMPLETE.value,
        evaluation_version="phase5-v1",
    )
    db_session.add(record)
    await db_session.commit()

    from vapt_platform.domain.assessment_completion import AssessmentCompletionResult

    history_svc = CompletionHistoryService(db_session)
    await history_svc.record_transition(
        scan_id=scan.id,
        previous_status=CompletionStatus.INCOMPLETE.value,
        new_status=CompletionStatus.INCOMPLETE.value.replace("INCOMPLETE", "BLOCKED"),
        result=AssessmentCompletionResult(
            assessment_status="BLOCKED",
            reason_codes=["SAFETY_POLICY_BLOCKING"],
        ),
    )
    report = {
        "scan_id": str(scan.id),
        "assessment_completion": {
            "assessment_status": "BLOCKED",
            "evaluation_version": "phase5-v1",
            "reason_codes": ["SAFETY_POLICY_BLOCKING"],
        },
        "assessment_completion_history": [],
    }
    snap = await ReportSnapshotService(db_session).create_snapshot(scan.id, report)
    await db_session.commit()
    assert snap is not None
    assert snap.completion_version == "phase5-v1"
    from vapt_platform.db.tables.models import AssessmentCompletionHistory

    history_count = (
        await db_session.execute(
            select(func.count())
            .select_from(AssessmentCompletionHistory)
            .where(AssessmentCompletionHistory.scan_id == scan.id)
        )
    ).scalar_one()
    assert history_count >= 1


@pytest.mark.asyncio
async def test_legacy_merged_row_still_supported(db_session, monkeypatch) -> None:
    monkeypatch.setenv("PHASE7_REQUIREMENT_GRANULARITY_ENABLED", "false")
    monkeypatch.setenv("PHASE7_LEGACY_REQUIREMENT_MERGE_ONLY", "true")
    from vapt_platform.config.settings import get_settings

    get_settings.cache_clear()

    scan, asset = await _scan_with_asset(db_session)
    vc = (
        await db_session.execute(
            select(VulnerabilityClass).where(VulnerabilityClass.class_code == "INJECTION_CLASS")
        )
    ).scalar_one()
    matrix = await TestMatrixEngine(db_session).build(scan.id, asset.id)
    await db_session.commit()

    applier = CorrelationResultApplier(db_session)
    await applier.apply(
        scan_id=scan.id,
        event_id=uuid.uuid4(),
        result=_requirement_result(asset.id, parameter_name="id"),
    )
    await applier.apply(
        scan_id=scan.id,
        event_id=uuid.uuid4(),
        result=_requirement_result(asset.id, parameter_name="q"),
    )
    await db_session.commit()

    reqs = list(
        (
            await db_session.execute(
                select(TestRequirement).where(TestRequirement.matrix_id == matrix.id)
            )
        )
        .scalars()
        .all()
    )
    merged = [r for r in reqs if r.vulnerability_class_id == vc.id]
    assert len(merged) == 1
    scopes = (merged[0].reasoning_trace or {}).get("parameter_scopes", [])
    assert len(scopes) >= 1

    get_settings.cache_clear()
