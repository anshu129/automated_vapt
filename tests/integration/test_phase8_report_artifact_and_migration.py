"""Phase 8 integration — report artifacts and migration."""

from __future__ import annotations

import tempfile
import uuid
from pathlib import Path

import pytest
from sqlalchemy import select

from vapt_platform.db.tables.models import Asset, AssetTestMatrix, TestPlan, TestRequirement, VulnerabilityClass
from vapt_platform.domain.correlation_rule import CorrelationResult, CorrelationResultType
from vapt_platform.domain.enums import CompletionStatus
from vapt_platform.domain.report_artifact import ReportStalenessStatus
from vapt_platform.engines.assessment import TestPlanner
from vapt_platform.services.core import ProjectService, ScanService
from vapt_platform.services.correlation_result_applier import CorrelationResultApplier
from vapt_platform.services.report_snapshot_service import ReportSnapshotService
from vapt_platform.services.report_staleness_service import ReportStalenessService


async def _scan_with_asset(db_session):
    project = await ProjectService(db_session).create("P8 Integration")
    scan = await ScanService(db_session).create(project.id, "P8 scan", [])
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


def _req_result(asset_id: uuid.UUID, parameter_name: str = "") -> CorrelationResult:
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
async def test_scenario_a_snapshot_replay(db_session) -> None:
    scan, _ = await _scan_with_asset(db_session)
    with tempfile.TemporaryDirectory() as tmp:
        from vapt_platform.services.report_artifact_store import ReportArtifactStore

        svc = ReportSnapshotService(db_session)
        svc.artifact_store = ReportArtifactStore(root=Path(tmp))
        report = {
            "scan_id": str(scan.id),
            "summary": {"assets": 1},
            "assessment_completion": {
                "assessment_status": CompletionStatus.INCOMPLETE.value,
                "evaluation_version": "phase5-v1",
            },
        }
        row = await svc.create_snapshot(scan.id, report)
        await db_session.commit()
        replay = await svc.load_artifact(row)
        assert replay["summary"]["assets"] == 1
        assert row.content_hash


@pytest.mark.asyncio
async def test_scenario_b_stale_detection(db_session) -> None:
    scan, _ = await _scan_with_asset(db_session)
    with tempfile.TemporaryDirectory() as tmp:
        from vapt_platform.services.report_artifact_store import ReportArtifactStore

        svc = ReportSnapshotService(db_session)
        svc.artifact_store = ReportArtifactStore(root=Path(tmp))
        report = {
            "scan_id": str(scan.id),
            "assessment_completion": {
                "assessment_status": CompletionStatus.INCOMPLETE.value,
                "evaluation_version": "phase5-v1",
            },
        }
        await svc.create_snapshot(scan.id, report)
        await db_session.commit()
        from vapt_platform.db.tables.models import AssessmentCompletionRecord

        record = AssessmentCompletionRecord(
            scan_id=scan.id,
            status=CompletionStatus.BLOCKED.value,
            evaluation_version="phase5-v1",
        )
        db_session.add(record)
        await db_session.commit()
        freshness = await ReportStalenessService(db_session).evaluate(scan.id)
        assert freshness.status == ReportStalenessStatus.STALE.value


@pytest.mark.asyncio
async def test_scenario_c_equivalent_plan_reuse(db_session) -> None:
    scan, asset = await _scan_with_asset(db_session)
    vc = (
        await db_session.execute(
            select(VulnerabilityClass).where(VulnerabilityClass.class_code == "INJECTION_CLASS")
        )
    ).scalar_one()
    matrix = AssetTestMatrix(scan_id=scan.id, asset_id=asset.id)
    db_session.add(matrix)
    await db_session.flush()
    req = TestRequirement(
        matrix_id=matrix.id,
        vulnerability_class_id=vc.id,
        applicability_state="APPLICABLE",
        testing_mode="AUTOMATED",
        uniqueness_key="same-key",
        scope_granularity="PARAMETER",
        next_action="PLAN_AUTOMATED",
        coverage_status="NOT_TESTED",
    )
    db_session.add(req)
    await db_session.commit()
    planner = TestPlanner(db_session)
    first = await planner.plan_scan(scan.id)
    second = await planner.plan_scan(scan.id)
    await db_session.commit()
    assert len(first) >= 1
    assert len(second) == 0


@pytest.mark.asyncio
async def test_scenario_d_distinct_parameter_plans(db_session) -> None:
    scan, asset = await _scan_with_asset(db_session)
    applier = CorrelationResultApplier(db_session)
    await applier.apply(
        scan_id=scan.id, event_id=uuid.uuid4(), result=_req_result(asset.id, parameter_name="id")
    )
    await applier.apply(
        scan_id=scan.id, event_id=uuid.uuid4(), result=_req_result(asset.id, parameter_name="q")
    )
    await db_session.commit()
    plans = await TestPlanner(db_session).plan_scan(scan.id)
    await db_session.commit()
    assert len(plans) >= 2
    fingerprints = {p.planning_fingerprint for p in plans if p.planning_fingerprint}
    assert len(fingerprints) >= 2


@pytest.mark.asyncio
async def test_scenario_e_schema_detector_on_fresh_db(db_session) -> None:
    from sqlalchemy import text
    from vapt_platform.services.schema_compatibility_detector import SchemaCompatibilityDetector

    conn = await db_session.connection()
    report = await conn.run_sync(lambda sync: SchemaCompatibilityDetector().inspect(sync))
    assert report.phase7_report_snapshots or report.schema_version
    rows = await db_session.execute(text("SELECT 1"))
    assert rows.scalar_one() == 1
