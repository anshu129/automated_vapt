"""Phase 9 integration — artifact retention and orchestration."""

from __future__ import annotations

import tempfile
import uuid
from pathlib import Path

import pytest
from sqlalchemy import select

from vapt_platform.db.tables.models import AssessmentCompletionRecord, Asset, AssetTestMatrix, TestPlan, TestRequirement, VulnerabilityClass
from vapt_platform.domain.artifact_integrity import IntegrityStatus
from vapt_platform.domain.enums import CompletionStatus
from vapt_platform.domain.report_artifact import ReportStalenessStatus
from vapt_platform.engines.assessment import TestPlanner
from vapt_platform.services.core import ProjectService, ScanService
from vapt_platform.services.report_artifact_integrity_service import ReportArtifactIntegrityService
from vapt_platform.services.report_artifact_retention_service import ReportArtifactRetentionService
from vapt_platform.services.report_artifact_store import ReportArtifactStore
from vapt_platform.services.report_snapshot_service import ReportSnapshotService
from vapt_platform.services.report_staleness_polling_service import ReportStalenessPollingService
from vapt_platform.services.schema_compatibility_detector import SchemaCompatibilityDetector
from vapt_platform.services.sqlite_migration_command import SqliteMigrationCommand


async def _scan_with_asset(db_session):
    project = await ProjectService(db_session).create("P9 Integration")
    scan = await ScanService(db_session).create(project.id, "P9 scan", [])
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


@pytest.mark.asyncio
async def test_scenario_a_replayable_artifact_backend(db_session) -> None:
    scan, _ = await _scan_with_asset(db_session)
    with tempfile.TemporaryDirectory() as tmp:
        svc = ReportSnapshotService(db_session, artifact_store=ReportArtifactStore(root=Path(tmp)))
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
        assert row.fingerprint_hash
        assert row.content_hash
        assert row.artifact_storage_backend == "filesystem"


@pytest.mark.asyncio
async def test_scenario_b_retention_cleanup(db_session) -> None:
    scan, _ = await _scan_with_asset(db_session)
    with tempfile.TemporaryDirectory() as tmp:
        store = ReportArtifactStore(root=Path(tmp))
        svc = ReportSnapshotService(db_session, artifact_store=store)
        for _ in range(3):
            await svc.create_snapshot(
                scan.id,
                {
                    "scan_id": str(scan.id),
                    "assessment_completion": {"assessment_status": "INCOMPLETE", "evaluation_version": "v1"},
                },
            )
        await db_session.commit()
        retention = ReportArtifactRetentionService(db_session, artifact_store=store)
        retention.policy.max_versions_per_scan = 1
        dry = await retention.cleanup(scan.id, dry_run=True)
        assert dry.dry_run
        assert len(dry.candidates) == 3


@pytest.mark.asyncio
async def test_scenario_c_freshness_polling(db_session) -> None:
    scan, _ = await _scan_with_asset(db_session)
    with tempfile.TemporaryDirectory() as tmp:
        svc = ReportSnapshotService(db_session, artifact_store=ReportArtifactStore(root=Path(tmp)))
        await svc.create_snapshot(
            scan.id,
            {"scan_id": str(scan.id), "assessment_completion": {"assessment_status": "INCOMPLETE", "evaluation_version": "v1"}},
        )
        await db_session.commit()
        db_session.add(
            AssessmentCompletionRecord(
                scan_id=scan.id,
                status=CompletionStatus.BLOCKED.value,
                evaluation_version="v1",
            )
        )
        await db_session.commit()
        ReportStalenessPollingService.clear_cache(scan.id)
        result = await ReportStalenessPollingService(db_session).poll(scan.id, force=True)
        assert result.status == ReportStalenessStatus.STALE.value


@pytest.mark.asyncio
async def test_scenario_d_plan_splitting(db_session) -> None:
    scan, asset = await _scan_with_asset(db_session)
    vc = (
        await db_session.execute(
            select(VulnerabilityClass).where(VulnerabilityClass.class_code == "INJECTION_CLASS")
        )
    ).scalar_one()
    matrix = AssetTestMatrix(scan_id=scan.id, asset_id=asset.id)
    db_session.add(matrix)
    await db_session.flush()
    broad = TestRequirement(
        matrix_id=matrix.id,
        vulnerability_class_id=vc.id,
        applicability_state="APPLICABLE",
        testing_mode="AUTOMATED",
        coverage_status="NOT_TESTED",
        next_action="PLAN_AUTOMATED",
        uniqueness_key="broad",
        scope_granularity="SURFACE",
    )
    param = TestRequirement(
        matrix_id=matrix.id,
        vulnerability_class_id=vc.id,
        applicability_state="APPLICABLE",
        testing_mode="AUTOMATED",
        coverage_status="NOT_TESTED",
        next_action="PLAN_AUTOMATED",
        uniqueness_key="param-id",
        scope_granularity="PARAMETER",
    )
    db_session.add(broad)
    await db_session.commit()
    first_plans = await TestPlanner(db_session).plan_scan(scan.id)
    await db_session.commit()
    assert len(first_plans) >= 1
    db_session.add(param)
    await db_session.commit()
    second_plans = await TestPlanner(db_session).plan_scan(scan.id)
    await db_session.commit()
    assert len(second_plans) >= 1
    param_plans = [p for p in second_plans if p.plan_granularity == "PARAMETER"]
    assert param_plans
    assert any(p.split_from_plan_id for p in param_plans)


@pytest.mark.asyncio
async def test_scenario_e_integrity_audit(db_session) -> None:
    scan, _ = await _scan_with_asset(db_session)
    with tempfile.TemporaryDirectory() as tmp:
        store = ReportArtifactStore(root=Path(tmp))
        svc = ReportSnapshotService(db_session, artifact_store=store)
        row = await svc.create_snapshot(
            scan.id,
            {"scan_id": str(scan.id), "assessment_completion": {"assessment_status": "INCOMPLETE", "evaluation_version": "v1"}},
        )
        await db_session.commit()
        summary = await ReportArtifactIntegrityService(db_session, artifact_store=store).audit_scan(scan.id)
        assert summary.overall_status == IntegrityStatus.OK.value
        store.delete(row.artifact_reference, scan_id=str(scan.id), snapshot_id=str(row.id))
        summary2 = await ReportArtifactIntegrityService(db_session, artifact_store=store).audit_scan(scan.id)
        assert summary2.issue_count >= 1


@pytest.mark.asyncio
async def test_scenario_f_schema_phase9_detection(db_session) -> None:
    conn = await db_session.connection()
    report = await conn.run_sync(lambda sync: SchemaCompatibilityDetector().inspect(sync))
    assert report.phase9_fingerprint_hash or report.schema_version in {"phase9-v1", "legacy", "phase8-v1"}
    check = await conn.run_sync(lambda sync: SqliteMigrationCommand().check(sync))
    assert "schema" in check
