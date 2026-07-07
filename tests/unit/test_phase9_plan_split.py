"""Phase 9 plan split policy unit tests."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from vapt_platform.db.tables.models import Asset, AssetTestMatrix, TestPlan, TestRequirement, VulnerabilityClass
from vapt_platform.domain.plan_split_policy import PlanSplitAction
from vapt_platform.services.core import ProjectService, ScanService
from vapt_platform.services.test_plan_split_policy import TestPlanSplitPolicy


async def _fixture(db_session):
    project = await ProjectService(db_session).create("P9 split")
    scan = await ScanService(db_session).create(project.id, "split scan", [])
    asset = Asset(
        scan_id=scan.id,
        project_id=scan.project_id,
        asset_type="WEB_APPLICATION",
        display_name="app",
        normalized_key="app",
    )
    db_session.add(asset)
    await db_session.flush()
    vc = (
        await db_session.execute(
            select(VulnerabilityClass).where(VulnerabilityClass.class_code == "INJECTION_CLASS")
        )
    ).scalar_one()
    matrix = AssetTestMatrix(scan_id=scan.id, asset_id=asset.id)
    db_session.add(matrix)
    await db_session.flush()
    return scan, asset, vc, matrix


@pytest.mark.asyncio
async def test_broad_plan_kept_broad(db_session) -> None:
    _, asset, vc, matrix = await _fixture(db_session)
    req = TestRequirement(
        matrix_id=matrix.id,
        vulnerability_class_id=vc.id,
        applicability_state="APPLICABLE",
        testing_mode="AUTOMATED",
        coverage_status="NOT_TESTED",
        next_action="PLAN_AUTOMATED",
        uniqueness_key="broad-key",
        scope_granularity="SURFACE",
    )
    policy = TestPlanSplitPolicy()
    decision = policy.evaluate(
        scan_id=matrix.scan_id,
        req=req,
        asset_id=asset.id,
        existing_plans=[],
    )
    assert decision.action == PlanSplitAction.KEEP_BROAD.value


@pytest.mark.asyncio
async def test_parameter_plan_split_from_broad(db_session) -> None:
    scan, asset, vc, matrix = await _fixture(db_session)
    broad_plan = TestPlan(
        scan_id=scan.id,
        asset_ids=[str(asset.id)],
        vulnerability_class_ids=[str(vc.id)],
        testing_mode="AUTOMATED",
        safety_class="PASSIVE",
        status="SCHEDULED",
        plan_granularity="SURFACE",
        planning_fingerprint="broad-fp",
    )
    req = TestRequirement(
        matrix_id=matrix.id,
        vulnerability_class_id=vc.id,
        applicability_state="APPLICABLE",
        testing_mode="AUTOMATED",
        coverage_status="NOT_TESTED",
        next_action="PLAN_AUTOMATED",
        uniqueness_key="param-key",
        scope_granularity="PARAMETER",
    )
    decision = TestPlanSplitPolicy().evaluate(
        scan_id=scan.id,
        req=req,
        asset_id=asset.id,
        existing_plans=[broad_plan],
    )
    assert decision.action == PlanSplitAction.SPLIT.value
    assert decision.split_from_plan_id == str(broad_plan.id)


@pytest.mark.asyncio
async def test_split_fingerprint_deterministic() -> None:
    from vapt_platform.services.test_plan_uniqueness_policy import TestPlanUniquenessPolicy

    scan_id = uuid.uuid4()
    asset_id = uuid.uuid4()
    class_id = uuid.uuid4()
    fp1 = TestPlanUniquenessPolicy.build_fingerprint(
        scan_id=scan_id,
        asset_id=asset_id,
        vulnerability_class_id=class_id,
        uniqueness_key="k",
        testing_mode="AUTOMATED",
        granularity="PARAMETER",
    )
    fp2 = TestPlanUniquenessPolicy.build_fingerprint(
        scan_id=scan_id,
        asset_id=asset_id,
        vulnerability_class_id=class_id,
        uniqueness_key="k",
        testing_mode="AUTOMATED",
        granularity="PARAMETER",
    )
    assert fp1 == fp2
