"""Authorization policy unit tests."""

import uuid

import pytest
from sqlalchemy import select

from vapt_platform.db.tables.models import Asset, TestPlan
from vapt_platform.domain.enums import Capability, SafetyClass, TestPlanStatus, TestingMode
from vapt_platform.engines.authorization_policy import AuthorizationPolicy
from vapt_platform.engines.assessment import TestMatrixEngine
from vapt_platform.services.core import ProjectService, ScanService


@pytest.mark.asyncio
async def test_in_scope_plan_allowed(db_session) -> None:
    project = await ProjectService(db_session).create("Auth Policy")
    scan = await ScanService(db_session).create(
        project.id,
        "Auth Scan",
        [{"rule_type": "ROOT_DOMAIN", "pattern": "example.com", "priority": 100}],
    )
    await ScanService(db_session).start(scan.id)
    await TestMatrixEngine(db_session).build(scan.id, (await _web_asset(db_session, scan.id)).id)
    asset = await _web_asset(db_session, scan.id)
    plan = TestPlan(
        scan_id=scan.id,
        asset_ids=[str(asset.id)],
        vulnerability_class_ids=[],
        testing_mode=TestingMode.AUTOMATED.value,
        required_capabilities=[Capability.TEMPLATE_BASED_ASSESSMENT.value],
        safety_class=SafetyClass.LOW_IMPACT.value,
        authorization_requirement="PRE_APPROVED",
        status=TestPlanStatus.APPROVED.value,
    )
    db_session.add(plan)
    await db_session.flush()
    decision = await AuthorizationPolicy(db_session).evaluate(
        scan_id=scan.id,
        plan=plan,
        requirement=None,
        capability=Capability.TEMPLATE_BASED_ASSESSMENT.value,
        asset=asset,
        active_validation_allowed=False,
    )
    assert decision.allowed


@pytest.mark.asyncio
async def test_out_of_scope_asset_rejected(db_session) -> None:
    project = await ProjectService(db_session).create("Out Scope")
    scan = await ScanService(db_session).create(
        project.id,
        "Out Scope Scan",
        [{"rule_type": "ROOT_DOMAIN", "pattern": "allowed.com", "priority": 100}],
    )
    asset = Asset(
        scan_id=scan.id,
        project_id=project.id,
        asset_type="WEB_APPLICATION",
        normalized_key="https://other.com",
        display_name="other",
        metadata_={"base_url": "https://other.com"},
    )
    db_session.add(asset)
    plan = TestPlan(
        scan_id=scan.id,
        asset_ids=[str(asset.id)],
        testing_mode=TestingMode.AUTOMATED.value,
        required_capabilities=[Capability.TEMPLATE_BASED_ASSESSMENT.value],
        safety_class=SafetyClass.LOW_IMPACT.value,
        authorization_requirement="PRE_APPROVED",
        status=TestPlanStatus.APPROVED.value,
    )
    db_session.add(plan)
    await db_session.flush()
    decision = await AuthorizationPolicy(db_session).evaluate(
        scan_id=scan.id,
        plan=plan,
        requirement=None,
        capability=Capability.TEMPLATE_BASED_ASSESSMENT.value,
        asset=asset,
        active_validation_allowed=False,
    )
    assert not decision.allowed
    assert "OUT_OF_SCOPE" in decision.reason_codes


@pytest.mark.asyncio
async def test_scan_mismatch_rejected(db_session) -> None:
    project = await ProjectService(db_session).create("Mismatch")
    scan_a = await ScanService(db_session).create(project.id, "A", [])
    scan_b = await ScanService(db_session).create(project.id, "B", [])
    plan = TestPlan(
        scan_id=scan_a.id,
        asset_ids=[],
        testing_mode=TestingMode.AUTOMATED.value,
        safety_class=SafetyClass.LOW_IMPACT.value,
        authorization_requirement="PRE_APPROVED",
        status=TestPlanStatus.APPROVED.value,
    )
    db_session.add(plan)
    await db_session.flush()
    decision = await AuthorizationPolicy(db_session).evaluate(
        scan_id=scan_b.id,
        plan=plan,
        requirement=None,
        capability=Capability.TEMPLATE_BASED_ASSESSMENT.value,
        asset=None,
        active_validation_allowed=False,
    )
    assert "PLAN_SCAN_MISMATCH" in decision.reason_codes


@pytest.mark.asyncio
async def test_unauthorized_active_validation_rejected(db_session) -> None:
    project = await ProjectService(db_session).create("Active")
    scan = await ScanService(db_session).create(
        project.id,
        "Active Scan",
        [{"rule_type": "ROOT_DOMAIN", "pattern": "example.com"}],
    )
    await ScanService(db_session).start(scan.id)
    asset = await _web_asset(db_session, scan.id)
    plan = TestPlan(
        scan_id=scan.id,
        asset_ids=[str(asset.id)],
        testing_mode=TestingMode.AUTOMATED.value,
        safety_class=SafetyClass.STATE_CHANGING.value,
        authorization_requirement="PRE_APPROVED",
        status=TestPlanStatus.APPROVED.value,
    )
    db_session.add(plan)
    await db_session.flush()
    decision = await AuthorizationPolicy(db_session).evaluate(
        scan_id=scan.id,
        plan=plan,
        requirement=None,
        capability=Capability.INJECTION_VALIDATION.value,
        asset=asset,
        active_validation_allowed=False,
    )
    assert "ACTIVE_TESTING_NOT_AUTHORIZED" in decision.reason_codes


async def _web_asset(db_session, scan_id: uuid.UUID) -> Asset:
    asset = (
        await db_session.execute(
            select(Asset).where(
                Asset.scan_id == scan_id,
                Asset.asset_type == "WEB_APPLICATION",
            )
        )
    ).scalars().first()
    assert asset is not None
    return asset
