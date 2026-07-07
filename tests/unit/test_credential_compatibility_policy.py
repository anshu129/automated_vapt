"""Credential compatibility policy unit tests."""

import uuid

import pytest

from vapt_platform.db.tables.models import Asset, AuthenticationContext, CredentialReference
from vapt_platform.domain.capability_provider import TestPlanContext
from vapt_platform.domain.enums import Capability, CredentialType, SafetyClass
from vapt_platform.engines.credential_compatibility_policy import CredentialCompatibilityPolicy
from vapt_platform.db.tables.models import TestRequirement
from vapt_platform.services.core import ProjectService, ScanService


def _plan(asset_id: str) -> TestPlanContext:
    return TestPlanContext(
        scan_id="scan",
        test_plan_id="plan",
        asset_ids=[asset_id],
        vulnerability_class_ids=["class"],
        class_codes=["AUTHENTICATION"],
        required_capabilities=[Capability.TEMPLATE_BASED_ASSESSMENT.value],
        testing_mode="AUTOMATED",
        safety_class=SafetyClass.LOW_IMPACT.value,
        authorization_requirement="PRE_APPROVED",
        target_url="https://app.example.com",
        asset_type="WEB_APPLICATION",
    )


@pytest.mark.asyncio
async def test_credential_not_required(db_session) -> None:
    project = await ProjectService(db_session).create("Cred")
    scan = await ScanService(db_session).create(project.id, "Cred Scan", [])
    req = TestRequirement(
        matrix_id=uuid.uuid4(),
        vulnerability_class_id=uuid.uuid4(),
        credential_requirement=None,
    )
    decision = await CredentialCompatibilityPolicy(db_session).evaluate(
        scan_id=scan.id,
        requirement=req,
        plan=_plan(str(uuid.uuid4())),
        provider_id="nuclei",
        asset_id=str(uuid.uuid4()),
    )
    assert decision.compatible


@pytest.mark.asyncio
async def test_required_credential_available(db_session) -> None:
    project = await ProjectService(db_session).create("Cred Available")
    scan = await ScanService(db_session).create(project.id, "Scan", [])
    asset = Asset(
        scan_id=scan.id,
        project_id=project.id,
        asset_type="WEB_APPLICATION",
        normalized_key="https://app.example.com",
        display_name="app",
        metadata_={"base_url": "https://app.example.com"},
    )
    db_session.add(asset)
    cred = CredentialReference(
        project_id=project.id,
        credential_type=CredentialType.HTTP_BASIC.value,
        secret_backend_reference="vault://test",
        role_name="user",
    )
    db_session.add(cred)
    await db_session.flush()
    auth_ctx = AuthenticationContext(
        scan_id=scan.id,
        credential_id=cred.id,
        asset_id=asset.id,
        auth_method="BASIC",
    )
    db_session.add(auth_ctx)
    await db_session.flush()
    req = TestRequirement(
        matrix_id=uuid.uuid4(),
        vulnerability_class_id=uuid.uuid4(),
        credential_requirement="AUTHENTICATED",
    )
    decision = await CredentialCompatibilityPolicy(db_session).evaluate(
        scan_id=scan.id,
        requirement=req,
        plan=_plan(str(asset.id)),
        provider_id="nuclei",
        asset_id=str(asset.id),
    )
    assert decision.compatible
    assert decision.credential_context_id == str(auth_ctx.id)


@pytest.mark.asyncio
async def test_required_credential_unavailable(db_session) -> None:
    project = await ProjectService(db_session).create("Cred Missing")
    scan = await ScanService(db_session).create(project.id, "Scan", [])
    req = TestRequirement(
        matrix_id=uuid.uuid4(),
        vulnerability_class_id=uuid.uuid4(),
        credential_requirement="AUTHENTICATED",
    )
    decision = await CredentialCompatibilityPolicy(db_session).evaluate(
        scan_id=scan.id,
        requirement=req,
        plan=_plan(str(uuid.uuid4())),
        provider_id="nuclei",
        asset_id=str(uuid.uuid4()),
    )
    assert not decision.compatible
    assert "CREDENTIAL_CONTEXT_REQUIRED" in decision.reason_codes
