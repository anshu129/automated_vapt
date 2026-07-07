"""Phase I - credential references and authenticated coverage."""

import json
import uuid

import pytest
from sqlalchemy import select

from vapt_platform.api.routes.core import (
    get_credential_reference,
    list_project_credentials,
    scan_auth_coverage,
    scan_report,
    scan_role_coverage,
)
from vapt_platform.controller.recon_controller import ReconController
from vapt_platform.db.tables.models import Asset
from vapt_platform.domain.enums import AssetType, Capability
from vapt_platform.mcp.read_tools import AssessmentMCPReadService
from vapt_platform.scope.manager import ScopeManager, ScopeRuleData
from vapt_platform.services.core import ProjectService, ScanService, build_target_descriptor
from vapt_platform.services.credentials import CredentialContextService


@pytest.mark.asyncio
async def test_credential_context_metadata_is_bound_and_secret_safe(db_session) -> None:
    project = await ProjectService(db_session).create("Credential Context")
    scan = await ScanService(db_session).create(
        project.id,
        "Authenticated Coverage Scan",
        [{"rule_type": "ROOT_DOMAIN", "pattern": "example.com", "priority": 100}],
    )
    await db_session.commit()
    await ScanService(db_session).start(scan.id)
    await db_session.flush()

    web_app = (
        (
            await db_session.execute(
                select(Asset).where(
                    Asset.scan_id == scan.id,
                    Asset.asset_type == AssetType.WEB_APPLICATION.value,
                )
            )
        )
        .scalars()
        .first()
    )
    assert web_app is not None

    secret_ref = "env://VAPT_TEST_PASSWORD"
    service = CredentialContextService(db_session)
    credential = await service.create_reference(
        project.id,
        "HTTP_BASIC",
        secret_ref,
        label="Authorized user",
        role_name="user",
        allowed_capabilities=[Capability.WEB_ACTIVE_ASSESSMENT.value],
    )
    binding = await service.create_binding(
        credential.id,
        application_id=web_app.id,
        url_prefix=web_app.normalized_key,
    )
    auth_context = await service.bind_session(
        credential.id,
        web_app.id,
        scan_id=scan.id,
        coverage_dimensions=["AUTHENTICATED", "AUTHORIZATION"],
        coverage_status={"AUTHENTICATED": "COMPLETE", "AUTHORIZATION": "PARTIAL"},
    )
    await db_session.flush()

    eligible = await service.get_eligible_credentials(web_app.id, Capability.WEB_ACTIVE_ASSESSMENT)
    assert [item.id for item in eligible] == [credential.id]
    assert binding.assessment_mode == "CREDENTIALED"
    assert auth_context.session_established is True

    credential_item = await get_credential_reference(credential.id, db_session)
    project_credentials = await list_project_credentials(project.id, db_session)
    auth_coverage = await scan_auth_coverage(scan.id, db_session)
    role_coverage = await scan_role_coverage(scan.id, db_session)
    report = await scan_report(scan.id, db_session)
    mcp_auth = await AssessmentMCPReadService(db_session).get_auth_coverage(scan.id)
    mcp_roles = await AssessmentMCPReadService(db_session).get_role_coverage(scan.id)

    assert credential_item["secret_backend_reference_present"] is True
    assert "secret_backend_reference" not in credential_item
    assert project_credentials["total"] == 1
    assert auth_coverage["secret_values_excluded"] is True
    assert role_coverage["secret_values_excluded"] is True
    assert mcp_auth == auth_coverage
    assert mcp_roles == role_coverage
    assert report["summary"]["authenticated_assets"] >= 1
    assert report["summary"]["authorized_roles"] >= 1

    web_auth = next(item for item in auth_coverage["items"] if item["asset_id"] == str(web_app.id))
    assert web_auth["auth_coverage_status"] == "AUTHENTICATED"
    assert set(web_auth["coverage_dimensions"]) == {"AUTHENTICATED", "AUTHORIZATION"}
    assert web_auth["roles"] == ["user"]
    assert role_coverage["items"][0]["coverage_status"]["AUTHORIZATION"] == "PARTIAL"

    serialized = json.dumps(
        {
            "credential_item": credential_item,
            "project_credentials": project_credentials,
            "auth_coverage": auth_coverage,
            "role_coverage": role_coverage,
            "report": report,
            "mcp_auth": mcp_auth,
            "mcp_roles": mcp_roles,
        },
        sort_keys=True,
    )
    assert secret_ref not in serialized


@pytest.mark.asyncio
async def test_runtime_credentials_do_not_persist_to_task_descriptor(db_session) -> None:
    project = await ProjectService(db_session).create("Runtime Credential Safety")
    scan = await ScanService(db_session).create(
        project.id,
        "Runtime Credential Safety Scan",
        [{"rule_type": "URL_PREFIX", "pattern": "https://example.com", "priority": 100}],
    )
    await db_session.flush()

    descriptor = build_target_descriptor("https://user:Secret123@example.com/admin")
    assert descriptor["url"] == "https://example.com/admin"
    assert descriptor["operational_context"]["auth_required"] is True
    assert "username" not in descriptor
    assert "password" not in descriptor

    controller = ReconController(
        db_session,
        ScopeManager(
            [
                ScopeRuleData(
                    "URL_PREFIX",
                    "https://example.com",
                    "ACTIVE",
                    100,
                )
            ]
        ),
    )
    task = await controller.create_task(
        scan.id,
        Capability.HTTP_PROBING,
        {"url": "https://example.com", "hostname": "example.com"},
        uuid.uuid4(),
    )
    assert task is not None

    result = await ScanService(db_session).run_ready_tasks(
        scan.id,
        limit=1,
        username="user",
        password="Secret123",
    )
    await db_session.refresh(task)

    assert result["executed"] == 1
    serialized_task = json.dumps(
        {
            "target_descriptor": task.target_descriptor,
            "parameters": task.parameters,
        },
        sort_keys=True,
    )
    assert "Secret123" not in serialized_task
    assert "password" not in (task.target_descriptor or {})
    assert "username" not in (task.target_descriptor or {})
