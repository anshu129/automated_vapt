"""Phase E - per-asset test matrix depth."""

import pytest
from sqlalchemy import select

from vapt_platform.db.tables.models import (
    Asset,
    AssetVulnerabilityApplicability,
    VulnerabilityClass,
)
from vapt_platform.db.tables.models import (
    TestPlan as PlanModel,
)
from vapt_platform.db.tables.models import (
    TestRequirement as RequirementModel,
)
from vapt_platform.domain.enums import (
    ApplicabilityState,
    AssetType,
)
from vapt_platform.domain.enums import (
    TestingMode as Mode,
)
from vapt_platform.domain.enums import (
    TestPlanStatus as PlanStatus,
)
from vapt_platform.domain.enums import (
    TestRequirementCoverageStatus as CoverageStatus,
)
from vapt_platform.domain.enums import (
    TestRequirementNextAction as NextAction,
)
from vapt_platform.engines.assessment import TestMatrixEngine as MatrixEngine
from vapt_platform.services.core import ProjectService, ScanService


async def _seed_asset_applicability(db_session, name: str):
    project = await ProjectService(db_session).create(name)
    scan = await ScanService(db_session).create(
        project.id,
        f"{name} Scan",
        [{"rule_type": "ROOT_DOMAIN", "pattern": "example.com"}],
    )
    web_app = Asset(
        scan_id=scan.id,
        project_id=project.id,
        asset_type=AssetType.WEB_APPLICATION.value,
        normalized_key="https://www.example.com",
        display_name="Example App",
        metadata_={"http_confirmed": True, "base_url": "https://www.example.com"},
    )
    db_session.add(web_app)
    await db_session.flush()

    classes = {
        vc.class_code: vc
        for vc in (await db_session.execute(select(VulnerabilityClass))).scalars().all()
    }
    app_specs = [
        ("SECURITY_HEADERS", ApplicabilityState.APPLICABLE.value, 0.85, ["web-app-baseline"]),
        ("AUTHENTICATION", ApplicabilityState.APPLICABLE.value, 0.85, ["web-app-baseline"]),
        (
            "KNOWN_COMPONENT_VULNERABILITY",
            ApplicabilityState.POSSIBLY_APPLICABLE.value,
            0.5,
            ["known-component-technology-only"],
        ),
    ]
    for class_code, state, confidence, rule_ids in app_specs:
        db_session.add(
            AssetVulnerabilityApplicability(
                scan_id=scan.id,
                asset_id=web_app.id,
                vulnerability_class_id=classes[class_code].id,
                applicability_state=state,
                confidence=confidence,
                supporting_evidence_ids=[str(web_app.id)],
                rule_ids=rule_ids,
                explanation=f"{class_code} seeded for matrix test",
            )
        )

    matrix = await MatrixEngine(db_session).build(scan.id, web_app.id)
    await db_session.flush()
    return web_app, matrix


async def _requirements_by_class(db_session, matrix_id):
    reqs = list(
        (
            await db_session.execute(
                select(RequirementModel).where(RequirementModel.matrix_id == matrix_id)
            )
        )
        .scalars()
        .all()
    )
    class_map = {
        vc.id: vc.class_code
        for vc in (await db_session.execute(select(VulnerabilityClass))).scalars().all()
    }
    return {class_map[req.vulnerability_class_id]: req for req in reqs}


@pytest.mark.asyncio
async def test_phase_e_matrix_has_evidence_requirements_and_actions(db_session) -> None:
    _, matrix = await _seed_asset_applicability(db_session, "Phase E Matrix")
    by_code = await _requirements_by_class(db_session, matrix.id)

    security_headers = by_code["SECURITY_HEADERS"]
    assert security_headers.applicability_state == "APPLICABLE"
    assert security_headers.testing_mode == Mode.AUTOMATED.value
    assert security_headers.coverage_status == CoverageStatus.NOT_TESTED.value
    assert security_headers.next_action == NextAction.PLAN_AUTOMATED.value
    assert "TEMPLATE_BASED_ASSESSMENT" in security_headers.eligible_capabilities
    assert security_headers.required_evidence["class_code"] == "SECURITY_HEADERS"
    assert security_headers.required_evidence["required"]

    authentication = by_code["AUTHENTICATION"]
    assert authentication.testing_mode == Mode.MANUAL.value
    assert authentication.next_action == NextAction.PLAN_MANUAL.value
    assert authentication.required_evidence["required"][0]["evidence_type"] == "AUTH_FLOW_REVIEW"

    known_component = by_code["KNOWN_COMPONENT_VULNERABILITY"]
    assert known_component.applicability_state == "POSSIBLY_APPLICABLE"
    assert known_component.testing_mode == Mode.ASSISTED.value
    assert known_component.next_action == NextAction.PLAN_ASSISTED.value

    business_logic = by_code["BUSINESS_LOGIC"]
    assert business_logic.coverage_status == CoverageStatus.NOT_APPLICABLE.value
    assert business_logic.next_action == NextAction.NONE.value


@pytest.mark.asyncio
async def test_matrix_coverage_reflects_pending_plan(db_session) -> None:
    web_app, matrix = await _seed_asset_applicability(db_session, "Phase E Planned")
    by_code = await _requirements_by_class(db_session, matrix.id)
    security_headers = by_code["SECURITY_HEADERS"]

    plan = PlanModel(
        scan_id=matrix.scan_id,
        asset_ids=[str(web_app.id)],
        vulnerability_class_ids=[str(security_headers.vulnerability_class_id)],
        testing_mode=Mode.AUTOMATED.value,
        required_capabilities=["TEMPLATE_BASED_ASSESSMENT"],
        safety_class="STATE_CHANGING",
        authorization_requirement="ANALYST_APPROVAL_REQUIRED",
        status=PlanStatus.PENDING_APPROVAL.value,
        reasoning_trace={"rule_ids": ["test"]},
    )
    db_session.add(plan)
    await db_session.flush()

    await MatrixEngine(db_session).build(matrix.scan_id, web_app.id)
    await db_session.flush()

    by_code = await _requirements_by_class(db_session, matrix.id)
    security_headers = by_code["SECURITY_HEADERS"]
    assert security_headers.coverage_status == CoverageStatus.PLANNED.value
    assert security_headers.next_action == NextAction.AWAIT_APPROVAL.value
