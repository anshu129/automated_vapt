"""Phase F - test planner from matrix requirements."""

import pytest
from sqlalchemy import select

from vapt_platform.db.tables.models import (
    Asset,
    AssetVulnerabilityApplicability,
    Event,
    EvidencePackage,
    ValidationTask,
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
from vapt_platform.engines.assessment import TestPlanner as Planner
from vapt_platform.services.core import ProjectService, ScanService


async def _seed_phase_f_matrix(db_session):
    project = await ProjectService(db_session).create("Phase F Project")
    scan = await ScanService(db_session).create(
        project.id,
        "Phase F Scan",
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
    for class_code, state, confidence in (
        ("SECURITY_HEADERS", ApplicabilityState.APPLICABLE.value, 0.9),
        ("KNOWN_COMPONENT_VULNERABILITY", ApplicabilityState.POSSIBLY_APPLICABLE.value, 0.5),
        ("AUTHENTICATION", ApplicabilityState.APPLICABLE.value, 0.85),
    ):
        db_session.add(
            AssetVulnerabilityApplicability(
                scan_id=scan.id,
                asset_id=web_app.id,
                vulnerability_class_id=classes[class_code].id,
                applicability_state=state,
                confidence=confidence,
                supporting_evidence_ids=[str(web_app.id)],
                rule_ids=["phase-f-seed"],
                explanation=f"{class_code} seeded for planner test",
            )
        )

    matrix = await MatrixEngine(db_session).build(scan.id, web_app.id)
    await db_session.flush()
    return scan, web_app, matrix, classes


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
async def test_phase_f_planner_creates_mode_specific_plans(db_session) -> None:
    scan, web_app, matrix, classes = await _seed_phase_f_matrix(db_session)

    plans = await Planner(db_session).plan_scan(scan.id)
    await db_session.flush()

    assert len(plans) == 3
    assert all(plan.hypothesis_id for plan in plans)
    plans_by_class = {
        next(
            code
            for code, vc in classes.items()
            if str(vc.id) in plan.vulnerability_class_ids
        ): plan
        for plan in plans
    }

    security_headers = plans_by_class["SECURITY_HEADERS"]
    assert security_headers.testing_mode == Mode.AUTOMATED.value
    assert security_headers.status == PlanStatus.APPROVED.value
    assert security_headers.safety_class == "LOW_IMPACT"
    assert security_headers.authorization_requirement == "PRE_APPROVED"
    assert "TEMPLATE_BASED_ASSESSMENT" in security_headers.required_capabilities

    known_component = plans_by_class["KNOWN_COMPONENT_VULNERABILITY"]
    assert known_component.testing_mode == Mode.ASSISTED.value
    assert known_component.status == PlanStatus.SCHEDULED.value
    assisted_task = (
        await db_session.execute(
            select(ValidationTask).where(ValidationTask.test_plan_id == known_component.id)
        )
    ).scalar_one()
    assert assisted_task.testing_mode == Mode.ASSISTED.value
    assert assisted_task.hypothesis_id == known_component.hypothesis_id
    package = (
        await db_session.execute(
            select(EvidencePackage).where(EvidencePackage.validation_task_id == assisted_task.id)
        )
    ).scalar_one()
    assert package.package_data["class_code"] == "KNOWN_COMPONENT_VULNERABILITY"
    assert package.hypothesis_id == known_component.hypothesis_id

    authentication = plans_by_class["AUTHENTICATION"]
    assert authentication.testing_mode == Mode.MANUAL.value
    manual_task = (
        await db_session.execute(
            select(ValidationTask).where(ValidationTask.test_plan_id == authentication.id)
        )
    ).scalar_one()
    assert manual_task.testing_mode == Mode.MANUAL.value
    assert manual_task.hypothesis_id == authentication.hypothesis_id
    assert str(web_app.id) in manual_task.asset_ids

    by_code = await _requirements_by_class(db_session, matrix.id)
    assert by_code["SECURITY_HEADERS"].coverage_status == CoverageStatus.PLANNED.value
    assert by_code["SECURITY_HEADERS"].next_action == NextAction.AWAIT_EXECUTION.value


@pytest.mark.asyncio
async def test_phase_f_planner_is_idempotent_and_emits_events(db_session) -> None:
    scan, _, _, _ = await _seed_phase_f_matrix(db_session)

    first = await Planner(db_session).plan_scan(scan.id)
    second = await Planner(db_session).plan_scan(scan.id)
    await db_session.flush()

    assert len(first) == 3
    assert second == []
    plans = list(
        (await db_session.execute(select(PlanModel).where(PlanModel.scan_id == scan.id)))
        .scalars()
        .all()
    )
    assert len(plans) == 3

    events = list(
        (
            await db_session.execute(
                select(Event).where(
                    Event.scan_id == scan.id,
                    Event.event_type == "TEST_PLAN_CREATED",
                )
            )
        )
        .scalars()
        .all()
    )
    assert len(events) == 3
    assert {event.payload["testing_mode"] for event in events} == {
        Mode.AUTOMATED.value,
        Mode.ASSISTED.value,
        Mode.MANUAL.value,
    }
    assert all(event.payload["hypothesis_id"] for event in events)
