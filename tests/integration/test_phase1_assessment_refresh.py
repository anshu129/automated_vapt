"""Phase 1 — assessment refresh chain integration test."""

from sqlalchemy import select

from vapt_platform.db.tables.models import Asset, TestRequirement, VulnerabilityClass
from vapt_platform.domain.enums import ApplicabilityState, AssetType
from vapt_platform.engines.assessment import TestMatrixEngine, TestPlanner
from vapt_platform.services.core import ProjectService, ScanService
from vapt_platform.services.full_assessment import FullAssessmentService


async def test_assessment_refresh_enriches_requirements_and_planner_sees_fresh_state(
    db_session,
) -> None:
    project = await ProjectService(db_session).create("Phase 1 Project")
    scan = await ScanService(db_session).create(
        project.id,
        "Phase 1 Scan",
        [{"rule_type": "URL_PREFIX", "pattern": "https://app.example.com", "priority": 90}],
    )
    await db_session.commit()

    await ScanService(db_session).start(scan.id)
    await db_session.commit()

    refresh = await FullAssessmentService(db_session).refresh_assessment_state(scan.id)
    await db_session.commit()

    assert refresh.assets_refreshed >= 1
    assert refresh.matrices_built >= 1
    assert refresh.applicable_requirements >= 1

    web_app = (
        await db_session.execute(
            select(Asset).where(
                Asset.scan_id == scan.id,
                Asset.asset_type == AssetType.WEB_APPLICATION.value,
            )
        )
    ).scalar_one()

    classes = {
        row.class_code: row
        for row in (await db_session.execute(select(VulnerabilityClass))).scalars().all()
    }
    matrix = await TestMatrixEngine(db_session).build(scan.id, web_app.id)
    await db_session.commit()

    auth_req = (
        await db_session.execute(
            select(TestRequirement).where(
                TestRequirement.matrix_id == matrix.id,
                TestRequirement.vulnerability_class_id == classes["AUTHENTICATION"].id,
            )
        )
    ).scalar_one()

    assert auth_req.applicability_state == ApplicabilityState.APPLICABLE.value
    assert auth_req.source_rule_ids
    assert auth_req.reasoning_trace.get("source_rule_ids")
    assert auth_req.reasoning_trace.get("why")
    assert auth_req.required_capability is not None
    assert len(auth_req.eligible_capabilities) >= 1
    assert auth_req.safety_class is not None

    obj_req = (
        await db_session.execute(
            select(TestRequirement).where(
                TestRequirement.matrix_id == matrix.id,
                TestRequirement.vulnerability_class_id
                == classes["OBJECT_LEVEL_AUTHORIZATION"].id,
            )
        )
    ).scalar_one()
    assert "AUTHORIZATION_SURFACE_ANALYSIS" in obj_req.eligible_capabilities
    assert "MANUAL_VALIDATION" in obj_req.eligible_capabilities
    assert obj_req.credential_requirement == "AUTHENTICATED"

    plans = await TestPlanner(db_session).plan_scan(scan.id)
    await db_session.commit()
    assert len(plans) >= 1
    auth_class_id = str(classes["AUTHENTICATION"].id)
    assert any(auth_class_id in (plan.vulnerability_class_ids or []) for plan in plans)


async def test_prepare_for_planning_runs_refresh_after_inline_recon(db_session) -> None:
    project = await ProjectService(db_session).create("Phase 1 Recon")
    scan = await ScanService(db_session).create(
        project.id,
        "Recon Scan",
        [{"rule_type": "HOSTNAME", "pattern": "scan.example.com", "priority": 100}],
    )
    await db_session.commit()
    await ScanService(db_session).start(scan.id)
    await db_session.commit()

    summary = await FullAssessmentService(db_session).prepare_for_planning(scan.id)
    await db_session.commit()

    assert summary.assets_refreshed >= 1
    assert summary.requirements_enriched >= 0
