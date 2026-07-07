"""End-to-end attack surface and vulnerability assessment outputs."""

import pytest
from sqlalchemy import select

from vapt_platform.api.routes.core import (
    evidence_packages,
    list_assets,
    list_confirmed_findings,
    list_evidence_links,
    list_hypotheses,
    list_relationships,
    list_test_plans,
    list_validation_results,
    list_verdicts,
    scan_report,
    scan_surface_coverage,
    scan_test_matrix,
    scan_vulnerability_applicability,
    validation_backlog,
)
from vapt_platform.db.tables.models import ValidationTask
from vapt_platform.engines.assessment import TestPlanner as Planner
from vapt_platform.services.core import ProjectService, ScanService, ValidationService


@pytest.mark.asyncio
async def test_full_assessment_workflow_outputs(db_session) -> None:
    project = await ProjectService(db_session).create("Full Assessment")
    scan = await ScanService(db_session).create(
        project.id,
        "example.com full assessment",
        [{"rule_type": "ROOT_DOMAIN", "pattern": "example.com", "priority": 100}],
    )
    await db_session.commit()

    await ScanService(db_session).start(scan.id)
    await Planner(db_session).plan_scan(scan.id)
    await db_session.flush()

    validation_task = (
        await db_session.execute(
            select(ValidationTask).where(
                ValidationTask.scan_id == scan.id,
                ValidationTask.testing_mode == "MANUAL",
            )
        )
    ).scalars().first()
    assert validation_task is not None
    assert validation_task.hypothesis_id is not None
    with pytest.raises(ValueError, match="requires evidence"):
        await ValidationService(db_session).record_result(
            validation_task.id,
            "CONFIRMED",
            "This result must be rejected because it has no evidence.",
            [],
        )
    validation_result = await ValidationService(db_session).record_result(
        validation_task.id,
        "CONFIRMED",
        "Confirmed through an authorized manual review.",
        ["evidence-manual-review-1"],
        recorded_by="integration-tester",
    )
    await db_session.flush()

    assets = await list_assets(scan.id, db_session)
    relationships = await list_relationships(scan.id, db_session)
    surface = await scan_surface_coverage(scan.id, asset_type=None, session=db_session)
    applicability = await scan_vulnerability_applicability(
        scan.id, state=None, session=db_session
    )
    matrix = await scan_test_matrix(scan.id, db_session)
    plans = await list_test_plans(scan.id, db_session)
    hypotheses = await list_hypotheses(scan.id, db_session)
    backlog = await validation_backlog(scan.id, db_session)
    packages = await evidence_packages(scan.id, db_session)
    validation_results = await list_validation_results(scan.id, db_session)
    evidence_links = await list_evidence_links(scan.id, db_session)
    verdicts = await list_verdicts(scan.id, db_session)
    findings = await list_confirmed_findings(scan.id, db_session)
    report = await scan_report(scan.id, db_session)

    assert assets["total"] >= 8
    assert {item["asset_type"] for item in assets["items"]} >= {
        "DOMAIN",
        "HOSTNAME",
        "IP_ADDRESS",
        "SERVICE",
        "WEB_APPLICATION",
        "ENDPOINT",
    }
    assert all("metadata" in item for item in assets["items"])

    assert relationships["total"] >= 4
    relationship_types = {
        item["relationship_type"] for item in relationships["items"]
    }
    assert {"HAS_SUBDOMAIN", "RESOLVES_TO", "CONTAINS"} <= relationship_types
    assert all(item["source"] and item["target"] for item in relationships["items"])

    assert surface["total"] >= 1
    assert applicability["total"] >= 6
    assert matrix["total"] >= 1
    assert any(item["requirements"] for item in matrix["items"])
    assert any(
        requirement["coverage_status"] == "CONFIRMED_ISSUE"
        for item in matrix["items"]
        for requirement in item["requirements"]
    )
    assert plans["total"] >= 6
    assert hypotheses["total"] == plans["total"]
    assert backlog["items"]
    assert packages["items"]
    assert validation_results["total"] == 1
    assert validation_results["items"][0]["outcome"] == "CONFIRMED"
    assert evidence_links["total"] == 1
    assert evidence_links["items"][0]["link_type"] == "CONFIRMS"
    assert verdicts["total"] == 1
    assert verdicts["items"][0]["validation_result_id"] == str(validation_result.id)
    assert verdicts["items"][0]["status"] == "CONFIRMED"
    assert findings["total"] == 1
    assert findings["items"][0]["evidence_ids"] == ["evidence-manual-review-1"]
    assert findings["items"][0]["confirmed_by"] == "integration-tester"

    assert report["summary"]["assets"] == assets["total"]
    assert report["summary"]["relationships"] == relationships["total"]
    assert report["summary"]["test_plans"] == plans["total"]
    assert report["summary"]["hypotheses"] == hypotheses["total"]
    assert report["summary"]["validation_results"] == validation_results["total"]
    assert report["summary"]["evidence_links"] == evidence_links["total"]
    assert report["summary"]["verdicts"] == verdicts["total"]
    assert report["summary"]["confirmed_findings"] == findings["total"]
    assert report["relationships"]
    assert report["test_plans"]
    assert report["validation_backlog"]
    assert report["validation_results"]
    assert report["evidence_links"]
    assert report["hypotheses"]
    assert report["verdicts"]
    assert report["confirmed_findings"]
