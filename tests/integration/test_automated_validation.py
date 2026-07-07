"""Automated validation execution and analyst-review handoff."""

import uuid

import pytest
from sqlalchemy import select

from vapt_platform.db.tables.models import (
    AssetTestMatrix,
    ConfirmedFinding,
    Event,
    EvidenceLink,
    Hypothesis,
    ValidationTask,
    Verdict,
)
from vapt_platform.db.tables.models import TestExecution as ExecutionModel
from vapt_platform.db.tables.models import TestPlan as PlanModel
from vapt_platform.db.tables.models import TestRequirement as RequirementModel
from vapt_platform.domain.enums import (
    HypothesisStatus,
    SafetyClass,
)
from vapt_platform.domain.enums import TestingMode as Mode
from vapt_platform.domain.enums import TestPlanStatus as PlanStatus
from vapt_platform.domain.enums import (
    TestRequirementCoverageStatus as CoverageStatus,
)
from vapt_platform.engines.assessment import TestPlanner as Planner
from vapt_platform.services.automated_validation import (
    AutomatedValidationOrchestrator,
)
from vapt_platform.services.core import ProjectService, ScanService


@pytest.mark.asyncio
async def test_automated_plans_reuse_tasks_and_create_review_backlog(
    db_session,
) -> None:
    project = await ProjectService(db_session).create("Automated Validation")
    scan = await ScanService(db_session).create(
        project.id,
        "Automated Validation Scan",
        [{"rule_type": "ROOT_DOMAIN", "pattern": "example.com", "priority": 100}],
    )
    await db_session.commit()
    await ScanService(db_session).start(scan.id)
    await Planner(db_session).plan_scan(scan.id)
    await db_session.flush()

    orchestrator = AutomatedValidationOrchestrator(db_session)
    first = await orchestrator.execute_scan(scan.id)
    await db_session.flush()

    completed = [item for item in first if item.execution_id]
    candidates = [item for item in completed if item.finding_candidates]
    assert completed
    assert candidates

    candidate_run = candidates[0]
    plan = await db_session.get(PlanModel, candidate_run.plan_id)
    execution = await db_session.get(ExecutionModel, candidate_run.execution_id)
    assert plan is not None
    assert execution is not None
    assert plan.testing_mode == Mode.AUTOMATED.value
    assert plan.status == PlanStatus.COMPLETED.value
    assert execution.status == "COMPLETED"
    assert execution.evidence_ids
    assert execution.result_summary["finding_candidate_count"] >= 1

    review_task = (
        await db_session.execute(
            select(ValidationTask).where(ValidationTask.test_plan_id == plan.id)
        )
    ).scalar_one()
    assert review_task.testing_mode == Mode.ASSISTED.value
    assert review_task.hypothesis_id == plan.hypothesis_id

    hypothesis = await db_session.get(Hypothesis, plan.hypothesis_id)
    assert hypothesis is not None
    assert hypothesis.status == HypothesisStatus.VALIDATION_IN_PROGRESS.value
    assert (
        await db_session.execute(
            select(Verdict).where(Verdict.hypothesis_id == hypothesis.id)
        )
    ).scalar_one_or_none() is None

    matrix = (
        await db_session.execute(
            select(AssetTestMatrix).where(
                AssetTestMatrix.scan_id == scan.id,
                AssetTestMatrix.asset_id.in_(
                    [uuid.UUID(value) for value in plan.asset_ids]
                ),
            )
        )
    ).scalars().first()
    assert matrix is not None
    requirement = (
        await db_session.execute(
            select(RequirementModel).where(
                RequirementModel.matrix_id == matrix.id,
                RequirementModel.vulnerability_class_id.in_(
                    [uuid.UUID(value) for value in plan.vulnerability_class_ids]
                ),
            )
        )
    ).scalar_one()
    assert (
        requirement.coverage_status
        == CoverageStatus.PARTIALLY_TESTED.value
    )

    events = list(
        (
            await db_session.execute(
                select(Event).where(
                    Event.scan_id == scan.id,
                    Event.event_type == "TEST_EXECUTION_COMPLETED",
                )
            )
        )
        .scalars()
        .all()
    )
    assert events

    execution_count = len(
        list(
            (
                await db_session.execute(
                    select(ExecutionModel).join(
                        PlanModel, ExecutionModel.test_plan_id == PlanModel.id
                    ).where(PlanModel.scan_id == scan.id)
                )
            )
            .scalars()
            .all()
        )
    )
    second = await orchestrator.execute_scan(scan.id)
    await db_session.flush()
    second_execution_count = len(
        list(
            (
                await db_session.execute(
                    select(ExecutionModel).join(
                        PlanModel, ExecutionModel.test_plan_id == PlanModel.id
                    ).where(PlanModel.scan_id == scan.id)
                )
            )
            .scalars()
            .all()
        )
    )
    assert second_execution_count == execution_count
    assert any(item.reason == "Existing test execution reused" for item in second)


@pytest.mark.asyncio
async def test_state_changing_automated_plan_is_not_executed(db_session) -> None:
    project = await ProjectService(db_session).create("Safety Gate")
    scan = await ScanService(db_session).create(
        project.id,
        "Safety Gate Scan",
        [{"rule_type": "ROOT_DOMAIN", "pattern": "example.com"}],
    )
    plan = PlanModel(
        scan_id=scan.id,
        asset_ids=[],
        testing_mode=Mode.AUTOMATED.value,
        required_capabilities=["TEMPLATE_BASED_ASSESSMENT"],
        safety_class=SafetyClass.STATE_CHANGING.value,
        authorization_requirement="ANALYST_APPROVAL_REQUIRED",
        status=PlanStatus.PENDING_APPROVAL.value,
    )
    db_session.add(plan)
    await db_session.flush()

    result = await AutomatedValidationOrchestrator(db_session).execute_plan(plan)

    assert result.status == "SKIPPED"
    assert "not executable" in (result.reason or "")
    assert (
        await db_session.execute(
            select(ExecutionModel).where(ExecutionModel.test_plan_id == plan.id)
        )
    ).scalar_one_or_none() is None


@pytest.mark.asyncio
async def test_conclusive_negative_execution_rejects_without_confirming(
    db_session,
    monkeypatch,
) -> None:
    from vapt_platform.adapters.fake.providers import AdapterOutput, FAKE_ADAPTERS

    fake_nuclei = FAKE_ADAPTERS["fake-nuclei"]

    def no_findings(target, profile="STANDARD"):
        return AdapterOutput(
            stdout='{"findings": []}',
            exit_code=0,
            observations=[],
            events=[],
        )

    monkeypatch.setattr(fake_nuclei, "execute", no_findings)

    project = await ProjectService(db_session).create("Negative Validation")
    scan = await ScanService(db_session).create(
        project.id,
        "Negative Validation Scan",
        [{"rule_type": "ROOT_DOMAIN", "pattern": "example.com", "priority": 100}],
    )
    await db_session.commit()
    await ScanService(db_session).start(scan.id)
    await Planner(db_session).plan_scan(scan.id)
    results = await AutomatedValidationOrchestrator(db_session).execute_scan(scan.id)
    await db_session.flush()

    negative = next(
        item
        for item in results
        if item.execution_id and item.finding_candidates == 0
    )
    plan = await db_session.get(PlanModel, negative.plan_id)
    assert plan is not None
    hypothesis = await db_session.get(Hypothesis, plan.hypothesis_id)
    assert hypothesis is not None
    assert hypothesis.status == HypothesisStatus.REJECTED.value

    verdict = (
        await db_session.execute(
            select(Verdict).where(Verdict.hypothesis_id == hypothesis.id)
        )
    ).scalar_one()
    assert verdict.status == "REJECTED"
    assert verdict.validation_result_id is None
    assert verdict.rule_ids == ["verdict-automated"]

    evidence_link = (
        await db_session.execute(
            select(EvidenceLink).where(
                EvidenceLink.target_id == hypothesis.id,
                EvidenceLink.link_type == "REJECTS",
            )
        )
    ).scalar_one()
    assert evidence_link.source_type == "TEST_EXECUTION"
    assert evidence_link.source_id == negative.execution_id

    findings = list(
        (
            await db_session.execute(
                select(ConfirmedFinding).where(
                    ConfirmedFinding.scan_id == scan.id
                )
            )
        )
        .scalars()
        .all()
    )
    assert findings == []
