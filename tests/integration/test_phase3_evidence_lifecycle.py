"""Phase 3 evidence lifecycle integration tests."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from vapt_platform.db.tables.models import (
    ConfirmedFinding,
    EvidenceLink,
    EvidenceNode,
    Hypothesis,
    ScannerFinding,
    TestExecution,
    TestPlan,
    Verdict,
    VerdictTransition,
)
from vapt_platform.domain.capability_provider import ProviderExecutionResult
from vapt_platform.domain.enums import TestPlanStatus, TestingMode, VerdictStatus
from vapt_platform.engines.assessment import TestPlanner
from vapt_platform.services.core import ProjectService, ScanService
from vapt_platform.services.evidence_ingestion import EvidenceIngestionService
from vapt_platform.services.full_assessment import FullAssessmentService
from vapt_platform.services.result_normalizer import NormalizationContext


async def _seed_scan(db_session):
    project = await ProjectService(db_session).create("Phase 3 Project")
    scan = await ScanService(db_session).create(
        project.id,
        "Phase 3 Scan",
        [{"rule_type": "URL_PREFIX", "pattern": "https://app.example.com", "priority": 90}],
    )
    await ScanService(db_session).start(scan.id)
    await FullAssessmentService(db_session).refresh_assessment_state(scan.id)
    await TestPlanner(db_session).plan_scan(scan.id)
    await db_session.commit()
    return scan


@pytest.mark.asyncio
async def test_positive_scanner_insufficient_confirmation_no_confirmed_finding(db_session) -> None:
    scan = await _seed_scan(db_session)
    plan = (
        await db_session.execute(select(TestPlan).where(TestPlan.scan_id == scan.id))
    ).scalars().first()
    assert plan is not None
    hypothesis = await db_session.get(Hypothesis, plan.hypothesis_id)
    assert hypothesis is not None

    execution = TestExecution(
        test_plan_id=plan.id,
        selected_provider_id="nuclei",
        executed_capability="TEMPLATE_BASED_ASSESSMENT",
        status="COMPLETED",
    )
    db_session.add(execution)
    await db_session.flush()

    result = ProviderExecutionResult(
        provider_id="nuclei",
        capability="TEMPLATE_BASED_ASSESSMENT",
        status="CORROBORATED",
        findings=[
            {
                "template_id": "header-missing",
                "name": "Missing header",
                "severity": "medium",
                "matched_at": "https://app.example.com",
                "tags": ["misconfig"],
            }
        ],
    )
    context = NormalizationContext(
        scan_id=str(scan.id),
        asset_id=plan.asset_ids[0] if plan.asset_ids else None,
        test_plan_id=str(plan.id),
        test_requirement_id=(plan.reasoning_trace or {}).get("requirement_id"),
        test_execution_id=str(execution.id),
        provider_id="nuclei",
        executed_capability="TEMPLATE_BASED_ASSESSMENT",
        vulnerability_classes=["SECURITY_HEADERS"],
    )
    summary = await EvidenceIngestionService(db_session).ingest_provider_result(
        execution=execution,
        plan=plan,
        provider_result=result,
        context=context,
    )
    await db_session.commit()

    assert summary.scanner_finding_ids
    assert summary.verdict_status in {
        VerdictStatus.PARTIALLY_VALIDATED.value,
        VerdictStatus.REQUIRES_MANUAL_REVIEW.value,
    }
    findings = list(
        (await db_session.execute(select(ConfirmedFinding).where(ConfirmedFinding.scan_id == scan.id)))
        .scalars()
        .all()
    )
    assert findings == []
    nodes = list(
        (await db_session.execute(select(EvidenceNode).where(EvidenceNode.scan_id == scan.id))).scalars().all()
    )
    assert nodes
    supports = list(
        (
            await db_session.execute(
                select(EvidenceLink).where(
                    EvidenceLink.scan_id == scan.id,
                    EvidenceLink.link_type == "SUPPORTS",
                )
            )
        )
        .scalars()
        .all()
    )
    assert supports


@pytest.mark.asyncio
async def test_clean_negative_creates_negative_evidence(db_session) -> None:
    scan = await _seed_scan(db_session)
    plan = (
        await db_session.execute(select(TestPlan).where(TestPlan.scan_id == scan.id))
    ).scalars().first()
    assert plan is not None
    execution = TestExecution(
        test_plan_id=plan.id,
        selected_provider_id="nuclei",
        executed_capability="TEMPLATE_BASED_ASSESSMENT",
        status="COMPLETED",
    )
    db_session.add(execution)
    await db_session.flush()

    result = ProviderExecutionResult(
        provider_id="nuclei",
        capability="TEMPLATE_BASED_ASSESSMENT",
        status="NO_EVIDENCE",
        detail="no template matches",
    )
    context = NormalizationContext(
        scan_id=str(scan.id),
        asset_id=plan.asset_ids[0] if plan.asset_ids else None,
        test_plan_id=str(plan.id),
        test_requirement_id=None,
        test_execution_id=str(execution.id),
        provider_id="nuclei",
        executed_capability="TEMPLATE_BASED_ASSESSMENT",
        vulnerability_classes=["SECURITY_HEADERS"],
    )
    await EvidenceIngestionService(db_session).ingest_provider_result(
        execution=execution,
        plan=plan,
        provider_result=result,
        context=context,
    )
    await db_session.commit()
    assert execution.result_summary.get("coverage_status") == "TESTED_NO_EVIDENCE"
    assert execution.result_summary.get("coverage_scope", {}).get("capability") == "TEMPLATE_BASED_ASSESSMENT"


@pytest.mark.asyncio
async def test_timeout_inconclusive_not_complete(db_session) -> None:
    scan = await _seed_scan(db_session)
    plan = (
        await db_session.execute(select(TestPlan).where(TestPlan.scan_id == scan.id))
    ).scalars().first()
    assert plan is not None
    execution = TestExecution(
        test_plan_id=plan.id,
        selected_provider_id="nuclei",
        status="FAILED",
    )
    db_session.add(execution)
    await db_session.flush()
    result = ProviderExecutionResult(
        provider_id="nuclei",
        capability="TEMPLATE_BASED_ASSESSMENT",
        status="ERROR",
        error_code="TIMEOUT",
        detail="timeout",
    )
    context = NormalizationContext(
        scan_id=str(scan.id),
        asset_id=plan.asset_ids[0] if plan.asset_ids else None,
        test_plan_id=str(plan.id),
        test_requirement_id=None,
        test_execution_id=str(execution.id),
        provider_id="nuclei",
        executed_capability="TEMPLATE_BASED_ASSESSMENT",
        vulnerability_classes=["SECURITY_HEADERS"],
    )
    summary = await EvidenceIngestionService(db_session).ingest_provider_result(
        execution=execution,
        plan=plan,
        provider_result=result,
        context=context,
    )
    await db_session.commit()
    assert summary.verdict_status in {
        VerdictStatus.INCONCLUSIVE.value,
        VerdictStatus.REQUIRES_MANUAL_REVIEW.value,
        None,
    }
    assert execution.result_summary.get("coverage_status") == "INCONCLUSIVE"
    assert (
        await db_session.execute(select(ConfirmedFinding).where(ConfirmedFinding.scan_id == scan.id))
    ).scalar_one_or_none() is None


@pytest.mark.asyncio
async def test_sqlmap_positive_with_validation_can_confirm(db_session) -> None:
    scan = await _seed_scan(db_session)
    plan = TestPlan(
        scan_id=scan.id,
        hypothesis_id=None,
        asset_ids=[],
        vulnerability_class_ids=[],
        testing_mode=TestingMode.AUTOMATED.value,
        required_capabilities=["INJECTION_VALIDATION"],
        safety_class="STATE_CHANGING",
        authorization_requirement="PRE_APPROVED",
        status=TestPlanStatus.APPROVED.value,
    )
    hyp = Hypothesis(
        scan_id=scan.id,
        title="Injection test",
        hypothesis_type="INJECTION_CLASS",
        affected_asset_ids=[],
        status="READY_FOR_VALIDATION",
    )
    db_session.add(hyp)
    await db_session.flush()
    plan.hypothesis_id = hyp.id
    db_session.add(plan)
    await db_session.flush()

    execution = TestExecution(test_plan_id=plan.id, selected_provider_id="sqlmap_mcp", status="COMPLETED")
    db_session.add(execution)
    await db_session.flush()

    result = ProviderExecutionResult(
        provider_id="sqlmap_mcp",
        capability="INJECTION_VALIDATION",
        status="CORROBORATED",
        findings=[{"template_id": "sqlmap-scan", "name": "sqli", "severity": "high"}],
    )
    context = NormalizationContext(
        scan_id=str(scan.id),
        asset_id=None,
        test_plan_id=str(plan.id),
        test_requirement_id=None,
        test_execution_id=str(execution.id),
        provider_id="sqlmap_mcp",
        executed_capability="INJECTION_VALIDATION",
        vulnerability_classes=["INJECTION_CLASS"],
        endpoint_context={"parameter_name": "id", "parameter_location": "query"},
    )
    summary = await EvidenceIngestionService(db_session).ingest_provider_result(
        execution=execution,
        plan=plan,
        provider_result=result,
        context=context,
    )
    await db_session.commit()

    if summary.verdict_status == VerdictStatus.CONFIRMED.value:
        assert (
            await db_session.execute(select(ConfirmedFinding).where(ConfirmedFinding.scan_id == scan.id))
        ).scalar_one_or_none() is not None
        transition = (
            await db_session.execute(select(VerdictTransition).where(VerdictTransition.scan_id == scan.id))
        ).scalar_one_or_none()
        assert transition is not None
