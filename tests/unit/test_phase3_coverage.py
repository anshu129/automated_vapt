"""Coverage granularity tests (Phase 3)."""

from __future__ import annotations

import pytest

from vapt_platform.db.tables.models import TestExecution, TestPlan
from vapt_platform.domain.capability_provider import ProviderExecutionResult
from vapt_platform.domain.enums import TestPlanStatus, TestingMode
from vapt_platform.services.core import ProjectService, ScanService
from vapt_platform.services.evidence_ingestion import EvidenceIngestionService
from vapt_platform.services.result_normalizer import NormalizationContext


async def _plan_and_execution(db_session):
    project = await ProjectService(db_session).create("Coverage")
    scan = await ScanService(db_session).create(project.id, "Coverage Scan", [])
    plan = TestPlan(
        scan_id=scan.id,
        hypothesis_id=None,
        asset_ids=[],
        vulnerability_class_ids=[],
        testing_mode=TestingMode.AUTOMATED.value,
        required_capabilities=["INJECTION_VALIDATION", "TEMPLATE_BASED_ASSESSMENT"],
        safety_class="PASSIVE",
        authorization_requirement="IN_SCOPE",
        status=TestPlanStatus.APPROVED.value,
    )
    db_session.add(plan)
    await db_session.flush()
    execution = TestExecution(
        test_plan_id=plan.id,
        selected_provider_id="nuclei",
        status="COMPLETED",
    )
    db_session.add(execution)
    await db_session.flush()
    return scan, plan, execution


@pytest.mark.asyncio
async def test_clean_negative_marks_exact_capability_coverage(db_session) -> None:
    scan, plan, execution = await _plan_and_execution(db_session)
    context = NormalizationContext(
        scan_id=str(scan.id),
        asset_id=None,
        test_plan_id=str(plan.id),
        test_requirement_id=None,
        test_execution_id=str(execution.id),
        provider_id="nuclei",
        executed_capability="TEMPLATE_BASED_ASSESSMENT",
        vulnerability_classes=["SECURITY_HEADERS"],
        endpoint_context={"parameter_name": "id"},
    )
    await EvidenceIngestionService(db_session).ingest_provider_result(
        execution=execution,
        plan=plan,
        provider_result=ProviderExecutionResult(
            provider_id="nuclei",
            capability="TEMPLATE_BASED_ASSESSMENT",
            status="NO_EVIDENCE",
            detail="clean run",
        ),
        context=context,
    )
    scope = execution.result_summary.get("coverage_scope", {})
    assert scope.get("capability") == "TEMPLATE_BASED_ASSESSMENT"
    assert execution.result_summary.get("coverage_status") == "TESTED_NO_EVIDENCE"


@pytest.mark.asyncio
async def test_parser_failure_does_not_mark_complete(db_session) -> None:
    scan, plan, execution = await _plan_and_execution(db_session)
    context = NormalizationContext(
        scan_id=str(scan.id),
        asset_id=None,
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
        provider_result=ProviderExecutionResult(
            provider_id="nuclei",
            capability="TEMPLATE_BASED_ASSESSMENT",
            status="ERROR",
            error_code="PARSER_FAILED",
            detail="json decode error",
        ),
        context=context,
    )
    assert execution.status == "FAILED"
    assert execution.result_summary.get("coverage_status") == "INCONCLUSIVE"
    assert execution.result_summary.get("coverage_status") != "TESTED_NO_EVIDENCE"


@pytest.mark.asyncio
async def test_timeout_does_not_mark_complete(db_session) -> None:
    scan, plan, execution = await _plan_and_execution(db_session)
    context = NormalizationContext(
        scan_id=str(scan.id),
        asset_id=None,
        test_plan_id=str(plan.id),
        test_requirement_id=None,
        test_execution_id=str(execution.id),
        provider_id="sqlmap_mcp",
        executed_capability="INJECTION_VALIDATION",
        vulnerability_classes=["INJECTION_CLASS"],
    )
    await EvidenceIngestionService(db_session).ingest_provider_result(
        execution=execution,
        plan=plan,
        provider_result=ProviderExecutionResult(
            provider_id="sqlmap_mcp",
            capability="INJECTION_VALIDATION",
            status="ERROR",
            error_code="TIMEOUT",
            detail="timeout",
        ),
        context=context,
    )
    assert execution.result_summary.get("coverage_status") == "INCONCLUSIVE"


@pytest.mark.asyncio
async def test_positive_result_partial_coverage_not_class_complete(db_session) -> None:
    scan, plan, execution = await _plan_and_execution(db_session)
    context = NormalizationContext(
        scan_id=str(scan.id),
        asset_id=None,
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
        provider_result=ProviderExecutionResult(
            provider_id="nuclei",
            capability="TEMPLATE_BASED_ASSESSMENT",
            status="CORROBORATED",
            findings=[{"name": "header issue", "severity": "medium"}],
        ),
        context=context,
    )
    assert execution.result_summary.get("coverage_status") == "PARTIALLY_TESTED"
