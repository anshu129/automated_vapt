"""AI and MCP boundary enforcement tests (Phase 3)."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from vapt_platform.db.tables.models import (
    ConfirmedFinding,
    EvidenceLink,
    EvidenceNode,
    Hypothesis,
    TestExecution,
    TestPlan,
    Verdict,
)
from vapt_platform.domain.capability_provider import ProviderExecutionResult
from vapt_platform.domain.enums import TestPlanStatus, TestingMode
from vapt_platform.services.ai_validation import AIValidationService
from vapt_platform.services.core import ProjectService, ScanService
from vapt_platform.services.evidence_ingestion import EvidenceIngestionService
from vapt_platform.services.result_normalizer import NormalizationContext


@pytest.mark.asyncio
async def test_ai_advisory_does_not_create_verdict_or_confirmed_finding(db_session) -> None:
    project = await ProjectService(db_session).create("AI Boundary")
    scan = await ScanService(db_session).create(project.id, "AI Boundary Scan", [])
    await AIValidationService(db_session).run(scan.id)
    await db_session.commit()

    assert (
        await db_session.execute(select(ConfirmedFinding).where(ConfirmedFinding.scan_id == scan.id))
    ).scalar_one_or_none() is None
    assert (
        await db_session.execute(select(Verdict).where(Verdict.scan_id == scan.id))
    ).scalar_one_or_none() is None
    confirms = list(
        (
            await db_session.execute(
                select(EvidenceLink).where(
                    EvidenceLink.scan_id == scan.id,
                    EvidenceLink.link_type == "CONFIRMS",
                )
            )
        )
        .scalars()
        .all()
    )
    assert confirms == []


@pytest.mark.asyncio
async def test_mcp_burp_result_ingestion_no_direct_confirmed_finding(db_session) -> None:
    project = await ProjectService(db_session).create("MCP Burp")
    scan = await ScanService(db_session).create(project.id, "MCP Burp Scan", [])
    hyp = Hypothesis(
        scan_id=scan.id,
        title="Burp passive",
        hypothesis_type="SECURITY_HEADERS",
        affected_asset_ids=[],
        status="READY_FOR_VALIDATION",
    )
    db_session.add(hyp)
    await db_session.flush()
    plan = TestPlan(
        scan_id=scan.id,
        hypothesis_id=hyp.id,
        asset_ids=[],
        vulnerability_class_ids=[],
        testing_mode=TestingMode.AUTOMATED.value,
        required_capabilities=["WEB_PASSIVE_ASSESSMENT"],
        safety_class="PASSIVE",
        authorization_requirement="IN_SCOPE",
        status=TestPlanStatus.APPROVED.value,
    )
    db_session.add(plan)
    await db_session.flush()
    execution = TestExecution(
        test_plan_id=plan.id,
        selected_provider_id="burp_mcp",
        status="COMPLETED",
    )
    db_session.add(execution)
    await db_session.flush()

    result = ProviderExecutionResult(
        provider_id="burp_mcp",
        capability="WEB_PASSIVE_ASSESSMENT",
        status="CORROBORATED",
        findings=[
            {
                "issue_type": "passive",
                "name": "Missing CSP",
                "severity": "low",
                "url": "https://app.example.com",
            }
        ],
    )
    context = NormalizationContext(
        scan_id=str(scan.id),
        asset_id=None,
        test_plan_id=str(plan.id),
        test_requirement_id=None,
        test_execution_id=str(execution.id),
        provider_id="burp_mcp",
        executed_capability="WEB_PASSIVE_ASSESSMENT",
        vulnerability_classes=["SECURITY_HEADERS"],
    )
    await EvidenceIngestionService(db_session).ingest_provider_result(
        execution=execution,
        plan=plan,
        provider_result=result,
        context=context,
    )
    await db_session.commit()

    nodes = list(
        (await db_session.execute(select(EvidenceNode).where(EvidenceNode.scan_id == scan.id))).scalars().all()
    )
    assert nodes
    assert (
        await db_session.execute(select(ConfirmedFinding).where(ConfirmedFinding.scan_id == scan.id))
    ).scalar_one_or_none() is None
    confirms = list(
        (
            await db_session.execute(
                select(EvidenceLink).where(
                    EvidenceLink.scan_id == scan.id,
                    EvidenceLink.link_type == "CONFIRMS",
                )
            )
        )
        .scalars()
        .all()
    )
    assert confirms == []


@pytest.mark.asyncio
async def test_mcp_sqlmap_scanner_only_no_confirms_link(db_session) -> None:
    project = await ProjectService(db_session).create("MCP Sqlmap")
    scan = await ScanService(db_session).create(project.id, "MCP Sqlmap Scan", [])
    hyp = Hypothesis(
        scan_id=scan.id,
        title="SQLi candidate",
        hypothesis_type="INJECTION_CLASS",
        affected_asset_ids=[],
        status="READY_FOR_VALIDATION",
    )
    db_session.add(hyp)
    await db_session.flush()
    plan = TestPlan(
        scan_id=scan.id,
        hypothesis_id=hyp.id,
        asset_ids=[],
        vulnerability_class_ids=[],
        testing_mode=TestingMode.AUTOMATED.value,
        required_capabilities=["INJECTION_VALIDATION"],
        safety_class="STATE_CHANGING",
        authorization_requirement="PRE_APPROVED",
        status=TestPlanStatus.APPROVED.value,
    )
    db_session.add(plan)
    await db_session.flush()
    execution = TestExecution(test_plan_id=plan.id, selected_provider_id="sqlmap_mcp", status="COMPLETED")
    db_session.add(execution)
    await db_session.flush()

    result = ProviderExecutionResult(
        provider_id="sqlmap_mcp",
        capability="INJECTION_VALIDATION",
        status="CORROBORATED",
        findings=[{"name": "possible sqli", "severity": "high"}],
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
    )
    summary = await EvidenceIngestionService(db_session).ingest_provider_result(
        execution=execution,
        plan=plan,
        provider_result=result,
        context=context,
    )
    await db_session.commit()

    assert summary.scanner_finding_ids or summary.evidence_node_ids
    confirms = list(
        (
            await db_session.execute(
                select(EvidenceLink).where(
                    EvidenceLink.scan_id == scan.id,
                    EvidenceLink.link_type == "CONFIRMS",
                )
            )
        )
        .scalars()
        .all()
    )
    assert confirms == []
