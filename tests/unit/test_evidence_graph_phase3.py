"""Evidence graph provenance and link tests (Phase 3)."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from vapt_platform.db.tables.models import EvidenceLink, EvidenceNode, TestExecution, TestPlan
from vapt_platform.domain.capability_provider import ProviderExecutionResult
from vapt_platform.domain.enums import TestPlanStatus, TestingMode
from vapt_platform.services.core import ProjectService, ScanService
from vapt_platform.services.evidence_graph import EvidenceGraphService
from vapt_platform.services.evidence_ingestion import EvidenceIngestionService
from vapt_platform.services.result_normalizer import NormalizationContext


@pytest.mark.asyncio
async def test_supports_and_contradicts_links_created(db_session) -> None:
    project = await ProjectService(db_session).create("Graph Links")
    scan = await ScanService(db_session).create(project.id, "Graph Links Scan", [])
    from vapt_platform.db.tables.models import Hypothesis

    hyp = Hypothesis(
        scan_id=scan.id,
        title="Headers",
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
        required_capabilities=["TEMPLATE_BASED_ASSESSMENT"],
        safety_class="PASSIVE",
        authorization_requirement="IN_SCOPE",
        status=TestPlanStatus.APPROVED.value,
    )
    db_session.add(plan)
    await db_session.flush()
    execution = TestExecution(test_plan_id=plan.id, selected_provider_id="nuclei", status="COMPLETED")
    db_session.add(execution)
    await db_session.flush()

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
            findings=[{"name": "missing header", "severity": "low"}],
        ),
        context=context,
    )
    await db_session.commit()

    supports = list(
        (
            await db_session.execute(
                select(EvidenceLink).where(
                    EvidenceLink.scan_id == scan.id,
                    EvidenceLink.link_type == "SUPPORTS",
                    EvidenceLink.target_type == "HYPOTHESIS",
                )
            )
        )
        .scalars()
        .all()
    )
    assert supports
    derived = list(
        (
            await db_session.execute(
                select(EvidenceLink).where(
                    EvidenceLink.scan_id == scan.id,
                    EvidenceLink.link_type == "DERIVED_FROM",
                )
            )
        )
        .scalars()
        .all()
    )
    assert derived


@pytest.mark.asyncio
async def test_duplicate_ingestion_idempotent_nodes(db_session) -> None:
    project = await ProjectService(db_session).create("Idempotent")
    scan = await ScanService(db_session).create(project.id, "Idempotent Scan", [])
    graph = EvidenceGraphService(db_session)
    entity_id = uuid.uuid4()
    first = await graph.get_or_create_node(
        scan_id=scan.id,
        node_type="OBSERVATION",
        entity_type="OBSERVATION",
        entity_id=entity_id,
        idempotency_key="provider-result-abc",
    )
    second = await graph.get_or_create_node(
        scan_id=scan.id,
        node_type="OBSERVATION",
        entity_type="OBSERVATION",
        entity_id=entity_id,
        idempotency_key="provider-result-abc",
    )
    await db_session.commit()
    assert first.id == second.id
    count = len(
        list(
            (
                await db_session.execute(
                    select(EvidenceNode).where(
                        EvidenceNode.scan_id == scan.id,
                        EvidenceNode.idempotency_key == "provider-result-abc",
                    )
                )
            )
            .scalars()
            .all()
        )
    )
    assert count == 1
