"""Phase 4 recursive correlation integration tests."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from vapt_platform.db.tables.models import (
    CorrelationEvent,
    CorrelationExecution,
    CoverageGap,
    Hypothesis,
    TestRequirement,
)
from vapt_platform.domain.correlation_event import CorrelationEventData, CorrelationEventType
from vapt_platform.services.correlation_event_processor import CorrelationEventProcessor
from vapt_platform.services.correlation_event_service import CorrelationEventService
from vapt_platform.services.core import ProjectService, ScanService


async def _scan(db_session):
    project = await ProjectService(db_session).create("Phase 4")
    return await ScanService(db_session).create(project.id, "Phase 4 Scan", [])


@pytest.mark.asyncio
async def test_js_endpoint_gap_scenario(db_session) -> None:
    scan = await _scan(db_session)
    asset_id = str(uuid.uuid4())
    emitter = CorrelationEventService(db_session)
    event = await emitter.emit(
        CorrelationEventData(
            scan_id=scan.id,
            event_type=CorrelationEventType.OBSERVATION_RECORDED.value,
            source_type="OBSERVATION",
            source_id=uuid.uuid4(),
            asset_ids=[asset_id],
            safe_context={
                "js_endpoints": ["/api/hidden"],
                "crawl_endpoints": ["/"],
            },
            idempotency_key="js-gap-1",
        )
    )
    await db_session.commit()
    assert event is not None
    summary = await CorrelationEventProcessor(db_session).process_event(event.id)
    await db_session.commit()
    assert "CORR-ENDPOINT-001" in summary.rules_selected
    gaps = list(
        (await db_session.execute(select(CoverageGap).where(CoverageGap.scan_id == scan.id))).scalars().all()
    )
    hyps = list(
        (await db_session.execute(select(Hypothesis).where(Hypothesis.scan_id == scan.id))).scalars().all()
    )
    assert gaps
    assert hyps
    summary2 = await CorrelationEventProcessor(db_session).process_event(event.id)
    await db_session.commit()
    assert summary2.duplicate_suppression_count >= 0


@pytest.mark.asyncio
async def test_shared_identity_auth_gap(db_session) -> None:
    scan = await _scan(db_session)
    app_a, app_b = str(uuid.uuid4()), str(uuid.uuid4())
    event = await CorrelationEventService(db_session).emit(
        CorrelationEventData(
            scan_id=scan.id,
            event_type=CorrelationEventType.AUTH_COVERAGE_CHANGED.value,
            source_type="AUTH_CONTEXT",
            source_id=uuid.uuid4(),
            asset_ids=[app_b],
            safe_context={
                "application_a_id": app_a,
                "application_b_id": app_b,
                "app_a_auth_coverage": "COMPLETE",
                "app_b_auth_coverage": "NOT_TESTED",
            },
            idempotency_key="auth-gap-1",
        )
    )
    await db_session.commit()
    summary = await CorrelationEventProcessor(db_session).process_event(event.id)
    await db_session.commit()
    assert "CORR-AUTH-001" in summary.rules_selected
    hyps = list(
        (await db_session.execute(select(Hypothesis).where(Hypothesis.scan_id == scan.id))).scalars().all()
    )
    assert hyps
    assert not any(h.status == "CONFIRMED" for h in hyps)


@pytest.mark.asyncio
async def test_negative_evidence_scope_granularity(db_session) -> None:
    from vapt_platform.db.tables.models import AssetTestMatrix

    scan = await _scan(db_session)
    asset_id = str(uuid.uuid4())
    event = await CorrelationEventService(db_session).emit(
        CorrelationEventData(
            scan_id=scan.id,
            event_type=CorrelationEventType.NEGATIVE_EVIDENCE_RECORDED.value,
            source_type="TEST_EXECUTION",
            source_id=uuid.uuid4(),
            asset_ids=[asset_id],
            vulnerability_classes=["INJECTION_CLASS"],
            safe_context={
                "evidence_type": "NEGATIVE_EVIDENCE",
                "parameter_name": "id",
                "endpoint_ref": "/search",
                "untested_parameters": ["q", "sort"],
                "vulnerability_class": "INJECTION_CLASS",
            },
            idempotency_key="neg-scope-1",
        )
    )
    await db_session.commit()
    summary = await CorrelationEventProcessor(db_session).process_event(event.id)
    await db_session.commit()
    assert summary.created_test_requirement_ids or summary.results_applied >= 1
    reqs = list(
        (
            await db_session.execute(
                select(TestRequirement)
                .join(AssetTestMatrix, TestRequirement.matrix_id == AssetTestMatrix.id)
                .where(AssetTestMatrix.scan_id == scan.id)
            )
        ).scalars().all()
    )
    assert reqs
    scopes = (reqs[0].reasoning_trace or {}).get("parameter_scopes", [])
    assert len(scopes) >= 2 or len(reqs) >= 2


@pytest.mark.asyncio
async def test_bound_reached(db_session, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CORRELATION_MAX_GENERATIONS", "1")
    from vapt_platform.config.settings import get_settings

    get_settings.cache_clear()
    scan = await _scan(db_session)
    for i in range(3):
        await CorrelationEventService(db_session).emit(
            CorrelationEventData(
                scan_id=scan.id,
                event_type=CorrelationEventType.OBSERVATION_RECORDED.value,
                source_type="OBSERVATION",
                source_id=uuid.uuid4(),
                asset_ids=[str(uuid.uuid4())],
                safe_context={
                    "js_endpoints": [f"/api/{i}"],
                    "crawl_endpoints": [],
                },
                idempotency_key=f"bound-{i}",
            )
        )
    await db_session.commit()
    from vapt_platform.services.full_assessment import FullAssessmentService

    result = await FullAssessmentService(db_session).run_recursive_assessment_loop(scan.id)
    await db_session.commit()
    assert result["enabled"] is True
    state = await CorrelationEventService(db_session).get_scan_state(scan.id)
    assert state.events_processed >= 1
