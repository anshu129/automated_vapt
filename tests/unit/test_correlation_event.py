"""Correlation event unit tests (Phase 4)."""

from __future__ import annotations

import uuid

import pytest

from vapt_platform.domain.correlation_event import CorrelationEventData, CorrelationEventType
from vapt_platform.services.correlation_event_service import CorrelationEventService
from vapt_platform.services.core import ProjectService, ScanService


@pytest.mark.asyncio
async def test_emit_after_evidence_no_duplicate(db_session) -> None:
    project = await ProjectService(db_session).create("Corr Event")
    scan = await ScanService(db_session).create(project.id, "Corr Scan", [])
    service = CorrelationEventService(db_session)
    event = CorrelationEventData(
        scan_id=scan.id,
        event_type=CorrelationEventType.SCANNER_FINDING_RECORDED.value,
        source_type="TEST_EXECUTION",
        source_id=uuid.uuid4(),
        idempotency_key="idem-1",
        safe_context={"evidence_type": "SCANNER_FINDING"},
    )
    first = await service.emit(event)
    second = await service.emit(event)
    await db_session.commit()
    assert first is not None
    assert second is not None
    assert first.id == second.id


@pytest.mark.asyncio
async def test_safe_context_has_no_credentials(db_session) -> None:
    project = await ProjectService(db_session).create("Safe")
    scan = await ScanService(db_session).create(project.id, "Safe Scan", [])
    service = CorrelationEventService(db_session)
    row = await service.emit(
        CorrelationEventData(
            scan_id=scan.id,
            event_type=CorrelationEventType.OBSERVATION_RECORDED.value,
            source_type="OBSERVATION",
            source_id=uuid.uuid4(),
            safe_context={
                "Authorization": "Bearer secret-token",
                "note": "ok",
            },
        )
    )
    await db_session.commit()
    assert row is not None
    assert "secret-token" not in str(row.safe_context)
