"""Correlation event emission and persistence (Phase 4)."""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from vapt_platform.config.settings import get_settings
from vapt_platform.db.tables.models import CorrelationEvent, CorrelationScanState
from vapt_platform.domain.correlation_event import CorrelationEventData
from vapt_platform.security.sensitive_data_redactor import SensitiveDataRedactor

logger = logging.getLogger(__name__)


class CorrelationEventService:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.redactor = SensitiveDataRedactor()

    async def emit(self, event: CorrelationEventData) -> CorrelationEvent | None:
        settings = get_settings()
        if not settings.recursive_correlation_enabled:
            return None

        if event.idempotency_key:
            existing = (
                await self.session.execute(
                    select(CorrelationEvent).where(
                        CorrelationEvent.scan_id == event.scan_id,
                        CorrelationEvent.idempotency_key == event.idempotency_key,
                    )
                )
            ).scalar_one_or_none()
            if existing:
                return existing

        state = await self._scan_state(event.scan_id)
        if state.bound_reached:
            return None
        if state.events_processed >= settings.correlation_max_events_per_scan:
            state.bound_reached = "CORRELATION_MAX_EVENTS_PER_SCAN"
            state.bound_context = {
                "limit": settings.correlation_max_events_per_scan,
                "count": state.events_processed,
            }
            return None

        correlation_id = event.correlation_id or uuid.uuid4()
        row = CorrelationEvent(
            scan_id=event.scan_id,
            event_type=event.event_type,
            source_type=event.source_type,
            source_id=event.source_id,
            asset_ids=list(event.asset_ids),
            surface_ids=list(event.surface_ids),
            relationship_ids=list(event.relationship_ids),
            hypothesis_ids=list(event.hypothesis_ids),
            vulnerability_classes=list(event.vulnerability_classes),
            safe_context=self.redactor.redact_dict(event.safe_context),
            causation_id=event.causation_id,
            correlation_id=correlation_id,
            generation=event.generation,
            idempotency_key=event.idempotency_key,
            status="PENDING",
        )
        self.session.add(row)
        await self.session.flush()
        logger.info(
            "correlation_event_emitted scan_id=%s event_id=%s event_type=%s generation=%d",
            event.scan_id,
            row.id,
            event.event_type,
            event.generation,
        )
        return row

    async def pending_events(self, scan_id: uuid.UUID) -> list[CorrelationEvent]:
        return list(
            (
                await self.session.execute(
                    select(CorrelationEvent)
                    .where(
                        CorrelationEvent.scan_id == scan_id,
                        CorrelationEvent.status == "PENDING",
                    )
                    .order_by(CorrelationEvent.created_at)
                )
            )
            .scalars()
            .all()
        )

    async def _scan_state(self, scan_id: uuid.UUID) -> CorrelationScanState:
        row = (
            await self.session.execute(
                select(CorrelationScanState).where(CorrelationScanState.scan_id == scan_id)
            )
        ).scalar_one_or_none()
        if row:
            return row
        row = CorrelationScanState(scan_id=scan_id)
        self.session.add(row)
        await self.session.flush()
        return row

    async def get_scan_state(self, scan_id: uuid.UUID) -> CorrelationScanState:
        return await self._scan_state(scan_id)
