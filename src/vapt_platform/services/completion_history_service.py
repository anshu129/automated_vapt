"""Assessment completion history service (Phase 6/7)."""

from __future__ import annotations

import hashlib
import logging
import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from vapt_platform.config.settings import get_settings
from vapt_platform.db.tables.models import AssessmentCompletionHistory, AssessmentCompletionRecord
from vapt_platform.domain.assessment_completion import AssessmentCompletionResult
from vapt_platform.domain.completion_history import CompletionHistoryEntry

logger = logging.getLogger(__name__)


def _transition_fingerprint(
    previous_status: str | None, new_status: str, reason_codes: list[str]
) -> str:
    payload = f"{previous_status}|{new_status}|{'|'.join(reason_codes)}"
    return hashlib.sha256(payload.encode()).hexdigest()


class CompletionHistoryService:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def record_transition(
        self,
        *,
        scan_id: uuid.UUID,
        previous_status: str | None,
        new_status: str,
        result: AssessmentCompletionResult,
        job_id: str | None = None,
        triggered_by: str = "completion-evaluator",
        report_snapshot_id: uuid.UUID | None = None,
    ) -> AssessmentCompletionHistory | None:
        settings = get_settings()
        if not settings.phase6_completion_history_enabled:
            return None
        if previous_status == new_status:
            return None

        fingerprint = _transition_fingerprint(previous_status, new_status, result.reason_codes)
        row = AssessmentCompletionHistory(
            scan_id=scan_id,
            job_id=job_id,
            previous_status=previous_status,
            new_status=new_status,
            reason_codes=list(result.reason_codes),
            pending_work_summary=result.pending_work.to_dict(),
            accepted_gaps=dict(result.accepted_gaps),
            bound_reached=result.bound_reached,
            evaluation_version=result.evaluation_version,
            triggered_by=triggered_by,
            transition_fingerprint=fingerprint,
            report_snapshot_id=report_snapshot_id,
        )
        self.session.add(row)
        await self.session.flush()

        if settings.phase7_latest_transition_denormalized:
            await self._update_latest_transition(scan_id, row)

        logger.info(
            "completion_history_recorded scan_id=%s previous=%s new=%s triggered_by=%s "
            "history_transition=true",
            scan_id,
            previous_status,
            new_status,
            triggered_by,
        )
        return row

    async def _update_latest_transition(
        self, scan_id: uuid.UUID, row: AssessmentCompletionHistory
    ) -> None:
        record = (
            await self.session.execute(
                select(AssessmentCompletionRecord).where(
                    AssessmentCompletionRecord.scan_id == scan_id
                )
            )
        ).scalar_one_or_none()
        if not record:
            return
        summary = {
            "id": str(row.id),
            "previous_status": row.previous_status,
            "new_status": row.new_status,
            "reason_codes": list(row.reason_codes or []),
            "bound_reached": row.bound_reached,
            "triggered_by": row.triggered_by,
            "created_at": row.created_at.isoformat() if row.created_at else None,
        }
        record.latest_transition_id = row.id
        record.latest_transition_at = row.created_at or datetime.now(UTC)
        record.latest_transition_summary = summary
        await self.session.flush()
        logger.info(
            "latest_transition_denormalized scan_id=%s transition_status=%s->%s",
            scan_id,
            row.previous_status,
            row.new_status,
        )

    async def list_history(
        self, scan_id: uuid.UUID, *, limit: int = 50
    ) -> list[CompletionHistoryEntry]:
        rows = list(
            (
                await self.session.execute(
                    select(AssessmentCompletionHistory)
                    .where(AssessmentCompletionHistory.scan_id == scan_id)
                    .order_by(AssessmentCompletionHistory.created_at.desc())
                    .limit(limit)
                )
            )
            .scalars()
            .all()
        )
        return [
            CompletionHistoryEntry(
                id=str(row.id),
                scan_id=str(row.scan_id),
                job_id=row.job_id,
                previous_status=row.previous_status,
                new_status=row.new_status,
                reason_codes=list(row.reason_codes or []),
                pending_work_summary=dict(row.pending_work_summary or {}),
                accepted_gaps=dict(row.accepted_gaps or {}),
                bound_reached=row.bound_reached,
                evaluation_version=row.evaluation_version,
                triggered_by=row.triggered_by,
                created_at=row.created_at.isoformat() if row.created_at else None,
            )
            for row in rows
        ]
