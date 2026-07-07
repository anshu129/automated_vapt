"""Normalized completion payload for API, UI, and report (Phase 6)."""

from __future__ import annotations

import logging
import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from vapt_platform.db.tables.models import AssessmentCompletionRecord, Scan
from vapt_platform.domain.assessment_completion import AssessmentCompletionResult
from vapt_platform.services.completion_history_service import CompletionHistoryService

logger = logging.getLogger(__name__)

PAYLOAD_VERSION = "phase6-v1"


def _pending_from_summary(summary: dict[str, Any] | None) -> "PendingAssessmentWork":
    from vapt_platform.domain.assessment_completion import PendingAssessmentWork

    data = {k: v for k, v in (summary or {}).items() if k != "total"}
    return PendingAssessmentWork(**data)


class CompletionSerializationService:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.history = CompletionHistoryService(session)

    async def build_payload(
        self,
        scan_id: uuid.UUID,
        *,
        result: AssessmentCompletionResult | None = None,
        job_status: str | None = None,
    ) -> dict[str, Any]:
        record = (
            await self.session.execute(
                select(AssessmentCompletionRecord).where(
                    AssessmentCompletionRecord.scan_id == scan_id
                )
            )
        ).scalar_one_or_none()
        scan = await self.session.get(Scan, scan_id)
        history = await self.history.list_history(scan_id)

        if result is None and record:
            from vapt_platform.domain.assessment_completion import PendingAssessmentWork

            pending = _pending_from_summary(record.pending_work_summary)
            result = AssessmentCompletionResult(
                assessment_status=record.status,
                reason_codes=list(record.reason_codes or []),
                blocking_conditions=list(record.blocking_items or []),
                accepted_gaps=dict(record.accepted_gaps or {}),
                pending_work=pending,
                bound_reached=record.bound_reached,
                coverage_summary=(record.completion_reasons or {}).get("coverage_summary", {}),
                completion_notes=(record.completion_reasons or {}).get("completion_notes", ""),
                evaluation_version=record.evaluation_version or "phase5-v1",
            )
        elif result is None:
            from vapt_platform.domain.enums import CompletionStatus

            result = AssessmentCompletionResult(
                assessment_status=CompletionStatus.INCOMPLETE.value,
            )

        base = result.to_report_dict()
        payload = {
            "payload_version": PAYLOAD_VERSION,
            "scan_id": str(scan_id),
            "scan_status": scan.status if scan else None,
            "job_status": job_status,
            "assessment_status": result.assessment_status,
            "reason_codes": result.reason_codes,
            "pending_work_summary": result.pending_work.to_dict(),
            "accepted_gaps": result.accepted_gaps,
            "bound_reached": result.bound_reached,
            "blocked_conditions": result.blocking_conditions,
            "coverage_summary": result.coverage_summary,
            "completion_notes": result.completion_notes,
            "evaluation_version": result.evaluation_version,
            "evaluation_timestamp": (
                record.evaluated_at.isoformat() if record and record.evaluated_at else None
            ),
            "history": [entry.to_dict() for entry in history],
            "summary": self.build_demo_summary(result, job_status),
        }
        payload.update(base)
        latest_transition = None
        if record and record.latest_transition_summary:
            latest_transition = dict(record.latest_transition_summary)
        elif history:
            latest_transition = history[0].to_dict()
        if latest_transition:
            payload["summary"]["latest_transition"] = latest_transition
            payload["latest_transition"] = latest_transition
            payload["latest_transition_at"] = (
                record.latest_transition_at.isoformat()
                if record and record.latest_transition_at
                else latest_transition.get("created_at")
            )
        logger.info(
            "completion_payload_built scan_id=%s job_status=%s assessment_status=%s "
            "reason_codes=%s pending_work_count=%d accepted_gap_count=%d bound_reached=%s "
            "history_count=%d evaluation_version=%s",
            scan_id,
            job_status,
            result.assessment_status,
            result.reason_codes,
            result.pending_work_count,
            sum(len(v) if isinstance(v, list) else 0 for v in result.accepted_gaps.values()),
            result.bound_reached,
            len(history),
            result.evaluation_version,
        )
        return payload

    @staticmethod
    def build_demo_summary(
        result: AssessmentCompletionResult,
        job_status: str | None = None,
    ) -> dict[str, Any]:
        status = result.assessment_status
        headline = {
            "COMPLETE": "Assessment complete",
            "COMPLETE_WITH_ACCEPTED_GAPS": "Complete with accepted gaps",
            "INCOMPLETE": "Assessment incomplete",
            "BLOCKED": "Assessment blocked",
            "INCONCLUSIVE": "Assessment inconclusive",
        }.get(status, status)

        pending_highlights = []
        pw = result.pending_work
        if pw.manual_validation_pending:
            pending_highlights.append(f"{pw.manual_validation_pending} manual validation tasks")
        if pw.coverage_pending:
            pending_highlights.append(f"{pw.coverage_pending} coverage items")
        if pw.correlation_pending:
            pending_highlights.append(f"{pw.correlation_pending} correlation events pending")

        accepted_count = sum(
            len(v) if isinstance(v, list) else 0 for v in result.accepted_gaps.values()
        )
        accepted_highlights = (
            [f"{accepted_count} accepted gap dimension(s)"] if accepted_count else []
        )

        one_line = result.completion_notes or headline
        if result.bound_reached:
            one_line = f"{one_line} (bound: {result.bound_reached})"

        return {
            "headline": headline,
            "status_label": status,
            "one_line_reason": one_line,
            "job_status": job_status,
            "assessment_status": status,
            "is_scan_job_done": job_status in {"COMPLETED", "FAILED"} if job_status else None,
            "is_assessment_complete": status
            in {"COMPLETE", "COMPLETE_WITH_ACCEPTED_GAPS"},
            "pending_highlights": pending_highlights,
            "accepted_gap_highlights": accepted_highlights,
            "bound_reached": result.bound_reached,
            "latest_transition": None,
        }

    async def build_report_sections(
        self,
        scan_id: uuid.UUID,
        *,
        job_status: str | None = None,
    ) -> dict[str, Any]:
        payload = await self.build_payload(scan_id, job_status=job_status)
        return {
            "assessment_completion": {
                k: payload[k]
                for k in (
                    "job_status",
                    "assessment_status",
                    "reason_codes",
                    "pending_work_summary",
                    "accepted_gaps",
                    "bound_reached",
                    "blocked_conditions",
                    "coverage_summary",
                    "completion_notes",
                    "evaluation_version",
                    "evaluation_timestamp",
                    "summary",
                )
                if k in payload
            },
            "assessment_completion_history": payload.get("history", []),
        }
