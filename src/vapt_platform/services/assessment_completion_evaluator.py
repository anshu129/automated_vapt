"""Assessment completion evaluator V2 (Phase 5)."""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from vapt_platform.config.settings import get_settings
from vapt_platform.db.tables.models import AssessmentCompletionRecord, CorrelationScanState
from vapt_platform.domain.assessment_completion import (
    AssessmentCompletionResult,
    CompletionReasonCode,
    PendingAssessmentWork,
)
from vapt_platform.domain.enums import CompletionStatus
from vapt_platform.engines.accepted_gap_policy import AcceptedGapPolicy
from vapt_platform.services.completion_history_service import CompletionHistoryService
from vapt_platform.services.pending_work_aggregator import PendingWorkAggregator

logger = logging.getLogger(__name__)

EVALUATION_VERSION = "phase5-v1"


class AssessmentCompletionEvaluatorService:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.aggregator = PendingWorkAggregator(session)
        self.gap_policy = AcceptedGapPolicy()

    async def evaluate(
        self,
        scan_id: uuid.UUID,
        *,
        job_id: str | None = None,
    ) -> AssessmentCompletionResult:
        settings = get_settings()
        record = await self._get_or_create_record(scan_id)
        accepted = dict(record.accepted_gaps or {})

        pending, details = await self.aggregator.aggregate(scan_id, accepted_gaps=accepted)
        bound_reached = details.get("bound_reached")

        corr_state = (
            await self.session.execute(
                select(CorrelationScanState).where(CorrelationScanState.scan_id == scan_id)
            )
        ).scalar_one_or_none()

        reason_codes: list[str] = []
        blocking_conditions: list[str] = []
        coverage_summary = {
            "discovery_complete": pending.discovery_pending == 0,
            "surface_complete": pending.surface_inventory_pending == 0,
            "authenticated_coverage_complete": pending.authenticated_coverage_pending == 0,
            "role_coverage_complete": pending.role_coverage_pending == 0,
            "manual_backlog_empty": pending.manual_validation_pending == 0,
            "unresolved_contradictions_present": pending.contradiction_resolution_pending > 0,
            "accepted_gaps_present": bool(accepted),
        }

        accepted_count = sum(
            len(v) if isinstance(v, list) else len(v.keys()) if isinstance(v, dict) else 0
            for v in accepted.values()
        )

        # BLOCKED
        if details.get("missing_auth_context") and pending.authenticated_coverage_pending > 0:
            status = CompletionStatus.BLOCKED.value
            reason_codes.append(CompletionReasonCode.REQUIRED_CREDENTIALS_MISSING)
            blocking_conditions.append("Authenticated coverage required but no auth context")
        elif pending.policy_blocked_pending > 0:
            status = CompletionStatus.BLOCKED.value
            reason_codes.append(CompletionReasonCode.SAFETY_POLICY_BLOCKING)
            blocking_conditions.append("Safety policy blocks remaining work")
        # INCONCLUSIVE
        elif pending.contradiction_resolution_pending > 0 and pending.manual_validation_pending == 0:
            status = CompletionStatus.INCONCLUSIVE.value
            reason_codes.append(CompletionReasonCode.UNRESOLVED_CONTRADICTIONS)
            blocking_conditions.append(
                f"{pending.contradiction_resolution_pending} unresolved contradictions"
            )
        # INCOMPLETE
        elif self._has_pending_authorized_work(pending, details):
            status = CompletionStatus.INCOMPLETE.value
            if bound_reached:
                reason_codes.append(CompletionReasonCode.CORRELATION_BOUND_REACHED)
                blocking_conditions.append(f"Correlation bound reached: {bound_reached}")
            if pending.manual_validation_pending:
                reason_codes.append(CompletionReasonCode.PENDING_MANUAL_VALIDATION)
            if pending.coverage_pending:
                reason_codes.append(CompletionReasonCode.PENDING_TEST_REQUIREMENTS)
            if pending.correlation_pending:
                reason_codes.append(CompletionReasonCode.PENDING_CORRELATION_EVENTS)
            if pending.hypothesis_pending:
                reason_codes.append(CompletionReasonCode.PENDING_HYPOTHESES)
            if pending.authenticated_coverage_pending:
                reason_codes.append(CompletionReasonCode.AUTHENTICATED_COVERAGE_INCOMPLETE)
            if pending.role_coverage_pending:
                reason_codes.append(CompletionReasonCode.ROLE_COVERAGE_INCOMPLETE)
            reason_codes.append(CompletionReasonCode.PENDING_AUTHORIZED_WORK)
        # COMPLETE_WITH_ACCEPTED_GAPS
        elif accepted_count > 0 or (
            bound_reached
            and self.gap_policy.allows_completion_with_gaps(
                accepted_gap_count=accepted_count,
                pending_authorized_work=0,
                bound_reached=bound_reached,
            )
        ):
            status = CompletionStatus.COMPLETE_WITH_ACCEPTED_GAPS.value
            reason_codes.append(CompletionReasonCode.ACCEPTED_GAPS_PRESENT)
            if bound_reached:
                reason_codes.append(CompletionReasonCode.CORRELATION_BOUND_REACHED)
            if accepted_count:
                reason_codes.append(CompletionReasonCode.COVERAGE_ACCEPTED_BY_POLICY)
        # COMPLETE
        else:
            status = CompletionStatus.COMPLETE.value
            reason_codes.append(CompletionReasonCode.NO_ACTIONABLE_WORK_REMAINS)
            reason_codes.append(CompletionReasonCode.ALL_SCOPED_SURFACES_COVERED)
            if pending.manual_validation_pending == 0:
                reason_codes.append(CompletionReasonCode.MANUAL_BACKLOG_EMPTY)

        notes = self._completion_notes(status, pending, bound_reached)

        result = AssessmentCompletionResult(
            assessment_status=status,
            reason_codes=list(dict.fromkeys(reason_codes)),
            blocking_conditions=blocking_conditions,
            accepted_gaps=accepted,
            pending_work=pending,
            bound_reached=bound_reached,
            coverage_summary=coverage_summary,
            completion_notes=notes,
            evaluation_version=EVALUATION_VERSION,
        )

        if settings.assessment_completion_v2 or settings.pending_work_aware_completion:
            await self._persist_record(scan_id, result, record, job_id, details)

        logger.info(
            "assessment_completion_evaluated scan_id=%s assessment_status=%s "
            "reason_codes=%s pending_total=%d bound_reached=%s",
            scan_id,
            status,
            result.reason_codes,
            pending.total,
            bound_reached,
        )
        return result

    async def _get_or_create_record(self, scan_id: uuid.UUID) -> AssessmentCompletionRecord:
        record = (
            await self.session.execute(
                select(AssessmentCompletionRecord).where(
                    AssessmentCompletionRecord.scan_id == scan_id
                )
            )
        ).scalar_one_or_none()
        if not record:
            record = AssessmentCompletionRecord(
                scan_id=scan_id,
                status=CompletionStatus.INCOMPLETE.value,
            )
            self.session.add(record)
            await self.session.flush()
        return record

    async def _persist_record(
        self,
        scan_id: uuid.UUID,
        result: AssessmentCompletionResult,
        record: AssessmentCompletionRecord,
        job_id: str | None,
        details: dict[str, Any],
    ) -> None:
        previous_status = record.status
        record.status = result.assessment_status
        record.reason_codes = result.reason_codes
        record.pending_work_summary = result.pending_work.to_dict()
        record.bound_reached = result.bound_reached
        record.evaluation_version = result.evaluation_version
        if job_id:
            record.job_id = job_id
        record.blocking_items = result.blocking_conditions
        record.completion_reasons = {
            "reason_codes": result.reason_codes,
            "coverage_summary": result.coverage_summary,
            "details": details,
            "completion_notes": result.completion_notes,
        }
        record.metrics = {
            **result.pending_work.to_dict(),
            "open_validation_tasks": result.pending_work.manual_validation_pending,
            "blocking_test_requirement_count": details.get("blocking_requirements", 0),
            "blocking_gap_count": result.pending_work.surface_inventory_pending,
            "accepted_gap_count": sum(
                len(v) if isinstance(v, list) else 0 for v in result.accepted_gaps.values()
            ),
        }
        record.evaluated_at = datetime.now(UTC)
        await self.session.flush()

        if previous_status != result.assessment_status:
            await CompletionHistoryService(self.session).record_transition(
                scan_id=scan_id,
                previous_status=previous_status,
                new_status=result.assessment_status,
                result=result,
                job_id=job_id,
            )
            logger.info(
                "completion_history_transition scan_id=%s job_status=None assessment_status=%s "
                "previous=%s reason_codes=%s pending_work_count=%d accepted_gap_count=%d "
                "bound_reached=%s history_transition=true evaluation_version=%s",
                scan_id,
                result.assessment_status,
                previous_status,
                result.reason_codes,
                result.pending_work_count,
                sum(
                    len(v) if isinstance(v, list) else 0
                    for v in result.accepted_gaps.values()
                ),
                result.bound_reached,
                result.evaluation_version,
            )

    @staticmethod
    def _has_pending_authorized_work(
        pending: PendingAssessmentWork, details: dict[str, Any]
    ) -> bool:
        if pending.manual_validation_pending:
            return True
        if pending.coverage_pending:
            return True
        if pending.surface_inventory_pending:
            return True
        if pending.automated_validation_pending:
            return True
        if pending.hypothesis_pending:
            return True
        if pending.correlation_pending:
            return True
        if pending.authenticated_coverage_pending and not details.get("missing_auth_context"):
            return True
        if pending.role_coverage_pending:
            return True
        if details.get("blocking_requirements", 0) > 0:
            return True
        return False

    @staticmethod
    def _completion_notes(
        status: str, pending: PendingAssessmentWork, bound_reached: str | None
    ) -> str:
        if status == CompletionStatus.COMPLETE.value:
            return "All authorized assessment work is complete."
        if status == CompletionStatus.COMPLETE_WITH_ACCEPTED_GAPS.value:
            return "Assessment complete with explicitly accepted coverage gaps."
        if status == CompletionStatus.BLOCKED.value:
            return "Assessment blocked by missing credentials, authorization, or policy."
        if status == CompletionStatus.INCONCLUSIVE.value:
            return "Assessment inconclusive due to unresolved contradictory evidence."
        if bound_reached:
            return (
                f"Assessment incomplete: correlation bound reached ({bound_reached}) "
                f"with {pending.total} pending work items."
            )
        return f"Assessment incomplete: {pending.total} pending work items remain."
