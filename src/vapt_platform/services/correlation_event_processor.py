"""Process correlation events through rules (Phase 4)."""

from __future__ import annotations

import hashlib
import logging
import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from vapt_platform.config.settings import get_settings
from vapt_platform.db.tables.models import CorrelationEvent, CorrelationExecution, CorrelationScanState
from vapt_platform.domain.correlation_event import CorrelationEventData, CorrelationEventType
from vapt_platform.domain.correlation_rule import CorrelationContext, CorrelationProcessingResult
from vapt_platform.engines.correlation_rule_registry import CorrelationRuleRegistry
from vapt_platform.services.correlation_event_service import CorrelationEventService
from vapt_platform.services.correlation_result_applier import CorrelationResultApplier

logger = logging.getLogger(__name__)


class CorrelationEventProcessor:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.registry = CorrelationRuleRegistry()
        self.event_service = CorrelationEventService(session)
        self.applier = CorrelationResultApplier(session)

    async def process_event(self, event_id: uuid.UUID) -> CorrelationProcessingResult:
        event_row = await self.session.get(CorrelationEvent, event_id)
        if not event_row or event_row.status != "PENDING":
            return CorrelationProcessingResult(event_id=event_id)

        settings = get_settings()
        state = await self.event_service.get_scan_state(event_row.scan_id)
        if state.bound_reached:
            return CorrelationProcessingResult(event_id=event_id, bound_reached=state.bound_reached)

        event = CorrelationEventData(
            scan_id=event_row.scan_id,
            event_type=event_row.event_type,
            source_type=event_row.source_type,
            source_id=event_row.source_id,
            asset_ids=list(event_row.asset_ids or []),
            surface_ids=list(event_row.surface_ids or []),
            relationship_ids=list(event_row.relationship_ids or []),
            hypothesis_ids=list(event_row.hypothesis_ids or []),
            vulnerability_classes=list(event_row.vulnerability_classes or []),
            safe_context=dict(event_row.safe_context or {}),
            causation_id=event_row.causation_id,
            correlation_id=event_row.correlation_id,
            generation=event_row.generation,
        )

        rules = self.registry.dependency_index().rules_for(event)
        context = self._build_context(event)
        result_summary = CorrelationProcessingResult(
            event_id=event_id,
            rules_selected=[r.rule_id for r in rules],
        )

        for rule in rules:
            if state.rules_executed >= settings.correlation_max_rule_executions_per_scan:
                state.bound_reached = "CORRELATION_MAX_RULE_EXECUTIONS_PER_SCAN"
                result_summary.bound_reached = state.bound_reached
                break

            input_fp = self._input_fingerprint(event_id, rule.rule_id, event)
            existing_exec = (
                await self.session.execute(
                    select(CorrelationExecution).where(
                        CorrelationExecution.scan_id == event_row.scan_id,
                        CorrelationExecution.input_fingerprint == input_fp,
                    )
                )
            ).scalar_one_or_none()
            if existing_exec:
                result_summary.duplicate_suppression_count += 1
                continue

            execution = CorrelationExecution(
                scan_id=event_row.scan_id,
                event_id=event_id,
                rule_id=rule.rule_id,
                rule_version=rule.rule_version,
                input_fingerprint=input_fp,
                result_fingerprint="",
                status="PENDING",
            )
            self.session.add(execution)
            await self.session.flush()

            try:
                results = rule.evaluate(event, context)
                applied = 0
                for corr_result in results:
                    apply_summary = await self.applier.apply(
                        scan_id=event_row.scan_id,
                        event_id=event_id,
                        result=corr_result,
                    )
                    applied += 1
                    result_summary.created_hypothesis_ids.extend(apply_summary.created_hypothesis_ids)
                    result_summary.updated_hypothesis_ids.extend(apply_summary.updated_hypothesis_ids)
                    result_summary.created_coverage_gap_ids.extend(
                        apply_summary.created_coverage_gap_ids
                    )
                    result_summary.created_test_requirement_ids.extend(
                        apply_summary.created_test_requirement_ids
                    )
                    result_summary.duplicate_suppression_count += (
                        apply_summary.duplicate_suppression_count
                    )
                    if apply_summary.meaningful_change:
                        follow_up = await self._maybe_emit_follow_up(
                            event_row, corr_result, apply_summary
                        )
                        if follow_up:
                            result_summary.follow_up_event_ids.append(str(follow_up.id))

                execution.status = "COMPLETED" if applied else "NO_CHANGE"
                execution.result_fingerprint = hashlib.sha256(
                    f"{rule.rule_id}:{applied}".encode()
                ).hexdigest()
                execution.completed_at = datetime.now(UTC)
                state.rules_executed += 1
                result_summary.rules_executed += 1
                result_summary.results_applied += applied
            except Exception:
                execution.status = "FAILED"
                execution.completed_at = datetime.now(UTC)
                logger.exception("correlation_rule_failed rule_id=%s event_id=%s", rule.rule_id, event_id)

        event_row.status = "PROCESSED"
        event_row.processed_at = datetime.now(UTC)
        state.events_processed += 1
        state.hypotheses_created += len(result_summary.created_hypothesis_ids)
        state.requirements_created += len(result_summary.created_test_requirement_ids)
        state.updated_at = datetime.now(UTC)
        await self.session.flush()

        logger.info(
            "correlation_event_processed scan_id=%s event_id=%s rules=%s hypotheses=%d requirements=%d",
            event_row.scan_id,
            event_id,
            result_summary.rules_selected,
            len(result_summary.created_hypothesis_ids),
            len(result_summary.created_test_requirement_ids),
        )
        return result_summary

    async def process_pending(self, scan_id: uuid.UUID) -> list[CorrelationProcessingResult]:
        pending = await self.event_service.pending_events(scan_id)
        summaries: list[CorrelationProcessingResult] = []
        for event in pending:
            summaries.append(await self.process_event(event.id))
        return summaries

    def _build_context(self, event: CorrelationEventData) -> CorrelationContext:
        ctx = event.safe_context
        return CorrelationContext(
            scan_id=event.scan_id,
            js_endpoints=set(ctx.get("js_endpoints") or []),
            crawl_endpoints=set(ctx.get("crawl_endpoints") or []),
            authorization_coverage=dict(ctx.get("authorization_coverage") or {}),
            authenticated_coverage=dict(ctx.get("authenticated_coverage") or {}),
        )

    @staticmethod
    def _input_fingerprint(event_id: uuid.UUID, rule_id: str, event: CorrelationEventData) -> str:
        raw = f"{event_id}|{rule_id}|{event.event_type}|{event.generation}"
        return hashlib.sha256(raw.encode()).hexdigest()

    async def _maybe_emit_follow_up(self, parent_event, corr_result, apply_summary):
        if not apply_summary.meaningful_change:
            return None
        if apply_summary.created_coverage_gap_ids:
            event_type = CorrelationEventType.COVERAGE_GAP_CREATED.value
        elif apply_summary.created_hypothesis_ids:
            return None
        elif apply_summary.created_test_requirement_ids:
            return None
        else:
            return None
        return await self.event_service.emit(
            CorrelationEventData(
                scan_id=parent_event.scan_id,
                event_type=event_type,
                source_type="CORRELATION_RESULT",
                source_id=parent_event.id,
                asset_ids=list(parent_event.asset_ids or []),
                causation_id=parent_event.id,
                correlation_id=parent_event.correlation_id,
                generation=parent_event.generation + 1,
                idempotency_key=f"{parent_event.id}:{corr_result.result_fingerprint}",
                safe_context={"gap_ids": apply_summary.created_coverage_gap_ids},
            )
        )
