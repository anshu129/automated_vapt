"""Full assessment orchestration — Phase 1 refresh chain.

Connects recon quiescence → surface refresh → applicability → test matrix →
requirement enrichment before test planning.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from vapt_platform.config.settings import get_settings
from vapt_platform.db.tables.models import Asset, AssetTestMatrix, TestRequirement
from vapt_platform.domain.enums import ApplicabilityState
from vapt_platform.engines.assessment import TestMatrixEngine
from vapt_platform.engines.surface_completeness import SurfaceCompletenessEngine
from vapt_platform.engines.vulnerability_applicability import VulnerabilityApplicabilityEngine
from vapt_platform.services.core import ScanService

_APPLICABLE_STATES = {
    ApplicabilityState.APPLICABLE.value,
    ApplicabilityState.POSSIBLY_APPLICABLE.value,
}


@dataclass
class AssessmentRefreshSummary:
    scan_id: str
    assets_refreshed: int = 0
    surfaces_computed: int = 0
    applicability_rows: int = 0
    matrices_built: int = 0
    requirements_enriched: int = 0
    applicable_requirements: int = 0
    details: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "assets_refreshed": self.assets_refreshed,
            "surfaces_computed": self.surfaces_computed,
            "applicability_rows": self.applicability_rows,
            "matrices_built": self.matrices_built,
            "requirements_enriched": self.requirements_enriched,
            "applicable_requirements": self.applicable_requirements,
        }


class FullAssessmentService:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def run_recon_until_quiescent(self, scan_id: uuid.UUID) -> int:
        """Execute the bounded recon pipeline until no READY tasks remain."""
        return await ScanService(self.session).run_recon_pipeline(scan_id)

    async def refresh_assessment_state(self, scan_id: uuid.UUID) -> AssessmentRefreshSummary:
        """Surface → applicability → matrix → requirement enrichment for all assets."""
        summary = AssessmentRefreshSummary(scan_id=str(scan_id))
        assets = list(
            (await self.session.execute(select(Asset).where(Asset.scan_id == scan_id)))
            .scalars()
            .all()
        )
        surface_engine = SurfaceCompletenessEngine(self.session)
        applicability_engine = VulnerabilityApplicabilityEngine(self.session)
        matrix_engine = TestMatrixEngine(self.session)

        for asset in assets:
            summary.assets_refreshed += 1
            await surface_engine.compute(scan_id, asset.id)
            summary.surfaces_computed += 1

            rows = await applicability_engine.reevaluate(asset.id, scan_id)
            summary.applicability_rows += len(rows)

            await matrix_engine.build(scan_id, asset.id)
            summary.matrices_built += 1

        req_rows = list(
            (
                await self.session.execute(
                    select(TestRequirement)
                    .join(
                        AssetTestMatrix,
                        TestRequirement.matrix_id == AssetTestMatrix.id,
                    )
                    .where(AssetTestMatrix.scan_id == scan_id)
                )
            )
            .scalars()
            .all()
        )
        for req in req_rows:
            if req.reasoning_trace.get("why") and req.source_rule_ids is not None:
                summary.requirements_enriched += 1
            if req.applicability_state in _APPLICABLE_STATES:
                summary.applicable_requirements += 1

        await self.session.flush()
        return summary

    async def prepare_for_planning(self, scan_id: uuid.UUID) -> AssessmentRefreshSummary:
        """Run recon (when configured) then refresh assessment state."""
        settings = get_settings()
        if settings.ui_scan_inline_recon and not settings.scan_start_inline_execution:
            await self.run_recon_until_quiescent(scan_id)
        return await self.refresh_assessment_state(scan_id)

    async def plan_tests(self, scan_id: uuid.UUID):
        """Create TestPlans from enriched requirements."""
        from vapt_platform.engines.assessment import TestPlanner

        return await TestPlanner(self.session).plan_scan(scan_id)

    async def execute_automated_plans(
        self,
        scan_id: uuid.UUID,
        *,
        active_validation_allowed: bool = False,
        username: str | None = None,
        password: str | None = None,
    ):
        """Route automated TestPlans through CapabilityValidationRouter."""
        from vapt_platform.services.capability_validation_router import (
            CapabilityValidationRouter,
        )

        return await CapabilityValidationRouter(self.session).execute_scan_plans(
            scan_id,
            active_validation_allowed=active_validation_allowed,
            username=username,
            password=password,
        )

    async def process_pending_correlation_events(self, scan_id: uuid.UUID):
        from vapt_platform.services.correlation_event_processor import CorrelationEventProcessor

        return await CorrelationEventProcessor(self.session).process_pending(scan_id)

    async def reevaluate_affected_hypotheses(self, scan_id: uuid.UUID, event_ids: list[uuid.UUID] | None = None):
        from sqlalchemy import select

        from vapt_platform.db.tables.models import CorrelationEvent
        from vapt_platform.domain.correlation_event import CorrelationEventData
        from vapt_platform.services.hypothesis_reevaluation import HypothesisReevaluationService

        service = HypothesisReevaluationService(self.session)
        if event_ids:
            events = [await self.session.get(CorrelationEvent, eid) for eid in event_ids]
        else:
            events = list(
                (
                    await self.session.execute(
                        select(CorrelationEvent).where(
                            CorrelationEvent.scan_id == scan_id,
                            CorrelationEvent.status == "PROCESSED",
                        )
                    )
                )
                .scalars()
                .all()
            )
        summaries = []
        for row in events:
            if not row:
                continue
            event = CorrelationEventData(
                scan_id=row.scan_id,
                event_type=row.event_type,
                source_type=row.source_type,
                source_id=row.source_id,
                asset_ids=list(row.asset_ids or []),
                hypothesis_ids=list(row.hypothesis_ids or []),
                vulnerability_classes=list(row.vulnerability_classes or []),
                safe_context=dict(row.safe_context or {}),
                causation_id=row.causation_id,
                correlation_id=row.correlation_id,
                generation=row.generation,
            )
            summaries.append(await service.reevaluate_for_event(event))
        return summaries

    async def plan_new_requirements(self, scan_id: uuid.UUID):
        return await self.plan_tests(scan_id)

    async def execute_new_automated_plans(
        self,
        scan_id: uuid.UUID,
        *,
        active_validation_allowed: bool = False,
        username: str | None = None,
        password: str | None = None,
    ):
        return await self.execute_automated_plans(
            scan_id,
            active_validation_allowed=active_validation_allowed,
            username=username,
            password=password,
        )

    async def run_recursive_assessment_loop(
        self,
        scan_id: uuid.UUID,
        *,
        max_generations: int | None = None,
        active_validation_allowed: bool = False,
        username: str | None = None,
        password: str | None = None,
    ) -> dict:
        from vapt_platform.services.correlation_event_service import CorrelationEventService

        settings = get_settings()
        if not settings.recursive_correlation_enabled:
            return {"enabled": False, "generations": 0}

        limit = max_generations or settings.correlation_max_generations
        processor_summaries = []
        execution_summaries = []
        generation = 0
        quiescent = False

        while generation <= limit:
            pending_before = await CorrelationEventService(self.session).pending_events(scan_id)
            if generation == 0 and not pending_before:
                await self.prepare_for_planning(scan_id)
                await self.plan_tests(scan_id)
                execution_summaries.append(
                    await self.execute_automated_plans(
                        scan_id,
                        active_validation_allowed=active_validation_allowed,
                        username=username,
                        password=password,
                    )
                )

            summaries = await self.process_pending_correlation_events(scan_id)
            processor_summaries.extend(summaries)
            await self.reevaluate_affected_hypotheses(scan_id)
            await self.plan_new_requirements(scan_id)
            exec_result = await self.execute_new_automated_plans(
                scan_id,
                active_validation_allowed=active_validation_allowed,
                username=username,
                password=password,
            )
            execution_summaries.append(exec_result)

            pending_after = await CorrelationEventService(self.session).pending_events(scan_id)
            meaningful = any(
                s.created_hypothesis_ids or s.created_test_requirement_ids or s.results_applied
                for s in summaries
            )
            if not pending_after and not meaningful:
                quiescent = True
                break
            if generation >= limit:
                state = await CorrelationEventService(self.session).get_scan_state(scan_id)
                if not state.bound_reached:
                    state.bound_reached = "CORRELATION_MAX_GENERATIONS"
                    state.bound_context = {"generation": generation, "limit": limit}
                break
            generation += 1

        state = await CorrelationEventService(self.session).get_scan_state(scan_id)
        return {
            "enabled": True,
            "generations": generation,
            "quiescent": quiescent,
            "bound_reached": state.bound_reached,
            "events_processed": state.events_processed,
            "hypotheses_created": state.hypotheses_created,
            "requirements_created": state.requirements_created,
        }

    async def evaluate_completion(
        self, scan_id: uuid.UUID, *, job_id: str | None = None
    ):
        from vapt_platform.services.assessment_completion_evaluator import (
            AssessmentCompletionEvaluatorService,
        )

        return await AssessmentCompletionEvaluatorService(self.session).evaluate(
            scan_id, job_id=job_id
        )

    async def finalize_assessment(
        self, scan_id: uuid.UUID, *, job_id: str | None = None
    ):
        from vapt_platform.services.correlation_event_service import CorrelationEventService

        settings = get_settings()
        if settings.recursive_correlation_enabled:
            await self.process_pending_correlation_events(scan_id)
        result = await self.evaluate_completion(scan_id, job_id=job_id)
        settings = get_settings()
        if settings.phase9_staleness_polling_enabled or settings.phase8_report_staleness_detection_enabled:
            from vapt_platform.services.report_staleness_service import ReportStalenessService

            await ReportStalenessService(self.session).mark_snapshot_stale_flags(scan_id)
        if settings.phase6_status_sync_enabled:
            from vapt_platform.db.tables.models import Scan
            from vapt_platform.domain.enums import ScanStatus

            scan = await self.session.get(Scan, scan_id)
            if scan and scan.status == ScanStatus.CREATED.value:
                scan.status = ScanStatus.RUNNING.value
        await self.session.flush()
        return result

    async def sync_scan_lifecycle_on_job_end(
        self, scan_id: uuid.UUID, *, job_status: str
    ) -> None:
        """Align scan lifecycle status with job outcome without touching assessment status."""
        settings = get_settings()
        if not settings.phase6_status_sync_enabled:
            return
        from vapt_platform.db.tables.models import Scan
        from vapt_platform.domain.enums import ScanStatus

        scan = await self.session.get(Scan, scan_id)
        if not scan:
            return
        if job_status == "COMPLETED" and scan.status != ScanStatus.CANCELLED.value:
            scan.status = ScanStatus.COMPLETED.value
        elif job_status in {"QUEUED", "RUNNING"}:
            scan.status = ScanStatus.RUNNING.value

    async def update_assessment_status(self, scan_id: uuid.UUID) -> None:
        await self.evaluate_completion(scan_id)
        await self.session.flush()

