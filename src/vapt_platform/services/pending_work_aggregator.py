"""Consolidated pending assessment work accounting (Phase 5)."""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from vapt_platform.db.tables.models import (
    Asset,
    AssetTestMatrix,
    AuthenticationContext,
    CorrelationEvent,
    CorrelationScanState,
    CoverageGap,
    EvidenceLink,
    Hypothesis,
    RoleContext,
    TestExecution,
    TestPlan,
    TestRequirement,
    ValidationTask,
    Verdict,
)
from vapt_platform.domain.assessment_completion import PendingAssessmentWork
from vapt_platform.domain.enums import (
    AssetType,
    HypothesisStatus,
    TestPlanStatus,
    TestRequirementCoverageStatus,
    ValidationTaskStatus,
    VerdictStatus,
)
from vapt_platform.engines.surface_completeness import SurfaceCompletenessEngine


_BLOCKING_REQ_STATUSES = {
    TestRequirementCoverageStatus.NOT_TESTED.value,
    TestRequirementCoverageStatus.PLANNED.value,
    TestRequirementCoverageStatus.TESTING.value,
    TestRequirementCoverageStatus.PARTIALLY_TESTED.value,
    TestRequirementCoverageStatus.INCONCLUSIVE.value,
}

_OPEN_PLAN_STATUSES = {
    TestPlanStatus.APPROVED.value,
    TestPlanStatus.SCHEDULED.value,
    TestPlanStatus.EXECUTING.value,
    TestPlanStatus.PENDING_APPROVAL.value,
}

_OPEN_HYPOTHESIS_STATUSES = {
    HypothesisStatus.PROPOSED.value,
    HypothesisStatus.NEEDS_MORE_EVIDENCE.value,
    HypothesisStatus.READY_FOR_VALIDATION.value,
    HypothesisStatus.VALIDATION_IN_PROGRESS.value,
}


class PendingWorkAggregator:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.surface_engine = SurfaceCompletenessEngine(session)

    async def aggregate(
        self,
        scan_id: uuid.UUID,
        *,
        accepted_gaps: dict | None = None,
    ) -> tuple[PendingAssessmentWork, dict]:
        work = PendingAssessmentWork()
        details: dict = {}

        open_tasks = list(
            (
                await self.session.execute(
                    select(ValidationTask).where(
                        ValidationTask.scan_id == scan_id,
                        ValidationTask.status.in_(
                            [
                                ValidationTaskStatus.OPEN.value,
                                ValidationTaskStatus.ASSIGNED.value,
                                ValidationTaskStatus.IN_PROGRESS.value,
                                ValidationTaskStatus.BLOCKED.value,
                                ValidationTaskStatus.INCONCLUSIVE.value,
                            ]
                        ),
                    )
                )
            )
            .scalars()
            .all()
        )
        work.manual_validation_pending = len(open_tasks)
        details["open_validation_tasks"] = len(open_tasks)

        matrices = list(
            (
                await self.session.execute(
                    select(AssetTestMatrix).where(AssetTestMatrix.scan_id == scan_id)
                )
            )
            .scalars()
            .all()
        )
        matrix_ids = [m.id for m in matrices]
        requirements = (
            list(
                (
                    await self.session.execute(
                        select(TestRequirement).where(TestRequirement.matrix_id.in_(matrix_ids))
                    )
                )
                .scalars()
                .all()
            )
            if matrix_ids
            else []
        )
        blocking_reqs = [r for r in requirements if r.coverage_status in _BLOCKING_REQ_STATUSES]
        work.coverage_pending = len(blocking_reqs)
        param_scopes = sum(
            len((r.reasoning_trace or {}).get("parameter_scopes", []))
            for r in blocking_reqs
            if (r.reasoning_trace or {}).get("parameter_scopes")
        )
        if param_scopes:
            details["parameter_scopes_pending"] = param_scopes

        open_plans = list(
            (
                await self.session.execute(
                    select(TestPlan).where(
                        TestPlan.scan_id == scan_id,
                        TestPlan.status.in_(_OPEN_PLAN_STATUSES),
                    )
                )
            )
            .scalars()
            .all()
        )
        work.automated_validation_pending += len(open_plans)

        pending_execs = list(
            (
                await self.session.execute(
                    select(TestExecution)
                    .join(TestPlan, TestExecution.test_plan_id == TestPlan.id)
                    .where(
                        TestPlan.scan_id == scan_id,
                        TestExecution.status.in_(("RUNNING", "EXECUTING", "PENDING")),
                    )
                )
            )
            .scalars()
            .all()
        )
        work.automated_validation_pending += len(pending_execs)

        open_hyps = list(
            (
                await self.session.execute(
                    select(Hypothesis).where(
                        Hypothesis.scan_id == scan_id,
                        Hypothesis.status.in_(_OPEN_HYPOTHESIS_STATUSES),
                    )
                )
            )
            .scalars()
            .all()
        )
        work.hypothesis_pending = len(open_hyps)

        open_gaps = list(
            (
                await self.session.execute(
                    select(CoverageGap).where(
                        CoverageGap.scan_id == scan_id,
                        CoverageGap.status == "OPEN",
                    )
                )
            )
            .scalars()
            .all()
        )
        work.coverage_pending += len(open_gaps)

        pending_corr = list(
            (
                await self.session.execute(
                    select(CorrelationEvent).where(
                        CorrelationEvent.scan_id == scan_id,
                        CorrelationEvent.status == "PENDING",
                    )
                )
            )
            .scalars()
            .all()
        )
        work.correlation_pending = len(pending_corr)

        contradict_links = list(
            (
                await self.session.execute(
                    select(EvidenceLink).where(
                        EvidenceLink.scan_id == scan_id,
                        EvidenceLink.link_type == "CONTRADICTS",
                        EvidenceLink.target_type == "HYPOTHESIS",
                    )
                )
            )
            .scalars()
            .all()
        )
        unresolved = 0
        for link in contradict_links:
            hyp = await self.session.get(Hypothesis, link.target_id)
            if hyp and hyp.status not in {
                HypothesisStatus.CONFIRMED.value,
                HypothesisStatus.REJECTED.value,
            }:
                verdict = await self.session.get(Verdict, hyp.verdict_id) if hyp.verdict_id else None
                if not verdict or verdict.status not in {
                    VerdictStatus.CONFIRMED.value,
                    VerdictStatus.REJECTED.value,
                }:
                    unresolved += 1
        work.contradiction_resolution_pending = unresolved

        accepted = accepted_gaps or {}
        web_apps = list(
            (
                await self.session.execute(
                    select(Asset).where(
                        Asset.scan_id == scan_id,
                        Asset.asset_type == AssetType.WEB_APPLICATION.value,
                    )
                )
            )
            .scalars()
            .all()
        )

        auth_contexts = list(
            (
                await self.session.execute(
                    select(AuthenticationContext).where(AuthenticationContext.scan_id == scan_id)
                )
            )
            .scalars()
            .all()
        )
        if not auth_contexts:
            for asset in web_apps:
                surface_reqs = await self.surface_engine.missing_requirements(
                    asset.id, scan_id, accepted_gaps=accepted
                )
                auth_blocking = [
                    r
                    for r in surface_reqs
                    if r.dimension == "AUTHENTICATED_AREA_COVERAGE" and r.blocking
                ]
                if auth_blocking:
                    work.authenticated_coverage_pending += len(auth_blocking)
                    details["missing_auth_context"] = True

        roles = list(
            (
                await self.session.execute(
                    select(RoleContext).where(RoleContext.scan_id == scan_id)
                )
            )
            .scalars()
            .all()
        )
        incomplete_roles = sum(
            1
            for r in roles
            for status in (r.coverage_status or {}).values()
            if status not in {"COMPLETE", "TESTED_NO_EVIDENCE"}
        )
        work.role_coverage_pending = incomplete_roles

        blocking_surface = 0
        for asset in web_apps:
            reqs = await self.surface_engine.missing_requirements(
                asset.id, scan_id, accepted_gaps=accepted
            )
            blocking_surface += sum(1 for r in reqs if r.blocking)
        work.surface_inventory_pending = blocking_surface

        corr_state = (
            await self.session.execute(
                select(CorrelationScanState).where(CorrelationScanState.scan_id == scan_id)
            )
        ).scalar_one_or_none()
        details["bound_reached"] = corr_state.bound_reached if corr_state else None

        details["blocking_requirements"] = len(blocking_reqs)
        details["open_coverage_gaps"] = len(open_gaps)
        return work, details
