"""Test plan split policy (Phase 9)."""

from __future__ import annotations

import logging
import uuid

from vapt_platform.db.tables.models import TestPlan, TestRequirement
from vapt_platform.domain.enums import TestPlanStatus
from vapt_platform.domain.plan_split_policy import PlanSplitAction, PlanSplitDecision
from vapt_platform.services.test_plan_uniqueness_policy import TestPlanUniquenessPolicy

logger = logging.getLogger(__name__)

POLICY_VERSION = "phase9-v1"
_ACTIVE_PLAN_STATUSES = {
    TestPlanStatus.DRAFT.value,
    TestPlanStatus.PENDING_APPROVAL.value,
    TestPlanStatus.APPROVED.value,
    TestPlanStatus.SCHEDULED.value,
    TestPlanStatus.EXECUTING.value,
    TestPlanStatus.COMPLETED.value,
}


class TestPlanSplitPolicy:
    def __init__(self) -> None:
        self._uniqueness = TestPlanUniquenessPolicy()

    def evaluate(
        self,
        *,
        scan_id: uuid.UUID,
        req: TestRequirement,
        asset_id: uuid.UUID,
        existing_plans: list[TestPlan],
    ) -> PlanSplitDecision:
        granularity = (req.scope_granularity or "SURFACE").upper()
        identity = self._uniqueness.build_identity(scan_id=scan_id, req=req, asset_id=asset_id)
        asset_ref = str(asset_id)
        class_ref = str(req.vulnerability_class_id)

        active = [
            p
            for p in existing_plans
            if p.status in _ACTIVE_PLAN_STATUSES
            and asset_ref in (p.asset_ids or [])
            and class_ref in (p.vulnerability_class_ids or [])
        ]

        for plan in active:
            decision = self._uniqueness.evaluate_existing(plan, identity)
            if decision.relation == "EQUIVALENT":
                return PlanSplitDecision(
                    action=PlanSplitAction.MERGE.value,
                    reason_codes=["equivalent_plan_exists"],
                    policy_version=POLICY_VERSION,
                )

        if granularity == "PARAMETER":
            broad_plans = [
                p
                for p in active
                if (p.plan_granularity or "SURFACE").upper() == "SURFACE"
            ]
            if broad_plans:
                logger.info(
                    "plan_split_decision scan_id=%s action=SPLIT broad_plan_id=%s granularity=PARAMETER",
                    scan_id,
                    broad_plans[0].id,
                )
                return PlanSplitDecision(
                    action=PlanSplitAction.SPLIT.value,
                    reason_codes=["parameter_scoped_from_broad_plan"],
                    split_from_plan_id=str(broad_plans[0].id),
                    policy_version=POLICY_VERSION,
                )
            return PlanSplitDecision(
                action=PlanSplitAction.KEEP_DISTINCT.value,
                reason_codes=["parameter_scoped_no_broad_parent"],
                policy_version=POLICY_VERSION,
            )

        if granularity == "SURFACE":
            return PlanSplitDecision(
                action=PlanSplitAction.KEEP_BROAD.value,
                reason_codes=["surface_granularity"],
                policy_version=POLICY_VERSION,
            )

        related = [
            p
            for p in active
            if self._uniqueness.evaluate_existing(p, identity).relation == "RELATED"
        ]
        if related:
            return PlanSplitDecision(
                action=PlanSplitAction.RELATED_ONLY.value,
                reason_codes=["related_plan_exists"],
                policy_version=POLICY_VERSION,
            )

        return PlanSplitDecision(
            action=PlanSplitAction.KEEP_DISTINCT.value,
            reason_codes=["default_distinct"],
            policy_version=POLICY_VERSION,
        )
