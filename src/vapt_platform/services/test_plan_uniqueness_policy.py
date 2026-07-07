"""TestPlan uniqueness policy (Phase 8)."""

from __future__ import annotations

import hashlib
import logging
import uuid
from typing import Any

from vapt_platform.db.tables.models import TestPlan, TestRequirement
from vapt_platform.domain.test_plan_uniqueness import PlanUniquenessDecision, PlanUniquenessRelation

logger = logging.getLogger(__name__)


class TestPlanUniquenessPolicy:
    def build_identity(
        self,
        *,
        scan_id: uuid.UUID,
        req: TestRequirement,
        asset_id: uuid.UUID,
    ) -> PlanUniquenessDecision:
        source_keys = [req.uniqueness_key] if req.uniqueness_key else []
        granularity = req.scope_granularity or "SURFACE"
        fingerprint = self.build_fingerprint(
            scan_id=scan_id,
            asset_id=asset_id,
            vulnerability_class_id=req.vulnerability_class_id,
            uniqueness_key=req.uniqueness_key or "",
            testing_mode=req.testing_mode,
            granularity=granularity,
        )
        uniqueness_key = fingerprint
        return PlanUniquenessDecision(
            relation=PlanUniquenessRelation.DISTINCT.value,
            planning_fingerprint=fingerprint,
            uniqueness_key=uniqueness_key,
            source_requirement_uniqueness_keys=source_keys,
            reason="new_plan_identity",
        )

    @staticmethod
    def build_fingerprint(
        *,
        scan_id: uuid.UUID,
        asset_id: uuid.UUID,
        vulnerability_class_id: uuid.UUID,
        uniqueness_key: str,
        testing_mode: str,
        granularity: str,
    ) -> str:
        parts = [
            str(scan_id),
            str(asset_id),
            str(vulnerability_class_id),
            uniqueness_key,
            testing_mode,
            granularity,
        ]
        return hashlib.sha256("|".join(parts).encode()).hexdigest()

    def evaluate_existing(
        self, plan: TestPlan, identity: PlanUniquenessDecision
    ) -> PlanUniquenessDecision:
        plan_fp = plan.planning_fingerprint or (plan.reasoning_trace or {}).get(
            "planning_fingerprint"
        )
        plan_key = plan.uniqueness_key or (plan.reasoning_trace or {}).get("uniqueness_key")
        if plan_fp and plan_fp == identity.planning_fingerprint:
            return PlanUniquenessDecision(
                relation=PlanUniquenessRelation.EQUIVALENT.value,
                planning_fingerprint=identity.planning_fingerprint,
                uniqueness_key=identity.uniqueness_key,
                source_requirement_uniqueness_keys=identity.source_requirement_uniqueness_keys,
                reason="equivalent_planning_fingerprint",
            )
        if plan_key and plan_key == identity.uniqueness_key:
            return PlanUniquenessDecision(
                relation=PlanUniquenessRelation.EQUIVALENT.value,
                planning_fingerprint=identity.planning_fingerprint,
                uniqueness_key=identity.uniqueness_key,
                source_requirement_uniqueness_keys=identity.source_requirement_uniqueness_keys,
                reason="equivalent_uniqueness_key",
            )
        shared = set(identity.source_requirement_uniqueness_keys) & set(
            plan.source_requirement_uniqueness_keys or []
        )
        if shared and plan_fp != identity.planning_fingerprint:
            return PlanUniquenessDecision(
                relation=PlanUniquenessRelation.RELATED.value,
                planning_fingerprint=identity.planning_fingerprint,
                uniqueness_key=identity.uniqueness_key,
                source_requirement_uniqueness_keys=identity.source_requirement_uniqueness_keys,
                reason="related_requirement_keys",
            )
        return PlanUniquenessDecision(
            relation=PlanUniquenessRelation.DISTINCT.value,
            planning_fingerprint=identity.planning_fingerprint,
            uniqueness_key=identity.uniqueness_key,
            source_requirement_uniqueness_keys=identity.source_requirement_uniqueness_keys,
            reason="distinct_plan",
        )

    def log_decision(
        self,
        *,
        scan_id: uuid.UUID,
        plan_id: str | None,
        decision: PlanUniquenessDecision,
    ) -> None:
        logger.info(
            "plan_uniqueness_decision scan_id=%s plan_id=%s relation=%s "
            "plan_uniqueness_key_prefix=%s reason=%s",
            scan_id,
            plan_id,
            decision.relation,
            decision.uniqueness_key[:12],
            decision.reason,
        )
