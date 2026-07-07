"""Phase 8 test plan uniqueness unit tests."""

from __future__ import annotations

import uuid

from vapt_platform.db.tables.models import TestPlan, TestRequirement
from vapt_platform.domain.test_plan_uniqueness import PlanUniquenessRelation
from vapt_platform.services.test_plan_uniqueness_policy import TestPlanUniquenessPolicy


def test_equivalent_fingerprint() -> None:
    policy = TestPlanUniquenessPolicy()
    scan_id = uuid.uuid4()
    asset_id = uuid.uuid4()
    class_id = uuid.uuid4()
    req = TestRequirement(
        matrix_id=uuid.uuid4(),
        vulnerability_class_id=class_id,
        uniqueness_key="key-a",
        scope_granularity="PARAMETER",
        testing_mode="AUTOMATED",
    )
    identity = policy.build_identity(scan_id=scan_id, req=req, asset_id=asset_id)
    plan = TestPlan(
        scan_id=scan_id,
        testing_mode="AUTOMATED",
        safety_class="PASSIVE",
        planning_fingerprint=identity.planning_fingerprint,
        uniqueness_key=identity.uniqueness_key,
    )
    decision = policy.evaluate_existing(plan, identity)
    assert decision.relation == PlanUniquenessRelation.EQUIVALENT.value


def test_distinct_parameter_scoped_fingerprints() -> None:
    policy = TestPlanUniquenessPolicy()
    scan_id = uuid.uuid4()
    asset_id = uuid.uuid4()
    class_id = uuid.uuid4()
    req_a = TestRequirement(
        matrix_id=uuid.uuid4(),
        vulnerability_class_id=class_id,
        uniqueness_key="param-id",
        scope_granularity="PARAMETER",
        testing_mode="AUTOMATED",
    )
    req_b = TestRequirement(
        matrix_id=uuid.uuid4(),
        vulnerability_class_id=class_id,
        uniqueness_key="param-q",
        scope_granularity="PARAMETER",
        testing_mode="AUTOMATED",
    )
    id_a = policy.build_identity(scan_id=scan_id, req=req_a, asset_id=asset_id)
    id_b = policy.build_identity(scan_id=scan_id, req=req_b, asset_id=asset_id)
    assert id_a.planning_fingerprint != id_b.planning_fingerprint
