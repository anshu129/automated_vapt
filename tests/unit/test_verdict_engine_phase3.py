"""Verdict engine transition and V2 gating tests (Phase 3)."""

from __future__ import annotations

import uuid

import pytest

from sqlalchemy import select

from vapt_platform.db.tables.models import Hypothesis, Verdict, VerdictTransition
from vapt_platform.domain.enums import VerdictStatus
from vapt_platform.engines.assessment import VerdictEngine
from vapt_platform.engines.confirmation_policy import ConfirmationDecision


def test_transition_allowed_matrix() -> None:
    engine = VerdictEngine(session=None)  # type: ignore[arg-type]
    assert engine._transition_allowed(VerdictStatus.UNTESTED.value, VerdictStatus.TESTING.value)
    assert engine._transition_allowed(
        VerdictStatus.TESTING.value, VerdictStatus.PARTIALLY_VALIDATED.value
    )
    assert not engine._transition_allowed(VerdictStatus.REJECTED.value, VerdictStatus.CONFIRMED.value)


@pytest.mark.asyncio
async def test_invalid_transition_downgrades_to_inconclusive(db_session) -> None:
    from vapt_platform.services.core import ProjectService, ScanService

    project = await ProjectService(db_session).create("Verdict Transition")
    scan = await ScanService(db_session).create(project.id, "Verdict Scan", [])
    hyp = Hypothesis(
        scan_id=scan.id,
        title="Test hypothesis",
        hypothesis_type="DEFAULT",
        affected_asset_ids=[],
        status="READY_FOR_VALIDATION",
    )
    db_session.add(hyp)
    await db_session.flush()
    rejected = Verdict(
        scan_id=scan.id,
        hypothesis_id=hyp.id,
        status=VerdictStatus.REJECTED.value,
        confidence=0.5,
        supporting_evidence_ids=[],
        contradicting_evidence_ids=[],
        rule_ids=[],
        explanation="prior rejection",
    )
    db_session.add(rejected)
    await db_session.flush()
    hyp.verdict_id = rejected.id

    decision = ConfirmationDecision(
        recommended_verdict=VerdictStatus.CONFIRMED.value,
        requirements_satisfied=True,
        missing_evidence_types=[],
        supporting_evidence_ids=["node-1"],
        contradicting_evidence_ids=[],
        policy_id="DEFAULT",
        policy_version="1",
        reason_codes=["test"],
    )
    execution_id = uuid.uuid4()
    plan_id = uuid.uuid4()
    verdict = await VerdictEngine(db_session).apply_confirmation_decision(
        hypothesis_id=hyp.id,
        decision=decision,
        test_execution_id=execution_id,
        test_plan_id=plan_id,
        evidence_node_ids=["node-1"],
    )
    await db_session.commit()
    assert verdict is not None
    transition = (
        await db_session.execute(
            select(VerdictTransition).where(VerdictTransition.hypothesis_id == hyp.id)
        )
    ).scalar_one()
    assert transition.previous_state == VerdictStatus.REJECTED.value
    assert transition.new_state == VerdictStatus.INCONCLUSIVE.value


@pytest.mark.asyncio
async def test_v2_direct_confirm_without_validation_result_rejected(db_session) -> None:
    from vapt_platform.services.core import ProjectService, ScanService

    project = await ProjectService(db_session).create("V2 Guard")
    scan = await ScanService(db_session).create(project.id, "V2 Guard Scan", [])
    hyp = Hypothesis(
        scan_id=scan.id,
        title="Guard test",
        hypothesis_type="DEFAULT",
        affected_asset_ids=[],
        status="READY_FOR_VALIDATION",
    )
    db_session.add(hyp)
    await db_session.flush()

    with pytest.raises(ValueError, match="V2: CONFIRMED verdict requires ValidationResult"):
        await VerdictEngine(db_session).evaluate_hypothesis(
            hyp.id,
            "CONFIRMED",
            ["evidence-1"],
            recorded_by="scanner-bypass",
        )


@pytest.mark.asyncio
async def test_scanner_finding_alone_does_not_confirm_via_policy(db_session) -> None:
    from vapt_platform.engines.confirmation_policy import ConfirmationPolicy

    decision = ConfirmationPolicy().evaluate(
        vulnerability_class="INJECTION_CLASS",
        supporting_evidence=[{"id": "sf-1", "type": "SCANNER_FINDING"}],
        contradicting_evidence=[],
        coverage_evidence=[],
        has_validation_evidence=False,
        has_scanner_finding=True,
        has_negative_evidence=False,
    )
    assert decision.recommended_verdict != VerdictStatus.CONFIRMED.value
    assert not decision.requirements_satisfied
