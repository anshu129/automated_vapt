"""Unit tests for ConfirmationPolicy."""

from vapt_platform.domain.enums import VerdictStatus
from vapt_platform.engines.confirmation_policy import ConfirmationPolicy


def test_insufficient_scanner_evidence_partially_validated() -> None:
    decision = ConfirmationPolicy().evaluate(
        vulnerability_class="SECURITY_HEADERS",
        supporting_evidence=[{"id": "node-1", "type": "SCANNER_FINDING"}],
        contradicting_evidence=[],
        coverage_evidence=[],
        has_validation_evidence=False,
        has_scanner_finding=True,
        has_negative_evidence=False,
    )
    assert decision.recommended_verdict == VerdictStatus.REQUIRES_MANUAL_REVIEW.value
    assert not decision.requirements_satisfied


def test_sufficient_validation_evidence_confirmed() -> None:
    decision = ConfirmationPolicy().evaluate(
        vulnerability_class="INJECTION_CLASS",
        supporting_evidence=[{"id": "n1"}],
        contradicting_evidence=[],
        coverage_evidence=[{"id": "c1"}],
        has_validation_evidence=True,
        has_scanner_finding=True,
        has_negative_evidence=False,
    )
    assert decision.recommended_verdict == VerdictStatus.CONFIRMED.value
    assert decision.requirements_satisfied


def test_decisive_negative_rejected() -> None:
    decision = ConfirmationPolicy().evaluate(
        vulnerability_class="INJECTION_CLASS",
        supporting_evidence=[],
        contradicting_evidence=[{"id": "neg-1"}],
        coverage_evidence=[{"id": "c1"}],
        has_validation_evidence=False,
        has_scanner_finding=False,
        has_negative_evidence=True,
    )
    assert decision.recommended_verdict == VerdictStatus.REJECTED.value


def test_conflicting_evidence_inconclusive() -> None:
    decision = ConfirmationPolicy().evaluate(
        vulnerability_class="DEFAULT",
        supporting_evidence=[{"id": "s1"}],
        contradicting_evidence=[{"id": "c1"}],
        coverage_evidence=[],
        has_validation_evidence=False,
        has_scanner_finding=True,
        has_negative_evidence=True,
    )
    assert decision.recommended_verdict == VerdictStatus.INCONCLUSIVE.value
