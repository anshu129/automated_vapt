"""Evidence quality evaluator tests."""

from vapt_platform.domain.enums import Capability, EvidenceQualityStatus
from vapt_platform.evidence.quality import EvidenceQualityEvaluator, TargetContext, TaskRunResult


def test_positive_with_observations() -> None:
    ev = EvidenceQualityEvaluator()
    result = ev.evaluate(
        Capability.DNS_RESOLUTION,
        TaskRunResult(0, [{"type": "DNS_RECORD"}]),
        TargetContext(hostname="www.example.com"),
    )
    assert result.status == EvidenceQualityStatus.POSITIVE


def test_silent_dns_inconclusive() -> None:
    ev = EvidenceQualityEvaluator(no_discovery_assumption=True)
    result = ev.evaluate(
        Capability.DNS_RESOLUTION,
        TaskRunResult(0, []),
        TargetContext(hostname="www.example.com"),
        previous_attempts=0,
        fake_behavior="silent",
    )
    assert result.status == EvidenceQualityStatus.NEGATIVE_INCONCLUSIVE
    assert result.retry_allowed


def test_no_observations_not_conclusive_on_first_attempt() -> None:
    ev = EvidenceQualityEvaluator(no_discovery_assumption=True)
    result = ev.evaluate(
        Capability.HTTP_PROBING,
        TaskRunResult(0, []),
        TargetContext(),
        previous_attempts=0,
    )
    assert result.status == EvidenceQualityStatus.NEGATIVE_INCONCLUSIVE
