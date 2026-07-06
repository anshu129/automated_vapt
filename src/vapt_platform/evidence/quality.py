"""Evidence quality evaluation."""

from dataclasses import dataclass
from typing import Any

from vapt_platform.domain.enums import Capability, EvidenceQualityStatus, ExecutionProfile


@dataclass
class TaskRunResult:
    exit_code: int
    observations: list[dict[str, Any]]
    error_summary: str | None = None
    rate_limited: bool = False


@dataclass
class TargetContext:
    hostname: str | None = None
    capability: Capability | None = None
    execution_profile: str = ExecutionProfile.STANDARD.value


@dataclass
class EvidenceQualityDecisionData:
    status: EvidenceQualityStatus
    confidence: float
    reason_codes: list[str]
    explanation: str
    recommended_next_capability: Capability | None
    eligible_alternate_profiles: list[str]
    retry_allowed: bool
    manual_review_required: bool
    rule_ids: list[str]


INCONCLUSIVE_STATUSES = {
    EvidenceQualityStatus.NEGATIVE_INCONCLUSIVE,
    EvidenceQualityStatus.PARTIAL,
    EvidenceQualityStatus.FAILED,
    EvidenceQualityStatus.RATE_LIMITED,
    EvidenceQualityStatus.UNKNOWN,
}


class EvidenceQualityEvaluator:
    """Deterministic evidence quality classification."""

    def __init__(self, no_discovery_assumption: bool = True) -> None:
        self.no_discovery_assumption = no_discovery_assumption

    def evaluate(
        self,
        task_capability: Capability,
        result: TaskRunResult,
        target_context: TargetContext,
        previous_attempts: int = 0,
        fake_behavior: str | None = None,
    ) -> EvidenceQualityDecisionData:
        if result.rate_limited:
            return EvidenceQualityDecisionData(
                status=EvidenceQualityStatus.RATE_LIMITED,
                confidence=0.9,
                reason_codes=["HTTP_429_RATIO_EXCEEDED"],
                explanation="Rate limiting observed",
                recommended_next_capability=task_capability,
                eligible_alternate_profiles=[ExecutionProfile.CAUTIOUS.value],
                retry_allowed=True,
                manual_review_required=False,
                rule_ids=["eq-rate-limit"],
            )

        if result.exit_code != 0 or result.error_summary:
            return EvidenceQualityDecisionData(
                status=EvidenceQualityStatus.FAILED,
                confidence=0.8,
                reason_codes=["TOOL_ERROR"],
                explanation=result.error_summary or "Tool execution failed",
                recommended_next_capability=task_capability,
                eligible_alternate_profiles=[ExecutionProfile.HIGH_LATENCY.value],
                retry_allowed=previous_attempts < 2,
                manual_review_required=previous_attempts >= 2,
                rule_ids=["eq-failed"],
            )

        if fake_behavior == "silent":
            return self._handle_silent_dns(task_capability, previous_attempts)

        if not result.observations:
            return self._handle_no_observations(task_capability, previous_attempts)

        obs_types = {o.get("type") for o in result.observations}
        if "DNS_UNRESOLVED" in obs_types:
            return EvidenceQualityDecisionData(
                status=EvidenceQualityStatus.NEGATIVE_CONCLUSIVE,
                confidence=0.85,
                reason_codes=["NXDOMAIN_MULTI_RESOLVER"],
                explanation="DNS resolution returned NXDOMAIN",
                recommended_next_capability=None,
                eligible_alternate_profiles=[],
                retry_allowed=False,
                manual_review_required=False,
                rule_ids=["eq-dns-nxdomain"],
            )

        return EvidenceQualityDecisionData(
            status=EvidenceQualityStatus.POSITIVE,
            confidence=0.9,
            reason_codes=["OBSERVATIONS_PRESENT"],
            explanation="Positive observations collected",
            recommended_next_capability=None,
            eligible_alternate_profiles=[],
            retry_allowed=False,
            manual_review_required=False,
            rule_ids=["eq-positive"],
        )

    def _handle_silent_dns(
        self, capability: Capability, previous_attempts: int
    ) -> EvidenceQualityDecisionData:
        if self.no_discovery_assumption or previous_attempts < 1:
            return EvidenceQualityDecisionData(
                status=EvidenceQualityStatus.NEGATIVE_INCONCLUSIVE,
                confidence=0.4,
                reason_codes=["NO_RESPONSE_SINGLE_PROVIDER"],
                explanation="No DNS response; absence not conclusive",
                recommended_next_capability=capability,
                eligible_alternate_profiles=[ExecutionProfile.HIGH_LATENCY.value],
                retry_allowed=True,
                manual_review_required=False,
                rule_ids=["eq-dns-silent-inconclusive"],
            )
        return EvidenceQualityDecisionData(
            status=EvidenceQualityStatus.NEGATIVE_CONCLUSIVE,
            confidence=0.75,
            reason_codes=["NO_RESPONSE_AFTER_RETRIES"],
            explanation="No response after alternate attempts",
            recommended_next_capability=None,
            eligible_alternate_profiles=[],
            retry_allowed=False,
            manual_review_required=True,
            rule_ids=["eq-dns-silent-conclusive"],
        )

    def _handle_no_observations(
        self, capability: Capability, previous_attempts: int
    ) -> EvidenceQualityDecisionData:
        if previous_attempts < 1:
            return EvidenceQualityDecisionData(
                status=EvidenceQualityStatus.NEGATIVE_INCONCLUSIVE,
                confidence=0.3,
                reason_codes=["NO_OBSERVATIONS"],
                explanation="No observations; inconclusive",
                recommended_next_capability=capability,
                eligible_alternate_profiles=[ExecutionProfile.HIGH_LATENCY.value],
                retry_allowed=True,
                manual_review_required=False,
                rule_ids=["eq-no-obs-inconclusive"],
            )
        return EvidenceQualityDecisionData(
            status=EvidenceQualityStatus.UNKNOWN,
            confidence=0.2,
            reason_codes=["NO_OBSERVATIONS_EXHAUSTED"],
            explanation="No observations after retries",
            recommended_next_capability=None,
            eligible_alternate_profiles=[],
            retry_allowed=False,
            manual_review_required=True,
            rule_ids=["eq-no-obs-unknown"],
        )
