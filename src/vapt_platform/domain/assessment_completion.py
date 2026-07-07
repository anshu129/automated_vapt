"""Assessment completion result types (Phase 5)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


class CompletionReasonCode:
    ALL_SCOPED_SURFACES_COVERED = "ALL_SCOPED_SURFACES_COVERED"
    ACCEPTED_GAPS_PRESENT = "ACCEPTED_GAPS_PRESENT"
    MANUAL_BACKLOG_EMPTY = "MANUAL_BACKLOG_EMPTY"
    MANUAL_BACKLOG_REQUIRES_REVIEW = "MANUAL_BACKLOG_REQUIRES_REVIEW"
    AUTHENTICATED_COVERAGE_INCOMPLETE = "AUTHENTICATED_COVERAGE_INCOMPLETE"
    ROLE_COVERAGE_INCOMPLETE = "ROLE_COVERAGE_INCOMPLETE"
    CORRELATION_BOUND_REACHED = "CORRELATION_BOUND_REACHED"
    PENDING_AUTHORIZED_WORK = "PENDING_AUTHORIZED_WORK"
    PENDING_BLOCKED_WORK = "PENDING_BLOCKED_WORK"
    PENDING_MANUAL_VALIDATION = "PENDING_MANUAL_VALIDATION"
    PENDING_CORRELATION_REEVALUATION = "PENDING_CORRELATION_REEVALUATION"
    UNRESOLVED_CONTRADICTIONS = "UNRESOLVED_CONTRADICTIONS"
    COVERAGE_ACCEPTED_BY_POLICY = "COVERAGE_ACCEPTED_BY_POLICY"
    COVERAGE_INVALIDATED = "COVERAGE_INVALIDATED"
    NO_ACTIONABLE_WORK_REMAINS = "NO_ACTIONABLE_WORK_REMAINS"
    REQUIRED_CREDENTIALS_MISSING = "REQUIRED_CREDENTIALS_MISSING"
    REQUIRED_AUTHORIZATION_MISSING = "REQUIRED_AUTHORIZATION_MISSING"
    SAFETY_POLICY_BLOCKING = "SAFETY_POLICY_BLOCKING"
    SCAN_SCOPE_EXHAUSTED = "SCAN_SCOPE_EXHAUSTED"
    PENDING_TEST_REQUIREMENTS = "PENDING_TEST_REQUIREMENTS"
    PENDING_HYPOTHESES = "PENDING_HYPOTHESES"
    PENDING_CORRELATION_EVENTS = "PENDING_CORRELATION_EVENTS"
    PENDING_COVERAGE_GAPS = "PENDING_COVERAGE_GAPS"


@dataclass
class PendingAssessmentWork:
    discovery_pending: int = 0
    surface_inventory_pending: int = 0
    coverage_pending: int = 0
    automated_validation_pending: int = 0
    manual_validation_pending: int = 0
    contradiction_resolution_pending: int = 0
    revalidation_pending: int = 0
    authenticated_coverage_pending: int = 0
    role_coverage_pending: int = 0
    policy_blocked_pending: int = 0
    correlation_pending: int = 0
    hypothesis_pending: int = 0

    @property
    def total(self) -> int:
        return (
            self.discovery_pending
            + self.surface_inventory_pending
            + self.coverage_pending
            + self.automated_validation_pending
            + self.manual_validation_pending
            + self.contradiction_resolution_pending
            + self.revalidation_pending
            + self.authenticated_coverage_pending
            + self.role_coverage_pending
            + self.policy_blocked_pending
            + self.correlation_pending
            + self.hypothesis_pending
        )

    def to_dict(self) -> dict[str, int]:
        return {
            "discovery_pending": self.discovery_pending,
            "surface_inventory_pending": self.surface_inventory_pending,
            "coverage_pending": self.coverage_pending,
            "automated_validation_pending": self.automated_validation_pending,
            "manual_validation_pending": self.manual_validation_pending,
            "contradiction_resolution_pending": self.contradiction_resolution_pending,
            "revalidation_pending": self.revalidation_pending,
            "authenticated_coverage_pending": self.authenticated_coverage_pending,
            "role_coverage_pending": self.role_coverage_pending,
            "policy_blocked_pending": self.policy_blocked_pending,
            "correlation_pending": self.correlation_pending,
            "hypothesis_pending": self.hypothesis_pending,
            "total": self.total,
        }


@dataclass
class AssessmentCompletionResult:
    assessment_status: str
    reason_codes: list[str] = field(default_factory=list)
    blocking_conditions: list[str] = field(default_factory=list)
    accepted_gaps: dict[str, Any] = field(default_factory=dict)
    pending_work: PendingAssessmentWork = field(default_factory=PendingAssessmentWork)
    bound_reached: str | None = None
    coverage_summary: dict[str, Any] = field(default_factory=dict)
    completion_notes: str = ""
    policy_version: str = "1.0"
    evaluation_version: str = "phase5-v1"

    @property
    def pending_work_count(self) -> int:
        return self.pending_work.total

    def to_report_dict(self) -> dict[str, Any]:
        return {
            "assessment_status": self.assessment_status,
            "reason_codes": self.reason_codes,
            "blocking_conditions": self.blocking_conditions,
            "accepted_gaps": self.accepted_gaps,
            "pending_work": self.pending_work.to_dict(),
            "bound_reached": self.bound_reached,
            "coverage_summary": self.coverage_summary,
            "completion_notes": self.completion_notes,
            "policy_version": self.policy_version,
            "evaluation_version": self.evaluation_version,
        }
