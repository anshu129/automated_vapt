"""Correlation rule protocol and result types (Phase 4)."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Protocol

from vapt_platform.domain.correlation_event import CorrelationEventData


class CorrelationResultType(StrEnum):
    RELATIONSHIP_CANDIDATE = "RELATIONSHIP_CANDIDATE"
    RELATIONSHIP_UPDATE = "RELATIONSHIP_UPDATE"
    HYPOTHESIS_CANDIDATE = "HYPOTHESIS_CANDIDATE"
    HYPOTHESIS_UPDATE = "HYPOTHESIS_UPDATE"
    COVERAGE_GAP_CANDIDATE = "COVERAGE_GAP_CANDIDATE"
    TEST_REQUIREMENT_CANDIDATE = "TEST_REQUIREMENT_CANDIDATE"
    NO_ACTION = "NO_ACTION"


@dataclass
class RuleDependencies:
    event_types: list[str] = field(default_factory=list)
    asset_types: list[str] = field(default_factory=list)
    relationship_types: list[str] = field(default_factory=list)
    vulnerability_classes: list[str] = field(default_factory=list)
    evidence_types: list[str] = field(default_factory=list)


@dataclass
class CorrelationContext:
    scan_id: uuid.UUID
    assets: dict[str, Any] = field(default_factory=dict)
    relationships: list[Any] = field(default_factory=list)
    hypotheses: list[Any] = field(default_factory=list)
    coverage_gaps: list[Any] = field(default_factory=list)
    auth_contexts: list[Any] = field(default_factory=list)
    role_contexts: list[Any] = field(default_factory=list)
    observations: list[Any] = field(default_factory=list)
    scanner_findings: list[Any] = field(default_factory=list)
    crawl_endpoints: set[str] = field(default_factory=set)
    js_endpoints: set[str] = field(default_factory=set)
    authorization_coverage: dict[str, str] = field(default_factory=dict)
    authenticated_coverage: dict[str, str] = field(default_factory=dict)
    parameters_by_endpoint: dict[str, list[str]] = field(default_factory=dict)
    technology_by_asset: dict[str, list[str]] = field(default_factory=dict)
    negative_evidence_scopes: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class CorrelationResult:
    result_type: str
    rule_id: str
    rule_version: str
    input_fact_ids: list[str] = field(default_factory=list)
    input_evidence_ids: list[str] = field(default_factory=list)
    participating_asset_ids: list[str] = field(default_factory=list)
    participating_surface_ids: list[str] = field(default_factory=list)
    participating_relationship_ids: list[str] = field(default_factory=list)
    supporting_evidence_ids: list[str] = field(default_factory=list)
    contradicting_evidence_ids: list[str] = field(default_factory=list)
    confidence: float = 0.5
    reason_codes: list[str] = field(default_factory=list)
    explanation_data: dict[str, Any] = field(default_factory=dict)
    result_fingerprint: str = ""
    payload: dict[str, Any] = field(default_factory=dict)


class CorrelationRule(Protocol):
    rule_id: str
    rule_version: str

    def dependencies(self) -> RuleDependencies: ...

    def evaluate(
        self,
        event: CorrelationEventData,
        context: CorrelationContext,
    ) -> list[CorrelationResult]: ...


@dataclass
class CorrelationProcessingResult:
    event_id: uuid.UUID
    rules_selected: list[str] = field(default_factory=list)
    rules_executed: int = 0
    results_applied: int = 0
    created_hypothesis_ids: list[str] = field(default_factory=list)
    updated_hypothesis_ids: list[str] = field(default_factory=list)
    created_coverage_gap_ids: list[str] = field(default_factory=list)
    created_test_requirement_ids: list[str] = field(default_factory=list)
    duplicate_suppression_count: int = 0
    follow_up_event_ids: list[str] = field(default_factory=list)
    bound_reached: str | None = None
