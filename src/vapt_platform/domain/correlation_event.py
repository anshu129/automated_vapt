"""Correlation event domain types (Phase 4)."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any


class CorrelationEventType(StrEnum):
    OBSERVATION_RECORDED = "OBSERVATION_RECORDED"
    SCANNER_FINDING_RECORDED = "SCANNER_FINDING_RECORDED"
    NEGATIVE_EVIDENCE_RECORDED = "NEGATIVE_EVIDENCE_RECORDED"
    COVERAGE_EVIDENCE_RECORDED = "COVERAGE_EVIDENCE_RECORDED"
    INCONCLUSIVE_EVIDENCE_RECORDED = "INCONCLUSIVE_EVIDENCE_RECORDED"
    VALIDATION_RESULT_RECORDED = "VALIDATION_RESULT_RECORDED"
    VERDICT_CHANGED = "VERDICT_CHANGED"
    ASSET_CREATED = "ASSET_CREATED"
    ASSET_UPDATED = "ASSET_UPDATED"
    RELATIONSHIP_CREATED = "RELATIONSHIP_CREATED"
    RELATIONSHIP_UPDATED = "RELATIONSHIP_UPDATED"
    ENDPOINT_DISCOVERED = "ENDPOINT_DISCOVERED"
    PARAMETER_DISCOVERED = "PARAMETER_DISCOVERED"
    SERVICE_DISCOVERED = "SERVICE_DISCOVERED"
    TECHNOLOGY_OBSERVED = "TECHNOLOGY_OBSERVED"
    AUTH_CONTEXT_AVAILABLE = "AUTH_CONTEXT_AVAILABLE"
    ROLE_CONTEXT_AVAILABLE = "ROLE_CONTEXT_AVAILABLE"
    AUTH_COVERAGE_CHANGED = "AUTH_COVERAGE_CHANGED"
    ROLE_COVERAGE_CHANGED = "ROLE_COVERAGE_CHANGED"
    COVERAGE_GAP_CREATED = "COVERAGE_GAP_CREATED"
    CHANGE_EVENT_RECORDED = "CHANGE_EVENT_RECORDED"
    CONFIRMED_FINDING_CREATED = "CONFIRMED_FINDING_CREATED"


@dataclass
class CorrelationEventData:
    """In-memory correlation event before persistence."""

    scan_id: uuid.UUID
    event_type: str
    source_type: str
    source_id: uuid.UUID
    asset_ids: list[str] = field(default_factory=list)
    surface_ids: list[str] = field(default_factory=list)
    relationship_ids: list[str] = field(default_factory=list)
    hypothesis_ids: list[str] = field(default_factory=list)
    vulnerability_classes: list[str] = field(default_factory=list)
    safe_context: dict[str, Any] = field(default_factory=dict)
    causation_id: uuid.UUID | None = None
    correlation_id: uuid.UUID | None = None
    generation: int = 0
    idempotency_key: str | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
