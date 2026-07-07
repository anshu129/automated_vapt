"""Normalized assessment artifacts (Phase 3)."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any


class NormalizedArtifactType(StrEnum):
    OBSERVATION = "OBSERVATION"
    SCANNER_FINDING = "SCANNER_FINDING"
    NEGATIVE_EVIDENCE = "NEGATIVE_EVIDENCE"
    COVERAGE_EVIDENCE = "COVERAGE_EVIDENCE"
    EXECUTION_ERROR = "EXECUTION_ERROR"
    INCONCLUSIVE_EVIDENCE = "INCONCLUSIVE_EVIDENCE"


class ExecutionSemantics(StrEnum):
    POSITIVE_RESULT = "POSITIVE_RESULT"
    CLEAN_NEGATIVE = "CLEAN_NEGATIVE"
    TIMEOUT = "TIMEOUT"
    PARSER_FAILED = "PARSER_FAILED"
    TRANSPORT_FAILED = "TRANSPORT_FAILED"
    PROVIDER_UNAVAILABLE = "PROVIDER_UNAVAILABLE"
    PARTIAL_RESULT = "PARTIAL_RESULT"
    AMBIGUOUS_RESULT = "AMBIGUOUS_RESULT"


NORMALIZER_VERSION = "1.0"


@dataclass
class NormalizedArtifact:
    artifact_type: str
    scan_id: str
    asset_id: str | None = None
    surface_id: str | None = None
    endpoint_id: str | None = None
    parameter_id: str | None = None
    test_requirement_id: str | None = None
    test_plan_id: str | None = None
    test_execution_id: str | None = None
    provider_id: str | None = None
    executed_capability: str | None = None
    provider_selection_decision_id: str | None = None
    vulnerability_class: str | None = None
    title: str | None = None
    description: str | None = None
    confidence: float = 0.5
    evidence_payload: dict[str, Any] = field(default_factory=dict)
    safe_metadata: dict[str, Any] = field(default_factory=dict)
    execution_semantics: str | None = None
    observed_at: datetime | None = None
    normalizer_version: str = NORMALIZER_VERSION
    idempotency_key: str | None = None
