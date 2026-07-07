"""Coverage invalidation policy (Phase 4)."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class InvalidationAction(StrEnum):
    KEEP_VALID = "KEEP_VALID"
    PARTIALLY_INVALIDATE = "PARTIALLY_INVALIDATE"
    INVALIDATE = "INVALIDATE"
    CREATE_ADDITIONAL_SCOPE_REQUIREMENT = "CREATE_ADDITIONAL_SCOPE_REQUIREMENT"


@dataclass
class InvalidationDecision:
    action: str
    reason_codes: list[str]
    affected_dimensions: list[str]


class CoverageInvalidationPolicy:
    def evaluate(self, *, change_category: str, context: dict[str, Any]) -> InvalidationDecision:
        category = change_category.upper()
        if category in {"PARAMETER_DISCOVERED", "ENDPOINT_ADDED", "ENDPOINT_DISCOVERED"}:
            return InvalidationDecision(
                action=InvalidationAction.CREATE_ADDITIONAL_SCOPE_REQUIREMENT.value,
                reason_codes=["NEW_SCOPE_DISCOVERED"],
                affected_dimensions=[context.get("dimension", "endpoint")],
            )
        if category in {"TECHNOLOGY_CHANGED", "SERVICE_VERSION_CHANGED"}:
            return InvalidationDecision(
                action=InvalidationAction.PARTIALLY_INVALIDATE.value,
                reason_codes=["TECHNOLOGY_CONTEXT_CHANGED"],
                affected_dimensions=["technology_specific"],
            )
        if category in {"AUTH_RELATIONSHIP_CHANGED", "AUTH_FLOW_CHANGED"}:
            return InvalidationDecision(
                action=InvalidationAction.PARTIALLY_INVALIDATE.value,
                reason_codes=["AUTH_CONTEXT_CHANGED"],
                affected_dimensions=["authentication", "session"],
            )
        if category == "ROLE_ADDED":
            return InvalidationDecision(
                action=InvalidationAction.CREATE_ADDITIONAL_SCOPE_REQUIREMENT.value,
                reason_codes=["NEW_ROLE_SCOPE"],
                affected_dimensions=["authorization_role"],
            )
        return InvalidationDecision(
            action=InvalidationAction.KEEP_VALID.value,
            reason_codes=["NO_INVALIDATION"],
            affected_dimensions=[],
        )
