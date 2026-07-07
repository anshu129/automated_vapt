"""Accepted gap policy (Phase 5)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

POLICY_VERSION = "1.0"


@dataclass
class GapAcceptanceDecision:
    accepted: bool
    reason_code: str
    explanation: str


class AcceptedGapPolicy:
    def evaluate_gap(
        self,
        *,
        gap_type: str,
        accepted_gaps: dict[str, Any],
        asset_id: str | None = None,
        dimension: str | None = None,
    ) -> GapAcceptanceDecision:
        if asset_id and dimension:
            asset_gaps = accepted_gaps.get(str(asset_id), [])
            if isinstance(asset_gaps, list) and dimension in asset_gaps:
                return GapAcceptanceDecision(
                    accepted=True,
                    reason_code="COVERAGE_ACCEPTED_BY_POLICY",
                    explanation=f"Dimension {dimension} explicitly accepted for asset {asset_id}",
                )
        if gap_type in {"OUT_OF_SCOPE", "EXCLUDED_ROLE", "EXCLUDED_AUTH_AREA"}:
            return GapAcceptanceDecision(
                accepted=True,
                reason_code="COVERAGE_ACCEPTED_BY_POLICY",
                explanation=f"Gap type {gap_type} is policy-accepted",
            )
        if gap_type in {"MISSING_CREDENTIALS", "MISSING_AUTHORIZATION"}:
            return GapAcceptanceDecision(
                accepted=False,
                reason_code="REQUIRED_CREDENTIALS_MISSING",
                explanation="Required credential or authorization gap cannot be accepted",
            )
        return GapAcceptanceDecision(
            accepted=False,
            reason_code="PENDING_AUTHORIZED_WORK",
            explanation="Gap requires further authorized work",
        )

    def allows_completion_with_gaps(
        self,
        *,
        accepted_gap_count: int,
        pending_authorized_work: int,
        bound_reached: str | None,
    ) -> bool:
        if pending_authorized_work > 0:
            return False
        if accepted_gap_count > 0 and not bound_reached:
            return True
        if accepted_gap_count > 0 and bound_reached:
            return True
        return False
