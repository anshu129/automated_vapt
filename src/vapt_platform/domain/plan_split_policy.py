"""Test plan split policy domain types (Phase 9)."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class PlanSplitAction(StrEnum):
    KEEP_BROAD = "KEEP_BROAD"
    SPLIT = "SPLIT"
    MERGE = "MERGE"
    KEEP_DISTINCT = "KEEP_DISTINCT"
    RELATED_ONLY = "RELATED_ONLY"


@dataclass
class PlanSplitDecision:
    action: str
    reason_codes: list[str] = field(default_factory=list)
    split_from_plan_id: str | None = None
    policy_version: str = "phase9-v1"

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "reason_codes": self.reason_codes,
            "split_from_plan_id": self.split_from_plan_id,
            "policy_version": self.policy_version,
        }
