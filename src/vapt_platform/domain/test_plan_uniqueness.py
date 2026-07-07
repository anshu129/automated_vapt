"""TestPlan uniqueness domain types (Phase 8)."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class PlanUniquenessRelation(StrEnum):
    EQUIVALENT = "EQUIVALENT"
    MERGEABLE = "MERGEABLE"
    DISTINCT = "DISTINCT"
    RELATED = "RELATED"


@dataclass
class PlanUniquenessDecision:
    relation: str
    planning_fingerprint: str
    uniqueness_key: str
    reason: str = ""
    source_requirement_uniqueness_keys: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "relation": self.relation,
            "planning_fingerprint": self.planning_fingerprint,
            "uniqueness_key": self.uniqueness_key,
            "reason": self.reason,
            "source_requirement_uniqueness_keys": self.source_requirement_uniqueness_keys,
        }
