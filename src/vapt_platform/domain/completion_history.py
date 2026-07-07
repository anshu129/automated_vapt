"""Completion history domain types (Phase 6)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class CompletionHistoryEntry:
    id: str
    scan_id: str
    job_id: str | None
    previous_status: str | None
    new_status: str
    reason_codes: list[str] = field(default_factory=list)
    pending_work_summary: dict[str, Any] = field(default_factory=dict)
    accepted_gaps: dict[str, Any] = field(default_factory=dict)
    bound_reached: str | None = None
    evaluation_version: str = "1.0"
    triggered_by: str = "system"
    created_at: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "job_id": self.job_id,
            "previous_status": self.previous_status,
            "new_status": self.new_status,
            "reason_codes": self.reason_codes,
            "pending_work_summary": self.pending_work_summary,
            "accepted_gaps": self.accepted_gaps,
            "bound_reached": self.bound_reached,
            "evaluation_version": self.evaluation_version,
            "triggered_by": self.triggered_by,
            "created_at": self.created_at,
        }
