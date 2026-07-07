"""Artifact retention domain types (Phase 9)."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class RetentionAction(StrEnum):
    KEEP = "KEEP"
    DELETE_CANDIDATE = "DELETE_CANDIDATE"
    EXPIRED = "EXPIRED"


@dataclass
class RetentionCandidate:
    snapshot_id: str
    scan_id: str
    action: str
    reason: str
    artifact_reference: str | None = None
    created_at: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "snapshot_id": self.snapshot_id,
            "scan_id": self.scan_id,
            "action": self.action,
            "reason": self.reason,
            "artifact_reference": self.artifact_reference,
            "created_at": self.created_at,
        }


@dataclass
class RetentionResult:
    dry_run: bool
    kept: int = 0
    deleted: int = 0
    candidates: list[RetentionCandidate] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "dry_run": self.dry_run,
            "kept": self.kept,
            "deleted": self.deleted,
            "candidates": [c.to_dict() for c in self.candidates],
            "errors": self.errors,
        }
