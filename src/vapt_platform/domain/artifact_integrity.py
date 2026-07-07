"""Report artifact integrity domain types (Phase 9)."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class IntegrityStatus(StrEnum):
    OK = "OK"
    MISSING_ARTIFACT = "MISSING_ARTIFACT"
    HASH_MISMATCH = "HASH_MISMATCH"
    STALE_METADATA = "STALE_METADATA"
    REPLAY_UNAVAILABLE = "REPLAY_UNAVAILABLE"
    PARTIAL_FAILURE = "PARTIAL_FAILURE"


@dataclass
class SnapshotIntegrityResult:
    snapshot_id: str
    status: str
    reasons: list[str] = field(default_factory=list)
    artifact_hash: str | None = None
    computed_hash: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "snapshot_id": self.snapshot_id,
            "status": self.status,
            "reasons": self.reasons,
            "artifact_hash": self.artifact_hash,
            "computed_hash": self.computed_hash,
        }


@dataclass
class ScanIntegritySummary:
    scan_id: str
    overall_status: str
    total_snapshots: int = 0
    ok_count: int = 0
    issue_count: int = 0
    results: list[SnapshotIntegrityResult] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "overall_status": self.overall_status,
            "total_snapshots": self.total_snapshots,
            "ok_count": self.ok_count,
            "issue_count": self.issue_count,
            "results": [r.to_dict() for r in self.results],
        }
