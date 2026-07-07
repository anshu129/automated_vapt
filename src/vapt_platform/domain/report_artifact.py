"""Report artifact domain types (Phase 8)."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class ReportStalenessStatus(StrEnum):
    FRESH = "FRESH"
    STALE = "STALE"
    UNKNOWN = "UNKNOWN"
    REGENERATE_REQUIRED = "REGENERATE_REQUIRED"
    SNAPSHOT_MISMATCH = "SNAPSHOT_MISMATCH"


@dataclass
class ReportArtifactRef:
    snapshot_id: str
    scan_id: str
    artifact_reference: str
    artifact_hash: str
    content_type: str = "application/json"
    artifact_size: int = 0
    storage_backend: str = "filesystem"
    replayable: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "snapshot_id": self.snapshot_id,
            "scan_id": self.scan_id,
            "artifact_reference": self.artifact_reference,
            "artifact_hash": self.artifact_hash,
            "content_type": self.content_type,
            "artifact_size": self.artifact_size,
            "storage_backend": self.storage_backend,
            "replayable": self.replayable,
        }


@dataclass
class ReportFreshnessResult:
    status: str
    snapshot_id: str | None = None
    snapshot_hash: str | None = None
    live_hash: str | None = None
    fingerprint_hash: str | None = None
    live_fingerprint_hash: str | None = None
    reasons: list[str] = field(default_factory=list)
    assessment_status: str | None = None
    snapshot_assessment_status: str | None = None
    completion_version: str | None = None
    snapshot_completion_version: str | None = None
    check_method: str = "fingerprint"
    fallback_used: bool = False
    polled_at: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "snapshot_id": self.snapshot_id,
            "snapshot_hash": self.snapshot_hash,
            "live_hash": self.live_hash,
            "fingerprint_hash": self.fingerprint_hash,
            "live_fingerprint_hash": self.live_fingerprint_hash,
            "reasons": self.reasons,
            "assessment_status": self.assessment_status,
            "snapshot_assessment_status": self.snapshot_assessment_status,
            "completion_version": self.completion_version,
            "snapshot_completion_version": self.snapshot_completion_version,
            "check_method": self.check_method,
            "fallback_used": self.fallback_used,
            "polled_at": self.polled_at,
        }
