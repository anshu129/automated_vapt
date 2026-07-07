"""Report snapshot domain types (Phase 7)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


REPORT_VERSION = "phase7-v1"


@dataclass
class ReportSnapshotMetadata:
    id: str
    scan_id: str
    report_version: str
    completion_version: str
    generation_version: str
    content_hash: str
    assessment_status: str | None
    job_status: str | None
    reason_codes: list[str] = field(default_factory=list)
    bound_reached: str | None = None
    accepted_gaps_count: int = 0
    pending_work_count: int = 0
    generated_by: str = "system"
    created_at: str | None = None
    is_stale: bool | None = None
    artifact_reference: str | None = None
    artifact_hash: str | None = None
    artifact_storage_backend: str | None = None
    replayable: bool = False
    freshness_status: str | None = None
    fingerprint_hash: str | None = None
    integrity_status: str | None = None
    artifact_retention_status: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "report_version": self.report_version,
            "completion_version": self.completion_version,
            "generation_version": self.generation_version,
            "content_hash": self.content_hash,
            "fingerprint_hash": self.fingerprint_hash,
            "assessment_status": self.assessment_status,
            "job_status": self.job_status,
            "reason_codes": self.reason_codes,
            "bound_reached": self.bound_reached,
            "accepted_gaps_count": self.accepted_gaps_count,
            "pending_work_count": self.pending_work_count,
            "generated_by": self.generated_by,
            "created_at": self.created_at,
            "is_stale": self.is_stale,
            "artifact_reference": self.artifact_reference,
            "artifact_hash": self.artifact_hash,
            "artifact_storage_backend": self.artifact_storage_backend,
            "replayable": self.replayable,
            "freshness_status": self.freshness_status,
            "integrity_status": self.integrity_status,
            "artifact_retention_status": self.artifact_retention_status,
        }
