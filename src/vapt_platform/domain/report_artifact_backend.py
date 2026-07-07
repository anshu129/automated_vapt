"""Report artifact storage backend protocol (Phase 9)."""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from vapt_platform.domain.report_artifact import ReportArtifactRef


@runtime_checkable
class ReportArtifactBackend(Protocol):
    backend_name: str

    def save(
        self,
        scan_id: str,
        snapshot_id: str,
        content: bytes,
        metadata: dict[str, Any],
    ) -> ReportArtifactRef:
        ...

    def load(self, ref: ReportArtifactRef) -> bytes:
        ...

    def exists(self, ref: ReportArtifactRef) -> bool:
        ...

    def delete(self, ref: ReportArtifactRef) -> None:
        ...

    def list_versions(self, scan_id: str) -> list[ReportArtifactRef]:
        ...
