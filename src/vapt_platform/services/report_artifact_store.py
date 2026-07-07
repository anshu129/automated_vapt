"""Report artifact storage facade (Phase 8/9)."""

from __future__ import annotations

import json
import logging
import uuid
from pathlib import Path
from typing import Any

from vapt_platform.domain.report_artifact import ReportArtifactRef
from vapt_platform.domain.report_artifact_backend import ReportArtifactBackend
from vapt_platform.services.report_artifact_backend_registry import get_report_artifact_backend
from vapt_platform.services.report_hashing import compute_report_content_hash

logger = logging.getLogger(__name__)


class ReportArtifactStore:
    def __init__(
        self,
        root: Path | None = None,
        backend: ReportArtifactBackend | None = None,
    ) -> None:
        self._backend = backend or get_report_artifact_backend(root=root)

    @property
    def backend(self) -> ReportArtifactBackend:
        return self._backend

    def store(
        self,
        scan_id: uuid.UUID,
        snapshot_id: uuid.UUID,
        report: dict[str, Any],
    ) -> ReportArtifactRef:
        payload = json.dumps(report, sort_keys=True, separators=(",", ":"), default=str)
        content = payload.encode("utf-8")
        artifact_hash = compute_report_content_hash(report)
        ref = self._backend.save(
            str(scan_id),
            str(snapshot_id),
            content,
            {
                "artifact_hash": artifact_hash,
                "content_type": "application/json",
            },
        )
        return ref

    def load(self, artifact_reference: str, *, backend_name: str | None = None) -> dict[str, Any]:
        ref = ReportArtifactRef(
            snapshot_id="",
            scan_id="",
            artifact_reference=artifact_reference,
            artifact_hash="",
            storage_backend=backend_name or self._backend.backend_name,
        )
        data = self._backend.load(ref)
        report = json.loads(data.decode("utf-8"))
        logger.info(
            "report_artifact_replay artifact_reference=%s content_hash_prefix=%s",
            artifact_reference,
            compute_report_content_hash(report)[:12],
        )
        return report

    def exists(self, artifact_reference: str) -> bool:
        ref = ReportArtifactRef(
            snapshot_id="",
            scan_id="",
            artifact_reference=artifact_reference,
            artifact_hash="",
            storage_backend=self._backend.backend_name,
        )
        return self._backend.exists(ref)

    def delete(self, artifact_reference: str, *, scan_id: str = "", snapshot_id: str = "") -> None:
        ref = ReportArtifactRef(
            snapshot_id=snapshot_id,
            scan_id=scan_id,
            artifact_reference=artifact_reference,
            artifact_hash="",
            storage_backend=self._backend.backend_name,
        )
        self._backend.delete(ref)

    def list_versions(self, scan_id: uuid.UUID) -> list[ReportArtifactRef]:
        return self._backend.list_versions(str(scan_id))
