"""Object storage report artifact backend stub (Phase 9)."""

from __future__ import annotations

import logging
from typing import Any

from vapt_platform.domain.report_artifact import ReportArtifactRef

logger = logging.getLogger(__name__)


class ObjectStoreReportArtifactBackend:
    """Stub backend for multi-instance deployments. Requires external object-store wiring."""

    backend_name = "object_store"

    def __init__(self, bucket: str = "vapt-reports", prefix: str = "report-artifacts") -> None:
        self.bucket = bucket
        self.prefix = prefix
        self._store: dict[str, bytes] = {}

    def _key(self, scan_id: str, snapshot_id: str) -> str:
        return f"{self.prefix}/{scan_id}/{snapshot_id}.json"

    def save(
        self,
        scan_id: str,
        snapshot_id: str,
        content: bytes,
        metadata: dict[str, Any],
    ) -> ReportArtifactRef:
        key = self._key(scan_id, snapshot_id)
        self._store[key] = content
        artifact_hash = metadata.get("artifact_hash", "")
        ref = ReportArtifactRef(
            snapshot_id=snapshot_id,
            scan_id=scan_id,
            artifact_reference=f"object://{self.bucket}/{key}",
            artifact_hash=artifact_hash,
            content_type=metadata.get("content_type", "application/json"),
            artifact_size=len(content),
            storage_backend=self.backend_name,
            replayable=True,
        )
        logger.info(
            "report_artifact_created scan_id=%s report_snapshot_id=%s artifact_backend=object_store "
            "content_hash_prefix=%s",
            scan_id,
            snapshot_id,
            artifact_hash[:12] if artifact_hash else "",
        )
        return ref

    def load(self, ref: ReportArtifactRef) -> bytes:
        key = ref.artifact_reference.removeprefix(f"object://{self.bucket}/")
        if key not in self._store:
            raise FileNotFoundError(f"Object store artifact not found: {ref.artifact_reference}")
        return self._store[key]

    def exists(self, ref: ReportArtifactRef) -> bool:
        key = ref.artifact_reference.removeprefix(f"object://{self.bucket}/")
        return key in self._store

    def delete(self, ref: ReportArtifactRef) -> None:
        key = ref.artifact_reference.removeprefix(f"object://{self.bucket}/")
        self._store.pop(key, None)

    def list_versions(self, scan_id: str) -> list[ReportArtifactRef]:
        prefix = f"{self.prefix}/{scan_id}/"
        refs: list[ReportArtifactRef] = []
        for key in sorted(self._store):
            if not key.startswith(prefix):
                continue
            snapshot_id = key.rsplit("/", 1)[-1].removesuffix(".json")
            refs.append(
                ReportArtifactRef(
                    snapshot_id=snapshot_id,
                    scan_id=scan_id,
                    artifact_reference=f"object://{self.bucket}/{key}",
                    artifact_hash="",
                    artifact_size=len(self._store[key]),
                    storage_backend=self.backend_name,
                    replayable=True,
                )
            )
        return refs
