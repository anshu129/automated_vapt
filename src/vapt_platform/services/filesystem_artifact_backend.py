"""Filesystem report artifact backend (Phase 9)."""

from __future__ import annotations

import json
import logging
import uuid
from pathlib import Path
from typing import Any

from vapt_platform.config.settings import get_settings
from vapt_platform.domain.report_artifact import ReportArtifactRef

logger = logging.getLogger(__name__)

DEFAULT_ARTIFACT_ROOT = Path("data/report_artifacts")


class FilesystemReportArtifactBackend:
    backend_name = "filesystem"

    def __init__(self, root: Path | None = None) -> None:
        settings = get_settings()
        configured = getattr(settings, "report_artifact_root", None)
        self.root = root or (Path(configured) if configured else DEFAULT_ARTIFACT_ROOT)

    def _artifact_path(self, scan_id: str, snapshot_id: str) -> Path:
        return self.root / scan_id / f"{snapshot_id}.json"

    def save(
        self,
        scan_id: str,
        snapshot_id: str,
        content: bytes,
        metadata: dict[str, Any],
    ) -> ReportArtifactRef:
        path = self._artifact_path(scan_id, snapshot_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        artifact_hash = metadata.get("artifact_hash", "")
        ref = ReportArtifactRef(
            snapshot_id=snapshot_id,
            scan_id=scan_id,
            artifact_reference=str(path),
            artifact_hash=artifact_hash,
            content_type=metadata.get("content_type", "application/json"),
            artifact_size=len(content),
            storage_backend=self.backend_name,
            replayable=True,
        )
        logger.info(
            "report_artifact_created scan_id=%s report_snapshot_id=%s artifact_backend=filesystem "
            "content_hash_prefix=%s artifact_size=%d",
            scan_id,
            snapshot_id,
            artifact_hash[:12] if artifact_hash else "",
            ref.artifact_size,
        )
        return ref

    def load(self, ref: ReportArtifactRef) -> bytes:
        path = Path(ref.artifact_reference)
        if not path.is_file():
            raise FileNotFoundError(f"Report artifact not found: {ref.artifact_reference}")
        data = path.read_bytes()
        logger.info(
            "report_artifact_replay artifact_reference=%s artifact_backend=filesystem",
            ref.artifact_reference,
        )
        return data

    def exists(self, ref: ReportArtifactRef) -> bool:
        return Path(ref.artifact_reference).is_file()

    def delete(self, ref: ReportArtifactRef) -> None:
        path = Path(ref.artifact_reference)
        if path.is_file():
            path.unlink()
            logger.info("report_artifact_deleted artifact_reference=%s", ref.artifact_reference)

    def list_versions(self, scan_id: str) -> list[ReportArtifactRef]:
        scan_dir = self.root / scan_id
        if not scan_dir.is_dir():
            return []
        refs: list[ReportArtifactRef] = []
        for path in sorted(scan_dir.glob("*.json")):
            snapshot_id = path.stem
            try:
                uuid.UUID(snapshot_id)
            except ValueError:
                continue
            refs.append(
                ReportArtifactRef(
                    snapshot_id=snapshot_id,
                    scan_id=scan_id,
                    artifact_reference=str(path),
                    artifact_hash="",
                    artifact_size=path.stat().st_size,
                    storage_backend=self.backend_name,
                    replayable=True,
                )
            )
        return refs
