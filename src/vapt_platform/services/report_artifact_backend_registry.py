"""Report artifact backend registry (Phase 9)."""

from __future__ import annotations

from pathlib import Path

from vapt_platform.config.settings import get_settings
from vapt_platform.domain.report_artifact_backend import ReportArtifactBackend
from vapt_platform.services.filesystem_artifact_backend import FilesystemReportArtifactBackend
from vapt_platform.services.object_store_artifact_backend import ObjectStoreReportArtifactBackend

_backends: dict[str, ReportArtifactBackend] = {}


def get_report_artifact_backend(
    *,
    backend_name: str | None = None,
    root: Path | None = None,
) -> ReportArtifactBackend:
    settings = get_settings()
    name = backend_name or settings.report_artifact_backend
    if name == "filesystem":
        if root is not None:
            return FilesystemReportArtifactBackend(root=root)
        if name not in _backends:
            _backends[name] = FilesystemReportArtifactBackend()
        return _backends[name]
    if name == "object_store":
        if name not in _backends:
            _backends[name] = ObjectStoreReportArtifactBackend(
                bucket=settings.report_artifact_object_bucket,
                prefix=settings.report_artifact_object_prefix,
            )
        return _backends[name]
    return FilesystemReportArtifactBackend(root=root)


def reset_backend_cache() -> None:
    _backends.clear()
