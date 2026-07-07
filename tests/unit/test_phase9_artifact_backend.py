"""Phase 9 artifact backend unit tests."""

from __future__ import annotations

import json
import tempfile
import uuid
from pathlib import Path

from vapt_platform.services.filesystem_artifact_backend import FilesystemReportArtifactBackend
from vapt_platform.services.object_store_artifact_backend import ObjectStoreReportArtifactBackend
from vapt_platform.services.report_artifact_backend_registry import get_report_artifact_backend, reset_backend_cache
from vapt_platform.services.report_artifact_store import ReportArtifactStore
from vapt_platform.services.report_hashing import compute_report_content_hash


def test_filesystem_backend_roundtrip() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        backend = FilesystemReportArtifactBackend(root=Path(tmp))
        scan_id = str(uuid.uuid4())
        snap_id = str(uuid.uuid4())
        report = {"scan_id": scan_id, "summary": {"assets": 1}}
        content = json.dumps(report).encode()
        ref = backend.save(scan_id, snap_id, content, {"artifact_hash": compute_report_content_hash(report)})
        loaded = json.loads(backend.load(ref).decode())
        assert loaded["summary"]["assets"] == 1
        assert ref.storage_backend == "filesystem"
        assert backend.exists(ref)


def test_object_store_backend_roundtrip() -> None:
    backend = ObjectStoreReportArtifactBackend()
    scan_id = str(uuid.uuid4())
    snap_id = str(uuid.uuid4())
    content = b'{"ok": true}'
    ref = backend.save(scan_id, snap_id, content, {"artifact_hash": "abc"})
    assert backend.load(ref) == content
    assert ref.artifact_reference.startswith("object://")


def test_backend_registry_filesystem() -> None:
    reset_backend_cache()
    with tempfile.TemporaryDirectory() as tmp:
        backend = get_report_artifact_backend(backend_name="filesystem", root=Path(tmp))
        assert backend.backend_name == "filesystem"


def test_report_artifact_store_uses_backend() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        store = ReportArtifactStore(root=Path(tmp))
        scan_id = uuid.uuid4()
        snap_id = uuid.uuid4()
        report = {"scan_id": str(scan_id)}
        ref = store.store(scan_id, snap_id, report)
        loaded = store.load(ref.artifact_reference)
        assert loaded["scan_id"] == str(scan_id)
