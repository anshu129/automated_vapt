"""Phase 8 report artifact unit tests."""

from __future__ import annotations

import json
import tempfile
import uuid
from pathlib import Path

import pytest

from vapt_platform.services.report_artifact_store import ReportArtifactStore
from vapt_platform.services.report_hashing import compute_report_content_hash


def test_artifact_store_roundtrip() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        store = ReportArtifactStore(root=Path(tmp))
        scan_id = uuid.uuid4()
        snap_id = uuid.uuid4()
        report = {"scan_id": str(scan_id), "summary": {"assets": 2}}
        ref = store.store(scan_id, snap_id, report)
        loaded = store.load(ref.artifact_reference)
        assert loaded["summary"]["assets"] == 2
        assert ref.artifact_hash == compute_report_content_hash(report)
        assert store.exists(ref.artifact_reference)


@pytest.mark.asyncio
async def test_snapshot_persists_artifact_reference(db_session) -> None:
    from vapt_platform.services.core import ProjectService, ScanService
    from vapt_platform.services.report_snapshot_service import ReportSnapshotService
    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as tmp:
        project = await ProjectService(db_session).create("P8 artifact")
        scan = await ScanService(db_session).create(project.id, "artifact scan", [])
        svc = ReportSnapshotService(db_session)
        svc.artifact_store = ReportArtifactStore(root=Path(tmp))
        report = {
            "scan_id": str(scan.id),
            "summary": {"assets": 0},
            "assessment_completion": {"assessment_status": "INCOMPLETE", "evaluation_version": "phase5-v1"},
        }
        row = await svc.create_snapshot(scan.id, report)
        await db_session.commit()
        assert row is not None
        assert row.artifact_reference
        assert row.replayable
        replay = svc.artifact_store.load(row.artifact_reference)
        assert replay["scan_id"] == str(scan.id)
