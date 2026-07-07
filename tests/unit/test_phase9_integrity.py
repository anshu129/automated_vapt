"""Phase 9 integrity audit unit tests."""

from __future__ import annotations

import tempfile
import uuid
from pathlib import Path

import pytest

from vapt_platform.db.tables.models import ReportSnapshot
from vapt_platform.domain.artifact_integrity import IntegrityStatus
from vapt_platform.services.core import ProjectService, ScanService
from vapt_platform.services.report_artifact_integrity_service import ReportArtifactIntegrityService
from vapt_platform.services.report_artifact_store import ReportArtifactStore
from vapt_platform.services.report_hashing import compute_report_content_hash


async def _scan(db_session):
    project = await ProjectService(db_session).create("P9 integrity")
    return await ScanService(db_session).create(project.id, "integrity scan", [])


@pytest.mark.asyncio
async def test_integrity_ok(db_session) -> None:
    scan = await _scan(db_session)
    with tempfile.TemporaryDirectory() as tmp:
        store = ReportArtifactStore(root=Path(tmp))
        svc = ReportArtifactIntegrityService(db_session, artifact_store=store)
        report = {"scan_id": str(scan.id), "summary": {}}
        row = ReportSnapshot(
            scan_id=scan.id,
            report_version="phase7-v1",
            completion_version="v1",
            content_hash=compute_report_content_hash(report),
            replayable=True,
        )
        db_session.add(row)
        await db_session.flush()
        ref = store.store(scan.id, row.id, report)
        row.artifact_reference = ref.artifact_reference
        row.artifact_hash = ref.artifact_hash
        row.artifact_storage_backend = ref.storage_backend
        await db_session.commit()
        result = await svc.verify_snapshot(row)
        assert result.status == IntegrityStatus.OK.value


@pytest.mark.asyncio
async def test_missing_artifact_detected(db_session) -> None:
    scan = await _scan(db_session)
    row = ReportSnapshot(
        scan_id=scan.id,
        report_version="phase7-v1",
        completion_version="v1",
        content_hash="abc",
        artifact_reference="/nonexistent/path.json",
        replayable=True,
    )
    db_session.add(row)
    await db_session.commit()
    result = await ReportArtifactIntegrityService(db_session).verify_snapshot(row)
    assert result.status == IntegrityStatus.MISSING_ARTIFACT.value


@pytest.mark.asyncio
async def test_hash_mismatch_detected(db_session) -> None:
    scan = await _scan(db_session)
    with tempfile.TemporaryDirectory() as tmp:
        store = ReportArtifactStore(root=Path(tmp))
        svc = ReportArtifactIntegrityService(db_session, artifact_store=store)
        report = {"scan_id": str(scan.id)}
        row = ReportSnapshot(
            scan_id=scan.id,
            report_version="phase7-v1",
            completion_version="v1",
            content_hash=compute_report_content_hash(report),
            replayable=True,
            artifact_hash="wrong-hash",
        )
        db_session.add(row)
        await db_session.flush()
        ref = store.store(scan.id, row.id, report)
        row.artifact_reference = ref.artifact_reference
        row.artifact_storage_backend = ref.storage_backend
        await db_session.commit()
        result = await svc.verify_snapshot(row)
        assert result.status == IntegrityStatus.HASH_MISMATCH.value
