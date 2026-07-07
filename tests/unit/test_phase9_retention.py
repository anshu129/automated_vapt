"""Phase 9 retention policy unit tests."""

from __future__ import annotations

import tempfile
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from vapt_platform.db.tables.models import ReportSnapshot
from vapt_platform.domain.artifact_retention import RetentionAction
from vapt_platform.services.core import ProjectService, ScanService
from vapt_platform.services.report_artifact_retention_service import (
    ReportArtifactRetentionPolicy,
    ReportArtifactRetentionService,
)
from vapt_platform.services.report_artifact_store import ReportArtifactStore


async def _scan(db_session):
    project = await ProjectService(db_session).create("P9 retention")
    return await ScanService(db_session).create(project.id, "retention scan", [])


@pytest.mark.asyncio
async def test_keep_latest_enforced(db_session) -> None:
    scan = await _scan(db_session)
    policy = ReportArtifactRetentionPolicy(max_versions_per_scan=1, ttl_days=1, keep_latest=True)
    svc = ReportArtifactRetentionService(db_session)
    svc.policy = policy
    for i in range(2):
        db_session.add(
            ReportSnapshot(
                scan_id=scan.id,
                report_version="phase7-v1",
                completion_version="v1",
                content_hash=f"hash{i}",
                created_at=datetime.now(timezone.utc) - timedelta(days=i),
            )
        )
    await db_session.commit()
    candidates = await svc.list_candidates(scan.id)
    latest = candidates[0]
    assert latest.action == RetentionAction.KEEP.value
    assert latest.reason == "keep_latest"


@pytest.mark.asyncio
async def test_dry_run_reports_candidates(db_session) -> None:
    scan = await _scan(db_session)
    policy = ReportArtifactRetentionPolicy(max_versions_per_scan=1, keep_latest=True)
    svc = ReportArtifactRetentionService(db_session)
    svc.policy = policy
    for i in range(3):
        db_session.add(
            ReportSnapshot(
                scan_id=scan.id,
                report_version="phase7-v1",
                completion_version="v1",
                content_hash=f"h{i}",
            )
        )
    await db_session.commit()
    result = await svc.cleanup(scan.id, dry_run=True)
    assert result.dry_run
    assert len(result.candidates) == 3


@pytest.mark.asyncio
async def test_cleanup_preserves_latest(db_session) -> None:
    scan = await _scan(db_session)
    with tempfile.TemporaryDirectory() as tmp:
        store = ReportArtifactStore(root=Path(tmp))
        svc = ReportArtifactRetentionService(db_session, artifact_store=store)
        svc.policy = ReportArtifactRetentionPolicy(max_versions_per_scan=1, keep_latest=True)
        rows = []
        for i in range(2):
            row = ReportSnapshot(
                scan_id=scan.id,
                report_version="phase7-v1",
                completion_version="v1",
                content_hash=f"h{i}",
                replayable=True,
            )
            db_session.add(row)
            await db_session.flush()
            ref = store.store(scan.id, row.id, {"i": i})
            row.artifact_reference = ref.artifact_reference
            row.artifact_hash = ref.artifact_hash
            rows.append(row)
        await db_session.commit()
        result = await svc.cleanup(scan.id, dry_run=False)
        await db_session.commit()
        latest = rows[-1]
        assert store.exists(latest.artifact_reference)
        assert result.deleted >= 0
