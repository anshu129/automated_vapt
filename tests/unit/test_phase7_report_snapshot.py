"""Phase 7 report snapshot unit tests."""

from __future__ import annotations

import uuid

import pytest

from vapt_platform.services.report_hashing import (
    canonical_report_for_hash,
    compute_report_content_hash,
)


def test_content_hash_deterministic() -> None:
    report = {
        "scan_id": "abc",
        "summary": {"assets": 3, "completion_status": "INCOMPLETE"},
        "assessment_completion": {"assessment_status": "INCOMPLETE", "reason_codes": ["X"]},
    }
    assert compute_report_content_hash(report) == compute_report_content_hash(report)


def test_content_hash_ignores_volatile_fields() -> None:
    a = {"scan_id": "abc", "evaluation_timestamp": "2026-01-01T00:00:00Z"}
    b = {"scan_id": "abc", "evaluation_timestamp": "2026-01-02T00:00:00Z"}
    assert compute_report_content_hash(a) == compute_report_content_hash(b)


def test_content_hash_changes_when_semantics_change() -> None:
    a = {"scan_id": "abc", "summary": {"assets": 1}}
    b = {"scan_id": "abc", "summary": {"assets": 2}}
    assert compute_report_content_hash(a) != compute_report_content_hash(b)


def test_canonical_strip() -> None:
    stripped = canonical_report_for_hash({"a": 1, "created_at": "x"})
    assert "created_at" not in stripped


@pytest.mark.asyncio
async def test_snapshot_created_and_retained(db_session) -> None:
    from vapt_platform.db.tables.models import ReportSnapshot
    from vapt_platform.services.core import ProjectService, ScanService
    from vapt_platform.services.report_snapshot_service import ReportSnapshotService
    from sqlalchemy import func, select

    project = await ProjectService(db_session).create("Phase 7 Report")
    scan = await ScanService(db_session).create(project.id, "Report scan", [])
    svc = ReportSnapshotService(db_session)
    report = {
        "scan_id": str(scan.id),
        "summary": {"assets": 0},
        "assessment_completion": {"assessment_status": "INCOMPLETE", "reason_codes": []},
    }
    first = await svc.create_snapshot(scan.id, report)
    report["summary"]["assets"] = 5
    second = await svc.create_snapshot(scan.id, report)
    await db_session.commit()
    assert first is not None and second is not None
    assert first.id != second.id
    assert first.content_hash != second.content_hash
    count = (
        await db_session.execute(
            select(func.count()).select_from(ReportSnapshot).where(ReportSnapshot.scan_id == scan.id)
        )
    ).scalar_one()
    assert count == 2
