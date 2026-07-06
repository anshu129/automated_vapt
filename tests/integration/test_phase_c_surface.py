"""Phase C — surface completeness integration tests."""

import pytest
from sqlalchemy import select

from vapt_platform.db.tables.models import AssessmentCompletionRecord, Event, SurfaceCoverageRecord
from vapt_platform.domain.enums import AssetType, CompletionStatus
from vapt_platform.engines.assessment import AssessmentCompletionEvaluator
from vapt_platform.engines.surface_completeness import SurfaceCompletenessEngine
from vapt_platform.services.core import ProjectService, ScanService


@pytest.mark.asyncio
async def test_surface_gaps_emitted_with_structure(db_session) -> None:
    project = await ProjectService(db_session).create("Phase C Project")
    scan = await ScanService(db_session).create(
        project.id,
        "Phase C Scan",
        [{"rule_type": "ROOT_DOMAIN", "pattern": "example.com", "priority": 100}],
    )
    await db_session.commit()
    await ScanService(db_session).start(scan.id)
    await db_session.commit()

    gap_events = list(
        (
            await db_session.execute(
                select(Event).where(
                    Event.scan_id == scan.id,
                    Event.event_type == "SURFACE_GAP_IDENTIFIED",
                )
            )
        ).scalars().all()
    )
    assert len(gap_events) >= 1
    payload = gap_events[0].payload
    assert "gaps" in payload
    assert "blocking_count" in payload
    assert isinstance(payload["gaps"], list)

    computed = list(
        (
            await db_session.execute(
                select(Event).where(
                    Event.scan_id == scan.id,
                    Event.event_type == "SURFACE_COVERAGE_COMPUTED",
                )
            )
        ).scalars().all()
    )
    assert len(computed) >= 1


@pytest.mark.asyncio
async def test_missing_requirements_classifies_blocking(db_session) -> None:
    project = await ProjectService(db_session).create("Gap Classify")
    scan = await ScanService(db_session).create(
        project.id,
        "Gap Scan",
        [{"rule_type": "ROOT_DOMAIN", "pattern": "example.com"}],
    )
    await db_session.commit()
    await ScanService(db_session).start(scan.id)
    await db_session.commit()

    engine = SurfaceCompletenessEngine(db_session)
    records = await engine.compute_scan_summary(scan.id, asset_type=AssetType.WEB_APPLICATION)
    assert records

    reqs = await engine.missing_requirements(records[0].asset_id, scan.id)
    dimensions = {r.dimension for r in reqs}
    assert "AUTHENTICATED_AREA_COVERAGE" not in dimensions or all(
        not r.blocking for r in reqs if r.dimension == "AUTHENTICATED_AREA_COVERAGE"
    )
    live_crawl = [r for r in reqs if r.dimension == "LIVE_CRAWL"]
    if live_crawl and live_crawl[0].status != "COMPLETE":
        assert live_crawl[0].blocking is True


@pytest.mark.asyncio
async def test_accepted_gaps_mark_requirements_non_blocking(db_session) -> None:
    project = await ProjectService(db_session).create("Accept Gaps")
    scan = await ScanService(db_session).create(
        project.id,
        "Accept Scan",
        [{"rule_type": "ROOT_DOMAIN", "pattern": "example.com"}],
    )
    await db_session.commit()
    await ScanService(db_session).start(scan.id)
    await db_session.commit()

    engine = SurfaceCompletenessEngine(db_session)
    records = await engine.compute_scan_summary(scan.id, asset_type=AssetType.WEB_APPLICATION)
    assert records
    asset_id = records[0].asset_id

    reqs_before = await engine.missing_requirements(asset_id, scan.id)
    open_req = next((r for r in reqs_before if not r.accepted), None)
    assert open_req is not None

    accepted = {str(asset_id): [open_req.dimension]}
    reqs_after = await engine.missing_requirements(
        asset_id, scan.id, accepted_gaps=accepted
    )
    accepted_req = next(r for r in reqs_after if r.dimension == open_req.dimension)
    assert accepted_req.accepted is True
    assert accepted_req.blocking is False

    record = (
        await db_session.execute(
            select(AssessmentCompletionRecord).where(
                AssessmentCompletionRecord.scan_id == scan.id
            )
        )
    ).scalar_one_or_none()
    if not record:
        record = AssessmentCompletionRecord(
            scan_id=scan.id, status=CompletionStatus.INCOMPLETE.value
        )
        db_session.add(record)
    record.accepted_gaps = accepted
    await db_session.flush()

    completion = await AssessmentCompletionEvaluator(db_session).evaluate(scan.id)
    assert completion.status in (
        CompletionStatus.COMPLETE.value,
        CompletionStatus.COMPLETE_WITH_ACCEPTED_GAPS.value,
    )
    assert completion.metrics.get("accepted_gap_count", 0) >= 1


@pytest.mark.asyncio
async def test_scan_surface_summary(db_session) -> None:
    project = await ProjectService(db_session).create("Summary")
    scan = await ScanService(db_session).create(
        project.id,
        "Summary Scan",
        [{"rule_type": "ROOT_DOMAIN", "pattern": "example.com"}],
    )
    await db_session.commit()
    await ScanService(db_session).start(scan.id)
    await db_session.commit()

    engine = SurfaceCompletenessEngine(db_session)
    records = await engine.compute_scan_summary(scan.id)
    assert len(records) >= 1

    web_records = await engine.compute_scan_summary(scan.id, asset_type=AssetType.WEB_APPLICATION)
    assert all(r.asset_type == AssetType.WEB_APPLICATION.value for r in web_records)

    surfaces = list(
        (
            await db_session.execute(
                select(SurfaceCoverageRecord).where(SurfaceCoverageRecord.scan_id == scan.id)
            )
        ).scalars().all()
    )
    assert len(surfaces) == len(records)
