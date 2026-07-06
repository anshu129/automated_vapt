"""Phase B — full adaptive recon slice integration test."""

import pytest
from sqlalchemy import select

from vapt_platform.db.tables.models import Asset, Event, SurfaceCoverageRecord, Task
from vapt_platform.domain.enums import AssetType
from vapt_platform.services.core import ProjectService, ScanService


@pytest.mark.asyncio
async def test_phase_b_full_recon_pipeline(db_session) -> None:
    """Domain → subdomain → DNS → HTTP → port → crawl → endpoints → surface."""
    project = await ProjectService(db_session).create("Phase B Project")
    scan = await ScanService(db_session).create(
        project.id,
        "Phase B Scan",
        [{"rule_type": "ROOT_DOMAIN", "pattern": "example.com", "priority": 100}],
    )
    await db_session.commit()

    await ScanService(db_session).start(scan.id)
    await db_session.commit()

    events = list(
        (await db_session.execute(select(Event).where(Event.scan_id == scan.id))).scalars().all()
    )
    event_types = {e.event_type for e in events}
    assert "DOMAIN_ACCEPTED" in event_types
    assert "HOSTNAME_DISCOVERED" in event_types
    assert "DNS_RESOLVED" in event_types
    assert "HTTP_SERVICE_CONFIRMED" in event_types
    assert "WEB_APPLICATION_CONFIRMED" in event_types
    assert "ENDPOINT_DISCOVERED" in event_types

    endpoints = list(
        (
            await db_session.execute(
                select(Asset).where(
                    Asset.scan_id == scan.id,
                    Asset.asset_type == AssetType.ENDPOINT.value,
                )
            )
        ).scalars().all()
    )
    assert len(endpoints) >= 2

    web_apps = list(
        (
            await db_session.execute(
                select(Asset).where(
                    Asset.scan_id == scan.id,
                    Asset.asset_type == AssetType.WEB_APPLICATION.value,
                )
            )
        ).scalars().all()
    )
    assert len(web_apps) >= 1

    surfaces = list(
        (
            await db_session.execute(
                select(SurfaceCoverageRecord).where(SurfaceCoverageRecord.scan_id == scan.id)
            )
        ).scalars().all()
    )
    assert len(surfaces) >= 1
    assert any(s.dimensions.get("HTTP_CHARACTERIZATION") == "COMPLETE" for s in surfaces)
    assert any(s.dimensions.get("LIVE_CRAWL") == "COMPLETE" for s in surfaces)

    tasks = list(
        (await db_session.execute(select(Task).where(Task.scan_id == scan.id))).scalars().all()
    )
    capabilities = {t.capability for t in tasks}
    assert "PASSIVE_SUBDOMAIN_DISCOVERY" in capabilities
    assert "DNS_RESOLUTION" in capabilities
    assert "HTTP_PROBING" in capabilities
    assert "LIVE_CRAWLING" in capabilities
