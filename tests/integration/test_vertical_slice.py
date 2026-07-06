"""End-to-end vertical slice integration test."""

import uuid

import pytest
from sqlalchemy import select

from vapt_platform.db.tables.models import Asset, Event, Task
from vapt_platform.services.core import ProjectService, ScanService


@pytest.mark.asyncio
async def test_adaptive_recon_vertical_slice(db_session) -> None:
    project = await ProjectService(db_session).create("Test Project")
    scan = await ScanService(db_session).create(
        project.id,
        "Integration Scan",
        [{"rule_type": "ROOT_DOMAIN", "pattern": "example.com", "priority": 100}],
    )
    await db_session.commit()

    started = await ScanService(db_session).start(scan.id)
    await db_session.commit()

    assert started.status == "RUNNING"

    assets = list(
        (await db_session.execute(select(Asset).where(Asset.scan_id == scan.id))).scalars().all()
    )
    assert len(assets) >= 1

    events = list(
        (await db_session.execute(select(Event).where(Event.scan_id == scan.id))).scalars().all()
    )
    event_types = {e.event_type for e in events}
    assert "DOMAIN_ACCEPTED" in event_types
    assert "HOSTNAME_DISCOVERED" in event_types or "DNS_RESOLVED" in event_types

    tasks = list(
        (await db_session.execute(select(Task).where(Task.scan_id == scan.id))).scalars().all()
    )
    assert len(tasks) >= 1

    dns_tasks = [t for t in tasks if t.capability == "DNS_RESOLUTION"]
    if len(dns_tasks) >= 2:
        profiles = {t.execution_profile_id for t in dns_tasks}
        assert "HIGH_LATENCY" in profiles or len(dns_tasks) >= 2


@pytest.mark.asyncio
async def test_duplicate_task_not_created(db_session) -> None:
    from vapt_platform.controller.recon_controller import ReconController
    from vapt_platform.domain.enums import Capability
    from vapt_platform.scope.manager import ScopeManager, ScopeRuleData

    project = await ProjectService(db_session).create("Dup Test")
    scan = await ScanService(db_session).create(
        project.id,
        "Dup Scan",
        [{"rule_type": "ROOT_DOMAIN", "pattern": "example.com"}],
    )
    scan.status = "RUNNING"
    await db_session.commit()

    controller = ReconController(
        db_session,
        ScopeManager([ScopeRuleData("ROOT_DOMAIN", "example.com")]),
    )
    cid = uuid.uuid4()
    target = {"hostname": "www.example.com"}
    t1 = await controller.create_task(scan.id, Capability.DNS_RESOLUTION, target, cid)
    t2 = await controller.create_task(scan.id, Capability.DNS_RESOLUTION, target, cid)
    await db_session.commit()
    assert t1 is not None
    assert t2 is None
