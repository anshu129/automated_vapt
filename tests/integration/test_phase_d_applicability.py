"""Phase D — vulnerability applicability integration tests."""

import pytest
from sqlalchemy import select

from vapt_platform.db.tables.models import (
    Asset,
    AssetTestMatrix,
    AssetVulnerabilityApplicability,
    Event,
    VulnerabilityClass,
)
from vapt_platform.domain.enums import ApplicabilityState, AssetType
from vapt_platform.services.core import ProjectService, ScanService


@pytest.mark.asyncio
async def test_applicability_computed_after_recon(db_session) -> None:
    project = await ProjectService(db_session).create("Phase D Project")
    scan = await ScanService(db_session).create(
        project.id,
        "Phase D Scan",
        [{"rule_type": "ROOT_DOMAIN", "pattern": "example.com", "priority": 100}],
    )
    await db_session.commit()
    await ScanService(db_session).start(scan.id)
    await db_session.commit()

    events = list(
        (
            await db_session.execute(
                select(Event).where(
                    Event.scan_id == scan.id,
                    Event.event_type == "APPLICABILITY_COMPUTED",
                )
            )
        ).scalars().all()
    )
    assert len(events) >= 1
    assert events[0].payload.get("applicable_count", 0) >= 6


@pytest.mark.asyncio
async def test_web_app_baseline_classes_applicable(db_session) -> None:
    project = await ProjectService(db_session).create("Applicability Baseline")
    scan = await ScanService(db_session).create(
        project.id,
        "Baseline Scan",
        [{"rule_type": "ROOT_DOMAIN", "pattern": "example.com"}],
    )
    await db_session.commit()
    await ScanService(db_session).start(scan.id)
    await db_session.commit()

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
    assert web_apps

    class_by_code = {
        vc.class_code: vc.id
        for vc in (
            await db_session.execute(select(VulnerabilityClass))
        ).scalars().all()
    }

    rows = list(
        (
            await db_session.execute(
                select(AssetVulnerabilityApplicability).where(
                    AssetVulnerabilityApplicability.asset_id == web_apps[0].id
                )
            )
        ).scalars().all()
    )
    by_code = {
        next(
            code
            for code, cid in class_by_code.items()
            if cid == row.vulnerability_class_id
        ): row
        for row in rows
    }

    for code in (
        "AUTHENTICATION",
        "SESSION_MANAGEMENT",
        "AUTHORIZATION",
        "INPUT_VALIDATION",
        "SECURITY_HEADERS",
        "TRANSPORT_SECURITY",
    ):
        assert by_code[code].applicability_state == ApplicabilityState.APPLICABLE.value
        assert "web-app-baseline" in (by_code[code].rule_ids or [])

    assert (
        by_code["KNOWN_COMPONENT_VULNERABILITY"].applicability_state
        == ApplicabilityState.POSSIBLY_APPLICABLE.value
    )
    assert by_code["OBJECT_LEVEL_AUTHORIZATION"].applicability_state == (
        ApplicabilityState.APPLICABLE.value
    )


@pytest.mark.asyncio
async def test_test_matrix_created_for_applicable_classes(db_session) -> None:
    project = await ProjectService(db_session).create("Matrix")
    scan = await ScanService(db_session).create(
        project.id,
        "Matrix Scan",
        [{"rule_type": "ROOT_DOMAIN", "pattern": "example.com"}],
    )
    await db_session.commit()
    await ScanService(db_session).start(scan.id)
    await db_session.commit()

    matrices = list(
        (
            await db_session.execute(
                select(AssetTestMatrix).where(AssetTestMatrix.scan_id == scan.id)
            )
        ).scalars().all()
    )
    assert len(matrices) >= 1
