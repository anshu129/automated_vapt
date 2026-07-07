"""Vulnerability breadth, advisory AI, and read-only MCP views."""

import json

import pytest
from sqlalchemy import func, select

from vapt_platform.api.routes.core import (
    scan_vulnerability_coverage,
    vulnerability_classes,
)
from vapt_platform.config.settings import Settings
from vapt_platform.db.tables.models import (
    AIEnrichment,
    ConfirmedFinding,
    Hypothesis,
    Task,
    Verdict,
)
from vapt_platform.engines.assessment import TestPlanner as Planner
from vapt_platform.enrichment.mistral import (
    AdvisoryPriority,
    CrossAssetHypothesisSuggestion,
    MistralEnrichmentService,
    VulnerabilityCoverageAdvisory,
)
from vapt_platform.mcp.read_tools import AssessmentMCPReadService
from vapt_platform.services.core import ProjectService, ScanService


async def _seed_scan(db_session):
    project = await ProjectService(db_session).create("Coverage Intelligence")
    scan = await ScanService(db_session).create(
        project.id,
        "Coverage Intelligence Scan",
        [{"rule_type": "ROOT_DOMAIN", "pattern": "example.com", "priority": 100}],
    )
    await db_session.commit()
    await ScanService(db_session).start(scan.id)
    await Planner(db_session).plan_scan(scan.id)
    await db_session.flush()
    return scan


@pytest.mark.asyncio
async def test_catalog_and_coverage_expose_all_open_obligations(db_session) -> None:
    scan = await _seed_scan(db_session)

    catalog = await vulnerability_classes(db_session)
    coverage = await scan_vulnerability_coverage(scan.id, db_session)

    class_codes = {item["class_code"] for item in catalog["items"]}
    assert catalog["total"] >= 35
    assert {
        "EXPOSED_SERVICE",
        "FUNCTION_LEVEL_AUTHORIZATION",
        "SERVER_SIDE_REQUEST_BEHAVIOR",
        "CROSS_ORIGIN_POLICY",
        "RATE_CONTROL",
        "SECRET_EXPOSURE",
        "HISTORICAL_OR_STALE_SURFACE",
    } <= class_codes
    assert coverage["catalog_classes"] == catalog["total"]
    assert coverage["assets_with_test_matrix"] >= 3
    assert coverage["matrix_cells"] >= coverage["catalog_classes"]
    assert coverage["open_cells"] > 0
    assert any(item["open_assets"] for item in coverage["classes"])


@pytest.mark.asyncio
async def test_mistral_disabled_uses_cached_deterministic_fallback(db_session) -> None:
    scan = await _seed_scan(db_session)
    settings = Settings(AI_ENABLED=False)
    service = MistralEnrichmentService(db_session, settings)

    task_count_before = (
        await db_session.execute(select(func.count(Task.id)).where(Task.scan_id == scan.id))
    ).scalar_one()
    first = await service.enrich_vulnerability_coverage(scan.id)
    second = await service.enrich_vulnerability_coverage(scan.id)
    task_count_after = (
        await db_session.execute(select(func.count(Task.id)).where(Task.scan_id == scan.id))
    ).scalar_one()

    assert first.id == second.id
    assert second.cached is True
    assert first.provider == "deterministic-fallback"
    assert first.validation_status == "FALLBACK"
    assert first.output["priority_classes"]
    assert first.output["cross_asset_hypotheses"] == []
    assert task_count_after == task_count_before


@pytest.mark.asyncio
async def test_mistral_output_is_filtered_to_catalog_and_redacted_assets(
    db_session,
    monkeypatch,
) -> None:
    scan = await _seed_scan(db_session)
    settings = Settings(
        AI_ENABLED=True,
        MISTRAL_API_KEY="test-key",
        MISTRAL_MODEL="mistral-small-latest",
    )
    service = MistralEnrichmentService(db_session, settings)
    snapshot, class_codes, asset_ids = await service._coverage_snapshot(scan.id)
    assert "example.com" not in json.dumps(snapshot)

    valid_asset = next(iter(asset_ids))

    async def fake_call(redacted_snapshot):
        assert redacted_snapshot == snapshot
        return VulnerabilityCoverageAdvisory(
            summary="Advisory only.",
            priority_classes=[
                AdvisoryPriority(
                    class_code="AUTHORIZATION",
                    rationale="Open authorization cells span assets.",
                    evidence_gap="Role and object evidence is incomplete.",
                    recommended_validation="Review authorized role/object matrices.",
                ),
                AdvisoryPriority(
                    class_code="MADE_UP_CLASS",
                    rationale="Invalid",
                    evidence_gap="Invalid",
                    recommended_validation="Invalid",
                ),
            ],
            cross_asset_hypotheses=[
                CrossAssetHypothesisSuggestion(
                    title="Shared authorization policy may be inconsistent",
                    class_code="AUTHORIZATION",
                    asset_ids=[valid_asset, "not-an-asset"],
                    rationale="Multiple assets have open authorization coverage.",
                    required_evidence=["ROLE_MATRIX", "OBJECT_ACCESS_REVIEW"],
                    confidence=0.6,
                )
            ],
            limitations=["Not a verdict."],
        )

    monkeypatch.setattr(service, "_call_mistral", fake_call)
    record = await service.enrich_vulnerability_coverage(scan.id)

    assert record.provider == "mistral"
    assert record.validation_status == "VALID"
    assert [item["class_code"] for item in record.output["priority_classes"]] == ["AUTHORIZATION"]
    assert record.output["cross_asset_hypotheses"][0]["asset_ids"] == [valid_asset]
    assert set(class_codes) >= {"AUTHORIZATION"}


@pytest.mark.asyncio
async def test_mcp_read_models_do_not_mutate_assessment_state(db_session) -> None:
    scan = await _seed_scan(db_session)
    service = AssessmentMCPReadService(db_session)
    tracked_models = [Task, Hypothesis, Verdict, ConfirmedFinding, AIEnrichment]

    async def counts():
        return {
            model.__tablename__: (
                await db_session.execute(select(func.count(model.id)))
            ).scalar_one()
            for model in tracked_models
        }

    before = await counts()
    overview = await service.get_scan_overview(scan.id)
    assets = await service.list_scan_assets(scan.id)
    graph = await service.get_attack_surface_graph(scan.id)
    catalog = await service.get_vulnerability_catalog()
    coverage = await service.get_vulnerability_coverage(scan.id)
    matrix = await service.get_test_matrix(scan.id)
    backlog = await service.get_validation_backlog(scan.id)
    hypotheses = await service.get_hypotheses(scan.id)
    verdicts = await service.get_verdicts(scan.id)
    findings = await service.get_confirmed_findings(scan.id)
    completion = await service.get_completion_status(scan.id)
    advisories = await service.get_ai_advisories(scan.id)
    after = await counts()

    assert overview["asset_count"] == assets["total"]
    assert graph["nodes"]
    assert catalog["total"] >= 35
    assert coverage["open_cells"] > 0
    assert matrix["items"]
    assert backlog["items"]
    assert hypotheses["items"]
    assert verdicts["total"] == 0
    assert findings["total"] == 0
    assert completion["status"]
    assert advisories["total"] == 0
    assert all("metadata" not in item for item in assets["items"])
    assert before == after
