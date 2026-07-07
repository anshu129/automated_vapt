"""Phase 2 capability routing integration tests."""

from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, patch

import pytest
from sqlalchemy import select

from vapt_platform.db.tables.models import (
    Asset,
    AssetTestMatrix,
    AssetVulnerabilityApplicability,
    ProviderSelectionDecision,
    TestExecution,
    TestPlan,
    TestRequirement,
    VulnerabilityClass,
)
from vapt_platform.domain.capability_provider import (
    ProviderAvailabilityContext,
    ProviderAvailabilityResult,
    ProviderExecutionContext,
    ProviderExecutionResult,
    ProviderMetadata,
    ProviderSupportDecision,
    TestPlanContext,
)
from vapt_platform.domain.enums import (
    ApplicabilityState,
    AssetType,
    Capability,
    SafetyClass,
    TestPlanStatus,
    TestingMode,
)
from vapt_platform.engines.assessment import TestMatrixEngine, TestPlanner
from vapt_platform.services.capability_provider_registry import CapabilityProviderRegistry
from vapt_platform.services.capability_validation_router import CapabilityValidationRouter
from vapt_platform.services.core import ProjectService, ScanService
from vapt_platform.services.full_assessment import FullAssessmentService
from vapt_platform.services.mcp_validation import McpValidationService


class _RecordingProvider:
    def __init__(self, provider_id: str, caps: set[Capability], priority: int = 50) -> None:
        self.provider_id = provider_id
        self._caps = caps
        self._priority = priority
        self.execute_calls = 0

    def metadata(self) -> ProviderMetadata:
        return ProviderMetadata(
            provider_id=self.provider_id,
            display_name=self.provider_id,
            declared_capabilities=tuple(c.value for c in self._caps),
            supported_asset_types=(
                AssetType.WEB_APPLICATION.value,
                AssetType.ENDPOINT.value,
            ),
            supported_surface_types=("HTTP",),
            supported_authentication_types=("NONE",),
            default_safety_class=SafetyClass.LOW_IMPACT.value,
            execution_mode="LOCAL_PROCESS",
            priority=self._priority,
        )

    def declared_capabilities(self) -> set[Capability]:
        return self._caps

    def is_available(self, context: ProviderAvailabilityContext) -> ProviderAvailabilityResult:
        if self.provider_id == "sqlmap_mcp" and not context.active_validation_allowed:
            return ProviderAvailabilityResult(
                available=False,
                reason_codes=["ACTIVE_TESTING_NOT_AUTHORIZED"],
            )
        return ProviderAvailabilityResult(available=True)

    def supports_plan(self, plan: TestPlanContext) -> ProviderSupportDecision:
        if self.provider_id == "sqlmap_mcp":
            endpoint = plan.endpoint_context or {}
            if not endpoint.get("parameter_name"):
                return ProviderSupportDecision(supported=False, reason_codes=["PLAN_NOT_SUPPORTED"])
        return ProviderSupportDecision(supported=True)

    async def execute(self, context: ProviderExecutionContext) -> ProviderExecutionResult:
        self.execute_calls += 1
        return ProviderExecutionResult(
            provider_id=self.provider_id,
            capability=context.capability,
            status="NO_EVIDENCE",
        )


async def _seed_web_scan(db_session):
    project = await ProjectService(db_session).create("Phase 2 Project")
    scan = await ScanService(db_session).create(
        project.id,
        "Phase 2 Scan",
        [{"rule_type": "URL_PREFIX", "pattern": "https://app.example.com", "priority": 90}],
    )
    await ScanService(db_session).start(scan.id)
    await db_session.commit()
    return scan


@pytest.mark.asyncio
async def test_phase2_routing_end_to_end_with_fake_provider(db_session) -> None:
    scan = await _seed_web_scan(db_session)
    refresh = await FullAssessmentService(db_session).refresh_assessment_state(scan.id)
    assert refresh.matrices_built >= 1

    web_app = (
        await db_session.execute(
            select(Asset).where(
                Asset.scan_id == scan.id,
                Asset.asset_type == AssetType.WEB_APPLICATION.value,
            )
        )
    ).scalar_one()

    classes = {
        row.class_code: row
        for row in (await db_session.execute(select(VulnerabilityClass))).scalars().all()
    }
    matrix = await TestMatrixEngine(db_session).build(scan.id, web_app.id)
    req = (
        await db_session.execute(
            select(TestRequirement).where(
                TestRequirement.matrix_id == matrix.id,
                TestRequirement.vulnerability_class_id == classes["SECURITY_HEADERS"].id,
            )
        )
    ).scalar_one()
    assert Capability.TEMPLATE_BASED_ASSESSMENT.value in req.eligible_capabilities

    plans = await TestPlanner(db_session).plan_scan(scan.id)
    await db_session.commit()
    assert plans
    target_plan = next(
        p
        for p in plans
        if classes["SECURITY_HEADERS"].id
        in [uuid.UUID(str(v)) for v in (p.vulnerability_class_ids or [])]
    )

    fake_nuclei = _RecordingProvider("nuclei", {Capability.TEMPLATE_BASED_ASSESSMENT}, 10)
    registry = CapabilityProviderRegistry([fake_nuclei])

    with patch.object(McpValidationService, "validate_scan", new_callable=AsyncMock) as legacy:
        router = CapabilityValidationRouter(db_session, registry=registry)
        result = await router.route_and_execute(scan.id, target_plan.id)
        await db_session.commit()

    assert result["selected_provider"] == "nuclei"
    assert fake_nuclei.execute_calls == 1
    legacy.assert_not_called()

    decision = await db_session.get(ProviderSelectionDecision, uuid.UUID(result["decision_id"]))
    assert decision is not None
    assert decision.selected_provider == "nuclei"

    execution = await db_session.get(TestExecution, uuid.UUID(result["execution_id"]))
    assert execution is not None
    assert execution.selected_provider_id == "nuclei"


@pytest.mark.asyncio
async def test_injection_blocked_when_active_validation_unauthorized(db_session) -> None:
    scan = await _seed_web_scan(db_session)
    web_app = (
        await db_session.execute(
            select(Asset).where(
                Asset.scan_id == scan.id,
                Asset.asset_type == AssetType.WEB_APPLICATION.value,
            )
        )
    ).scalar_one()
    classes = {
        row.class_code: row
        for row in (await db_session.execute(select(VulnerabilityClass))).scalars().all()
    }
    matrix = await TestMatrixEngine(db_session).build(scan.id, web_app.id)
    req = (
        await db_session.execute(
            select(TestRequirement).where(
                TestRequirement.matrix_id == matrix.id,
                TestRequirement.vulnerability_class_id == classes["INJECTION_CLASS"].id,
            )
        )
    ).scalar_one()
    plan = TestPlan(
        scan_id=scan.id,
        asset_ids=[str(web_app.id)],
        vulnerability_class_ids=[str(classes["INJECTION_CLASS"].id)],
        testing_mode=TestingMode.AUTOMATED.value,
        required_capabilities=[Capability.INJECTION_VALIDATION.value],
        safety_class=SafetyClass.STATE_CHANGING.value,
        authorization_requirement="PRE_APPROVED",
        status=TestPlanStatus.APPROVED.value,
        required_context={
            "endpoint": {
                "url": "https://app.example.com/search",
                "parameter_location": "query",
                "parameter_name": "q",
                "applicability_state": ApplicabilityState.APPLICABLE.value,
            }
        },
        reasoning_trace={"requirement_id": str(req.id)},
    )
    db_session.add(plan)
    await db_session.flush()

    fake_sqlmap = _RecordingProvider("sqlmap_mcp", {Capability.INJECTION_VALIDATION}, 30)
    registry = CapabilityProviderRegistry([fake_sqlmap])
    router = CapabilityValidationRouter(db_session, registry=registry)
    result = await router.route_and_execute(
        scan.id,
        plan.id,
        active_validation_allowed=False,
    )
    await db_session.commit()

    assert result["selected_provider"] is None
    assert fake_sqlmap.execute_calls == 0
    decision = await db_session.get(ProviderSelectionDecision, uuid.UUID(result["decision_id"]))
    assert decision is not None
    assert "sqlmap_mcp" in (decision.rejection_reasons or {})


@pytest.mark.asyncio
async def test_template_plan_selects_nuclei_not_sqlmap(db_session) -> None:
    scan = await _seed_web_scan(db_session)
    web_app = (
        await db_session.execute(
            select(Asset).where(
                Asset.scan_id == scan.id,
                Asset.asset_type == AssetType.WEB_APPLICATION.value,
            )
        )
    ).scalar_one()
    classes = {
        row.class_code: row
        for row in (await db_session.execute(select(VulnerabilityClass))).scalars().all()
    }
    plan = TestPlan(
        scan_id=scan.id,
        asset_ids=[str(web_app.id)],
        vulnerability_class_ids=[str(classes["SECURITY_HEADERS"].id)],
        testing_mode=TestingMode.AUTOMATED.value,
        required_capabilities=[
            Capability.TEMPLATE_BASED_ASSESSMENT.value,
            Capability.INJECTION_VALIDATION.value,
        ],
        safety_class=SafetyClass.LOW_IMPACT.value,
        authorization_requirement="PRE_APPROVED",
        status=TestPlanStatus.APPROVED.value,
    )
    db_session.add(plan)
    await db_session.flush()

    fake_nuclei = _RecordingProvider("nuclei", {Capability.TEMPLATE_BASED_ASSESSMENT}, 10)
    fake_sqlmap = _RecordingProvider("sqlmap_mcp", {Capability.INJECTION_VALIDATION}, 30)
    registry = CapabilityProviderRegistry([fake_sqlmap, fake_nuclei])
    router = CapabilityValidationRouter(db_session, registry=registry)
    result = await router.route_and_execute(scan.id, plan.id, active_validation_allowed=True)
    await db_session.commit()

    assert result["selected_provider"] == "nuclei"
    assert result["required_capability"] == Capability.TEMPLATE_BASED_ASSESSMENT.value
    assert fake_nuclei.execute_calls == 1
    assert fake_sqlmap.execute_calls == 0
