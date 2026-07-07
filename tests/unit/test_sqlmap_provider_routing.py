"""SQLMap MCP provider routing unit tests."""

import pytest

from vapt_platform.domain.capability_provider import (
    ProviderAvailabilityContext,
    ProviderExecutionContext,
    TestPlanContext,
)
from vapt_platform.domain.enums import ApplicabilityState, Capability, SafetyClass
from vapt_platform.providers.sqlmap_provider import SqlmapCapabilityProvider
from vapt_platform.validators.base import ValidationOutcome
from vapt_platform.validators.sqlmap_mcp import SqlmapMcpValidator


class _FakeSqlmap(SqlmapMcpValidator):
    def __init__(self) -> None:
        self.called = False

    def is_available(self) -> bool:
        return True

    async def validate(self, **kwargs) -> ValidationOutcome:
        self.called = True
        return ValidationOutcome(
            connector="sqlmap",
            target_url=kwargs.get("target_url", ""),
            asset_id=kwargs.get("asset_id"),
            class_codes=kwargs.get("class_codes", []),
            tags=kwargs.get("tags", []),
            status="NO_EVIDENCE",
        )


def _injection_plan(**kwargs) -> TestPlanContext:
    endpoint = {
        "url": "https://app.example.com/search",
        "parameter_location": "query",
        "parameter_name": "q",
        "applicability_state": ApplicabilityState.APPLICABLE.value,
    }
    base = {
        "scan_id": "s",
        "test_plan_id": "p",
        "asset_ids": ["a"],
        "vulnerability_class_ids": ["c"],
        "class_codes": ["SQL_INJECTION"],
        "required_capabilities": [Capability.INJECTION_VALIDATION.value],
        "testing_mode": "AUTOMATED",
        "safety_class": SafetyClass.STATE_CHANGING.value,
        "authorization_requirement": "PRE_APPROVED",
        "target_url": "https://app.example.com",
        "asset_type": "WEB_APPLICATION",
        "endpoint_context": endpoint,
        "active_validation_allowed": True,
    }
    base.update(kwargs)
    return TestPlanContext(**base)


def test_sqlmap_requires_injection_capability() -> None:
    provider = SqlmapCapabilityProvider(validator=_FakeSqlmap())
    decision = provider.supports_plan(
        _injection_plan(required_capabilities=[Capability.TEMPLATE_BASED_ASSESSMENT.value])
    )
    assert not decision.supported


def test_sqlmap_requires_structured_input_location() -> None:
    provider = SqlmapCapabilityProvider(validator=_FakeSqlmap())
    plan = _injection_plan()
    plan.endpoint_context = {"url": "https://app.example.com"}
    assert not provider.supports_plan(plan).supported


def test_sqlmap_unavailable_when_active_not_allowed() -> None:
    provider = SqlmapCapabilityProvider(validator=_FakeSqlmap())
    result = provider.is_available(
        ProviderAvailabilityContext(scan_id="s", active_validation_allowed=False)
    )
    assert not result.available


@pytest.mark.asyncio
async def test_eligible_injection_plan_routes_to_sqlmap() -> None:
    fake = _FakeSqlmap()
    provider = SqlmapCapabilityProvider(validator=fake)
    assert provider.supports_plan(_injection_plan()).supported
    await provider.execute(
        ProviderExecutionContext(
            plan=_injection_plan(),
            capability=Capability.INJECTION_VALIDATION.value,
            provider_id="sqlmap_mcp",
        )
    )
    assert fake.called
