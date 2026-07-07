"""Nuclei provider routing unit tests."""

import pytest

from vapt_platform.domain.capability_provider import (
    ProviderAvailabilityContext,
    ProviderExecutionContext,
    TestPlanContext,
)
from vapt_platform.domain.enums import Capability, SafetyClass
from vapt_platform.providers.nuclei_provider import NucleiCapabilityProvider
from vapt_platform.services.capability_provider_registry import CapabilityProviderRegistry
from vapt_platform.validators.base import ValidationOutcome
from vapt_platform.validators.nuclei import NucleiValidator


class _FakeNuclei(NucleiValidator):
    def __init__(self) -> None:
        pass

    def is_available(self) -> bool:
        return True

    async def validate(self, **kwargs) -> ValidationOutcome:
        return ValidationOutcome(
            connector="nuclei",
            target_url=kwargs.get("target_url", ""),
            asset_id=kwargs.get("asset_id"),
            class_codes=kwargs.get("class_codes", []),
            tags=kwargs.get("tags", []),
            status="NO_EVIDENCE",
        )


def _plan(**kwargs) -> TestPlanContext:
    base = {
        "scan_id": "s",
        "test_plan_id": "p",
        "asset_ids": ["a"],
        "vulnerability_class_ids": ["c"],
        "class_codes": ["SECURITY_HEADERS"],
        "required_capabilities": [Capability.TEMPLATE_BASED_ASSESSMENT.value],
        "testing_mode": "AUTOMATED",
        "safety_class": SafetyClass.LOW_IMPACT.value,
        "authorization_requirement": "PRE_APPROVED",
        "target_url": "https://app.example.com",
        "asset_type": "WEB_APPLICATION",
    }
    base.update(kwargs)
    return TestPlanContext(**base)


@pytest.mark.asyncio
async def test_nuclei_cannot_execute_without_matching_capability() -> None:
    provider = NucleiCapabilityProvider(validator=_FakeNuclei())
    decision = provider.supports_plan(
        _plan(required_capabilities=[Capability.INJECTION_VALIDATION.value])
    )
    assert not decision.supported


@pytest.mark.asyncio
async def test_matching_template_plan_supports_nuclei() -> None:
    provider = NucleiCapabilityProvider(validator=_FakeNuclei())
    assert provider.supports_plan(_plan()).supported
    registry = CapabilityProviderRegistry([provider])
    assert registry.providers_for(Capability.TEMPLATE_BASED_ASSESSMENT)[0].provider_id == "nuclei"


@pytest.mark.asyncio
async def test_nuclei_execute_without_plan_context_fails_support() -> None:
    provider = NucleiCapabilityProvider(validator=_FakeNuclei())
    decision = provider.supports_plan(_plan(target_url=None))
    assert not decision.supported


@pytest.mark.asyncio
async def test_nuclei_provider_executes_for_eligible_plan() -> None:
    provider = NucleiCapabilityProvider(validator=_FakeNuclei())
    result = await provider.execute(
        ProviderExecutionContext(
            plan=_plan(),
            capability=Capability.TEMPLATE_BASED_ASSESSMENT.value,
            provider_id="nuclei",
        )
    )
    assert result.provider_id == "nuclei"
    assert result.status == "NO_EVIDENCE"
