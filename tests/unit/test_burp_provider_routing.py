"""Burp MCP provider routing unit tests."""

import pytest

from vapt_platform.domain.capability_provider import ProviderExecutionContext, TestPlanContext
from vapt_platform.domain.enums import Capability, SafetyClass
from vapt_platform.providers.burp_provider import BurpCapabilityProvider
from vapt_platform.validators.base import ValidationOutcome
from vapt_platform.validators.burp import BurpMcpValidator


class _FakeBurp(BurpMcpValidator):
    def __init__(self) -> None:
        self.called = False

    def is_available(self) -> bool:
        return True

    async def validate(self, **kwargs) -> ValidationOutcome:
        self.called = True
        return ValidationOutcome(
            connector="burp",
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
        "required_capabilities": [Capability.WEB_PASSIVE_ASSESSMENT.value],
        "testing_mode": "AUTOMATED",
        "safety_class": SafetyClass.PASSIVE.value,
        "authorization_requirement": "PRE_APPROVED",
        "target_url": "https://app.example.com",
        "asset_type": "WEB_APPLICATION",
    }
    base.update(kwargs)
    return TestPlanContext(**base)


def test_burp_declares_passive_and_import_only() -> None:
    provider = BurpCapabilityProvider(validator=_FakeBurp())
    caps = {c.value for c in provider.declared_capabilities()}
    assert Capability.WEB_PASSIVE_ASSESSMENT.value in caps
    assert Capability.VULNERABILITY_FINDING_IMPORT.value in caps
    assert Capability.WEB_ACTIVE_ASSESSMENT.value not in caps


@pytest.mark.asyncio
async def test_router_burp_provider_fake_transport() -> None:
    fake = _FakeBurp()
    provider = BurpCapabilityProvider(validator=fake)
    await provider.execute(
        ProviderExecutionContext(
            plan=_plan(),
            capability=Capability.WEB_PASSIVE_ASSESSMENT.value,
            provider_id="burp_mcp",
        )
    )
    assert fake.called
