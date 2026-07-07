"""Unit tests for CapabilityProviderRegistry."""

import pytest

from vapt_platform.domain.capability_provider import (
    ProviderAvailabilityContext,
    ProviderAvailabilityResult,
    ProviderExecutionContext,
    ProviderExecutionResult,
    ProviderMetadata,
    ProviderSupportDecision,
    TestPlanContext,
)
from vapt_platform.domain.enums import Capability, SafetyClass
from vapt_platform.services.capability_provider_registry import CapabilityProviderRegistry


class _FakeProvider:
    def __init__(self, provider_id: str, caps: set[Capability], priority: int = 50) -> None:
        self._provider_id = provider_id
        self._caps = caps
        self._priority = priority
        self._available = True

    @property
    def provider_id(self) -> str:
        return self._provider_id

    def metadata(self) -> ProviderMetadata:
        return ProviderMetadata(
            provider_id=self._provider_id,
            display_name=self._provider_id,
            declared_capabilities=tuple(c.value for c in self._caps),
            supported_asset_types=("WEB_APPLICATION",),
            supported_surface_types=("HTTP",),
            supported_authentication_types=("NONE",),
            default_safety_class=SafetyClass.LOW_IMPACT.value,
            execution_mode="LOCAL_PROCESS",
            priority=self._priority,
        )

    def declared_capabilities(self) -> set[Capability]:
        return self._caps

    def is_available(self, context: ProviderAvailabilityContext) -> ProviderAvailabilityResult:
        return ProviderAvailabilityResult(available=self._available)

    def supports_plan(self, plan: TestPlanContext) -> ProviderSupportDecision:
        return ProviderSupportDecision(supported=True)

    async def execute(self, context: ProviderExecutionContext) -> ProviderExecutionResult:
        return ProviderExecutionResult(
            provider_id=self._provider_id,
            capability=context.capability,
            status="NO_EVIDENCE",
        )


def test_registry_registration_and_providers_for() -> None:
    registry = CapabilityProviderRegistry()
    nuclei = _FakeProvider("nuclei", {Capability.TEMPLATE_BASED_ASSESSMENT}, priority=10)
    sqlmap = _FakeProvider("sqlmap_mcp", {Capability.INJECTION_VALIDATION}, priority=30)
    registry.register(nuclei)
    registry.register(sqlmap)

    matched = registry.providers_for(Capability.TEMPLATE_BASED_ASSESSMENT)
    assert [p.provider_id for p in matched] == ["nuclei"]


def test_registry_rejects_duplicate_provider_id() -> None:
    registry = CapabilityProviderRegistry()
    registry.register(_FakeProvider("nuclei", {Capability.TEMPLATE_BASED_ASSESSMENT}))
    with pytest.raises(ValueError, match="Duplicate"):
        registry.register(_FakeProvider("nuclei", {Capability.WEB_PASSIVE_ASSESSMENT}))


def test_registry_deterministic_ordering() -> None:
    registry = CapabilityProviderRegistry(
        [
            _FakeProvider("z-provider", {Capability.WEB_PASSIVE_ASSESSMENT}, priority=10),
            _FakeProvider("a-provider", {Capability.WEB_PASSIVE_ASSESSMENT}, priority=10),
        ]
    )
    assert [p.provider_id for p in registry.providers_for(Capability.WEB_PASSIVE_ASSESSMENT)] == [
        "a-provider",
        "z-provider",
    ]


def test_unavailable_provider_handling() -> None:
    provider = _FakeProvider("nuclei", {Capability.TEMPLATE_BASED_ASSESSMENT})
    provider._available = False
    registry = CapabilityProviderRegistry([provider])
    result = registry.check_availability(
        "nuclei",
        ProviderAvailabilityContext(scan_id="scan-1"),
    )
    assert not result.available
