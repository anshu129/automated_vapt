"""Unit tests for CapabilityMatcher."""

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
from vapt_platform.engines.capability_matcher import CapabilityMatcher
from vapt_platform.services.capability_provider_registry import CapabilityProviderRegistry


class _StubProvider:
    def __init__(self, provider_id: str, caps: set[Capability]) -> None:
        self._provider_id = provider_id
        self._caps = caps

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
        )

    def declared_capabilities(self) -> set[Capability]:
        return self._caps

    def is_available(self, context: ProviderAvailabilityContext) -> ProviderAvailabilityResult:
        return ProviderAvailabilityResult(available=True)

    def supports_plan(self, plan: TestPlanContext) -> ProviderSupportDecision:
        return ProviderSupportDecision(supported=True)

    async def execute(self, context: ProviderExecutionContext) -> ProviderExecutionResult:
        return ProviderExecutionResult(
            provider_id=self._provider_id,
            capability=context.capability,
            status="NO_EVIDENCE",
        )


def _plan(**kwargs) -> TestPlanContext:
    defaults = {
        "scan_id": "s1",
        "test_plan_id": "p1",
        "asset_ids": ["a1"],
        "vulnerability_class_ids": ["c1"],
        "class_codes": ["SQL_INJECTION"],
        "required_capabilities": [Capability.INJECTION_VALIDATION.value],
        "testing_mode": "AUTOMATED",
        "safety_class": SafetyClass.LOW_IMPACT.value,
        "authorization_requirement": "PRE_APPROVED",
        "target_url": "https://app.example.com",
        "asset_type": "WEB_APPLICATION",
    }
    defaults.update(kwargs)
    return TestPlanContext(**defaults)


def test_exact_capability_match() -> None:
    providers = [
        _StubProvider("nuclei", {Capability.TEMPLATE_BASED_ASSESSMENT}),
        _StubProvider("sqlmap_mcp", {Capability.INJECTION_VALIDATION}),
    ]
    match = CapabilityMatcher().match(
        _plan(required_capabilities=[Capability.INJECTION_VALIDATION.value]),
        providers,
    )
    assert match.capability == Capability.INJECTION_VALIDATION.value
    assert [p.provider_id for p in match.eligible_providers] == ["sqlmap_mcp"]


def test_multi_capability_requirement_picks_first_match() -> None:
    providers = [
        _StubProvider("nuclei", {Capability.TEMPLATE_BASED_ASSESSMENT}),
        _StubProvider("burp_mcp", {Capability.WEB_PASSIVE_ASSESSMENT}),
    ]
    match = CapabilityMatcher().match(
        _plan(
            required_capabilities=[
                Capability.WEB_PASSIVE_ASSESSMENT.value,
                Capability.TEMPLATE_BASED_ASSESSMENT.value,
            ]
        ),
        providers,
    )
    assert match.capability == Capability.WEB_PASSIVE_ASSESSMENT.value


def test_provider_rejected_for_undeclared_capability() -> None:
    providers = [_StubProvider("nuclei", {Capability.TEMPLATE_BASED_ASSESSMENT})]
    match = CapabilityMatcher().match(
        _plan(required_capabilities=[Capability.INJECTION_VALIDATION.value]),
        providers,
    )
    assert match.eligible_providers == []
    assert "nuclei" in match.rejected


def test_provider_rejected_for_unsupported_surface() -> None:
    class _NarrowProvider(_StubProvider):
        def metadata(self) -> ProviderMetadata:
            meta = super().metadata()
            return ProviderMetadata(
                provider_id=meta.provider_id,
                display_name=meta.display_name,
                declared_capabilities=meta.declared_capabilities,
                supported_asset_types=("SERVICE",),
                supported_surface_types=meta.supported_surface_types,
                supported_authentication_types=meta.supported_authentication_types,
                default_safety_class=meta.default_safety_class,
                execution_mode=meta.execution_mode,
            )

    providers = [_NarrowProvider("nuclei", {Capability.TEMPLATE_BASED_ASSESSMENT})]
    match = CapabilityMatcher().match(
        _plan(
            required_capabilities=[Capability.TEMPLATE_BASED_ASSESSMENT.value],
            asset_type="WEB_APPLICATION",
        ),
        providers,
    )
    assert match.eligible_providers == []
