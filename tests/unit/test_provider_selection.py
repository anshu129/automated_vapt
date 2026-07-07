"""Unit tests for provider selection via CapabilityValidationRouter helpers."""

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


class _SelectableProvider:
    def __init__(self, provider_id: str, caps: set[Capability], priority: int) -> None:
        self._provider_id = provider_id
        self._caps = caps
        self._priority = priority

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
        return ProviderAvailabilityResult(available=True)

    def supports_plan(self, plan: TestPlanContext) -> ProviderSupportDecision:
        return ProviderSupportDecision(supported=True)

    async def execute(self, context: ProviderExecutionContext) -> ProviderExecutionResult:
        return ProviderExecutionResult(
            provider_id=self._provider_id,
            capability=context.capability,
            status="NO_EVIDENCE",
        )


def _select(registry: CapabilityProviderRegistry, capability: str) -> str:
    providers = registry.providers_for(capability)
    ordered = sorted(
        providers,
        key=lambda p: (p.metadata().priority, p.provider_id),
    )
    return ordered[0].provider_id if ordered else ""


def test_one_eligible_provider_selected() -> None:
    registry = CapabilityProviderRegistry(
        [_SelectableProvider("nuclei", {Capability.TEMPLATE_BASED_ASSESSMENT}, 10)]
    )
    assert _select(registry, Capability.TEMPLATE_BASED_ASSESSMENT.value) == "nuclei"


def test_multiple_providers_use_deterministic_priority() -> None:
    registry = CapabilityProviderRegistry(
        [
            _SelectableProvider("z-last", {Capability.WEB_PASSIVE_ASSESSMENT}, 20),
            _SelectableProvider("a-first", {Capability.WEB_PASSIVE_ASSESSMENT}, 10),
        ]
    )
    assert _select(registry, Capability.WEB_PASSIVE_ASSESSMENT.value) == "a-first"


def test_lexical_tie_breaker() -> None:
    registry = CapabilityProviderRegistry(
        [
            _SelectableProvider("z-provider", {Capability.WEB_PASSIVE_ASSESSMENT}, 10),
            _SelectableProvider("a-provider", {Capability.WEB_PASSIVE_ASSESSMENT}, 10),
        ]
    )
    assert _select(registry, Capability.WEB_PASSIVE_ASSESSMENT.value) == "a-provider"


def test_all_providers_rejected_returns_no_match() -> None:
    plan = TestPlanContext(
        scan_id="s",
        test_plan_id="p",
        asset_ids=["a"],
        vulnerability_class_ids=["c"],
        class_codes=["XSS"],
        required_capabilities=[Capability.INJECTION_VALIDATION.value],
        testing_mode="AUTOMATED",
        safety_class=SafetyClass.LOW_IMPACT.value,
        authorization_requirement="PRE_APPROVED",
        target_url="https://example.com",
        asset_type="WEB_APPLICATION",
    )
    providers = [_SelectableProvider("nuclei", {Capability.TEMPLATE_BASED_ASSESSMENT}, 10)]
    match = CapabilityMatcher().match(plan, providers)
    assert match.capability is None
    assert match.eligible_providers == []
