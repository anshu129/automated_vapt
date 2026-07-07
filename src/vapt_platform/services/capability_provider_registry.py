"""Registry of capability providers (Phase 2)."""

from __future__ import annotations

from vapt_platform.domain.capability_provider import (
    CapabilityProvider as CapabilityProviderProtocol,
    ProviderAvailabilityContext,
    ProviderAvailabilityResult,
)
from vapt_platform.domain.enums import Capability


class CapabilityProviderRegistry:
    """Returns eligible candidates by declared capability; does not select winners."""

    def __init__(self, providers: list[CapabilityProviderProtocol] | None = None) -> None:
        self._providers: dict[str, CapabilityProviderProtocol] = {}
        if providers:
            for provider in providers:
                self.register(provider)

    def register(self, provider: CapabilityProviderProtocol) -> None:
        provider_id = provider.provider_id
        if provider_id in self._providers:
            raise ValueError(f"Duplicate provider ID: {provider_id}")
        self._providers[provider_id] = provider

    def list_providers(self) -> list[CapabilityProviderProtocol]:
        return self._sorted(self._providers.values())

    def get(self, provider_id: str) -> CapabilityProviderProtocol | None:
        return self._providers.get(provider_id)

    def providers_for(self, capability: Capability | str) -> list[CapabilityProviderProtocol]:
        cap = Capability(capability) if isinstance(capability, str) else capability
        matched = [
            provider
            for provider in self._providers.values()
            if cap in provider.declared_capabilities()
        ]
        return self._sorted(matched)

    def check_availability(
        self,
        provider_id: str,
        context: ProviderAvailabilityContext,
    ) -> ProviderAvailabilityResult:
        provider = self._providers.get(provider_id)
        if not provider:
            return ProviderAvailabilityResult(
                available=False,
                reason_codes=["PROVIDER_UNAVAILABLE"],
            )
        return provider.is_available(context)

    @staticmethod
    def _sorted(providers: list[CapabilityProviderProtocol]) -> list[CapabilityProviderProtocol]:
        return sorted(
            providers,
            key=lambda p: (p.metadata().priority, p.provider_id),
        )
