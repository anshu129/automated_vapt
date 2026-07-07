"""Match TestPlan capabilities to provider declarations (Phase 2)."""

from __future__ import annotations

from dataclasses import dataclass, field

from vapt_platform.domain.capability_provider import (
    CapabilityProvider,
    ProviderRejectionReason,
    TestPlanContext,
)
from vapt_platform.domain.enums import Capability


@dataclass
class CapabilityMatchResult:
    capability: str | None
    eligible_providers: list[CapabilityProvider] = field(default_factory=list)
    rejected: dict[str, list[str]] = field(default_factory=dict)


_SUPPORTED_SURFACES = {"WEB_APPLICATION", "ENDPOINT", "SERVICE", None}


class CapabilityMatcher:
    def match(
        self,
        plan: TestPlanContext,
        providers: list[CapabilityProvider],
        *,
        required_capability: str | None = None,
    ) -> CapabilityMatchResult:
        capabilities = (
            [required_capability]
            if required_capability
            else list(plan.required_capabilities or [])
        )
        rejected: dict[str, list[str]] = {}
        for capability in capabilities:
            try:
                cap_enum = Capability(capability)
            except ValueError:
                continue
            eligible: list[CapabilityProvider] = []
            for provider in providers:
                declared = provider.declared_capabilities()
                if cap_enum not in declared:
                    rejected.setdefault(provider.provider_id, []).append(
                        ProviderRejectionReason.CAPABILITY_NOT_DECLARED.value
                    )
                    continue
                if plan.asset_type:
                    supported = provider.metadata().supported_asset_types or ()
                    if plan.asset_type not in supported:
                        rejected.setdefault(provider.provider_id, []).append(
                            ProviderRejectionReason.SURFACE_NOT_SUPPORTED.value
                        )
                        continue
                eligible.append(provider)
            if eligible:
                return CapabilityMatchResult(
                    capability=capability,
                    eligible_providers=eligible,
                    rejected=rejected,
                )
        return CapabilityMatchResult(capability=None, eligible_providers=[], rejected=rejected)
