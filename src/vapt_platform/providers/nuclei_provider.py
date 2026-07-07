"""Nuclei capability provider (Phase 2)."""

from __future__ import annotations

from vapt_platform.domain.capability_provider import (
    ProviderAvailabilityContext,
    ProviderAvailabilityResult,
    ProviderExecutionContext,
    ProviderExecutionResult,
    ProviderMetadata,
    ProviderSupportDecision,
    TestPlanContext,
)
from vapt_platform.domain.enums import AssetType, Capability, SafetyClass
from vapt_platform.validators.base import ValidationFinding, nuclei_tags_for_class
from vapt_platform.validators.nuclei import NucleiValidator


class NucleiCapabilityProvider:
    provider_id = "nuclei"

    def __init__(self, validator: NucleiValidator | None = None) -> None:
        self._validator = validator or NucleiValidator()

    def metadata(self) -> ProviderMetadata:
        return ProviderMetadata(
            provider_id=self.provider_id,
            display_name="Nuclei",
            declared_capabilities=(
                Capability.TEMPLATE_BASED_ASSESSMENT.value,
            ),
            supported_asset_types=(
                AssetType.WEB_APPLICATION.value,
                AssetType.ENDPOINT.value,
                AssetType.SERVICE.value,
            ),
            supported_surface_types=("HTTP",),
            supported_authentication_types=("BASIC", "FORM", "BEARER", "NONE"),
            default_safety_class=SafetyClass.LOW_IMPACT.value,
            execution_mode="LOCAL_PROCESS",
            priority=10,
        )

    def declared_capabilities(self) -> set[Capability]:
        return {Capability.TEMPLATE_BASED_ASSESSMENT}

    def is_available(self, context: ProviderAvailabilityContext) -> ProviderAvailabilityResult:
        if self._validator.is_available():
            return ProviderAvailabilityResult(available=True)
        return ProviderAvailabilityResult(
            available=False,
            reason_codes=["PROVIDER_UNAVAILABLE"],
        )

    def supports_plan(self, plan: TestPlanContext) -> ProviderSupportDecision:
        if Capability.TEMPLATE_BASED_ASSESSMENT.value not in (plan.required_capabilities or []):
            return ProviderSupportDecision(
                supported=False,
                reason_codes=["CAPABILITY_NOT_DECLARED"],
            )
        if not plan.target_url:
            return ProviderSupportDecision(
                supported=False,
                reason_codes=["SURFACE_NOT_SUPPORTED"],
            )
        return ProviderSupportDecision(supported=True)

    async def execute(self, context: ProviderExecutionContext) -> ProviderExecutionResult:
        plan = context.plan
        tags: list[str] = []
        for code in plan.class_codes:
            for tag in nuclei_tags_for_class(code):
                if tag not in tags:
                    tags.append(tag)
        outcome = await self._validator.validate(
            target_url=plan.target_url or "",
            tags=tags or ["misconfig", "exposure"],
            class_codes=plan.class_codes,
            asset_id=plan.asset_ids[0] if plan.asset_ids else None,
            username=plan.username,
            password=plan.password,
        )
        return ProviderExecutionResult(
            provider_id=self.provider_id,
            capability=context.capability,
            status=outcome.status,
            detail=outcome.detail,
            findings=[_finding_dict(f) for f in outcome.findings],
            redacted_command=outcome.redacted_command,
        )


def _finding_dict(finding: ValidationFinding) -> dict:
    return finding.to_dict()
