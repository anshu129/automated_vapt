"""Burp MCP capability provider (Phase 2) — read-only import/passive assessment."""

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
from vapt_platform.validators.base import ValidationFinding
from vapt_platform.validators.burp import BurpMcpValidator


class BurpCapabilityProvider:
    provider_id = "burp_mcp"

    def __init__(
        self,
        validator: BurpMcpValidator | None = None,
        sse_url: str = "http://127.0.0.1:9876",
    ) -> None:
        self._validator = validator or BurpMcpValidator(sse_url=sse_url)

    def metadata(self) -> ProviderMetadata:
        return ProviderMetadata(
            provider_id=self.provider_id,
            display_name="Burp Suite MCP",
            declared_capabilities=(
                Capability.WEB_PASSIVE_ASSESSMENT.value,
                Capability.VULNERABILITY_FINDING_IMPORT.value,
            ),
            supported_asset_types=(
                AssetType.WEB_APPLICATION.value,
                AssetType.ENDPOINT.value,
            ),
            supported_surface_types=("HTTP",),
            supported_authentication_types=("BASIC", "FORM", "BEARER", "SESSION", "NONE"),
            default_safety_class=SafetyClass.PASSIVE.value,
            execution_mode="MCP",
            priority=20,
        )

    def declared_capabilities(self) -> set[Capability]:
        return {Capability.WEB_PASSIVE_ASSESSMENT, Capability.VULNERABILITY_FINDING_IMPORT}

    def is_available(self, context: ProviderAvailabilityContext) -> ProviderAvailabilityResult:
        if self._validator.is_available():
            return ProviderAvailabilityResult(available=True)
        return ProviderAvailabilityResult(
            available=False,
            reason_codes=["PROVIDER_UNAVAILABLE"],
        )

    def supports_plan(self, plan: TestPlanContext) -> ProviderSupportDecision:
        declared = {cap.value for cap in self.declared_capabilities()}
        if not declared.intersection(plan.required_capabilities or []):
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
        tags = ["burp"]
        outcome = await self._validator.validate(
            target_url=plan.target_url or "",
            tags=tags,
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
            findings=[f.to_dict() for f in outcome.findings],
            redacted_command=outcome.redacted_command,
        )
