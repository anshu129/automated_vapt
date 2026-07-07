"""SQLMap MCP injection validation provider (Phase 2)."""

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
from vapt_platform.domain.enums import ApplicabilityState, AssetType, Capability, SafetyClass
from vapt_platform.validators.sqlmap_mcp import SqlmapMcpValidator

_SUPPORTED_INPUT_LOCATIONS = {"query", "body", "form", "cookie", "header", "json"}


class SqlmapCapabilityProvider:
    provider_id = "sqlmap_mcp"

    def __init__(
        self,
        validator: SqlmapMcpValidator | None = None,
        server_path: str = "",
        command: str = "python",
        extra_args: list[str] | None = None,
    ) -> None:
        self._validator = (
            validator
            if validator is not None
            else SqlmapMcpValidator(
                server_path=server_path,
                command=command,
                extra_args=extra_args or [],
            )
        )

    def metadata(self) -> ProviderMetadata:
        return ProviderMetadata(
            provider_id=self.provider_id,
            display_name="SQLMap MCP",
            declared_capabilities=(Capability.INJECTION_VALIDATION.value,),
            supported_asset_types=(
                AssetType.WEB_APPLICATION.value,
                AssetType.ENDPOINT.value,
            ),
            supported_surface_types=("HTTP",),
            supported_authentication_types=("BASIC", "FORM", "BEARER", "NONE"),
            default_safety_class=SafetyClass.STATE_CHANGING.value,
            execution_mode="MCP",
            priority=30,
        )

    def declared_capabilities(self) -> set[Capability]:
        return {Capability.INJECTION_VALIDATION}

    def is_available(self, context: ProviderAvailabilityContext) -> ProviderAvailabilityResult:
        if not context.active_validation_allowed:
            return ProviderAvailabilityResult(
                available=False,
                reason_codes=["ACTIVE_TESTING_NOT_AUTHORIZED"],
            )
        if self._validator.is_available():
            return ProviderAvailabilityResult(available=True)
        return ProviderAvailabilityResult(
            available=False,
            reason_codes=["PROVIDER_UNAVAILABLE"],
        )

    def supports_plan(self, plan: TestPlanContext) -> ProviderSupportDecision:
        if Capability.INJECTION_VALIDATION.value not in (plan.required_capabilities or []):
            return ProviderSupportDecision(
                supported=False,
                reason_codes=["CAPABILITY_NOT_DECLARED"],
            )
        endpoint = plan.endpoint_context or {}
        if not endpoint.get("url") and not plan.target_url:
            return ProviderSupportDecision(
                supported=False,
                reason_codes=["SURFACE_NOT_SUPPORTED"],
            )
        location = str(endpoint.get("parameter_location", "")).lower()
        name = endpoint.get("parameter_name")
        if not location or not name:
            return ProviderSupportDecision(
                supported=False,
                reason_codes=["PLAN_NOT_SUPPORTED"],
            )
        if location not in _SUPPORTED_INPUT_LOCATIONS:
            return ProviderSupportDecision(
                supported=False,
                reason_codes=["PLAN_NOT_SUPPORTED"],
            )
        applicability = str(endpoint.get("applicability_state", "")).upper()
        if applicability and applicability not in {
            ApplicabilityState.APPLICABLE.value,
            ApplicabilityState.POSSIBLY_APPLICABLE.value,
        }:
            return ProviderSupportDecision(
                supported=False,
                reason_codes=["PLAN_NOT_SUPPORTED"],
            )
        if not self._validator._targets_sqli(plan.class_codes):
            return ProviderSupportDecision(
                supported=False,
                reason_codes=["PLAN_NOT_SUPPORTED"],
            )
        return ProviderSupportDecision(supported=True)

    async def execute(self, context: ProviderExecutionContext) -> ProviderExecutionResult:
        plan = context.plan
        endpoint = plan.endpoint_context or {}
        target_url = endpoint.get("url") or plan.target_url or ""
        outcome = await self._validator.validate(
            target_url=target_url,
            tags=["sqli"],
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
