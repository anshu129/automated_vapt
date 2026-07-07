"""Capability provider protocol and routing context models (Phase 2)."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Protocol, runtime_checkable

from vapt_platform.domain.enums import Capability


class RoutingErrorCode(StrEnum):
    NO_PROVIDER_FOR_CAPABILITY = "NO_PROVIDER_FOR_CAPABILITY"
    PROVIDER_UNAVAILABLE = "PROVIDER_UNAVAILABLE"
    SURFACE_NOT_SUPPORTED = "SURFACE_NOT_SUPPORTED"
    SAFETY_POLICY_REJECTED = "SAFETY_POLICY_REJECTED"
    AUTHORIZATION_POLICY_REJECTED = "AUTHORIZATION_POLICY_REJECTED"
    CREDENTIAL_CONTEXT_REQUIRED = "CREDENTIAL_CONTEXT_REQUIRED"
    CREDENTIAL_CONTEXT_INCOMPATIBLE = "CREDENTIAL_CONTEXT_INCOMPATIBLE"
    PROVIDER_EXECUTION_FAILED = "PROVIDER_EXECUTION_FAILED"
    INVALID_TEST_PLAN = "INVALID_TEST_PLAN"
    INVALID_TEST_REQUIREMENT = "INVALID_TEST_REQUIREMENT"
    CAPABILITY_NOT_DECLARED = "CAPABILITY_NOT_DECLARED"


class ProviderRejectionReason(StrEnum):
    CAPABILITY_NOT_DECLARED = "CAPABILITY_NOT_DECLARED"
    PROVIDER_UNAVAILABLE = "PROVIDER_UNAVAILABLE"
    SURFACE_NOT_SUPPORTED = "SURFACE_NOT_SUPPORTED"
    SAFETY_POLICY_REJECTED = "SAFETY_POLICY_REJECTED"
    AUTHORIZATION_POLICY_REJECTED = "AUTHORIZATION_POLICY_REJECTED"
    CREDENTIAL_INCOMPATIBLE = "CREDENTIAL_INCOMPATIBLE"
    PLAN_NOT_SUPPORTED = "PLAN_NOT_SUPPORTED"
    COVERAGE_ALREADY_COMPLETE = "COVERAGE_ALREADY_COMPLETE"


class ProviderExecutionMode(StrEnum):
    LOCAL_PROCESS = "LOCAL_PROCESS"
    MCP = "MCP"
    IMPORT_ONLY = "IMPORT_ONLY"


@dataclass(frozen=True)
class ProviderMetadata:
    provider_id: str
    display_name: str
    declared_capabilities: tuple[str, ...]
    supported_asset_types: tuple[str, ...]
    supported_surface_types: tuple[str, ...]
    supported_authentication_types: tuple[str, ...]
    default_safety_class: str
    execution_mode: str
    priority: int = 100


@dataclass
class ProviderAvailabilityContext:
    scan_id: str
    active_validation_allowed: bool = False


@dataclass
class ProviderAvailabilityResult:
    available: bool
    reason_codes: list[str] = field(default_factory=list)


@dataclass
class TestPlanContext:
    scan_id: str
    test_plan_id: str
    asset_ids: list[str]
    vulnerability_class_ids: list[str]
    class_codes: list[str]
    required_capabilities: list[str]
    testing_mode: str
    safety_class: str
    authorization_requirement: str
    target_url: str | None
    asset_type: str | None
    credential_requirement: str | None = None
    requirement_id: str | None = None
    endpoint_context: dict[str, Any] = field(default_factory=dict)
    active_validation_allowed: bool = False
    username: str | None = None
    password: str | None = None


@dataclass
class ProviderSupportDecision:
    supported: bool
    reason_codes: list[str] = field(default_factory=list)


@dataclass
class ProviderExecutionContext:
    plan: TestPlanContext
    capability: str
    provider_id: str


@dataclass
class ProviderExecutionResult:
    provider_id: str
    capability: str
    status: str
    detail: str | None = None
    findings: list[dict[str, Any]] = field(default_factory=list)
    redacted_command: str | None = None
    error_code: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class RoutedExecutionResult:
    scan_id: str
    test_plan_id: str
    required_capability: str | None
    selected_provider: str | None
    status: str
    decision_id: str | None = None
    execution_id: str | None = None
    error_codes: list[str] = field(default_factory=list)
    detail: str | None = None


@runtime_checkable
class CapabilityProvider(Protocol):
    @property
    def provider_id(self) -> str: ...

    def metadata(self) -> ProviderMetadata: ...

    def declared_capabilities(self) -> set[Capability]: ...

    def is_available(self, context: ProviderAvailabilityContext) -> ProviderAvailabilityResult: ...

    def supports_plan(self, plan: TestPlanContext) -> ProviderSupportDecision: ...

    async def execute(self, context: ProviderExecutionContext) -> ProviderExecutionResult: ...
