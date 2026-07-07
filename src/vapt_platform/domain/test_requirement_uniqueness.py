"""TestRequirement scope and uniqueness domain types (Phase 7)."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class ScopeGranularity(StrEnum):
    SURFACE = "SURFACE"
    ENDPOINT = "ENDPOINT"
    PARAMETER = "PARAMETER"
    ROLE = "ROLE"
    AUTH_CONTEXT = "AUTH_CONTEXT"
    MIXED = "MIXED"


@dataclass
class RequirementScopeDimensions:
    scan_id: str = ""
    asset_id: str = ""
    vulnerability_class: str = ""
    capability_group: str = ""
    endpoint_ref: str = ""
    parameter_name: str = ""
    parameter_location: str = ""
    auth_context_id: str = ""
    role_name: str = ""
    validation_objective: str = ""

    @classmethod
    def from_payload(cls, payload: dict[str, Any], *, scan_id: str, asset_id: str) -> RequirementScopeDimensions:
        return cls(
            scan_id=scan_id,
            asset_id=asset_id,
            vulnerability_class=str(payload.get("vulnerability_class") or payload.get("class_code") or ""),
            capability_group=str(payload.get("capability_group") or ""),
            endpoint_ref=str(payload.get("endpoint_ref") or ""),
            parameter_name=str(payload.get("parameter_name") or ""),
            parameter_location=str(payload.get("parameter_location") or ""),
            auth_context_id=str(payload.get("auth_context_id") or ""),
            role_name=str(payload.get("role_name") or ""),
            validation_objective=str(payload.get("validation_objective") or ""),
        )

    def to_dict(self) -> dict[str, str]:
        return {
            "scan_id": self.scan_id,
            "asset_id": self.asset_id,
            "vulnerability_class": self.vulnerability_class,
            "capability_group": self.capability_group,
            "endpoint_ref": self.endpoint_ref,
            "parameter_name": self.parameter_name,
            "parameter_location": self.parameter_location,
            "auth_context_id": self.auth_context_id,
            "role_name": self.role_name,
            "validation_objective": self.validation_objective,
        }


@dataclass
class UniquenessDecision:
    equivalent: bool = False
    mergeable: bool = False
    distinct: bool = False
    should_create_distinct_row: bool = False
    should_reuse_existing: bool = False
    reason: str = ""
    scope_granularity: str = ScopeGranularity.SURFACE.value


@dataclass
class RequirementIdentity:
    uniqueness_key: str
    scope_granularity: str
    scope_dimensions: dict[str, Any] = field(default_factory=dict)
    is_legacy_merged: bool = False
