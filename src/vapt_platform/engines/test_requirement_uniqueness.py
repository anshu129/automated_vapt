"""Deterministic TestRequirement uniqueness keys (Phase 4)."""

from __future__ import annotations

import hashlib
from typing import Any


def build_test_requirement_uniqueness_key(
    *,
    scan_id: str,
    asset_id: str,
    vulnerability_class: str,
    capability_group: str = "",
    endpoint_ref: str = "",
    parameter_name: str = "",
    parameter_location: str = "",
    auth_context_id: str = "",
    role_name: str = "",
    validation_objective: str = "",
) -> str:
    parts = [
        scan_id,
        asset_id,
        vulnerability_class,
        capability_group,
        endpoint_ref,
        parameter_name,
        parameter_location,
        auth_context_id,
        role_name,
        validation_objective,
    ]
    return hashlib.sha256("|".join(parts).encode()).hexdigest()


def scope_from_key_parts(**kwargs: Any) -> dict[str, Any]:
    return {k: v for k, v in kwargs.items() if v}
