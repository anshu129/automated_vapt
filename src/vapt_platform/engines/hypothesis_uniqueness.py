"""Deterministic hypothesis uniqueness keys (Phase 4)."""

from __future__ import annotations

import hashlib
from typing import Any


def hypothesis_uniqueness_key(
    *,
    hypothesis_type: str,
    vulnerability_class: str,
    asset_ids: list[str],
    surface_ids: list[str] | None = None,
    relationship_ids: list[str] | None = None,
    scope_dimension: str = "",
    role_context: str = "",
    auth_context: str = "",
    rule_id: str = "",
    endpoint_ref: str = "",
    parameter_name: str = "",
) -> str:
    parts = [
        hypothesis_type,
        vulnerability_class,
        "|".join(sorted(asset_ids)),
        "|".join(sorted(surface_ids or [])),
        "|".join(sorted(relationship_ids or [])),
        scope_dimension,
        role_context,
        auth_context,
        rule_id,
        endpoint_ref,
        parameter_name,
    ]
    return hashlib.sha256("|".join(parts).encode()).hexdigest()
