"""TestRequirement uniqueness policy (Phase 7)."""

from __future__ import annotations

import logging
from typing import Any

from vapt_platform.domain.test_requirement_uniqueness import (
    RequirementScopeDimensions,
    ScopeGranularity,
    UniquenessDecision,
)
from vapt_platform.engines.test_requirement_uniqueness import build_test_requirement_uniqueness_key

logger = logging.getLogger(__name__)


class TestRequirementUniquenessPolicy:
    """Decides whether requirements are equivalent, mergeable, or distinct."""

    def build_identity(
        self,
        *,
        scan_id: str,
        asset_id: str,
        vulnerability_class: str,
        payload: dict[str, Any] | None = None,
    ) -> tuple[str, str, dict[str, str]]:
        dims = RequirementScopeDimensions.from_payload(
            payload or {},
            scan_id=scan_id,
            asset_id=asset_id,
        )
        if vulnerability_class:
            dims.vulnerability_class = vulnerability_class
        granularity = self.classify_granularity(dims)
        ukey = build_test_requirement_uniqueness_key(
            scan_id=dims.scan_id,
            asset_id=dims.asset_id,
            vulnerability_class=dims.vulnerability_class,
            capability_group=dims.capability_group,
            endpoint_ref=dims.endpoint_ref,
            parameter_name=dims.parameter_name,
            parameter_location=dims.parameter_location,
            auth_context_id=dims.auth_context_id,
            role_name=dims.role_name,
            validation_objective=dims.validation_objective,
        )
        return ukey, granularity, dims.to_dict()

    @staticmethod
    def classify_granularity(dims: RequirementScopeDimensions) -> str:
        if dims.parameter_name:
            return ScopeGranularity.PARAMETER.value
        if dims.role_name:
            return ScopeGranularity.ROLE.value
        if dims.auth_context_id:
            return ScopeGranularity.AUTH_CONTEXT.value
        if dims.endpoint_ref:
            return ScopeGranularity.ENDPOINT.value
        if dims.validation_objective:
            return ScopeGranularity.MIXED.value
        return ScopeGranularity.SURFACE.value

    def evaluate(
        self,
        *,
        existing_uniqueness_key: str,
        existing_granularity: str,
        new_uniqueness_key: str,
        new_granularity: str,
        phase7_enabled: bool,
    ) -> UniquenessDecision:
        if existing_uniqueness_key == new_uniqueness_key:
            return UniquenessDecision(
                equivalent=True,
                should_reuse_existing=True,
                reason="identical_uniqueness_key",
                scope_granularity=new_granularity,
            )

        if not phase7_enabled:
            return UniquenessDecision(
                mergeable=True,
                reason="legacy_merge_parameter_scopes",
                scope_granularity=existing_granularity or ScopeGranularity.MIXED.value,
            )

        if new_granularity == ScopeGranularity.PARAMETER.value:
            return UniquenessDecision(
                distinct=True,
                should_create_distinct_row=True,
                reason="parameter_scoped_distinct",
                scope_granularity=new_granularity,
            )

        if new_granularity == ScopeGranularity.ROLE.value:
            return UniquenessDecision(
                distinct=True,
                should_create_distinct_row=True,
                reason="role_scoped_distinct",
                scope_granularity=new_granularity,
            )

        if new_granularity == ScopeGranularity.AUTH_CONTEXT.value:
            return UniquenessDecision(
                distinct=True,
                should_create_distinct_row=True,
                reason="auth_context_scoped_distinct",
                scope_granularity=new_granularity,
            )

        if new_granularity == ScopeGranularity.ENDPOINT.value and existing_granularity in {
            ScopeGranularity.SURFACE.value,
            ScopeGranularity.MIXED.value,
            "",
        }:
            return UniquenessDecision(
                distinct=True,
                should_create_distinct_row=True,
                reason="endpoint_narrower_than_surface",
                scope_granularity=new_granularity,
            )

        return UniquenessDecision(
            mergeable=True,
            reason="broad_requirement_absorbs_narrow_scope",
            scope_granularity=existing_granularity or ScopeGranularity.MIXED.value,
        )

    def log_decision(
        self,
        *,
        scan_id: str,
        requirement_id: str | None,
        decision: UniquenessDecision,
        uniqueness_key: str,
    ) -> None:
        logger.info(
            "requirement_uniqueness_decision scan_id=%s requirement_id=%s "
            "scope_granularity=%s equivalent=%s mergeable=%s distinct=%s reason=%s "
            "content_hash_prefix=%s",
            scan_id,
            requirement_id,
            decision.scope_granularity,
            decision.equivalent,
            decision.mergeable,
            decision.distinct,
            decision.reason,
            uniqueness_key[:12],
        )
