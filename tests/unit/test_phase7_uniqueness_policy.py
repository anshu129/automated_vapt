"""Phase 7 uniqueness policy unit tests."""

from __future__ import annotations

from vapt_platform.domain.test_requirement_uniqueness import ScopeGranularity
from vapt_platform.engines.test_requirement_uniqueness import build_test_requirement_uniqueness_key
from vapt_platform.services.requirement_uniqueness_policy import TestRequirementUniquenessPolicy


def test_equivalent_requirements_same_key() -> None:
    policy = TestRequirementUniquenessPolicy()
    a, ga, _ = policy.build_identity(
        scan_id="s1",
        asset_id="a1",
        vulnerability_class="INJECTION_CLASS",
        payload={"endpoint_ref": "/search", "parameter_name": "id"},
    )
    b, gb, _ = policy.build_identity(
        scan_id="s1",
        asset_id="a1",
        vulnerability_class="INJECTION_CLASS",
        payload={"endpoint_ref": "/search", "parameter_name": "id"},
    )
    assert a == b
    assert ga == ScopeGranularity.PARAMETER.value
    decision = policy.evaluate(
        existing_uniqueness_key=a,
        existing_granularity=ga,
        new_uniqueness_key=b,
        new_granularity=gb,
        phase7_enabled=True,
    )
    assert decision.equivalent
    assert decision.should_reuse_existing


def test_distinct_parameters_not_merged_when_phase7() -> None:
    policy = TestRequirementUniquenessPolicy()
    base_key = build_test_requirement_uniqueness_key(
        scan_id="s1",
        asset_id="a1",
        vulnerability_class="INJECTION_CLASS",
        endpoint_ref="/search",
    )
    param_key = build_test_requirement_uniqueness_key(
        scan_id="s1",
        asset_id="a1",
        vulnerability_class="INJECTION_CLASS",
        endpoint_ref="/search",
        parameter_name="q",
    )
    decision = policy.evaluate(
        existing_uniqueness_key=base_key,
        existing_granularity=ScopeGranularity.ENDPOINT.value,
        new_uniqueness_key=param_key,
        new_granularity=ScopeGranularity.PARAMETER.value,
        phase7_enabled=True,
    )
    assert decision.should_create_distinct_row
    assert decision.distinct


def test_legacy_merge_when_phase7_disabled() -> None:
    policy = TestRequirementUniquenessPolicy()
    decision = policy.evaluate(
        existing_uniqueness_key="a",
        existing_granularity=ScopeGranularity.SURFACE.value,
        new_uniqueness_key="b",
        new_granularity=ScopeGranularity.PARAMETER.value,
        phase7_enabled=False,
    )
    assert decision.mergeable
    assert not decision.should_create_distinct_row


def test_classify_granularity_role_and_auth() -> None:
    policy = TestRequirementUniquenessPolicy()
    _, role_g, _ = policy.build_identity(
        scan_id="s1",
        asset_id="a1",
        vulnerability_class="AUTHORIZATION",
        payload={"role_name": "admin"},
    )
    _, auth_g, _ = policy.build_identity(
        scan_id="s1",
        asset_id="a1",
        vulnerability_class="AUTHORIZATION",
        payload={"auth_context_id": "ctx-1"},
    )
    assert role_g == ScopeGranularity.ROLE.value
    assert auth_g == ScopeGranularity.AUTH_CONTEXT.value
