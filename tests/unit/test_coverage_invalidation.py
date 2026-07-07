"""Coverage invalidation policy tests (Phase 4)."""

from vapt_platform.engines.coverage_invalidation_policy import (
    CoverageInvalidationPolicy,
    InvalidationAction,
)


def test_new_parameter_creates_additional_scope() -> None:
    decision = CoverageInvalidationPolicy().evaluate(
        change_category="PARAMETER_DISCOVERED",
        context={"dimension": "parameter"},
    )
    assert decision.action == InvalidationAction.CREATE_ADDITIONAL_SCOPE_REQUIREMENT.value


def test_new_endpoint_does_not_invalidate_unrelated() -> None:
    decision = CoverageInvalidationPolicy().evaluate(
        change_category="ENDPOINT_ADDED",
        context={},
    )
    assert decision.action == InvalidationAction.CREATE_ADDITIONAL_SCOPE_REQUIREMENT.value


def test_unrelated_change_keeps_valid() -> None:
    decision = CoverageInvalidationPolicy().evaluate(
        change_category="MINOR_METADATA",
        context={},
    )
    assert decision.action == InvalidationAction.KEEP_VALID.value
