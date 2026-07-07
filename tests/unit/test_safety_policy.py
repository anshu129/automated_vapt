"""Unit tests for SafetyPolicy."""

from vapt_platform.config.settings import Settings
from vapt_platform.domain.enums import SafetyClass
from vapt_platform.engines.safety_policy import SafetyPolicy


def test_passive_allowed_in_scope() -> None:
    decision = SafetyPolicy().evaluate(
        plan_safety_class=SafetyClass.PASSIVE.value,
        requirement_safety_class=None,
        provider_default_safety=SafetyClass.PASSIVE.value,
    )
    assert decision.allowed


def test_low_impact_obey_engagement_policy() -> None:
    settings = Settings(engagement_allow_state_changing=False)
    policy = SafetyPolicy(settings)
    blocked = policy.evaluate(
        plan_safety_class=SafetyClass.LOW_IMPACT.value,
        requirement_safety_class=None,
        provider_default_safety=SafetyClass.LOW_IMPACT.value,
        engagement_allows_low_impact=False,
    )
    assert not blocked.allowed
    allowed = policy.evaluate(
        plan_safety_class=SafetyClass.LOW_IMPACT.value,
        requirement_safety_class=None,
        provider_default_safety=SafetyClass.LOW_IMPACT.value,
        engagement_allows_low_impact=True,
    )
    assert allowed.allowed


def test_state_changing_requires_approval() -> None:
    decision = SafetyPolicy().evaluate(
        plan_safety_class=SafetyClass.STATE_CHANGING.value,
        requirement_safety_class=None,
        provider_default_safety=SafetyClass.STATE_CHANGING.value,
    )
    assert not decision.allowed
    assert decision.requires_manual_approval


def test_destructive_rejected() -> None:
    decision = SafetyPolicy().evaluate(
        plan_safety_class=SafetyClass.DESTRUCTIVE.value,
        requirement_safety_class=None,
        provider_default_safety=SafetyClass.DESTRUCTIVE.value,
    )
    assert not decision.allowed


def test_prohibited_rejected() -> None:
    decision = SafetyPolicy().evaluate(
        plan_safety_class=SafetyClass.PROHIBITED.value,
        requirement_safety_class=None,
        provider_default_safety=SafetyClass.PROHIBITED.value,
    )
    assert not decision.allowed
