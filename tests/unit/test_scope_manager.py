"""Scope manager tests."""

import uuid

import pytest

from vapt_platform.domain.enums import Capability
from vapt_platform.domain.exceptions import ScopeDeniedError
from vapt_platform.scope.manager import ScopeManager, ScopeRuleData, TargetDescriptor


@pytest.fixture
def scope_manager() -> ScopeManager:
    rules = [
        ScopeRuleData("ROOT_DOMAIN", "example.com", "ACTIVE", 100),
        ScopeRuleData("EXCLUSION", "secret.example.com", "ACTIVE", 200),
    ]
    return ScopeManager(rules)


def test_allow_in_scope(scope_manager: ScopeManager) -> None:
    target = TargetDescriptor(hostname="www.example.com")
    decision = scope_manager.evaluate(target, Capability.DNS_RESOLUTION)
    assert decision.allowed


def test_deny_out_of_scope(scope_manager: ScopeManager) -> None:
    target = TargetDescriptor(hostname="www.other.com")
    decision = scope_manager.evaluate(target, Capability.DNS_RESOLUTION)
    assert not decision.allowed


def test_exclusion_denies(scope_manager: ScopeManager) -> None:
    target = TargetDescriptor(hostname="secret.example.com")
    decision = scope_manager.evaluate(target, Capability.DNS_RESOLUTION)
    assert not decision.allowed


def test_assert_allowed_raises(scope_manager: ScopeManager) -> None:
    with pytest.raises(ScopeDeniedError):
        scope_manager.assert_allowed(
            TargetDescriptor(hostname="evil.com"), Capability.DNS_RESOLUTION
        )


def test_task_uniqueness_key_stable() -> None:
    from vapt_platform.scope.manager import task_uniqueness_key

    sid = uuid.uuid4()
    k1 = task_uniqueness_key(sid, "DNS_RESOLUTION", "www.example.com")
    k2 = task_uniqueness_key(sid, "DNS_RESOLUTION", "www.example.com")
    assert k1 == k2
