"""Hypothesis and requirement uniqueness tests (Phase 4)."""

from vapt_platform.engines.hypothesis_uniqueness import hypothesis_uniqueness_key
from vapt_platform.engines.test_requirement_uniqueness import build_test_requirement_uniqueness_key


def test_same_facts_same_scope_same_key() -> None:
    a = hypothesis_uniqueness_key(
        hypothesis_type="INJECTION_CLASS",
        vulnerability_class="INJECTION_CLASS",
        asset_ids=["a1"],
        endpoint_ref="/api/orders",
        parameter_name="id",
        rule_id="CORR-PARAM-001",
    )
    b = hypothesis_uniqueness_key(
        hypothesis_type="INJECTION_CLASS",
        vulnerability_class="INJECTION_CLASS",
        asset_ids=["a1"],
        endpoint_ref="/api/orders",
        parameter_name="id",
        rule_id="CORR-PARAM-001",
    )
    assert a == b


def test_different_endpoint_distinct_key() -> None:
    a = hypothesis_uniqueness_key(
        hypothesis_type="AUTHORIZATION",
        vulnerability_class="AUTHORIZATION",
        asset_ids=["a1"],
        endpoint_ref="/api/orders",
        rule_id="CORR-AUTH-001",
    )
    b = hypothesis_uniqueness_key(
        hypothesis_type="AUTHORIZATION",
        vulnerability_class="AUTHORIZATION",
        asset_ids=["a1"],
        endpoint_ref="/api/invoices",
        rule_id="CORR-AUTH-001",
    )
    assert a != b


def test_different_parameter_distinct_requirement_key() -> None:
    a = build_test_requirement_uniqueness_key(
        scan_id="s1",
        asset_id="a1",
        vulnerability_class="INJECTION_CLASS",
        endpoint_ref="/search",
        parameter_name="id",
    )
    b = build_test_requirement_uniqueness_key(
        scan_id="s1",
        asset_id="a1",
        vulnerability_class="INJECTION_CLASS",
        endpoint_ref="/search",
        parameter_name="q",
    )
    assert a != b
