"""Tests for explainable parameter selection."""

from vapt_platform.parameters.context import OperationalContext
from vapt_platform.parameters.engine import ParameterSelectionEngine
from vapt_platform.parameters.references import (
    load_parameter_references,
    parameter_count,
)
from vapt_platform.tools.manifest import load_tool_manifests


def test_nmap_disable_arp_ping_when_firewall_inferred() -> None:
    engine = ParameterSelectionEngine()
    ctx = OperationalContext(
        execution_profile="STANDARD",
        capability="PORT_DISCOVERY",
        firewall_inferred=True,
    )
    decision = engine.derive(
        "nmap",
        ["-sV", "-p", "80,443", "{target}"],
        {"hostname": "app.example.com", "ip": "10.0.0.1"},
        ctx,
    )
    assert "--disable-arp-ping" in decision.added_args
    assert "param-nmap-disable-arp-ping-firewall" in decision.rule_ids
    assert decision.reference_doc is not None


def test_nmap_proxy_arp_disable_arp_ping() -> None:
    engine = ParameterSelectionEngine()
    ctx = OperationalContext(proxy_arp_suspected=True, local_network_target=True)
    decision = engine.derive("nmap", ["-sV"], {"ip": "192.168.1.10"}, ctx)
    assert "--disable-arp-ping" in decision.added_args
    assert "param-nmap-disable-arp-ping-proxy-arp" in decision.rule_ids


def test_nmap_skip_ping_when_icmp_blocked() -> None:
    engine = ParameterSelectionEngine()
    ctx = OperationalContext(icmp_blocked=True, firewall_inferred=True)
    decision = engine.derive("nmap", ["-sV"], {"ip": "203.0.113.5"}, ctx)
    assert "-Pn" in decision.added_args
    assert "param-nmap-skip-ping-icmp" in decision.rule_ids


def test_httpx_rate_limit_when_throttled() -> None:
    engine = ParameterSelectionEngine()
    ctx = OperationalContext(rate_limited=True)
    decision = engine.derive(
        "httpx",
        ["-silent", "-json"],
        {"hostname": "api.example.com"},
        ctx,
    )
    assert "-rate-limit" in decision.added_args
    assert "50" in decision.final_args


def test_no_rules_without_matching_context() -> None:
    engine = ParameterSelectionEngine()
    ctx = OperationalContext()
    decision = engine.derive("nmap", ["-sV"], {"ip": "1.2.3.4"}, ctx)
    assert decision.added_args == []
    assert decision.rule_ids == []


def test_all_manifest_tools_have_parameter_references() -> None:
    manifests = load_tool_manifests()
    references = load_parameter_references()
    missing = sorted(set(manifests) - set(references))
    assert not missing, f"Tools missing parameter references: {missing}"


def test_each_reference_has_docs_and_parameters() -> None:
    references = load_parameter_references()
    for name, spec in references.items():
        assert spec.get("official_docs"), f"{name} missing official_docs"
        assert parameter_count(spec) > 0, f"{name} missing parameters"
        assert spec.get("summary"), f"{name} missing summary"


def test_nmap_full_catalog_coverage() -> None:
    spec = load_parameter_references()["nmap"]
    assert spec.get("parameter_groups"), "nmap should use full parameter_groups catalog"
    assert spec.get("usage")
    assert parameter_count(spec) >= 100, "nmap catalog should document 100+ flags/options"
    group_ids = {g["id"] for g in spec["parameter_groups"]}
    for required in (
        "TARGET_SPECIFICATION",
        "HOST_DISCOVERY",
        "SCAN_TECHNIQUES",
        "PORT_SPECIFICATION",
        "SERVICE_VERSION",
        "TIMING_PERFORMANCE",
        "OUTPUT",
    ):
        assert required in group_ids, f"nmap missing group {required}"
