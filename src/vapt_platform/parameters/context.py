"""Operational context for adaptive parameter selection."""

from dataclasses import dataclass, field
from typing import Any


@dataclass
class OperationalContext:
    """Evidence-derived facts that drive tool parameter selection."""

    execution_profile: str = "STANDARD"
    capability: str | None = None
    # Network / transport
    waf_detected: bool = False
    firewall_inferred: bool = False
    icmp_blocked: bool = False
    filtered_ports_observed: bool = False
    proxy_arp_suspected: bool = False
    local_network_target: bool = False
    cdn_detected: bool = False
    # HTTP behavior
    rate_limited: bool = False
    auth_required: bool = False
    tls_enforced: bool = False
    http_only_service: bool = False
    # DNS
    wildcard_dns_suspected: bool = False
    inconclusive_dns: bool = False
    # Discovery yield
    low_subdomain_gain: bool = False
    large_target_set: bool = False
    cidr_scope: bool = False
    # API / cloud
    api_surface_detected: bool = False
    cloud_asset_candidate: bool = False
    graphql_endpoint: bool = False
    # Execution history
    previous_timeouts: int = 0
    passive_only: bool = False
    reason_codes: list[str] = field(default_factory=list)
    asset_metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_target(
        cls,
        target: dict[str, Any],
        profile: str,
        capability: str | None = None,
    ) -> "OperationalContext":
        op = target.get("operational_context", {})
        meta = target.get("asset_metadata", {})
        passive = profile == "PASSIVE_ONLY" or bool(op.get("passive_only"))
        return cls(
            execution_profile=profile,
            capability=capability,
            waf_detected=bool(op.get("waf_detected") or meta.get("waf_detected")),
            firewall_inferred=bool(op.get("firewall_inferred") or meta.get("firewall_inferred")),
            icmp_blocked=bool(op.get("icmp_blocked")),
            filtered_ports_observed=bool(op.get("filtered_ports_observed")),
            proxy_arp_suspected=bool(op.get("proxy_arp_suspected")),
            local_network_target=bool(op.get("local_network_target") or meta.get("local_network")),
            cdn_detected=bool(op.get("cdn_detected") or meta.get("cdn")),
            rate_limited=bool(op.get("rate_limited")),
            auth_required=bool(
                op.get("auth_required")
                or meta.get("auth_required")
                or target.get("username")
                or target.get("password")
                or target.get("basic_auth_token")
            ),
            tls_enforced=bool(op.get("tls_enforced") or meta.get("tls_enforced")),
            http_only_service=bool(op.get("http_only_service")),
            wildcard_dns_suspected=bool(op.get("wildcard_dns_suspected")),
            inconclusive_dns=bool(op.get("inconclusive_dns")),
            low_subdomain_gain=bool(op.get("low_subdomain_gain")),
            large_target_set=bool(op.get("large_target_set") or meta.get("large_target_set")),
            cidr_scope=bool(op.get("cidr_scope") or target.get("cidr")),
            api_surface_detected=bool(op.get("api_surface_detected") or meta.get("api")),
            cloud_asset_candidate=bool(op.get("cloud_asset_candidate")),
            graphql_endpoint=bool(op.get("graphql_endpoint") or meta.get("graphql")),
            previous_timeouts=int(op.get("previous_timeouts", 0)),
            passive_only=passive,
            reason_codes=list(op.get("reason_codes", [])),
            asset_metadata=meta,
        )

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in self.__dict__.items() if k != "asset_metadata"}
