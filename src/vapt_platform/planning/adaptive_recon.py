"""Adaptive reconnaissance planning — capability sequencing from events and surface state."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any

from vapt_platform.capabilities.matcher import CapabilityMatcher
from vapt_platform.domain.enums import Capability, EventType, ExecutionProfile
from vapt_platform.planning.port_scan import http_service_port, scheme_for_service
from vapt_platform.planning.targets import as_str, host_from_payload, url_from_payload


@dataclass
class CapabilityPlanItem:
    capability: Capability
    target: dict[str, Any]
    execution_profile: str = ExecutionProfile.STANDARD.value
    priority: int = 50
    reasoning_trace: dict[str, Any] = field(default_factory=dict)
    rule_ids: list[str] = field(default_factory=list)


# Event-driven baseline workflow (Phase B)
EVENT_CAPABILITIES: dict[str, list[Capability]] = {
    EventType.DOMAIN_ACCEPTED.value: [Capability.PASSIVE_SUBDOMAIN_DISCOVERY],
    EventType.HOSTNAME_DISCOVERED.value: [Capability.DNS_RESOLUTION],
    EventType.DNS_RESOLVED.value: [
        Capability.HTTP_PROBING,
        Capability.PORT_DISCOVERY,
    ],
    EventType.HTTP_SERVICE_CONFIRMED.value: [
        Capability.WAF_IDENTIFICATION,
        Capability.LIVE_CRAWLING,
    ],
    EventType.SERVICE_OBSERVED.value: [
        Capability.HTTP_PROBING,
    ],
    EventType.WEB_APPLICATION_CONFIRMED.value: [
        Capability.TEMPLATE_BASED_ASSESSMENT,
        Capability.PARAMETER_DISCOVERY,
        Capability.JAVASCRIPT_COLLECTION,
    ],
    EventType.ENDPOINT_DISCOVERED.value: [],
}


class AdaptiveReconPlanner:
    """
    Plans next capabilities from workflow events and surface completeness gaps.
    Deterministic: same inputs + rule versions → same plan.
    """

    def __init__(self, matcher: CapabilityMatcher | None = None) -> None:
        self.matcher = matcher or CapabilityMatcher()

    def plan_from_event(
        self,
        event_type: str,
        payload: dict[str, Any],
        *,
        scan_id: uuid.UUID | None = None,
        passive_only: bool = False,
    ) -> list[CapabilityPlanItem]:
        caps = list(EVENT_CAPABILITIES.get(event_type, []))
        if passive_only:
            caps = [c for c in caps if c in _PASSIVE_EVENT_CAPS]
        items: list[CapabilityPlanItem] = []
        for cap in caps:
            for target in self._targets_for_capability(cap, payload):
                items.append(
                    CapabilityPlanItem(
                        capability=cap,
                        target=target,
                        rule_ids=[f"workflow-{event_type.lower()}"],
                        reasoning_trace={
                            "trigger": event_type,
                            "capability": cap.value,
                            "scan_id": str(scan_id) if scan_id else None,
                        },
                    )
                )
        return items

    def plan_from_surface_gaps(
        self,
        dimensions: dict[str, str],
        base_target: dict[str, Any],
        *,
        scan_id: uuid.UUID | None = None,
        passive_only: bool = False,
    ) -> list[CapabilityPlanItem]:
        caps = self.matcher.capabilities_for_gaps(dimensions, passive_only=passive_only)
        items: list[CapabilityPlanItem] = []
        for cap in caps:
            items.append(
                CapabilityPlanItem(
                    capability=cap,
                    target=dict(base_target),
                    priority=40,
                    rule_ids=["surface-gap-fill"],
                    reasoning_trace={
                        "trigger": "SURFACE_GAP_IDENTIFIED",
                        "capability": cap.value,
                        "scan_id": str(scan_id) if scan_id else None,
                    },
                )
            )
        return items

    def _targets_for_capability(
        self,
        capability: Capability,
        payload: dict[str, Any],
    ) -> list[dict[str, Any]]:
        op_ctx = payload.get("operational_context", {})
        base: dict[str, Any] = {}
        if op_ctx:
            base["operational_context"] = op_ctx

        if capability in (
            Capability.PASSIVE_SUBDOMAIN_DISCOVERY,
            Capability.CERTIFICATE_TRANSPARENCY_DISCOVERY,
        ):
            return [{**base, "domain": payload.get("domain")}]
        if capability == Capability.DNS_RESOLUTION:
            return [{**base, "hostname": payload.get("hostname")}]
        if capability in (
            Capability.HTTP_PROBING,
            Capability.LIVE_CRAWLING,
            Capability.WAF_IDENTIFICATION,
            Capability.TLS_CHARACTERIZATION,
            Capability.PARAMETER_DISCOVERY,
            Capability.JAVASCRIPT_COLLECTION,
            Capability.HTTP_CHARACTERIZATION,
            Capability.TECHNOLOGY_IDENTIFICATION,
        ):
            if payload.get("type") == "SERVICE_OBSERVED":
                port = payload.get("port")
                service = payload.get("service")
                if not http_service_port(port, service):
                    return []
                host = host_from_payload(payload)
                scheme = scheme_for_service(service, port)
                try:
                    port_num = int(port)
                except (TypeError, ValueError):
                    port_num = 0
                if port_num in {80, 443}:
                    url = f"{scheme}://{host}"
                else:
                    url = f"{scheme}://{host}:{port_num}"
                target = {**base, "hostname": host, "url": url}
                ip = as_str(payload.get("ip"), "")
                if ip or _looks_like_ip(host):
                    target["ip"] = ip or host
                return [target]
            host = host_from_payload(payload)
            url = url_from_payload(payload)
            target = {**base, "hostname": host, "url": url}
            ip = as_str(payload.get("ip"), "")
            if ip or _looks_like_ip(host):
                target["ip"] = ip or host
            return [target]
        if capability in (Capability.PORT_DISCOVERY, Capability.SERVICE_IDENTIFICATION):
            host = payload.get("hostname", "")
            ip = payload.get("ip")
            if not ip and payload.get("records"):
                for rec in payload["records"]:
                    if rec.get("type") == "A":
                        ip = rec.get("value")
                        break
            return [{**base, "hostname": host, "ip": ip or host}]
        if capability == Capability.TEMPLATE_BASED_ASSESSMENT:
            return [{**base, "url": url_from_payload(payload)}]
        return [{**base, **payload}]


_PASSIVE_EVENT_CAPS = {
    Capability.PASSIVE_SUBDOMAIN_DISCOVERY,
    Capability.CERTIFICATE_TRANSPARENCY_DISCOVERY,
    Capability.HISTORICAL_URL_DISCOVERY,
}


def _looks_like_ip(value: str | None) -> bool:
    if not value:
        return False
    parts = value.split(".")
    if len(parts) != 4:
        return False
    return all(part.isdigit() and 0 <= int(part) <= 255 for part in parts)
