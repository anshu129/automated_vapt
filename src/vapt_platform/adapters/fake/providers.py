"""Fake tool adapters for development and testing."""

import json
from dataclasses import dataclass
from typing import Any

from vapt_platform.domain.enums import Capability


@dataclass
class AdapterOutput:
    stdout: str
    exit_code: int
    observations: list[dict[str, Any]]
    events: list[dict[str, Any]]


class FakeAdapter:
    capability: Capability
    provider_name: str
    behavior: str

    def __init__(self, capability: Capability, provider_name: str, behavior: str) -> None:
        self.capability = capability
        self.provider_name = provider_name
        self.behavior = behavior

    def execute(self, target: dict[str, Any], profile: str = "STANDARD") -> AdapterOutput:
        hostname = (
            target.get("hostname")
            or target.get("ip")
            or target.get("domain", "unknown.example.com")
        )
        if self.behavior == "subfinder":
            return AdapterOutput(
                stdout=json.dumps({"hosts": [f"www.{hostname}", f"api.{hostname}"]}),
                exit_code=0,
                observations=[],
                events=[
                    {
                        "type": "HOSTNAME_DISCOVERED",
                        "hostname": f"www.{hostname}",
                        "source": self.provider_name,
                    },
                    {
                        "type": "HOSTNAME_DISCOVERED",
                        "hostname": f"api.{hostname}",
                        "source": self.provider_name,
                    },
                ],
            )
        if self.behavior == "dns_silent":
            return AdapterOutput(
                stdout="",
                exit_code=0,
                observations=[],
                events=[],
            )
        if self.behavior == "dns_resolve":
            return AdapterOutput(
                stdout=json.dumps({"A": ["93.184.216.34"]}),
                exit_code=0,
                observations=[],
                events=[
                    {
                        "type": "DNS_RESOLVED",
                        "hostname": hostname,
                        "records": [{"type": "A", "value": "93.184.216.34"}],
                    }
                ],
            )
        if self.behavior == "httpx":
            url = target.get("url") or f"https://{hostname}"
            return AdapterOutput(
                stdout=json.dumps({"url": url, "status": 200}),
                exit_code=0,
                observations=[],
                events=[
                    {"type": "HTTP_SERVICE_CONFIRMED", "url": url, "status_code": 200},
                    {"type": "WEB_APPLICATION_CONFIRMED", "base_url": url, "title": "Example App"},
                    {"type": "TECHNOLOGY_OBSERVED", "technology": "nginx", "version": "1.18"},
                ],
            )
        if self.behavior == "katana":
            base = target.get("url") or f"https://{hostname}"
            return AdapterOutput(
                stdout="",
                exit_code=0,
                observations=[],
                events=[
                    {"type": "ENDPOINT_DISCOVERED", "url": f"{base}/login", "method": "GET"},
                    {"type": "ENDPOINT_DISCOVERED", "url": f"{base}/api/users", "method": "GET"},
                    {"type": "JAVASCRIPT_DISCOVERED", "url": f"{base}/static/app.js"},
                ],
            )
        if self.behavior == "nuclei":
            return AdapterOutput(
                stdout=json.dumps({"findings": [{"template": "missing-hsts", "severity": "low"}]}),
                exit_code=0,
                observations=[{"type": "SCANNER_OBSERVATION", "template": "missing-hsts"}],
                events=[],
            )
        if self.behavior == "naabu":
            return AdapterOutput(
                stdout=json.dumps({"host": hostname, "port": 443}),
                exit_code=0,
                observations=[],
                events=[
                    {
                        "type": "SERVICE_OBSERVED",
                        "host": hostname,
                        "port": 443,
                        "protocol": "tcp",
                    }
                ],
            )
        if self.behavior == "wafw00f":
            return AdapterOutput(
                stdout="The site is behind Cloudflare WAF",
                exit_code=0,
                observations=[
                    {
                        "type": "OPERATIONAL_OBSERVATION",
                        "waf_detected": True,
                        "firewall_inferred": True,
                    }
                ],
                events=[],
            )
        if self.behavior in ("paramspider", "noop"):
            return AdapterOutput(stdout="", exit_code=0, observations=[], events=[])
        return AdapterOutput(stdout="", exit_code=0, observations=[], events=[])


FAKE_ADAPTERS: dict[str, FakeAdapter] = {
    "fake-subfinder": FakeAdapter(
        Capability.PASSIVE_SUBDOMAIN_DISCOVERY, "fake-subfinder", "subfinder"
    ),
    "fake-dnsx-silent": FakeAdapter(Capability.DNS_RESOLUTION, "fake-dnsx-silent", "dns_silent"),
    "fake-dnsx-resolve": FakeAdapter(Capability.DNS_RESOLUTION, "fake-dnsx-resolve", "dns_resolve"),
    "fake-httpx": FakeAdapter(Capability.HTTP_PROBING, "fake-httpx", "httpx"),
    "fake-katana": FakeAdapter(Capability.LIVE_CRAWLING, "fake-katana", "katana"),
    "fake-nuclei": FakeAdapter(Capability.TEMPLATE_BASED_ASSESSMENT, "fake-nuclei", "nuclei"),
    "fake-naabu": FakeAdapter(Capability.PORT_DISCOVERY, "fake-naabu", "naabu"),
    "fake-wafw00f": FakeAdapter(Capability.WAF_IDENTIFICATION, "fake-wafw00f", "wafw00f"),
    "fake-paramspider": FakeAdapter(
        Capability.PARAMETER_DISCOVERY, "fake-paramspider", "paramspider"
    ),
    "fake-js-collect": FakeAdapter(Capability.JAVASCRIPT_COLLECTION, "fake-js-collect", "noop"),
}


def get_fake_adapter(provider_name: str) -> FakeAdapter | None:
    return FAKE_ADAPTERS.get(provider_name)
