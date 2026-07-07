"""Parse tool output into observations and events."""

import json
from typing import Any


def parse_tool_output(
    provider_name: str,
    stdout: str,
    target: dict[str, Any],
) -> dict[str, list[dict[str, Any]]]:
    parser = PARSERS.get(provider_name, _parse_generic)
    return parser(stdout, target)


def _parse_subfinder(stdout: str, target: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    events = []
    for line in stdout.strip().splitlines():
        host = line.strip()
        if host and "." in host:
            events.append(
                {"type": "HOSTNAME_DISCOVERED", "hostname": host, "source": "subfinder"}
            )
    return {"events": events, "observations": []}


def _parse_crtsh(stdout: str, target: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    events = []
    seen: set[str] = set()
    try:
        rows = json.loads(stdout or "[]")
    except json.JSONDecodeError:
        rows = []
    for row in rows if isinstance(rows, list) else []:
        name_value = str(row.get("name_value") or row.get("common_name") or "")
        for host in name_value.replace("*.", "").splitlines():
            host = host.strip().lower()
            if host and "." in host and host not in seen:
                seen.add(host)
                events.append({"type": "HOSTNAME_DISCOVERED", "hostname": host, "source": "crtsh"})
    return {"events": events, "observations": []}


def _parse_dnsx(stdout: str, target: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    events = []
    hostname = target.get("hostname", "")
    for line in stdout.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
            host = rec.get("host", hostname)
            records = []
            for key in ("a", "aaaa", "cname"):
                for val in rec.get(key, []) or []:
                    records.append({"type": key.upper(), "value": val})
            if records:
                events.append({"type": "DNS_RESOLVED", "hostname": host, "records": records})
        except json.JSONDecodeError:
            if hostname:
                events.append(
                    {
                        "type": "DNS_RESOLVED",
                        "hostname": hostname,
                        "records": [{"type": "A", "value": line}],
                    }
                )
    return {"events": events, "observations": []}


def _parse_naabu(stdout: str, target: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    events = []
    fallback_host = target.get("hostname") or target.get("ip") or target.get("domain", "")
    for line in stdout.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
            host = rec.get("host") or rec.get("ip") or fallback_host
            port = rec.get("port")
        except json.JSONDecodeError:
            if ":" in line:
                host, _, port_raw = line.rpartition(":")
                port = int(port_raw) if port_raw.isdigit() else None
            else:
                host, port = fallback_host, None
        if host and port:
            events.append(
                {"type": "SERVICE_OBSERVED", "host": host, "ip": target.get("ip"), "port": port, "protocol": "tcp"}
            )
    return {"events": events, "observations": []}


def _parse_httpx(stdout: str, target: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    events = []
    observations = []
    for line in stdout.strip().splitlines():
        try:
            rec = json.loads(line)
            url = rec.get("url") or rec.get("input", target.get("url", ""))
            status = rec.get("status_code") or rec.get("status-code", 0)
            if url and status:
                events.append(
                    {"type": "HTTP_SERVICE_CONFIRMED", "url": url, "status_code": status}
                )
                events.append(
                    {
                        "type": "WEB_APPLICATION_CONFIRMED",
                        "base_url": url.split("/", 3)[0] + "//" + url.split("/")[2]
                        if "/" in url
                        else url,
                        "title": rec.get("title", ""),
                    }
                )
            tech = rec.get("tech") or rec.get("technologies") or []
            for t in tech:
                name = t if isinstance(t, str) else t.get("name", "")
                if name:
                    events.append(
                        {
                            "type": "TECHNOLOGY_OBSERVED",
                            "technology": name,
                            "version": "",
                        }
                    )
            if status == 429:
                observations.append(
                    {
                        "type": "OPERATIONAL_OBSERVATION",
                        "rate_limited": True,
                    }
                )
            cdn = rec.get("cdn") or rec.get("cdn_name")
            if cdn:
                observations.append(
                    {
                        "type": "OPERATIONAL_OBSERVATION",
                        "cdn_detected": True,
                    }
                )
        except json.JSONDecodeError:
            continue
    return {"events": events, "observations": observations}


def _parse_nmap(stdout: str, target: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    events = []
    observations = []
    if "filtered" in stdout.lower():
        observations.append(
            {
                "type": "OPERATIONAL_OBSERVATION",
                "filtered_ports_observed": True,
                "firewall_inferred": True,
            }
        )
    lower = stdout.lower()
    if "host down" in lower or "0 hosts up" in lower:
        observations.append(
            {
                "type": "OPERATIONAL_OBSERVATION",
                "icmp_blocked": True,
            }
        )
    if "arp" in lower and ("proxy" in lower or "all hosts up" in lower):
        observations.append(
            {
                "type": "OPERATIONAL_OBSERVATION",
                "proxy_arp_suspected": True,
                "local_network_target": True,
            }
        )
    if "<host>" in stdout:
        events.append(
            {
                "type": "SERVICE_OBSERVED",
                "host": target.get("hostname") or target.get("ip", ""),
                "port": 443,
                "protocol": "tcp",
            }
        )
    return {"events": events, "observations": observations}


def _parse_katana(stdout: str, target: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    events = []
    for line in stdout.strip().splitlines():
        try:
            rec = json.loads(line)
            url = rec.get("request", {}).get("endpoint") or rec.get("url", "")
            if url:
                events.append({"type": "ENDPOINT_DISCOVERED", "url": url, "method": "GET"})
        except json.JSONDecodeError:
            if line.startswith("http"):
                events.append({"type": "ENDPOINT_DISCOVERED", "url": line.strip(), "method": "GET"})
    return {"events": events, "observations": []}


def _parse_url_lines(stdout: str, target: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    observations = []
    for line in stdout.strip().splitlines():
        url = line.strip()
        if url.startswith("http"):
            observations.append(
                {
                    "type": "HISTORICAL_OBSERVATION",
                    "url": url,
                    "requires_live_validation": True,
                }
            )
    return {"events": [], "observations": observations}


def _parse_url_utility(stdout: str, target: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    observations = [
        {"type": "URL_UTILITY_OBSERVATION", "value": line.strip()}
        for line in stdout.strip().splitlines()
        if line.strip()
    ]
    return {"events": [], "observations": observations}


def _parse_content_discovery(stdout: str, target: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    events = []
    observations = []
    for line in stdout.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        url = ""
        status = None
        try:
            rec = json.loads(line)
            url = (
                rec.get("url")
                or rec.get("input", {}).get("FUZZ")
                or rec.get("target")
                or rec.get("path")
                or ""
            )
            status = rec.get("status") or rec.get("status_code")
        except (json.JSONDecodeError, AttributeError):
            if line.startswith("http"):
                url = line.split()[0]
        if url.startswith("/"):
            base = target.get("url", "").rstrip("/")
            url = f"{base}{url}"
        if url.startswith("http"):
            events.append({"type": "ENDPOINT_DISCOVERED", "url": url, "method": "GET"})
            observations.append({"type": "CONTENT_DISCOVERY_OBSERVATION", "url": url, "status": status})
    return {"events": events, "observations": observations}


def _parse_arjun(stdout: str, target: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    observations = []
    try:
        data = json.loads(stdout or "{}")
    except json.JSONDecodeError:
        data = {}
    if isinstance(data, dict):
        for url, params in data.items():
            if isinstance(params, dict):
                params = params.get("params") or params.get("parameters") or []
            if isinstance(params, list):
                observations.append(
                    {"type": "PARAMETER_OBSERVATION", "url": url, "parameters": params}
                )
    for line in stdout.strip().splitlines():
        if "?" in line and "=" in line:
            observations.append({"type": "PARAMETER_OBSERVATION", "raw": line.strip()})
    return {"events": [], "observations": observations}


def _parse_secret_output(stdout: str, target: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    observations = []
    for line in stdout.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            rec = {"raw": line}
        observations.append({"type": "SECRET_INDICATOR_OBSERVATION", "payload": rec})
    return {"events": [], "observations": observations}


def _parse_wafw00f(stdout: str, target: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    observations = []
    if "is behind" in stdout.lower() or "waf" in stdout.lower():
        observations.append(
            {
                "type": "OPERATIONAL_OBSERVATION",
                "waf_detected": True,
                "firewall_inferred": True,
            }
        )
    return {
        "events": [],
        "observations": observations,
    }


def _parse_nuclei(stdout: str, target: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    observations = []
    for line in stdout.strip().splitlines():
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(record, dict):
            continue
        info = record.get("info") if isinstance(record.get("info"), dict) else {}
        observations.append(
            {
                "type": "SCANNER_OBSERVATION",
                "template_id": (
                    record.get("template-id")
                    or record.get("template_id")
                    or record.get("template")
                ),
                "name": info.get("name") or record.get("name"),
                "severity": info.get("severity") or record.get("severity"),
                "matched_at": (
                    record.get("matched-at")
                    or record.get("matched_at")
                    or record.get("host")
                ),
                "target": target.get("url"),
            }
        )
    return {"events": [], "observations": observations}


def _parse_generic(stdout: str, target: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    if not stdout.strip():
        return {"events": [], "observations": []}
    return {
        "events": [],
        "observations": [{"type": "RAW_TOOL_OUTPUT", "length": len(stdout)}],
    }


PARSERS: dict[str, Any] = {
    "subfinder": _parse_subfinder,
    "assetfinder": _parse_subfinder,
    "findomain": _parse_subfinder,
    "amass": _parse_subfinder,
    "crtsh": _parse_crtsh,
    "dnsx": _parse_dnsx,
    "puredns": _parse_dnsx,
    "altdns": _parse_subfinder,
    "dnsgen": _parse_subfinder,
    "httpx": _parse_httpx,
    "nmap": _parse_nmap,
    "naabu": _parse_naabu,
    "katana": _parse_katana,
    "gau": _parse_url_lines,
    "waybackurls": _parse_url_lines,
    "waymore": _parse_url_lines,
    "ffuf": _parse_content_discovery,
    "feroxbuster": _parse_content_discovery,
    "arjun": _parse_arjun,
    "paramspider": _parse_arjun,
    "unfurl": _parse_url_utility,
    "gf": _parse_url_utility,
    "qsreplace": _parse_url_utility,
    "trufflehog": _parse_secret_output,
    "gitleaks": _parse_secret_output,
    "wafw00f": _parse_wafw00f,
    "nuclei": _parse_nuclei,
    "fake-subfinder": _parse_subfinder,
    "fake-dnsx-resolve": _parse_dnsx,
    "fake-httpx": _parse_httpx,
    "fake-katana": _parse_katana,
    "fake-nuclei": _parse_nuclei,
}
