"""Shared helpers for port-scan observations and HTTP service targeting."""

from __future__ import annotations

from typing import Any


def http_service_port(port: Any, service: str | None) -> bool:
    try:
        port_num = int(port)
    except (TypeError, ValueError):
        return False
    svc = (service or "").lower()
    if svc in {"http", "https", "ssl/http", "http-alt", "http-proxy", "www", "www-http"}:
        return True
    return port_num in {80, 443, 8080, 8443, 8000, 8888}


def scheme_for_service(service: str | None, port: Any) -> str:
    try:
        port_num = int(port)
    except (TypeError, ValueError):
        port_num = 0
    svc = (service or "").lower()
    if port_num == 443 or svc == "https" or "ssl" in svc:
        return "https"
    return "http"


def apply_port_scan_metadata(
    metadata: dict[str, Any] | None,
    payload: dict[str, Any],
) -> dict[str, Any]:
    """Merge port-scan observations into asset metadata (always returns a new dict)."""
    meta = dict(metadata or {})
    meta["ports_discovered"] = True
    meta["services_identified"] = True
    port = payload.get("port")
    meta["last_observed_port"] = port
    if not port:
        return meta
    services = {
        (str(svc.get("port")), str(svc.get("protocol") or "tcp")): svc
        for svc in meta.get("services", [])
        if isinstance(svc, dict)
    }
    services[(str(port), str(payload.get("protocol") or "tcp"))] = {
        "port": port,
        "protocol": payload.get("protocol") or "tcp",
        "service": payload.get("service"),
        "product": payload.get("product"),
        "version": payload.get("version"),
        "source": payload.get("source"),
    }
    meta["services"] = sorted(
        services.values(), key=lambda s: (int(s["port"]) if str(s["port"]).isdigit() else 0)
    )
    meta["open_ports"] = sorted(
        {int(s["port"]) for s in meta["services"] if str(s["port"]).isdigit()}
    )
    return meta
