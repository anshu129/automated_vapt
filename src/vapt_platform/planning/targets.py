"""Normalize target/event string fields before URL parsing."""

from __future__ import annotations

from typing import Any


def as_str(value: Any, default: str = "") -> str:
    if value is None:
        return default
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float)):
        return str(value)
    return str(value)


def host_from_payload(payload: dict[str, Any]) -> str:
    for key in ("hostname", "host", "ip"):
        text = as_str(payload.get(key), "")
        if text:
            return text
    base_url = payload.get("base_url")
    if base_url is None:
        return ""
    text = as_str(base_url, "")
    if not text:
        return ""
    return text.replace("https://", "").replace("http://", "").split("/")[0]


def url_from_payload(payload: dict[str, Any], *, default_scheme: str = "https") -> str:
    for key in ("url", "base_url"):
        text = as_str(payload.get(key), "")
        if text:
            return text
    host = host_from_payload(payload)
    if host:
        return f"{default_scheme}://{host}"
    return ""
