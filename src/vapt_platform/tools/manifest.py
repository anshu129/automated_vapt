"""Tool manifest loading."""

import os
import shutil
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from vapt_platform.config.settings import get_settings


@dataclass
class ToolManifestSpec:
    name: str
    binary: str
    capabilities: list[str]
    capability_group: str
    safety_class: str
    cost_tier: str
    output_format: str
    base_args: list[str]
    priority: int = 50
    enabled: bool = True
    requires_api_key: bool = False
    wrapper: str | None = None
    stdin: bool = False
    fake_behavior: str | None = None


@lru_cache
def load_tool_manifests(path: str | None = None) -> dict[str, ToolManifestSpec]:
    manifest_path = Path(path or "config/tools/manifests.yaml")
    if not manifest_path.exists():
        return {}
    with manifest_path.open(encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    tools: dict[str, ToolManifestSpec] = {}
    for name, spec in (data.get("tools") or {}).items():
        tools[name] = ToolManifestSpec(
            name=name,
            binary=spec.get("binary", name),
            capabilities=spec.get("capabilities", []),
            capability_group=spec.get("capability_group", "GENERAL"),
            safety_class=spec.get("safety_class", "PASSIVE"),
            cost_tier=spec.get("cost_tier", "FREE"),
            output_format=spec.get("output_format", "text"),
            base_args=spec.get("base_args", []),
            priority=spec.get("priority", 50),
            enabled=spec.get("enabled", True),
            requires_api_key=spec.get("requires_api_key", False),
            wrapper=spec.get("wrapper"),
            stdin=spec.get("stdin", False),
        )
    return tools


def providers_for_capability(
    capability: str,
    manifests: dict[str, ToolManifestSpec] | None = None,
) -> list[ToolManifestSpec]:
    m = manifests or load_tool_manifests()
    return sorted(
        [s for s in m.values() if capability in s.capabilities and s.enabled],
        key=lambda x: x.priority,
        reverse=True,
    )


def resolve_tool_binary(binary: str) -> str | None:
    """Resolve a tool binary, preferring configured security-tool paths over PATH."""
    binary_path = Path(binary)
    if binary_path.is_file():
        return str(binary_path)

    names = [binary]
    if not binary_path.suffix:
        names.extend([f"{binary}.exe", f"{binary}.cmd", f"{binary}.bat"])

    for raw_path in _tool_search_paths():
        folder = Path(raw_path)
        for name in names:
            candidate = folder / name
            if candidate.is_file():
                return str(candidate)

    source = shutil.which(binary)
    if source:
        return source
    return None


def _tool_search_paths() -> list[str]:
    configured = get_settings().tool_search_paths
    if not configured:
        return []
    parts = configured.split(os.pathsep)
    if os.pathsep != ";":
        parts = [sub for part in parts for sub in part.split(";")]
    return [part.strip() for part in parts if part.strip()]
