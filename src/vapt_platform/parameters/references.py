"""Load per-tool parameter reference knowledge base."""

from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml


def flatten_parameters(spec: dict[str, Any]) -> list[dict[str, Any]]:
    """Return flat parameter list from parameters or parameter_groups."""
    if spec.get("parameters"):
        return list(spec["parameters"])
    flat: list[dict[str, Any]] = []
    for group in spec.get("parameter_groups", []):
        gid = group.get("id", "")
        for param in group.get("parameters", []):
            flat.append({**param, "_group": gid, "_group_title": group.get("title")})
    return flat


def parameter_count(spec: dict[str, Any]) -> int:
    return len(flatten_parameters(spec))


@lru_cache
def load_parameter_references(
    references_dir: str | None = None,
) -> dict[str, dict[str, Any]]:
    """Load all tool parameter references keyed by manifest tool name."""
    base = Path(references_dir or "config/parameters/references")
    refs: dict[str, dict[str, Any]] = {}
    if not base.exists():
        return refs
    for path in sorted(base.glob("*.yaml")):
        with path.open(encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        for name, spec in (data.get("tools") or {}).items():
            enriched = {
                **spec,
                "_source_file": path.name,
                "_category": data.get("category"),
                "_parameter_count": parameter_count(spec),
            }
            refs[name] = enriched
    return refs


def reference_for_tool(tool_name: str) -> dict[str, Any] | None:
    return load_parameter_references().get(tool_name)


def find_parameter_in_reference(tool: str, param_id: str) -> dict[str, Any] | None:
    spec = reference_for_tool(tool)
    if not spec:
        return None
    for param in flatten_parameters(spec):
        if param.get("id") == param_id:
            return param
    return None
