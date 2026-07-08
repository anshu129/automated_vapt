"""Resolve per-tool wordlist paths (SecLists defaults with local fallback)."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from vapt_platform.config.settings import get_settings

_DEFAULT_CONFIG = Path("config/wordlists/tool_defaults.yaml")


@lru_cache
def _load_wordlist_config(path: str = str(_DEFAULT_CONFIG)) -> dict[str, Any]:
    config_path = Path(path)
    if not config_path.is_file():
        return {}
    with config_path.open(encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}


def seclists_root(project_root: Path | None = None) -> Path:
    settings = get_settings()
    root = Path(settings.seclists_root)
    if root.is_absolute():
        return root
    base = project_root or Path.cwd()
    return (base / root).resolve()


def _fallback_wordlist(config: dict[str, Any], project_root: Path) -> Path:
    rel = str(config.get("fallback_wordlist") or "config/wordlists/common.txt")
    candidate = Path(rel)
    if not candidate.is_absolute():
        candidate = (project_root / candidate).resolve()
    return candidate


def default_wordlist_relative_path(tool: str) -> str | None:
    config = _load_wordlist_config()
    tools = config.get("tools") or {}
    entry = tools.get(tool)
    if not entry:
        return None
    if isinstance(entry, str):
        return entry
    return entry.get("path")


def resolve_wordlist_path(
    tool: str,
    target: dict[str, Any] | None = None,
    *,
    project_root: Path | None = None,
) -> str:
    """Return an absolute filesystem path for a tool wordlist.

    Precedence:
    1. ``target["wordlist"]`` when explicitly set
    2. SecLists default for the tool (from tool_defaults.yaml)
    3. config/wordlists/common.txt
    """
    base = (project_root or Path.cwd()).resolve()
    explicit = (target or {}).get("wordlist")
    if explicit:
        path = Path(str(explicit))
        if not path.is_absolute():
            path = (base / path).resolve()
        return str(path)

    config = _load_wordlist_config()
    rel = default_wordlist_relative_path(tool)
    if rel:
        candidate = seclists_root(base) / rel
        if candidate.is_file():
            return str(candidate.resolve())

    fallback = _fallback_wordlist(config, base)
    if fallback.is_file():
        return str(fallback)
    if rel:
        return str((seclists_root(base) / rel).resolve())
    return str(fallback)


def wordlist_mappings() -> dict[str, str]:
    """Tool -> resolved absolute path (for diagnostics)."""
    config = _load_wordlist_config()
    tools = config.get("tools") or {}
    return {name: resolve_wordlist_path(name) for name in sorted(tools)}
