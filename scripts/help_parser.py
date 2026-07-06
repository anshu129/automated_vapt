"""Parse CLI -h / man-page style help into parameter_groups."""

from __future__ import annotations

import re
from typing import Any

SECTION_RE = re.compile(r"^([A-Z][A-Z0-9_ /-]{2,}):\s*$")
OPTION_LINE_RE = re.compile(
    r"^\s{1,8}(-[-\w/\[\]<>|.,]+(?:\s+<[^>]+>)?)\s*:?\s*(.*)$"
)
USAGE_RE = re.compile(r"^Usage:\s*(.+)$", re.I)
VERSION_RE = re.compile(r"^(\S+)\s+([\d.]+[^\s]*)", re.I)


def _slug_flag(flag: str) -> str:
    primary = flag.split(",")[0].split("/")[0].strip()
    primary = primary.split()[0] if primary else flag
    primary = primary.lstrip("-")
    return re.sub(r"[^a-zA-Z0-9_-]", "_", primary) or "opt"


def _split_combo_flags(flag_part: str) -> list[str]:
    if "/" in flag_part and flag_part.startswith("-"):
        base = flag_part.lstrip("-")
        parts = base.split("/")
        return [f"-{p}" if not p.startswith("-") else p for p in parts]
    return [flag_part.strip()]


def parse_help_text(help_text: str, tool_name: str = "") -> dict[str, Any]:
    lines = help_text.replace("\r\n", "\n").split("\n")
    groups: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    usage: str | None = None
    version: str | None = None
    summary_lines: list[str] = []

    def flush_group() -> None:
        nonlocal current
        if current and current.get("parameters"):
            groups.append(current)
        current = None

    for raw in lines:
        line = raw.rstrip()
        if not line.strip():
            continue

        vm = VERSION_RE.match(line.strip())
        if vm and (not tool_name or tool_name.lower() in vm.group(1).lower()) and not version:
            version = vm.group(2).strip("()")

        um = USAGE_RE.match(line.strip())
        if um:
            usage = um.group(1).strip()
            continue

        sm = SECTION_RE.match(line.strip())
        if sm:
            flush_group()
            title = sm.group(1).strip()
            gid = re.sub(r"[^A-Z0-9]+", "_", title.upper()).strip("_")
            current = {"id": gid or "OPTIONS", "title": title, "parameters": []}
            continue

        om = OPTION_LINE_RE.match(line)
        if om:
            flag_raw, desc = om.group(1).strip(), om.group(2).strip()
            if not current:
                current = {"id": "OPTIONS", "title": "Options", "parameters": []}
            for flag in _split_combo_flags(flag_raw):
                pid = _slug_flag(flag)
                current["parameters"].append(
                    {
                        "id": pid,
                        "flags": [flag],
                        "description": desc or flag,
                        "rationale": f"From {tool_name} -h/man: {desc or flag}",
                    }
                )
            continue

        if not groups and not current and not line.startswith((" ", "\t", "-")):
            if "http" not in line.lower() and len(line) < 120:
                summary_lines.append(line.strip())

    flush_group()
    if not groups:
        groups = [{"id": "OPTIONS", "title": "Options", "parameters": []}]

    return {
        "usage": usage,
        "tool_version": version,
        "summary": summary_lines[0] if summary_lines else f"{tool_name} CLI",
        "parameter_groups": groups,
    }


def compact_parameters_to_groups(
    parameters: list[dict[str, Any]],
    title: str = "Documented options",
) -> list[dict[str, Any]]:
    entries = []
    for p in parameters:
        flags = p.get("flags", [])
        flag = flags[0] if flags else p.get("id", "option")
        entries.append(
            {
                "id": p.get("id", _slug_flag(str(flag))),
                "flags": flags,
                "description": p.get("when_to_use", p.get("rationale", flag)),
                "rationale": p.get("rationale", ""),
                "when_to_use": p.get("when_to_use"),
                "operational_triggers": p.get("operational_triggers", []),
                "avoid_when": p.get("avoid_when", []),
            }
        )
    return [{"id": "PLATFORM_DOCUMENTED", "title": title, "parameters": entries}]


def merge_adaptive_overlay(
    groups: list[dict[str, Any]],
    overlay_params: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    by_flag: dict[str, dict[str, Any]] = {}
    for p in overlay_params:
        for f in p.get("flags", []):
            by_flag[f.lstrip("-")] = p
            by_flag[f] = p

    for group in groups:
        for param in group.get("parameters", []):
            for flag in param.get("flags", []):
                key = flag.lstrip("-").split()[0]
                if key in by_flag:
                    src = by_flag[key]
                    for field in (
                        "when_to_use",
                        "operational_triggers",
                        "avoid_when",
                        "adaptive_rule_id",
                        "platform_default",
                    ):
                        if src.get(field):
                            param[field] = src[field]
                    if src.get("rationale"):
                        param["rationale"] = src["rationale"]
    return groups
