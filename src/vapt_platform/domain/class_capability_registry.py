"""Versioned vulnerability-class → capability mapping registry.

Loads from ``config/class_capability_mapping.yaml``. Supports multiple
capabilities per class (ordered by planning priority). Used by TestMatrixEngine
to enrich TestRequirement rows without hard-coding mappings in assessment code.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

_DEFAULT_MAPPING_PATH = (
    Path(__file__).resolve().parents[3] / "config" / "class_capability_mapping.yaml"
)


@dataclass(frozen=True)
class ClassCapabilityMapping:
    class_code: str
    capabilities: tuple[str, ...]
    safety_class: str | None = None
    authorization_requirement: str | None = None
    credential_requirement: str | None = None

    @property
    def primary_capability(self) -> str | None:
        return self.capabilities[0] if self.capabilities else None


@dataclass
class ClassCapabilityRegistry:
    version: str
    defaults: dict[str, Any] = field(default_factory=dict)
    mappings: dict[str, ClassCapabilityMapping] = field(default_factory=dict)

    def resolve(self, class_code: str) -> ClassCapabilityMapping | None:
        return self.mappings.get(class_code.upper())

    def capabilities_for(
        self,
        class_code: str,
        *,
        profile_capabilities: list[str] | None = None,
    ) -> list[str]:
        """Return merged capability list: registry first, then profile extras."""
        ordered: list[str] = []
        mapping = self.resolve(class_code)
        if mapping:
            ordered.extend(mapping.capabilities)
        for cap in profile_capabilities or []:
            if cap not in ordered:
                ordered.append(cap)
        return ordered

    @classmethod
    def from_yaml(cls, path: Path | None = None) -> ClassCapabilityRegistry:
        mapping_file = path or _DEFAULT_MAPPING_PATH
        with mapping_file.open(encoding="utf-8") as handle:
            data = yaml.safe_load(handle) or {}
        version = str(data.get("version", "1.0"))
        defaults = dict(data.get("defaults") or {})
        mappings: dict[str, ClassCapabilityMapping] = {}
        for class_code, raw in (data.get("mappings") or {}).items():
            if not isinstance(raw, dict):
                continue
            caps = raw.get("capabilities") or []
            mappings[class_code.upper()] = ClassCapabilityMapping(
                class_code=class_code.upper(),
                capabilities=tuple(str(c) for c in caps),
                safety_class=raw.get("safety_class") or defaults.get("safety_class"),
                authorization_requirement=(
                    raw.get("authorization_requirement")
                    or defaults.get("authorization_requirement")
                ),
                credential_requirement=(
                    raw.get("credential_requirement")
                    if "credential_requirement" in raw
                    else defaults.get("credential_requirement")
                ),
            )
        return cls(version=version, defaults=defaults, mappings=mappings)


@lru_cache
def get_class_capability_registry() -> ClassCapabilityRegistry:
    return ClassCapabilityRegistry.from_yaml()


def clear_registry_cache() -> None:
    get_class_capability_registry.cache_clear()
