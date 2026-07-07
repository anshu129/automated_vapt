"""Correlation rule registry (Phase 4)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from vapt_platform.domain.correlation_rule import CorrelationRule
from vapt_platform.engines.correlation_rule_dependency_index import CorrelationRuleDependencyIndex
from vapt_platform.engines.correlation_rules import build_initial_rules

_CONFIG_PATH = Path(__file__).resolve().parents[3] / "config" / "correlation_rules.yaml"


class CorrelationRuleRegistry:
    def __init__(self, config_path: Path | None = None) -> None:
        path = config_path or _CONFIG_PATH
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) if path.exists() else {}
        self._config: dict[str, dict[str, Any]] = raw.get("rules", {})
        self._rules: dict[str, CorrelationRule] = {}
        for rule in build_initial_rules():
            self.register(rule)

    def register(self, rule: CorrelationRule) -> None:
        key = f"{rule.rule_id}:{rule.rule_version}"
        if rule.rule_id in self._rules:
            raise ValueError(f"Duplicate correlation rule id: {rule.rule_id}")
        cfg = self._config.get(rule.rule_id, {})
        if cfg.get("enabled", True) is False:
            return
        self._rules[rule.rule_id] = rule

    def get(self, rule_id: str) -> CorrelationRule | None:
        return self._rules.get(rule_id)

    def enabled_rules(self) -> list[CorrelationRule]:
        rules: list[CorrelationRule] = []
        for rule_id, rule in sorted(self._rules.items()):
            cfg = self._config.get(rule_id, {})
            if cfg.get("enabled", True):
                rules.append(rule)
        return sorted(rules, key=lambda r: (-self._priority(r.rule_id), r.rule_id))

    def dependency_index(self) -> CorrelationRuleDependencyIndex:
        return CorrelationRuleDependencyIndex(self.enabled_rules())

    def _priority(self, rule_id: str) -> int:
        return int(self._config.get(rule_id, {}).get("priority", 0))

    def rule_metadata(self, rule_id: str) -> dict[str, Any]:
        rule = self._rules.get(rule_id)
        if not rule:
            return {}
        cfg = self._config.get(rule_id, {})
        return {
            "rule_id": rule.rule_id,
            "rule_version": rule.rule_version,
            "dependencies": rule.dependencies().__dict__,
            **cfg,
        }
