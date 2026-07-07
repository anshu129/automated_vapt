"""Correlation rule dependency index (Phase 4)."""

from __future__ import annotations

from vapt_platform.domain.correlation_event import CorrelationEventData, CorrelationEventType
from vapt_platform.domain.correlation_rule import CorrelationRule, RuleDependencies


class CorrelationRuleDependencyIndex:
    def __init__(self, rules: list[CorrelationRule]) -> None:
        self._rules = rules
        self._by_event: dict[str, list[CorrelationRule]] = {}
        for rule in rules:
            for event_type in rule.dependencies().event_types:
                self._by_event.setdefault(event_type, []).append(rule)

    def rules_for(self, event: CorrelationEventData) -> list[CorrelationRule]:
        candidates = list(self._by_event.get(event.event_type, []))
        if not candidates:
            return []
        filtered: list[CorrelationRule] = []
        for rule in candidates:
            deps = rule.dependencies()
            if deps.vulnerability_classes and event.vulnerability_classes:
                if not set(deps.vulnerability_classes) & set(event.vulnerability_classes):
                    continue
            if deps.evidence_types:
                evidence_type = event.safe_context.get("evidence_type")
                if evidence_type and evidence_type not in deps.evidence_types:
                    continue
            filtered.append(rule)
        return sorted(filtered, key=lambda r: r.rule_id)
