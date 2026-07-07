"""Correlation dependency index tests (Phase 4)."""

from __future__ import annotations

import uuid

from vapt_platform.domain.correlation_event import CorrelationEventData, CorrelationEventType
from vapt_platform.engines.correlation_rule_dependency_index import CorrelationRuleDependencyIndex
from vapt_platform.engines.correlation_rule_registry import CorrelationRuleRegistry


def test_event_returns_only_relevant_rules() -> None:
    registry = CorrelationRuleRegistry()
    index = registry.dependency_index()
    event = CorrelationEventData(
        scan_id=uuid.uuid4(),
        event_type=CorrelationEventType.PARAMETER_DISCOVERED.value,
        source_type="PARAMETER",
        source_id=uuid.uuid4(),
        vulnerability_classes=["INJECTION_CLASS"],
    )
    rules = index.rules_for(event)
    rule_ids = {r.rule_id for r in rules}
    assert "CORR-PARAM-001" in rule_ids
    assert "CORR-ENDPOINT-001" not in rule_ids


def test_deterministic_ordering() -> None:
    registry = CorrelationRuleRegistry()
    index = registry.dependency_index()
    event = CorrelationEventData(
        scan_id=uuid.uuid4(),
        event_type=CorrelationEventType.OBSERVATION_RECORDED.value,
        source_type="OBSERVATION",
        source_id=uuid.uuid4(),
        safe_context={"js_endpoints": ["/api/hidden"], "crawl_endpoints": []},
        asset_ids=["asset-1"],
    )
    first = [r.rule_id for r in index.rules_for(event)]
    second = [r.rule_id for r in index.rules_for(event)]
    assert first == second
