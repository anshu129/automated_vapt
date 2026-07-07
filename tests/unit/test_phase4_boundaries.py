"""Phase 4 AI and MCP boundary tests."""

from __future__ import annotations

import uuid

import pytest

from vapt_platform.domain.correlation_event import CorrelationEventData, CorrelationEventType
from vapt_platform.engines.correlation_rule_registry import CorrelationRuleRegistry
from vapt_platform.services.ai_validation import AIValidationService
from vapt_platform.services.core import ProjectService, ScanService
from vapt_platform.services.correlation_event_service import CorrelationEventService


@pytest.mark.asyncio
async def test_ai_advisory_does_not_emit_canonical_correlation_events(db_session) -> None:
    project = await ProjectService(db_session).create("AI Corr Boundary")
    scan = await ScanService(db_session).create(project.id, "AI Corr Scan", [])
    await AIValidationService(db_session).run(scan.id)
    await db_session.commit()
    pending = await CorrelationEventService(db_session).pending_events(scan.id)
    assert pending == []


def test_correlation_registry_has_no_ai_rules() -> None:
    registry = CorrelationRuleRegistry()
    for rule in registry.enabled_rules():
        assert "ai" not in rule.rule_id.lower()
        assert "mistral" not in rule.rule_id.lower()
