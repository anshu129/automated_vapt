"""AI-assisted validation and assignment over the evidence-gated backlog.

This orchestrates the *safe* parts of validation without ever auto-confirming a
finding:

1. Runs the ``AutomatedValidationOrchestrator`` (PASSIVE / LOW_IMPACT plans only,
   e.g. nuclei) which produces finding *candidates* and routes them to analyst
   validation tasks.
2. Generates a Mistral coverage advisory (falls back to a deterministic summary
   when ``AI_ENABLED`` is off or no API key is configured).
3. Uses the advisory to prioritise and assign the open validation tasks so an
   analyst (or an MCP-connected agent) has a ranked, actionable worklist.

Confirmation of a vulnerability still requires recorded evidence via the normal
validation-result flow; nothing here marks a hypothesis as CONFIRMED.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from vapt_platform.db.tables.models import (
    Hypothesis,
    TestPlan,
    ValidationTask,
    VulnerabilityClass,
)
from vapt_platform.domain.enums import ValidationTaskStatus
from vapt_platform.enrichment.mistral import MistralEnrichmentService
from vapt_platform.services.automated_validation import AutomatedValidationOrchestrator

_AUTOMATED_QUEUE = "automated-validation"
_ANALYST_QUEUE = "analyst-queue"
_OPEN_STATUSES = {
    ValidationTaskStatus.OPEN.value,
    ValidationTaskStatus.ASSIGNED.value,
}


@dataclass
class AssignmentEntry:
    validation_task_id: str
    hypothesis_id: str | None
    assigned_to: str
    priority: int
    class_codes: list[str]
    recommended_validation: str
    testing_mode: str


@dataclass
class AIValidationSummary:
    scan_id: str
    automated_attempted: int = 0
    automated_executed: int = 0
    finding_candidates: int = 0
    assignments: list[AssignmentEntry] = field(default_factory=list)
    advisory: dict[str, Any] = field(default_factory=dict)
    advisory_provider: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "automated_attempted": self.automated_attempted,
            "automated_executed": self.automated_executed,
            "finding_candidates": self.finding_candidates,
            "advisory_provider": self.advisory_provider,
            "advisory": self.advisory,
            "assignments": [
                {
                    "validation_task_id": entry.validation_task_id,
                    "hypothesis_id": entry.hypothesis_id,
                    "assigned_to": entry.assigned_to,
                    "priority": entry.priority,
                    "class_codes": entry.class_codes,
                    "recommended_validation": entry.recommended_validation,
                    "testing_mode": entry.testing_mode,
                }
                for entry in self.assignments
            ],
            "note": (
                "AI is advisory only: candidates are routed to the evidence-gated "
                "validation backlog. No finding is auto-confirmed."
            ),
        }


class AIValidationService:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def run(self, scan_id: uuid.UUID) -> AIValidationSummary:
        summary = AIValidationSummary(scan_id=str(scan_id))

        automated = await AutomatedValidationOrchestrator(self.session).execute_scan(scan_id)
        summary.automated_attempted = len(automated)
        summary.automated_executed = sum(1 for item in automated if item.execution_id)
        summary.finding_candidates = sum(item.finding_candidates for item in automated)

        enrichment = await MistralEnrichmentService(self.session).enrich_vulnerability_coverage(
            scan_id
        )
        advisory = dict(enrichment.output or {})
        summary.advisory = advisory
        summary.advisory_provider = enrichment.provider

        priority_by_class = self._priority_by_class(advisory)
        recommendation_by_class = self._recommendation_by_class(advisory)

        summary.assignments = await self._assign_backlog(
            scan_id, priority_by_class, recommendation_by_class
        )
        return summary

    @staticmethod
    def _priority_by_class(advisory: dict[str, Any]) -> dict[str, int]:
        ordered = advisory.get("priority_classes") or []
        mapping: dict[str, int] = {}
        for rank, item in enumerate(ordered):
            code = item.get("class_code") if isinstance(item, dict) else None
            if code:
                mapping[code] = max(10, 100 - rank * 5)
        return mapping

    @staticmethod
    def _recommendation_by_class(advisory: dict[str, Any]) -> dict[str, str]:
        mapping: dict[str, str] = {}
        for item in advisory.get("priority_classes") or []:
            if isinstance(item, dict) and item.get("class_code"):
                mapping[item["class_code"]] = str(
                    item.get("recommended_validation") or ""
                ).strip()
        return mapping

    async def _assign_backlog(
        self,
        scan_id: uuid.UUID,
        priority_by_class: dict[str, int],
        recommendation_by_class: dict[str, str],
    ) -> list[AssignmentEntry]:
        tasks = list(
            (
                await self.session.execute(
                    select(ValidationTask).where(ValidationTask.scan_id == scan_id)
                )
            )
            .scalars()
            .all()
        )
        class_code_by_id = await self._class_code_lookup()
        entries: list[AssignmentEntry] = []
        for task in tasks:
            if task.status not in _OPEN_STATUSES:
                continue
            class_codes = await self._class_codes_for_task(task, class_code_by_id)
            priority = max(
                (priority_by_class.get(code, 0) for code in class_codes),
                default=0,
            )
            if priority <= 0:
                priority = 50
            recommendation = next(
                (recommendation_by_class[code] for code in class_codes if recommendation_by_class.get(code)),
                "Reproduce within authorized scope and record evidence before confirming.",
            )
            queue = (
                _AUTOMATED_QUEUE
                if str(task.testing_mode).upper() in {"ASSISTED", "AUTOMATED"}
                else _ANALYST_QUEUE
            )
            task.assigned_to = task.assigned_to or queue
            task.priority = priority
            if task.status == ValidationTaskStatus.OPEN.value:
                task.status = ValidationTaskStatus.ASSIGNED.value
            entries.append(
                AssignmentEntry(
                    validation_task_id=str(task.id),
                    hypothesis_id=str(task.hypothesis_id) if task.hypothesis_id else None,
                    assigned_to=task.assigned_to,
                    priority=priority,
                    class_codes=class_codes,
                    recommended_validation=recommendation,
                    testing_mode=task.testing_mode,
                )
            )
        entries.sort(key=lambda entry: entry.priority, reverse=True)
        return entries

    async def _class_code_lookup(self) -> dict[uuid.UUID, str]:
        rows = list(
            (await self.session.execute(select(VulnerabilityClass))).scalars().all()
        )
        return {row.id: row.class_code for row in rows}

    async def _class_codes_for_task(
        self,
        task: ValidationTask,
        class_code_by_id: dict[uuid.UUID, str],
    ) -> list[str]:
        class_ids: list[str] = []
        if task.test_plan_id:
            plan = await self.session.get(TestPlan, task.test_plan_id)
            if plan and plan.vulnerability_class_ids:
                class_ids.extend(plan.vulnerability_class_ids)
        if not class_ids and task.hypothesis_id:
            hypothesis = await self.session.get(Hypothesis, task.hypothesis_id)
            if hypothesis and getattr(hypothesis, "vulnerability_class_id", None):
                class_ids.append(str(hypothesis.vulnerability_class_id))
        codes: list[str] = []
        for raw in class_ids:
            try:
                code = class_code_by_id.get(uuid.UUID(str(raw)))
            except (TypeError, ValueError):
                code = None
            if code and code not in codes:
                codes.append(code)
        return codes
