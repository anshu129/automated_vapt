"""Selective hypothesis re-evaluation (Phase 4)."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from vapt_platform.db.tables.models import EvidenceLink, Hypothesis, Verdict
from vapt_platform.domain.correlation_event import CorrelationEventData
from vapt_platform.domain.enums import VerdictStatus
from vapt_platform.engines.assessment import VerdictEngine
from vapt_platform.engines.confirmation_policy import ConfirmationPolicy
from vapt_platform.services.correlation_event_service import CorrelationEventService
from vapt_platform.domain.correlation_event import CorrelationEventType


@dataclass
class ReevaluationSummary:
    hypothesis_ids: list[str] = field(default_factory=list)
    verdict_changed: list[str] = field(default_factory=list)


class HypothesisReevaluationService:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.policy = ConfirmationPolicy()
        self.event_service = CorrelationEventService(session)

    async def reevaluate_for_event(self, event: CorrelationEventData) -> ReevaluationSummary:
        summary = ReevaluationSummary()
        hypotheses = await self._affected_hypotheses(event)
        for hyp in hypotheses:
            summary.hypothesis_ids.append(str(hyp.id))
            previous = None
            if hyp.verdict_id:
                verdict = await self.session.get(Verdict, hyp.verdict_id)
                previous = verdict.status if verdict else None

            supporting, contradicting, coverage = await self._evidence_buckets(hyp)
            decision = self.policy.evaluate(
                vulnerability_class=hyp.hypothesis_type,
                supporting_evidence=supporting,
                contradicting_evidence=contradicting,
                coverage_evidence=coverage,
                has_validation_evidence=any(
                    e.get("type") == "VALIDATION_RESULT" for e in supporting
                ),
                has_scanner_finding=any(
                    e.get("type") == "SCANNER_FINDING" for e in supporting
                ),
                has_negative_evidence=any(
                    e.get("type") == "NEGATIVE_EVIDENCE" for e in contradicting
                ),
            )
            engine = VerdictEngine(self.session)
            verdict = await engine.apply_confirmation_decision(
                hypothesis_id=hyp.id,
                decision=decision,
                test_execution_id=event.source_id,
                test_plan_id=hyp.test_plan_id or event.source_id,
                evidence_node_ids=[e["id"] for e in supporting + contradicting if e.get("id")],
            )
            if verdict and previous and verdict.status != previous:
                summary.verdict_changed.append(str(hyp.id))
                await self.event_service.emit(
                    CorrelationEventData(
                        scan_id=event.scan_id,
                        event_type=CorrelationEventType.VERDICT_CHANGED.value,
                        source_type="HYPOTHESIS",
                        source_id=hyp.id,
                        hypothesis_ids=[str(hyp.id)],
                        asset_ids=list(hyp.affected_asset_ids or []),
                        vulnerability_classes=[hyp.hypothesis_type],
                        causation_id=event.causation_id or event.source_id,
                        correlation_id=event.correlation_id,
                        generation=event.generation,
                        idempotency_key=f"verdict-changed:{hyp.id}:{previous}:{verdict.status}",
                        safe_context={
                            "hypothesis_id": str(hyp.id),
                            "previous_verdict": previous,
                            "new_verdict": verdict.status,
                            "vulnerability_class": hyp.hypothesis_type,
                        },
                    )
                )
        return summary

    async def _affected_hypotheses(self, event: CorrelationEventData) -> list[Hypothesis]:
        if event.hypothesis_ids:
            rows = []
            for hid in event.hypothesis_ids:
                hyp = await self.session.get(Hypothesis, uuid.UUID(str(hid)))
                if hyp:
                    rows.append(hyp)
            return rows
        if not event.asset_ids:
            return []
        asset_set = set(event.asset_ids)
        candidates = list(
            (
                await self.session.execute(
                    select(Hypothesis).where(Hypothesis.scan_id == event.scan_id)
                )
            )
            .scalars()
            .all()
        )
        return [
            h
            for h in candidates
            if asset_set & set(h.affected_asset_ids or [])
            and (
                not event.vulnerability_classes
                or h.hypothesis_type in event.vulnerability_classes
            )
        ]

    async def _evidence_buckets(self, hyp: Hypothesis) -> tuple[list, list, list]:
        links = list(
            (
                await self.session.execute(
                    select(EvidenceLink).where(
                        EvidenceLink.scan_id == hyp.scan_id,
                        EvidenceLink.target_type == "HYPOTHESIS",
                        EvidenceLink.target_id == hyp.id,
                    )
                )
            )
            .scalars()
            .all()
        )
        supporting, contradicting, coverage = [], [], []
        for link in links:
            record = {
                "id": str(link.source_id),
                "type": link.link_type,
            }
            if link.link_type == "SUPPORTS":
                supporting.append(record)
            elif link.link_type == "CONTRADICTS":
                contradicting.append(record)
            elif link.link_type == "COVERS":
                coverage.append(record)
        return supporting, contradicting, coverage
