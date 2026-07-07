"""Evidence ingestion from normalized provider artifacts (Phase 3)."""

from __future__ import annotations

import hashlib
import logging
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from vapt_platform.config.settings import get_settings
from vapt_platform.db.tables.models import (
    ConfirmationDecisionRecord,
    Hypothesis,
    Observation,
    ProviderRawResult,
    ScannerFinding,
    TestExecution,
    TestPlan,
    TestRequirement,
)
from vapt_platform.domain.capability_provider import ProviderExecutionResult
from vapt_platform.domain.enums import (
    EvidenceLinkType,
    HypothesisStatus,
    TestRequirementCoverageStatus,
    VerdictStatus,
)
from vapt_platform.domain.normalized_artifact import NormalizedArtifactType
from vapt_platform.engines.assessment import TestMatrixEngine, VerdictEngine
from vapt_platform.engines.confirmation_policy import ConfirmationPolicy
from vapt_platform.security.sensitive_data_redactor import SensitiveDataRedactor
from vapt_platform.services.correlation_event_service import CorrelationEventService
from vapt_platform.services.evidence_graph import EvidenceGraphService
from vapt_platform.services.result_normalizer import NormalizationContext, ResultNormalizer
from vapt_platform.domain.correlation_event import CorrelationEventData, CorrelationEventType

logger = logging.getLogger(__name__)


@dataclass
class IngestionSummary:
    artifact_count: int = 0
    evidence_node_ids: list[str] = field(default_factory=list)
    scanner_finding_ids: list[str] = field(default_factory=list)
    observation_ids: list[str] = field(default_factory=list)
    verdict_status: str | None = None


class EvidenceIngestionService:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.normalizer = ResultNormalizer()
        self.graph = EvidenceGraphService(session)
        self.confirmation = ConfirmationPolicy()
        self.redactor = SensitiveDataRedactor()

    async def ingest_provider_result(
        self,
        *,
        execution: TestExecution,
        plan: TestPlan,
        provider_result: ProviderExecutionResult,
        context: NormalizationContext,
        raw_content: str | None = None,
    ) -> IngestionSummary:
        summary = IngestionSummary()
        artifacts = self.normalizer.normalize(provider_result, context)
        summary.artifact_count = len(artifacts)

        if raw_content:
            raw = ProviderRawResult(
                test_execution_id=execution.id,
                provider_id=context.provider_id,
                content_hash=hashlib.sha256(raw_content.encode()).hexdigest(),
                content_type="text/plain",
                redacted_content=self.redactor.redact_text(raw_content)[:8000],
            )
            self.session.add(raw)
            await self.session.flush()
            execution.raw_result_reference = str(raw.id)

        execution.executed_capability = context.executed_capability
        execution.normalizer_version = artifacts[0].normalizer_version if artifacts else None
        execution.provider_selection_decision_id = (
            uuid.UUID(context.provider_selection_decision_id)
            if context.provider_selection_decision_id
            else None
        )

        node_ids: list[str] = []
        supporting: list[dict[str, Any]] = []
        contradicting: list[dict[str, Any]] = []
        coverage: list[dict[str, Any]] = []
        has_scanner = False
        has_negative = False
        has_validation = False

        for artifact in artifacts:
            entity_id, entity_type = await self._persist_artifact(artifact, execution)
            if not entity_id:
                continue

            node = await self.graph.get_or_create_node(
                scan_id=uuid.UUID(artifact.scan_id),
                node_type=artifact.artifact_type,
                entity_type=entity_type,
                entity_id=entity_id,
                test_execution_id=execution.id,
                provenance=artifact.safe_metadata,
                idempotency_key=artifact.idempotency_key,
            )
            node_ids.append(str(node.id))
            summary.evidence_node_ids.append(str(node.id))

            await self.graph.link(
                scan_id=uuid.UUID(artifact.scan_id),
                source_node_id=node.id,
                target_type="TEST_EXECUTION",
                target_id=execution.id,
                relationship_type="DERIVED_FROM",
                reason_code="PROVIDER_EXECUTION",
            )
            if artifact.test_plan_id:
                await self.graph.link(
                    scan_id=uuid.UUID(artifact.scan_id),
                    source_node_id=node.id,
                    target_type="TEST_PLAN",
                    target_id=uuid.UUID(artifact.test_plan_id),
                    relationship_type="APPLIES_TO",
                    reason_code="PLAN_PROVENANCE",
                )
            if artifact.test_requirement_id:
                await self.graph.link(
                    scan_id=uuid.UUID(artifact.scan_id),
                    source_node_id=node.id,
                    target_type="TEST_REQUIREMENT",
                    target_id=uuid.UUID(artifact.test_requirement_id),
                    relationship_type="COVERS",
                    reason_code="REQUIREMENT_PROVENANCE",
                )

            record = {"id": str(node.id), "type": artifact.artifact_type}
            if artifact.artifact_type == NormalizedArtifactType.SCANNER_FINDING.value:
                has_scanner = True
                supporting.append(record)
                summary.scanner_finding_ids.append(str(entity_id))
            elif artifact.artifact_type == NormalizedArtifactType.NEGATIVE_EVIDENCE.value:
                has_negative = True
                contradicting.append(record)
            elif artifact.artifact_type == NormalizedArtifactType.COVERAGE_EVIDENCE.value:
                coverage.append(record)
            elif artifact.artifact_type == NormalizedArtifactType.OBSERVATION.value:
                supporting.append(record)
                summary.observation_ids.append(str(entity_id))
            elif artifact.artifact_type in {
                NormalizedArtifactType.EXECUTION_ERROR.value,
                NormalizedArtifactType.INCONCLUSIVE_EVIDENCE.value,
            }:
                contradicting.append(record)

        if (
            provider_result.provider_id == "sqlmap_mcp"
            and provider_result.status == "CORROBORATED"
            and coverage
        ):
            has_validation = True

        execution.evidence_ids = list(dict.fromkeys([*execution.evidence_ids, *node_ids]))
        await self._update_coverage(execution, plan, context, artifacts)
        await self.session.flush()

        hypothesis = await self._linked_hypothesis(plan)
        if hypothesis:
            for artifact, node_id in zip(artifacts, node_ids, strict=False):
                if artifact.artifact_type in {
                    NormalizedArtifactType.NEGATIVE_EVIDENCE.value,
                    NormalizedArtifactType.EXECUTION_ERROR.value,
                }:
                    link_type = EvidenceLinkType.CONTRADICTS.value
                else:
                    link_type = EvidenceLinkType.SUPPORTS.value
                await self.graph.link(
                    scan_id=hypothesis.scan_id,
                    source_node_id=uuid.UUID(node_id),
                    target_type="HYPOTHESIS",
                    target_id=hypothesis.id,
                    relationship_type=link_type,
                    reason_code="PROVIDER_EVIDENCE",
                )

            vuln_class = (
                context.vulnerability_classes[0]
                if context.vulnerability_classes
                else hypothesis.hypothesis_type
            )
            decision = self.confirmation.evaluate(
                vulnerability_class=vuln_class or hypothesis.hypothesis_type,
                supporting_evidence=supporting,
                contradicting_evidence=contradicting,
                coverage_evidence=coverage,
                has_validation_evidence=has_validation,
                has_scanner_finding=has_scanner,
                has_negative_evidence=has_negative,
            )
            self.session.add(
                ConfirmationDecisionRecord(
                    scan_id=hypothesis.scan_id,
                    hypothesis_id=hypothesis.id,
                    test_execution_id=execution.id,
                    policy_id=decision.policy_id,
                    policy_version=decision.policy_version,
                    recommended_verdict=decision.recommended_verdict,
                    requirements_satisfied=decision.requirements_satisfied,
                    missing_evidence_types=decision.missing_evidence_types,
                    supporting_evidence_ids=decision.supporting_evidence_ids,
                    contradicting_evidence_ids=decision.contradicting_evidence_ids,
                    reason_codes=decision.reason_codes,
                )
            )
            await self.session.flush()

            verdict_engine = VerdictEngine(self.session)
            verdict = await verdict_engine.apply_confirmation_decision(
                hypothesis_id=hypothesis.id,
                decision=decision,
                test_execution_id=execution.id,
                test_plan_id=plan.id,
                evidence_node_ids=node_ids,
            )
            summary.verdict_status = verdict.status if verdict else decision.recommended_verdict

            logger.info(
                "evidence_ingested scan_id=%s test_execution_id=%s provider_id=%s "
                "artifact_count=%d verdict=%s",
                context.scan_id,
                execution.id,
                context.provider_id,
                summary.artifact_count,
                summary.verdict_status,
            )

        await self._emit_correlation_events(
            execution=execution,
            plan=plan,
            context=context,
            artifacts=artifacts,
            provider_result=provider_result,
            hypothesis=hypothesis,
        )

        return summary

    async def _emit_correlation_events(
        self,
        *,
        execution: TestExecution,
        plan: TestPlan,
        context: NormalizationContext,
        artifacts: list,
        provider_result: ProviderExecutionResult,
        hypothesis: Hypothesis | None,
    ) -> None:
        from vapt_platform.config.settings import get_settings

        if not get_settings().recursive_correlation_enabled:
            return

        emitter = CorrelationEventService(self.session)
        scan_uuid = uuid.UUID(context.scan_id)
        base = dict(
            scan_id=scan_uuid,
            source_type="TEST_EXECUTION",
            source_id=execution.id,
            asset_ids=[context.asset_id] if context.asset_id else list(plan.asset_ids or []),
            hypothesis_ids=[str(hypothesis.id)] if hypothesis else [],
            vulnerability_classes=list(context.vulnerability_classes or []),
            causation_id=execution.id,
            correlation_id=uuid.uuid4(),
            generation=0,
        )
        emitted_types: set[str] = set()
        for artifact in artifacts:
            event_type = {
                NormalizedArtifactType.SCANNER_FINDING.value: CorrelationEventType.SCANNER_FINDING_RECORDED.value,
                NormalizedArtifactType.NEGATIVE_EVIDENCE.value: CorrelationEventType.NEGATIVE_EVIDENCE_RECORDED.value,
                NormalizedArtifactType.COVERAGE_EVIDENCE.value: CorrelationEventType.COVERAGE_EVIDENCE_RECORDED.value,
                NormalizedArtifactType.INCONCLUSIVE_EVIDENCE.value: CorrelationEventType.INCONCLUSIVE_EVIDENCE_RECORDED.value,
                NormalizedArtifactType.OBSERVATION.value: CorrelationEventType.OBSERVATION_RECORDED.value,
            }.get(artifact.artifact_type)
            if not event_type or event_type in emitted_types:
                continue
            emitted_types.add(event_type)
            safe_context = {
                "evidence_type": artifact.artifact_type,
                "provider_id": context.provider_id,
                "executed_capability": context.executed_capability,
                "endpoint_context": context.endpoint_context,
                "hypothesis_id": str(hypothesis.id) if hypothesis else None,
                "parameter_name": (context.endpoint_context or {}).get("parameter_name"),
                "endpoint_ref": (context.endpoint_context or {}).get("endpoint_ref"),
                "untested_parameters": (context.endpoint_context or {}).get("untested_parameters"),
                "vulnerability_class": (
                    context.vulnerability_classes[0] if context.vulnerability_classes else None
                ),
            }
            if artifact.artifact_type == NormalizedArtifactType.NEGATIVE_EVIDENCE.value:
                safe_context["execution_semantics"] = artifact.execution_semantics
            await emitter.emit(
                CorrelationEventData(
                    event_type=event_type,
                    safe_context=safe_context,
                    idempotency_key=f"{execution.id}:{artifact.artifact_type}:{artifact.idempotency_key}",
                    **base,
                )
            )

    async def _persist_artifact(
        self,
        artifact,
        execution: TestExecution,
    ) -> tuple[uuid.UUID | None, str]:
        if artifact.artifact_type == NormalizedArtifactType.SCANNER_FINDING.value:
            existing = None
            if artifact.idempotency_key:
                existing = (
                    await self.session.execute(
                        select(ScannerFinding).where(
                            ScannerFinding.idempotency_key == artifact.idempotency_key
                        )
                    )
                ).scalar_one_or_none()
            if existing:
                return existing.id, "SCANNER_FINDING"
            row = ScannerFinding(
                scan_id=uuid.UUID(artifact.scan_id),
                asset_id=uuid.UUID(artifact.asset_id) if artifact.asset_id else None,
                test_requirement_id=(
                    uuid.UUID(artifact.test_requirement_id)
                    if artifact.test_requirement_id
                    else None
                ),
                test_plan_id=uuid.UUID(artifact.test_plan_id) if artifact.test_plan_id else None,
                test_execution_id=execution.id,
                provider_id=artifact.provider_id,
                executed_capability=artifact.executed_capability,
                vulnerability_class=artifact.vulnerability_class,
                source_rule_or_check_id=artifact.safe_metadata.get("template_id"),
                title=artifact.title or "Scanner finding",
                description=artifact.description,
                source_severity=artifact.safe_metadata.get("source_severity"),
                source_confidence=artifact.confidence,
                status="VALIDATION_REQUIRED",
                raw_result_reference=execution.raw_result_reference,
                safe_metadata=artifact.safe_metadata,
                idempotency_key=artifact.idempotency_key,
            )
            self.session.add(row)
            await self.session.flush()
            return row.id, "SCANNER_FINDING"

        obs_type = {
            NormalizedArtifactType.OBSERVATION.value: "PROVIDER_OBSERVATION",
            NormalizedArtifactType.NEGATIVE_EVIDENCE.value: "NEGATIVE_EVIDENCE",
            NormalizedArtifactType.COVERAGE_EVIDENCE.value: "COVERAGE_EVIDENCE",
            NormalizedArtifactType.EXECUTION_ERROR.value: "EXECUTION_ERROR",
            NormalizedArtifactType.INCONCLUSIVE_EVIDENCE.value: "INCONCLUSIVE_EVIDENCE",
        }.get(artifact.artifact_type, "PROVIDER_OBSERVATION")

        obs = Observation(
            scan_id=uuid.UUID(artifact.scan_id),
            subject_asset_id=uuid.UUID(artifact.asset_id) if artifact.asset_id else None,
            observation_type=obs_type,
            source_type="PROVIDER",
            source_id=artifact.provider_id,
            payload=self.redactor.redact_dict(artifact.evidence_payload),
            confidence=artifact.confidence,
            provenance={
                **artifact.safe_metadata,
                "artifact_type": artifact.artifact_type,
                "execution_semantics": artifact.execution_semantics,
                "test_execution_id": str(execution.id),
                "executed_capability": artifact.executed_capability,
            },
        )
        self.session.add(obs)
        await self.session.flush()
        return obs.id, "OBSERVATION"

    async def _linked_hypothesis(self, plan: TestPlan) -> Hypothesis | None:
        if plan.hypothesis_id:
            return await self.session.get(Hypothesis, plan.hypothesis_id)
        return None

    async def _update_coverage(
        self,
        execution: TestExecution,
        plan: TestPlan,
        context: NormalizationContext,
        artifacts: list,
    ) -> None:
        from vapt_platform.domain.normalized_artifact import ExecutionSemantics

        semantics = {a.execution_semantics for a in artifacts}
        if ExecutionSemantics.PARSER_FAILED.value in semantics or ExecutionSemantics.TRANSPORT_FAILED.value in semantics:
            execution.status = "FAILED"
            execution.result_summary = {
                **(execution.result_summary or {}),
                "coverage_status": TestRequirementCoverageStatus.INCONCLUSIVE.value,
            }
            return
        if ExecutionSemantics.TIMEOUT.value in semantics or ExecutionSemantics.AMBIGUOUS_RESULT.value in semantics:
            execution.result_summary = {
                **(execution.result_summary or {}),
                "coverage_status": TestRequirementCoverageStatus.INCONCLUSIVE.value,
            }
            return
        if ExecutionSemantics.CLEAN_NEGATIVE.value in semantics:
            execution.result_summary = {
                **(execution.result_summary or {}),
                "coverage_status": TestRequirementCoverageStatus.TESTED_NO_EVIDENCE.value,
                "coverage_scope": {
                    "capability": context.executed_capability,
                    "endpoint_context": context.endpoint_context,
                },
            }
        elif ExecutionSemantics.POSITIVE_RESULT.value in semantics:
            execution.result_summary = {
                **(execution.result_summary or {}),
                "coverage_status": TestRequirementCoverageStatus.PARTIALLY_TESTED.value,
                "coverage_scope": {"capability": context.executed_capability},
            }

        if context.test_requirement_id:
            req = await self.session.get(TestRequirement, uuid.UUID(context.test_requirement_id))
            if req and execution.result_summary.get("coverage_status"):
                req.coverage_status = execution.result_summary["coverage_status"]
        if plan.asset_ids:
            for asset_id in plan.asset_ids:
                try:
                    await TestMatrixEngine(self.session).build(plan.scan_id, uuid.UUID(asset_id))
                except (TypeError, ValueError):
                    continue
