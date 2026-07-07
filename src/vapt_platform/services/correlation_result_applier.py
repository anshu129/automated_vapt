"""Apply correlation results idempotently (Phase 4)."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from vapt_platform.config.settings import get_settings
from vapt_platform.db.tables.models import (
    Asset,
    AssetTestMatrix,
    CoverageGap,
    Hypothesis,
    Relationship,
    TestRequirement,
    VulnerabilityClass,
)
from vapt_platform.domain.correlation_rule import CorrelationResult, CorrelationResultType
from vapt_platform.domain.enums import (
    HypothesisStatus,
    TestRequirementCoverageStatus,
    TestRequirementNextAction,
    TestingMode,
)
from vapt_platform.engines.hypothesis_uniqueness import hypothesis_uniqueness_key
from vapt_platform.engines.test_requirement_uniqueness import (
    scope_from_key_parts,
    build_test_requirement_uniqueness_key,
)
from vapt_platform.services.requirement_uniqueness_policy import TestRequirementUniquenessPolicy


@dataclass
class ApplySummary:
    created_hypothesis_ids: list[str] = field(default_factory=list)
    updated_hypothesis_ids: list[str] = field(default_factory=list)
    created_coverage_gap_ids: list[str] = field(default_factory=list)
    created_test_requirement_ids: list[str] = field(default_factory=list)
    created_relationship_ids: list[str] = field(default_factory=list)
    duplicate_suppression_count: int = 0
    meaningful_change: bool = False


class CorrelationResultApplier:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def apply(
        self,
        *,
        scan_id: uuid.UUID,
        event_id: uuid.UUID,
        result: CorrelationResult,
    ) -> ApplySummary:
        summary = ApplySummary()
        if result.result_type == CorrelationResultType.NO_ACTION.value:
            return summary

        if result.result_type == CorrelationResultType.HYPOTHESIS_CANDIDATE.value:
            hyp_id = await self._create_hypothesis(scan_id, event_id, result, summary)
            if hyp_id:
                summary.meaningful_change = True

        elif result.result_type == CorrelationResultType.HYPOTHESIS_UPDATE.value:
            if await self._update_hypothesis(result, summary):
                summary.meaningful_change = True

        elif result.result_type == CorrelationResultType.COVERAGE_GAP_CANDIDATE.value:
            gap_id = await self._create_coverage_gap(scan_id, event_id, result, summary)
            if gap_id:
                summary.meaningful_change = True

        elif result.result_type == CorrelationResultType.TEST_REQUIREMENT_CANDIDATE.value:
            req_id = await self._create_or_link_requirement(scan_id, event_id, result, summary)
            if req_id:
                summary.meaningful_change = True

        elif result.result_type in {
            CorrelationResultType.RELATIONSHIP_CANDIDATE.value,
            CorrelationResultType.RELATIONSHIP_UPDATE.value,
        }:
            rel_id = await self._upsert_relationship(scan_id, result, summary)
            if rel_id:
                summary.meaningful_change = True

        return summary

    async def _create_hypothesis(
        self,
        scan_id: uuid.UUID,
        event_id: uuid.UUID,
        result: CorrelationResult,
        summary: ApplySummary,
    ) -> str | None:
        settings = get_settings()
        state_count = await self._hypothesis_count(scan_id)
        if state_count >= settings.correlation_max_new_hypotheses_per_scan:
            return None

        payload = result.payload
        asset_ids = list(payload.get("asset_ids") or result.participating_asset_ids)
        scope = dict(payload.get("scope_dimensions") or {})
        ukey = hypothesis_uniqueness_key(
            hypothesis_type=payload.get("hypothesis_type", "CORRELATION"),
            vulnerability_class=payload.get("vulnerability_class", "DEFAULT"),
            asset_ids=asset_ids,
            scope_dimension=scope.get("endpoint_ref", ""),
            role_context=scope.get("role_name", ""),
            auth_context=scope.get("auth_context_id", ""),
            rule_id=result.rule_id,
            endpoint_ref=scope.get("endpoint_ref", ""),
            parameter_name=scope.get("parameter_name", ""),
        )
        existing = (
            await self.session.execute(
                select(Hypothesis).where(
                    Hypothesis.scan_id == scan_id,
                    Hypothesis.uniqueness_key == ukey,
                )
            )
        ).scalar_one_or_none()
        if existing:
            summary.duplicate_suppression_count += 1
            return None

        hyp = Hypothesis(
            scan_id=scan_id,
            title=payload.get("title", "Correlation hypothesis"),
            description=payload.get("description"),
            hypothesis_type=payload.get("hypothesis_type", "CORRELATION"),
            affected_asset_ids=asset_ids,
            correlation_rule_ids=[result.rule_id],
            confidence=result.confidence,
            validation_requirements={"testing_mode": payload.get("testing_mode")},
            status=HypothesisStatus.READY_FOR_VALIDATION.value,
            uniqueness_key=ukey,
            scope_dimensions=scope,
            explanation_data={
                **result.explanation_data,
                "source_event_id": str(event_id),
                "rule_version": result.rule_version,
            },
        )
        self.session.add(hyp)
        await self.session.flush()
        summary.created_hypothesis_ids.append(str(hyp.id))
        return str(hyp.id)

    async def _update_hypothesis(self, result: CorrelationResult, summary: ApplySummary) -> bool:
        payload = result.payload
        hyp_id = payload.get("hypothesis_id")
        if not hyp_id:
            return False
        hyp = await self.session.get(Hypothesis, uuid.UUID(str(hyp_id)))
        if not hyp:
            return False
        if payload.get("preserve_rejection") and hyp.status == HypothesisStatus.REJECTED.value:
            return False
        new_status = payload.get("status")
        if new_status and hyp.status != new_status:
            hyp.status = new_status
            summary.updated_hypothesis_ids.append(str(hyp.id))
            return True
        return False

    async def _create_coverage_gap(
        self,
        scan_id: uuid.UUID,
        event_id: uuid.UUID,
        result: CorrelationResult,
        summary: ApplySummary,
    ) -> str | None:
        payload = result.payload
        ukey = build_test_requirement_uniqueness_key(
            scan_id=str(scan_id),
            asset_id=str(payload.get("asset_id", "")),
            vulnerability_class=payload.get("gap_type", "COVERAGE"),
            endpoint_ref=payload.get("endpoint_ref", ""),
            validation_objective=payload.get("validation_objective", ""),
        )
        existing = (
            await self.session.execute(
                select(CoverageGap).where(
                    CoverageGap.scan_id == scan_id,
                    CoverageGap.uniqueness_key == ukey,
                )
            )
        ).scalar_one_or_none()
        if existing:
            summary.duplicate_suppression_count += 1
            return None

        gap = CoverageGap(
            scan_id=scan_id,
            gap_type=payload.get("gap_type", "COVERAGE"),
            asset_id=uuid.UUID(str(payload["asset_id"])) if payload.get("asset_id") else None,
            endpoint_ref=payload.get("endpoint_ref"),
            parameter_name=payload.get("parameter_name"),
            parameter_location=payload.get("parameter_location"),
            vulnerability_class=payload.get("vulnerability_class"),
            auth_context_id=(
                uuid.UUID(str(payload["auth_context_id"]))
                if payload.get("auth_context_id")
                else None
            ),
            uniqueness_key=ukey,
            source_rule_id=result.rule_id,
            source_event_id=event_id,
            reasoning_trace={
                "rule_id": result.rule_id,
                "rule_version": result.rule_version,
                "reason_codes": result.reason_codes,
                **result.explanation_data,
            },
        )
        self.session.add(gap)
        await self.session.flush()
        summary.created_coverage_gap_ids.append(str(gap.id))
        return str(gap.id)

    async def _create_or_link_requirement(
        self,
        scan_id: uuid.UUID,
        event_id: uuid.UUID,
        result: CorrelationResult,
        summary: ApplySummary,
    ) -> str | None:
        settings = get_settings()
        if await self._requirement_count(scan_id) >= settings.correlation_max_new_test_requirements_per_scan:
            return None

        payload = result.payload
        asset_id = payload.get("asset_id")
        if not asset_id:
            return None
        class_code = payload.get("vulnerability_class", "DEFAULT")
        vc = (
            await self.session.execute(
                select(VulnerabilityClass).where(VulnerabilityClass.class_code == class_code)
            )
        ).scalar_one_or_none()
        if not vc:
            return None

        matrix = (
            await self.session.execute(
                select(AssetTestMatrix).where(
                    AssetTestMatrix.scan_id == scan_id,
                    AssetTestMatrix.asset_id == uuid.UUID(str(asset_id)),
                )
            )
        ).scalar_one_or_none()
        if not matrix:
            matrix = AssetTestMatrix(scan_id=scan_id, asset_id=uuid.UUID(str(asset_id)))
            self.session.add(matrix)
            await self.session.flush()

        ukey = build_test_requirement_uniqueness_key(
            scan_id=str(scan_id),
            asset_id=str(asset_id),
            vulnerability_class=class_code,
            capability_group=payload.get("capability_group", ""),
            endpoint_ref=payload.get("endpoint_ref", ""),
            parameter_name=payload.get("parameter_name", ""),
            parameter_location=payload.get("parameter_location", ""),
            auth_context_id=str(payload.get("auth_context_id") or ""),
            role_name=payload.get("role_name", ""),
            validation_objective=payload.get("validation_objective", ""),
        )
        policy = TestRequirementUniquenessPolicy()
        _, granularity, scope_dims = policy.build_identity(
            scan_id=str(scan_id),
            asset_id=str(asset_id),
            vulnerability_class=class_code,
            payload=payload,
        )
        phase7_enabled = (
            settings.phase7_requirement_granularity_enabled
            and not settings.phase7_legacy_requirement_merge_only
        )

        req = (
            await self.session.execute(
                select(TestRequirement).where(
                    TestRequirement.matrix_id == matrix.id,
                    TestRequirement.vulnerability_class_id == vc.id,
                    TestRequirement.uniqueness_key == ukey,
                )
            )
        ).scalar_one_or_none()

        scope_facts = scope_from_key_parts(**payload)
        trace = {
            "reason": result.reason_codes[0] if result.reason_codes else "CORRELATION",
            "rule_id": result.rule_id,
            "rule_version": result.rule_version,
            "facts": scope_facts,
        }
        if payload.get("parameter_name"):
            trace["parameter_scopes"] = [scope_facts]

        if req:
            summary.duplicate_suppression_count += 1
            req.source_event_ids = list(dict.fromkeys([*(req.source_event_ids or []), str(event_id)]))
            if payload.get("hypothesis_id"):
                req.source_hypothesis_ids = list(
                    dict.fromkeys(
                        [*(req.source_hypothesis_ids or []), str(payload["hypothesis_id"])]
                    )
                )
            req.reasoning_trace = {**(req.reasoning_trace or {}), **trace}
            if req.coverage_status == TestRequirementCoverageStatus.TESTED_NO_EVIDENCE.value:
                req.coverage_status = TestRequirementCoverageStatus.NOT_TESTED.value
                req.next_action = TestRequirementNextAction.PLAN_AUTOMATED.value
                summary.meaningful_change = True
            return str(req.id)

        base_req = (
            await self.session.execute(
                select(TestRequirement).where(
                    TestRequirement.matrix_id == matrix.id,
                    TestRequirement.vulnerability_class_id == vc.id,
                    TestRequirement.uniqueness_key == "",
                )
            )
        ).scalar_one_or_none()
        if not base_req:
            base_req = (
                await self.session.execute(
                    select(TestRequirement)
                    .where(
                        TestRequirement.matrix_id == matrix.id,
                        TestRequirement.vulnerability_class_id == vc.id,
                    )
                    .order_by(TestRequirement.created_at.asc())
                    .limit(1)
                )
            ).scalar_one_or_none()
        if base_req and ukey and base_req.uniqueness_key != ukey:
            decision = policy.evaluate(
                existing_uniqueness_key=base_req.uniqueness_key or "",
                existing_granularity=base_req.scope_granularity or "SURFACE",
                new_uniqueness_key=ukey,
                new_granularity=granularity,
                phase7_enabled=phase7_enabled,
            )
            policy.log_decision(
                scan_id=str(scan_id),
                requirement_id=str(base_req.id),
                decision=decision,
                uniqueness_key=ukey,
            )
            if decision.should_create_distinct_row:
                return await self._insert_requirement(
                    matrix=matrix,
                    vc=vc,
                    ukey=ukey,
                    granularity=granularity,
                    scope_dims=scope_dims,
                    trace=trace,
                    payload=payload,
                    event_id=event_id,
                    result=result,
                    summary=summary,
                    is_legacy_merged=False,
                )
            scopes = list((base_req.reasoning_trace or {}).get("parameter_scopes", []))
            if scope_facts not in scopes:
                scopes.append(scope_facts)
                base_req.reasoning_trace = {
                    **(base_req.reasoning_trace or {}),
                    **trace,
                    "parameter_scopes": scopes,
                }
                base_req.is_legacy_merged = True
                base_req.source_event_ids = list(
                    dict.fromkeys([*(base_req.source_event_ids or []), str(event_id)])
                )
                summary.meaningful_change = True
            else:
                summary.duplicate_suppression_count += 1
            return str(base_req.id)

        return await self._insert_requirement(
            matrix=matrix,
            vc=vc,
            ukey=ukey,
            granularity=granularity,
            scope_dims=scope_dims,
            trace=trace,
            payload=payload,
            event_id=event_id,
            result=result,
            summary=summary,
            is_legacy_merged=False,
        )

    async def _insert_requirement(
        self,
        *,
        matrix: AssetTestMatrix,
        vc: VulnerabilityClass,
        ukey: str,
        granularity: str,
        scope_dims: dict[str, Any],
        trace: dict[str, Any],
        payload: dict[str, Any],
        event_id: uuid.UUID,
        result: CorrelationResult,
        summary: ApplySummary,
        is_legacy_merged: bool,
    ) -> str:
        testing_mode = payload.get("testing_mode", TestingMode.AUTOMATED.value)
        req = TestRequirement(
            matrix_id=matrix.id,
            vulnerability_class_id=vc.id,
            applicability_state="APPLICABLE",
            testing_mode=testing_mode,
            coverage_status=TestRequirementCoverageStatus.NOT_TESTED.value,
            required_evidence={"correlation": trace},
            eligible_capabilities=[payload.get("capability_group", "TEMPLATE_BASED_ASSESSMENT")],
            source_rule_ids=[result.rule_id],
            reasoning_trace=trace,
            uniqueness_key=ukey,
            scope_granularity=granularity,
            scope_dimensions=scope_dims,
            is_legacy_merged=is_legacy_merged,
            source_event_ids=[str(event_id)],
            source_hypothesis_ids=(
                [str(payload["hypothesis_id"])] if payload.get("hypothesis_id") else []
            ),
            next_action={
                TestingMode.AUTOMATED.value: TestRequirementNextAction.PLAN_AUTOMATED.value,
                TestingMode.ASSISTED.value: TestRequirementNextAction.PLAN_ASSISTED.value,
            }.get(testing_mode, TestRequirementNextAction.PLAN_MANUAL.value),
        )
        self.session.add(req)
        await self.session.flush()
        summary.created_test_requirement_ids.append(str(req.id))
        return str(req.id)

    async def _upsert_relationship(
        self, scan_id: uuid.UUID, result: CorrelationResult, summary: ApplySummary
    ) -> str | None:
        payload = result.payload
        source = payload.get("source_asset_id")
        target = payload.get("target_asset_id")
        rel_type = payload.get("relationship_type")
        if not source or not target or not rel_type:
            return None
        existing = (
            await self.session.execute(
                select(Relationship).where(
                    Relationship.scan_id == scan_id,
                    Relationship.source_asset_id == uuid.UUID(str(source)),
                    Relationship.target_asset_id == uuid.UUID(str(target)),
                    Relationship.relationship_type == rel_type,
                )
            )
        ).scalar_one_or_none()
        if existing:
            existing.last_seen = datetime.now(UTC)
            existing.confidence = max(existing.confidence, result.confidence)
            summary.duplicate_suppression_count += 1
            return str(existing.id)
        rel = Relationship(
            scan_id=scan_id,
            source_asset_id=uuid.UUID(str(source)),
            target_asset_id=uuid.UUID(str(target)),
            relationship_type=rel_type,
            confidence=result.confidence,
            evidence_ids=list(result.supporting_evidence_ids),
        )
        self.session.add(rel)
        await self.session.flush()
        summary.created_relationship_ids.append(str(rel.id))
        return str(rel.id)

    async def _hypothesis_count(self, scan_id: uuid.UUID) -> int:
        from vapt_platform.db.tables.models import CorrelationScanState

        state = (
            await self.session.execute(
                select(CorrelationScanState).where(CorrelationScanState.scan_id == scan_id)
            )
        ).scalar_one_or_none()
        return state.hypotheses_created if state else 0

    async def _requirement_count(self, scan_id: uuid.UUID) -> int:
        from vapt_platform.db.tables.models import CorrelationScanState

        state = (
            await self.session.execute(
                select(CorrelationScanState).where(CorrelationScanState.scan_id == scan_id)
            )
        ).scalar_one_or_none()
        return state.requirements_created if state else 0
