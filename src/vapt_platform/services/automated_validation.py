"""Safe automated execution for approved assessment test plans."""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from vapt_platform.controller.recon_controller import ReconController
from vapt_platform.db.tables.models import (
    Asset,
    AssetVulnerabilityApplicability,
    CapabilityProvider,
    EvidencePackage,
    EvidenceQualityDecision,
    Hypothesis,
    Observation,
    RawArtifact,
    Scan,
    ScopeSnapshot,
    Task,
    TaskRun,
    TestExecution,
    TestPlan,
    ValidationTask,
)
from vapt_platform.domain.enums import (
    ApplicabilityState,
    AssetType,
    Capability,
    EventType,
    HypothesisStatus,
    SafetyClass,
    TaskStatus,
    TestingMode,
    TestPlanStatus,
    ValidationTaskStatus,
)
from vapt_platform.engines.assessment import (
    AssessmentCompletionEvaluator,
    TestMatrixEngine,
    VerdictEngine,
)
from vapt_platform.scope.manager import ScopeManager, ScopeRuleData


@dataclass
class AutomatedPlanRun:
    plan_id: uuid.UUID
    status: str
    execution_id: uuid.UUID | None = None
    task_id: uuid.UUID | None = None
    task_run_id: uuid.UUID | None = None
    finding_candidates: int = 0
    reused_task: bool = False
    reason: str | None = None


class AutomatedValidationOrchestrator:
    """Executes only pre-approved PASSIVE or LOW_IMPACT automated plans."""

    _ALLOWED_PLAN_STATUSES = {
        TestPlanStatus.APPROVED.value,
        TestPlanStatus.SCHEDULED.value,
        TestPlanStatus.EXECUTING.value,
    }
    _ALLOWED_SAFETY = {
        SafetyClass.PASSIVE.value,
        SafetyClass.LOW_IMPACT.value,
    }

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def execute_scan(self, scan_id: uuid.UUID) -> list[AutomatedPlanRun]:
        plans = list(
            (
                await self.session.execute(
                    select(TestPlan)
                    .where(
                        TestPlan.scan_id == scan_id,
                        TestPlan.testing_mode == TestingMode.AUTOMATED.value,
                    )
                    .order_by(TestPlan.priority.desc(), TestPlan.created_at)
                )
            )
            .scalars()
            .all()
        )
        controller = await self._controller(scan_id)
        results = [await self.execute_plan(plan, controller) for plan in plans]
        await AssessmentCompletionEvaluator(self.session).evaluate(scan_id)
        return results

    async def execute_plan(
        self,
        plan: TestPlan,
        controller: ReconController | None = None,
    ) -> AutomatedPlanRun:
        existing = (
            await self.session.execute(
                select(TestExecution)
                .where(TestExecution.test_plan_id == plan.id)
                .order_by(TestExecution.executed_at.desc())
            )
        ).scalars().first()
        if existing:
            return AutomatedPlanRun(
                plan_id=plan.id,
                status=existing.status,
                execution_id=existing.id,
                task_run_id=existing.task_run_id,
                finding_candidates=int(
                    (existing.result_summary or {}).get("finding_candidate_count", 0)
                ),
                reused_task=True,
                reason="Existing test execution reused",
            )
        if plan.testing_mode != TestingMode.AUTOMATED.value:
            return AutomatedPlanRun(
                plan_id=plan.id,
                status="SKIPPED",
                reason="Plan is not automated",
            )
        if plan.status not in self._ALLOWED_PLAN_STATUSES:
            return AutomatedPlanRun(
                plan_id=plan.id,
                status="SKIPPED",
                reason=f"Plan status {plan.status} is not executable",
            )
        if plan.safety_class not in self._ALLOWED_SAFETY:
            return AutomatedPlanRun(
                plan_id=plan.id,
                status="SKIPPED",
                reason=f"Safety class {plan.safety_class} requires analyst approval",
            )
        if plan.authorization_requirement != "PRE_APPROVED":
            return AutomatedPlanRun(
                plan_id=plan.id,
                status="SKIPPED",
                reason="Plan is not pre-approved",
            )

        target = await self._target_for_plan(plan)
        if not target:
            plan.status = TestPlanStatus.FAILED.value
            return AutomatedPlanRun(
                plan_id=plan.id,
                status=TestPlanStatus.FAILED.value,
                reason="No executable target could be derived from the plan assets",
            )

        controller = controller or await self._controller(plan.scan_id)
        plan.status = TestPlanStatus.EXECUTING.value
        selected: tuple[Task, TaskRun, bool] | None = None
        selected_capability: Capability | None = None
        for capability_code in plan.required_capabilities or []:
            try:
                capability = Capability(capability_code)
            except ValueError:
                continue
            selected = await self._resolve_task_run(controller, plan, capability, target)
            if selected:
                selected_capability = capability
                break

        if not selected or not selected_capability:
            plan.status = TestPlanStatus.FAILED.value
            await self._set_applicability(
                plan,
                ApplicabilityState.INCONCLUSIVE.value,
                [],
                "No eligible provider was available for this automated plan.",
            )
            return AutomatedPlanRun(
                plan_id=plan.id,
                status=TestPlanStatus.FAILED.value,
                reason="No eligible capability provider or reusable task run",
            )

        task, task_run, reused_task = selected
        await self.session.flush()
        artifacts = list(
            (
                await self.session.execute(
                    select(RawArtifact).where(RawArtifact.task_run_id == task_run.id)
                )
            )
            .scalars()
            .all()
        )
        observations = list(
            (
                await self.session.execute(
                    select(Observation).where(
                        Observation.scan_id == plan.scan_id,
                        Observation.source_id == str(task_run.id),
                    )
                )
            )
            .scalars()
            .all()
        )
        provider = (
            await self.session.get(CapabilityProvider, task.capability_provider_id)
            if task.capability_provider_id
            else None
        )
        decision = (
            await self.session.get(
                EvidenceQualityDecision, task.evidence_quality_decision_id
            )
            if task.evidence_quality_decision_id
            else None
        )
        candidates, conclusive = self._extract_finding_candidates(
            artifacts,
            provider.provider_name if provider else "",
            task_run.exit_code,
        )
        evidence_ids = [
            *(str(artifact.id) for artifact in artifacts),
            *(str(observation.id) for observation in observations),
        ]
        if decision:
            evidence_ids.append(str(decision.id))
        evidence_ids = list(dict.fromkeys(evidence_ids))

        execution_status = (
            "COMPLETED" if task_run.exit_code == 0 else "FAILED"
        )
        execution = TestExecution(
            test_plan_id=plan.id,
            task_run_id=task_run.id,
            provider_id=task.capability_provider_id,
            template_id=(
                candidates[0].get("template_id") if len(candidates) == 1 else None
            ),
            status=execution_status,
            result_summary={
                "capability": selected_capability.value,
                "task_id": str(task.id),
                "exit_code": task_run.exit_code,
                "evidence_quality_status": decision.status if decision else None,
                "finding_candidate_count": len(candidates),
                "finding_candidates": candidates,
                "conclusive": conclusive,
                "reused_task": reused_task,
            },
            evidence_ids=evidence_ids,
        )
        self.session.add(execution)
        await self.session.flush()

        if task_run.exit_code != 0 or not conclusive:
            plan.status = TestPlanStatus.FAILED.value
            await self._set_applicability(
                plan,
                ApplicabilityState.INCONCLUSIVE.value,
                evidence_ids,
                "Automated execution did not produce conclusive evidence.",
            )
            hypothesis = await self._hypothesis(plan)
            if hypothesis:
                hypothesis.status = HypothesisStatus.INCONCLUSIVE.value
        elif candidates:
            plan.status = TestPlanStatus.COMPLETED.value
            await self._set_applicability(
                plan,
                ApplicabilityState.PARTIALLY_TESTED.value,
                evidence_ids,
                "Automated findings require analyst validation before confirmation.",
            )
            await self._create_review_task(plan, execution, candidates, evidence_ids)
        else:
            plan.status = TestPlanStatus.COMPLETED.value
            hypothesis = await self._hypothesis(plan)
            if hypothesis:
                await VerdictEngine(self.session).evaluate_hypothesis(
                    hypothesis.id,
                    "REJECTED",
                    evidence_ids,
                    test_plan_id=plan.id,
                    test_execution_id=execution.id,
                    recorded_by="automated-validation",
                )
            else:
                await self._set_applicability(
                    plan,
                    ApplicabilityState.TESTED_NO_EVIDENCE.value,
                    evidence_ids,
                    "Automated execution completed with no finding candidates.",
                )

        await controller.emit_event(
            plan.scan_id,
            EventType.TEST_EXECUTION_COMPLETED,
            {
                "execution_id": str(execution.id),
                "plan_id": str(plan.id),
                "task_run_id": str(task_run.id),
                "status": execution.status,
                "finding_candidate_count": len(candidates),
            },
            uuid.uuid4(),
            causation_id=task_run.id,
        )
        return AutomatedPlanRun(
            plan_id=plan.id,
            status=execution.status,
            execution_id=execution.id,
            task_id=task.id,
            task_run_id=task_run.id,
            finding_candidates=len(candidates),
            reused_task=reused_task,
        )

    async def _controller(self, scan_id: uuid.UUID) -> ReconController:
        scan = await self.session.get(Scan, scan_id)
        if not scan:
            raise ValueError("Scan not found")
        snapshot = await self.session.get(ScopeSnapshot, scan.scope_snapshot_id)
        rules = [ScopeRuleData(**rule) for rule in (snapshot.rules if snapshot else [])]
        return ReconController(self.session, ScopeManager(rules))

    async def _target_for_plan(self, plan: TestPlan) -> dict[str, Any] | None:
        for asset_ref in plan.asset_ids or []:
            try:
                asset_id = uuid.UUID(asset_ref)
            except (TypeError, ValueError):
                continue
            asset = await self.session.get(Asset, asset_id)
            if not asset:
                continue
            metadata = asset.metadata_ or {}
            if asset.asset_type in {
                AssetType.WEB_APPLICATION.value,
                AssetType.ENDPOINT.value,
            }:
                url = (
                    metadata.get("base_url")
                    or metadata.get("url")
                    or asset.normalized_key
                )
                hostname = urlparse(url).hostname
                return {
                    "url": url,
                    "hostname": hostname,
                    "asset_id": str(asset.id),
                }
            if asset.asset_type in {
                AssetType.HOSTNAME.value,
                AssetType.DOMAIN.value,
            }:
                return {
                    "hostname": asset.normalized_key,
                    "domain": asset.normalized_key,
                    "asset_id": str(asset.id),
                }
            if asset.asset_type == AssetType.IP_ADDRESS.value:
                return {"ip": asset.normalized_key, "asset_id": str(asset.id)}
        return None

    async def _resolve_task_run(
        self,
        controller: ReconController,
        plan: TestPlan,
        capability: Capability,
        target: dict[str, Any],
    ) -> tuple[Task, TaskRun, bool] | None:
        tasks = list(
            (
                await self.session.execute(
                    select(Task)
                    .where(
                        Task.scan_id == plan.scan_id,
                        Task.capability == capability.value,
                    )
                    .order_by(Task.created_at.desc())
                )
            )
            .scalars()
            .all()
        )
        for task in tasks:
            if not self._targets_overlap(task.target_descriptor or {}, target):
                continue
            if task.status == TaskStatus.COMPLETED.value:
                run = await self._latest_task_run(task.id)
                if run:
                    return task, run, True
            if task.status == TaskStatus.READY.value:
                run = await controller.execute_task(task.id, uuid.uuid4())
                return task, run, True

        task = await controller.create_task(
            plan.scan_id,
            capability,
            target,
            uuid.uuid4(),
            configuration_salt=f"test-plan-{plan.id}-{capability.value}",
        )
        if not task:
            return None
        run = await controller.execute_task(task.id, uuid.uuid4())
        return task, run, False

    async def _latest_task_run(self, task_id: uuid.UUID) -> TaskRun | None:
        return (
            await self.session.execute(
                select(TaskRun)
                .where(TaskRun.task_id == task_id)
                .order_by(TaskRun.started_at.desc())
            )
        ).scalars().first()

    async def _create_review_task(
        self,
        plan: TestPlan,
        execution: TestExecution,
        candidates: list[dict[str, Any]],
        evidence_ids: list[str],
    ) -> None:
        existing = (
            await self.session.execute(
                select(ValidationTask).where(ValidationTask.test_plan_id == plan.id)
            )
        ).scalars().first()
        if existing:
            return
        hypothesis = await self._hypothesis(plan)
        if hypothesis:
            hypothesis.status = HypothesisStatus.VALIDATION_IN_PROGRESS.value
        package = EvidencePackage(
            scan_id=plan.scan_id,
            hypothesis_id=hypothesis.id if hypothesis else None,
            package_data={
                "test_execution_id": str(execution.id),
                "affected_assets": plan.asset_ids,
                "vulnerability_class_ids": plan.vulnerability_class_ids,
                "finding_candidates": candidates,
                "evidence_ids": evidence_ids,
                "validation_goal": "Review automated finding candidates",
            },
        )
        self.session.add(package)
        await self.session.flush()
        task = ValidationTask(
            scan_id=plan.scan_id,
            hypothesis_id=hypothesis.id if hypothesis else None,
            test_plan_id=plan.id,
            evidence_package_id=package.id,
            asset_ids=list(plan.asset_ids or []),
            validation_goal="Validate automated finding candidates before confirmation",
            required_evidence=dict(plan.evidence_requirements or {}),
            suggested_safe_checks=[
                "Review the linked raw artifact and scanner context",
                "Reproduce only within the authorized scope and safety policy",
                "Record evidence IDs before confirming or rejecting",
            ],
            testing_mode=TestingMode.ASSISTED.value,
            status=ValidationTaskStatus.OPEN.value,
        )
        self.session.add(task)
        await self.session.flush()
        package.validation_task_id = task.id

    async def _set_applicability(
        self,
        plan: TestPlan,
        state: str,
        evidence_ids: list[str],
        explanation: str,
    ) -> None:
        asset_ids = self._uuid_list(plan.asset_ids or [])
        class_ids = self._uuid_list(plan.vulnerability_class_ids or [])
        if not asset_ids or not class_ids:
            return
        rows = list(
            (
                await self.session.execute(
                    select(AssetVulnerabilityApplicability).where(
                        AssetVulnerabilityApplicability.scan_id == plan.scan_id,
                        AssetVulnerabilityApplicability.asset_id.in_(asset_ids),
                        AssetVulnerabilityApplicability.vulnerability_class_id.in_(
                            class_ids
                        ),
                    )
                )
            )
            .scalars()
            .all()
        )
        for row in rows:
            row.applicability_state = state
            row.supporting_evidence_ids = list(
                dict.fromkeys([*(row.supporting_evidence_ids or []), *evidence_ids])
            )
            row.rule_ids = list(
                dict.fromkeys([*(row.rule_ids or []), "automated-validation"])
            )
            row.explanation = explanation
        for asset_id in asset_ids:
            await TestMatrixEngine(self.session).build(plan.scan_id, asset_id)

    async def _hypothesis(self, plan: TestPlan) -> Hypothesis | None:
        return (
            await self.session.get(Hypothesis, plan.hypothesis_id)
            if plan.hypothesis_id
            else None
        )

    @staticmethod
    def _targets_overlap(left: dict[str, Any], right: dict[str, Any]) -> bool:
        left_values = AutomatedValidationOrchestrator._target_values(left)
        right_values = AutomatedValidationOrchestrator._target_values(right)
        return bool(left_values & right_values)

    @staticmethod
    def _target_values(target: dict[str, Any]) -> set[str]:
        values: set[str] = set()
        for key in ("url", "hostname", "domain", "ip"):
            value = target.get(key)
            if not value:
                continue
            normalized = str(value).strip().lower().rstrip("/")
            values.add(normalized)
            if key == "url":
                hostname = urlparse(normalized).hostname
                if hostname:
                    values.add(hostname)
        return values

    @staticmethod
    def _uuid_list(values: list[str]) -> list[uuid.UUID]:
        parsed: list[uuid.UUID] = []
        for value in values:
            try:
                parsed.append(uuid.UUID(value))
            except (TypeError, ValueError):
                continue
        return parsed

    @staticmethod
    def _extract_finding_candidates(
        artifacts: list[RawArtifact],
        provider_name: str,
        exit_code: int | None,
    ) -> tuple[list[dict[str, Any]], bool]:
        candidates: list[dict[str, Any]] = []
        parsed_result = False
        for artifact in artifacts:
            content = (artifact.content or "").strip()
            if not content:
                continue
            records: list[Any] = []
            try:
                records = [json.loads(content)]
            except json.JSONDecodeError:
                for line in content.splitlines():
                    try:
                        records.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
            for record in records:
                if isinstance(record, dict) and isinstance(record.get("findings"), list):
                    parsed_result = True
                    candidates.extend(
                        AutomatedValidationOrchestrator._normalize_candidate(item)
                        for item in record["findings"]
                        if isinstance(item, dict)
                    )
                elif isinstance(record, list):
                    parsed_result = True
                    candidates.extend(
                        AutomatedValidationOrchestrator._normalize_candidate(item)
                        for item in record
                        if isinstance(item, dict)
                    )
                elif isinstance(record, dict) and (
                    record.get("template-id")
                    or record.get("template_id")
                    or record.get("template")
                ):
                    parsed_result = True
                    candidates.append(
                        AutomatedValidationOrchestrator._normalize_candidate(record)
                    )
        if "nuclei" in provider_name.lower() and exit_code == 0:
            parsed_result = True
        return candidates, parsed_result

    @staticmethod
    def _normalize_candidate(candidate: dict[str, Any]) -> dict[str, Any]:
        info = candidate.get("info") if isinstance(candidate.get("info"), dict) else {}
        return {
            "template_id": (
                candidate.get("template-id")
                or candidate.get("template_id")
                or candidate.get("template")
            ),
            "name": info.get("name") or candidate.get("name"),
            "severity": info.get("severity") or candidate.get("severity"),
            "matched_at": (
                candidate.get("matched-at")
                or candidate.get("matched_at")
                or candidate.get("host")
            ),
            "type": candidate.get("type"),
        }
