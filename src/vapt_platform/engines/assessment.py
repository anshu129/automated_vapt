"""Assessment engines."""

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from vapt_platform.db.tables.models import (
    AssessmentCompletionRecord,
    Asset,
    AssetTestMatrix,
    AssetVulnerabilityApplicability,
    ConfirmedFinding,
    Event,
    EvidenceLink,
    EvidencePackage,
    Hypothesis,
    TestExecution,
    TestPlan,
    TestRequirement,
    ValidationResult,
    ValidationTask,
    Verdict,
    VulnerabilityClass,
)
from vapt_platform.domain.enums import (
    ApplicabilityState,
    AssetType,
    Capability,
    CompletionStatus,
    HypothesisStatus,
    SafetyClass,
    TestingMode,
    TestPlanStatus,
    TestRequirementCoverageStatus,
    TestRequirementNextAction,
    ValidationTaskStatus,
    VerdictStatus,
    default_safety_for,
)
from vapt_platform.engines.surface_completeness import SurfaceCompletenessEngine

MATRIX_RULE_VERSION = "1.0"

_PLAN_CREATED_STATUSES = {
    TestPlanStatus.DRAFT.value,
    TestPlanStatus.PENDING_APPROVAL.value,
    TestPlanStatus.APPROVED.value,
    TestPlanStatus.SCHEDULED.value,
}

_PRESERVED_COVERAGE_STATUSES = {
    TestRequirementCoverageStatus.PLANNED.value,
    TestRequirementCoverageStatus.TESTING.value,
    TestRequirementCoverageStatus.TESTED_NO_EVIDENCE.value,
    TestRequirementCoverageStatus.PARTIALLY_TESTED.value,
    TestRequirementCoverageStatus.CONFIRMED_ISSUE.value,
    TestRequirementCoverageStatus.INCONCLUSIVE.value,
}

_ACTIVE_PLAN_STATUSES = {
    TestPlanStatus.DRAFT.value,
    TestPlanStatus.PENDING_APPROVAL.value,
    TestPlanStatus.APPROVED.value,
    TestPlanStatus.SCHEDULED.value,
    TestPlanStatus.EXECUTING.value,
    TestPlanStatus.COMPLETED.value,
}

_SAFETY_ORDER = {
    SafetyClass.PASSIVE.value: 0,
    SafetyClass.LOW_IMPACT.value: 1,
    SafetyClass.STATE_CHANGING.value: 2,
    SafetyClass.DESTRUCTIVE.value: 3,
    SafetyClass.PROHIBITED.value: 4,
}

_CLASS_TEST_PROFILES: dict[str, dict[str, Any]] = {
    "SECURITY_HEADERS": {
        "testing_mode": TestingMode.AUTOMATED.value,
        "eligible_capabilities": [
            Capability.WEB_PASSIVE_ASSESSMENT.value,
            Capability.TEMPLATE_BASED_ASSESSMENT.value,
        ],
        "required": [
            {"evidence_type": "HTTP_RESPONSE_HEADERS", "minimum": 1},
            {"evidence_type": "HEADER_POLICY_EVALUATION", "minimum": 1},
        ],
        "completion": "Security headers assessed from HTTP response evidence.",
    },
    "TLS_CONFIGURATION": {
        "testing_mode": TestingMode.AUTOMATED.value,
        "eligible_capabilities": [
            Capability.TLS_CHARACTERIZATION.value,
            Capability.TEMPLATE_BASED_ASSESSMENT.value,
        ],
        "required": [
            {"evidence_type": "TLS_HANDSHAKE", "minimum": 1},
            {"evidence_type": "CERTIFICATE_METADATA", "minimum": 1},
        ],
        "completion": "TLS configuration assessed from protocol and certificate evidence.",
    },
    "TRANSPORT_SECURITY": {
        "testing_mode": TestingMode.AUTOMATED.value,
        "eligible_capabilities": [
            Capability.TLS_CHARACTERIZATION.value,
            Capability.WEB_PASSIVE_ASSESSMENT.value,
        ],
        "required": [
            {"evidence_type": "TRANSPORT_POLICY", "minimum": 1},
            {"evidence_type": "HTTP_RESPONSE_HEADERS", "minimum": 1},
        ],
        "completion": "Transport security assessed without changing application state.",
    },
    "KNOWN_COMPONENT_VULNERABILITY": {
        "testing_mode": TestingMode.ASSISTED.value,
        "eligible_capabilities": [
            Capability.TECHNOLOGY_IDENTIFICATION.value,
            Capability.TEMPLATE_BASED_ASSESSMENT.value,
        ],
        "required": [
            {"evidence_type": "VERSIONED_TECHNOLOGY", "minimum": 1},
            {"evidence_type": "TEMPLATE_MATCH_OR_NEGATIVE_EVIDENCE", "minimum": 1},
        ],
        "completion": "Component testing requires version confidence or scanner evidence.",
    },
    "INPUT_VALIDATION": {
        "testing_mode": TestingMode.ASSISTED.value,
        "eligible_capabilities": [
            Capability.PARAMETER_DISCOVERY.value,
            Capability.WEB_ACTIVE_ASSESSMENT.value,
        ],
        "required": [
            {"evidence_type": "PARAMETER_INVENTORY", "minimum": 1},
            {"evidence_type": "VALIDATION_RESULT", "minimum": 1},
        ],
        "completion": "Input validation requires parameter coverage and validation evidence.",
    },
    "INJECTION_CLASS": {
        "testing_mode": TestingMode.ASSISTED.value,
        "eligible_capabilities": [
            Capability.PARAMETER_DISCOVERY.value,
            Capability.WEB_ACTIVE_ASSESSMENT.value,
        ],
        "required": [
            {"evidence_type": "PARAMETER_INVENTORY", "minimum": 1},
            {"evidence_type": "CONTROLLED_TEST_RESULT", "minimum": 1},
        ],
        "completion": "Injection coverage requires parameter inventory and controlled tests.",
    },
    "GRAPHQL_SECURITY": {
        "testing_mode": TestingMode.ASSISTED.value,
        "eligible_capabilities": [
            Capability.GRAPHQL_SCHEMA_INVENTORY.value,
            Capability.WEB_ACTIVE_ASSESSMENT.value,
        ],
        "required": [
            {"evidence_type": "GRAPHQL_SCHEMA", "minimum": 1},
            {"evidence_type": "AUTHORIZATION_REVIEW", "minimum": 1},
        ],
        "completion": "GraphQL testing requires schema and authorization context.",
    },
    "UPLOAD_SECURITY": {
        "testing_mode": TestingMode.ASSISTED.value,
        "eligible_capabilities": [
            Capability.CONTENT_DISCOVERY.value,
            Capability.WEB_ACTIVE_ASSESSMENT.value,
        ],
        "required": [
            {"evidence_type": "UPLOAD_SURFACE", "minimum": 1},
            {"evidence_type": "VALIDATION_RESULT", "minimum": 1},
        ],
        "completion": "Upload testing requires explicit upload surface validation evidence.",
    },
    "FILE_HANDLING": {
        "testing_mode": TestingMode.ASSISTED.value,
        "eligible_capabilities": [
            Capability.CONTENT_DISCOVERY.value,
            Capability.WEB_ACTIVE_ASSESSMENT.value,
        ],
        "required": [
            {"evidence_type": "FILE_SURFACE", "minimum": 1},
            {"evidence_type": "VALIDATION_RESULT", "minimum": 1},
        ],
        "completion": "File handling requires analyst-reviewed validation evidence.",
    },
}

_MANUAL_CLASS_EVIDENCE: dict[str, list[dict[str, Any]]] = {
    "AUTHENTICATION": [{"evidence_type": "AUTH_FLOW_REVIEW", "minimum": 1}],
    "SESSION_MANAGEMENT": [{"evidence_type": "SESSION_FLOW_REVIEW", "minimum": 1}],
    "AUTHORIZATION": [{"evidence_type": "AUTHORIZATION_REVIEW", "minimum": 1}],
    "OBJECT_LEVEL_AUTHORIZATION": [{"evidence_type": "OBJECT_ACCESS_REVIEW", "minimum": 1}],
    "CROSS_APPLICATION_AUTHORIZATION": [{"evidence_type": "CROSS_APP_ACCESS_REVIEW", "minimum": 1}],
    "BUSINESS_LOGIC": [{"evidence_type": "BUSINESS_LOGIC_REVIEW", "minimum": 1}],
}


class TestMatrixEngine:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def build(self, scan_id: uuid.UUID, asset_id: uuid.UUID) -> AssetTestMatrix:
        stmt = select(AssetTestMatrix).where(
            AssetTestMatrix.scan_id == scan_id,
            AssetTestMatrix.asset_id == asset_id,
        )
        matrix = (await self.session.execute(stmt)).scalar_one_or_none()
        if not matrix:
            matrix = AssetTestMatrix(scan_id=scan_id, asset_id=asset_id)
            self.session.add(matrix)
            await self.session.flush()

        class_stmt = select(VulnerabilityClass).where(VulnerabilityClass.active.is_(True))
        classes = list((await self.session.execute(class_stmt)).scalars().all())

        app_stmt = select(AssetVulnerabilityApplicability).where(
            AssetVulnerabilityApplicability.scan_id == scan_id,
            AssetVulnerabilityApplicability.asset_id == asset_id,
        )
        applicabilities = list((await self.session.execute(app_stmt)).scalars().all())
        app_by_class = {app.vulnerability_class_id: app for app in applicabilities}

        for vc in sorted(classes, key=lambda row: row.class_code):
            app = app_by_class.get(vc.id)
            applicability_state = (
                app.applicability_state if app else ApplicabilityState.NOT_APPLICABLE.value
            )
            profile = _class_profile(vc)
            req_stmt = select(TestRequirement).where(
                TestRequirement.matrix_id == matrix.id,
                TestRequirement.vulnerability_class_id == vc.id,
            )
            req = (await self.session.execute(req_stmt)).scalar_one_or_none()
            if not req:
                req = TestRequirement(
                    matrix_id=matrix.id,
                    vulnerability_class_id=vc.id,
                    applicability_state=applicability_state,
                    testing_mode=profile["testing_mode"],
                    coverage_status=TestRequirementCoverageStatus.NOT_TESTED.value,
                    required_evidence={},
                    eligible_capabilities=[],
                    confidence=app.confidence if app else 0.1,
                    next_action=TestRequirementNextAction.NONE.value,
                )
                self.session.add(req)

            latest_plan = await self._latest_plan(scan_id, asset_id, vc.id)
            latest_execution = await self._latest_execution(latest_plan.id) if latest_plan else None

            req.applicability_state = applicability_state
            req.testing_mode = profile["testing_mode"]
            req.required_evidence = _required_evidence_payload(vc, app, profile)
            req.eligible_capabilities = list(profile["eligible_capabilities"])
            req.confidence = app.confidence if app else 0.1
            req.latest_result_id = latest_execution.id if latest_execution else None
            req.coverage_status = self._coverage_status(
                applicability_state,
                req.coverage_status,
                latest_plan,
                latest_execution,
            )
            req.next_action = self._next_action(
                req.coverage_status,
                req.testing_mode,
                latest_plan.status if latest_plan else None,
            )

        matrix.computed_at = datetime.now(UTC)
        matrix.rule_version = MATRIX_RULE_VERSION
        return matrix

    async def _latest_plan(
        self,
        scan_id: uuid.UUID,
        asset_id: uuid.UUID,
        vulnerability_class_id: uuid.UUID,
    ) -> TestPlan | None:
        stmt = (
            select(TestPlan)
            .where(TestPlan.scan_id == scan_id)
            .order_by(
                TestPlan.updated_at.desc(),
                TestPlan.created_at.desc(),
            )
        )
        plans = list((await self.session.execute(stmt)).scalars().all())
        asset_ref = str(asset_id)
        class_ref = str(vulnerability_class_id)
        for plan in plans:
            if asset_ref not in (plan.asset_ids or []):
                continue
            if class_ref not in (plan.vulnerability_class_ids or []):
                continue
            return plan
        return None

    async def _latest_execution(self, plan_id: uuid.UUID) -> TestExecution | None:
        stmt = (
            select(TestExecution)
            .where(TestExecution.test_plan_id == plan_id)
            .order_by(TestExecution.executed_at.desc())
        )
        return (await self.session.execute(stmt)).scalars().first()

    def _coverage_status(
        self,
        applicability_state: str,
        current_status: str,
        latest_plan: TestPlan | None,
        latest_execution: TestExecution | None,
    ) -> str:
        if applicability_state == ApplicabilityState.NOT_APPLICABLE.value:
            return TestRequirementCoverageStatus.NOT_APPLICABLE.value

        state_map = {
            ApplicabilityState.TESTED_NO_EVIDENCE.value: (
                TestRequirementCoverageStatus.TESTED_NO_EVIDENCE.value
            ),
            ApplicabilityState.PARTIALLY_TESTED.value: (
                TestRequirementCoverageStatus.PARTIALLY_TESTED.value
            ),
            ApplicabilityState.CONFIRMED.value: (
                TestRequirementCoverageStatus.CONFIRMED_ISSUE.value
            ),
            ApplicabilityState.INCONCLUSIVE.value: TestRequirementCoverageStatus.INCONCLUSIVE.value,
        }
        if applicability_state in state_map:
            return state_map[applicability_state]

        if latest_execution:
            if latest_execution.status in ("RUNNING", "EXECUTING"):
                return TestRequirementCoverageStatus.TESTING.value
            if latest_execution.status == "COMPLETED":
                return TestRequirementCoverageStatus.TESTED_NO_EVIDENCE.value
            if latest_execution.status in ("FAILED_RETRYABLE", "FAILED_TERMINAL", "FAILED"):
                return TestRequirementCoverageStatus.INCONCLUSIVE.value

        if latest_plan:
            if latest_plan.status in _PLAN_CREATED_STATUSES:
                return TestRequirementCoverageStatus.PLANNED.value
            if latest_plan.status == TestPlanStatus.EXECUTING.value:
                return TestRequirementCoverageStatus.TESTING.value
            if latest_plan.status == TestPlanStatus.COMPLETED.value:
                return TestRequirementCoverageStatus.TESTED_NO_EVIDENCE.value
            if latest_plan.status == TestPlanStatus.FAILED.value:
                return TestRequirementCoverageStatus.INCONCLUSIVE.value

        if current_status in _PRESERVED_COVERAGE_STATUSES:
            return current_status
        return TestRequirementCoverageStatus.NOT_TESTED.value

    @staticmethod
    def _next_action(
        coverage_status: str,
        testing_mode: str,
        latest_plan_status: str | None,
    ) -> str:
        if coverage_status == TestRequirementCoverageStatus.NOT_APPLICABLE.value:
            return TestRequirementNextAction.NONE.value
        if coverage_status == TestRequirementCoverageStatus.NOT_TESTED.value:
            return {
                TestingMode.AUTOMATED.value: TestRequirementNextAction.PLAN_AUTOMATED.value,
                TestingMode.ASSISTED.value: TestRequirementNextAction.PLAN_ASSISTED.value,
            }.get(testing_mode, TestRequirementNextAction.PLAN_MANUAL.value)
        if coverage_status == TestRequirementCoverageStatus.PLANNED.value:
            if latest_plan_status == TestPlanStatus.PENDING_APPROVAL.value:
                return TestRequirementNextAction.AWAIT_APPROVAL.value
            return TestRequirementNextAction.AWAIT_EXECUTION.value
        if coverage_status == TestRequirementCoverageStatus.TESTING.value:
            return TestRequirementNextAction.CONTINUE_TESTING.value
        if coverage_status in {
            TestRequirementCoverageStatus.PARTIALLY_TESTED.value,
            TestRequirementCoverageStatus.INCONCLUSIVE.value,
        }:
            return TestRequirementNextAction.REVIEW_EVIDENCE.value
        return TestRequirementNextAction.NONE.value


def _class_profile(vc: VulnerabilityClass) -> dict[str, Any]:
    profile = _CLASS_TEST_PROFILES.get(vc.class_code)
    if profile:
        return profile

    required = _MANUAL_CLASS_EVIDENCE.get(
        vc.class_code,
        [{"evidence_type": "ANALYST_VALIDATION", "minimum": 1}],
    )
    return {
        "testing_mode": vc.default_testing_mode or TestingMode.MANUAL.value,
        "eligible_capabilities": [],
        "required": required,
        "completion": "Manual validation evidence is required to close this class.",
    }


def _required_evidence_payload(
    vc: VulnerabilityClass,
    app: AssetVulnerabilityApplicability | None,
    profile: dict[str, Any],
) -> dict[str, Any]:
    payload = {
        "class_code": vc.class_code,
        "required": [dict(item) for item in profile["required"]],
        "completion": profile["completion"],
        "applicability": {
            "state": app.applicability_state if app else ApplicabilityState.NOT_APPLICABLE.value,
            "rule_ids": list(app.rule_ids or []) if app else [],
            "supporting_evidence_ids": (list(app.supporting_evidence_ids or []) if app else []),
        },
    }
    return payload


class TestPlanner:
    def __init__(self, session: AsyncSession, allow_state_changing: bool = False) -> None:
        self.session = session
        self.allow_state_changing = allow_state_changing

    async def plan_scan(self, scan_id: uuid.UUID) -> list[TestPlan]:
        matrices = list(
            (
                await self.session.execute(
                    select(AssetTestMatrix).where(AssetTestMatrix.scan_id == scan_id)
                )
            )
            .scalars()
            .all()
        )
        created: list[TestPlan] = []
        touched_matrix_ids: set[uuid.UUID] = set()
        for matrix in matrices:
            reqs = list(
                (
                    await self.session.execute(
                        select(TestRequirement).where(TestRequirement.matrix_id == matrix.id)
                    )
                )
                .scalars()
                .all()
            )
            for req in reqs:
                if not self._should_plan(req):
                    continue
                existing = await self._existing_plan(
                    scan_id, matrix.asset_id, req.vulnerability_class_id
                )
                if existing:
                    continue
                plan = await self._create_from_requirement(scan_id, matrix.asset_id, req)
                created.append(plan)
                touched_matrix_ids.add(matrix.id)

        await self.session.flush()
        for matrix_id in touched_matrix_ids:
            matrix = await self.session.get(AssetTestMatrix, matrix_id)
            if matrix:
                await TestMatrixEngine(self.session).build(scan_id, matrix.asset_id)
        return created

    async def plan_automated(
        self,
        scan_id: uuid.UUID,
        asset_id: uuid.UUID,
        vulnerability_class_id: uuid.UUID,
        capabilities: list[str],
    ) -> TestPlan:
        safety = self._safety_for_capabilities(capabilities)
        auth_req, status = self._authorization_for_safety(safety, TestingMode.AUTOMATED.value)
        plan = TestPlan(
            scan_id=scan_id,
            asset_ids=[str(asset_id)],
            vulnerability_class_ids=[str(vulnerability_class_id)],
            testing_mode=TestingMode.AUTOMATED.value,
            required_capabilities=capabilities,
            safety_class=safety,
            authorization_requirement=auth_req,
            status=status,
            reasoning_trace={"rule_ids": ["tp-automated"]},
        )
        self.session.add(plan)
        await self.session.flush()
        await self._emit_plan_created(plan)
        return plan

    async def plan_manual(
        self,
        scan_id: uuid.UUID,
        hypothesis_id: uuid.UUID,
        asset_ids: list[str],
        goal: str,
    ) -> tuple[TestPlan, ValidationTask]:
        plan = TestPlan(
            scan_id=scan_id,
            hypothesis_id=hypothesis_id,
            asset_ids=asset_ids,
            testing_mode=TestingMode.MANUAL.value,
            safety_class="PASSIVE",
            authorization_requirement="PRE_APPROVED",
            status=TestPlanStatus.SCHEDULED.value,
            reasoning_trace={"rule_ids": ["tp-manual"]},
        )
        self.session.add(plan)
        await self.session.flush()
        task = ValidationTask(
            scan_id=scan_id,
            hypothesis_id=hypothesis_id,
            test_plan_id=plan.id,
            asset_ids=asset_ids,
            validation_goal=goal,
            testing_mode=TestingMode.MANUAL.value,
            status=ValidationTaskStatus.OPEN.value,
            suggested_safe_checks=["Review authorization boundary consistency"],
        )
        self.session.add(task)
        await self.session.flush()
        await self._emit_plan_created(plan)
        return plan, task

    @staticmethod
    def _should_plan(req: TestRequirement) -> bool:
        if req.applicability_state not in {
            ApplicabilityState.APPLICABLE.value,
            ApplicabilityState.POSSIBLY_APPLICABLE.value,
        }:
            return False
        if req.next_action not in {
            TestRequirementNextAction.PLAN_AUTOMATED.value,
            TestRequirementNextAction.PLAN_ASSISTED.value,
            TestRequirementNextAction.PLAN_MANUAL.value,
        }:
            return False
        return req.coverage_status in {
            TestRequirementCoverageStatus.NOT_TESTED.value,
            TestRequirementCoverageStatus.INCONCLUSIVE.value,
            TestRequirementCoverageStatus.PARTIALLY_TESTED.value,
        }

    async def _existing_plan(
        self,
        scan_id: uuid.UUID,
        asset_id: uuid.UUID,
        vulnerability_class_id: uuid.UUID,
    ) -> TestPlan | None:
        stmt = select(TestPlan).where(TestPlan.scan_id == scan_id)
        plans = list((await self.session.execute(stmt)).scalars().all())
        asset_ref = str(asset_id)
        class_ref = str(vulnerability_class_id)
        for plan in plans:
            if plan.status not in _ACTIVE_PLAN_STATUSES:
                continue
            if asset_ref not in (plan.asset_ids or []):
                continue
            if class_ref not in (plan.vulnerability_class_ids or []):
                continue
            return plan
        return None

    async def _create_from_requirement(
        self,
        scan_id: uuid.UUID,
        asset_id: uuid.UUID,
        req: TestRequirement,
    ) -> TestPlan:
        vc = await self.session.get(VulnerabilityClass, req.vulnerability_class_id)
        asset = await self.session.get(Asset, asset_id)
        class_code = vc.class_code if vc else str(req.vulnerability_class_id)
        capabilities = list(req.eligible_capabilities or [])
        safety = self._safety_for_capabilities(capabilities)
        auth_req, status = self._authorization_for_safety(safety, req.testing_mode)
        applicability = (req.required_evidence or {}).get("applicability", {})
        rule_ids = list(
            dict.fromkeys(
                [
                    *(applicability.get("rule_ids") or []),
                    "hyp-from-test-requirement",
                ]
            )
        )
        target_name = asset.display_name if asset else str(asset_id)
        hypothesis = Hypothesis(
            scan_id=scan_id,
            title=f"Validate {class_code} on {target_name}",
            description=(
                f"{class_code} is applicable to {target_name} and requires explicit "
                "validation. Applicability alone is not a confirmed vulnerability."
            ),
            hypothesis_type=class_code,
            affected_asset_ids=[str(asset_id)],
            supporting_evidence_ids=list(applicability.get("supporting_evidence_ids") or []),
            correlation_rule_ids=rule_ids,
            confidence=req.confidence,
            impact_if_confirmed=(
                f"A confirmed {class_code} weakness may affect the security of {target_name}."
            ),
            validation_requirements=dict(req.required_evidence or {}),
            status=HypothesisStatus.READY_FOR_VALIDATION.value,
        )
        self.session.add(hypothesis)
        await self.session.flush()
        await self._emit_hypothesis_created(hypothesis)

        plan = TestPlan(
            scan_id=scan_id,
            hypothesis_id=hypothesis.id,
            asset_ids=[str(asset_id)],
            vulnerability_class_ids=[str(req.vulnerability_class_id)],
            testing_mode=req.testing_mode,
            required_capabilities=capabilities,
            required_context={"asset_id": str(asset_id), "class_code": class_code},
            evidence_requirements=dict(req.required_evidence or {}),
            completion_conditions={
                "required_evidence": (req.required_evidence or {}).get("required", []),
                "coverage_status": TestRequirementCoverageStatus.TESTED_NO_EVIDENCE.value,
            },
            safety_class=safety,
            authorization_requirement=auth_req,
            priority=self._priority_for_requirement(req),
            status=status,
            reasoning_trace={
                "rule_ids": ["tp-from-test-requirement"],
                "requirement_id": str(req.id),
                "next_action": req.next_action,
                "applicability_state": req.applicability_state,
            },
        )
        self.session.add(plan)
        await self.session.flush()
        hypothesis.test_plan_id = plan.id

        if req.testing_mode == TestingMode.ASSISTED.value:
            await self._create_assisted_backlog(
                scan_id, asset_id, req, plan, hypothesis, class_code
            )
        elif req.testing_mode == TestingMode.MANUAL.value:
            await self._create_manual_backlog(scan_id, asset_id, req, plan, hypothesis, class_code)

        await self._emit_plan_created(plan)
        return plan

    async def _create_assisted_backlog(
        self,
        scan_id: uuid.UUID,
        asset_id: uuid.UUID,
        req: TestRequirement,
        plan: TestPlan,
        hypothesis: Hypothesis,
        class_code: str,
    ) -> None:
        package = EvidencePackage(
            scan_id=scan_id,
            hypothesis_id=hypothesis.id,
            package_data={
                "affected_assets": [str(asset_id)],
                "vulnerability_class_id": str(req.vulnerability_class_id),
                "class_code": class_code,
                "validation_goal": self._validation_goal(class_code, req.testing_mode),
                "required_evidence": req.required_evidence or {},
                "eligible_capabilities": list(req.eligible_capabilities or []),
            },
        )
        self.session.add(package)
        await self.session.flush()
        task = ValidationTask(
            scan_id=scan_id,
            hypothesis_id=hypothesis.id,
            test_plan_id=plan.id,
            evidence_package_id=package.id,
            asset_ids=[str(asset_id)],
            validation_goal=self._validation_goal(class_code, req.testing_mode),
            required_evidence=req.required_evidence or {},
            suggested_safe_checks=[
                "Collect non-destructive evidence before analyst validation",
                "Do not include secrets in the evidence package",
            ],
            testing_mode=TestingMode.ASSISTED.value,
            status=ValidationTaskStatus.OPEN.value,
        )
        self.session.add(task)
        await self.session.flush()
        package.validation_task_id = task.id
        await self._emit_validation_task_created(task)

    async def _create_manual_backlog(
        self,
        scan_id: uuid.UUID,
        asset_id: uuid.UUID,
        req: TestRequirement,
        plan: TestPlan,
        hypothesis: Hypothesis,
        class_code: str,
    ) -> None:
        task = ValidationTask(
            scan_id=scan_id,
            hypothesis_id=hypothesis.id,
            test_plan_id=plan.id,
            asset_ids=[str(asset_id)],
            validation_goal=self._validation_goal(class_code, req.testing_mode),
            required_evidence=req.required_evidence or {},
            suggested_safe_checks=[
                "Review the affected workflow manually",
                "Record evidence IDs before issuing a verdict",
            ],
            testing_mode=TestingMode.MANUAL.value,
            status=ValidationTaskStatus.OPEN.value,
        )
        self.session.add(task)
        await self.session.flush()
        await self._emit_validation_task_created(task)

    def _authorization_for_safety(self, safety: str, testing_mode: str) -> tuple[str, str]:
        if safety in {SafetyClass.DESTRUCTIVE.value, SafetyClass.PROHIBITED.value}:
            return "ANALYST_APPROVAL_REQUIRED", TestPlanStatus.PENDING_APPROVAL.value
        if safety == SafetyClass.STATE_CHANGING.value and not self.allow_state_changing:
            return "ANALYST_APPROVAL_REQUIRED", TestPlanStatus.PENDING_APPROVAL.value
        if testing_mode in {TestingMode.ASSISTED.value, TestingMode.MANUAL.value}:
            return "PRE_APPROVED", TestPlanStatus.SCHEDULED.value
        return "PRE_APPROVED", TestPlanStatus.APPROVED.value

    @staticmethod
    def _safety_for_capabilities(capabilities: list[str]) -> str:
        if not capabilities:
            return SafetyClass.PASSIVE.value
        safety = SafetyClass.PASSIVE.value
        for cap_code in capabilities:
            try:
                candidate = default_safety_for(Capability(cap_code)).value
            except ValueError:
                candidate = SafetyClass.LOW_IMPACT.value
            if _SAFETY_ORDER[candidate] > _SAFETY_ORDER[safety]:
                safety = candidate
        return safety

    @staticmethod
    def _priority_for_requirement(req: TestRequirement) -> int:
        if req.applicability_state == ApplicabilityState.APPLICABLE.value:
            return 100
        return 70

    @staticmethod
    def _validation_goal(class_code: str, testing_mode: str) -> str:
        if testing_mode == TestingMode.ASSISTED.value:
            return f"Prepare and review evidence for {class_code}"
        return f"Manually validate {class_code}"

    async def _emit_plan_created(self, plan: TestPlan) -> None:
        self.session.add(
            Event(
                scan_id=plan.scan_id,
                event_type="TEST_PLAN_CREATED",
                payload={
                    "plan_id": str(plan.id),
                    "hypothesis_id": (str(plan.hypothesis_id) if plan.hypothesis_id else None),
                    "testing_mode": plan.testing_mode,
                    "asset_ids": plan.asset_ids,
                    "vulnerability_class_ids": plan.vulnerability_class_ids,
                    "status": plan.status,
                    "safety_class": plan.safety_class,
                },
                correlation_id=uuid.uuid4(),
                sequence_number=await self._next_event_sequence(plan.scan_id),
                processed_at=datetime.now(UTC),
            )
        )

    async def _emit_hypothesis_created(self, hypothesis: Hypothesis) -> None:
        self.session.add(
            Event(
                scan_id=hypothesis.scan_id,
                event_type="HYPOTHESIS_CREATED",
                payload={
                    "hypothesis_id": str(hypothesis.id),
                    "hypothesis_type": hypothesis.hypothesis_type,
                    "asset_ids": hypothesis.affected_asset_ids,
                    "status": hypothesis.status,
                },
                correlation_id=uuid.uuid4(),
                sequence_number=await self._next_event_sequence(hypothesis.scan_id),
                processed_at=datetime.now(UTC),
            )
        )

    async def _emit_validation_task_created(self, task: ValidationTask) -> None:
        self.session.add(
            Event(
                scan_id=task.scan_id,
                event_type="VALIDATION_TASK_CREATED",
                payload={
                    "validation_task_id": str(task.id),
                    "hypothesis_id": (str(task.hypothesis_id) if task.hypothesis_id else None),
                    "test_plan_id": (str(task.test_plan_id) if task.test_plan_id else None),
                    "testing_mode": task.testing_mode,
                },
                correlation_id=uuid.uuid4(),
                sequence_number=await self._next_event_sequence(task.scan_id),
                processed_at=datetime.now(UTC),
            )
        )

    async def _next_event_sequence(self, scan_id: uuid.UUID) -> int:
        stmt = select(func.max(Event.sequence_number)).where(Event.scan_id == scan_id)
        current = (await self.session.execute(stmt)).scalar() or 0
        return int(current) + 1


class VerdictEngine:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def evaluate_hypothesis(
        self,
        hypothesis_id: uuid.UUID,
        outcome: str,
        evidence_ids: list[str],
        validation_result_id: uuid.UUID | None = None,
        test_plan_id: uuid.UUID | None = None,
        test_execution_id: uuid.UUID | None = None,
        recorded_by: str = "analyst",
    ) -> Verdict:
        hyp = await self.session.get(Hypothesis, hypothesis_id)
        if not hyp:
            raise ValueError("Hypothesis not found")
        if outcome not in {"CONFIRMED", "REJECTED", "INCONCLUSIVE"}:
            raise ValueError(f"Unsupported validation outcome: {outcome}")
        validation_result = (
            await self.session.get(ValidationResult, validation_result_id)
            if validation_result_id
            else None
        )
        if validation_result_id and not validation_result:
            raise ValueError("Validation result not found")
        if validation_result and validation_result.outcome != outcome:
            raise ValueError("Validation result outcome does not match verdict outcome")
        canonical_evidence_ids = list(
            dict.fromkeys(validation_result.evidence_ids if validation_result else evidence_ids)
        )
        if outcome == "CONFIRMED" and not canonical_evidence_ids:
            raise ValueError("Confirmed verdict requires evidence")
        status = {
            "CONFIRMED": VerdictStatus.CONFIRMED.value,
            "REJECTED": VerdictStatus.REJECTED.value,
            "INCONCLUSIVE": VerdictStatus.INCONCLUSIVE.value,
        }[outcome]
        resolved_plan_id = test_plan_id or hyp.test_plan_id
        verdict = Verdict(
            scan_id=hyp.scan_id,
            hypothesis_id=hypothesis_id,
            test_plan_id=resolved_plan_id,
            validation_result_id=validation_result_id,
            status=status,
            confidence=hyp.confidence,
            supporting_evidence_ids=(canonical_evidence_ids if outcome == "CONFIRMED" else []),
            contradicting_evidence_ids=(canonical_evidence_ids if outcome == "REJECTED" else []),
            rule_ids=["verdict-automated" if test_execution_id else "verdict-manual"],
            explanation=(
                f"Verdict based on {'automated execution' if test_execution_id else 'validation'} "
                f"outcome {outcome}"
            ),
        )
        self.session.add(verdict)
        await self.session.flush()
        hyp.status = {
            "CONFIRMED": HypothesisStatus.CONFIRMED.value,
            "REJECTED": HypothesisStatus.REJECTED.value,
        }.get(outcome, HypothesisStatus.INCONCLUSIVE.value)
        hyp.verdict_id = verdict.id
        if canonical_evidence_ids:
            if outcome == "CONFIRMED":
                hyp.supporting_evidence_ids = list(
                    dict.fromkeys([*(hyp.supporting_evidence_ids or []), *canonical_evidence_ids])
                )
            elif outcome == "REJECTED":
                hyp.contradicting_evidence_ids = list(
                    dict.fromkeys(
                        [*(hyp.contradicting_evidence_ids or []), *canonical_evidence_ids]
                    )
                )

        if outcome in {"CONFIRMED", "REJECTED"}:
            self.session.add(
                EvidenceLink(
                    scan_id=hyp.scan_id,
                    source_type=(
                        "VALIDATION_RESULT"
                        if validation_result_id
                        else "TEST_EXECUTION"
                        if test_execution_id
                        else "VERDICT"
                    ),
                    source_id=validation_result_id or test_execution_id or verdict.id,
                    target_type="HYPOTHESIS",
                    target_id=hypothesis_id,
                    link_type="CONFIRMS" if outcome == "CONFIRMED" else "REJECTS",
                    provenance={"verdict_id": str(verdict.id)},
                )
            )

        related_tasks = list(
            (
                await self.session.execute(
                    select(ValidationTask).where(ValidationTask.hypothesis_id == hypothesis_id)
                )
            )
            .scalars()
            .all()
        )
        terminal_task_status = {
            "CONFIRMED": ValidationTaskStatus.VALIDATED.value,
            "REJECTED": ValidationTaskStatus.REJECTED.value,
            "INCONCLUSIVE": ValidationTaskStatus.INCONCLUSIVE.value,
        }[outcome]
        for task in related_tasks:
            if task.status in {
                ValidationTaskStatus.OPEN.value,
                ValidationTaskStatus.ASSIGNED.value,
                ValidationTaskStatus.IN_PROGRESS.value,
            }:
                task.status = terminal_task_status

        plan = await self.session.get(TestPlan, resolved_plan_id) if resolved_plan_id else None
        if plan:
            plan.status = TestPlanStatus.COMPLETED.value

        if outcome == "CONFIRMED" and validation_result_id:
            self.session.add(
                ConfirmedFinding(
                    scan_id=hyp.scan_id,
                    hypothesis_id=hyp.id,
                    validation_result_id=validation_result_id,
                    title=hyp.title,
                    description=hyp.description,
                    affected_asset_ids=list(hyp.affected_asset_ids or []),
                    evidence_ids=canonical_evidence_ids,
                    confirmed_by=recorded_by,
                )
            )

        await self._update_applicability(
            hyp,
            plan,
            outcome,
            canonical_evidence_ids,
            verdict.id,
        )
        self.session.add(
            Event(
                scan_id=hyp.scan_id,
                event_type="VERDICT_ISSUED",
                payload={
                    "verdict_id": str(verdict.id),
                    "hypothesis_id": str(hyp.id),
                    "validation_result_id": (
                        str(validation_result_id) if validation_result_id else None
                    ),
                    "test_execution_id": (str(test_execution_id) if test_execution_id else None),
                    "status": verdict.status,
                },
                correlation_id=uuid.uuid4(),
                sequence_number=await self._next_event_sequence(hyp.scan_id),
                processed_at=datetime.now(UTC),
            )
        )
        return verdict

    async def _update_applicability(
        self,
        hypothesis: Hypothesis,
        plan: TestPlan | None,
        outcome: str,
        evidence_ids: list[str],
        verdict_id: uuid.UUID,
    ) -> None:
        if not plan:
            return
        asset_ids = self._uuid_list(plan.asset_ids or [])
        class_ids = self._uuid_list(plan.vulnerability_class_ids or [])
        if not asset_ids or not class_ids:
            return
        rows = list(
            (
                await self.session.execute(
                    select(AssetVulnerabilityApplicability).where(
                        AssetVulnerabilityApplicability.scan_id == hypothesis.scan_id,
                        AssetVulnerabilityApplicability.asset_id.in_(asset_ids),
                        AssetVulnerabilityApplicability.vulnerability_class_id.in_(class_ids),
                    )
                )
            )
            .scalars()
            .all()
        )
        state = {
            "CONFIRMED": ApplicabilityState.CONFIRMED.value,
            "REJECTED": ApplicabilityState.TESTED_NO_EVIDENCE.value,
            "INCONCLUSIVE": ApplicabilityState.INCONCLUSIVE.value,
        }[outcome]
        for row in rows:
            row.applicability_state = state
            row.supporting_evidence_ids = list(
                dict.fromkeys([*(row.supporting_evidence_ids or []), *evidence_ids])
            )
            row.rule_ids = list(dict.fromkeys([*(row.rule_ids or []), "verdict-manual"]))
            row.explanation = f"Validation outcome {outcome}; verdict_id={verdict_id}"
            row.computed_at = datetime.now(UTC)
        for asset_id in asset_ids:
            await TestMatrixEngine(self.session).build(hypothesis.scan_id, asset_id)

    @staticmethod
    def _uuid_list(values: list[str]) -> list[uuid.UUID]:
        parsed: list[uuid.UUID] = []
        for value in values:
            try:
                parsed.append(uuid.UUID(value))
            except (TypeError, ValueError):
                continue
        return parsed

    async def _next_event_sequence(self, scan_id: uuid.UUID) -> int:
        stmt = select(func.max(Event.sequence_number)).where(Event.scan_id == scan_id)
        current = (await self.session.execute(stmt)).scalar() or 0
        return int(current) + 1


class RecursiveCorrelationEngine:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def check_js_endpoint_gap(
        self,
        scan_id: uuid.UUID,
        js_endpoints: set[str],
        crawl_endpoints: set[str],
        asset_id: uuid.UUID,
    ) -> Hypothesis | None:
        missing = js_endpoints - crawl_endpoints
        if not missing:
            return None
        hyp = Hypothesis(
            scan_id=scan_id,
            title="Undocumented endpoint referenced by JavaScript",
            description=f"Endpoints {missing} referenced in JS but not in crawl inventory",
            hypothesis_type="ENDPOINT_DISCOVERY_GAP",
            affected_asset_ids=[str(asset_id)],
            correlation_rule_ids=["corr-js-endpoint-gap"],
            confidence=0.7,
            status=HypothesisStatus.READY_FOR_VALIDATION.value,
            validation_requirements={"goal": "Validate JS-referenced endpoints"},
        )
        self.session.add(hyp)
        return hyp


class AssessmentCompletionEvaluator:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.surface_engine = SurfaceCompletenessEngine(session)

    async def evaluate(self, scan_id: uuid.UUID) -> AssessmentCompletionRecord:
        stmt = select(AssessmentCompletionRecord).where(
            AssessmentCompletionRecord.scan_id == scan_id
        )
        record = (await self.session.execute(stmt)).scalar_one_or_none()
        if not record:
            record = AssessmentCompletionRecord(
                scan_id=scan_id, status=CompletionStatus.INCOMPLETE.value
            )
            self.session.add(record)

        open_tasks = await self.session.execute(
            select(ValidationTask).where(
                ValidationTask.scan_id == scan_id,
                ValidationTask.status.in_(
                    [
                        ValidationTaskStatus.OPEN.value,
                        ValidationTaskStatus.ASSIGNED.value,
                        ValidationTaskStatus.IN_PROGRESS.value,
                        ValidationTaskStatus.BLOCKED.value,
                        ValidationTaskStatus.INCONCLUSIVE.value,
                    ]
                ),
            )
        )
        open_count = len(list(open_tasks.scalars().all()))

        matrices = list(
            (
                await self.session.execute(
                    select(AssetTestMatrix).where(AssetTestMatrix.scan_id == scan_id)
                )
            )
            .scalars()
            .all()
        )
        matrix_ids = [matrix.id for matrix in matrices]
        requirements = (
            list(
                (
                    await self.session.execute(
                        select(TestRequirement).where(TestRequirement.matrix_id.in_(matrix_ids))
                    )
                )
                .scalars()
                .all()
            )
            if matrix_ids
            else []
        )
        blocking_coverage_statuses = {
            TestRequirementCoverageStatus.NOT_TESTED.value,
            TestRequirementCoverageStatus.PLANNED.value,
            TestRequirementCoverageStatus.TESTING.value,
            TestRequirementCoverageStatus.PARTIALLY_TESTED.value,
            TestRequirementCoverageStatus.INCONCLUSIVE.value,
        }
        blocking_requirements = [
            {
                "matrix_id": str(requirement.matrix_id),
                "vulnerability_class_id": str(requirement.vulnerability_class_id),
                "coverage_status": requirement.coverage_status,
                "next_action": requirement.next_action,
            }
            for requirement in requirements
            if requirement.coverage_status in blocking_coverage_statuses
        ]

        accepted = record.accepted_gaps or {}
        web_apps = list(
            (
                await self.session.execute(
                    select(Asset).where(
                        Asset.scan_id == scan_id,
                        Asset.asset_type == AssetType.WEB_APPLICATION.value,
                    )
                )
            )
            .scalars()
            .all()
        )

        blocking_gaps: list[dict[str, Any]] = []
        for asset in web_apps:
            reqs = await self.surface_engine.missing_requirements(
                asset.id, scan_id, accepted_gaps=accepted
            )
            blocking_gaps.extend(
                {
                    "asset_id": str(asset.id),
                    "dimension": r.dimension,
                    "status": r.status,
                    "reason": r.reason,
                }
                for r in reqs
                if r.blocking
            )

        blocking: list[str] = []
        if open_count:
            blocking.append(f"{open_count} open validation tasks")
        if blocking_gaps:
            blocking.append(f"{len(blocking_gaps)} blocking surface gaps")
        if blocking_requirements:
            blocking.append(f"{len(blocking_requirements)} unresolved test requirements")

        accepted_count = sum(
            len(v) if isinstance(v, list) else len(v.keys()) if isinstance(v, dict) else 0
            for v in accepted.values()
        )

        if blocking:
            record.status = CompletionStatus.INCOMPLETE.value
            record.blocking_items = blocking
            record.completion_reasons = {
                "blocking_surface_gaps": blocking_gaps,
                "blocking_test_requirements": blocking_requirements,
            }
        elif accepted_count:
            record.status = CompletionStatus.COMPLETE_WITH_ACCEPTED_GAPS.value
            record.blocking_items = []
            record.completion_reasons = {"accepted_gap_count": accepted_count}
        else:
            record.status = CompletionStatus.COMPLETE.value
            record.blocking_items = []
            record.completion_reasons = {"reason": "all blocking requirements satisfied"}

        record.evaluated_at = datetime.now(UTC)
        record.metrics = {
            "open_validation_tasks": open_count,
            "web_application_count": len(web_apps),
            "blocking_gap_count": len(blocking_gaps),
            "blocking_test_requirement_count": len(blocking_requirements),
            "accepted_gap_count": accepted_count,
        }
        return record
