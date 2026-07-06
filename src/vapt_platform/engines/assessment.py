"""Assessment engines."""

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from vapt_platform.db.tables.models import (
    AssessmentCompletionRecord,
    Asset,
    AssetTestMatrix,
    AssetVulnerabilityApplicability,
    EvidenceLink,
    Hypothesis,
    TestExecution,
    TestPlan,
    TestRequirement,
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
    TestRequirementCoverageStatus,
    TestRequirementNextAction,
    TestingMode,
    TestPlanStatus,
    VerdictStatus,
)
from vapt_platform.engines.surface_completeness import SurfaceCompletenessEngine
from vapt_platform.engines.vulnerability_applicability import VulnerabilityApplicabilityEngine


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
    "CROSS_APPLICATION_AUTHORIZATION": [
        {"evidence_type": "CROSS_APP_ACCESS_REVIEW", "minimum": 1}
    ],
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
        stmt = select(TestPlan).where(TestPlan.scan_id == scan_id).order_by(
            TestPlan.updated_at.desc(),
            TestPlan.created_at.desc(),
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
            "supporting_evidence_ids": (
                list(app.supporting_evidence_ids or []) if app else []
            ),
        },
    }
    return payload


class TestPlanner:
    def __init__(self, session: AsyncSession, allow_state_changing: bool = False) -> None:
        self.session = session
        self.allow_state_changing = allow_state_changing

    async def plan_automated(
        self,
        scan_id: uuid.UUID,
        asset_id: uuid.UUID,
        vulnerability_class_id: uuid.UUID,
        capabilities: list[str],
    ) -> TestPlan:
        safety = "LOW_IMPACT"
        auth_req = "PRE_APPROVED"
        status = TestPlanStatus.APPROVED.value
        if "WEB_ACTIVE_ASSESSMENT" in capabilities and not self.allow_state_changing:
            safety = "STATE_CHANGING"
            auth_req = "ANALYST_APPROVAL_REQUIRED"
            status = TestPlanStatus.PENDING_APPROVAL.value
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
            status=TestPlanStatus.COMPLETED.value,
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
            suggested_safe_checks=["Review authorization boundary consistency"],
        )
        self.session.add(task)
        return plan, task


class VerdictEngine:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def evaluate_hypothesis(
        self,
        hypothesis_id: uuid.UUID,
        outcome: str,
        evidence_ids: list[str],
    ) -> Verdict:
        hyp = await self.session.get(Hypothesis, hypothesis_id)
        if not hyp:
            raise ValueError("Hypothesis not found")
        if outcome == "CONFIRMED" and not evidence_ids:
            raise ValueError("Confirmed verdict requires evidence")
        status = {
            "CONFIRMED": VerdictStatus.CONFIRMED.value,
            "REJECTED": VerdictStatus.REJECTED.value,
            "INCONCLUSIVE": VerdictStatus.INCONCLUSIVE.value,
        }.get(outcome, VerdictStatus.INCONCLUSIVE.value)
        verdict = Verdict(
            scan_id=hyp.scan_id,
            hypothesis_id=hypothesis_id,
            status=status,
            supporting_evidence_ids=evidence_ids,
            rule_ids=["verdict-manual"],
            explanation=f"Verdict based on validation outcome {outcome}",
        )
        self.session.add(verdict)
        hyp.status = {
            "CONFIRMED": HypothesisStatus.CONFIRMED.value,
            "REJECTED": HypothesisStatus.REJECTED.value,
        }.get(outcome, HypothesisStatus.INCONCLUSIVE.value)
        hyp.verdict_id = verdict.id
        link = EvidenceLink(
            scan_id=hyp.scan_id,
            source_type="VALIDATION_RESULT",
            source_id=verdict.id,
            target_type="HYPOTHESIS",
            target_id=hypothesis_id,
            link_type="CONFIRMS" if outcome == "CONFIRMED" else "REJECTS",
        )
        self.session.add(link)
        return verdict


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
                ValidationTask.status.in_(["OPEN", "ASSIGNED", "IN_PROGRESS"]),
            )
        )
        open_count = len(list(open_tasks.scalars().all()))

        accepted = record.accepted_gaps or {}
        web_apps = list(
            (
                await self.session.execute(
                    select(Asset).where(
                        Asset.scan_id == scan_id,
                        Asset.asset_type == AssetType.WEB_APPLICATION.value,
                    )
                )
            ).scalars().all()
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

        accepted_count = sum(
            len(v) if isinstance(v, list) else len(v.keys()) if isinstance(v, dict) else 0
            for v in accepted.values()
        )

        if blocking:
            record.status = CompletionStatus.INCOMPLETE.value
            record.blocking_items = blocking
            record.completion_reasons = {"blocking_surface_gaps": blocking_gaps}
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
            "accepted_gap_count": accepted_count,
        }
        return record
