"""Capability-based validation routing (Phase 2 entry point)."""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from vapt_platform.config.settings import Settings, get_settings
from vapt_platform.db.tables.models import (
    Asset,
    ProviderSelectionDecision,
    TestExecution,
    TestPlan,
    TestRequirement,
    VulnerabilityClass,
)
from vapt_platform.domain.capability_provider import (
    ProviderAvailabilityContext,
    ProviderExecutionContext,
    ProviderRejectionReason,
    RoutingErrorCode,
    TestPlanContext,
)
from vapt_platform.domain.enums import AssetType, Capability, TestPlanStatus, TestingMode, default_safety_for, default_safety_for
from vapt_platform.engines.authorization_policy import AuthorizationPolicy
from vapt_platform.engines.capability_matcher import CapabilityMatcher
from vapt_platform.engines.credential_compatibility_policy import CredentialCompatibilityPolicy
from vapt_platform.engines.safety_policy import SafetyPolicy
from vapt_platform.providers import build_default_capability_providers
from vapt_platform.services.capability_provider_registry import CapabilityProviderRegistry

logger = logging.getLogger(__name__)

_EXECUTABLE_PLAN_STATUSES = {
    TestPlanStatus.APPROVED.value,
    TestPlanStatus.SCHEDULED.value,
}


@dataclass
class RoutedScanSummary:
    scan_id: str
    plans_attempted: int = 0
    plans_executed: int = 0
    plans_blocked: int = 0
    results: list[dict[str, Any]] = field(default_factory=list)


class CapabilityValidationRouter:
    def __init__(
        self,
        session: AsyncSession,
        registry: CapabilityProviderRegistry | None = None,
        settings: Settings | None = None,
    ) -> None:
        self.session = session
        self.settings = settings or get_settings()
        self.registry = registry or CapabilityProviderRegistry(
            build_default_capability_providers(self.settings)
        )
        self.matcher = CapabilityMatcher()
        self.safety_policy = SafetyPolicy(self.settings)
        self.authorization_policy = AuthorizationPolicy(session)
        self.credential_policy = CredentialCompatibilityPolicy(session)

    async def route_and_execute(
        self,
        scan_id: str | uuid.UUID,
        test_plan_id: str | uuid.UUID,
        *,
        active_validation_allowed: bool = False,
        username: str | None = None,
        password: str | None = None,
    ) -> dict[str, Any]:
        scan_uuid = uuid.UUID(str(scan_id))
        plan_uuid = uuid.UUID(str(test_plan_id))
        plan = await self.session.get(TestPlan, plan_uuid)
        if not plan or str(plan.scan_id) != str(scan_uuid):
            return self._error_result(
                str(scan_id),
                str(test_plan_id),
                [RoutingErrorCode.INVALID_TEST_PLAN.value],
                "Test plan not found for scan",
            )

        existing = (
            await self.session.execute(
                select(TestExecution)
                .where(TestExecution.test_plan_id == plan.id)
                .order_by(TestExecution.executed_at.desc())
            )
        ).scalars().first()
        if existing:
            return {
                "scan_id": str(scan_id),
                "test_plan_id": str(test_plan_id),
                "status": existing.status,
                "selected_provider": existing.selected_provider_id,
                "execution_id": str(existing.id),
                "reused": True,
            }

        requirement = await self._load_requirement(plan)
        plan_context = await self._build_plan_context(
            plan,
            requirement,
            active_validation_allowed=active_validation_allowed,
            username=username,
            password=password,
        )
        if requirement is None and not plan.required_capabilities:
            return self._error_result(
                str(scan_id),
                str(test_plan_id),
                [RoutingErrorCode.INVALID_TEST_REQUIREMENT.value],
                "No linked test requirement",
            )

        match = self.matcher.match(
            plan_context,
            self.registry.list_providers(),
        )
        rejected = dict(match.rejected)
        eligible_ids: list[str] = []
        availability_ctx = ProviderAvailabilityContext(
            scan_id=str(scan_id),
            active_validation_allowed=active_validation_allowed,
        )

        asset = await self._primary_asset(plan)
        for provider in match.eligible_providers:
            pid = provider.provider_id
            avail = provider.is_available(availability_ctx)
            if not avail.available:
                rejected.setdefault(pid, []).extend(avail.reason_codes or ["PROVIDER_UNAVAILABLE"])
                continue
            support = provider.supports_plan(plan_context)
            if not support.supported:
                rejected.setdefault(pid, []).extend(
                    support.reason_codes or [ProviderRejectionReason.PLAN_NOT_SUPPORTED.value]
                )
                continue
            safety = self.safety_policy.evaluate(
                plan_safety_class=plan.safety_class,
                requirement_safety_class=requirement.safety_class if requirement else None,
                provider_default_safety=provider.metadata().default_safety_class,
                capability_safety_class=self._safety_for_capability(match.capability),
            )
            if not safety.allowed:
                rejected.setdefault(pid, []).extend(
                    safety.reason_codes or [RoutingErrorCode.SAFETY_POLICY_REJECTED.value]
                )
                continue
            auth = await self.authorization_policy.evaluate(
                scan_id=scan_uuid,
                plan=plan,
                requirement=requirement,
                capability=match.capability or "",
                asset=asset,
                active_validation_allowed=active_validation_allowed,
            )
            if not auth.allowed:
                rejected.setdefault(pid, []).extend(
                    auth.reason_codes or [RoutingErrorCode.AUTHORIZATION_POLICY_REJECTED.value]
                )
                continue
            cred = await self.credential_policy.evaluate(
                scan_id=scan_uuid,
                requirement=requirement,
                plan=plan_context,
                provider_id=pid,
                asset_id=plan_context.asset_ids[0] if plan_context.asset_ids else None,
            )
            if not cred.compatible:
                rejected.setdefault(pid, []).extend(
                    cred.reason_codes or [RoutingErrorCode.CREDENTIAL_CONTEXT_INCOMPATIBLE.value]
                )
                continue
            eligible_ids.append(pid)

        selected_provider: str | None = None
        if eligible_ids:
            ordered = sorted(
                eligible_ids,
                key=lambda pid: (
                    self.registry.get(pid).metadata().priority if self.registry.get(pid) else 999,
                    pid,
                ),
            )
            selected_provider = ordered[0]

        decision = ProviderSelectionDecision(
            scan_id=scan_uuid,
            test_plan_id=plan.id,
            required_capability=match.capability,
            eligible_providers=eligible_ids,
            rejected_providers=sorted(rejected.keys()),
            rejection_reasons=rejected,
            selected_provider=selected_provider,
            selection_rule="CAPABILITY_MATCH_THEN_POLICY",
            decision_context={
                "required_capability": match.capability,
                "eligible_providers": eligible_ids,
                "rejected_providers": sorted(rejected.keys()),
                "rejection_reasons": rejected,
                "selected_provider": selected_provider,
                "selection_rule": "CAPABILITY_MATCH_THEN_POLICY",
                "safety_class": plan.safety_class,
                "credential_status": "compatible" if selected_provider else "blocked",
            },
        )
        self.session.add(decision)
        await self.session.flush()

        logger.info(
            "routing_decision scan_id=%s test_plan_id=%s capability=%s candidates=%d selected=%s",
            scan_id,
            test_plan_id,
            match.capability,
            len(eligible_ids),
            selected_provider,
        )

        if not selected_provider or not match.capability:
            return {
                "scan_id": str(scan_id),
                "test_plan_id": str(test_plan_id),
                "required_capability": match.capability,
                "selected_provider": None,
                "status": "NO_PROVIDER",
                "decision_id": str(decision.id),
                "error_codes": [RoutingErrorCode.NO_PROVIDER_FOR_CAPABILITY.value],
                "rejection_reasons": rejected,
            }

        provider = self.registry.get(selected_provider)
        if not provider:
            return self._error_result(
                str(scan_id),
                str(test_plan_id),
                [RoutingErrorCode.PROVIDER_UNAVAILABLE.value],
                "Selected provider missing from registry",
                decision_id=str(decision.id),
            )

        plan.status = TestPlanStatus.EXECUTING.value
        exec_ctx = ProviderExecutionContext(
            plan=plan_context,
            capability=match.capability,
            provider_id=selected_provider,
        )
        try:
            result = await provider.execute(exec_ctx)
        except Exception as exc:  # noqa: BLE001
            execution = TestExecution(
                test_plan_id=plan.id,
                selected_provider_id=selected_provider,
                status="FAILED",
                result_summary={"error": str(exc)[:400]},
            )
            self.session.add(execution)
            plan.status = TestPlanStatus.FAILED.value
            await self.session.flush()
            return {
                "scan_id": str(scan_id),
                "test_plan_id": str(test_plan_id),
                "status": "FAILED",
                "decision_id": str(decision.id),
                "execution_id": str(execution.id),
                "error_codes": [RoutingErrorCode.PROVIDER_EXECUTION_FAILED.value],
                "detail": str(exc)[:400],
            }

        execution_status = "COMPLETED" if result.status != "ERROR" else "FAILED"
        execution = TestExecution(
            test_plan_id=plan.id,
            selected_provider_id=selected_provider,
            executed_capability=match.capability,
            provider_selection_decision_id=decision.id,
            status=execution_status,
            result_summary={
                "provider_id": selected_provider,
                "capability": match.capability,
                "connector_status": result.status,
                "finding_count": len(result.findings),
                "detail": result.detail,
            },
        )
        self.session.add(execution)
        await self.session.flush()

        requirement = await self._load_requirement(plan)
        if asset:
            from vapt_platform.services.evidence_ingestion import EvidenceIngestionService
            from vapt_platform.services.result_normalizer import NormalizationContext

            norm_context = NormalizationContext(
                scan_id=str(scan_uuid),
                asset_id=str(asset.id),
                test_plan_id=str(plan.id),
                test_requirement_id=str(requirement.id) if requirement else None,
                test_execution_id=str(execution.id),
                provider_id=selected_provider,
                executed_capability=match.capability or "",
                provider_selection_decision_id=str(decision.id),
                vulnerability_classes=plan_context.class_codes,
                endpoint_context=plan_context.endpoint_context,
            )
            await EvidenceIngestionService(self.session).ingest_provider_result(
                execution=execution,
                plan=plan,
                provider_result=result,
                context=norm_context,
                raw_content=result.detail,
            )

        plan.status = (
            TestPlanStatus.COMPLETED.value
            if execution_status == "COMPLETED"
            else TestPlanStatus.FAILED.value
        )
        await self.session.flush()

        return {
            "scan_id": str(scan_id),
            "test_plan_id": str(test_plan_id),
            "required_capability": match.capability,
            "selected_provider": selected_provider,
            "status": execution_status,
            "decision_id": str(decision.id),
            "execution_id": str(execution.id),
            "connector_status": result.status,
            "finding_count": len(result.findings),
        }

    async def execute_scan_plans(
        self,
        scan_id: uuid.UUID,
        *,
        active_validation_allowed: bool = False,
        username: str | None = None,
        password: str | None = None,
    ) -> RoutedScanSummary:
        summary = RoutedScanSummary(scan_id=str(scan_id))
        plans = list(
            (
                await self.session.execute(
                    select(TestPlan)
                    .where(
                        TestPlan.scan_id == scan_id,
                        TestPlan.testing_mode == TestingMode.AUTOMATED.value,
                        TestPlan.status.in_(_EXECUTABLE_PLAN_STATUSES),
                    )
                    .order_by(TestPlan.priority.desc(), TestPlan.created_at)
                )
            )
            .scalars()
            .all()
        )
        for plan in plans:
            summary.plans_attempted += 1
            result = await self.route_and_execute(
                scan_id,
                plan.id,
                active_validation_allowed=active_validation_allowed,
                username=username,
                password=password,
            )
            summary.results.append(result)
            status = result.get("status")
            if status == "COMPLETED":
                summary.plans_executed += 1
            elif status == "NO_PROVIDER":
                summary.plans_blocked += 1
            elif status in {"FAILED", "ERROR"}:
                summary.plans_blocked += 1
            elif result.get("reused"):
                summary.plans_executed += 1
        return summary

    @staticmethod
    def _safety_for_capability(capability: str | None) -> str | None:
        if not capability:
            return None
        try:
            return default_safety_for(Capability(capability)).value
        except ValueError:
            return None

    async def _load_requirement(self, plan: TestPlan) -> TestRequirement | None:
        req_id = (plan.reasoning_trace or {}).get("requirement_id")
        if req_id:
            try:
                return await self.session.get(TestRequirement, uuid.UUID(str(req_id)))
            except (TypeError, ValueError):
                pass
        if not plan.vulnerability_class_ids or not plan.asset_ids:
            return None
        from vapt_platform.db.tables.models import AssetTestMatrix

        asset_id = uuid.UUID(str(plan.asset_ids[0]))
        class_id = uuid.UUID(str(plan.vulnerability_class_ids[0]))
        matrix = (
            await self.session.execute(
                select(AssetTestMatrix).where(
                    AssetTestMatrix.scan_id == plan.scan_id,
                    AssetTestMatrix.asset_id == asset_id,
                )
            )
        ).scalar_one_or_none()
        if not matrix:
            return None
        return (
            await self.session.execute(
                select(TestRequirement).where(
                    TestRequirement.matrix_id == matrix.id,
                    TestRequirement.vulnerability_class_id == class_id,
                )
            )
        ).scalar_one_or_none()

    async def _build_plan_context(
        self,
        plan: TestPlan,
        requirement: TestRequirement | None,
        *,
        active_validation_allowed: bool,
        username: str | None,
        password: str | None,
    ) -> TestPlanContext:
        class_codes: list[str] = []
        for raw in plan.vulnerability_class_ids or []:
            vc = await self.session.get(VulnerabilityClass, uuid.UUID(str(raw)))
            if vc:
                class_codes.append(vc.class_code)
        asset = await self._primary_asset(plan)
        target_url = self._asset_url(asset) if asset else None
        endpoint_context = dict(plan.required_context or {})
        if requirement:
            endpoint_context.update((requirement.required_evidence or {}).get("endpoint", {}))
        return TestPlanContext(
            scan_id=str(plan.scan_id),
            test_plan_id=str(plan.id),
            asset_ids=[str(a) for a in (plan.asset_ids or [])],
            vulnerability_class_ids=[str(v) for v in (plan.vulnerability_class_ids or [])],
            class_codes=class_codes,
            required_capabilities=list(plan.required_capabilities or []),
            testing_mode=plan.testing_mode,
            safety_class=plan.safety_class,
            authorization_requirement=plan.authorization_requirement,
            target_url=target_url,
            asset_type=asset.asset_type if asset else None,
            credential_requirement=requirement.credential_requirement if requirement else None,
            requirement_id=str(requirement.id) if requirement else None,
            endpoint_context=endpoint_context,
            active_validation_allowed=active_validation_allowed,
            username=username,
            password=password,
        )

    async def _primary_asset(self, plan: TestPlan) -> Asset | None:
        if not plan.asset_ids:
            return None
        return await self.session.get(Asset, uuid.UUID(str(plan.asset_ids[0])))

    @staticmethod
    def _asset_url(asset: Asset | None) -> str | None:
        if not asset:
            return None
        metadata = asset.metadata_ or {}
        if asset.asset_type in {
            AssetType.WEB_APPLICATION.value,
            AssetType.ENDPOINT.value,
        }:
            return metadata.get("base_url") or metadata.get("url") or asset.normalized_key
        if asset.asset_type == AssetType.SERVICE.value:
            url = metadata.get("url")
            if url:
                return url
            scheme = metadata.get("scheme") or "https"
            host = metadata.get("hostname")
            port = metadata.get("port")
            if host:
                return f"{scheme}://{host}:{port}" if port else f"{scheme}://{host}"
        return asset.normalized_key

    @staticmethod
    def _error_result(
        scan_id: str,
        test_plan_id: str,
        error_codes: list[str],
        detail: str,
        decision_id: str | None = None,
    ) -> dict[str, Any]:
        return {
            "scan_id": scan_id,
            "test_plan_id": test_plan_id,
            "status": "ERROR",
            "error_codes": error_codes,
            "detail": detail,
            "decision_id": decision_id,
        }
