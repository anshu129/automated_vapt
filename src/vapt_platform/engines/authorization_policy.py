"""Authorization policy for planned assessment operations (Phase 2)."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from vapt_platform.db.tables.models import Asset, Scan, ScopeSnapshot, TestPlan, TestRequirement
from vapt_platform.domain.enums import Capability, TestingMode
from vapt_platform.scope.manager import ScopeManager, ScopeRuleData, TargetDescriptor


@dataclass
class AuthorizationDecision:
    allowed: bool
    reason_codes: list[str] = field(default_factory=list)


_ACTIVE_CAPABILITIES = {
    Capability.INJECTION_VALIDATION.value,
    Capability.WEB_ACTIVE_ASSESSMENT.value,
}


class AuthorizationPolicy:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def evaluate(
        self,
        *,
        scan_id: uuid.UUID,
        plan: TestPlan,
        requirement: TestRequirement | None,
        capability: str,
        asset: Asset | None,
        active_validation_allowed: bool,
        authenticated_testing_allowed: bool = True,
    ) -> AuthorizationDecision:
        if str(plan.scan_id) != str(scan_id):
            return AuthorizationDecision(
                allowed=False,
                reason_codes=["PLAN_SCAN_MISMATCH"],
            )
        if requirement is not None:
            matrix = requirement.matrix_id
            from vapt_platform.db.tables.models import AssetTestMatrix

            row = await self.session.get(AssetTestMatrix, matrix)
            if row and str(row.scan_id) != str(scan_id):
                return AuthorizationDecision(
                    allowed=False,
                    reason_codes=["REQUIREMENT_SCAN_MISMATCH"],
                )

        if asset is None:
            return AuthorizationDecision(
                allowed=False,
                reason_codes=["OUT_OF_SCOPE"],
            )

        scope_rules = await self._scope_rules(scan_id)
        manager = ScopeManager(scope_rules)
        target = self._target_for_asset(asset)
        scope_decision = manager.evaluate(target, capability)
        if not scope_decision.allowed:
            return AuthorizationDecision(
                allowed=False,
                reason_codes=["OUT_OF_SCOPE"],
            )

        if capability in _ACTIVE_CAPABILITIES and not active_validation_allowed:
            return AuthorizationDecision(
                allowed=False,
                reason_codes=["ACTIVE_TESTING_NOT_AUTHORIZED"],
            )

        if (
            requirement
            and requirement.credential_requirement == "AUTHENTICATED"
            and not authenticated_testing_allowed
        ):
            return AuthorizationDecision(
                allowed=False,
                reason_codes=["AUTHENTICATED_TESTING_NOT_AUTHORIZED"],
            )

        if plan.authorization_requirement not in {"PRE_APPROVED", "AUTHORIZED"}:
            if plan.testing_mode == TestingMode.AUTOMATED.value:
                return AuthorizationDecision(
                    allowed=False,
                    reason_codes=["CAPABILITY_NOT_ALLOWED"],
                )

        return AuthorizationDecision(allowed=True)

    async def _scope_rules(self, scan_id: uuid.UUID) -> list[ScopeRuleData]:
        scan = await self.session.get(Scan, scan_id)
        if not scan:
            return []
        snapshot = (
            await self.session.execute(
                select(ScopeSnapshot)
                .where(ScopeSnapshot.project_id == scan.project_id)
                .order_by(ScopeSnapshot.created_at.desc())
            )
        ).scalar_one_or_none()
        if snapshot and snapshot.rules:
            return [
                ScopeRuleData(
                    rule_type=rule.get("rule_type", ""),
                    pattern=rule.get("pattern", ""),
                    assessment_mode=rule.get("assessment_mode", "ACTIVE"),
                    priority=int(rule.get("priority", 0)),
                    enabled=bool(rule.get("enabled", True)),
                )
                for rule in snapshot.rules
                if isinstance(rule, dict)
            ]
        from vapt_platform.db.tables.models import ScopeRule

        rows = list(
            (
                await self.session.execute(
                    select(ScopeRule).where(ScopeRule.project_id == scan.project_id)
                )
            )
            .scalars()
            .all()
        )
        return [
            ScopeRuleData(
                rule_type=row.rule_type,
                pattern=row.pattern,
                assessment_mode=row.assessment_mode,
                priority=row.priority,
                enabled=row.enabled,
            )
            for row in rows
        ]

    @staticmethod
    def _target_for_asset(asset: Asset) -> TargetDescriptor:
        metadata = asset.metadata_ or {}
        return TargetDescriptor(
            hostname=metadata.get("hostname") or asset.normalized_key,
            url=metadata.get("base_url") or metadata.get("url"),
            ip=metadata.get("ip"),
            port=metadata.get("port"),
            domain=metadata.get("domain") or asset.normalized_key,
        )
