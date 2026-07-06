"""Capability registry and selection."""

from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from vapt_platform.db.tables.models import CapabilityProvider, ToolManifest
from vapt_platform.domain.enums import Capability, CostTier
from vapt_platform.tools.manifest import load_tool_manifests, resolve_tool_binary


@dataclass
class ProviderInfo:
    id: str
    capability_code: str
    provider_name: str
    priority_weight: int
    cost_tier: str
    enabled: bool
    fake_behavior: str | None
    supported_profiles: list[str]
    binary_available: bool = False
    binary_name: str | None = None


@dataclass
class SelectionContext:
    scan_id: str
    execution_profile: str
    paid_apis_enabled: bool = False
    excluded_provider_ids: list[str] | None = None
    gain_by_provider: dict[str, int] | None = None
    min_gain_threshold: int = 5


class CapabilityRegistry:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self._manifests = load_tool_manifests()

    async def list_providers(self, capability: Capability | None = None) -> list[ProviderInfo]:
        stmt = select(CapabilityProvider).where(CapabilityProvider.enabled.is_(True))
        if capability:
            stmt = stmt.where(CapabilityProvider.capability_code == capability.value)
        result = await self.session.execute(stmt)
        infos: list[ProviderInfo] = []
        for p in result.scalars().all():
            manifest = await self.session.get(ToolManifest, p.manifest_id) if p.manifest_id else None
            manifest_name = manifest.name if manifest else p.provider_name
            manifest_spec = self._manifests.get(p.provider_name) or self._manifests.get(manifest_name)
            binary = manifest_spec.binary if manifest_spec else p.provider_name
            binary_available = bool(resolve_tool_binary(binary))
            if p.provider_name.startswith("fake-"):
                binary_available = True
            infos.append(
                ProviderInfo(
                    id=str(p.id),
                    capability_code=p.capability_code,
                    provider_name=p.provider_name,
                    priority_weight=p.priority_weight,
                    cost_tier=p.cost_tier,
                    enabled=p.enabled,
                    fake_behavior=p.fake_behavior,
                    supported_profiles=p.supported_profiles or [],
                    binary_available=binary_available,
                    binary_name=binary,
                )
            )
        return infos

    async def get_eligible(
        self,
        capability: Capability,
        ctx: SelectionContext,
    ) -> list[ProviderInfo]:
        providers = await self.list_providers(capability)
        eligible: list[ProviderInfo] = []
        excluded = set(ctx.excluded_provider_ids or [])
        for p in providers:
            if p.id in excluded:
                continue
            if p.cost_tier == CostTier.OPTIONAL_PAID.value and not ctx.paid_apis_enabled:
                continue
            if not p.binary_available and not p.provider_name.startswith("fake-"):
                continue
            if ctx.execution_profile not in p.supported_profiles and p.supported_profiles:
                if ctx.execution_profile not in ("STANDARD",):
                    continue
            eligible.append(p)
        return eligible


class CapabilitySelectionEngine:
    """Deterministic provider selection."""

    def select(
        self,
        capability: Capability,
        eligible: list[ProviderInfo],
        ctx: SelectionContext,
        exclude_provider_id: str | None = None,
    ) -> ProviderInfo | None:
        if not eligible:
            return None
        candidates = [p for p in eligible if p.id != exclude_provider_id]
        if not candidates:
            return None

        gain = ctx.gain_by_provider or {}

        def sort_key(p: ProviderInfo) -> tuple[Any, ...]:
            unique_gain = gain.get(p.id, 0)
            if unique_gain < ctx.min_gain_threshold and gain:
                return (-1, 0, 0, p.provider_name)
            real_provider = 0 if p.provider_name.startswith("fake-") else 1
            return (unique_gain, real_provider, p.priority_weight, p.provider_name)

        candidates.sort(key=sort_key, reverse=True)
        best = candidates[0]
        if gain and gain.get(best.id, 0) < ctx.min_gain_threshold and len(gain) > 0:
            return None
        return best
