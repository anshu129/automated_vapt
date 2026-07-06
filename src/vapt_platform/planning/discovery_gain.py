"""Marginal discovery gain tracking."""

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from vapt_platform.db.tables.models import DiscoveryGainMetric


class MarginalDiscoveryGainEngine:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def record(
        self,
        scan_id: uuid.UUID | str,
        capability_code: str,
        provider_id: uuid.UUID | str | None,
        raw_count: int,
        unique_assets: int,
        unique_endpoints: int = 0,
        duration_ms: int = 0,
    ) -> DiscoveryGainMetric:
        stmt = select(DiscoveryGainMetric).where(
            DiscoveryGainMetric.scan_id == scan_id,
            DiscoveryGainMetric.capability_code == capability_code,
            DiscoveryGainMetric.provider_id == provider_id,
        )
        result = await self.session.execute(stmt)
        metric = result.scalar_one_or_none()
        if metric is None:
            metric = DiscoveryGainMetric(
                scan_id=scan_id,
                capability_code=capability_code,
                provider_id=provider_id,
            )
            self.session.add(metric)
        metric.raw_observation_count = (metric.raw_observation_count or 0) + raw_count
        metric.unique_asset_count = max(metric.unique_asset_count or 0, unique_assets)
        metric.unique_endpoint_count = max(metric.unique_endpoint_count or 0, unique_endpoints)
        metric.historical_unique_gain = unique_assets
        metric.execution_duration_ms = (metric.execution_duration_ms or 0) + duration_ms
        if metric.raw_observation_count > 0:
            metric.duplicate_ratio = 1.0 - (
                metric.unique_asset_count / max(metric.raw_observation_count, 1)
            )
        return metric

    async def should_continue_provider(
        self,
        scan_id: str,
        capability_code: str,
        provider_id: str,
        min_gain: int = 1,
    ) -> bool:
        stmt = select(DiscoveryGainMetric).where(
            DiscoveryGainMetric.scan_id == scan_id,
            DiscoveryGainMetric.capability_code == capability_code,
        )
        result = await self.session.execute(stmt)
        metrics = list(result.scalars().all())
        if len(metrics) < 2:
            return True
        for m in metrics:
            if str(m.provider_id) == provider_id:
                return m.historical_unique_gain >= min_gain or len(metrics) == 1
        return True

    async def get_metrics(self, scan_id: uuid.UUID | str) -> list[DiscoveryGainMetric]:
        sid = uuid.UUID(str(scan_id)) if not isinstance(scan_id, uuid.UUID) else scan_id
        stmt = select(DiscoveryGainMetric).where(DiscoveryGainMetric.scan_id == sid)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())
