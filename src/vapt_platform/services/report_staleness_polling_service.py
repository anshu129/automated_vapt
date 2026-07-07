"""Report staleness polling with cached freshness state (Phase 9)."""

from __future__ import annotations

import logging
import time
import uuid
from typing import Any, Awaitable, Callable

from sqlalchemy.ext.asyncio import AsyncSession

from vapt_platform.config.settings import get_settings
from vapt_platform.domain.report_artifact import ReportFreshnessResult
from vapt_platform.services.report_staleness_service import ReportStalenessService

logger = logging.getLogger(__name__)

_cache: dict[str, tuple[float, ReportFreshnessResult]] = {}

LiveReportBuilder = Callable[[uuid.UUID], Awaitable[dict[str, Any]]]


class ReportStalenessPollingService:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self._staleness = ReportStalenessService(session)

    async def poll(
        self,
        scan_id: uuid.UUID,
        *,
        force: bool = False,
        allow_full_hash: bool = False,
        live_report_builder: LiveReportBuilder | None = None,
    ) -> ReportFreshnessResult:
        settings = get_settings()
        if not settings.phase9_staleness_polling_enabled:
            return await self._staleness.evaluate(scan_id)

        cache_key = str(scan_id)
        now = time.monotonic()
        interval = settings.report_staleness_poll_interval_seconds

        if not force and cache_key in _cache:
            cached_at, cached_result = _cache[cache_key]
            if now - cached_at < interval:
                logger.info(
                    "report_staleness_poll_cached scan_id=%s stale_status=%s",
                    scan_id,
                    cached_result.status,
                )
                return cached_result

        result = await self._staleness.evaluate(
            scan_id,
            allow_full_hash=allow_full_hash,
            live_report_builder=live_report_builder,
        )
        if result.status != "FRESH":
            await self._staleness.mark_snapshot_stale_flags(scan_id)

        _cache[cache_key] = (now, result)
        logger.info(
            "report_staleness_polled scan_id=%s stale_status=%s check_method=%s",
            scan_id,
            result.status,
            result.check_method,
        )
        return result

    @staticmethod
    def clear_cache(scan_id: uuid.UUID | None = None) -> None:
        if scan_id is None:
            _cache.clear()
        else:
            _cache.pop(str(scan_id), None)
