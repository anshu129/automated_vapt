"""Report staleness detection with fingerprint and full-hash fallback (Phase 8/9)."""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from vapt_platform.config.settings import get_settings
from vapt_platform.db.tables.models import (
    AssessmentCompletionRecord,
    Asset,
    AssetTestMatrix,
    ReportSnapshot,
    TestRequirement,
)
from vapt_platform.domain.report_artifact import ReportFreshnessResult, ReportStalenessStatus
from vapt_platform.services.report_hashing import (
    compute_live_fingerprint_hash,
    compute_report_content_hash,
)

logger = logging.getLogger(__name__)

LiveReportBuilder = Callable[[uuid.UUID], Awaitable[dict[str, Any]]]


class ReportStalenessService:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def build_live_fingerprint(self, scan_id: uuid.UUID) -> dict[str, Any]:
        record = (
            await self.session.execute(
                select(AssessmentCompletionRecord).where(
                    AssessmentCompletionRecord.scan_id == scan_id
                )
            )
        ).scalar_one_or_none()
        asset_count = (
            await self.session.execute(
                select(func.count()).select_from(Asset).where(Asset.scan_id == scan_id)
            )
        ).scalar_one()
        req_count = (
            await self.session.execute(
                select(func.count())
                .select_from(TestRequirement)
                .join(AssetTestMatrix, TestRequirement.matrix_id == AssetTestMatrix.id)
                .where(AssetTestMatrix.scan_id == scan_id)
            )
        ).scalar_one()
        return {
            "scan_id": str(scan_id),
            "assessment_status": record.status if record else None,
            "completion_version": record.evaluation_version if record else None,
            "reason_codes": list(record.reason_codes or []) if record else [],
            "latest_transition_id": (
                str(record.latest_transition_id) if record and record.latest_transition_id else None
            ),
            "asset_count": asset_count,
            "requirement_count": req_count,
            "bound_reached": record.bound_reached if record else None,
        }

    async def evaluate(
        self,
        scan_id: uuid.UUID,
        *,
        snapshot: ReportSnapshot | None = None,
        allow_full_hash: bool = False,
        live_report_builder: LiveReportBuilder | None = None,
    ) -> ReportFreshnessResult:
        settings = get_settings()
        if not settings.phase8_report_staleness_detection_enabled:
            return ReportFreshnessResult(status=ReportStalenessStatus.UNKNOWN.value)

        if snapshot is None:
            snapshot = (
                await self.session.execute(
                    select(ReportSnapshot)
                    .where(ReportSnapshot.scan_id == scan_id)
                    .order_by(ReportSnapshot.created_at.desc())
                    .limit(1)
                )
            ).scalar_one_or_none()

        if not snapshot:
            return ReportFreshnessResult(
                status=ReportStalenessStatus.UNKNOWN.value, reasons=["no_snapshot"]
            )

        record = (
            await self.session.execute(
                select(AssessmentCompletionRecord).where(
                    AssessmentCompletionRecord.scan_id == scan_id
                )
            )
        ).scalar_one_or_none()

        reasons: list[str] = []
        current_status = record.status if record else None
        current_version = record.evaluation_version if record else None
        current_transition = (
            str(record.latest_transition_id) if record and record.latest_transition_id else None
        )

        if (
            current_status
            and snapshot.assessment_status
            and current_status != snapshot.assessment_status
        ):
            reasons.append("assessment_status_changed")
        if (
            current_version
            and snapshot.completion_version
            and current_version != snapshot.completion_version
        ):
            reasons.append("completion_version_changed")
        if (
            current_transition
            and snapshot.live_hash_at_generation
            and current_transition != snapshot.live_hash_at_generation
        ):
            reasons.append("completion_transition_changed")

        live_fingerprint = await self.build_live_fingerprint(scan_id)
        live_fp_hash = compute_live_fingerprint_hash(live_fingerprint)
        stored_fp_hash = getattr(snapshot, "fingerprint_hash", None) or ""

        status = ReportStalenessStatus.FRESH.value
        check_method = "fingerprint"
        fallback_used = False
        live_content_hash: str | None = None

        if reasons:
            status = ReportStalenessStatus.STALE.value
        elif stored_fp_hash and live_fp_hash != stored_fp_hash:
            status = ReportStalenessStatus.STALE.value
            reasons.append("live_fingerprint_hash_mismatch")
        elif not stored_fp_hash and snapshot.content_hash:
            # Legacy snapshots without fingerprint_hash: inconclusive without fallback
            if allow_full_hash and live_report_builder and settings.phase9_staleness_full_hash_fallback_enabled:
                live_report = await live_report_builder(scan_id)
                live_content_hash = compute_report_content_hash(live_report)
                check_method = "full_hash"
                fallback_used = True
                if live_content_hash != snapshot.content_hash:
                    status = ReportStalenessStatus.STALE.value
                    reasons.append("full_live_hash_mismatch")
            else:
                status = ReportStalenessStatus.UNKNOWN.value
                reasons.append("fingerprint_hash_missing")

        if snapshot.stale and status == ReportStalenessStatus.FRESH.value:
            status = ReportStalenessStatus.STALE.value
            reasons.append("snapshot_marked_stale")

        if (
            status == ReportStalenessStatus.UNKNOWN.value
            and allow_full_hash
            and live_report_builder
            and settings.phase9_staleness_full_hash_fallback_enabled
            and "fingerprint_hash_missing" in reasons
        ):
            live_report = await live_report_builder(scan_id)
            live_content_hash = compute_report_content_hash(live_report)
            check_method = "full_hash"
            fallback_used = True
            if live_content_hash == snapshot.content_hash:
                status = ReportStalenessStatus.FRESH.value
                reasons = [r for r in reasons if r != "fingerprint_hash_missing"]
            else:
                status = ReportStalenessStatus.REGENERATE_REQUIRED.value
                reasons.append("full_live_hash_mismatch")

        logger.info(
            "report_staleness_evaluated scan_id=%s report_snapshot_id=%s stale_status=%s "
            "reasons=%s check_method=%s content_hash_prefix=%s",
            scan_id,
            snapshot.id,
            status,
            reasons,
            check_method,
            (snapshot.content_hash or "")[:12],
        )
        return ReportFreshnessResult(
            status=status,
            snapshot_id=str(snapshot.id),
            snapshot_hash=snapshot.content_hash,
            live_hash=live_content_hash,
            fingerprint_hash=stored_fp_hash or None,
            live_fingerprint_hash=live_fp_hash,
            reasons=reasons,
            assessment_status=current_status,
            snapshot_assessment_status=snapshot.assessment_status,
            completion_version=current_version,
            snapshot_completion_version=snapshot.completion_version,
            check_method=check_method,
            fallback_used=fallback_used,
            polled_at=datetime.now(timezone.utc).isoformat(),
        )

    async def mark_snapshot_stale_flags(self, scan_id: uuid.UUID) -> None:
        freshness = await self.evaluate(scan_id)
        if freshness.status != ReportStalenessStatus.FRESH.value:
            snapshots = list(
                (
                    await self.session.execute(
                        select(ReportSnapshot).where(ReportSnapshot.scan_id == scan_id)
                    )
                )
                .scalars()
                .all()
            )
            for snap in snapshots:
                snap.stale = True
            await self.session.flush()
            logger.info(
                "report_snapshots_marked_stale scan_id=%s count=%d stale_status=%s",
                scan_id,
                len(snapshots),
                freshness.status,
            )
