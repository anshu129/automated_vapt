"""Report snapshot persistence and hashing (Phase 7/8/9)."""

from __future__ import annotations

import logging
import uuid
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from vapt_platform.config.settings import get_settings
from vapt_platform.db.tables.models import AssessmentCompletionRecord, ReportSnapshot
from vapt_platform.domain.report_artifact import ReportStalenessStatus
from vapt_platform.domain.report_snapshot import REPORT_VERSION, ReportSnapshotMetadata
from vapt_platform.services.report_artifact_store import ReportArtifactStore
from vapt_platform.services.report_hashing import (
    compute_live_fingerprint_hash,
    compute_report_content_hash,
)
from vapt_platform.services.report_staleness_polling_service import ReportStalenessPollingService

logger = logging.getLogger(__name__)

GENERATION_VERSION = "phase9-v1"


class ReportSnapshotService:
    def __init__(
        self,
        session: AsyncSession,
        *,
        artifact_store: ReportArtifactStore | None = None,
    ) -> None:
        self.session = session
        self._artifact_store = artifact_store

    @property
    def artifact_store(self) -> ReportArtifactStore:
        if self._artifact_store is None:
            self._artifact_store = ReportArtifactStore()
        return self._artifact_store

    @artifact_store.setter
    def artifact_store(self, store: ReportArtifactStore) -> None:
        self._artifact_store = store

    async def create_snapshot(
        self,
        scan_id: uuid.UUID,
        report: dict[str, Any],
        *,
        job_status: str | None = None,
        generated_by: str = "report-generator",
    ) -> ReportSnapshot | None:
        settings = get_settings()
        if not settings.phase7_report_snapshots_enabled:
            return None

        completion = report.get("assessment_completion") or {}
        assessment_status = completion.get("assessment_status") or report.get("summary", {}).get(
            "completion_status"
        )
        reason_codes = list(completion.get("reason_codes") or [])
        bound_reached = completion.get("bound_reached")
        pending = completion.get("pending_work_summary") or completion.get("pending_work") or {}
        accepted_gaps = completion.get("accepted_gaps") or {}
        accepted_count = sum(len(v) if isinstance(v, list) else 0 for v in accepted_gaps.values())
        pending_count = pending.get("total", 0) if isinstance(pending, dict) else 0
        completion_version = completion.get("evaluation_version") or "unknown"
        content_hash = compute_report_content_hash(report)

        record = (
            await self.session.execute(
                select(AssessmentCompletionRecord).where(
                    AssessmentCompletionRecord.scan_id == scan_id
                )
            )
        ).scalar_one_or_none()
        live_transition = (
            str(record.latest_transition_id) if record and record.latest_transition_id else None
        )

        from vapt_platform.services.report_staleness_service import ReportStalenessService

        live_fp = await ReportStalenessService(self.session).build_live_fingerprint(scan_id)
        fingerprint_hash = compute_live_fingerprint_hash(live_fp)

        row = ReportSnapshot(
            scan_id=scan_id,
            report_version=REPORT_VERSION,
            completion_version=completion_version,
            generation_version=GENERATION_VERSION,
            content_hash=content_hash,
            fingerprint_hash=fingerprint_hash,
            assessment_status=assessment_status,
            job_status=job_status,
            reason_codes=reason_codes,
            bound_reached=bound_reached,
            accepted_gaps_count=accepted_count,
            pending_work_count=pending_count,
            generated_by=generated_by,
            content_summary={
                "scan_id": str(scan_id),
                "summary": report.get("summary"),
                "assessment_status": assessment_status,
                "reason_codes": reason_codes,
            },
            live_hash_at_generation=live_transition,
            stale=False,
            artifact_retention_status="active",
        )
        self.session.add(row)
        await self.session.flush()

        if settings.phase8_report_artifact_storage_enabled:
            ref = self.artifact_store.store(scan_id, row.id, report)
            row.artifact_reference = ref.artifact_reference
            row.artifact_hash = ref.artifact_hash
            row.artifact_content_type = ref.content_type
            row.artifact_size = ref.artifact_size
            row.artifact_storage_backend = ref.storage_backend
            row.replayable = ref.replayable
            await self.session.flush()

        ReportStalenessPollingService.clear_cache(scan_id)
        logger.info(
            "report_snapshot_created scan_id=%s report_snapshot_id=%s report_version=%s "
            "content_hash_prefix=%s fingerprint_hash_prefix=%s assessment_status=%s replayable=%s "
            "artifact_backend=%s",
            scan_id,
            row.id,
            REPORT_VERSION,
            content_hash[:12],
            fingerprint_hash[:12],
            assessment_status,
            row.replayable,
            row.artifact_storage_backend,
        )
        return row

    def _metadata_from_row(
        self, row: ReportSnapshot, *, freshness_status: str | None = None, is_stale: bool | None = None
    ) -> ReportSnapshotMetadata:
        return ReportSnapshotMetadata(
            id=str(row.id),
            scan_id=str(row.scan_id),
            report_version=row.report_version,
            completion_version=row.completion_version,
            generation_version=row.generation_version,
            content_hash=row.content_hash,
            fingerprint_hash=getattr(row, "fingerprint_hash", None),
            assessment_status=row.assessment_status,
            job_status=row.job_status,
            reason_codes=list(row.reason_codes or []),
            bound_reached=row.bound_reached,
            accepted_gaps_count=row.accepted_gaps_count,
            pending_work_count=row.pending_work_count,
            generated_by=row.generated_by,
            created_at=row.created_at.isoformat() if row.created_at else None,
            is_stale=is_stale if is_stale is not None else row.stale,
            artifact_reference=row.artifact_reference,
            artifact_hash=row.artifact_hash,
            artifact_storage_backend=row.artifact_storage_backend,
            replayable=row.replayable,
            freshness_status=freshness_status,
            integrity_status=getattr(row, "integrity_status", None),
            artifact_retention_status=getattr(row, "artifact_retention_status", None),
        )

    async def latest_snapshot(self, scan_id: uuid.UUID) -> ReportSnapshotMetadata | None:
        row = (
            await self.session.execute(
                select(ReportSnapshot)
                .where(ReportSnapshot.scan_id == scan_id)
                .order_by(ReportSnapshot.created_at.desc())
                .limit(1)
            )
        ).scalar_one_or_none()
        if not row:
            return None
        freshness_status = None
        is_stale = row.stale
        settings = get_settings()
        if settings.phase8_report_staleness_detection_enabled:
            from vapt_platform.services.report_staleness_service import ReportStalenessService

            if settings.phase9_staleness_polling_enabled:
                freshness = await ReportStalenessPollingService(self.session).poll(scan_id)
            else:
                freshness = await ReportStalenessService(self.session).evaluate(
                    scan_id, snapshot=row
                )
            freshness_status = freshness.status
            is_stale = freshness.status != ReportStalenessStatus.FRESH.value
        return self._metadata_from_row(row, freshness_status=freshness_status, is_stale=is_stale)

    async def fetch_snapshot(self, snapshot_id: uuid.UUID) -> ReportSnapshot | None:
        return await self.session.get(ReportSnapshot, snapshot_id)

    async def load_artifact(self, snapshot: ReportSnapshot) -> dict[str, Any]:
        if not snapshot.artifact_reference or not snapshot.replayable:
            raise FileNotFoundError("Snapshot is not replayable")
        return self.artifact_store.load(
            snapshot.artifact_reference,
            backend_name=snapshot.artifact_storage_backend,
        )

    async def list_snapshots(
        self, scan_id: uuid.UUID, *, limit: int = 20
    ) -> list[ReportSnapshotMetadata]:
        rows = list(
            (
                await self.session.execute(
                    select(ReportSnapshot)
                    .where(ReportSnapshot.scan_id == scan_id)
                    .order_by(ReportSnapshot.created_at.desc())
                    .limit(limit)
                )
            )
            .scalars()
            .all()
        )
        return [self._metadata_from_row(row) for row in rows]
