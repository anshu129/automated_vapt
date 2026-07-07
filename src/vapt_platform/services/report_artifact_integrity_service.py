"""Report artifact integrity verification (Phase 9)."""

from __future__ import annotations

import json
import logging
import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from vapt_platform.config.settings import get_settings
from vapt_platform.db.tables.models import ReportSnapshot
from vapt_platform.domain.artifact_integrity import IntegrityStatus, ScanIntegritySummary, SnapshotIntegrityResult
from vapt_platform.domain.report_artifact import ReportArtifactRef
from vapt_platform.services.report_artifact_store import ReportArtifactStore
from vapt_platform.services.report_hashing import compute_report_content_hash

logger = logging.getLogger(__name__)


class ReportArtifactIntegrityService:
    def __init__(self, session: AsyncSession, *, artifact_store: ReportArtifactStore | None = None) -> None:
        self.session = session
        self.artifact_store = artifact_store or ReportArtifactStore()

    async def verify_snapshot(self, snapshot: ReportSnapshot) -> SnapshotIntegrityResult:
        settings = get_settings()
        if not settings.phase9_integrity_audit_enabled:
            return SnapshotIntegrityResult(
                snapshot_id=str(snapshot.id),
                status=IntegrityStatus.OK.value,
                reasons=["integrity_audit_disabled"],
            )

        if not snapshot.replayable or not snapshot.artifact_reference:
            return SnapshotIntegrityResult(
                snapshot_id=str(snapshot.id),
                status=IntegrityStatus.REPLAY_UNAVAILABLE.value,
                reasons=["not_replayable"],
            )

        ref = ReportArtifactRef(
            snapshot_id=str(snapshot.id),
            scan_id=str(snapshot.scan_id),
            artifact_reference=snapshot.artifact_reference,
            artifact_hash=snapshot.artifact_hash or "",
            storage_backend=snapshot.artifact_storage_backend,
        )
        if not self.artifact_store.backend.exists(ref):
            return SnapshotIntegrityResult(
                snapshot_id=str(snapshot.id),
                status=IntegrityStatus.MISSING_ARTIFACT.value,
                reasons=["artifact_file_missing"],
                artifact_hash=snapshot.artifact_hash,
            )

        try:
            raw = self.artifact_store.backend.load(ref)
            report = json.loads(raw.decode("utf-8"))
            computed = compute_report_content_hash(report)
        except (FileNotFoundError, json.JSONDecodeError, OSError) as exc:
            return SnapshotIntegrityResult(
                snapshot_id=str(snapshot.id),
                status=IntegrityStatus.PARTIAL_FAILURE.value,
                reasons=[str(exc)],
            )

        if snapshot.artifact_hash and computed != snapshot.artifact_hash:
            return SnapshotIntegrityResult(
                snapshot_id=str(snapshot.id),
                status=IntegrityStatus.HASH_MISMATCH.value,
                reasons=["artifact_hash_mismatch"],
                artifact_hash=snapshot.artifact_hash,
                computed_hash=computed,
            )

        if snapshot.content_hash and computed != snapshot.content_hash:
            return SnapshotIntegrityResult(
                snapshot_id=str(snapshot.id),
                status=IntegrityStatus.STALE_METADATA.value,
                reasons=["content_hash_metadata_mismatch"],
                artifact_hash=snapshot.artifact_hash,
                computed_hash=computed,
            )

        snapshot.integrity_status = IntegrityStatus.OK.value
        return SnapshotIntegrityResult(
            snapshot_id=str(snapshot.id),
            status=IntegrityStatus.OK.value,
            artifact_hash=snapshot.artifact_hash,
            computed_hash=computed,
        )

    async def audit_scan(self, scan_id: uuid.UUID) -> ScanIntegritySummary:
        rows = list(
            (
                await self.session.execute(
                    select(ReportSnapshot)
                    .where(ReportSnapshot.scan_id == scan_id)
                    .order_by(ReportSnapshot.created_at.desc())
                )
            )
            .scalars()
            .all()
        )
        results: list[SnapshotIntegrityResult] = []
        ok_count = 0
        issue_count = 0
        for row in rows:
            result = await self.verify_snapshot(row)
            results.append(result)
            if result.status == IntegrityStatus.OK.value:
                ok_count += 1
            else:
                issue_count += 1
                row.integrity_status = result.status

        overall = IntegrityStatus.OK.value
        if issue_count and ok_count:
            overall = IntegrityStatus.PARTIAL_FAILURE.value
        elif issue_count:
            overall = results[0].status if len(results) == 1 else IntegrityStatus.PARTIAL_FAILURE.value

        await self.session.flush()
        logger.info(
            "report_integrity_audit scan_id=%s total=%d ok=%d issues=%d overall=%s",
            scan_id,
            len(rows),
            ok_count,
            issue_count,
            overall,
        )
        return ScanIntegritySummary(
            scan_id=str(scan_id),
            overall_status=overall,
            total_snapshots=len(rows),
            ok_count=ok_count,
            issue_count=issue_count,
            results=results,
        )
