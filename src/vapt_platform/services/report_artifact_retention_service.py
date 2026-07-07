"""Report artifact retention service (Phase 9)."""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from vapt_platform.config.settings import get_settings
from vapt_platform.db.tables.models import ReportSnapshot
from vapt_platform.domain.artifact_retention import RetentionAction, RetentionCandidate, RetentionResult
from vapt_platform.domain.report_artifact import ReportArtifactRef
from vapt_platform.services.report_artifact_store import ReportArtifactStore

logger = logging.getLogger(__name__)


class ReportArtifactRetentionPolicy:
    def __init__(
        self,
        *,
        max_versions_per_scan: int = 10,
        ttl_days: int = 90,
        keep_latest: bool = True,
        keep_terminal: bool = True,
    ) -> None:
        self.max_versions_per_scan = max_versions_per_scan
        self.ttl_days = ttl_days
        self.keep_latest = keep_latest
        self.keep_terminal = keep_terminal

    @classmethod
    def from_settings(cls) -> ReportArtifactRetentionPolicy:
        settings = get_settings()
        return cls(
            max_versions_per_scan=settings.report_artifact_max_versions_per_scan,
            ttl_days=settings.report_artifact_ttl_days,
            keep_latest=settings.report_artifact_keep_latest,
            keep_terminal=settings.report_artifact_keep_terminal,
        )


class ReportArtifactRetentionService:
    def __init__(self, session: AsyncSession, *, artifact_store: ReportArtifactStore | None = None) -> None:
        self.session = session
        self.artifact_store = artifact_store or ReportArtifactStore()
        self.policy = ReportArtifactRetentionPolicy.from_settings()

    async def list_candidates(self, scan_id) -> list[RetentionCandidate]:  # type: ignore[no-untyped-def]
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
        if not rows:
            return []

        candidates: list[RetentionCandidate] = []
        now = datetime.now(timezone.utc)
        ttl_cutoff = now - timedelta(days=self.policy.ttl_days)
        latest_id = str(rows[0].id)

        for index, row in enumerate(rows):
            action = RetentionAction.KEEP.value
            reason = "within_policy"
            created = row.created_at
            if isinstance(created, datetime):
                if created.tzinfo is None:
                    created = created.replace(tzinfo=timezone.utc)
            else:
                created = None

            if self.policy.keep_latest and str(row.id) == latest_id:
                action = RetentionAction.KEEP.value
                reason = "keep_latest"
            elif self.policy.keep_terminal and row.assessment_status in {
                "COMPLETE",
                "COMPLETED",
                "ACCEPTED_WITH_GAPS",
            }:
                if index == 0:
                    action = RetentionAction.KEEP.value
                    reason = "keep_terminal_latest"
            elif created and created < ttl_cutoff:
                action = RetentionAction.EXPIRED.value
                reason = "ttl_expired"
            elif index >= self.policy.max_versions_per_scan:
                action = RetentionAction.DELETE_CANDIDATE.value
                reason = "max_versions_exceeded"

            if len(rows) == 1 and action != RetentionAction.KEEP.value:
                action = RetentionAction.KEEP.value
                reason = "only_snapshot"

            candidates.append(
                RetentionCandidate(
                    snapshot_id=str(row.id),
                    scan_id=str(scan_id),
                    action=action,
                    reason=reason,
                    artifact_reference=row.artifact_reference,
                    created_at=row.created_at.isoformat() if row.created_at else None,
                )
            )
        return candidates

    async def cleanup(self, scan_id, *, dry_run: bool = True) -> RetentionResult:  # type: ignore[no-untyped-def]
        settings = get_settings()
        if not settings.phase9_artifact_retention_enabled:
            return RetentionResult(dry_run=dry_run, errors=["retention_disabled"])

        candidates = await self.list_candidates(scan_id)
        result = RetentionResult(dry_run=dry_run, candidates=candidates)
        deletable = [
            c
            for c in candidates
            if c.action in {RetentionAction.DELETE_CANDIDATE.value, RetentionAction.EXPIRED.value}
        ]

        for candidate in candidates:
            if candidate.action == RetentionAction.KEEP.value:
                result.kept += 1

        if dry_run:
            logger.info(
                "report_retention_dry_run scan_id=%s candidates=%d deletable=%d",
                scan_id,
                len(candidates),
                len(deletable),
            )
            return result

        for candidate in deletable:
            row = await self.session.get(ReportSnapshot, uuid.UUID(candidate.snapshot_id))
            if not row or not row.artifact_reference:
                continue
            try:
                self.artifact_store.delete(
                    row.artifact_reference,
                    scan_id=str(scan_id),
                    snapshot_id=candidate.snapshot_id,
                )
                row.replayable = False
                row.artifact_retention_status = "deleted"
                result.deleted += 1
                logger.info(
                    "report_artifact_retained_deleted scan_id=%s report_snapshot_id=%s reason=%s",
                    scan_id,
                    candidate.snapshot_id,
                    candidate.reason,
                )
            except OSError as exc:
                result.errors.append(str(exc))

        await self.session.flush()
        return result
