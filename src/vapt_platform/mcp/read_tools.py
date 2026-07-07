"""Read-only assessment views shared by MCP tools."""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from vapt_platform.api.routes.core import (
    list_ai_enrichments,
    list_confirmed_findings,
    list_hypotheses,
    list_verdicts,
    scan_test_matrix,
    scan_vulnerability_coverage,
    validation_backlog,
    vulnerability_classes,
)
from vapt_platform.db.tables.models import (
    AssessmentCompletionRecord,
    Asset,
    EvidenceLink,
    Relationship,
    Scan,
)
from vapt_platform.services.credentials import CredentialContextService


class AssessmentMCPReadService:
    """Sanitized read models; no domain state transitions."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def get_scan_overview(self, scan_id: uuid.UUID) -> dict[str, Any]:
        scan = await self.session.get(Scan, scan_id)
        if not scan:
            raise ValueError("Scan not found")
        asset_count = (
            await self.session.execute(
                select(func.count(Asset.id)).where(Asset.scan_id == scan_id)
            )
        ).scalar_one()
        relationship_count = (
            await self.session.execute(
                select(func.count(Relationship.id)).where(
                    Relationship.scan_id == scan_id
                )
            )
        ).scalar_one()
        return {
            "id": str(scan.id),
            "project_id": str(scan.project_id),
            "name": scan.name,
            "status": scan.status,
            "operational_profile": scan.operational_profile,
            "workflow_version": scan.workflow_version,
            "rule_set_version": scan.rule_set_version,
            "asset_count": asset_count,
            "relationship_count": relationship_count,
        }

    async def list_scan_assets(self, scan_id: uuid.UUID) -> dict[str, Any]:
        assets = list(
            (await self.session.execute(select(Asset).where(Asset.scan_id == scan_id)))
            .scalars()
            .all()
        )
        return {
            "items": [
                {
                    "id": str(asset.id),
                    "asset_type": asset.asset_type,
                    "display_name": asset.display_name,
                    "normalized_key": asset.normalized_key,
                    "confidence": asset.confidence,
                    "criticality": asset.criticality,
                }
                for asset in assets
            ],
            "total": len(assets),
            "sanitized": True,
        }

    async def get_attack_surface_graph(self, scan_id: uuid.UUID) -> dict[str, Any]:
        assets = list(
            (await self.session.execute(select(Asset).where(Asset.scan_id == scan_id)))
            .scalars()
            .all()
        )
        relationships = list(
            (
                await self.session.execute(
                    select(Relationship).where(Relationship.scan_id == scan_id)
                )
            )
            .scalars()
            .all()
        )
        return {
            "nodes": [
                {
                    "id": str(asset.id),
                    "asset_type": asset.asset_type,
                    "display_name": asset.display_name,
                    "criticality": asset.criticality,
                }
                for asset in assets
            ],
            "edges": [
                {
                    "id": str(relationship.id),
                    "source_asset_id": str(relationship.source_asset_id),
                    "target_asset_id": str(relationship.target_asset_id),
                    "relationship_type": relationship.relationship_type,
                    "confidence": relationship.confidence,
                    "active": relationship.active,
                }
                for relationship in relationships
            ],
        }

    async def get_vulnerability_catalog(self) -> dict[str, Any]:
        return await vulnerability_classes(self.session)

    async def get_vulnerability_coverage(
        self, scan_id: uuid.UUID
    ) -> dict[str, Any]:
        return await scan_vulnerability_coverage(scan_id, self.session)

    async def get_test_matrix(self, scan_id: uuid.UUID) -> dict[str, Any]:
        return await scan_test_matrix(scan_id, self.session)

    async def get_validation_backlog(
        self, scan_id: uuid.UUID
    ) -> dict[str, Any]:
        return await validation_backlog(scan_id, self.session)

    async def get_hypotheses(self, scan_id: uuid.UUID) -> dict[str, Any]:
        return await list_hypotheses(scan_id, self.session)

    async def get_verdicts(self, scan_id: uuid.UUID) -> dict[str, Any]:
        return await list_verdicts(scan_id, self.session)

    async def get_confirmed_findings(
        self, scan_id: uuid.UUID
    ) -> dict[str, Any]:
        return await list_confirmed_findings(scan_id, self.session)

    async def get_completion_status(self, scan_id: uuid.UUID) -> dict[str, Any]:
        record = (
            await self.session.execute(
                select(AssessmentCompletionRecord).where(
                    AssessmentCompletionRecord.scan_id == scan_id
                )
            )
        ).scalar_one_or_none()
        if not record:
            return {
                "status": "NOT_EVALUATED",
                "blocking_items": [],
                "metrics": {},
            }
        return {
            "status": record.status,
            "blocking_items": record.blocking_items,
            "completion_reasons": record.completion_reasons,
            "metrics": record.metrics,
            "evaluated_at": (
                record.evaluated_at.isoformat() if record.evaluated_at else None
            ),
        }

    async def get_ai_advisories(self, scan_id: uuid.UUID) -> dict[str, Any]:
        return await list_ai_enrichments(scan_id, self.session)

    async def get_hypothesis_evidence(
        self, hypothesis_id: uuid.UUID
    ) -> dict[str, Any]:
        links = list(
            (
                await self.session.execute(
                    select(EvidenceLink).where(
                        EvidenceLink.target_type == "HYPOTHESIS",
                        EvidenceLink.target_id == hypothesis_id,
                    )
                )
            )
            .scalars()
            .all()
        )
        return {
            "hypothesis_id": str(hypothesis_id),
            "links": [
                {
                    "id": str(link.id),
                    "source_type": link.source_type,
                    "source_id": str(link.source_id),
                    "link_type": link.link_type,
                    "weight": link.weight,
                    "provenance": link.provenance,
                }
                for link in links
            ],
            "raw_artifacts_excluded": True,
        }

    async def get_auth_coverage(self, scan_id: uuid.UUID) -> dict[str, Any]:
        return await CredentialContextService(self.session).get_auth_coverage(scan_id)

    async def get_role_coverage(self, scan_id: uuid.UUID) -> dict[str, Any]:
        return await CredentialContextService(self.session).get_role_coverage(scan_id)
