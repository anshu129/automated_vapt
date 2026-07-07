"""Evidence graph service (Phase 3)."""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from vapt_platform.db.tables.models import EvidenceLink, EvidenceNode


class EvidenceGraphService:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def get_or_create_node(
        self,
        *,
        scan_id: uuid.UUID,
        node_type: str,
        entity_type: str,
        entity_id: uuid.UUID,
        test_execution_id: uuid.UUID | None = None,
        provenance: dict[str, Any] | None = None,
        idempotency_key: str | None = None,
    ) -> EvidenceNode:
        if idempotency_key:
            existing = (
                await self.session.execute(
                    select(EvidenceNode).where(
                        EvidenceNode.scan_id == scan_id,
                        EvidenceNode.idempotency_key == idempotency_key,
                    )
                )
            ).scalar_one_or_none()
            if existing:
                return existing

        node = EvidenceNode(
            scan_id=scan_id,
            node_type=node_type,
            entity_type=entity_type,
            entity_id=entity_id,
            test_execution_id=test_execution_id,
            provenance=provenance or {},
            idempotency_key=idempotency_key,
        )
        self.session.add(node)
        await self.session.flush()
        return node

    async def link(
        self,
        *,
        scan_id: uuid.UUID,
        source_node_id: uuid.UUID,
        target_type: str,
        target_id: uuid.UUID,
        relationship_type: str,
        confidence: float = 0.5,
        reason_code: str | None = None,
        policy_version: str | None = None,
        provenance: dict[str, Any] | None = None,
    ) -> EvidenceLink:
        link_prov = dict(provenance or {})
        if reason_code:
            link_prov["reason_code"] = reason_code
        if policy_version:
            link_prov["rule_or_policy_version"] = policy_version

        existing = (
            await self.session.execute(
                select(EvidenceLink).where(
                    EvidenceLink.scan_id == scan_id,
                    EvidenceLink.source_id == source_node_id,
                    EvidenceLink.target_type == target_type,
                    EvidenceLink.target_id == target_id,
                    EvidenceLink.link_type == relationship_type,
                )
            )
        ).scalar_one_or_none()
        if existing:
            return existing

        edge = EvidenceLink(
            scan_id=scan_id,
            source_type="EVIDENCE_NODE",
            source_id=source_node_id,
            target_type=target_type,
            target_id=target_id,
            link_type=relationship_type,
            weight=confidence,
            provenance=link_prov,
        )
        self.session.add(edge)
        await self.session.flush()
        return edge
