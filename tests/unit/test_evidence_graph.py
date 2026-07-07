"""Evidence graph idempotency tests."""

import uuid

import pytest

from vapt_platform.services.core import ProjectService, ScanService
from vapt_platform.services.evidence_graph import EvidenceGraphService


@pytest.mark.asyncio
async def test_duplicate_node_not_created(db_session) -> None:
    project = await ProjectService(db_session).create("Graph")
    scan = await ScanService(db_session).create(project.id, "Graph Scan", [])
    graph = EvidenceGraphService(db_session)
    entity_id = uuid.uuid4()
    first = await graph.get_or_create_node(
        scan_id=scan.id,
        node_type="OBSERVATION",
        entity_type="OBSERVATION",
        entity_id=entity_id,
        idempotency_key="key-1",
    )
    second = await graph.get_or_create_node(
        scan_id=scan.id,
        node_type="OBSERVATION",
        entity_type="OBSERVATION",
        entity_id=entity_id,
        idempotency_key="key-1",
    )
    assert first.id == second.id
