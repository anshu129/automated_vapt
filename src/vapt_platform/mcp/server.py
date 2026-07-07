"""Optional stdio MCP server exposing sanitized assessment read models."""

from __future__ import annotations

import uuid
from typing import Any

from vapt_platform.config.settings import get_settings
from vapt_platform.db.session import session_scope
from vapt_platform.mcp.read_tools import AssessmentMCPReadService


def build_server() -> Any:
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError as exc:
        raise RuntimeError(
            'MCP support is not installed. Install the optional dependency with '
            'pip install -e ".[mcp]"'
        ) from exc

    server = FastMCP(
        "VAPT Assessment Read API",
        instructions=(
            "Read-only authorized assessment context. Tools never execute scanners, "
            "change scope, record validation results, or confirm findings."
        ),
        json_response=True,
    )

    async def call(method: str, identifier: str | None = None) -> dict[str, Any]:
        async with session_scope() as session:
            service = AssessmentMCPReadService(session)
            function = getattr(service, method)
            if identifier is None:
                return await function()
            try:
                entity_id = uuid.UUID(identifier)
            except ValueError as exc:
                raise ValueError("Identifier must be a UUID") from exc
            return await function(entity_id)

    @server.tool()
    async def get_scan_overview(scan_id: str) -> dict[str, Any]:
        """Get scan status and attack-surface counts."""
        return await call("get_scan_overview", scan_id)

    @server.tool()
    async def list_scan_assets(scan_id: str) -> dict[str, Any]:
        """List sanitized assets for an authorized scan."""
        return await call("list_scan_assets", scan_id)

    @server.tool()
    async def get_attack_surface_graph(scan_id: str) -> dict[str, Any]:
        """Get asset nodes and relationship edges without raw artifacts."""
        return await call("get_attack_surface_graph", scan_id)

    @server.tool()
    async def get_vulnerability_catalog() -> dict[str, Any]:
        """Get the versioned vulnerability-class catalog."""
        return await call("get_vulnerability_catalog")

    @server.tool()
    async def get_vulnerability_coverage(scan_id: str) -> dict[str, Any]:
        """Get class-by-class applicability, testing, and open obligations."""
        return await call("get_vulnerability_coverage", scan_id)

    @server.tool()
    async def get_scan_test_matrix(scan_id: str) -> dict[str, Any]:
        """Get the per-asset vulnerability test matrix."""
        return await call("get_test_matrix", scan_id)

    @server.tool()
    async def get_validation_backlog(scan_id: str) -> dict[str, Any]:
        """Get analyst validation tasks and evidence requirements."""
        return await call("get_validation_backlog", scan_id)

    @server.tool()
    async def get_hypotheses(scan_id: str) -> dict[str, Any]:
        """Get unconfirmed security hypotheses for a scan."""
        return await call("get_hypotheses", scan_id)

    @server.tool()
    async def get_hypothesis_evidence(hypothesis_id: str) -> dict[str, Any]:
        """Trace evidence links for one hypothesis."""
        return await call("get_hypothesis_evidence", hypothesis_id)

    @server.tool()
    async def get_verdicts(scan_id: str) -> dict[str, Any]:
        """Get formal evidence-gated verdicts."""
        return await call("get_verdicts", scan_id)

    @server.tool()
    async def get_confirmed_findings(scan_id: str) -> dict[str, Any]:
        """Get confirmed findings only; raw evidence content is excluded."""
        return await call("get_confirmed_findings", scan_id)

    @server.tool()
    async def get_assessment_completion_status(scan_id: str) -> dict[str, Any]:
        """Get the latest stored completion state without mutating it."""
        return await call("get_completion_status", scan_id)

    @server.tool()
    async def get_auth_coverage(scan_id: str) -> dict[str, Any]:
        """Get authenticated assessment coverage without credential secrets."""
        return await call("get_auth_coverage", scan_id)

    @server.tool()
    async def get_role_coverage(scan_id: str) -> dict[str, Any]:
        """Get authorized role coverage without credential secrets."""
        return await call("get_role_coverage", scan_id)

    @server.tool()
    async def get_ai_advisories(scan_id: str) -> dict[str, Any]:
        """Get schema-validated advisory enrichments."""
        return await call("get_ai_advisories", scan_id)

    return server


def main() -> None:
    settings = get_settings()
    if not settings.mcp_enabled:
        raise RuntimeError("MCP is disabled. Set MCP_ENABLED=true to start the server.")
    build_server().run(transport="stdio")
