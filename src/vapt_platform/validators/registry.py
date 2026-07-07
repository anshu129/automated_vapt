"""Build the default validation connector set from application settings."""

from __future__ import annotations

from vapt_platform.config.settings import Settings, get_settings
from vapt_platform.validators.base import ValidationConnector
from vapt_platform.validators.burp import BurpMcpValidator
from vapt_platform.validators.nuclei import NucleiValidator
from vapt_platform.validators.sqlmap_mcp import SqlmapMcpValidator


def build_validation_connectors(settings: Settings | None = None) -> list[ValidationConnector]:
    cfg = settings or get_settings()
    connectors: list[ValidationConnector] = [NucleiValidator()]

    if cfg.burp_mcp_enabled:
        connectors.append(BurpMcpValidator(sse_url=cfg.burp_mcp_sse_url))

    if cfg.sqlmap_mcp_enabled and cfg.sqlmap_mcp_server_path.strip():
        connectors.append(
            SqlmapMcpValidator(
                server_path=cfg.sqlmap_mcp_server_path.strip(),
                command=cfg.sqlmap_mcp_command,
                extra_args=cfg.sqlmap_mcp_extra_args_list(),
            )
        )

    return connectors
