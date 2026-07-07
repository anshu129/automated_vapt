"""Capability provider adapters wrapping existing validators."""

from __future__ import annotations

from vapt_platform.config.settings import Settings, get_settings
from vapt_platform.domain.capability_provider import CapabilityProvider as CapabilityProviderProtocol
from vapt_platform.providers.burp_provider import BurpCapabilityProvider
from vapt_platform.providers.nuclei_provider import NucleiCapabilityProvider
from vapt_platform.providers.sqlmap_provider import SqlmapCapabilityProvider


def build_default_capability_providers(
    settings: Settings | None = None,
) -> list[CapabilityProviderProtocol]:
    cfg = settings or get_settings()
    providers: list[CapabilityProviderProtocol] = [NucleiCapabilityProvider()]

    if cfg.burp_mcp_enabled:
        providers.append(BurpCapabilityProvider(sse_url=cfg.burp_mcp_sse_url))

    if cfg.sqlmap_mcp_enabled and cfg.sqlmap_mcp_server_path.strip():
        providers.append(
            SqlmapCapabilityProvider(
                server_path=cfg.sqlmap_mcp_server_path.strip(),
                command=cfg.sqlmap_mcp_command,
                extra_args=cfg.sqlmap_mcp_extra_args_list(),
            )
        )

    return providers
