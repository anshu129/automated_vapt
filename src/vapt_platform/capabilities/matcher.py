"""Map surface coverage gaps to capabilities."""

from vapt_platform.domain.enums import Capability, SurfaceDimensionStatus

# Surface dimension -> capabilities that can fill the gap
SURFACE_GAP_CAPABILITIES: dict[str, list[Capability]] = {
    "HTTP_CHARACTERIZATION": [Capability.HTTP_CHARACTERIZATION, Capability.HTTP_PROBING],
    "TLS_CHARACTERIZATION": [Capability.TLS_CHARACTERIZATION],
    "TECHNOLOGY_FINGERPRINTING": [Capability.TECHNOLOGY_IDENTIFICATION, Capability.WEB_FINGERPRINTING],
    "LIVE_CRAWL": [Capability.LIVE_CRAWLING, Capability.ENDPOINT_EXTRACTION],
    "PARAMETER_INVENTORY": [Capability.PARAMETER_DISCOVERY],
    "JAVASCRIPT_COLLECTION": [Capability.JAVASCRIPT_COLLECTION, Capability.STATIC_ROUTE_EXTRACTION],
    "API_INVENTORY": [Capability.API_ROUTE_DISCOVERY, Capability.LIVE_CRAWLING],
    "AUTHENTICATION_SURFACE_INVENTORY": [Capability.CONTENT_DISCOVERY],
    "DNS_VALIDATION": [Capability.DNS_RESOLUTION, Capability.WILDCARD_DETECTION],
}


class CapabilityMatcher:
    """Deterministic mapping from incomplete surface dimensions to capabilities."""

    def capabilities_for_gaps(
        self,
        dimensions: dict[str, str],
        *,
        passive_only: bool = False,
    ) -> list[Capability]:
        caps: list[Capability] = []
        incomplete = {
            SurfaceDimensionStatus.NOT_STARTED.value,
            SurfaceDimensionStatus.PARTIAL.value,
            SurfaceDimensionStatus.INCONCLUSIVE.value,
        }
        for dim, status in dimensions.items():
            if status not in incomplete:
                continue
            for cap in SURFACE_GAP_CAPABILITIES.get(dim, []):
                if passive_only and cap not in _PASSIVE_CAPS:
                    continue
                if cap not in caps:
                    caps.append(cap)
        return caps


_PASSIVE_CAPS = {
    Capability.PASSIVE_SUBDOMAIN_DISCOVERY,
    Capability.CERTIFICATE_TRANSPARENCY_DISCOVERY,
    Capability.HISTORICAL_URL_DISCOVERY,
    Capability.WEB_PASSIVE_ASSESSMENT,
}
