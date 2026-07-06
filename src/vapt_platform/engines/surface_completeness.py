"""Surface completeness evaluation — eligibility, gaps, and scan summaries."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from vapt_platform.capabilities.matcher import CapabilityMatcher
from vapt_platform.db.tables.models import Asset, SurfaceCoverageRecord, Task
from vapt_platform.domain.enums import AssetType, SurfaceDimensionStatus, TaskStatus

RULE_VERSION = "1.0"

WEB_APP_DIMENSIONS = [
    "HTTP_CHARACTERIZATION",
    "TLS_CHARACTERIZATION",
    "TECHNOLOGY_FINGERPRINTING",
    "LIVE_CRAWL",
    "PARAMETER_INVENTORY",
    "JAVASCRIPT_COLLECTION",
    "API_INVENTORY",
    "AUTHENTICATION_SURFACE_INVENTORY",
    "AUTHENTICATED_AREA_COVERAGE",
    "AUTHORIZATION_COVERAGE",
]

HOSTNAME_DIMENSIONS = [
    "DNS_VALIDATION",
    "PORT_DISCOVERY",
    "SERVICE_DISCOVERY",
]

_INCOMPLETE = {
    SurfaceDimensionStatus.NOT_STARTED.value,
    SurfaceDimensionStatus.PARTIAL.value,
    SurfaceDimensionStatus.INCONCLUSIVE.value,
}

# Dimensions that block assessment completion when incomplete
BLOCKING_DIMENSIONS = {
    "HTTP_CHARACTERIZATION",
    "LIVE_CRAWL",
    "DNS_VALIDATION",
}

_CREDENTIAL_GATED = {
    "AUTHENTICATED_AREA_COVERAGE",
    "AUTHORIZATION_COVERAGE",
}

@dataclass
class SurfaceRequirement:
    dimension: str
    status: str
    blocking: bool
    eligible_capabilities: list[str] = field(default_factory=list)
    reason: str = ""
    accepted: bool = False


class SurfaceCompletenessEngine:
    """Per-asset surface dimension evaluation with gap classification."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self._matcher = CapabilityMatcher()

    async def compute(self, scan_id: uuid.UUID, asset_id: uuid.UUID) -> SurfaceCoverageRecord:
        asset = await self.session.get(Asset, asset_id)
        if not asset:
            raise ValueError("Asset not found")

        completed_caps = await self._completed_capabilities(scan_id, asset)
        meta = dict(asset.metadata_ or {})
        if asset.asset_type == AssetType.WEB_APPLICATION.value:
            endpoint_urls = await self._endpoint_urls_for_web_app(scan_id, asset)
            if endpoint_urls:
                merged = set(meta.get("endpoints", []))
                merged.update(endpoint_urls)
                meta["endpoints"] = list(merged)
        dimensions = self._evaluate_dimensions(asset, completed_caps, meta)
        gap_count = sum(1 for v in dimensions.values() if v in _INCOMPLETE)
        overall = self._overall_status(dimensions)

        stmt = select(SurfaceCoverageRecord).where(
            SurfaceCoverageRecord.scan_id == scan_id,
            SurfaceCoverageRecord.asset_id == asset_id,
        )
        record = (await self.session.execute(stmt)).scalar_one_or_none()
        if not record:
            record = SurfaceCoverageRecord(
                scan_id=scan_id, asset_id=asset_id, asset_type=asset.asset_type
            )
            self.session.add(record)
        record.dimensions = dimensions
        record.overall_status = overall
        record.gap_count = gap_count
        record.rule_version = RULE_VERSION
        record.computed_at = datetime.now(UTC)
        return record

    async def compute_scan_summary(
        self,
        scan_id: uuid.UUID,
        asset_type: AssetType | str | None = None,
    ) -> list[SurfaceCoverageRecord]:
        stmt = select(SurfaceCoverageRecord).where(SurfaceCoverageRecord.scan_id == scan_id)
        if asset_type:
            at = asset_type.value if isinstance(asset_type, AssetType) else asset_type
            stmt = stmt.where(SurfaceCoverageRecord.asset_type == at)
        return list((await self.session.execute(stmt)).scalars().all())

    async def missing_requirements(
        self,
        asset_id: uuid.UUID,
        scan_id: uuid.UUID,
        *,
        accepted_gaps: dict[str, Any] | None = None,
    ) -> list[SurfaceRequirement]:
        asset = await self.session.get(Asset, asset_id)
        if not asset:
            return []

        record = (
            await self.session.execute(
                select(SurfaceCoverageRecord).where(
                    SurfaceCoverageRecord.scan_id == scan_id,
                    SurfaceCoverageRecord.asset_id == asset_id,
                )
            )
        ).scalar_one_or_none()
        if not record:
            record = await self.compute(scan_id, asset_id)

        accepted = _accepted_for_asset(accepted_gaps or {}, asset_id)
        requirements: list[SurfaceRequirement] = []
        for dim, status in (record.dimensions or {}).items():
            if status not in _INCOMPLETE:
                continue
            caps = [
                c.value for c in self._matcher.capabilities_for_gaps({dim: status})
            ]
            blocking = self._is_blocking(dim, status, asset.metadata_ or {}, accepted)
            requirements.append(
                SurfaceRequirement(
                    dimension=dim,
                    status=status,
                    blocking=blocking,
                    eligible_capabilities=caps,
                    reason=_gap_reason(dim, status, asset.metadata_ or {}),
                    accepted=dim in accepted,
                )
            )
        return requirements

    def gaps_payload(
        self,
        asset_id: uuid.UUID,
        requirements: list[SurfaceRequirement],
    ) -> dict[str, Any]:
        open_gaps = [r for r in requirements if not r.accepted]
        return {
            "asset_id": str(asset_id),
            "gap_count": len(open_gaps),
            "blocking_count": sum(1 for r in open_gaps if r.blocking),
            "gaps": [
                {
                    "dimension": r.dimension,
                    "status": r.status,
                    "blocking": r.blocking,
                    "accepted": r.accepted,
                    "eligible_capabilities": r.eligible_capabilities,
                    "reason": r.reason,
                }
                for r in open_gaps
            ],
        }

    async def _completed_capabilities(
        self, scan_id: uuid.UUID, asset: Asset
    ) -> set[str]:
        stmt = select(Task).where(
            Task.scan_id == scan_id,
            Task.status == TaskStatus.COMPLETED.value,
        )
        tasks = list((await self.session.execute(stmt)).scalars().all())
        asset_key = asset.normalized_key.lower()
        caps: set[str] = set()
        for task in tasks:
            td = task.target_descriptor or {}
            keys = {
                (td.get("hostname") or "").lower(),
                (td.get("domain") or "").lower(),
                (td.get("url") or "").lower().rstrip("/"),
                (td.get("base_url") or "").lower().rstrip("/"),
            }
            keys.discard("")
            if asset_key in keys or any(asset_key in k for k in keys if k):
                caps.add(task.capability)
            elif asset.asset_type == AssetType.HOSTNAME.value and td.get("hostname", "").lower() == asset_key:
                caps.add(task.capability)
        return caps

    async def _endpoint_urls_for_web_app(
        self, scan_id: uuid.UUID, asset: Asset
    ) -> list[str]:
        base = asset.normalized_key.lower().rstrip("/")
        stmt = select(Asset).where(
            Asset.scan_id == scan_id,
            Asset.asset_type == AssetType.ENDPOINT.value,
        )
        endpoints = list((await self.session.execute(stmt)).scalars().all())
        return [
            ep.display_name
            for ep in endpoints
            if ep.normalized_key.startswith(base) or ep.display_name.lower().startswith(base)
        ]

    def _evaluate_dimensions(
        self,
        asset: Asset,
        completed_caps: set[str],
        meta: dict[str, Any] | None = None,
    ) -> dict[str, str]:
        effective_meta = meta if meta is not None else (asset.metadata_ or {})
        if asset.asset_type == AssetType.WEB_APPLICATION.value:
            return self._web_app_dimensions(effective_meta, completed_caps)
        if asset.asset_type == AssetType.HOSTNAME.value:
            return self._hostname_dimensions(effective_meta, completed_caps)
        return {}

    def _web_app_dimensions(
        self, meta: dict[str, Any], completed_caps: set[str]
    ) -> dict[str, str]:
        dimensions: dict[str, str] = {}
        endpoints: list[str] = meta.get("endpoints", [])
        js_urls: list[str] = meta.get("js_urls", [])
        uses_https = _uses_https(meta)

        for dim in WEB_APP_DIMENSIONS:
            dimensions[dim] = SurfaceDimensionStatus.NOT_STARTED.value

        if not meta.get("http_confirmed"):
            return dimensions

        dimensions["HTTP_CHARACTERIZATION"] = SurfaceDimensionStatus.COMPLETE.value

        if uses_https:
            dimensions["TLS_CHARACTERIZATION"] = (
                SurfaceDimensionStatus.COMPLETE.value
                if meta.get("tls_characterized")
                else SurfaceDimensionStatus.NOT_STARTED.value
            )
        else:
            dimensions["TLS_CHARACTERIZATION"] = SurfaceDimensionStatus.NOT_APPLICABLE.value

        dimensions["TECHNOLOGY_FINGERPRINTING"] = (
            SurfaceDimensionStatus.COMPLETE.value
            if meta.get("technologies")
            else SurfaceDimensionStatus.NOT_STARTED.value
        )

        if endpoints:
            dimensions["LIVE_CRAWL"] = SurfaceDimensionStatus.COMPLETE.value
        elif "LIVE_CRAWLING" in completed_caps:
            dimensions["LIVE_CRAWL"] = SurfaceDimensionStatus.PARTIAL.value

        dimensions["PARAMETER_INVENTORY"] = _capability_dimension_status(
            "PARAMETER_DISCOVERY", completed_caps, endpoints
        )
        dimensions["JAVASCRIPT_COLLECTION"] = _js_collection_status(
            meta, completed_caps, js_urls
        )

        api_eps = [e for e in endpoints if "/api" in e]
        if api_eps:
            dimensions["API_INVENTORY"] = (
                SurfaceDimensionStatus.COMPLETE.value
                if "API_ROUTE_DISCOVERY" in completed_caps
                else SurfaceDimensionStatus.PARTIAL.value
            )
        else:
            dimensions["API_INVENTORY"] = SurfaceDimensionStatus.NOT_APPLICABLE.value

        login_eps = [e for e in endpoints if "login" in e.lower()]
        dimensions["AUTHENTICATION_SURFACE_INVENTORY"] = (
            SurfaceDimensionStatus.COMPLETE.value
            if login_eps
            else SurfaceDimensionStatus.NOT_STARTED.value
        )

        if meta.get("credentials_available"):
            dimensions["AUTHENTICATED_AREA_COVERAGE"] = (
                SurfaceDimensionStatus.COMPLETE.value
                if meta.get("authenticated_crawl_done")
                else SurfaceDimensionStatus.NOT_STARTED.value
            )
            dimensions["AUTHORIZATION_COVERAGE"] = (
                SurfaceDimensionStatus.COMPLETE.value
                if meta.get("authorization_tested")
                else SurfaceDimensionStatus.NOT_STARTED.value
            )
        else:
            dimensions["AUTHENTICATED_AREA_COVERAGE"] = (
                SurfaceDimensionStatus.NOT_APPLICABLE.value
            )
            dimensions["AUTHORIZATION_COVERAGE"] = (
                SurfaceDimensionStatus.NOT_APPLICABLE.value
            )

        return dimensions

    def _hostname_dimensions(
        self, meta: dict[str, Any], completed_caps: set[str]
    ) -> dict[str, str]:
        dimensions = {dim: SurfaceDimensionStatus.NOT_STARTED.value for dim in HOSTNAME_DIMENSIONS}

        if meta.get("dns_status") == "COMPLETE" or meta.get("dns_resolved"):
            dimensions["DNS_VALIDATION"] = SurfaceDimensionStatus.COMPLETE.value

        if meta.get("ports_discovered") or "PORT_DISCOVERY" in completed_caps:
            dimensions["PORT_DISCOVERY"] = SurfaceDimensionStatus.COMPLETE.value

        if meta.get("services_identified") or meta.get("ports_discovered"):
            dimensions["SERVICE_DISCOVERY"] = SurfaceDimensionStatus.COMPLETE.value
        elif "PORT_DISCOVERY" in completed_caps:
            dimensions["SERVICE_DISCOVERY"] = SurfaceDimensionStatus.PARTIAL.value

        return dimensions

    @staticmethod
    def _overall_status(dimensions: dict[str, str]) -> str:
        if not dimensions:
            return SurfaceDimensionStatus.NOT_STARTED.value
        applicable = [
            v
            for k, v in dimensions.items()
            if v != SurfaceDimensionStatus.NOT_APPLICABLE.value
        ]
        if not applicable:
            return SurfaceDimensionStatus.NOT_APPLICABLE.value
        gap_count = sum(1 for v in applicable if v in _INCOMPLETE)
        if gap_count == 0:
            return SurfaceDimensionStatus.COMPLETE.value
        if gap_count < len(applicable):
            return SurfaceDimensionStatus.PARTIAL.value
        return SurfaceDimensionStatus.NOT_STARTED.value

    @staticmethod
    def _is_blocking(
        dimension: str,
        status: str,
        meta: dict[str, Any],
        accepted: set[str],
    ) -> bool:
        if status not in _INCOMPLETE:
            return False
        if dimension in accepted:
            return False
        if dimension in _CREDENTIAL_GATED and not meta.get("credentials_available"):
            return False
        if dimension in BLOCKING_DIMENSIONS:
            return True
        if dimension == "TLS_CHARACTERIZATION" and _uses_https(meta):
            return False
        return False


def _accepted_for_asset(accepted_gaps: dict[str, Any], asset_id: uuid.UUID) -> set[str]:
    per_asset = accepted_gaps.get(str(asset_id), accepted_gaps.get("dimensions", []))
    if isinstance(per_asset, dict):
        return set(per_asset.keys())
    if isinstance(per_asset, list):
        return set(per_asset)
    return set()


def _uses_https(meta: dict[str, Any]) -> bool:
    url = (meta.get("base_url") or meta.get("url") or "").lower()
    return url.startswith("https://")


def _capability_dimension_status(
    capability: str,
    completed_caps: set[str],
    endpoints: list[str],
) -> str:
    if capability in completed_caps:
        return SurfaceDimensionStatus.COMPLETE.value
    if endpoints:
        return SurfaceDimensionStatus.PARTIAL.value
    return SurfaceDimensionStatus.NOT_STARTED.value


def _js_collection_status(
    meta: dict[str, Any],
    completed_caps: set[str],
    js_urls: list[str],
) -> str:
    if "JAVASCRIPT_COLLECTION" in completed_caps:
        return SurfaceDimensionStatus.COMPLETE.value
    if js_urls:
        return SurfaceDimensionStatus.PARTIAL.value
    if meta.get("technologies"):
        return SurfaceDimensionStatus.NOT_STARTED.value
    return SurfaceDimensionStatus.NOT_APPLICABLE.value


def _gap_reason(dimension: str, status: str, meta: dict[str, Any]) -> str:
    if dimension in _CREDENTIAL_GATED and not meta.get("credentials_available"):
        return "Requires authorized credentials"
    if dimension == "TLS_CHARACTERIZATION" and _uses_https(meta):
        return "HTTPS in use; TLS characterization not yet performed"
    if dimension == "LIVE_CRAWL" and status == SurfaceDimensionStatus.NOT_STARTED.value:
        return "No endpoint inventory collected"
    return f"{dimension.replace('_', ' ').title()} is {status.lower().replace('_', ' ')}"
