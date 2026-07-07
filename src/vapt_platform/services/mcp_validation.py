"""MCP-client tool validation orchestration.

Runs configured validation connectors (nuclei today; Burp / sqlmap MCP servers
can be registered later) against applicable vulnerability classes, records the
tool evidence, and opens human-confirmable validation tasks. Nothing here
auto-confirms a finding: positive tool signals become OPEN validation tasks
with a recommended verdict, preserving the evidence-gated audit trail.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from vapt_platform.config.settings import get_settings
from vapt_platform.db.tables.models import (
    Asset,
    AssetVulnerabilityApplicability,
    EvidencePackage,
    Hypothesis,
    Observation,
    ValidationTask,
    VulnerabilityClass,
)
from vapt_platform.domain.enums import ApplicabilityState, AssetType, ValidationTaskStatus
from vapt_platform.validators.base import (
    ValidationConnector,
    ValidationOutcome,
    nuclei_tags_for_class,
    with_auth_url,
)
from vapt_platform.validators.registry import build_validation_connectors

_APPLICABLE_STATES = {
    ApplicabilityState.APPLICABLE.value,
    ApplicabilityState.POSSIBLY_APPLICABLE.value,
}
_MAX_TAGS = 12


@dataclass
class ScanValidationSummary:
    scan_id: str
    connectors: list[str]
    active_allowed: bool
    assets_validated: int = 0
    outcomes: list[dict[str, Any]] = field(default_factory=list)
    corroborated: int = 0
    tasks_created: int = 0
    skipped: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "connectors": self.connectors,
            "active_allowed": self.active_allowed,
            "assets_validated": self.assets_validated,
            "corroborated": self.corroborated,
            "tasks_created": self.tasks_created,
            "skipped": self.skipped,
            "outcomes": self.outcomes,
        }


class McpValidationService:
    def __init__(
        self,
        session: AsyncSession,
        connectors: list[ValidationConnector] | None = None,
    ) -> None:
        self.session = session
        self._all_connectors: list[ValidationConnector] = (
            connectors or build_validation_connectors(get_settings())
        )

    def _active_connectors(self, active_allowed: bool) -> list[ValidationConnector]:
        selected: list[ValidationConnector] = []
        for connector in self._all_connectors:
            if getattr(connector, "active", False) and not active_allowed:
                continue
            selected.append(connector)
        return selected

    async def validate_scan(
        self,
        scan_id: uuid.UUID,
        active_allowed: bool = False,
        username: str | None = None,
        password: str | None = None,
    ) -> ScanValidationSummary:
        connectors = self._active_connectors(active_allowed)
        summary = ScanValidationSummary(
            scan_id=str(scan_id),
            connectors=[c.name for c in connectors],
            active_allowed=active_allowed,
        )
        available = [c for c in connectors if c.is_available()]
        for connector in connectors:
            if connector not in available:
                summary.skipped.append(f"{connector.name}: tool/MCP server not available")
        if not available:
            return summary

        targets = await self._targets_with_classes(scan_id)
        for asset, url, class_map in targets:
            if not url or not class_map:
                continue
            tags = self._tags_for_classes(class_map.keys())
            summary.assets_validated += 1
            for connector in available:
                auth_url = with_auth_url(url, username, password) if url else url
                outcome = await connector.validate(
                    target_url=auth_url or url or "",
                    tags=tags,
                    class_codes=sorted(class_map.keys()),
                    asset_id=str(asset.id),
                    username=username,
                    password=password,
                )
                await self._persist_outcome(scan_id, asset, class_map, outcome, summary)
                summary.outcomes.append(outcome.to_dict())
        await self.session.flush()
        return summary

    async def validate_hypothesis(
        self,
        hypothesis_id: uuid.UUID,
        active_allowed: bool = False,
        username: str | None = None,
        password: str | None = None,
    ) -> ScanValidationSummary:
        hypothesis = await self.session.get(Hypothesis, hypothesis_id)
        if not hypothesis:
            raise ValueError("Hypothesis not found")
        summary = await self.validate_scan(
            hypothesis.scan_id,
            active_allowed=active_allowed,
            username=username,
            password=password,
        )
        # Scope the reported outcomes to the hypothesis's affected assets.
        affected = {str(a) for a in (hypothesis.affected_asset_ids or [])}
        if affected:
            summary.outcomes = [o for o in summary.outcomes if o.get("asset_id") in affected]
        return summary

    async def _targets_with_classes(
        self,
        scan_id: uuid.UUID,
    ) -> list[tuple[Asset, str | None, dict[str, uuid.UUID]]]:
        rows = list(
            (
                await self.session.execute(
                    select(AssetVulnerabilityApplicability, VulnerabilityClass.class_code)
                    .join(
                        VulnerabilityClass,
                        VulnerabilityClass.id
                        == AssetVulnerabilityApplicability.vulnerability_class_id,
                    )
                    .where(
                        AssetVulnerabilityApplicability.scan_id == scan_id,
                        AssetVulnerabilityApplicability.applicability_state.in_(_APPLICABLE_STATES),
                    )
                )
            ).all()
        )
        by_asset: dict[uuid.UUID, dict[str, uuid.UUID]] = {}
        for applicability, class_code in rows:
            by_asset.setdefault(applicability.asset_id, {})[class_code] = (
                applicability.vulnerability_class_id
            )
        results: list[tuple[Asset, str | None, dict[str, uuid.UUID]]] = []
        for asset_id, class_map in by_asset.items():
            asset = await self.session.get(Asset, asset_id)
            if not asset:
                continue
            url = self._asset_url(asset)
            if url:
                results.append((asset, url, class_map))
        return results

    @staticmethod
    def _asset_url(asset: Asset) -> str | None:
        metadata = asset.metadata_ or {}
        if asset.asset_type in {
            AssetType.WEB_APPLICATION.value,
            AssetType.ENDPOINT.value,
        }:
            return metadata.get("base_url") or metadata.get("url") or asset.normalized_key
        if asset.asset_type == AssetType.SERVICE.value:
            url = metadata.get("url")
            if url:
                return url
            scheme = metadata.get("scheme") or "https"
            host = metadata.get("hostname")
            port = metadata.get("port")
            if host:
                return f"{scheme}://{host}:{port}" if port else f"{scheme}://{host}"
        return None

    @staticmethod
    def _tags_for_classes(class_codes: Any) -> list[str]:
        tags: list[str] = []
        for code in class_codes:
            for tag in nuclei_tags_for_class(code):
                if tag not in tags:
                    tags.append(tag)
        return tags[:_MAX_TAGS]

    async def _persist_outcome(
        self,
        scan_id: uuid.UUID,
        asset: Asset,
        class_map: dict[str, uuid.UUID],
        outcome: ValidationOutcome,
        summary: ScanValidationSummary,
    ) -> None:
        run_observation = Observation(
            scan_id=scan_id,
            subject_asset_id=asset.id,
            observation_type="MCP_VALIDATION_RUN",
            source_type="TOOL",
            source_id=outcome.connector,
            payload={
                "status": outcome.status,
                "tags": outcome.tags,
                "class_codes": outcome.class_codes,
                "target_url": outcome.target_url,
                "detail": outcome.detail,
                "redacted_command": outcome.redacted_command,
                "finding_count": len(outcome.findings),
            },
            confidence=0.6 if outcome.status == "CORROBORATED" else 0.3,
            provenance={"connector": outcome.connector, "kind": "mcp-validation"},
        )
        self.session.add(run_observation)
        await self.session.flush()

        if outcome.status != "CORROBORATED" or not outcome.findings:
            return

        finding_observation_ids: list[str] = []
        for finding in outcome.findings:
            obs = Observation(
                scan_id=scan_id,
                subject_asset_id=asset.id,
                observation_type="MCP_VALIDATION_FINDING",
                source_type="TOOL",
                source_id=outcome.connector,
                payload=finding.to_dict(),
                confidence=0.7,
                provenance={"connector": outcome.connector, "run_id": str(run_observation.id)},
            )
            self.session.add(obs)
            await self.session.flush()
            finding_observation_ids.append(str(obs.id))

        summary.corroborated += 1
        evidence_ids = [str(run_observation.id), *finding_observation_ids]
        await self._update_applicability(scan_id, asset.id, class_map, outcome, evidence_ids)
        created = await self._open_validation_task(
            scan_id, asset, class_map, outcome, evidence_ids
        )
        if created:
            summary.tasks_created += 1

    async def _update_applicability(
        self,
        scan_id: uuid.UUID,
        asset_id: uuid.UUID,
        class_map: dict[str, uuid.UUID],
        outcome: ValidationOutcome,
        evidence_ids: list[str],
    ) -> None:
        rows = list(
            (
                await self.session.execute(
                    select(AssetVulnerabilityApplicability).where(
                        AssetVulnerabilityApplicability.scan_id == scan_id,
                        AssetVulnerabilityApplicability.asset_id == asset_id,
                        AssetVulnerabilityApplicability.vulnerability_class_id.in_(
                            list(class_map.values())
                        ),
                    )
                )
            )
            .scalars()
            .all()
        )
        note = (
            f"{outcome.connector} produced {len(outcome.findings)} corroborating "
            "signal(s); requires analyst confirmation before it becomes a finding."
        )
        for row in rows:
            row.supporting_evidence_ids = list(
                dict.fromkeys([*(row.supporting_evidence_ids or []), *evidence_ids])
            )
            row.rule_ids = list(
                dict.fromkeys([*(row.rule_ids or []), f"mcp-validation:{outcome.connector}"])
            )
            row.explanation = note

    async def _open_validation_task(
        self,
        scan_id: uuid.UUID,
        asset: Asset,
        class_map: dict[str, uuid.UUID],
        outcome: ValidationOutcome,
        evidence_ids: list[str],
    ) -> bool:
        existing = list(
            (
                await self.session.execute(
                    select(ValidationTask).where(ValidationTask.scan_id == scan_id)
                )
            )
            .scalars()
            .all()
        )
        for task in existing:
            provenance = (task.required_evidence or {}).get("mcp_connector")
            if (
                provenance == outcome.connector
                and str(asset.id) in (task.asset_ids or [])
            ):
                # Refresh evidence on the existing task instead of duplicating it.
                task.required_evidence = {
                    **(task.required_evidence or {}),
                    "evidence_ids": list(
                        dict.fromkeys(
                            [*(task.required_evidence or {}).get("evidence_ids", []), *evidence_ids]
                        )
                    ),
                }
                return False

        top = outcome.findings[0]
        asset_label = asset.display_name or asset.normalized_key
        package = EvidencePackage(
            scan_id=scan_id,
            package_data={
                "source": "mcp-validation",
                "connector": outcome.connector,
                "asset_id": str(asset.id),
                "target_url": outcome.target_url,
                "class_codes": outcome.class_codes,
                "findings": [f.to_dict() for f in outcome.findings],
                "evidence_ids": evidence_ids,
                "recommended_verdict": "CONFIRMED",
                "recommendation_basis": (
                    f"{outcome.connector} matched {len(outcome.findings)} template(s) "
                    f"(e.g. {top.template_id})"
                ),
            },
        )
        self.session.add(package)
        await self.session.flush()
        task = ValidationTask(
            scan_id=scan_id,
            evidence_package_id=package.id,
            asset_ids=[str(asset.id)],
            priority=90,
            validation_goal=(
                f"Confirm {', '.join(outcome.class_codes)} on {asset_label} "
                f"({outcome.connector} corroborated {len(outcome.findings)} signal(s))"
            ),
            required_evidence={
                "mcp_connector": outcome.connector,
                "evidence_ids": evidence_ids,
                "recommended_verdict": "CONFIRMED",
            },
            suggested_safe_checks=[
                f"Review the {outcome.connector} template matches and matched-at locations",
                "Reproduce within authorized scope, then record evidence before confirming",
            ],
            testing_mode="ASSISTED",
            status=ValidationTaskStatus.OPEN.value,
        )
        self.session.add(task)
        await self.session.flush()
        package.validation_task_id = task.id
        return True
