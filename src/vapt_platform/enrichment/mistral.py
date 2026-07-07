"""Optional Mistral advisory enrichment over redacted assessment read models."""

from __future__ import annotations

import hashlib
import json
import uuid
from typing import Any

import httpx
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from vapt_platform.config.settings import Settings, get_settings
from vapt_platform.db.tables.models import (
    AIEnrichment,
    Asset,
    AssetTestMatrix,
    TestRequirement,
    VulnerabilityClass,
)
from vapt_platform.domain.enums import TestRequirementCoverageStatus

PROMPT_TEMPLATE_VERSION = "coverage-advisory-v1"


def _clip(value: Any, limit: int) -> str:
    """Coerce to string and truncate to keep advisory records bounded."""
    text = value if isinstance(value, str) else ("" if value is None else str(value))
    return text[:limit]


class AdvisoryPriority(BaseModel):
    class_code: str = ""
    rationale: str = ""
    evidence_gap: str = ""
    recommended_validation: str = ""

    @field_validator("rationale", "evidence_gap", "recommended_validation", mode="before")
    @classmethod
    def _truncate(cls, value: Any) -> str:
        return _clip(value, 600)

    @field_validator("class_code", mode="before")
    @classmethod
    def _code(cls, value: Any) -> str:
        return _clip(value, 120)


class CrossAssetHypothesisSuggestion(BaseModel):
    title: str = ""
    class_code: str = ""
    asset_ids: list[str] = Field(default_factory=list)
    rationale: str = ""
    required_evidence: list[str] = Field(default_factory=list)
    confidence: float = 0.5

    @field_validator("title", "rationale", "class_code", mode="before")
    @classmethod
    def _truncate(cls, value: Any) -> str:
        return _clip(value, 800)

    @field_validator("asset_ids", "required_evidence", mode="before")
    @classmethod
    def _as_list(cls, value: Any) -> list[str]:
        if value is None:
            return []
        if isinstance(value, list):
            return [str(item) for item in value][:25]
        return [str(value)]

    @field_validator("confidence", mode="before")
    @classmethod
    def _clamp(cls, value: Any) -> float:
        try:
            number = float(value)
        except (TypeError, ValueError):
            return 0.5
        return min(1.0, max(0.0, number))


class VulnerabilityCoverageAdvisory(BaseModel):
    summary: str = ""
    priority_classes: list[AdvisoryPriority] = Field(default_factory=list)
    cross_asset_hypotheses: list[CrossAssetHypothesisSuggestion] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)

    @field_validator("summary", mode="before")
    @classmethod
    def _truncate(cls, value: Any) -> str:
        return _clip(value, 1500)

    @field_validator("limitations", mode="before")
    @classmethod
    def _as_list(cls, value: Any) -> list[str]:
        if value is None:
            return []
        if isinstance(value, list):
            return [_clip(item, 400) for item in value][:12]
        return [_clip(value, 400)]

    @field_validator("priority_classes", "cross_asset_hypotheses", mode="before")
    @classmethod
    def _cap(cls, value: Any) -> Any:
        if isinstance(value, list):
            return [item for item in value if isinstance(item, (dict, BaseModel))][:20]
        return []


class MistralEnrichmentService:
    """Produces advisory records without mutating assessment state."""

    def __init__(
        self,
        session: AsyncSession,
        settings: Settings | None = None,
    ) -> None:
        self.session = session
        self.settings = settings or get_settings()

    async def enrich_vulnerability_coverage(self, scan_id: uuid.UUID) -> AIEnrichment:
        snapshot, class_codes, asset_ids = await self._coverage_snapshot(scan_id)
        encoded = json.dumps(snapshot, sort_keys=True, separators=(",", ":"))
        input_hash = hashlib.sha256(encoded.encode()).hexdigest()
        model_config = {
            "model": self.settings.mistral_model,
            "temperature": 0.1,
            "max_tokens": self.settings.effective_ai_max_tokens(),
            "safe_prompt": True,
        }
        cache_key = hashlib.sha256(
            (
                input_hash + PROMPT_TEMPLATE_VERSION + json.dumps(model_config, sort_keys=True)
            ).encode()
        ).hexdigest()
        existing = (
            await self.session.execute(
                select(AIEnrichment).where(AIEnrichment.cache_key == cache_key)
            )
        ).scalar_one_or_none()
        if existing:
            existing.cached = True
            return existing

        advisory: VulnerabilityCoverageAdvisory
        validation_status = "VALID"
        provider = "mistral"
        error_type: str | None = None
        error_detail: str | None = None
        if not self.settings.ai_enabled:
            advisory = self._fallback(snapshot, "AI_ENABLED is false")
            validation_status = "FALLBACK"
            provider = "deterministic-fallback"
        elif not self.settings.mistral_api_key:
            advisory = self._fallback(snapshot, "MISTRAL_API_KEY is not configured")
            validation_status = "FALLBACK"
            provider = "deterministic-fallback"
        else:
            try:
                advisory = await self._call_mistral(snapshot)
                advisory = self._filter_output(advisory, class_codes, asset_ids)
            except (httpx.HTTPError, ValueError, KeyError) as exc:
                error_type = type(exc).__name__
                error_detail = str(exc)[:500]
                advisory = self._fallback(
                    snapshot,
                    "Mistral enrichment was unavailable; deterministic summary used.",
                )
                validation_status = "FALLBACK"
                provider = "deterministic-fallback"

        stored_config = dict(model_config)
        if error_type:
            stored_config["error_type"] = error_type
        if error_detail:
            stored_config["error_detail"] = error_detail
        record = AIEnrichment(
            scan_id=scan_id,
            enrichment_type="VULNERABILITY_COVERAGE_ADVISORY",
            target_entity_type="SCAN",
            target_entity_id=scan_id,
            provider=provider,
            prompt_template_version=PROMPT_TEMPLATE_VERSION,
            model_config=stored_config,
            input_artifact_hash=input_hash,
            cache_key=cache_key,
            output=advisory.model_dump(mode="json"),
            validation_status=validation_status,
            cached=False,
        )
        self.session.add(record)
        await self.session.flush()
        return record

    async def _call_mistral(
        self,
        snapshot: dict[str, Any],
    ) -> VulnerabilityCoverageAdvisory:
        api_key = self.settings.mistral_api_key
        if not api_key:
            raise ValueError("MISTRAL_API_KEY is not configured")
        system_prompt = (
            "You are an advisory security coverage analyst. Use only the supplied "
            "redacted assessment snapshot. Return JSON matching the requested schema. "
            "Do not claim a vulnerability is confirmed, provide exploit steps or "
            "commands, change scope, or recommend destructive testing. Use only "
            "class_code and asset_id values present in the input. Distinguish possible "
            "applicability, testing gaps, and evidence-backed confirmation."
        )
        user_prompt = (
            "Analyze cross-asset vulnerability coverage and prioritize validation gaps. "
            "Return keys summary, priority_classes, cross_asset_hypotheses, limitations. "
            "Each priority class needs class_code, rationale, evidence_gap, and "
            "recommended_validation. Each hypothesis needs title, class_code, asset_ids, "
            "rationale, required_evidence, and confidence. Limit summary to 3 sentences, "
            "priority_classes to at most 10 items, and cross_asset_hypotheses to at most 8 "
            "items. Snapshot: " + json.dumps(snapshot, separators=(",", ":"))
        )
        async with httpx.AsyncClient(timeout=float(self.settings.ai_timeout_seconds)) as client:
            response = await client.post(
                f"{self.settings.mistral_base_url.rstrip('/')}/chat/completions",
                headers={
                    "Authorization": f"Bearer {api_key.get_secret_value()}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": self.settings.mistral_model,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt},
                    ],
                    "temperature": 0.1,
                    "max_tokens": self.settings.effective_ai_max_tokens(),
                    "safe_prompt": True,
                    "response_format": {"type": "json_object"},
                },
            )
            response.raise_for_status()
        payload = response.json()
        content = payload["choices"][0]["message"]["content"]
        if isinstance(content, list):
            content = "".join(
                str(item.get("text", "")) for item in content if isinstance(item, dict)
            )
        if not isinstance(content, str):
            raise ValueError("Mistral response content is not text")
        data = self._extract_json_object(content)
        return VulnerabilityCoverageAdvisory.model_validate(data)

    @staticmethod
    def _extract_json_object(content: str) -> dict[str, Any]:
        """Tolerantly pull a JSON object out of a model response.

        Handles markdown code fences and leading/trailing prose that some
        models emit even when asked for strict JSON.
        """
        text = content.strip()
        if text.startswith("```"):
            text = text.split("```", 2)[1] if text.count("```") >= 2 else text.strip("`")
            if text.lstrip().lower().startswith("json"):
                text = text.lstrip()[4:]
        text = text.strip()
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            parsed = MistralEnrichmentService._loads_forgiving(text)
        if not isinstance(parsed, dict):
            raise ValueError("Mistral response JSON was not an object")
        return parsed

    @staticmethod
    def _loads_forgiving(text: str) -> Any:
        """Parse JSON that may be wrapped in prose or truncated by a token limit."""
        start = text.find("{")
        if start == -1:
            raise ValueError("Mistral response did not contain a JSON object")
        candidate = text[start:]
        # First, try the well-formed prefix up to the last closing brace.
        end = candidate.rfind("}")
        if end != -1:
            try:
                return json.loads(candidate[: end + 1])
            except json.JSONDecodeError:
                pass
        # Best-effort repair of a response truncated mid-structure: walk the
        # text tracking string state and the open-container stack, then close
        # any dangling string and containers in the correct nesting order.
        stack: list[str] = []
        in_string = False
        escaped = False
        for char in candidate:
            if in_string:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    in_string = False
                continue
            if char == '"':
                in_string = True
            elif char in "{[":
                stack.append("}" if char == "{" else "]")
            elif char in "}]" and stack:
                stack.pop()
        repaired = candidate.rstrip()
        if in_string:
            repaired += '"'
        if repaired.endswith((",", ":")):
            repaired = repaired[:-1]
        repaired += "".join(reversed(stack))
        return json.loads(repaired)

    async def _coverage_snapshot(
        self,
        scan_id: uuid.UUID,
    ) -> tuple[dict[str, Any], set[str], set[str]]:
        assets = list(
            (await self.session.execute(select(Asset).where(Asset.scan_id == scan_id)))
            .scalars()
            .all()
        )
        matrices = list(
            (
                await self.session.execute(
                    select(AssetTestMatrix).where(AssetTestMatrix.scan_id == scan_id)
                )
            )
            .scalars()
            .all()
        )
        matrix_ids = [matrix.id for matrix in matrices]
        requirements = (
            list(
                (
                    await self.session.execute(
                        select(TestRequirement).where(TestRequirement.matrix_id.in_(matrix_ids))
                    )
                )
                .scalars()
                .all()
            )
            if matrix_ids
            else []
        )
        classes = list(
            (
                await self.session.execute(
                    select(VulnerabilityClass).where(VulnerabilityClass.active.is_(True))
                )
            )
            .scalars()
            .all()
        )
        class_map = {item.id: item.class_code for item in classes}
        matrix_assets = {item.id: item.asset_id for item in matrices}
        class_summaries: dict[str, dict[str, Any]] = {}
        open_statuses = {
            TestRequirementCoverageStatus.NOT_TESTED.value,
            TestRequirementCoverageStatus.PLANNED.value,
            TestRequirementCoverageStatus.TESTING.value,
            TestRequirementCoverageStatus.PARTIALLY_TESTED.value,
            TestRequirementCoverageStatus.INCONCLUSIVE.value,
        }
        for requirement in requirements:
            class_code = class_map.get(requirement.vulnerability_class_id)
            if not class_code:
                continue
            summary = class_summaries.setdefault(
                class_code,
                {
                    "class_code": class_code,
                    "applicability_counts": {},
                    "coverage_counts": {},
                    "open_asset_ids": [],
                },
            )
            app_counts = summary["applicability_counts"]
            app_counts[requirement.applicability_state] = (
                app_counts.get(requirement.applicability_state, 0) + 1
            )
            coverage_counts = summary["coverage_counts"]
            coverage_counts[requirement.coverage_status] = (
                coverage_counts.get(requirement.coverage_status, 0) + 1
            )
            if requirement.coverage_status in open_statuses:
                summary["open_asset_ids"].append(str(matrix_assets[requirement.matrix_id]))
        matrix_asset_ids = set(matrix_assets.values())
        redacted_assets = []
        for asset in assets[:100]:
            metadata = asset.metadata_ or {}
            redacted_assets.append(
                {
                    "asset_id": str(asset.id),
                    "asset_type": asset.asset_type,
                    "criticality": asset.criticality,
                    "technologies": list(metadata.get("technologies", []))[:20],
                    "scheme": metadata.get("scheme"),
                    "port": metadata.get("port"),
                    "method": metadata.get("method"),
                    "has_test_matrix": asset.id in matrix_asset_ids,
                }
            )
        snapshot = {
            "scan_id": str(scan_id),
            "catalog_class_codes": sorted(class_map.values()),
            "assets": redacted_assets,
            "class_coverage": sorted(class_summaries.values(), key=lambda item: item["class_code"]),
            "redaction": (
                "Hostnames, URLs, raw artifacts, credentials, secret values, request "
                "bodies, and response bodies are excluded."
            ),
        }
        return snapshot, set(class_map.values()), {str(item.id) for item in assets}

    @staticmethod
    def _filter_output(
        advisory: VulnerabilityCoverageAdvisory,
        class_codes: set[str],
        asset_ids: set[str],
    ) -> VulnerabilityCoverageAdvisory:
        return advisory.model_copy(
            update={
                "priority_classes": [
                    item for item in advisory.priority_classes if item.class_code in class_codes
                ],
                "cross_asset_hypotheses": [
                    item.model_copy(
                        update={
                            "asset_ids": [
                                asset_id for asset_id in item.asset_ids if asset_id in asset_ids
                            ]
                        }
                    )
                    for item in advisory.cross_asset_hypotheses
                    if item.class_code in class_codes
                ],
            }
        )

    @staticmethod
    def _fallback(
        snapshot: dict[str, Any],
        reason: str,
    ) -> VulnerabilityCoverageAdvisory:
        ranked = sorted(
            snapshot.get("class_coverage", []),
            key=lambda item: len(item.get("open_asset_ids", [])),
            reverse=True,
        )
        priorities = [
            AdvisoryPriority(
                class_code=item["class_code"],
                rationale=(
                    f"{len(item.get('open_asset_ids', []))} asset matrix cells remain open."
                ),
                evidence_gap="Testing or validation coverage is incomplete.",
                recommended_validation=(
                    "Follow the deterministic next_action and collect the required evidence."
                ),
            )
            for item in ranked[:10]
            if item.get("open_asset_ids")
        ]
        return VulnerabilityCoverageAdvisory(
            summary=(
                f"Coverage advisory generated from {len(snapshot.get('assets', []))} "
                f"redacted assets and {len(snapshot.get('catalog_class_codes', []))} "
                "catalog classes."
            ),
            priority_classes=priorities,
            cross_asset_hypotheses=[],
            limitations=[
                reason,
                "This advisory does not confirm vulnerabilities or replace analyst validation.",
                "Unknown implementation-specific weaknesses may exist outside the catalog.",
            ],
        )
