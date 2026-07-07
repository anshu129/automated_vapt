"""Provider result normalization (Phase 3)."""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from vapt_platform.domain.capability_provider import ProviderExecutionResult
from vapt_platform.domain.normalized_artifact import (
    NORMALIZER_VERSION,
    ExecutionSemantics,
    NormalizedArtifact,
    NormalizedArtifactType,
)
from vapt_platform.security.sensitive_data_redactor import SensitiveDataRedactor


@dataclass
class NormalizationContext:
    scan_id: str
    asset_id: str | None
    test_plan_id: str | None
    test_execution_id: str | None
    provider_id: str
    executed_capability: str
    test_requirement_id: str | None = None
    provider_selection_decision_id: str | None = None
    vulnerability_classes: list[str] = field(default_factory=list)
    endpoint_context: dict[str, Any] = field(default_factory=dict)
    hypothesis_id: str | None = None


class ResultNormalizer:
    def __init__(self) -> None:
        self._redactor = SensitiveDataRedactor()
        self._adapters = {
            "nuclei": NucleiResultNormalizer(),
            "burp_mcp": BurpResultNormalizer(),
            "sqlmap_mcp": SqlmapResultNormalizer(),
        }

    def normalize(
        self,
        provider_result: ProviderExecutionResult,
        context: NormalizationContext,
    ) -> list[NormalizedArtifact]:
        adapter = self._adapters.get(provider_result.provider_id)
        if not adapter:
            return GenericResultNormalizer().normalize(provider_result, context)
        return adapter.normalize(provider_result, context)


class GenericResultNormalizer:
    def normalize(
        self,
        provider_result: ProviderExecutionResult,
        context: NormalizationContext,
    ) -> list[NormalizedArtifact]:
        semantics = _semantics_for_status(provider_result)
        if semantics == ExecutionSemantics.POSITIVE_RESULT:
            return [_artifact(
                NormalizedArtifactType.SCANNER_FINDING,
                context,
                provider_result,
                semantics=semantics,
                title="Provider positive result",
            )]
        if semantics == ExecutionSemantics.CLEAN_NEGATIVE:
            return [
                _artifact(
                    NormalizedArtifactType.NEGATIVE_EVIDENCE,
                    context,
                    provider_result,
                    semantics=semantics,
                    title="Clean negative validation",
                ),
                _artifact(
                    NormalizedArtifactType.COVERAGE_EVIDENCE,
                    context,
                    provider_result,
                    semantics=semantics,
                    title="Coverage completed",
                ),
            ]
        if semantics in {ExecutionSemantics.TIMEOUT, ExecutionSemantics.AMBIGUOUS_RESULT}:
            return [_artifact(
                NormalizedArtifactType.INCONCLUSIVE_EVIDENCE,
                context,
                provider_result,
                semantics=semantics,
                title="Inconclusive provider result",
            )]
        return [_artifact(
            NormalizedArtifactType.EXECUTION_ERROR,
            context,
            provider_result,
            semantics=semantics,
            title="Provider execution error",
        )]


class NucleiResultNormalizer:
    def normalize(
        self,
        provider_result: ProviderExecutionResult,
        context: NormalizationContext,
    ) -> list[NormalizedArtifact]:
        semantics = _semantics_for_status(provider_result)
        if semantics == ExecutionSemantics.CLEAN_NEGATIVE:
            return [
                _artifact(
                    NormalizedArtifactType.NEGATIVE_EVIDENCE,
                    context,
                    provider_result,
                    semantics=semantics,
                    title="Nuclei templates completed without matches",
                ),
                _artifact(
                    NormalizedArtifactType.COVERAGE_EVIDENCE,
                    context,
                    provider_result,
                    semantics=semantics,
                    title="Template coverage completed",
                    capability_only=True,
                ),
            ]
        if semantics != ExecutionSemantics.POSITIVE_RESULT:
            artifact_type = (
                NormalizedArtifactType.INCONCLUSIVE_EVIDENCE
                if semantics in {ExecutionSemantics.TIMEOUT, ExecutionSemantics.AMBIGUOUS_RESULT}
                else NormalizedArtifactType.EXECUTION_ERROR
            )
            return [_artifact(
                artifact_type,
                context,
                provider_result,
                semantics=semantics,
                title=provider_result.detail or "Nuclei execution issue",
            )]

        artifacts: list[NormalizedArtifact] = []
        for finding in provider_result.findings:
            severity = str(finding.get("severity") or "info").lower()
            is_info = severity in {"info", "unknown", ""}
            tags = [str(t).lower() for t in (finding.get("tags") or [])]
            is_observation = is_info and not any(
                t in tags for t in ("cve", "sqli", "xss", "rce", "injection")
            )
            artifact_type = (
                NormalizedArtifactType.OBSERVATION
                if is_observation
                else NormalizedArtifactType.SCANNER_FINDING
            )
            artifacts.append(
                _artifact(
                    artifact_type,
                    context,
                    provider_result,
                    semantics=ExecutionSemantics.POSITIVE_RESULT,
                    title=finding.get("name") or finding.get("template_id") or "Nuclei match",
                    finding=finding,
                )
            )
        return artifacts or [
            _artifact(
                NormalizedArtifactType.INCONCLUSIVE_EVIDENCE,
                context,
                provider_result,
                semantics=ExecutionSemantics.AMBIGUOUS_RESULT,
                title="Nuclei corroborated without parseable findings",
            )
        ]


class BurpResultNormalizer:
    def normalize(
        self,
        provider_result: ProviderExecutionResult,
        context: NormalizationContext,
    ) -> list[NormalizedArtifact]:
        semantics = _semantics_for_status(provider_result)
        if semantics == ExecutionSemantics.CLEAN_NEGATIVE:
            return [
                _artifact(
                    NormalizedArtifactType.NEGATIVE_EVIDENCE,
                    context,
                    provider_result,
                    semantics=semantics,
                    title="Burp returned no matching issues",
                )
            ]
        if semantics != ExecutionSemantics.POSITIVE_RESULT:
            artifact_type = (
                NormalizedArtifactType.INCONCLUSIVE_EVIDENCE
                if semantics == ExecutionSemantics.TIMEOUT
                else NormalizedArtifactType.EXECUTION_ERROR
            )
            return [_artifact(
                artifact_type,
                context,
                provider_result,
                semantics=semantics,
                title=provider_result.detail or "Burp MCP issue",
            )]

        artifacts: list[NormalizedArtifact] = []
        for finding in provider_result.findings:
            tags = [str(t).lower() for t in (finding.get("tags") or [])]
            severity = str(finding.get("severity") or "info").lower()
            is_proxy = "proxy" in tags or finding.get("template_id") == "burp-proxy-history"
            is_info = severity in {"info", "low"} and not is_proxy
            if is_proxy:
                artifact_type = NormalizedArtifactType.OBSERVATION
            elif is_info:
                artifact_type = NormalizedArtifactType.OBSERVATION
            else:
                artifact_type = NormalizedArtifactType.SCANNER_FINDING
            artifacts.append(
                _artifact(
                    artifact_type,
                    context,
                    provider_result,
                    semantics=ExecutionSemantics.POSITIVE_RESULT,
                    title=finding.get("name") or "Burp issue",
                    finding=finding,
                )
            )
        return artifacts


class SqlmapResultNormalizer:
    def normalize(
        self,
        provider_result: ProviderExecutionResult,
        context: NormalizationContext,
    ) -> list[NormalizedArtifact]:
        semantics = _semantics_for_status(provider_result)
        endpoint_meta = dict(context.endpoint_context or {})
        safe_endpoint = SensitiveDataRedactor().redact_dict(endpoint_meta)

        if semantics == ExecutionSemantics.CLEAN_NEGATIVE:
            return [
                _artifact(
                    NormalizedArtifactType.NEGATIVE_EVIDENCE,
                    context,
                    provider_result,
                    semantics=semantics,
                    title="sqlmap clean negative",
                    extra_metadata={"endpoint_context": safe_endpoint},
                ),
                _artifact(
                    NormalizedArtifactType.COVERAGE_EVIDENCE,
                    context,
                    provider_result,
                    semantics=semantics,
                    title="Injection parameter coverage complete",
                    capability_only=True,
                    extra_metadata={"endpoint_context": safe_endpoint},
                ),
            ]
        if semantics == ExecutionSemantics.POSITIVE_RESULT:
            return [
                _artifact(
                    NormalizedArtifactType.SCANNER_FINDING,
                    context,
                    provider_result,
                    semantics=semantics,
                    title="sqlmap injection signal",
                    finding=provider_result.findings[0] if provider_result.findings else {},
                    extra_metadata={"endpoint_context": safe_endpoint},
                )
            ]
        artifact_type = (
            NormalizedArtifactType.INCONCLUSIVE_EVIDENCE
            if semantics in {ExecutionSemantics.TIMEOUT, ExecutionSemantics.AMBIGUOUS_RESULT}
            else NormalizedArtifactType.EXECUTION_ERROR
        )
        return [_artifact(
            artifact_type,
            context,
            provider_result,
            semantics=semantics,
            title=provider_result.detail or "sqlmap execution issue",
            extra_metadata={"endpoint_context": safe_endpoint},
        )]


def _semantics_for_status(result: ProviderExecutionResult) -> ExecutionSemantics:
    code = (result.error_code or "").upper()
    detail_l = (result.detail or "").lower()
    if result.status == "UNAVAILABLE":
        return ExecutionSemantics.PROVIDER_UNAVAILABLE
    if code == "TIMEOUT" or "timeout" in detail_l:
        return ExecutionSemantics.TIMEOUT
    if "ambiguous" in detail_l:
        return ExecutionSemantics.AMBIGUOUS_RESULT
    if code == "PARSER_FAILED" or ("parse" in detail_l and "parser" not in detail_l):
        return ExecutionSemantics.PARSER_FAILED
    if code == "TRANSPORT_FAILED" or result.status == "ERROR":
        return ExecutionSemantics.TRANSPORT_FAILED
    if result.status == "CORROBORATED" and result.findings:
        return ExecutionSemantics.POSITIVE_RESULT
    if result.status == "NO_EVIDENCE":
        return ExecutionSemantics.CLEAN_NEGATIVE
    if result.status == "CORROBORATED":
        return ExecutionSemantics.AMBIGUOUS_RESULT
    return ExecutionSemantics.AMBIGUOUS_RESULT


def _artifact(
    artifact_type: NormalizedArtifactType,
    context: NormalizationContext,
    result: ProviderExecutionResult,
    *,
    semantics: ExecutionSemantics,
    title: str,
    finding: dict[str, Any] | None = None,
    capability_only: bool = False,
    extra_metadata: dict[str, Any] | None = None,
) -> NormalizedArtifact:
    redactor = SensitiveDataRedactor()
    vuln_class = context.vulnerability_classes[0] if context.vulnerability_classes else None
    payload: dict[str, Any] = {
        "provider_status": result.status,
        "detail": redactor.redact_text(result.detail or ""),
        "redacted_command": result.redacted_command,
    }
    safe_meta: dict[str, Any] = {
        "executed_capability": context.executed_capability,
        "provider_selection_decision_id": context.provider_selection_decision_id,
    }
    if finding:
        payload["finding"] = redactor.redact_dict(finding)
        safe_meta.update({
            "template_id": finding.get("template_id"),
            "source_severity": finding.get("severity"),
            "matched_at": finding.get("matched_at"),
        })
    if extra_metadata:
        safe_meta.update(extra_metadata)

    key_parts = [
        context.test_execution_id or "",
        artifact_type.value,
        context.executed_capability if capability_only else "",
        str((finding.get("template_id") or finding.get("name") or title) if finding else (title or "")),
        str(finding.get("matched_at") or "") if finding else "",
    ]
    idempotency_key = hashlib.sha256("|".join(key_parts).encode()).hexdigest()

    return NormalizedArtifact(
        artifact_type=artifact_type.value,
        scan_id=context.scan_id,
        asset_id=context.asset_id,
        test_requirement_id=context.test_requirement_id,
        test_plan_id=context.test_plan_id,
        test_execution_id=context.test_execution_id,
        provider_id=context.provider_id,
        executed_capability=context.executed_capability,
        provider_selection_decision_id=context.provider_selection_decision_id,
        vulnerability_class=vuln_class,
        title=title,
        description=redactor.redact_text(result.detail or ""),
        confidence=0.7 if artifact_type == NormalizedArtifactType.SCANNER_FINDING else 0.5,
        evidence_payload=payload,
        safe_metadata=safe_meta,
        execution_semantics=semantics.value,
        observed_at=datetime.now(UTC),
        normalizer_version=NORMALIZER_VERSION,
        idempotency_key=idempotency_key,
    )
