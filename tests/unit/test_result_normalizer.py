"""Unit tests for ResultNormalizer."""

from vapt_platform.domain.capability_provider import ProviderExecutionResult
from vapt_platform.domain.normalized_artifact import NormalizedArtifactType
from vapt_platform.services.result_normalizer import NormalizationContext, ResultNormalizer


def _ctx(**kwargs) -> NormalizationContext:
    base = {
        "scan_id": "scan-1",
        "asset_id": "asset-1",
        "test_plan_id": "plan-1",
        "test_requirement_id": "req-1",
        "test_execution_id": "exec-1",
        "provider_id": "nuclei",
        "executed_capability": "TEMPLATE_BASED_ASSESSMENT",
        "vulnerability_classes": ["SECURITY_HEADERS"],
    }
    base.update(kwargs)
    return NormalizationContext(**base)


def test_nuclei_positive_creates_scanner_finding() -> None:
    result = ProviderExecutionResult(
        provider_id="nuclei",
        capability="TEMPLATE_BASED_ASSESSMENT",
        status="CORROBORATED",
        findings=[
            {
                "template_id": "cve-2024-1",
                "name": "Test vuln",
                "severity": "high",
                "matched_at": "https://app.example.com",
                "tags": ["cve"],
            }
        ],
    )
    artifacts = ResultNormalizer().normalize(result, _ctx())
    assert any(a.artifact_type == NormalizedArtifactType.SCANNER_FINDING.value for a in artifacts)


def test_nuclei_informational_creates_observation() -> None:
    result = ProviderExecutionResult(
        provider_id="nuclei",
        capability="TEMPLATE_BASED_ASSESSMENT",
        status="CORROBORATED",
        findings=[
            {
                "template_id": "tech-detect",
                "name": "Tech detect",
                "severity": "info",
                "matched_at": "https://app.example.com",
                "tags": ["tech"],
            }
        ],
    )
    artifacts = ResultNormalizer().normalize(result, _ctx())
    assert any(a.artifact_type == NormalizedArtifactType.OBSERVATION.value for a in artifacts)


def test_nuclei_clean_negative() -> None:
    result = ProviderExecutionResult(
        provider_id="nuclei",
        capability="TEMPLATE_BASED_ASSESSMENT",
        status="NO_EVIDENCE",
    )
    artifacts = ResultNormalizer().normalize(result, _ctx())
    types = {a.artifact_type for a in artifacts}
    assert NormalizedArtifactType.NEGATIVE_EVIDENCE.value in types
    assert NormalizedArtifactType.COVERAGE_EVIDENCE.value in types


def test_nuclei_timeout_inconclusive() -> None:
    result = ProviderExecutionResult(
        provider_id="nuclei",
        capability="TEMPLATE_BASED_ASSESSMENT",
        status="ERROR",
        error_code="TIMEOUT",
        detail="timeout after 120s",
    )
    artifacts = ResultNormalizer().normalize(result, _ctx())
    assert artifacts[0].artifact_type == NormalizedArtifactType.INCONCLUSIVE_EVIDENCE.value


def test_burp_transport_failure_execution_error() -> None:
    result = ProviderExecutionResult(
        provider_id="burp_mcp",
        capability="WEB_PASSIVE_ASSESSMENT",
        status="ERROR",
        detail="connection refused",
    )
    artifacts = ResultNormalizer().normalize(result, _ctx(provider_id="burp_mcp"))
    assert artifacts[0].artifact_type == NormalizedArtifactType.EXECUTION_ERROR.value


def test_sqlmap_positive_scanner_finding() -> None:
    result = ProviderExecutionResult(
        provider_id="sqlmap_mcp",
        capability="INJECTION_VALIDATION",
        status="CORROBORATED",
        findings=[{"template_id": "sqlmap-scan", "name": "sqli", "severity": "high"}],
    )
    artifacts = ResultNormalizer().normalize(
        result,
        _ctx(
            provider_id="sqlmap_mcp",
            executed_capability="INJECTION_VALIDATION",
            endpoint_context={"parameter_name": "q", "parameter_location": "query"},
        ),
    )
    assert artifacts[0].artifact_type == NormalizedArtifactType.SCANNER_FINDING.value


def test_sqlmap_clean_negative() -> None:
    result = ProviderExecutionResult(
        provider_id="sqlmap_mcp",
        capability="INJECTION_VALIDATION",
        status="NO_EVIDENCE",
    )
    artifacts = ResultNormalizer().normalize(
        result, _ctx(provider_id="sqlmap_mcp", executed_capability="INJECTION_VALIDATION")
    )
    assert any(a.artifact_type == NormalizedArtifactType.NEGATIVE_EVIDENCE.value for a in artifacts)


def test_sqlmap_ambiguous_inconclusive() -> None:
    result = ProviderExecutionResult(
        provider_id="sqlmap_mcp",
        capability="INJECTION_VALIDATION",
        status="ERROR",
        detail="ambiguous parser output",
    )
    artifacts = ResultNormalizer().normalize(
        result, _ctx(provider_id="sqlmap_mcp", executed_capability="INJECTION_VALIDATION")
    )
    assert artifacts[0].artifact_type == NormalizedArtifactType.INCONCLUSIVE_EVIDENCE.value
