"""Initial deterministic correlation rules (Phase 4)."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

from vapt_platform.domain.correlation_event import CorrelationEventType
from vapt_platform.domain.correlation_rule import (
    CorrelationContext,
    CorrelationResult,
    CorrelationResultType,
    RuleDependencies,
)
from vapt_platform.domain.correlation_event import CorrelationEventData
from vapt_platform.domain.enums import TestingMode
from vapt_platform.engines.hypothesis_uniqueness import hypothesis_uniqueness_key


def _fingerprint(*parts: str) -> str:
    return hashlib.sha256("|".join(parts).encode()).hexdigest()


def _result(
    rule_id: str,
    rule_version: str,
    result_type: str,
    *,
    payload: dict[str, Any],
    confidence: float = 0.7,
    reason_codes: list[str] | None = None,
    asset_ids: list[str] | None = None,
    explanation: dict[str, Any] | None = None,
) -> CorrelationResult:
    fp = _fingerprint(rule_id, result_type, str(sorted(payload.items())))
    return CorrelationResult(
        result_type=result_type,
        rule_id=rule_id,
        rule_version=rule_version,
        participating_asset_ids=asset_ids or list(payload.get("asset_ids", [])),
        confidence=confidence,
        reason_codes=reason_codes or [],
        explanation_data=explanation or {},
        result_fingerprint=fp,
        payload=payload,
    )


@dataclass
class JsEndpointGapRule:
    rule_id: str = "CORR-ENDPOINT-001"
    rule_version: str = "1.0"

    def dependencies(self) -> RuleDependencies:
        return RuleDependencies(
            event_types=[
                CorrelationEventType.OBSERVATION_RECORDED.value,
                CorrelationEventType.ENDPOINT_DISCOVERED.value,
            ]
        )

    def evaluate(
        self, event: CorrelationEventData, context: CorrelationContext
    ) -> list[CorrelationResult]:
        ctx = event.safe_context
        js_endpoints = set(ctx.get("js_endpoints") or context.js_endpoints)
        crawl_endpoints = set(ctx.get("crawl_endpoints") or context.crawl_endpoints)
        asset_id = (event.asset_ids or [None])[0]
        if not asset_id or not js_endpoints:
            return []
        missing = sorted(js_endpoints - crawl_endpoints)
        if not missing:
            return []
        endpoint = missing[0]
        return [
            _result(
                self.rule_id,
                self.rule_version,
                CorrelationResultType.COVERAGE_GAP_CANDIDATE.value,
                payload={
                    "gap_type": "ENDPOINT_DISCOVERY",
                    "asset_id": asset_id,
                    "endpoint_ref": endpoint,
                    "validation_objective": "ENDPOINT_VALIDATION",
                },
                reason_codes=["JS_ENDPOINT_NOT_IN_CRAWL"],
                asset_ids=[asset_id],
                explanation={
                    "reason": "JS_ENDPOINT_GAP",
                    "endpoint": endpoint,
                    "rule_id": self.rule_id,
                },
            ),
            _result(
                self.rule_id,
                self.rule_version,
                CorrelationResultType.HYPOTHESIS_CANDIDATE.value,
                payload={
                    "hypothesis_type": "ENDPOINT_DISCOVERY_GAP",
                    "vulnerability_class": "ENDPOINT_DISCOVERY",
                    "asset_ids": [asset_id],
                    "endpoint_ref": endpoint,
                    "title": "Undocumented endpoint referenced by JavaScript",
                    "description": f"Endpoint {endpoint} referenced in JS but not in crawl inventory",
                    "scope_dimensions": {"endpoint_ref": endpoint},
                    "testing_mode": TestingMode.AUTOMATED.value,
                },
                reason_codes=["JS_ENDPOINT_NOT_IN_CRAWL"],
                asset_ids=[asset_id],
            ),
        ]


@dataclass
class SharedIdentityAuthGapRule:
    rule_id: str = "CORR-AUTH-001"
    rule_version: str = "1.0"

    def dependencies(self) -> RuleDependencies:
        return RuleDependencies(
            event_types=[
                CorrelationEventType.RELATIONSHIP_CREATED.value,
                CorrelationEventType.AUTH_COVERAGE_CHANGED.value,
                CorrelationEventType.ROLE_COVERAGE_CHANGED.value,
                CorrelationEventType.AUTH_CONTEXT_AVAILABLE.value,
            ],
            relationship_types=["AUTHENTICATES_WITH", "SHARES_IDENTITY_PROVIDER"],
        )

    def evaluate(
        self, event: CorrelationEventData, context: CorrelationContext
    ) -> list[CorrelationResult]:
        ctx = event.safe_context
        app_a = ctx.get("application_a_id")
        app_b = ctx.get("application_b_id")
        if not app_a or not app_b:
            return []
        cov_a = context.authorization_coverage.get(str(app_a), ctx.get("app_a_auth_coverage"))
        cov_b = context.authorization_coverage.get(str(app_b), ctx.get("app_b_auth_coverage"))
        if cov_a not in {"COMPLETE", "TESTED_NO_EVIDENCE"} or cov_b in {"COMPLETE", "TESTED_NO_EVIDENCE"}:
            return []
        return [
            _result(
                self.rule_id,
                self.rule_version,
                CorrelationResultType.HYPOTHESIS_CANDIDATE.value,
                payload={
                    "hypothesis_type": "CROSS_APPLICATION_AUTHORIZATION",
                    "vulnerability_class": "AUTHORIZATION",
                    "asset_ids": [str(app_b)],
                    "title": "Cross-application authorization consistency gap",
                    "description": (
                        f"Application {app_b} shares identity with {app_a} but lacks "
                        "equivalent authorization coverage"
                    ),
                    "scope_dimensions": {"shared_with": str(app_a)},
                    "testing_mode": TestingMode.ASSISTED.value,
                },
                reason_codes=["SHARED_IDENTITY_AUTH_GAP"],
                asset_ids=[str(app_b)],
                explanation={
                    "reason": "SHARED_IDENTITY_AUTHORIZATION_COVERAGE_GAP",
                    "application_a": str(app_a),
                    "application_b": str(app_b),
                    "rule_id": self.rule_id,
                },
            ),
            _result(
                self.rule_id,
                self.rule_version,
                CorrelationResultType.TEST_REQUIREMENT_CANDIDATE.value,
                payload={
                    "asset_id": str(app_b),
                    "vulnerability_class": "AUTHORIZATION",
                    "capability_group": "AUTHORIZATION_BOUNDARY",
                    "validation_objective": "CROSS_APP_AUTH_CONSISTENCY",
                    "testing_mode": TestingMode.ASSISTED.value,
                },
                reason_codes=["SHARED_IDENTITY_AUTH_GAP"],
                asset_ids=[str(app_b)],
            ),
        ]


@dataclass
class AuthenticatedSurfaceGapRule:
    rule_id: str = "CORR-AUTH-002"
    rule_version: str = "1.0"

    def dependencies(self) -> RuleDependencies:
        return RuleDependencies(
            event_types=[
                CorrelationEventType.AUTH_CONTEXT_AVAILABLE.value,
                CorrelationEventType.AUTH_COVERAGE_CHANGED.value,
            ]
        )

    def evaluate(
        self, event: CorrelationEventData, context: CorrelationContext
    ) -> list[CorrelationResult]:
        ctx = event.safe_context
        asset_id = (event.asset_ids or [ctx.get("asset_id")])[0]
        if not asset_id:
            return []
        unauth = ctx.get("unauthenticated_coverage") or context.authenticated_coverage.get(
            f"{asset_id}:unauth", "COMPLETE"
        )
        auth_cov = ctx.get("authenticated_coverage") or context.authenticated_coverage.get(
            str(asset_id), "INCOMPLETE"
        )
        auth_ctx_id = ctx.get("auth_context_id")
        if unauth not in {"COMPLETE", "TESTED_NO_EVIDENCE"} or auth_cov == "COMPLETE":
            return []
        return [
            _result(
                self.rule_id,
                self.rule_version,
                CorrelationResultType.COVERAGE_GAP_CANDIDATE.value,
                payload={
                    "gap_type": "AUTHENTICATED_SURFACE",
                    "asset_id": str(asset_id),
                    "auth_context_id": auth_ctx_id,
                    "validation_objective": "AUTHENTICATED_COVERAGE",
                },
                reason_codes=["AUTHENTICATED_COVERAGE_INCOMPLETE"],
                asset_ids=[str(asset_id)],
            ),
            _result(
                self.rule_id,
                self.rule_version,
                CorrelationResultType.TEST_REQUIREMENT_CANDIDATE.value,
                payload={
                    "asset_id": str(asset_id),
                    "vulnerability_class": "SECURITY_HEADERS",
                    "capability_group": "AUTHENTICATED_ASSESSMENT",
                    "auth_context_id": auth_ctx_id,
                    "validation_objective": "AUTHENTICATED_SURFACE_COVERAGE",
                    "testing_mode": TestingMode.AUTOMATED.value,
                },
                reason_codes=["AUTHENTICATED_COVERAGE_INCOMPLETE"],
                asset_ids=[str(asset_id)],
            ),
        ]


@dataclass
class NewExposedServiceRule:
    rule_id: str = "CORR-CHANGE-001"
    rule_version: str = "1.0"

    def dependencies(self) -> RuleDependencies:
        return RuleDependencies(
            event_types=[
                CorrelationEventType.SERVICE_DISCOVERED.value,
                CorrelationEventType.CHANGE_EVENT_RECORDED.value,
            ]
        )

    def evaluate(
        self, event: CorrelationEventData, context: CorrelationContext
    ) -> list[CorrelationResult]:
        ctx = event.safe_context
        if ctx.get("change_category") not in {None, "SERVICE_ADDED", "ASSET_ADDED"}:
            return []
        asset_id = (event.asset_ids or [ctx.get("asset_id")])[0]
        if not asset_id or not ctx.get("externally_reachable", True):
            return []
        return [
            _result(
                self.rule_id,
                self.rule_version,
                CorrelationResultType.TEST_REQUIREMENT_CANDIDATE.value,
                payload={
                    "asset_id": str(asset_id),
                    "vulnerability_class": "KNOWN_COMPONENT_VULNERABILITY",
                    "capability_group": "SERVICE_CHARACTERIZATION",
                    "validation_objective": "NEW_SERVICE_ASSESSMENT",
                    "testing_mode": TestingMode.AUTOMATED.value,
                },
                reason_codes=["NEW_EXPOSED_SERVICE"],
                asset_ids=[str(asset_id)],
            ),
        ]


@dataclass
class SharedRootCauseRule:
    rule_id: str = "CORR-ROOT-001"
    rule_version: str = "1.0"

    def dependencies(self) -> RuleDependencies:
        return RuleDependencies(
            event_types=[CorrelationEventType.SCANNER_FINDING_RECORDED.value],
            evidence_types=["SCANNER_FINDING"],
        )

    def evaluate(
        self, event: CorrelationEventData, context: CorrelationContext
    ) -> list[CorrelationResult]:
        ctx = event.safe_context
        related_ids = ctx.get("related_finding_ids") or []
        config_source = ctx.get("configuration_source")
        asset_id = (event.asset_ids or [None])[0]
        if not asset_id or len(related_ids) < 1:
            return []
        return [
            _result(
                self.rule_id,
                self.rule_version,
                CorrelationResultType.HYPOTHESIS_CANDIDATE.value,
                payload={
                    "hypothesis_type": "SHARED_ROOT_CAUSE",
                    "vulnerability_class": ctx.get("vulnerability_class", "DEFAULT"),
                    "asset_ids": [str(asset_id)],
                    "title": "Shared root cause candidate",
                    "description": "Multiple scanner findings share configuration evidence",
                    "scope_dimensions": {"configuration_source": config_source or "unknown"},
                    "related_finding_ids": related_ids,
                    "testing_mode": TestingMode.ASSISTED.value,
                },
                reason_codes=["SHARED_CONFIGURATION_EVIDENCE"],
                asset_ids=[str(asset_id)],
            ),
        ]


@dataclass
class SharedTechnologyCoverageRule:
    rule_id: str = "CORR-TECH-001"
    rule_version: str = "1.0"

    def dependencies(self) -> RuleDependencies:
        return RuleDependencies(
            event_types=[
                CorrelationEventType.TECHNOLOGY_OBSERVED.value,
                CorrelationEventType.OBSERVATION_RECORDED.value,
            ]
        )

    def evaluate(
        self, event: CorrelationEventData, context: CorrelationContext
    ) -> list[CorrelationResult]:
        ctx = event.safe_context
        tech = ctx.get("technology")
        source_asset = ctx.get("covered_asset_id")
        target_asset = (event.asset_ids or [ctx.get("uncovered_asset_id")])[0]
        if not tech or not source_asset or not target_asset:
            return []
        if str(source_asset) == str(target_asset):
            return []
        return [
            _result(
                self.rule_id,
                self.rule_version,
                CorrelationResultType.TEST_REQUIREMENT_CANDIDATE.value,
                payload={
                    "asset_id": str(target_asset),
                    "vulnerability_class": "KNOWN_COMPONENT_VULNERABILITY",
                    "capability_group": "TECHNOLOGY_ASSESSMENT",
                    "validation_objective": f"TECH_COVERAGE_{tech}",
                    "testing_mode": TestingMode.AUTOMATED.value,
                    "technology": tech,
                    "reference_asset_id": str(source_asset),
                },
                reason_codes=["SHARED_TECHNOLOGY_COVERAGE_GAP"],
                asset_ids=[str(target_asset)],
            ),
        ]


@dataclass
class ParameterDiscoveryGapRule:
    rule_id: str = "CORR-PARAM-001"
    rule_version: str = "1.0"

    def dependencies(self) -> RuleDependencies:
        return RuleDependencies(
            event_types=[CorrelationEventType.PARAMETER_DISCOVERED.value],
            vulnerability_classes=["INJECTION_CLASS"],
        )

    def evaluate(
        self, event: CorrelationEventData, context: CorrelationContext
    ) -> list[CorrelationResult]:
        ctx = event.safe_context
        asset_id = (event.asset_ids or [ctx.get("asset_id")])[0]
        endpoint = ctx.get("endpoint_ref")
        param = ctx.get("parameter_name")
        if not asset_id or not endpoint or not param:
            return []
        return [
            _result(
                self.rule_id,
                self.rule_version,
                CorrelationResultType.TEST_REQUIREMENT_CANDIDATE.value,
                payload={
                    "asset_id": str(asset_id),
                    "vulnerability_class": "INJECTION_CLASS",
                    "capability_group": "INJECTION_VALIDATION",
                    "endpoint_ref": endpoint,
                    "parameter_name": param,
                    "parameter_location": ctx.get("parameter_location", "query"),
                    "validation_objective": "PARAMETER_INJECTION_TEST",
                    "testing_mode": TestingMode.AUTOMATED.value,
                },
                reason_codes=["PARAMETER_COVERAGE_GAP"],
                asset_ids=[str(asset_id)],
            ),
        ]


@dataclass
class NegativeEvidenceScopeGapRule:
    rule_id: str = "CORR-EVIDENCE-001"
    rule_version: str = "1.0"

    def dependencies(self) -> RuleDependencies:
        return RuleDependencies(
            event_types=[CorrelationEventType.NEGATIVE_EVIDENCE_RECORDED.value],
            evidence_types=["NEGATIVE_EVIDENCE"],
        )

    def evaluate(
        self, event: CorrelationEventData, context: CorrelationContext
    ) -> list[CorrelationResult]:
        ctx = event.safe_context
        hypothesis_id = ctx.get("hypothesis_id") or (event.hypothesis_ids or [None])[0]
        tested_param = ctx.get("parameter_name")
        untested = ctx.get("untested_parameters") or []
        asset_id = (event.asset_ids or [None])[0]
        if not asset_id or not untested:
            return [_result(
                self.rule_id,
                self.rule_version,
                CorrelationResultType.NO_ACTION.value,
                payload={"reason": "no_untested_siblings"},
            )]
        results: list[CorrelationResult] = []
        for param in untested:
            results.append(
                _result(
                    self.rule_id,
                    self.rule_version,
                    CorrelationResultType.TEST_REQUIREMENT_CANDIDATE.value,
                    payload={
                        "asset_id": str(asset_id),
                        "vulnerability_class": ctx.get("vulnerability_class", "INJECTION_CLASS"),
                        "capability_group": "INJECTION_VALIDATION",
                        "endpoint_ref": ctx.get("endpoint_ref", ""),
                        "parameter_name": param,
                        "parameter_location": ctx.get("parameter_location", "query"),
                        "validation_objective": "PARAMETER_INJECTION_TEST",
                        "testing_mode": TestingMode.AUTOMATED.value,
                        "hypothesis_id": hypothesis_id,
                        "preserve_hypothesis": True,
                    },
                    reason_codes=["NEGATIVE_EVIDENCE_SCOPE_PARTIAL"],
                    asset_ids=[str(asset_id)],
                    explanation={
                        "reason": "NEGATIVE_EVIDENCE_SCOPE_GAP",
                        "tested_parameter": tested_param,
                        "untested_parameter": param,
                    },
                )
            )
        if hypothesis_id:
            results.append(
                _result(
                    self.rule_id,
                    self.rule_version,
                    CorrelationResultType.HYPOTHESIS_UPDATE.value,
                    payload={
                        "hypothesis_id": str(hypothesis_id),
                        "status": "VALIDATION_IN_PROGRESS",
                        "preserve_rejection": True,
                    },
                    reason_codes=["NEGATIVE_EVIDENCE_SCOPE_PARTIAL"],
                )
            )
        return results


def build_initial_rules() -> list[Any]:
    return [
        JsEndpointGapRule(),
        SharedIdentityAuthGapRule(),
        AuthenticatedSurfaceGapRule(),
        NewExposedServiceRule(),
        SharedRootCauseRule(),
        SharedTechnologyCoverageRule(),
        ParameterDiscoveryGapRule(),
        NegativeEvidenceScopeGapRule(),
    ]
