"""Scope validation."""

import hashlib
import ipaddress
import re
import uuid
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

from vapt_platform.domain.enums import AssessmentMode, Capability, ScopeDecisionType, ScopeRuleType
from vapt_platform.domain.exceptions import ScopeDeniedError


@dataclass
class TargetDescriptor:
    hostname: str | None = None
    ip: str | None = None
    url: str | None = None
    port: int | None = None
    domain: str | None = None

    def normalized_key(self) -> str:
        if self.url:
            return self.url.lower().rstrip("/")
        if self.hostname:
            return self.hostname.lower()
        if self.ip:
            p = f":{self.port}" if self.port else ""
            return f"{self.ip}{p}"
        if self.domain:
            return self.domain.lower()
        return "unknown"


@dataclass
class ScopeRuleData:
    rule_type: str
    pattern: str
    assessment_mode: str = "ACTIVE"
    priority: int = 0
    enabled: bool = True


@dataclass
class ScopeDecision:
    decision: ScopeDecisionType
    rule_id: str | None
    reason: str
    audit_id: uuid.UUID

    @property
    def allowed(self) -> bool:
        return self.decision == ScopeDecisionType.ALLOW


class ScopeManager:
    """Evaluates whether targets and capabilities are in authorized scope."""

    PASSIVE_CAPABILITIES = {
        Capability.PASSIVE_SUBDOMAIN_DISCOVERY,
        Capability.HISTORICAL_URL_DISCOVERY,
        Capability.WEB_PASSIVE_ASSESSMENT,
        Capability.VULNERABILITY_FINDING_IMPORT,
    }

    def __init__(self, rules: list[ScopeRuleData]) -> None:
        self.rules = sorted(
            [r for r in rules if r.enabled],
            key=lambda r: r.priority,
            reverse=True,
        )

    def evaluate(
        self,
        target: TargetDescriptor,
        capability: Capability | str,
        correlation_id: uuid.UUID | None = None,
    ) -> ScopeDecision:
        cap = Capability(capability) if isinstance(capability, str) else capability
        audit_id = uuid.uuid4()
        exclusions = [r for r in self.rules if r.rule_type == ScopeRuleType.EXCLUSION.value]
        for rule in exclusions:
            if self._matches(rule, target):
                return ScopeDecision(
                    ScopeDecisionType.DENY,
                    rule.pattern,
                    f"Excluded by rule {rule.pattern}",
                    audit_id,
                )

        inclusions = [r for r in self.rules if r.rule_type != ScopeRuleType.EXCLUSION.value]
        matched: ScopeRuleData | None = None
        for rule in inclusions:
            if self._matches(rule, target):
                matched = rule
                break

        if not matched:
            return ScopeDecision(
                ScopeDecisionType.DENY,
                None,
                "No matching inclusion rule",
                audit_id,
            )

        if matched.assessment_mode == AssessmentMode.PASSIVE_ONLY.value:
            if cap not in self.PASSIVE_CAPABILITIES:
                return ScopeDecision(
                    ScopeDecisionType.DENY,
                    matched.pattern,
                    "Passive-only target; capability not passive",
                    audit_id,
                )

        return ScopeDecision(
            ScopeDecisionType.ALLOW,
            matched.pattern,
            f"Allowed by {matched.rule_type}={matched.pattern}",
            audit_id,
        )

    def assert_allowed(
        self, target: TargetDescriptor, capability: Capability | str
    ) -> ScopeDecision:
        decision = self.evaluate(target, capability)
        if not decision.allowed:
            raise ScopeDeniedError(decision.reason)
        return decision

    def _matches(self, rule: ScopeRuleData, target: TargetDescriptor) -> bool:
        rt = ScopeRuleType(rule.rule_type)
        pattern = rule.pattern.lower()
        if rt == ScopeRuleType.ROOT_DOMAIN:
            host = _target_host(target)
            return host == pattern or host.endswith(f".{pattern}")
        if rt == ScopeRuleType.HOSTNAME:
            return _target_host(target) == pattern
        if rt == ScopeRuleType.SUBDOMAIN_PATTERN:
            host = (target.hostname or "").lower()
            regex = pattern.replace("*.", ".*\\.")
            return bool(re.match(f"^{regex}$", host))
        if rt == ScopeRuleType.IP:
            return target.ip == rule.pattern
        if rt == ScopeRuleType.CIDR:
            if not target.ip:
                return False
            try:
                return ipaddress.ip_address(target.ip) in ipaddress.ip_network(
                    rule.pattern, strict=False
                )
            except ValueError:
                return False
        if rt == ScopeRuleType.URL_PREFIX:
            url = _scope_url(target.url or "")
            return url.startswith(_scope_url(pattern))
        if rt == ScopeRuleType.EXCLUSION:
            host = _target_host(target)
            return host == pattern or host.endswith(f".{pattern}")
        return False


def task_uniqueness_key(
    scan_id: uuid.UUID,
    capability: str,
    normalized_target: str,
    configuration_hash: str = "",
) -> str:
    raw = f"{scan_id}:{capability}:{normalized_target}:{configuration_hash}"
    return hashlib.sha256(raw.encode()).hexdigest()


def _scope_url(value: str) -> str:
    if not value:
        return ""
    try:
        parsed = urlsplit(value.lower().rstrip("/"))
    except ValueError:
        return value.lower().rstrip("/")
    if not parsed.scheme or not parsed.netloc:
        return value.lower().rstrip("/")
    host = parsed.hostname or parsed.netloc
    netloc = f"{host}:{parsed.port}" if parsed.port else host
    return urlunsplit((parsed.scheme, netloc, parsed.path.rstrip("/"), parsed.query, ""))


def _target_host(target: TargetDescriptor) -> str:
    if target.hostname:
        return target.hostname.lower()
    if target.domain:
        return target.domain.lower()
    if target.url:
        try:
            parsed = urlsplit(target.url)
        except ValueError:
            return ""
        return (parsed.hostname or parsed.netloc or "").lower()
    return ""
