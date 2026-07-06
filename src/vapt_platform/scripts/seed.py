"""Seed capabilities and providers from tool manifests."""

import asyncio

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from vapt_platform.db.session import init_db, session_scope
from vapt_platform.db.tables.models import (
    ApplicabilityRule,
    CapabilityDefinition,
    CapabilityExecutionProfile,
    CapabilityProvider,
    ToolManifest,
    VulnerabilityClass,
)
from vapt_platform.domain.enums import (
    Capability,
    TestingMode,
    VulnerabilityClassCode,
    default_safety_for,
)
from vapt_platform.tools.manifest import load_tool_manifests
from vapt_platform.vuln.applicability_rules import load_rules_from_yaml

# Fake providers for offline/testing (used when binary missing)
FAKE_PROVIDERS = [
    ("fake-subfinder", Capability.PASSIVE_SUBDOMAIN_DISCOVERY, "subfinder", 5),
    ("fake-dnsx-silent", Capability.DNS_RESOLUTION, "silent", 4),
    ("fake-dnsx-resolve", Capability.DNS_RESOLUTION, "dns_resolve", 5),
    ("fake-httpx", Capability.HTTP_PROBING, "httpx", 5),
    ("fake-naabu", Capability.PORT_DISCOVERY, "naabu", 5),
    ("fake-wafw00f", Capability.WAF_IDENTIFICATION, "wafw00f", 5),
    ("fake-katana", Capability.LIVE_CRAWLING, "katana", 5),
    ("fake-paramspider", Capability.PARAMETER_DISCOVERY, "paramspider", 5),
    ("fake-js-collect", Capability.JAVASCRIPT_COLLECTION, "noop", 5),
    ("fake-nuclei", Capability.TEMPLATE_BASED_ASSESSMENT, "nuclei", 5),
]

PROFILES = [
    ("STANDARD", "Default profile", 1.0, 1.0, {}),
    ("CAUTIOUS", "Reduced concurrency", 1.5, 0.5, {"cautious": True}),
    ("HIGH_LATENCY", "Extended timeouts", 3.0, 1.0, {"high_latency": True}),
    ("NO_DISCOVERY_ASSUMPTION", "Never infer absence from silence", 2.0, 1.0, {"no_assumption": True}),
    ("PASSIVE_ONLY", "Passive capabilities only", 1.0, 1.0, {"passive_only": True}),
]


async def seed_data(session: AsyncSession) -> None:
    """Populate reference data in an existing session."""
    manifests = load_tool_manifests()

    # All capabilities from enum
    for cap in Capability:
        existing = await session.get(CapabilityDefinition, cap.value)
        if not existing:
            session.add(
                CapabilityDefinition(
                    code=cap.value,
                    capability_group=_cap_group(cap),
                    description=cap.value.replace("_", " ").title(),
                    default_safety_class=default_safety_for(cap).value,
                )
            )

    for pid, desc, tm, cm, flags in PROFILES:
        if not await session.get(CapabilityExecutionProfile, pid):
            session.add(
                CapabilityExecutionProfile(
                    id=pid,
                    version="1.0",
                    description=desc,
                    timeout_multiplier=tm,
                    concurrency_multiplier=cm,
                    policy_flags=flags,
                )
            )

    for code in VulnerabilityClassCode:
        stmt = select(VulnerabilityClass).where(VulnerabilityClass.class_code == code.value)
        if not (await session.execute(stmt)).scalar_one_or_none():
            session.add(
                VulnerabilityClass(
                    class_code=code.value,
                    name=code.value.replace("_", " ").title(),
                    description=f"Vulnerability class {code.value}",
                    default_testing_mode=_default_testing_mode(code.value),
                    typical_evidence_types=_typical_evidence_types(code.value),
                )
            )

    await _seed_applicability_rules(session)

    # Real tools from manifests.yaml
    for name, spec in manifests.items():
        if not spec.capabilities:
            continue
        stmt_tm = select(ToolManifest).where(ToolManifest.name == name)
        if (await session.execute(stmt_tm)).scalar_one_or_none():
            continue
        tm = ToolManifest(
            name=name,
            version="1.0.0",
            capabilities=spec.capabilities,
            capability_group=spec.capability_group,
            safety_class=spec.safety_class,
            cost_tier=spec.cost_tier,
        )
        session.add(tm)
        await session.flush()
        for cap_code in spec.capabilities:
            stmt2 = select(CapabilityProvider).where(
                CapabilityProvider.capability_code == cap_code,
                CapabilityProvider.provider_name == name,
            )
            if (await session.execute(stmt2)).scalar_one_or_none():
                continue
            session.add(
                CapabilityProvider(
                    capability_code=cap_code,
                    provider_name=name,
                    manifest_id=tm.id,
                    priority_weight=spec.priority,
                    cost_tier=spec.cost_tier,
                    requires_api_key=spec.requires_api_key,
                    enabled=spec.enabled,
                    supported_profiles=["STANDARD", "HIGH_LATENCY", "CAUTIOUS", "PASSIVE_ONLY"],
                )
            )

    # Fake providers
    for pname, cap, behavior, priority in FAKE_PROVIDERS:
        stmt = select(CapabilityProvider).where(
            CapabilityProvider.capability_code == cap.value,
            CapabilityProvider.provider_name == pname,
        )
        existing = (await session.execute(stmt)).scalar_one_or_none()
        if existing:
            existing.priority_weight = priority
            existing.fake_behavior = behavior
            continue
        manifest = ToolManifest(
            name=pname,
            version="1.0.0-fake",
            capabilities=[cap.value],
            capability_group=_cap_group(cap),
            safety_class=default_safety_for(cap).value,
            cost_tier="FREE",
        )
        session.add(manifest)
        await session.flush()
        session.add(
            CapabilityProvider(
                capability_code=cap.value,
                provider_name=pname,
                manifest_id=manifest.id,
                priority_weight=priority,
                supported_profiles=["STANDARD", "HIGH_LATENCY", "CAUTIOUS"],
                fake_behavior=behavior,
                enabled=True,
            )
        )


async def _seed_applicability_rules(session: AsyncSession) -> None:
    version, specs = load_rules_from_yaml()
    for spec in specs:
        stmt = select(ApplicabilityRule).where(
            ApplicabilityRule.rule_id == spec.rule_id,
            ApplicabilityRule.version == spec.version,
        )
        if (await session.execute(stmt)).scalar_one_or_none():
            continue
        session.add(
            ApplicabilityRule(
                rule_id=spec.rule_id,
                version=spec.version,
                description=spec.description,
                condition=spec.condition,
                output_classes=[
                    {
                        "class_code": o.class_code,
                        "state": o.state,
                        "confidence": o.confidence,
                    }
                    for o in spec.outputs
                ],
                active=spec.active,
            )
        )


def _cap_group(cap: Capability) -> str:
    if "DNS" in cap.value or "CIDR" in cap.value or "WILDCARD" in cap.value:
        return "DNS"
    if "SUBDOMAIN" in cap.value or "CERTIFICATE" in cap.value or "CODE_REFERENCE" in cap.value:
        return "SUBDOMAIN_DISCOVERY"
    if "PORT" in cap.value or "SERVICE" in cap.value or "PROTOCOL" in cap.value:
        return "HOST_SERVICE"
    if "CRAWL" in cap.value or "HISTORICAL" in cap.value or "ENDPOINT" in cap.value:
        return "CRAWLING"
    if "CLOUD" in cap.value:
        return "CLOUD"
    if "API" in cap.value or "GRAPHQL" in cap.value or "TRAFFIC" in cap.value:
        return "API"
    if "OSINT" in cap.value or "EXTERNAL" in cap.value or "INTERNET" in cap.value:
        return "OSINT"
    if "VULNERABILITY" in cap.value or "TEMPLATE" in cap.value or "FINDING" in cap.value:
        return "VULNERABILITY_ASSESSMENT"
    return "HTTP_WEB"


def _default_testing_mode(class_code: str) -> str:
    if class_code in {
        "SECURITY_HEADERS",
        "TLS_CONFIGURATION",
        "TRANSPORT_SECURITY",
    }:
        return TestingMode.AUTOMATED.value
    if class_code in {
        "KNOWN_COMPONENT_VULNERABILITY",
        "INPUT_VALIDATION",
        "INJECTION_CLASS",
        "GRAPHQL_SECURITY",
        "UPLOAD_SECURITY",
        "FILE_HANDLING",
    }:
        return TestingMode.ASSISTED.value
    return TestingMode.MANUAL.value


def _typical_evidence_types(class_code: str) -> list[str]:
    return {
        "SECURITY_HEADERS": ["HTTP_RESPONSE_HEADERS", "HEADER_POLICY_EVALUATION"],
        "TLS_CONFIGURATION": ["TLS_HANDSHAKE", "CERTIFICATE_METADATA"],
        "TRANSPORT_SECURITY": ["TRANSPORT_POLICY", "HTTP_RESPONSE_HEADERS"],
        "KNOWN_COMPONENT_VULNERABILITY": ["VERSIONED_TECHNOLOGY", "TEMPLATE_OUTPUT"],
        "INPUT_VALIDATION": ["PARAMETER_INVENTORY", "VALIDATION_RESULT"],
        "INJECTION_CLASS": ["PARAMETER_INVENTORY", "CONTROLLED_TEST_RESULT"],
        "GRAPHQL_SECURITY": ["GRAPHQL_SCHEMA", "AUTHORIZATION_REVIEW"],
    }.get(class_code, ["VALIDATION_RESULT"])


async def seed(database_url: str | None = None) -> None:
    await init_db(database_url)
    async with session_scope() as session:
        await seed_data(session)
    print("Seed completed.")


if __name__ == "__main__":
    asyncio.run(seed())
