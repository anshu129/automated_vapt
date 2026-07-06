# Capability Registry

## 1. Purpose

All reconnaissance and assessment tools are registered as **capability providers**, not hardcoded pipeline stages. The controller requests capabilities; the registry returns eligible providers; the selection engine picks one deterministically.

```
CAPABILITY REQUIRED
        ↓
CAPABILITY REGISTRY
        ↓
ELIGIBLE PROVIDERS (scope + policy + availability filtered)
        ↓
SELECTION POLICY (deterministic)
        ↓
ADAPTER INVOCATION
```

**Anti-pattern (prohibited):** `Tool A → Tool B → Tool C` fixed chains.

---

## 2. Core entities

### Capability

Canonical capability identifier. Enum extended from Phase 0; grouped below.

### CapabilityProvider

| Field | Type | Description |
|-------|------|-------------|
| `id` | UUID | |
| `capability` | Capability | |
| `provider_name` | string | e.g. `subfinder`, `httpx` |
| `manifest_id` | UUID | FK to ToolManifest |
| `enabled` | bool | |
| `cost_tier` | enum | FREE, FREE_QUOTA, OPTIONAL_PAID |
| `requires_api_key` | bool | |
| `api_key_secret_ref` | string | Secret backend only |
| `priority_weight` | int | Selection tie-breaker |
| `max_concurrent` | int | Per provider |
| `supported_profiles` | string[] | Execution profile IDs |

### CapabilityExecutionProfile

See `adaptive-recon.md` §5.

### ToolManifest extensions

| New field | Description |
|-----------|-------------|
| `capability_group` | Discovery group enum |
| `safety_class` | PASSIVE, LOW_IMPACT, STATE_CHANGING, DESTRUCTIVE, PROHIBITED |
| `output_observation_types` | What observations parser may emit |
| `negative_evidence_support` | Can produce conclusive negative evidence? |
| `historical_only` | Output requires current validation? |

---

## 3. Capability groups and capabilities

### Asset and subdomain discovery

| Capability | Example free providers |
|------------|------------------------|
| `PASSIVE_SUBDOMAIN_DISCOVERY` | Subfinder, Amass (passive), Assetfinder |
| `ACTIVE_SUBDOMAIN_DISCOVERY` | Amass (active), DNS bruteforce adapters |
| `CERTIFICATE_TRANSPARENCY_DISCOVERY` | CT log integrations, crt.sh |
| `CODE_REFERENCE_DISCOVERY` | GitHub search (authorized) |
| `EXTERNAL_DATASET_DISCOVERY` | Chaos (free tier), Crobat |

### DNS

| Capability | Example providers |
|------------|-------------------|
| `DNS_RESOLUTION` | dnsx |
| `WILDCARD_DETECTION` | DNS wildcard check adapters |
| `DNS_BRUTEFORCE` | ShuffleDNS, MassDNS |
| `DNS_PERMUTATION_GENERATION` | AltDNS, dnsgen |
| `HIGH_VOLUME_DNS_RESOLUTION` | PureDNS, MassDNS |
| `CIDR_EXPANSION` | MapCIDR |

### Host and service

| Capability | Example providers |
|------------|-------------------|
| `HOST_REACHABILITY_ASSESSMENT` | httpx probe |
| `PORT_DISCOVERY` | Naabu, RustScan |
| `SERVICE_IDENTIFICATION` | Nmap NSE (limited), httpx |
| `PROTOCOL_CONFIRMATION` | Nmap |
| `HTTP_PROBING` | httpx |

### Historical URL and endpoint

| Capability | Example providers |
|------------|-------------------|
| `HISTORICAL_URL_DISCOVERY` | gau, waymore |
| `ARCHIVE_DISCOVERY` | Wayback integrations |
| `LIVE_CRAWLING` | Katana, Hakrawler |
| `ENDPOINT_EXTRACTION` | Parser from crawl output |

Historical output → `HISTORICAL_OBSERVATION`; requires current validation task.

### Directory and content

| Capability | Example providers |
|------------|-------------------|
| `CONTENT_DISCOVERY` | feroxbuster |
| `DIRECTORY_DISCOVERY` | gobuster, dirsearch |
| `FILE_DISCOVERY` | ffuf |

### Parameter and URL processing

| Capability | Example providers |
|------------|-------------------|
| `PARAMETER_DISCOVERY` | Arjun, ParamSpider |
| `URL_NORMALIZATION` | unfurl |
| `URL_PATTERN_CLASSIFICATION` | gf |
| `QUERY_MUTATION_PREPARATION` | qsreplace |

URL utilities are **not** vulnerability scanners.

### JavaScript and secrets

| Capability | Example providers |
|------------|-------------------|
| `JAVASCRIPT_COLLECTION` | Katana, custom fetch |
| `STATIC_ROUTE_EXTRACTION` | LinkFinder |
| `STATIC_API_REFERENCE_EXTRACTION` | LinkFinder, custom |
| `SECRET_INDICATOR_DISCOVERY` | TruffleHog, Gitleaks |
| `REPOSITORY_SECRET_DISCOVERY` | Gitleaks |

Secret material: redacted storage only; never in AI/MCP/logs.

### Fingerprinting

| Capability | Example providers |
|------------|-------------------|
| `TECHNOLOGY_IDENTIFICATION` | WhatWeb, webanalyze |
| `WAF_IDENTIFICATION` | WAFW00F |
| `TLS_CHARACTERIZATION` | tlsx |
| `WEB_FINGERPRINTING` | httpx metadata |

### OSINT (optional, zero-cost preferred)

| Capability | Example providers |
|------------|-------------------|
| `EXTERNAL_ASSET_ENRICHMENT` | Shodan (free quota), urlscan.io |
| `INTERNET_SERVICE_OBSERVATION` | Censys (optional) |
| `HISTORICAL_SERVICE_OBSERVATION` | SecurityTrails (optional) |

Paid providers: `enabled=false` by default. See `zero-cost-stack.md`.

### Cloud

| Capability | Example providers |
|------------|-------------------|
| `CLOUD_ASSET_DISCOVERY` | cloud_enum |
| `CLOUD_CONFIGURATION_ASSESSMENT` | ScoutSuite |
| `CLOUD_RESOURCE_OWNERSHIP_VALIDATION` | Internal rules + scope |

New cloud assets require ownership validation before active assessment.

### API

| Capability | Example providers |
|------------|-------------------|
| `API_ROUTE_DISCOVERY` | Kiterunner |
| `GRAPHQL_SCHEMA_INVENTORY` | InQL |
| `API_OPERATION_INVENTORY` | OpenAPI parser |
| `TRAFFIC_OBSERVATION_IMPORT` | mitmproxy import adapter |

### Vulnerability assessment (free tier)

| Capability | Example providers |
|------------|-------------------|
| `NETWORK_VULNERABILITY_ASSESSMENT` | OpenVAS/GVM |
| `SERVICE_SPECIFIC_ASSESSMENT` | Nmap NSE adapters |
| `KNOWN_VULNERABILITY_ASSESSMENT` | Nuclei |
| `CONFIGURATION_ASSESSMENT` | Nuclei, OpenVAS |
| `WEB_PASSIVE_ASSESSMENT` | ZAP passive |
| `WEB_ACTIVE_ASSESSMENT` | ZAP active (policy-controlled) |
| `API_ASSESSMENT` | ZAP API scan |
| `AUTHENTICATED_WEB_ASSESSMENT` | ZAP with auth context |
| `TEMPLATE_BASED_ASSESSMENT` | Nuclei |
| `DEPENDENCY_ASSESSMENT` | Trivy |
| `CONTAINER_ASSESSMENT` | Trivy |
| `IAC_ASSESSMENT` | Trivy, Checkov (future) |
| `REPOSITORY_SECRET_ASSESSMENT` | Gitleaks |
| `STATIC_RULE_ASSESSMENT` | Semgrep CE |

---

## 4. Provider selection policy (deterministic)

```python
def select_provider(
    capability: Capability,
    eligible: list[CapabilityProvider],
    context: SelectionContext,
) -> CapabilityProvider:
    # 1. Filter: scope, safety, cost policy, availability, API key present
    # 2. Exclude: providers below gain threshold (MarginalDiscoveryGainEngine)
    # 3. Sort: unique_gain_history DESC, priority_weight DESC, provider_name ASC
    # 4. Return first; tie-breaker is stable sort key
```

**No AI.** Selection trace stored in `AuditEvent` and task provenance.

---

## 5. CapabilityMatcher

Maps workflow stage + asset type + surface state → required capabilities:

```python
class CapabilityMatcher(Protocol):
    def required_capabilities(
        self,
        asset: Asset,
        stage: WorkflowStage,
        surface_coverage: SurfaceCoverageRecord | None,
    ) -> list[Capability]: ...
```

---

## 6. Registration requirements

Every provider integration requires:

1. ToolManifest with safety_class
2. Adapter implementation
3. Parser implementation
4. Unit tests
5. Integration fixture
6. Failure tests (malformed output, timeout)
7. zero-cost-stack.md entry

---

## 7. References

- ADR-0005
- `zero-cost-stack.md`
- `test-safety-policy.md`
- `phase-a-implementation-plan.md`
