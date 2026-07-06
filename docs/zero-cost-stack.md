# Zero-Cost Stack

## 1. Purpose

Document the capability provider stack usable **without mandatory paid services**. Commercial and paid APIs are optional integrations that degrade gracefully when unavailable.

---

## 2. Principles

1. Core workflow runs with open-source tools only
2. Paid OSINT APIs are optional (`enabled=false` by default)
3. Mistral AI is optional (`AI_ENABLED=false`)
4. MCP uses free protocol tooling
5. Local development via Docker Compose
6. Provider unavailable → skip with audit, never block scan

---

## 3. Capability provider matrix

### Asset and subdomain discovery

| Capability | Primary free provider | Fallback free | Optional paid | API key | Quota | Local resources | License |
|------------|----------------------|---------------|---------------|---------|-------|-----------------|---------|
| PASSIVE_SUBDOMAIN_DISCOVERY | Subfinder | Amass passive | SecurityTrails | Optional for paid | None for OSS | Low CPU | MIT |
| ACTIVE_SUBDOMAIN_DISCOVERY | Amass | DNS bruteforce adapters | — | No | — | Medium | MIT |
| CERTIFICATE_TRANSPARENCY_DISCOVERY | crt.sh API | Amass CT | — | No | Rate limit crt.sh | Low | MIT |
| CODE_REFERENCE_DISCOVERY | GitHub search | — | — | GitHub token optional | GitHub rate limits | Low | — |
| EXTERNAL_DATASET_DISCOVERY | Chaos (free tier) | — | — | Optional | ProjectDiscovery quota | Low | — |

### DNS

| Capability | Primary | Fallback | API | Quota | Resources | License |
|------------|---------|----------|-----|-------|-----------|---------|
| DNS_RESOLUTION | dnsx | dig wrapper | No | — | Low | MIT |
| WILDCARD_DETECTION | dnsx | custom | No | — | Low | MIT |
| DNS_BRUTEFORCE | ShuffleDNS | MassDNS | No | — | Medium | MIT |
| DNS_PERMUTATION_GENERATION | AltDNS | dnsgen | No | — | Low | MIT |
| HIGH_VOLUME_DNS_RESOLUTION | MassDNS | PureDNS | No | — | High network | GPL/MIT |
| CIDR_EXPANSION | MapCIDR | — | No | — | Low | MIT |

### Host and service

| Capability | Primary | Fallback | Optional paid | API | Resources | License |
|------------|---------|----------|---------------|-----|-----------|---------|
| HOST_REACHABILITY | httpx | curl adapter | — | No | Low | MIT |
| PORT_DISCOVERY | Naabu | RustScan | — | No | Medium | MIT |
| SERVICE_IDENTIFICATION | httpx | Nmap limited | — | No | Medium | MIT |
| PROTOCOL_CONFIRMATION | Nmap | — | — | No | Medium | GPL |
| HTTP_PROBING | httpx | — | — | No | Low | MIT |

### Historical URL and crawling

| Capability | Primary | Fallback | API | Resources | License |
|------------|---------|----------|-----|-----------|---------|
| HISTORICAL_URL_DISCOVERY | gau | waymore | No | Medium | MIT |
| ARCHIVE_DISCOVERY | Wayback CDX | gau | No | Medium | MIT |
| LIVE_CRAWLING | Katana | Hakrawler | No | Medium | MIT |
| ENDPOINT_EXTRACTION | Parser | — | No | Low | — |

### Content discovery

| Capability | Primary | Fallback | Resources | License |
|------------|---------|----------|-----------|---------|
| CONTENT_DISCOVERY | feroxbuster | ffuf | Medium | MIT |
| DIRECTORY_DISCOVERY | gobuster | dirsearch | Medium | MIT |
| FILE_DISCOVERY | ffuf | — | Medium | MIT |

### Parameters and URL tools

| Capability | Primary | Fallback | License |
|------------|---------|----------|---------|
| PARAMETER_DISCOVERY | Arjun | ParamSpider | MIT |
| URL_NORMALIZATION | unfurl | — | MIT |
| URL_PATTERN_CLASSIFICATION | gf | — | MIT |
| QUERY_MUTATION_PREPARATION | qsreplace | — | MIT |

### JavaScript and secrets

| Capability | Primary | Fallback | Notes | License |
|------------|---------|----------|-------|---------|
| JAVASCRIPT_COLLECTION | Katana | httpx | — | MIT |
| STATIC_ROUTE_EXTRACTION | LinkFinder | custom parser | — | GPL |
| STATIC_API_REFERENCE_EXTRACTION | LinkFinder | — | — | GPL |
| SECRET_INDICATOR_DISCOVERY | Gitleaks | TruffleHog OSS | Redact in storage | MIT |
| REPOSITORY_SECRET_ASSESSMENT | Gitleaks | — | Scope-bound repos | MIT |

### Fingerprinting

| Capability | Primary | Fallback | License |
|------------|---------|----------|---------|
| TECHNOLOGY_IDENTIFICATION | WhatWeb | webanalyze | GPL/MIT |
| WAF_IDENTIFICATION | WAFW00F | — | MIT |
| TLS_CHARACTERIZATION | tlsx | openssl wrapper | MIT |
| WEB_FINGERPRINTING | httpx | — | MIT |

### OSINT (optional)

| Capability | Primary free | Optional paid | API | Quota |
|------------|-------------|---------------|-----|-------|
| EXTERNAL_ASSET_ENRICHMENT | urlscan.io | Shodan, Censys | Yes for paid | Free tiers vary |
| INTERNET_SERVICE_OBSERVATION | — | Shodan | SHODAN_API_KEY | Free tier limited |
| HISTORICAL_SERVICE_OBSERVATION | — | SecurityTrails | API key | Paid |

**Default:** OSINT paid providers disabled in `config/default.yaml`.

### Cloud

| Capability | Primary | License |
|------------|---------|---------|
| CLOUD_ASSET_DISCOVERY | cloud_enum | MIT |
| CLOUD_CONFIGURATION_ASSESSMENT | ScoutSuite | Apache 2.0 |
| CLOUD_RESOURCE_OWNERSHIP_VALIDATION | Internal rules | — |

### API

| Capability | Primary | License |
|------------|---------|---------|
| API_ROUTE_DISCOVERY | Kiterunner | MIT |
| GRAPHQL_SCHEMA_INVENTORY | InQL | — |
| API_OPERATION_INVENTORY | OpenAPI parser | — |
| TRAFFIC_OBSERVATION_IMPORT | mitmproxy export | MIT |

### Vulnerability assessment (free core)

| Capability | Primary | Fallback | Notes | License |
|------------|---------|----------|-------|---------|
| NETWORK_VULNERABILITY_ASSESSMENT | OpenVAS/GVM CE | Nmap NSE limited | Heavy container | GPL |
| KNOWN_VULNERABILITY_ASSESSMENT | Nuclei | — | Template allowlist | MIT |
| CONFIGURATION_ASSESSMENT | Nuclei | OpenVAS | — | MIT |
| WEB_PASSIVE_ASSESSMENT | ZAP passive | — | — | Apache 2.0 |
| WEB_ACTIVE_ASSESSMENT | ZAP active | — | Policy-controlled | Apache 2.0 |
| API_ASSESSMENT | ZAP API | — | — | Apache 2.0 |
| AUTHENTICATED_WEB_ASSESSMENT | ZAP + auth context | — | Credential refs only | Apache 2.0 |
| TEMPLATE_BASED_ASSESSMENT | Nuclei | — | Safety classified | MIT |
| DEPENDENCY_ASSESSMENT | Trivy | — | — | Apache 2.0 |
| CONTAINER_ASSESSMENT | Trivy | — | — | Apache 2.0 |
| IAC_ASSESSMENT | Trivy | — | — | Apache 2.0 |
| STATIC_RULE_ASSESSMENT | Semgrep CE | — | — | LGPL |

### Platform services

| Component | Provider | Cost |
|-----------|----------|------|
| Database | PostgreSQL (Docker) | Free |
| Queue | Redis (Docker) | Free |
| Workers | Celery | Free |
| AI enrichment | Mistral API | Optional; free tier if available |
| MCP | Python MCP SDK | Free |
| Secret store (dev) | Env / encrypted file | Free |

---

## 4. Phase J initial integration set (minimal complementary)

| # | Capability group | Primary provider |
|---|------------------|------------------|
| 1 | Subdomain discovery | Subfinder |
| 2 | DNS validation | dnsx |
| 3 | Port discovery | Naabu |
| 4 | Service characterization | httpx |
| 5 | HTTP probing | httpx |
| 6 | Crawler | Katana |
| 7 | Template assessment | Nuclei |
| 8 | Web DAST | ZAP |
| 9 | Network vuln assessment | OpenVAS (or Nmap NSE fallback) |

No redundant providers until marginal gain justifies.

---

## 5. Configuration example

```yaml
providers:
  shodan:
    enabled: false
    cost_tier: OPTIONAL_PAID
  subfinder:
    enabled: true
    cost_tier: FREE
  nuclei:
    enabled: true
    cost_tier: FREE
    template_allowlist: config/nuclei-safe-templates.txt
```

---

## 6. References

- `capability-registry.md`
- `test-safety-policy.md`
- ADR-0005
