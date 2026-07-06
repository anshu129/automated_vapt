# Surface Completeness

## 1. Purpose

The Surface Completeness Engine determines whether each asset's attack surface has been adequately inventoried before vulnerability applicability and test planning proceed. Replaces coarse scan-level coverage as the per-asset source of truth for surface readiness.

---

## 2. SurfaceCompletenessEngine

### Interface

```python
class SurfaceCompletenessEngine(Protocol):
    def compute(
        self,
        asset_id: UUID,
        scan_id: UUID,
    ) -> SurfaceCoverageRecord: ...

    def compute_scan_summary(
        self,
        scan_id: UUID,
        asset_type: AssetType | None = None,
    ) -> list[SurfaceCoverageRecord]: ...

    def missing_requirements(
        self,
        asset_id: UUID,
        scan_id: UUID,
    ) -> list[SurfaceRequirement]: ...
```

---

## 3. SurfaceCoverageRecord

| Field | Type | Description |
|-------|------|-------------|
| `id` | UUID | |
| `asset_id` | UUID | |
| `scan_id` | UUID | |
| `asset_type` | AssetType | |
| `dimensions` | JSONB | Map dimension → status |
| `overall_status` | enum | COMPLETE, PARTIAL, NOT_STARTED, INCONCLUSIVE |
| `gap_count` | int | |
| `computed_at` | timestamp | |
| `rule_version` | string | |

### Dimension status values

`COMPLETE` | `PARTIAL` | `NOT_STARTED` | `INCONCLUSIVE` | `NOT_APPLICABLE`

---

## 4. Dimensions by asset type

### WEB_APPLICATION

| Dimension | Eligibility trigger |
|-----------|---------------------|
| `HTTP_CHARACTERIZATION` | WEB_APPLICATION confirmed |
| `REDIRECT_MAPPING` | HTTP service present |
| `TECHNOLOGY_FINGERPRINTING` | HTTP responses observed |
| `TLS_CHARACTERIZATION` | HTTPS in use |
| `LIVE_CRAWL` | In-scope web app |
| `HISTORICAL_URL_DISCOVERY` | External-facing app |
| `CONTENT_DISCOVERY` | Crawl found directories or policy requires |
| `PARAMETER_INVENTORY` | Forms/endpoints with parameters |
| `JAVASCRIPT_COLLECTION` | JS resources referenced |
| `JS_ROUTE_EXTRACTION` | JS collected |
| `API_INVENTORY` | API indicators present |
| `AUTHENTICATION_SURFACE_INVENTORY` | Login/auth endpoints detected |
| `AUTHENTICATED_AREA_COVERAGE` | Credentials authorized |
| `AUTHORIZATION_COVERAGE` | Multi-user/role context |
| `FILE_UPLOAD_SURFACE` | Upload endpoints observed |
| `ADMINISTRATIVE_SURFACE` | Admin path indicators |
| `EXTERNAL_DEPENDENCY_INVENTORY` | Third-party refs in JS/config |

### API

| Dimension | Notes |
|-----------|-------|
| `API_SPEC_DISCOVERY` | OpenAPI/GraphQL schema |
| `API_OPERATION_INVENTORY` | All operations enumerated |
| `GRAPHQL_SCHEMA_INVENTORY` | If GraphQL |
| `AUTHENTICATED_API_COVERAGE` | Per credential context |
| `PARAMETER_INVENTORY` | Request parameters |

### SERVICE (network)

| Dimension | Notes |
|-----------|-------|
| `SERVICE_IDENTIFICATION` | Banner/fingerprint |
| `TLS_CHARACTERIZATION` | If TLS |
| `PROTOCOL_CONFIRMATION` | Protocol verified |
| `NETWORK_VULN_ASSESSMENT` | If policy allows |

### HOSTNAME / IP

| Dimension | Notes |
|-----------|-------|
| `DNS_VALIDATION` | Resolved or conclusive negative |
| `PORT_DISCOVERY` | Eligible ports scanned |
| `SERVICE_DISCOVERY` | Services on open ports |

---

## 5. Example output

**Application A**

| Dimension | Status |
|-----------|--------|
| HTTP characterization | COMPLETE |
| TLS characterization | COMPLETE |
| Technology fingerprinting | COMPLETE |
| Live crawl | COMPLETE |
| Historical URL discovery | COMPLETE |
| Content discovery | PARTIAL |
| Parameter discovery | PARTIAL |
| JavaScript analysis | COMPLETE |
| API inventory | PARTIAL |
| Authentication mapping | COMPLETE |
| Authenticated crawl | NOT_STARTED |
| Authorization coverage | NOT_STARTED |

`overall_status = PARTIAL`

---

## 6. Gap → action mapping

| Gap | Generated artifact |
|-----|-------------------|
| `AUTHENTICATED_AREA_COVERAGE` NOT_STARTED + creds available | Authenticated assessment tasks |
| `JS_ROUTE_EXTRACTION` PARTIAL | STATIC_API_REFERENCE_EXTRACTION capability |
| `API_INVENTORY` PARTIAL | API_ROUTE_DISCOVERY |
| `HISTORICAL_URL` without live validation | HTTP_PROBING tasks per URL |
| Any INCONCLUSIVE dimension | Evidence quality re-evaluation or manual review |

Emit: `SURFACE_COVERAGE_COMPUTED`, `SURFACE_GAP_IDENTIFIED`

---

## 7. Consumers

| Consumer | Usage |
|----------|-------|
| Vulnerability Applicability Engine | Surface features → applicable classes |
| Test Matrix Engine | Coverage status per class |
| Assessment Completion Evaluator | Surface completeness gates |
| Test Planner | Missing dimensions → capabilities |
| Correlation Engine | JS endpoint gap rules |

---

## 8. Relationship to CoverageRecord

- `CoverageRecord` (Phase 0): scan-level aggregate ratios for dashboards
- `SurfaceCoverageRecord`: per-asset dimensional detail (source of truth for test planning)

Scan-level records are **derived** from surface records.

---

## 9. References

- `vulnerability-applicability.md`
- `test-planner.md`
- `assessment-completion.md`
- ADR-0008
