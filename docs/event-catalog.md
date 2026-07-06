# Event Catalog

## 1. Purpose

Events are the **sole driver** of Recon Controller transitions. Every event is:

- Schema-validated (Pydantic)
- Append-only in the event store
- Associated with `scan_id`, `correlation_id`, and optional `causation_id`
- Processed exactly once per `event_id` (idempotent handler via dedup key)

Events create **observations** and may trigger **tasks**. They never directly create confirmed vulnerabilities.

---

## 2. Event envelope

All events share a common envelope:

```yaml
id: UUID
scan_id: UUID
event_type: EventType
payload: object          # type-specific schema
correlation_id: UUID     # traces user request or task chain
causation_id: UUID       # parent event_id or task_run_id
sequence_number: int     # monotonic per scan
created_at: datetime
processed_at: datetime   # set by controller
schema_version: string   # e.g. "1.0"
```

---

## 3. Event categories

### 3.1 Scan lifecycle

| Event Type | Payload Fields | Emitted By | Controller Actions |
|------------|----------------|------------|-------------------|
| `SCAN_CREATED` | `project_id`, `scope_snapshot_id`, `workflow_version` | ScanService | Initialize scan state; schedule initial discovery tasks per workflow |
| `SCAN_STARTED` | `started_at` | ScanService | Transition scan to RUNNING; emit initial DOMAIN_ACCEPTED per scope |
| `SCAN_PAUSED` | `reason`, `paused_by` | ScanService | Cancel READY tasks; defer RUNNING leases |
| `SCAN_RESUMED` | `resumed_by` | ScanService | Re-evaluate deferred tasks |
| `SCAN_COMPLETED` | `completed_at`, `reason` | Controller/ScanService | Finalize coverage; trigger change detection if baseline exists |

### 3.2 DNS and domain discovery

| Event Type | Payload Fields | Emitted By | Controller Actions |
|------------|----------------|------------|-------------------|
| `DOMAIN_ACCEPTED` | `domain`, `scope_rule_id` | ScopeManager/Controller | Create DOMAIN asset; schedule PASSIVE_DOMAIN_DISCOVERY |
| `HOSTNAME_DISCOVERED` | `hostname`, `source`, `confidence` | Parser | Create HOSTNAME asset; HAS_SUBDOMAIN relationship; schedule DNS_RESOLUTION |
| `DNS_RESOLVED` | `hostname`, `records[]` (type, value, ttl) | Parser | Create RESOLVES_TO relationships; create IP assets; schedule SERVICE_DISCOVERY |
| `DNS_UNRESOLVED` | `hostname`, `reason` | Parser | Record observation; may reduce confidence; evaluate stopping rules |
| `DNS_WILDCARD_SUSPECTED` | `hostname`, `evidence` | Parser | Flag asset metadata; schedule DNS_WILDCARD_CHECK; adjust eligibility |
| `IP_DISCOVERED` | `ip_address`, `source` | Parser | Create IP_ADDRESS asset; schedule SERVICE_DISCOVERY if in scope |

### 3.3 Service and TLS

| Event Type | Payload Fields | Emitted By | Controller Actions |
|------------|----------------|------------|-------------------|
| `SERVICE_OBSERVED` | `host`, `port`, `protocol`, `banner` | Parser | Create SERVICE asset; RUNS relationship; schedule SERVICE_IDENTIFICATION |
| `SERVICE_CHANGED` | `service_id`, `previous`, `current` | ChangeDetection/Parser | Emit ASSET_CHANGED; reevaluate hypotheses |
| `TLS_CERTIFICATE_OBSERVED` | `fingerprint`, `sans[]`, `issuer`, `not_after` | Parser | Create TLS_CERTIFICATE; PRESENTS_CERTIFICATE; SHARES_CERTIFICATE_WITH detection |
| `HTTP_SERVICE_CONFIRMED` | `url`, `status_code`, `scheme` | Parser | Create/link WEB_APPLICATION; schedule HTTP_CHARACTERIZATION |
| `HTTP_RESPONSE_OBSERVED` | `url`, `headers`, `body_hash`, `status` | Parser | Store observation; technology hints |

### 3.4 Web application surface

| Event Type | Payload Fields | Emitted By | Controller Actions |
|------------|----------------|------------|-------------------|
| `WEB_APPLICATION_CONFIRMED` | `base_url`, `title` | Parser | Confirm WEB_APPLICATION asset; schedule WEB_CRAWLING, JS_COLLECTION |
| `TECHNOLOGY_OBSERVED` | `technology`, `version`, `evidence_type` | Parser | Create TECHNOLOGY asset; USES_TECHNOLOGY relationship (**not** a CVE claim) |
| `URL_DISCOVERED` | `url`, `source` | Parser | Create ENDPOINT candidate or link |
| `ENDPOINT_DISCOVERED` | `url`, `method`, `source` | Parser | Create ENDPOINT asset; update crawl coverage |
| `PARAMETER_DISCOVERED` | `endpoint_id`, `name`, `location` | Parser | Create PARAMETER asset; CONTAINS relationship |
| `JAVASCRIPT_DISCOVERED` | `url`, `source_page` | Parser | Create JAVASCRIPT_RESOURCE; schedule STATIC_REFERENCE_EXTRACTION |
| `API_SPEC_DISCOVERED` | `spec_url`, `format` (openapi, etc.) | Parser | Create API asset; schedule API_OPERATION_INVENTORY |
| `API_OPERATION_DISCOVERED` | `api_id`, `method`, `path`, `parameters[]` | Parser | Create API_OPERATION assets |

### 3.5 Findings pipeline

| Event Type | Payload Fields | Emitted By | Controller Actions |
|------------|----------------|------------|-------------------|
| `SCANNER_FINDING_INGESTED` | `import_batch_id`, `count` | FindingImportService | Schedule FINDING_NORMALIZATION tasks |
| `FINDING_NORMALIZED` | `normalized_finding_id`, `asset_refs[]` | Parser/Normalizer | Create FindingInstance; schedule FINDING_CORRELATION |
| `FINDING_CORRELATED` | `correlation_id`, `correlation_type` | CorrelationEngine | Evaluate HYPOTHESIS_RULEs; may create hypotheses |

### 3.6 Hypothesis and validation

| Event Type | Payload Fields | Emitted By | Controller Actions |
|------------|----------------|------------|-------------------|
| `HYPOTHESIS_CREATED` | `hypothesis_id`, `hypothesis_type` | HypothesisEngine | Create ValidationTask if READY_FOR_VALIDATION |
| `HYPOTHESIS_UPDATED` | `hypothesis_id`, `changed_fields[]` | HypothesisEngine | Update validation backlog priority |
| `HYPOTHESIS_REJECTED` | `hypothesis_id`, `reason`, `evidence_ids[]` | HypothesisEngine/Analyst | Close related validation tasks |
| `HYPOTHESIS_VALIDATED` | `hypothesis_id`, `validation_result_id` | ValidationService | May create ConfirmedFinding |
| `VALIDATION_TASK_CREATED` | `validation_task_id`, `hypothesis_id` | ValidationBacklogManager | Notify analysts (no auto-execution) |
| `VALIDATION_RESULT_RECORDED` | `validation_task_id`, `outcome` | ValidationService | Update hypothesis status; audit |

### 3.7 Operational signals

| Event Type | Payload Fields | Emitted By | Controller Actions |
|------------|----------------|------------|-------------------|
| `RATE_LIMIT_OBSERVED` | `target`, `ratio`, `window` | Parser/Worker | Evaluate FAILURE_RULE; may set CAUTIOUS profile |
| `HIGH_TIMEOUT_RATIO` | `target`, `ratio` | Parser/Worker | Defer tasks; reduce concurrency |
| `UNSTABLE_RESPONSE_PATTERN` | `target`, `pattern` | Parser | Adjust operational profile |
| `TASK_COMPLETED` | `task_id`, `task_run_id` | Worker | Dependency unlock; metrics |
| `TASK_FAILED` | `task_id`, `error_class`, `retryable` | Worker | FAILURE_RULE evaluation |
| `STAGE_LOW_GAIN` | `stage`, `gain_ratio` | Controller | STOPPING_RULE evaluation |
| `STAGE_COMPLETED` | `stage`, `coverage_snapshot` | Controller | Workflow transition |

### 3.8 Asset and relationship changes

| Event Type | Payload Fields | Emitted By | Controller Actions |
|------------|----------------|------------|-------------------|
| `ASSET_ADDED` | `asset_id`, `asset_type` | Controller | Coverage reevaluation |
| `ASSET_CHANGED` | `asset_id`, `changed_fields[]` | Controller/ChangeDetection | CHANGE_ANALYSIS; COVERAGE_REEVALUATION |
| `ASSET_REMOVED` | `asset_id`, `reason` | ChangeDetection | Update graph; hypothesis reevaluation |
| `RELATIONSHIP_ADDED` | `relationship_id`, `type`, `source`, `target` | Controller | REEVALUATE_RELEVANT_HYPOTHESES |
| `RELATIONSHIP_CHANGED` | `relationship_id`, `previous`, `current` | Controller | Trust/exposure correlation rules |

---

## 4. Event → observation mapping

| Event Type | Observation Type(s) Created |
|------------|----------------------------|
| `HOSTNAME_DISCOVERED` | `HOSTNAME_OBSERVATION` |
| `DNS_RESOLVED` | `DNS_RECORD_OBSERVATION` |
| `SERVICE_OBSERVED` | `SERVICE_BANNER_OBSERVATION` |
| `TLS_CERTIFICATE_OBSERVED` | `CERTIFICATE_OBSERVATION` |
| `HTTP_RESPONSE_OBSERVED` | `HTTP_RESPONSE_OBSERVATION` |
| `TECHNOLOGY_OBSERVED` | `TECHNOLOGY_OBSERVATION` |
| `ENDPOINT_DISCOVERED` | `ENDPOINT_OBSERVATION` |
| `JAVASCRIPT_DISCOVERED` | `JAVASCRIPT_OBSERVATION` |
| `RATE_LIMIT_OBSERVED` | `OPERATIONAL_OBSERVATION` |

Lifecycle events (`SCAN_*`, `TASK_*`, `HYPOTHESIS_*`) generally do **not** create environment observations unless they carry environmental payload.

---

## 5. Event → task mapping (workflow defaults)

Declarative workflow YAML overrides these defaults. Version recorded per scan.

| Trigger Event | Capability Task(s) |
|---------------|-------------------|
| `DOMAIN_ACCEPTED` | `PASSIVE_DOMAIN_DISCOVERY` |
| `HOSTNAME_DISCOVERED` | `DNS_RESOLUTION` |
| `DNS_RESOLVED` | `SERVICE_DISCOVERY` |
| `DNS_WILDCARD_SUSPECTED` | `DNS_WILDCARD_CHECK` |
| `SERVICE_OBSERVED` | `SERVICE_IDENTIFICATION`, `TLS_CHARACTERIZATION` |
| `HTTP_SERVICE_CONFIRMED` | `HTTP_CHARACTERIZATION`, `TECHNOLOGY_DETECTION` |
| `WEB_APPLICATION_CONFIRMED` | `WEB_CRAWLING`, `JAVASCRIPT_COLLECTION` |
| `JAVASCRIPT_DISCOVERED` | `STATIC_REFERENCE_EXTRACTION` |
| `API_SPEC_DISCOVERED` | `API_OPERATION_INVENTORY` |
| `SCANNER_FINDING_INGESTED` | `VULNERABILITY_FINDING_IMPORT` (processing), `FINDING_NORMALIZATION` |
| `FINDING_NORMALIZED` | `FINDING_CORRELATION` |
| `RELATIONSHIP_ADDED` | Internal: `REEVALUATE_RELEVANT_HYPOTHESES` |
| `ASSET_CHANGED` | Internal: `CHANGE_ANALYSIS`, `COVERAGE_REEVALUATION` |

Internal processing stages are implemented as in-process controller handlers, not external tool tasks.

---

## 6. Event ordering and idempotency

### Per-scan ordering

Events receive monotonic `sequence_number` at persistence time. Controller processes in sequence order per scan partition.

### Idempotency keys

| Event Type | Dedup Key |
|------------|-----------|
| `HOSTNAME_DISCOVERED` | `scan_id + hostname + source` |
| `DNS_RESOLVED` | `scan_id + hostname + record_set_hash` |
| `ENDPOINT_DISCOVERED` | `scan_id + normalized_url + method` |
| `TECHNOLOGY_OBSERVED` | `scan_id + asset_id + technology + version` |
| `FINDING_NORMALIZED` | `scan_id + normalized_finding_id` |

Duplicate delivery: observation `last_seen` updated; no duplicate tasks if uniqueness key matches.

---

## 7. Event schema versioning

- Each event type has a Pydantic model in `vapt_platform.domain.events`
- `schema_version` in envelope enables backward-compatible migration
- Unknown fields in payload are rejected (strict mode)
- Event catalog changes require ADR when semantics change

---

## 8. Correlation ID propagation

```
API Request → correlation_id (generated)
  → ScanService → SCAN_CREATED event
    → Task → TaskRun → Parser events (same correlation_id)
      → Controller decisions → AuditEvents
```

All logs include: `correlation_id`, `scan_id`, `event_id`, `task_id` (when applicable).
