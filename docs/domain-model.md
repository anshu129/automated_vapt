# Domain Model

## 1. Design principles

The platform maintains **ten distinct conceptual categories**. These must never be collapsed into a single generic "finding" object.

| # | Concept | Definition |
|---|---------|------------|
| 1 | **Observation** | A source reported something about the environment |
| 2 | **Evidence** | An observation relevant to a specific claim |
| 3 | **Asset** | A persistent entity in the attack surface model |
| 4 | **Relationship** | A typed, evidence-backed link between assets |
| 5 | **Scanner finding** | A vulnerability claim from an external scanner (unconfirmed) |
| 6 | **Correlated hypothesis** | A testable security claim supported by correlated evidence |
| 7 | **Validation task** | Structured analyst work to confirm or reject a hypothesis |
| 8 | **Confirmed vulnerability** | A validated security issue with required evidence |
| 9 | **Risk scenario** | A contextual combination of exposure, trust, and impact |
| 10 | **Attack-surface coverage gap** | A measurable absence of assessment for an eligible asset |

### Data flow

```
Tool Output → RawArtifact → Parser → Observation → Asset/Relationship update
                                              ↓
Scanner Report → ScannerFinding → NormalizedFinding → FindingInstance
                                              ↓
                         Correlation Engine → FindingCorrelation
                                              ↓
                         Hypothesis Engine → Hypothesis (+ HypothesisEvidence)
                                              ↓
                         Validation Backlog → ValidationTask → ValidationResult
                                              ↓
                                    ConfirmedFinding
```

---

## 2. Common entity attributes

All persistent entities include:

| Field | Type | Notes |
|-------|------|-------|
| `id` | UUID | Primary key |
| `created_at` | timestamp (UTC) | Immutable |
| `updated_at` | timestamp (UTC) | Updated on mutation |
| `project_id` | UUID | FK where applicable |
| `scan_id` | UUID | FK where scan-scoped |
| `provenance` | JSONB | Source chain: tool, task_run, parser version, etc. |
| `status` | enum | Entity-specific lifecycle state |
| `version` | int | Optimistic concurrency where applicable |

Additional fields per entity below.

---

## 3. Project and scan

### Project

Represents an authorized assessment engagement.

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Human-readable name |
| `description` | string | Optional |
| `owner` | string | Responsible party |
| `settings` | JSONB | Project-level defaults |

### Scan

A single assessment run within a project.

| Field | Type | Description |
|-------|------|-------------|
| `project_id` | UUID | Parent project |
| `name` | string | Scan label |
| `status` | ScanStatus | See state-machines.md |
| `workflow_version` | string | Workflow definition version used |
| `rule_set_version` | string | Rule pack version used |
| `operational_profile` | string | DEFAULT, CAUTIOUS, etc. |
| `scope_snapshot_id` | UUID | Immutable scope at scan start |
| `started_at` | timestamp | |
| `completed_at` | timestamp | |
| `previous_scan_id` | UUID | For change detection (optional) |

### Scope / ScopeRule

Scope is a versioned collection of rules evaluated by Scope Manager.

| ScopeRule field | Type | Description |
|-----------------|------|-------------|
| `rule_type` | enum | ROOT_DOMAIN, SUBDOMAIN_PATTERN, HOSTNAME, CIDR, IP, URL_PREFIX, EXCLUSION, PORT_RESTRICTION |
| `pattern` | string | Match pattern |
| `assessment_mode` | enum | PASSIVE_ONLY, ACTIVE, CREDENTIALED |
| `priority` | int | Higher wins on conflict |
| `enabled` | bool | |

Scope decisions are stored as `AuditEvent` records with target, capability, decision, and rule IDs.

---

## 4. Asset model

### Asset

| Field | Type | Description |
|-------|------|-------------|
| `asset_type` | AssetType | See below |
| `normalized_key` | string | Deterministic identity key |
| `display_name` | string | Human-readable |
| `confidence` | float | 0.0–1.0 |
| `first_seen` | timestamp | |
| `last_seen` | timestamp | |
| `metadata` | JSONB | Type-specific attributes |
| `identity_status` | enum | MERGED, RELATED, POSSIBLY_SAME, DISTINCT, UNRESOLVED |
| `criticality` | enum | LOW, MEDIUM, HIGH, CRITICAL (analyst-assigned or default) |

### AssetType

```
ORGANIZATION
DOMAIN
HOSTNAME
IP_ADDRESS
NETWORK_RANGE
CLOUD_RESOURCE
SERVICE
TLS_CERTIFICATE
WEB_APPLICATION
API
API_OPERATION
ENDPOINT
PARAMETER
JAVASCRIPT_RESOURCE
TECHNOLOGY
IDENTITY_PROVIDER
AUTHENTICATION_SURFACE
REPOSITORY_REFERENCE
EMAIL_DOMAIN
EXTERNAL_DEPENDENCY
```

### AssetIdentifier

Multiple identifiers may reference one asset. Identity resolution uses these without destructive merge.

| Field | Type | Description |
|-------|------|-------------|
| `asset_id` | UUID | |
| `identifier_type` | enum | HOSTNAME, IP, FINGERPRINT, SAN, URL, CLOUD_ARN, etc. |
| `identifier_value` | string | Normalized |
| `source_observation_id` | UUID | |
| `confidence` | float | |

### AssetIdentityResolution

Records reasoning when linking asset candidates.

| Field | Type | Description |
|-------|------|-------------|
| `candidate_a_id` | UUID | |
| `candidate_b_id` | UUID | |
| `resolution` | enum | MERGED, RELATED, POSSIBLY_SAME, DISTINCT, UNRESOLVED |
| `evidence_ids` | UUID[] | |
| `reasoning` | text | Deterministic explanation |
| `rule_ids` | string[] | |

---

## 5. Observation and evidence

### Observation

Raw-normalized fact from a source. **Not** a vulnerability.

| Field | Type | Description |
|-------|------|-------------|
| `observation_type` | enum | TECHNOLOGY_OBSERVED, DNS_RECORD, HTTP_HEADER, SERVICE_BANNER, etc. |
| `source_type` | enum | TOOL, PARSER, IMPORT, MANUAL, CORRELATION |
| `source_id` | string | task_run_id, import_id, etc. |
| `subject_asset_id` | UUID | Primary asset |
| `object_asset_id` | UUID | Secondary asset (optional) |
| `payload` | JSONB | Structured observation data |
| `confidence` | float | |
| `first_seen` | timestamp | |
| `last_seen` | timestamp | |
| `raw_artifact_id` | UUID | Link to immutable raw data |
| `contradicts_observation_id` | UUID | Optional conflict link |

### Evidence

An observation elevated to support a specific claim.

| Field | Type | Description |
|-------|------|-------------|
| `observation_id` | UUID | |
| `claim_type` | enum | HYPOTHESIS, FINDING, RELATIONSHIP, COVERAGE |
| `claim_id` | UUID | Target entity |
| `relevance` | enum | SUPPORTS, CONTRADICTS, CONTEXTUAL |
| `weight` | float | Contribution to confidence |

---

## 6. Relationship

Typed, evidence-backed edge in the attack surface graph.

| Field | Type | Description |
|-------|------|-------------|
| `source_asset_id` | UUID | |
| `target_asset_id` | UUID | |
| `relationship_type` | RelationshipType | See below |
| `confidence` | float | |
| `first_seen` | timestamp | |
| `last_seen` | timestamp | |
| `evidence_ids` | UUID[] | |
| `scan_id` | UUID | |
| `superseded_by_id` | UUID | Non-destructive versioning |
| `active` | bool | False when superseded but retained |

### RelationshipType

```
OWNS
HAS_SUBDOMAIN
RESOLVES_TO
REVERSE_RESOLVES_TO
EXPOSES
RUNS
HOSTS
CONTAINS
LOADS
REFERENCES
CALLS
REDIRECTS_TO
PRESENTS_CERTIFICATE
SHARES_CERTIFICATE_WITH
SHARES_IP_WITH
SHARES_INFRASTRUCTURE_WITH
USES_TECHNOLOGY
AUTHENTICATES_WITH
TRUSTS
DEPENDS_ON
OBSERVED_FROM
AFFECTED_BY
EVIDENCE_FOR
SUPPORTS_HYPOTHESIS
CONTRADICTS_HYPOTHESIS
```

**Invariant:** Conflicting relationships are stored as competing records, not overwritten.

---

## 7. Event

Append-only domain event driving the controller.

| Field | Type | Description |
|-------|------|-------------|
| `event_type` | EventType | See event-catalog.md |
| `payload` | JSONB | Event-specific data |
| `correlation_id` | UUID | Traces request/task chain |
| `causation_id` | UUID | Parent event or task_run |
| `sequence_number` | bigint | Per-scan ordering |
| `processed_at` | timestamp | Controller processing time |

---

## 8. Task model

### Task

| Field | Type | Description |
|-------|------|-------------|
| `capability` | Capability | See architecture.md tool registry |
| `target_descriptor` | JSONB | Normalized target |
| `normalized_target` | string | Dedup key component |
| `configuration_hash` | string | Dedup key component |
| `uniqueness_key` | string | Computed unique key |
| `priority` | int | |
| `status` | TaskStatus | See state-machines.md |
| `operational_profile` | string | |
| `parameters` | JSONB | Capability parameters |
| `retry_count` | int | |
| `max_retries` | int | |
| `scheduled_at` | timestamp | |
| `defer_until` | timestamp | |
| `claimed_by` | string | Worker ID |
| `lease_expires_at` | timestamp | |
| `scope_decision_id` | UUID | Audit reference |

### TaskDependency

| Field | Type | Description |
|-------|------|-------------|
| `task_id` | UUID | Dependent task |
| `depends_on_task_id` | UUID | Prerequisite |
| `dependency_type` | enum | HARD, SOFT |

### TaskRun

Execution record for a single task attempt.

| Field | Type | Description |
|-------|------|-------------|
| `task_id` | UUID | |
| `attempt_number` | int | |
| `worker_id` | string | |
| `started_at` | timestamp | |
| `completed_at` | timestamp | |
| `exit_code` | int | |
| `raw_artifact_ids` | UUID[] | |
| `metrics` | JSONB | Duration, bytes, etc. |
| `error_summary` | string | Redacted |
| `scope_revalidated` | bool | Must be true for execution |

---

## 9. Tool registry

### ToolManifest

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | |
| `version` | string | |
| `capabilities` | Capability[] | |
| `accepted_input_types` | string[] | |
| `produced_output_types` | string[] | |
| `supported_parameters` | JSONB | Schema |
| `timeouts` | JSONB | |
| `retry_safe` | bool | |
| `output_format` | enum | JSON, TEXT, XML |
| `container_image` | string | |
| `parser_version` | string | |
| `exit_code_semantics` | JSONB | |

### RawArtifact

Immutable tool output.

| Field | Type | Description |
|-------|------|-------------|
| `task_run_id` | UUID | |
| `artifact_type` | enum | STDOUT, STDERR, JSON, REPORT |
| `content_hash` | string | SHA-256 |
| `storage_path` | string | |
| `size_bytes` | int | |
| `metadata` | JSONB | Redacted command info |

---

## 10. Findings model

### ScannerFinding

As-imported from external tool.

| Field | Type | Description |
|-------|------|-------------|
| `source_tool` | string | |
| `source_finding_id` | string | External ID |
| `raw_artifact_id` | UUID | |
| `import_batch_id` | UUID | |

### NormalizedFinding

Canonical finding representation.

| Field | Type | Description |
|-------|------|-------------|
| `source_tool` | string | |
| `source_finding_id` | string | |
| `title` | string | |
| `description` | text | |
| `asset_reference` | JSONB | Resolved asset link |
| `service_reference` | JSONB | |
| `application_reference` | JSONB | |
| `endpoint_reference` | JSONB | |
| `parameter_reference` | JSONB | |
| `cve_ids` | string[] | |
| `cwe_ids` | string[] | |
| `source_severity` | enum | CRITICAL, HIGH, MEDIUM, LOW, INFO |
| `source_confidence` | float | |
| `evidence_refs` | UUID[] | |
| `first_seen` | timestamp | |
| `last_seen` | timestamp | |
| `status` | enum | OPEN, RESOLVED, REOPENED, SUPPRESSED |
| `raw_artifact_id` | UUID | |

### FindingInstance

Links a normalized finding to a specific asset context within a scan.

| Field | Type | Description |
|-------|------|-------------|
| `normalized_finding_id` | UUID | |
| `asset_id` | UUID | |
| `scan_id` | UUID | |
| `instance_key` | string | Deterministic per asset+finding |

### FindingCorrelation

| Field | Type | Description |
|-------|------|-------------|
| `correlation_type` | enum | DUPLICATE, SHARED_ROOT_CAUSE, SHARED_ASSET, DEPENDENCY, TRUST, EXPOSURE, CHANGE, COVERAGE |
| `entity_type_a` | string | |
| `entity_id_a` | UUID | |
| `entity_type_b` | string | |
| `entity_id_b` | UUID | |
| `participating_entity_ids` | UUID[] | For N-way correlations |
| `evidence_ids` | UUID[] | |
| `rule_ids` | string[] | |
| `confidence` | float | |
| `explanation` | text | Human-readable, deterministic |
| `recommended_validation_action` | text | |

**Dedup rule:** Same CVE on different assets = separate instances, possibly SHARED_ASSET correlated.

---

## 11. Hypothesis model

### Hypothesis

A testable security claim. **Not** a confirmed vulnerability.

| Field | Type | Description |
|-------|------|-------------|
| `title` | string | |
| `description` | text | |
| `hypothesis_type` | enum | See examples in spec |
| `affected_asset_ids` | UUID[] | |
| `supporting_evidence_ids` | UUID[] | |
| `contradicting_evidence_ids` | UUID[] | |
| `correlation_rule_ids` | string[] | |
| `confidence` | float | |
| `impact_if_confirmed` | text | High-level impact description |
| `validation_requirements` | JSONB | Required evidence to confirm/reject |
| `status` | HypothesisStatus | See state-machines.md |

### HypothesisEvidence

Junction with relevance weight.

| Field | Type | Description |
|-------|------|-------------|
| `hypothesis_id` | UUID | |
| `evidence_id` | UUID | |
| `relevance` | enum | SUPPORTS, CONTRADICTS |

---

## 12. Validation model

### ValidationTask

| Field | Type | Description |
|-------|------|-------------|
| `hypothesis_id` | UUID | |
| `asset_ids` | UUID[] | |
| `priority` | int | Contextual priority |
| `validation_goal` | text | What to determine |
| `required_evidence` | JSONB | Evidence needed |
| `suggested_safe_checks` | text[] | Non-exploitative guidance |
| `assigned_to` | string | Analyst |
| `status` | ValidationTaskStatus | |
| `source_correlation_id` | UUID | Optional |

### ValidationResult

| Field | Type | Description |
|-------|------|-------------|
| `validation_task_id` | UUID | |
| `outcome` | enum | CONFIRMED, REJECTED, INCONCLUSIVE |
| `analyst_notes` | text | |
| `evidence_ids` | UUID[] | Analyst-provided evidence |
| `recorded_by` | string | |
| `recorded_at` | timestamp | |

### ConfirmedFinding

| Field | Type | Description |
|-------|------|-------------|
| `hypothesis_id` | UUID | Optional lineage |
| `validation_result_id` | UUID | **Required** |
| `normalized_finding_id` | UUID | Optional scanner lineage |
| `title` | string | |
| `description` | text | |
| `affected_asset_ids` | UUID[] | |
| `cve_ids` | string[] | |
| `cwe_ids` | string[] | |
| `source_severity` | enum | From scanner if applicable |
| `contextual_priority` | enum | From risk engine |
| `evidence_ids` | UUID[] | **Required** |
| `confirmed_by` | string | |
| `confirmed_at` | timestamp | |

**Invariant:** ConfirmedFinding cannot exist without ValidationResult with outcome CONFIRMED.

---

## 13. Coverage, change, and risk

### CoverageRecord

| Field | Type | Description |
|-------|------|-------------|
| `coverage_type` | enum | DISCOVERY, DNS_VALIDATION, SERVICE_DISCOVERY, HTTP_CHARACTERIZATION, CRAWL, JS_ANALYSIS, API_INVENTORY, VULN_ASSESSMENT, AUTHN, AUTHZ, CONFIG, MANUAL_VALIDATION |
| `asset_type` | AssetType | Segment |
| `eligible_count` | int | |
| `completed_count` | int | |
| `coverage_ratio` | float | |
| `gap_asset_ids` | UUID[] | Assets lacking coverage |
| `computed_at` | timestamp | |

### ChangeEvent

| Field | Type | Description |
|-------|------|-------------|
| `change_type` | enum | ASSET_ADDED, ASSET_REMOVED, DNS_CHANGED, SERVICE_CHANGED, etc. |
| `entity_type` | string | |
| `entity_id` | UUID | |
| `previous_snapshot` | JSONB | |
| `current_snapshot` | JSONB | |
| `baseline_scan_id` | UUID | |
| `impact_summary` | text | |
| `triggered_hypothesis_ids` | UUID[] | |

### RiskScenario

| Field | Type | Description |
|-------|------|-------------|
| `title` | string | |
| `description` | text | |
| `participating_asset_ids` | UUID[] | |
| `participating_finding_ids` | UUID[] | |
| `exposure_context` | JSONB | |
| `trust_context` | JSONB | |
| `contextual_priority` | enum | |
| `source_severities` | JSONB | Preserved separately |
| `evidence_ids` | UUID[] | |

### MetricSnapshot

| Field | Type | Description |
|-------|------|-------------|
| `metric_name` | string | |
| `metric_value` | float | |
| `dimensions` | JSONB | scan_id, capability, etc. |
| `recorded_at` | timestamp | |

---

## 14. AI enrichment and audit

### AIEnrichment

| Field | Type | Description |
|-------|------|-------------|
| `enrichment_type` | enum | SUMMARY, EXPLANATION, CLUSTER_SUGGESTION, etc. |
| `target_entity_type` | string | |
| `target_entity_id` | UUID | |
| `prompt_template_version` | string | |
| `model_config` | JSONB | Model name, temperature, etc. |
| `input_artifact_hash` | string | Cache key component |
| `output` | JSONB | Validated against Pydantic schema |
| `validation_status` | enum | VALID, INVALID, FALLBACK |
| `cached` | bool | |

### AuditEvent

| Field | Type | Description |
|-------|------|-------------|
| `event_type` | enum | SCOPE_DECISION, TASK_CREATED, TASK_EXECUTED, VALIDATION_RECORDED, etc. |
| `actor` | string | User, worker, system |
| `resource_type` | string | |
| `resource_id` | UUID | |
| `details` | JSONB | Redacted |
| `correlation_id` | UUID | |

---

## 15. Entity relationship diagram (logical)

```
Project 1──* Scan 1──* ScopeRule (snapshot)
                │
                ├──* Event
                ├──* Task ──* TaskRun ──* RawArtifact
                │      └──* TaskDependency
                ├──* Asset ──* AssetIdentifier
                │      └──* Relationship (source/target)
                ├──* Observation ──* Evidence
                ├──* ScannerFinding → NormalizedFinding ──* FindingInstance
                ├──* FindingCorrelation
                ├──* Hypothesis ──* HypothesisEvidence
                │      └──* ValidationTask ──* ValidationResult
                │                              └── ConfirmedFinding
                ├──* CoverageRecord
                ├──* ChangeEvent
                ├──* RiskScenario
                ├──* MetricSnapshot
                ├──* AIEnrichment
                └──* AuditEvent
```

---

## 16. Graph projection interface

Domain logic interacts with relationships via `GraphRepository` protocol:

```python
class GraphRepository(Protocol):
    def add_relationship(self, rel: Relationship) -> Relationship: ...
    def get_neighbors(self, asset_id: UUID, rel_types: list[RelationshipType] | None) -> list[Relationship]: ...
    def find_path(self, source: UUID, target: UUID, max_depth: int) -> list[Relationship]: ...
    def get_shared_infrastructure(self, asset_id: UUID) -> list[Asset]: ...
    def project_subgraph(self, scan_id: UUID, root_asset_id: UUID, depth: int) -> Subgraph: ...
```

PostgreSQL implementation in Phase 1; Neo4j adapter possible later without domain changes.
