# Database Migration Plan — Extension

## 1. Overview

Migrations are ordered to support incremental delivery. Phase 1 core tables remain as planned; extension tables added in migration groups A–I aligned with implementation phases.

**Convention:** UUID PKs, `timestamptz`, `project_id`/`scan_id` FKs, JSONB for flexible metadata, provenance fields.

---

## 2. Migration 001 — Core (Phase 1, unchanged)

Tables: `projects`, `scans`, `scope_rules`, `scope_snapshots`, `assets`, `asset_identifiers`, `observations`, `evidence`, `relationships`, `events`, `tasks`, `task_dependencies`, `task_runs`, `tool_manifests`, `raw_artifacts`, `audit_events`, `metric_snapshots`

Indexes per phase-1-implementation-plan.md.

---

## 3. Migration 002 — Capability abstraction (Phase A)

```sql
-- capabilities (reference/enum table)
CREATE TABLE capabilities (
    code VARCHAR(128) PRIMARY KEY,
    capability_group VARCHAR(64) NOT NULL,
    description TEXT,
    default_safety_class VARCHAR(32) NOT NULL,
    active BOOLEAN DEFAULT true
);

-- capability_providers
CREATE TABLE capability_providers (
    id UUID PRIMARY KEY,
    capability_code VARCHAR(128) REFERENCES capabilities(code),
    provider_name VARCHAR(128) NOT NULL,
    manifest_id UUID REFERENCES tool_manifests(id),
    enabled BOOLEAN DEFAULT true,
    cost_tier VARCHAR(32) NOT NULL,
    requires_api_key BOOLEAN DEFAULT false,
    api_key_secret_ref VARCHAR(256),
    priority_weight INT DEFAULT 0,
    max_concurrent INT DEFAULT 5,
    supported_profiles JSONB DEFAULT '[]',
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    UNIQUE(capability_code, provider_name)
);

-- capability_execution_profiles
CREATE TABLE capability_execution_profiles (
    id VARCHAR(64) PRIMARY KEY,
    version VARCHAR(32) NOT NULL,
    description TEXT,
    timeout_multiplier FLOAT DEFAULT 1.0,
    concurrency_multiplier FLOAT DEFAULT 1.0,
    retry_policy JSONB,
    policy_flags JSONB,
    active BOOLEAN DEFAULT true
);

-- evidence_quality_decisions
CREATE TABLE evidence_quality_decisions (
    id UUID PRIMARY KEY,
    scan_id UUID NOT NULL REFERENCES scans(id),
    task_run_id UUID NOT NULL REFERENCES task_runs(id),
    status VARCHAR(32) NOT NULL,
    confidence FLOAT,
    reason_codes JSONB,
    explanation TEXT,
    recommended_next_capability VARCHAR(128),
    recommended_provider_id UUID REFERENCES capability_providers(id),
    eligible_alternate_profiles JSONB,
    retry_allowed BOOLEAN,
    manual_review_required BOOLEAN,
    rule_ids JSONB,
    evaluated_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX idx_eqd_scan ON evidence_quality_decisions(scan_id);
CREATE INDEX idx_eqd_task_run ON evidence_quality_decisions(task_run_id);

-- discovery_gain_metrics
CREATE TABLE discovery_gain_metrics (
    id UUID PRIMARY KEY,
    scan_id UUID NOT NULL REFERENCES scans(id),
    capability_code VARCHAR(128) NOT NULL,
    provider_id UUID REFERENCES capability_providers(id),
    raw_observation_count INT DEFAULT 0,
    unique_asset_count INT DEFAULT 0,
    unique_endpoint_count INT DEFAULT 0,
    unique_relationship_count INT DEFAULT 0,
    duplicate_ratio FLOAT,
    execution_duration_ms BIGINT,
    error_ratio FLOAT,
    rate_limit_ratio FLOAT,
    historical_unique_gain INT DEFAULT 0,
    confidence_contribution FLOAT,
    computed_at TIMESTAMPTZ NOT NULL,
    UNIQUE(scan_id, capability_code, provider_id)
);

-- Extend tasks
ALTER TABLE tasks ADD COLUMN capability_provider_id UUID REFERENCES capability_providers(id);
ALTER TABLE tasks ADD COLUMN execution_profile_id VARCHAR(64) REFERENCES capability_execution_profiles(id);
ALTER TABLE tasks ADD COLUMN evidence_quality_decision_id UUID REFERENCES evidence_quality_decisions(id);

-- Extend tool_manifests
ALTER TABLE tool_manifests ADD COLUMN capability_group VARCHAR(64);
ALTER TABLE tool_manifests ADD COLUMN safety_class VARCHAR(32);
ALTER TABLE tool_manifests ADD COLUMN cost_tier VARCHAR(32);
ALTER TABLE tool_manifests ADD COLUMN negative_evidence_support BOOLEAN DEFAULT false;
ALTER TABLE tool_manifests ADD COLUMN historical_only BOOLEAN DEFAULT false;
```

---

## 4. Migration 003 — Surface completeness (Phase C)

```sql
CREATE TABLE surface_coverage_records (
    id UUID PRIMARY KEY,
    scan_id UUID NOT NULL REFERENCES scans(id),
    asset_id UUID NOT NULL REFERENCES assets(id),
    asset_type VARCHAR(64) NOT NULL,
    dimensions JSONB NOT NULL,
    overall_status VARCHAR(32) NOT NULL,
    gap_count INT DEFAULT 0,
    rule_version VARCHAR(32),
    computed_at TIMESTAMPTZ NOT NULL,
    UNIQUE(scan_id, asset_id)
);
CREATE INDEX idx_scr_scan ON surface_coverage_records(scan_id);
CREATE INDEX idx_scr_asset ON surface_coverage_records(asset_id);
```

---

## 5. Migration 004 — Vulnerability knowledge (Phase D)

```sql
CREATE TABLE vulnerability_classes (
    id UUID PRIMARY KEY,
    class_code VARCHAR(128) UNIQUE NOT NULL,
    name VARCHAR(256) NOT NULL,
    description TEXT,
    parent_class_id UUID REFERENCES vulnerability_classes(id),
    related_cwe_ids JSONB,
    typical_evidence_types JSONB,
    default_testing_mode VARCHAR(32),
    taxonomy_version VARCHAR(32) NOT NULL,
    active BOOLEAN DEFAULT true
);

CREATE TABLE applicability_rules (
    id UUID PRIMARY KEY,
    rule_id VARCHAR(128) NOT NULL,
    version VARCHAR(32) NOT NULL,
    condition JSONB NOT NULL,
    output_classes JSONB NOT NULL,
    active BOOLEAN DEFAULT true,
    UNIQUE(rule_id, version)
);

CREATE TABLE asset_vulnerability_applicability (
    id UUID PRIMARY KEY,
    scan_id UUID NOT NULL REFERENCES scans(id),
    asset_id UUID NOT NULL REFERENCES assets(id),
    vulnerability_class_id UUID NOT NULL REFERENCES vulnerability_classes(id),
    applicability_state VARCHAR(32) NOT NULL,
    confidence FLOAT,
    supporting_evidence_ids JSONB,
    rule_ids JSONB,
    explanation TEXT,
    computed_at TIMESTAMPTZ NOT NULL,
    UNIQUE(scan_id, asset_id, vulnerability_class_id)
);
CREATE INDEX idx_ava_scan_asset ON asset_vulnerability_applicability(scan_id, asset_id);
```

---

## 6. Migration 005 — Test matrix and plans (Phase E–F)

```sql
CREATE TABLE asset_test_matrices (
    id UUID PRIMARY KEY,
    scan_id UUID NOT NULL REFERENCES scans(id),
    asset_id UUID NOT NULL REFERENCES assets(id),
    computed_at TIMESTAMPTZ NOT NULL,
    rule_version VARCHAR(32),
    UNIQUE(scan_id, asset_id)
);

CREATE TABLE test_requirements (
    id UUID PRIMARY KEY,
    matrix_id UUID NOT NULL REFERENCES asset_test_matrices(id),
    vulnerability_class_id UUID NOT NULL REFERENCES vulnerability_classes(id),
    applicability_state VARCHAR(32),
    testing_mode VARCHAR(32),
    coverage_status VARCHAR(32) NOT NULL,
    required_evidence JSONB,
    eligible_capabilities JSONB,
    latest_result_id UUID,
    confidence FLOAT,
    next_action VARCHAR(64),
    updated_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX idx_tr_matrix ON test_requirements(matrix_id);

CREATE TABLE test_plans (
    id UUID PRIMARY KEY,
    scan_id UUID NOT NULL REFERENCES scans(id),
    hypothesis_id UUID,
    asset_ids JSONB NOT NULL,
    vulnerability_class_ids JSONB,
    testing_mode VARCHAR(32) NOT NULL,
    required_capabilities JSONB,
    eligible_adapters JSONB,
    required_context JSONB,
    credential_context_reference UUID,
    evidence_requirements JSONB,
    completion_conditions JSONB,
    safety_class VARCHAR(32),
    authorization_requirement VARCHAR(32),
    priority INT,
    status VARCHAR(32) NOT NULL,
    reasoning_trace JSONB,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE test_executions (
    id UUID PRIMARY KEY,
    test_plan_id UUID NOT NULL REFERENCES test_plans(id),
    task_run_id UUID REFERENCES task_runs(id),
    provider_id UUID REFERENCES capability_providers(id),
    template_id VARCHAR(256),
    template_version VARCHAR(64),
    status VARCHAR(32) NOT NULL,
    result_summary JSONB,
    evidence_ids JSONB,
    executed_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE evidence_packages (
    id UUID PRIMARY KEY,
    scan_id UUID NOT NULL REFERENCES scans(id),
    hypothesis_id UUID,
    validation_task_id UUID,
    package_data JSONB NOT NULL,  -- no secrets
    created_at TIMESTAMPTZ NOT NULL
);
```

---

## 7. Migration 006 — Evidence graph and verdicts (Phase G)

```sql
CREATE TABLE evidence_links (
    id UUID PRIMARY KEY,
    scan_id UUID NOT NULL REFERENCES scans(id),
    source_type VARCHAR(64) NOT NULL,
    source_id UUID NOT NULL,
    target_type VARCHAR(64) NOT NULL,
    target_id UUID NOT NULL,
    link_type VARCHAR(32) NOT NULL,
    weight FLOAT,
    provenance JSONB,
    created_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX idx_el_scan_target ON evidence_links(scan_id, target_type, target_id);
CREATE INDEX idx_el_scan_source ON evidence_links(scan_id, source_type, source_id);

CREATE TABLE verdicts (
    id UUID PRIMARY KEY,
    scan_id UUID NOT NULL REFERENCES scans(id),
    hypothesis_id UUID NOT NULL,
    test_plan_id UUID REFERENCES test_plans(id),
    validation_result_id UUID,
    status VARCHAR(32) NOT NULL,
    confidence FLOAT,
    supporting_evidence_ids JSONB,
    contradicting_evidence_ids JSONB,
    rule_ids JSONB,
    explanation TEXT,
    issued_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX idx_verdict_hypothesis ON verdicts(hypothesis_id);
```

---

## 8. Migration 007 — Credentials (Phase I)

```sql
CREATE TABLE credential_references (
    id UUID PRIMARY KEY,
    project_id UUID NOT NULL REFERENCES projects(id),
    credential_type VARCHAR(64) NOT NULL,
    label VARCHAR(256),
    secret_backend_reference VARCHAR(512) NOT NULL,
    role_name VARCHAR(128),
    expiry TIMESTAMPTZ,
    allowed_capabilities JSONB,
    status VARCHAR(32) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE credential_scope_bindings (
    id UUID PRIMARY KEY,
    credential_id UUID NOT NULL REFERENCES credential_references(id),
    scope_rule_id UUID REFERENCES scope_rules(id),
    asset_id UUID REFERENCES assets(id),
    application_id UUID REFERENCES assets(id),
    url_prefix VARCHAR(2048),
    assessment_mode VARCHAR(32) NOT NULL
);

CREATE TABLE authentication_contexts (
    id UUID PRIMARY KEY,
    scan_id UUID NOT NULL REFERENCES scans(id),
    credential_id UUID NOT NULL REFERENCES credential_references(id),
    asset_id UUID NOT NULL REFERENCES assets(id),
    auth_method VARCHAR(64),
    session_established BOOLEAN,
    session_expires_at TIMESTAMPTZ,
    last_validated_at TIMESTAMPTZ,
    coverage_dimensions JSONB
);

CREATE TABLE role_contexts (
    id UUID PRIMARY KEY,
    authentication_context_id UUID NOT NULL REFERENCES authentication_contexts(id),
    role_name VARCHAR(128) NOT NULL,
    authorized BOOLEAN NOT NULL,
    coverage_status JSONB
);
```

---

## 9. Migration 008 — Assessment completion (Phase H)

```sql
CREATE TABLE assessment_completion_records (
    id UUID PRIMARY KEY,
    scan_id UUID NOT NULL REFERENCES scans(id),
    status VARCHAR(32) NOT NULL,
    completion_reasons JSONB,
    blocking_items JSONB,
    accepted_gaps JSONB,
    metrics JSONB,
    evaluated_at TIMESTAMPTZ NOT NULL,
    evaluated_by VARCHAR(256),
    UNIQUE(scan_id)
);
```

---

## 10. Migration 009 — Extend existing tables (Phase 5–8 alignment)

```sql
-- findings/hypotheses (when those tables exist from Phase 5–7)
-- ALTER finding_correlations: extend correlation_type check constraint
-- ALTER hypotheses ADD COLUMN verdict_id UUID REFERENCES verdicts(id);
-- ALTER hypotheses ADD COLUMN test_plan_id UUID REFERENCES test_plans(id);
-- ALTER validation_tasks ADD COLUMN test_plan_id UUID REFERENCES test_plans(id);
-- ALTER validation_tasks ADD COLUMN evidence_package_id UUID REFERENCES evidence_packages(id);
-- ALTER validation_tasks ADD COLUMN testing_mode VARCHAR(32);

-- observations: support HISTORICAL_OBSERVATION type (enum extension, no DDL if using VARCHAR)

-- scans: add rule/applicability versions
ALTER TABLE scans ADD COLUMN applicability_rule_version VARCHAR(32);
ALTER TABLE scans ADD COLUMN safety_policy_version VARCHAR(32);
```

---

## 11. Seed data migrations

| Migration | Content |
|-----------|---------|
| 002a | Seed `capabilities` from capability-registry.md |
| 002b | Seed `capability_execution_profiles` (STANDARD, CAUTIOUS, etc.) |
| 004a | Seed `vulnerability_classes` taxonomy |
| 004b | Seed initial `applicability_rules` v1.0 |

---

## 12. Rollback strategy

Each migration has `downgrade()` dropping tables in reverse FK order. Derived data tables (applicability, surface coverage, matrices) may be truncated and recomputed without data loss.

---

## 13. References

- `domain-model.md` (to be extended)
- `extension-gap-analysis.md`
- `phase-a-implementation-plan.md`
