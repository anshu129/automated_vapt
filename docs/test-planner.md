# Test Planner

## 1. Purpose

Convert hypotheses, applicability states, and coverage gaps into structured **TestPlans** with explicit testing mode (automated, assisted, manual), required capabilities, evidence requirements, and safety classification.

---

## 2. TestPlanner

### Interface

```python
class TestPlanner(Protocol):
    def plan(
        self,
        hypothesis: Hypothesis | None,
        asset_context: AssetContext,
        surface_context: SurfaceCoverageRecord,
        coverage_state: TestCoverageState,
        available_capabilities: list[Capability],
        credential_context: list[AuthenticationContext],
        authorization_policy: EngagementPolicy,
    ) -> TestPlan: ...
```

---

## 3. TestPlan

| Field | Type | Description |
|-------|------|-------------|
| `id` | UUID | |
| `scan_id` | UUID | |
| `hypothesis_id` | UUID | Optional |
| `asset_ids` | UUID[] | |
| `vulnerability_class_ids` | UUID[] | |
| `testing_mode` | TestingMode | AUTOMATED, ASSISTED, MANUAL |
| `required_capabilities` | Capability[] | |
| `eligible_adapters` | UUID[] | Provider IDs |
| `required_context` | JSONB | Auth role, surface refs |
| `credential_context_reference` | UUID | No secret values |
| `evidence_requirements` | JSONB | Required to close plan |
| `completion_conditions` | JSONB | |
| `safety_class` | SafetyClass | Max safety level |
| `authorization_requirement` | enum | PRE_APPROVED, ANALYST_APPROVAL_REQUIRED |
| `priority` | int | Contextual priority |
| `status` | TestPlanStatus | See state-machines-extensions.md |
| `reasoning_trace` | JSONB | rule_ids, facts |
| `created_at` | timestamp | |

---

## 4. Decision model

```
HYPOTHESIS or TEST_REQUIREMENT
        ↓
IS SAFE AUTOMATED VALIDATION AVAILABLE?
(TestSafetyPolicyEngine + eligible capability)
        ├── YES → AUTOMATED TEST PLAN
        └── NO
                ↓
        CAN TOOLS PREPARE EVIDENCE?
        (passive scans, inventory, traffic capture metadata)
                ├── YES → ASSISTED VALIDATION (EvidencePackage)
                └── NO → MANUAL VALIDATION (ValidationTask)
```

---

## 5. Testing modes

| Mode | Execution | Output |
|------|-----------|--------|
| `AUTOMATED` | Approved adapter via AutomatedValidationOrchestrator | TestExecution + observations |
| `ASSISTED` | Tools gather evidence; analyst decides | EvidencePackage + ValidationTask |
| `MANUAL` | Analyst only | ValidationTask + ValidationResult |

---

## 6. TestCapabilityMatcher

Maps vulnerability class + surface → required capabilities:

```python
class TestCapabilityMatcher(Protocol):
    def match(
        self,
        vulnerability_class: VulnerabilityClass,
        asset: Asset,
        surface: SurfaceCoverageRecord,
    ) -> list[Capability]: ...
```

Example:

| Class | Typical capabilities |
|-------|---------------------|
| `SECURITY_HEADERS` | WEB_PASSIVE_ASSESSMENT, TEMPLATE_BASED_ASSESSMENT |
| `KNOWN_COMPONENT_VULNERABILITY` | TECHNOLOGY_IDENTIFICATION + TEMPLATE_BASED_ASSESSMENT |
| `OBJECT_LEVEL_AUTHORIZATION` | MANUAL (default); ASSISTED if traffic import available |
| `CROSS_APPLICATION_AUTHORIZATION` | MANUAL |

---

## 7. Per-Asset Test Matrix integration

TestPlanner consumes `TestRequirement` cells from AssetTestMatrix:

| Matrix field | Planner usage |
|--------------|---------------|
| `applicability` | Only plan for APPLICABLE / POSSIBLY_APPLICABLE |
| `coverage_status` | Skip COMPLETE unless re-test triggered |
| `testing_mode` | Default mode from class + safety |
| `next_action` | PLAN_AUTOMATED / PLAN_ASSISTED / PLAN_MANUAL |

See ADR-0008.

---

## 8. Plan approval

| safety_class | authorization_requirement |
|--------------|---------------------------|
| PASSIVE, LOW_IMPACT | PRE_APPROVED (if policy allows) |
| STATE_CHANGING | ANALYST_APPROVAL_REQUIRED |
| DESTRUCTIVE, PROHIBITED | Plan not created |

API: `POST /test-plans/{id}/approve` — analyst action; audit logged.

---

## 9. Automated Validation Orchestrator

Executes approved AUTOMATED plans only:

1. Re-validate scope
2. Re-check TestSafetyPolicyEngine
3. Resolve credential handle (worker memory only)
4. Invoke adapter
5. Normalize results → Evidence Graph
6. Invoke VerdictEngine
7. Emit `TEST_EXECUTION_COMPLETED` → Recursive Correlation

Does **not** execute MANUAL or unapproved plans.

---

## 10. Assisted Validation Workflow

Creates `EvidencePackage` (see below) + `ValidationTask` with `testing_mode=ASSISTED`.

### EvidencePackage

| Field | Description |
|-------|-------------|
| `hypothesis_id` | |
| `affected_assets` | |
| `related_assets` | |
| `relevant_endpoints` | |
| `relevant_parameters` | |
| `authentication_context_metadata` | No secrets |
| `roles_involved` | |
| `supporting_observations` | IDs |
| `contradicting_observations` | IDs |
| `scanner_findings` | IDs |
| `historical_changes` | IDs |
| `coverage_gaps` | IDs |
| `validation_goal` | |
| `required_evidence` | |

No destructive exploitation instructions.

---

## 11. Manual Validation Backlog

Extends existing ValidationTask model. Same queue as Phase 0; enriched with test_plan_id and evidence_package_id.

---

## 12. API endpoints

| Endpoint | Purpose |
|----------|---------|
| `GET /scans/{id}/test-plans` | List plans |
| `GET /test-plans/{id}` | Plan detail |
| `POST /test-plans/{id}/approve` | Approve STATE_CHANGING automated plan |
| `POST /test-plans/{id}/cancel` | Cancel plan |

---

## 13. References

- `test-safety-policy.md`
- `verdict-engine.md`
- `recursive-correlation.md`
- ADR-0008
