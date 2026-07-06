# Recursive Correlation

## 1. Purpose

After validation results and test executions, feed normalized evidence back into the attack surface graph, reevaluate hypotheses, and generate new test requirements. This closes the loop:

```
TEST RESULT → NORMALIZE → EVIDENCE GRAPH → GRAPH UPDATE
    → REEVALUATE HYPOTHESES → CORRELATION RULES → NEW HYPOTHESIS?
        → YES: TEST PLANNER
        → NO: COMPLETION EVALUATOR
```

---

## 2. RecursiveCorrelationEngine

```python
class RecursiveCorrelationEngine(Protocol):
    def process(
        self,
        trigger: CorrelationTrigger,
        scan_id: UUID,
        context: CorrelationContext,
    ) -> CorrelationResult: ...
```

### CorrelationTrigger

`VALIDATION_RESULT_RECORDED` | `TEST_EXECUTION_COMPLETED` | `VERDICT_ISSUED` | `RELATIONSHIP_ADDED` | `ASSET_CHANGED` | `COVERAGE_UPDATED`

---

## 3. Processing pipeline

```
1. Ingest new evidence (observations, findings, validation results)
2. Update asset state and relationship confidence
3. Reevaluate existing hypotheses (support/contradict weights)
4. Run correlation rules (all categories)
5. Create new FindingCorrelation records
6. Create new Hypothesis candidates
7. Create TestRequirement / ValidationTask via TestPlanner
8. Emit CORRELATION_COMPLETED or RECURSIVE_CORRELATION_CYCLE events
```

### Cycle guard

- Max recursion depth per scan session (configurable, default 10)
- Dedup key on hypothesis candidates: `rule_id + entity_set_hash`
- Same trigger + same graph snapshot → idempotent

---

## 4. Correlation rule categories (extended)

| Category | Purpose |
|----------|---------|
| `ASSET_IDENTITY_CORRELATION` | Same/different asset resolution |
| `SHARED_INFRASTRUCTURE_CORRELATION` | Shared IP/hosting |
| `SHARED_CERTIFICATE_CORRELATION` | Cert SAN overlap |
| `SHARED_TECHNOLOGY_CORRELATION` | Same stack across apps |
| `SHARED_DEPENDENCY_CORRELATION` | Shared libs/packages |
| `AUTHENTICATION_RELATIONSHIP_CORRELATION` | Shared IdP |
| `TRUST_RELATIONSHIP_CORRELATION` | Trust boundary issues |
| `FINDING_DUPLICATE_CORRELATION` | Possible duplicate findings |
| `SHARED_ROOT_CAUSE_CORRELATION` | Common config cause |
| `EXPOSURE_CORRELATION` | External exposure amplifies risk |
| `CHANGE_CORRELATION` | New surface + existing context |
| `COVERAGE_CORRELATION` | Missing assessment |
| `AUTHENTICATED_COVERAGE_CORRELATION` | Auth gap |
| `ROLE_COVERAGE_CORRELATION` | Role-specific gap |
| `ENDPOINT_DISCOVERY_CORRELATION` | JS vs crawler gap |
| `HISTORICAL_SURFACE_CORRELATION` | Stale URL vs live surface |

---

## 5. Correlation output (required fields)

| Field | Description |
|-------|-------------|
| `rule_id` | |
| `rule_version` | |
| `input_facts` | JSONB snapshot |
| `participating_assets` | UUID[] |
| `participating_findings` | UUID[] |
| `participating_relationships` | UUID[] |
| `supporting_evidence` | UUID[] |
| `contradicting_evidence` | UUID[] |
| `confidence` | float |
| `resulting_action` | CREATE_HYPOTHESIS, CREATE_TEST_REQUIREMENT, UPDATE_RELATIONSHIP, etc. |
| `explanation` | text |

---

## 6. Example rules

### JS endpoint gap

```
IF javascript REFERENCES endpoint X
AND crawler DID NOT observe X
AND X in scope
THEN
  create endpoint candidate
  create endpoint validation task
  create API/endpoint coverage gap
  (NOT a vulnerability finding)
```

### Shared authentication context

```
IF app A and app B AUTHENTICATES_WITH same IDP
AND app A authorization coverage COMPLETE
AND app B authorization coverage ABSENT
THEN
  create CROSS_APPLICATION_AUTHORIZATION hypothesis
  create TestRequirement
```

### Post-validation trust update

```
IF validation confirms shared role namespace
THEN
  increase TRUSTS relationship confidence
  run AUTHENTICATION_RELATIONSHIP_CORRELATION
  IF app C shares same namespace
  THEN new validation requirement for app C
```

### Authenticated surface gap

```
IF credentials authorized for app A
AND unauthenticated coverage COMPLETE
AND authenticated coverage INCOMPLETE
THEN
  create AUTHENTICATED_ASSESSMENT coverage gap
  eligible authenticated assessment tasks
```

---

## 7. Integration with Test Planner

`resulting_action` of `CREATE_HYPOTHESIS` or `CREATE_TEST_REQUIREMENT` invokes TestPlanner synchronously within same transaction boundary (or via event for async).

---

## 8. Invariants

1. Correlation does not auto-merge findings
2. Correlation does not confirm vulnerabilities
3. Every output has explainable rule_id + facts
4. No AI in correlation decisions

---

## 9. References

- ADR-0010
- `test-planner.md`
- `assessment-completion.md`
- `event-catalog-extensions.md` §5
