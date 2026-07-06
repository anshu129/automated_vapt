# Event Catalog — Extensions

## 1. Purpose

Additional domain events for adaptive reconnaissance, evidence quality, surface completeness, test planning, verdicts, and recursive correlation. Follows envelope schema in `event-catalog.md` §2.

---

## 2. Evidence quality events

| Event Type | Payload | Emitted By | Controller Actions |
|------------|---------|------------|-------------------|
| `EVIDENCE_QUALITY_EVALUATED` | `decision_id`, `task_run_id`, `status`, `reason_codes[]` | EvidenceQualityEvaluator | Branch workflow; schedule alternate capability |
| `CONFLICTING_EVIDENCE_OBSERVED` | `observation_ids[]`, `target_asset_id` | EvidenceQualityEvaluator | Store competing obs; correlation rules |
| `NEGATIVE_EVIDENCE_RECORDED` | `observation_id`, `target_asset_id`, `conclusive` | Controller | Update asset confidence |
| `MANUAL_REVIEW_REQUIRED` | `decision_id`, `reason` | EvidenceQualityEvaluator | Create validation backlog item |

---

## 3. Capability planning events

| Event Type | Payload | Emitted By | Actions |
|------------|---------|------------|---------|
| `CAPABILITY_PLANNED` | `capability`, `provider_id`, `profile_id`, `reasoning_trace` | AdaptiveReconPlanner | Audit; optional pre-task |
| `CAPABILITY_PROVIDER_SELECTED` | `capability`, `provider_id`, `selection_trace` | CapabilitySelectionEngine | Create task with provider |
| `DISCOVERY_GAIN_COMPUTED` | `provider_id`, `metrics` | MarginalDiscoveryGainEngine | Update metrics; stopping rules |
| `PROVIDER_GAIN_THRESHOLD_NOT_MET` | `capability`, `provider_id` | MarginalDiscoveryGainEngine | Skip further providers |

---

## 4. Surface completeness events

| Event Type | Payload | Emitted By | Actions |
|------------|---------|------------|---------|
| `SURFACE_COVERAGE_COMPUTED` | `asset_id`, `record_id`, `overall_status` | SurfaceCompletenessEngine | Update derived CoverageRecord |
| `SURFACE_GAP_IDENTIFIED` | `asset_id`, `dimension`, `status` | SurfaceCompletenessEngine | TestPlanner / capability tasks |
| `HISTORICAL_OBSERVATION_RECORDED` | `observation_id`, `url` | Parser | Schedule live validation |

---

## 5. Applicability and test matrix events

| Event Type | Payload | Emitted By | Actions |
|------------|---------|------------|---------|
| `APPLICABILITY_COMPUTED` | `asset_id`, `class_count` | VulnerabilityApplicabilityEngine | Generate/update test matrix |
| `TEST_MATRIX_UPDATED` | `asset_id`, `matrix_id` | TestMatrixEngine | Completion evaluator input |
| `TEST_REQUIREMENT_CREATED` | `requirement_id`, `vulnerability_class_id` | TestMatrixEngine / Correlation | TestPlanner |
| `TEST_PLAN_CREATED` | `plan_id`, `testing_mode`, `hypothesis_id` | TestPlanner | Approval workflow if needed |
| `TEST_PLAN_APPROVED` | `plan_id`, `approved_by` | TestPlanService | Schedule automated execution |
| `TEST_PLAN_CANCELLED` | `plan_id`, `reason` | TestPlanService | Cancel related tasks |
| `TEST_EXECUTION_COMPLETED` | `execution_id`, `plan_id`, `summary` | AutomatedValidationOrchestrator | VerdictEngine; recursive correlation |
| `TEST_EXECUTION_FAILED` | `execution_id`, `error_class` | Worker | FAILURE_RULE |

---

## 6. Verdict and recursive correlation events

| Event Type | Payload | Emitted By | Actions |
|------------|---------|------------|---------|
| `VERDICT_ISSUED` | `verdict_id`, `hypothesis_id`, `status` | VerdictEngine | ConfirmedFinding gate; correlation |
| `RECURSIVE_CORRELATION_STARTED` | `trigger`, `depth` | RecursiveCorrelationEngine | Audit |
| `RECURSIVE_CORRELATION_COMPLETED` | `new_hypothesis_ids[]`, `new_requirement_ids[]` | RecursiveCorrelationEngine | TestPlanner for new items |
| `CORRELATION_CYCLE_LIMIT_REACHED` | `scan_id`, `depth` | RecursiveCorrelationEngine | Log; manual review flag |

---

## 7. Credential and auth coverage events

| Event Type | Payload | Emitted By | Actions |
|------------|---------|------------|---------|
| `CREDENTIAL_REGISTERED` | `credential_id` (metadata only) | CredentialService | Audit |
| `AUTHENTICATION_CONTEXT_ESTABLISHED` | `context_id`, `asset_id`, `role` | Worker (ephemeral) | No secret in payload |
| `AUTH_COVERAGE_GAP_IDENTIFIED` | `application_id`, `dimension` | CredentialContextManager | Authenticated test plans |
| `ROLE_COVERAGE_GAP_IDENTIFIED` | `application_id`, `role_name` | CredentialContextManager | Role-specific plans |

---

## 8. Assessment completion events

| Event Type | Payload | Emitted By | Actions |
|------------|---------|------------|---------|
| `ASSESSMENT_COMPLETION_EVALUATED` | `record_id`, `status`, `reasons` | AssessmentCompletionEvaluator | May emit SCAN_COMPLETED |
| `ASSESSMENT_GAP_ACCEPTED` | `gap_ids[]`, `accepted_by` | Analyst | Update completion record |
| `SCAN_COMPLETION_BLOCKED` | `blocking_items[]` | AssessmentCompletionEvaluator | Prevent SCAN_COMPLETED |

---

## 9. Event → task mapping (extensions)

| Trigger Event | Capability / Action |
|---------------|---------------------|
| `EVIDENCE_QUALITY_EVALUATED` (INCONCLUSIVE) | `recommended_next_capability` from decision |
| `SURFACE_GAP_IDENTIFIED` | CapabilityMatcher for dimension |
| `TEST_PLAN_APPROVED` (AUTOMATED) | Required capabilities via scheduler |
| `RECURSIVE_CORRELATION_COMPLETED` | TestPlanner for new requirements |
| `AUTH_COVERAGE_GAP_IDENTIFIED` | `AUTHENTICATED_WEB_ASSESSMENT` if creds bound |

---

## 10. Idempotency keys (extensions)

| Event | Dedup Key |
|-------|-----------|
| `EVIDENCE_QUALITY_EVALUATED` | `task_run_id` |
| `SURFACE_COVERAGE_COMPUTED` | `scan_id + asset_id + dimension_set_hash` |
| `APPLICABILITY_COMPUTED` | `scan_id + asset_id + rule_version` |
| `VERDICT_ISSUED` | `hypothesis_id + evidence_set_hash` |
| `TEST_PLAN_CREATED` | `scan_id + hypothesis_id + capability_set_hash` |

---

## 11. Schema versioning

Extension events use `schema_version: "1.0-ext"`. Bump minor on additive payload fields; major on semantic change with ADR.
