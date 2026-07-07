# Integration Migration Plan

**Date:** 2026-07-07  
**Prerequisite docs:** `current-runtime-gap-analysis.md`, `current-runtime-flow.md`, `target-runtime-flow.md`

**Constraint:** Do not redesign from scratch. Do not add tools for count. Connect existing engines.

---

## Migration Principles

1. **One orchestrator** — `FullAssessmentService` (new) replaces ad-hoc chains in `scan_jobs`, `full-validate`, and MCP shortcut.
2. **TestRequirement is the bridge** — all validation routes through requirements → plans → capability selection.
3. **Deprecate parallel paths** — `McpValidationService.validate_scan()` as top-level orchestrator becomes internal adapter executor called by orchestrator.
4. **Job status ≠ assessment status** — always call `AssessmentCompletionEvaluator` before reporting complete.
5. **Tests before UI polish** — 22-step E2E test is the Phase 8 gate.
6. **Incremental phases** — each phase mergeable; no big-bang rewrite.

---

## Phase Overview

| Phase | Goal | Depends on |
|-------|------|------------|
| **1** | Surface → Applicability → Matrix → TestRequirement chain in orchestrator | — |
| **2** | TestRequirement → Planner → CapabilityMatcher → SafetyPolicy → ProviderSelection | Phase 1 |
| **3** | Result → Normalizer → Evidence Graph → Verdict Engine | Phase 2 |
| **4** | Verdict/Evidence → Correlation → Hypothesis → New Requirements | Phase 3 |
| **5** | Test Matrix + Coverage → Assessment Completion (job vs assessment) | Phase 1–4 |
| **6** | Run Full Assessment refactor (replace full-validate shortcut) | Phase 1–5 |
| **7** | Report + UI tabs around connected runtime | Phase 6 |
| **8** | E2E test suite + correlation rules | Phase 6–7 |

---

## PHASE 1 — Connect Surface → Applicability → Matrix → TestRequirement

### Objective

Ensure every assessment refresh (including UI scan and Run Full Assessment) executes:

```
recon quiescence → surface refresh → applicability reevaluate → matrix rebuild → requirement enrichment
```

before any test planning or adapter execution.

### Deliverables

1. `FullAssessmentService.refresh_assessment_state(scan_id)` — single entry for steps 2–6 of target flow (recon refresh optional flag).
2. TestRequirement fields: `reasoning_trace`, `source_rule_ids`, `required_capability` (primary), `safety_class`, `authorization_requirement`, `credential_requirement`.
3. TestMatrixEngine writes reasoning from applicability rule_ids.
4. `scan_jobs._run_job` calls refresh after recon phase (with pipeline execution).
5. Integration test: scope seed → surface → applicability → matrix → requirements with trace.

### Files to Modify

| File | Change |
|------|--------|
| `src/vapt_platform/db/tables/models.py` | Add columns to `TestRequirement`: `reasoning_trace` JSON, `source_rule_ids` JSON list, `required_capability` string, `safety_class` string, `authorization_requirement` string, `credential_requirement` string (nullable defaults) |
| `src/vapt_platform/engines/assessment.py` | `TestMatrixEngine.build()`: populate new fields from applicability rows + rule metadata; derive `required_capability` from class→capability map |
| `src/vapt_platform/engines/vulnerability_applicability.py` | `_build_context()`: enrich from asset metadata (endpoint list from observations if present); persist `rule_ids` on applicability rows (already has `rule_ids`) |
| `src/vapt_platform/services/full_assessment.py` | **NEW** — `refresh_assessment_state()`, `run_recon_until_quiescent()` wrappers |
| `src/vapt_platform/services/scan_jobs.py` | After `ScanService.start()`: if not inline, call `run_recon_until_quiescent()` OR set pipeline execution for UI scans; call `refresh_assessment_state()` before planning |
| `src/vapt_platform/services/core.py` | Extract `run_scan_pipeline` invocation helper for reuse |
| `src/vapt_platform/config/settings.py` | Add `ui_scan_inline_recon: bool = True` (default true for UI to fix gap; distinct from global inline flag) |
| `tests/integration/test_phase1_assessment_refresh.py` | **NEW** — chain test |

### Files NOT to Modify in Phase 1

- Validators (nuclei/burp/sqlmap) — Phase 2
- UI labels — Phase 7
- Report structure — Phase 7
- Correlation engine — Phase 4

### Database Migration

Alembic or inline additive columns (SQLite dev):

```sql
ALTER TABLE test_requirements ADD COLUMN reasoning_trace JSON DEFAULT '{}';
ALTER TABLE test_requirements ADD COLUMN source_rule_ids JSON DEFAULT '[]';
ALTER TABLE test_requirements ADD COLUMN required_capability VARCHAR(64);
ALTER TABLE test_requirements ADD COLUMN safety_class VARCHAR(32);
ALTER TABLE test_requirements ADD COLUMN authorization_requirement VARCHAR(32) DEFAULT 'PRE_APPROVED';
ALTER TABLE test_requirements ADD COLUMN credential_requirement VARCHAR(32);
```

For SQLite dev without Alembic: SQLAlchemy `create_all` on fresh DB or manual migration script in `scripts/`.

### Class → capability mapping (versioned registry)

Use `config/class_capability_mapping.yaml` loaded by `src/vapt_platform/domain/class_capability_registry.py`.

Supports **multiple capabilities per class** (not one-to-one). `TestMatrixEngine` merges registry capabilities with legacy profile extras.

### Acceptance Criteria (Phase 1)

- [ ] UI scan executes recon pipeline (configurable, default on).
- [ ] After recon, `refresh_assessment_state()` runs surface + applicability + matrix.
- [ ] Every APPLICABLE `TestRequirement` has non-empty `source_rule_ids` and `reasoning_trace`.
- [ ] `TestPlanner.plan_scan()` sees updated requirements (no stale matrix).
- [ ] Integration test passes without MCP validators.
- [ ] Existing phase B–F tests still pass.

### Estimated Scope

~400–600 LOC changed/added; 1 new service module; 1 integration test file.

---

## PHASE 2 — TestRequirement → Planner → CapabilityMatcher → SafetyPolicy

### Objective

Replace direct MCP validator orchestration with capability-based provider selection.

### Key New Artifacts

| Artifact | Location |
|----------|----------|
| `ProviderSelectionDecision` model | `db/tables/models.py` |
| `CapabilityValidationRouter` | `services/capability_validation_router.py` |
| `SafetyPolicy` | `engines/safety_policy.py` (formalize existing filters in automated_validation) |
| `AuthorizationPolicy` | `engines/authorization_policy.py` |
| Refactored validators | `validators/` implement `CapabilityProvider` protocol |

### Changes

- `McpValidationService.validate_scan()` → deprecated; logic moves to router invoked by `FullAssessmentService.execute_automated_plans()`.
- `AutomatedValidationOrchestrator` merged into or called by `FullAssessmentService`.
- Nuclei only runs when TestPlan requires `TEMPLATE_BASED_ASSESSMENT`.
- Burp only when plan requires `WEB_PASSIVE_ASSESSMENT`.
- sqlmap only when plan requires `INJECTION_VALIDATION` + active gate.

### Acceptance Criteria

- [ ] ProviderSelectionDecision recorded for every automated execution.
- [ ] No direct `McpValidationService.validate_scan()` from UI endpoints (router only).
- [ ] Unit tests: sqlmap rejected without TestPlan; nuclei rejected without requirement.

---

## PHASE 3 — Evidence Graph + Verdict Gating

### Key New Artifacts

| Artifact | Location |
|----------|----------|
| `ScannerFinding` model | `db/tables/models.py` |
| `ResultNormalizer` | `services/result_normalizer.py` |
| `EvidenceGraphService` | `services/evidence_graph.py` |
| `ConfirmationPolicy` | `engines/confirmation_policy.py` |

### Changes

- MCP/Burp/nuclei output → normalizer → Observation + ScannerFinding + EvidenceLink.
- VerdictEngine consumes evidence graph; no scanner → ConfirmedFinding path.
- UI credentials → `CredentialContextService.create_runtime_context()` (no DB secret storage).

---

## PHASE 4 — Recursive Correlation

### Changes

- Wire `RecursiveCorrelationEngine` (extend with 5 deterministic scenarios).
- Event handler on `TEST_EXECUTION_COMPLETED`, `VALIDATION_RESULT_RECORDED`.
- Implement `FindingCorrelation` writes or defer to EvidenceLink with correlation type.
- Idempotency keys on hypothesis/requirement creation.

---

## PHASE 5 — Assessment Completion vs Job Status

### Changes

- `scan_jobs._run_job` final step: `AssessmentCompletionEvaluator.evaluate()`.
- Job payload includes `assessment_completion_status` separate from `status`.
- UI progress bar shows assessment state, not just job phase.
- `JOB_FINISHED` with `INCOMPLETE` assessment is valid state.

---

## PHASE 6 — Run Full Assessment Refactor

### Changes

| Current | Target |
|---------|--------|
| `POST /full-validate` → AI + MCP | `POST /full-assess` → `FullAssessmentService.run()` |
| `scan_jobs` AI + MCP phases | Single `FullAssessmentService` call |
| `app.js:runFullValidation` | `runFullAssessment` calling new endpoint |

`FullAssessmentService.run()` implements full target orchestration sequence (sections 1–17 in target-runtime-flow.md).

---

## PHASE 7 — Report + UI

### Report

Extend `scan_report()` with missing sections; evidence chains on confirmed findings.

### UI

- Rename "Run Full Validation" → "Run Full Assessment"
- Add tabs: Surface Coverage, Test Matrix, Evidence, Changes
- Attack surface node drill-down panel
- Sidebar capability groups (logical); keep Configure tools as advanced

---

## PHASE 8 — E2E Test Suite

Create `tests/integration/test_full_assessment_lifecycle.py` with 22 steps from spec plus negative tests (AI cannot verdict, credentials not in report, etc.).

---

## Risk Register

| Risk | Mitigation |
|------|------------|
| Recon pipeline slow for UI | Time budget + task limit; phased execution |
| Breaking existing MCP users | Feature flag `USE_LEGACY_MCP_VALIDATION` for one release |
| SQLite migration | Dev migration script; document PostgreSQL alembic for prod |
| Duplicate nuclei paths during Phase 2 | Flag off old path before removing |

---

## Rollback Strategy

Each phase behind settings flag:

- `FULL_ASSESSMENT_V2=false` → legacy scan_jobs + full-validate behavior
- Per-phase flags if needed

Remove legacy path only after Phase 8 tests pass.

---

## Implementation Order (Immediate Next Steps)

1. **Review and approve** this plan + Phase 1 file list.
2. Implement Phase 1 only (no validator refactor yet).
3. Run existing test suite + new Phase 1 integration test.
4. Demo UI scan showing test requirements with `reasoning_trace` in API.
5. Proceed to Phase 2 after sign-off.

**STOP:** No Phase 2+ code until Phase 1 acceptance criteria met.
