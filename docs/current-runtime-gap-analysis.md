# Current Runtime Gap Analysis

**Date:** 2026-07-07  
**Method:** Repository inspection — imports, service calls, API routes, job orchestration, database writes, UI calls, test coverage. Existence of files/endpoints/tables is **not** treated as proof of end-to-end behavior.

---

## Executive Summary

The platform has **substantial implemented engines** (surface completeness, applicability, test matrix, test planner, automated validation, verdict engine, completion evaluator) that are **partially wired**. The **default Web UI scan path** (`scan_jobs._run_job`) does **not** run the full intended architecture. It most closely resembles:

```
TARGET → scope seed events → TestPlanner → AI (TestPlan-based nuclei) → MCP validators (direct nuclei/Burp/sqlmap) → JOB_FINISHED
```

with report generation as a **separate manual step**.

Critical gaps:

| Gap | Severity |
|-----|----------|
| Recon pipeline not executed by default UI scan (`SCAN_START_INLINE_EXECUTION=false`) | **P0** |
| `McpValidationService` bypasses TestPlanner, CapabilityMatcher, SafetyPolicy | **P0** |
| `RecursiveCorrelationEngine` instantiated but never called | **P0** |
| `JOB_FINISHED` ≠ `ASSESSMENT_COMPLETE` (completion not evaluated at job end) | **P0** |
| UI credentials are URL-embedded; not `CredentialReference` / `AuthenticationContext` | **P1** |
| `ProviderSelectionDecision` does not exist | **P1** |
| Evidence graph mostly stub (`EvidenceLink` only on verdict) | **P1** |
| `ScannerFinding`, `ChangeEvent`, `FindingCorrelation` not in runtime | **P1** |
| Report missing many evidence-aware sections | **P2** |
| Applicability context lacks endpoint/parameter/role granularity | **P2** |

---

## Subsystem Analysis

Legend: **E2E** = connected end-to-end in default UI flow | **PARTIAL** | **DEAD** | **STUB**

---

### 1. Scope Manager

| Field | Value |
|-------|-------|
| **Claimed capability** | Mandatory scope validation at task persistence, scheduling, execution |
| **Actual implementation** | `scope/manager.py` — `ScopeManager` validates targets against scope rules |
| **Entry point** | `ReconController`, `ScanService.run_ready_tasks`, `ScanService.run_tools` |
| **Runtime caller** | Every `ReconController` instantiation; **not** called by `McpValidationService` URL resolution |
| **DB tables** | `ScopeSnapshot`, scope rules in JSON on scan |
| **Events consumed** | N/A (validation layer) |
| **Events produced** | Rejects out-of-scope task targets |
| **Connection** | **PARTIAL** — recon/API paths yes; MCP validators check applicability rows but not full scope re-validation on every URL |
| **Tests** | `tests/unit/test_scope_manager.py` |
| **Gap** | MCP validation should re-validate target URL against scope rules |
| **Required fix** | Inject `ScopeManager` into validation adapter selection |
| **Priority** | P1 |

---

### 2. Recon Controller

| Field | Value |
|-------|-------|
| **Claimed capability** | Event-driven adaptive reconnaissance, task creation, pipeline execution |
| **Actual implementation** | `controller/recon_controller.py` — ~900 lines, full event dispatch |
| **Entry point** | `ScanService.start()`, `AutomatedValidationOrchestrator`, REST `run-ready`/`run-tools` |
| **Runtime caller (UI)** | `scan_jobs` → `ScanService.start()` only |
| **DB tables** | `Asset`, `Relationship`, `Task`, `TaskRun`, `Observation`, `Event`, `RawArtifact` |
| **Events consumed** | 15+ event types (DNS, HTTP, endpoint, task completed, etc.) |
| **Events produced** | Asset/relationship creation, task scheduling, applicability triggers |
| **Downstream** | Surface engine, applicability engine, matrix engine, adaptive recon planner |
| **Connection** | **PARTIAL** — scope seed fires `WEB_APPLICATION_CONFIRMED` → surface/applicability/matrix; **READY tasks not executed** unless inline execution or automated validation |
| **Dead/stub** | `RecursiveCorrelationEngine` assigned to `self.correlation_engine` but **never invoked** |
| **Tests** | `test_vertical_slice.py`, `test_phase_b_pipeline.py`, `test_automated_validation.py` |
| **Gap** | UI scan creates gap-filling READY tasks but does not run `run_scan_pipeline` |
| **Required fix** | Full assessment must execute pending recon tasks or inline pipeline before planning |
| **Priority** | **P0** |

---

### 3. Capability Registry

| Field | Value |
|-------|-------|
| **Claimed capability** | Capability-based tool selection by priority, cost, availability |
| **Actual implementation** | `capabilities/registry.py`, `capabilities/matcher.py` |
| **Entry point** | `ReconController.create_task`, `AdaptiveReconPlanner`, `SurfaceCompletenessEngine` |
| **Runtime caller** | Recon path only |
| **DB tables** | `CapabilityProvider`, `CapabilityDefinition`, `CapabilityExecutionProfile` |
| **Connection** | **PARTIAL** — used for recon; **NOT** used by TestPlanner or MCP validators |
| **Tests** | Indirect via integration recon tests |
| **Gap** | TestPlanner selects plans from matrix; does not route through capability registry for validation adapters |
| **Required fix** | Phase 2: CapabilityMatcher for TestRequirement → provider selection |
| **Priority** | **P0** (for validation routing) |

---

### 4. Parameter Engine

| Field | Value |
|-------|-------|
| **Claimed capability** | Doc-grounded CLI flag adaptation |
| **Actual implementation** | `parameters/engine.py`, YAML rules in `config/parameters/rules/` |
| **Entry point** | `CliToolExecutor.execute()` |
| **Runtime caller** | Recon task execution, `NucleiValidator` (via executor) |
| **DB tables** | Parameter decisions stored on task runs (metadata) |
| **Connection** | **E2E** for recon CLI path; **PARTIAL** for MCP nuclei (uses executor) |
| **Tests** | `tests/unit/test_parameter_engine.py` (8 tests) |
| **Gap** | Burp/sqlmap MCP bypass parameter engine entirely |
| **Required fix** | Structured test context for MCP adapters, not free-form commands |
| **Priority** | P1 |

---

### 5. CLI Tool Executor

| Field | Value |
|-------|-------|
| **Claimed capability** | Execute approved tools with timeout, redaction, fake fallback |
| **Entry point** | `adapters/cli_executor.py` |
| **Runtime caller** | `ReconController.execute_task`, `NucleiValidator` |
| **Connection** | **E2E** for recon; nuclei validator only MCP path using it |
| **Tests** | `test_nuclei_integration.py` |
| **Priority** | P2 — extend metadata for test_plan_id linkage |

---

### 6. Tool Parsers

| Field | Value |
|-------|-------|
| **Claimed capability** | Normalize tool output to observations |
| **Actual implementation** | `parsers/registry.py`, event handlers in recon controller |
| **Runtime caller** | Post-execution in `ReconController.execute_task` |
| **Connection** | **PARTIAL** — recon yes; MCP validators parse inline, not through parser registry |
| **Gap** | No unified normalizer for MCP/Burp/sqlmap → Observation/ScannerFinding |
| **Priority** | P1 |

---

### 7. Asset Inventory

| Field | Value |
|-------|-------|
| **Claimed capability** | Persistent asset model with types, metadata, confidence |
| **Actual implementation** | `Asset` model, created via recon event handlers |
| **Entry point** | Event handlers in recon controller |
| **Runtime caller (UI)** | Scope seed events only (minimal assets unless pipeline runs) |
| **DB tables** | `assets` |
| **Connection** | **PARTIAL** — UI scan often has scope-seeded web app + hostname, not full discovery |
| **Tests** | Phase B integration |
| **Priority** | P0 — tied to recon pipeline execution |

---

### 8. Relationship Graph

| Field | Value |
|-------|-------|
| **Claimed capability** | Attack surface graph with typed edges |
| **Actual implementation** | `Relationship` model, `_add_relationship()` in recon controller |
| **Types implemented** | `HAS_SUBDOMAIN`, `RESOLVES_TO`, `CONTAINS` (asset-graph) |
| **Types claimed but missing** | `EXPOSES`, `HOSTS`, `ACCEPTS`, `LOADS`, `REFERENCES`, `AUTHENTICATES_WITH`, `TRUSTS`, `USES_TECHNOLOGY` |
| **Runtime caller** | Recon event handlers |
| **UI source** | `GET /scans/{id}/relationships` — **persisted**, not display-only |
| **Connection** | **PARTIAL** — basic edges; endpoint/parameter/JS relationships not modeled |
| **Gap** | `evidence_ids` on relationships never populated |
| **Tests** | Phase B |
| **Priority** | P1 |

---

### 9. Surface Completeness Engine

| Field | Value |
|-------|-------|
| **Claimed capability** | Per-asset surface dimension tracking, gap detection |
| **Actual implementation** | `engines/surface_completeness.py` |
| **Entry point** | `.compute()`, `.missing_requirements()` |
| **Runtime caller** | Recon event handlers; `AssessmentCompletionEvaluator`; REST API |
| **DB tables** | `SurfaceCoverageRecord` |
| **Connection** | **PARTIAL** — runs on scope seed events; **not refreshed** after UI job MCP phase |
| **Tests** | `test_phase_c_surface.py` |
| **Gap** | Not invoked in full-validate or scan_jobs completion |
| **Priority** | **P0** (Phase 1) |

---

### 10. Vulnerability Applicability Engine

| Field | Value |
|-------|-------|
| **Claimed capability** | Deterministic class applicability from rules + surface context |
| **Actual implementation** | `engines/vulnerability_applicability.py`, `config/applicability/rules.yaml` |
| **Context inputs** | `asset_type`, `metadata`, `surface_dimensions`, `endpoints[]`, `technologies[]`, `uses_https` |
| **Context missing vs spec** | parameter location, auth roles, upload surface, GraphQL, object IDs, trust relationships |
| **Output states** | All 7 states supported in enum; rules primarily emit APPLICABLE/POSSIBLY_APPLICABLE/NOT_APPLICABLE |
| **Runtime caller** | `_compute_and_emit_applicability` in recon controller |
| **MCP consumer** | Reads `AssetVulnerabilityApplicability` directly — **bypasses matrix** |
| **Connection** | **PARTIAL** — works when recon events fire; coarse context |
| **Tests** | `test_phase_d_applicability.py`, `test_applicability_rules.py` |
| **Gap** | Does not consume endpoint/parameter-level facts; may over-apply web classes |
| **Priority** | **P0** (Phase 1 context enrichment) |

---

### 11. Test Matrix Engine

| Field | Value |
|-------|-------|
| **Claimed capability** | ASSET × VULNERABILITY CLASS coverage grid |
| **Actual implementation** | `TestMatrixEngine.build()` in `engines/assessment.py` |
| **Entry point** | Called after applicability reevaluate |
| **Runtime caller** | Recon controller, TestPlanner, VerdictEngine, AutomatedValidationOrchestrator |
| **DB tables** | `AssetTestMatrix`, `TestRequirement` |
| **Connection** | **PARTIAL** — built on scope seed; **not surface-aware per-endpoint** |
| **Tests** | `test_phase_e_test_matrix.py` |
| **Gap** | Matrix is asset×class, not asset×surface×class; missing reasoning_trace on TestRequirement |
| **Priority** | **P0** (Phase 1) |

---

### 12. Test Planner

| Field | Value |
|-------|-------|
| **Claimed capability** | Generate automated/assisted/manual plans from matrix requirements |
| **Actual implementation** | `TestPlanner.plan_scan()` |
| **Entry point** | `scan_jobs` planning phase, REST API, CLI |
| **Runtime caller (UI)** | **Yes** — always called in `_run_job` |
| **DB tables** | `TestPlan`, `Hypothesis`, `EvidencePackage`, `ValidationTask` |
| **Connection** | **PARTIAL** — plans created but many recon tasks never ran; MCP bypasses entirely |
| **Tests** | `test_phase_f_test_planner.py` |
| **Gap** | Plans may exist for assets with incomplete surface |
| **Priority** | P0 |

---

### 13. Automated Validation Orchestrator

| Field | Value |
|-------|-------|
| **Claimed capability** | Execute PASSIVE/LOW_IMPACT pre-approved automated plans |
| **Actual implementation** | `services/automated_validation.py` |
| **Entry point** | `AIValidationService.run()`, REST execute-automated |
| **Runtime caller (UI)** | AI validation phase when `run_ai=true` |
| **Safety filter** | PASSIVE/LOW_IMPACT, PRE_APPROVED auth, AUTOMATED mode only |
| **Connection** | **E2E** for TestPlan path; calls `AssessmentCompletionEvaluator` at end |
| **Tests** | `test_automated_validation.py` |
| **Gap** | Zero finding candidates → auto REJECTED verdict (may be aggressive) |
| **Priority** | P1 |

---

### 14. Nuclei Validator (MCP path)

| Field | Value |
|-------|-------|
| **Claimed capability** | Template-based corroboration |
| **Actual implementation** | `validators/nuclei.py` via `McpValidationService` |
| **Trigger** | All applicable assets with URL; tag heuristics from class code |
| **Bypasses** | TestPlanner, TestRequirement, CapabilityMatcher, SafetyPolicy, ProviderSelectionDecision |
| **Connection** | **DEAD PATH relative to architecture** — parallel shortcut |
| **Tests** | Unit parsing only; no integration |
| **Gap** | Runs unconditionally per asset when MCP enabled; duplicate of TestPlan nuclei path |
| **Required fix** | Refactor to capability provider selected by TestRequirement |
| **Priority** | **P0** |

---

### 15. Burp MCP Validator

| Field | Value |
|-------|-------|
| **Claimed capability** | Burp scanner + proxy history corroboration |
| **Actual operations** | `get_scanner_issues`, `get_proxy_http_history_regex` (read-only) |
| **Does NOT** | Trigger scans, import requests, active assessment |
| **Capability declaration** | Should be `WEB_PASSIVE_ASSESSMENT` / `VULNERABILITY_FINDING_IMPORT` |
| **Connection** | **PARTIAL** — works when Burp running; bypasses planner; maps to ValidationTask not graph |
| **Tests** | Unit parse only |
| **Priority** | P1 |

---

### 16. sqlmap MCP Validator

| Field | Value |
|-------|-------|
| **Claimed capability** | SQL injection corroboration |
| **Actual implementation** | stdio MCP `sqlmap_scan_url`; class code filter SQL/INJECTION |
| **Gating** | `active=True`, requires `active_allowed` flag |
| **Bypasses** | TestPlanner, structured endpoint context, safety policy record |
| **Connection** | **PARTIAL** — eligibility check is class-code substring only |
| **Tests** | Unit positive/negative pattern only |
| **Priority** | **P0** |

---

### 17. AI Advisory (Mistral)

| Field | Value |
|-------|-------|
| **Claimed capability** | Optional coverage advisory, not in critical path |
| **Actual implementation** | `enrichment/mistral.py`, called from `AIValidationService` |
| **Runtime caller** | AI validation phase, REST enrich endpoint |
| **Connection** | **PARTIAL** — advisory works; sits **inside** AI validation phase (not purely post-deterministic) |
| **Gap** | No `AIContextBuilder` with strict bounded context; `AI_MAX_TOKENS=0` → 32k response only |
| **Tests** | `test_ai_mcp_coverage.py` (fallback path) |
| **Priority** | P1 (Phase 5+) |

---

### 18. Hypothesis Engine

| Field | Value |
|-------|-------|
| **Claimed capability** | Evidence-backed claims awaiting validation |
| **Actual implementation** | `Hypothesis` model; created by `TestPlanner._create_from_requirement` |
| **Runtime caller** | TestPlanner; **not** RecursiveCorrelationEngine |
| **Connection** | **PARTIAL** — rule_ids from applicability; no JS-endpoint-gap correlation |
| **Tests** | Phase F, full assessment workflow |
| **Priority** | P0 (Phase 4 correlation) |

---

### 19. Validation Backlog

| Field | Value |
|-------|-------|
| **Claimed capability** | Analyst worklist with priorities |
| **Actual implementation** | `ValidationTask` model |
| **Writers** | TestPlanner, AutomatedValidationOrchestrator, McpValidationService, AI assignment |
| **Connection** | **E2E** for display; multiple writers without unified dedup strategy |
| **Tests** | Full assessment workflow |
| **Priority** | P1 |

---

### 20. Evidence Package System

| Field | Value |
|-------|-------|
| **Claimed capability** | Structured evidence bundles |
| **Actual implementation** | `EvidencePackage` model — simplified JSON payloads |
| **Runtime dependency** | Referenced by ValidationTask; **not** driving verdict decisions except via validation result flow |
| **Connection** | **PARTIAL** — storage yes; graph integration minimal |
| **Priority** | P1 (Phase 3) |

---

### 21. Verdict Engine

| Field | Value |
|-------|-------|
| **Claimed capability** | Formal hypothesis outcomes; gates confirmed findings |
| **Actual implementation** | `VerdictEngine.evaluate_hypothesis()` |
| **Runtime caller** | `ValidationService.record_result`, AutomatedValidationOrchestrator (auto-REJECTED) |
| **NOT called by** | MCP validators, scan_jobs, AI |
| **Connection** | **PARTIAL** — works for manual validation API; MCP never reaches verdict |
| **Tests** | `test_full_assessment_workflow.py` |
| **Gap** | No explicit `ConfirmationPolicy` module |
| **Priority** | P0 (Phase 3) |

---

### 22. Confirmed Findings

| Field | Value |
|-------|-------|
| **Claimed capability** | Evidence-gated confirmed vulnerabilities |
| **Actual implementation** | Created only by VerdictEngine on CONFIRMED |
| **Connection** | **E2E** when analyst records validation result |
| **NOT created by** | Scanners, AI, MCP validators (by design) |
| **Tests** | Full assessment workflow |
| **Priority** | OK — preserve gating |

---

### 23. Assessment Completion Evaluator

| Field | Value |
|-------|-------|
| **Claimed capability** | Determine scan completeness vs job exit |
| **Actual implementation** | `AssessmentCompletionEvaluator.evaluate()` |
| **Criteria** | Open validation tasks, blocking surface gaps, unresolved test requirements |
| **Runtime caller** | Automated validation end, run_scan_pipeline end, REST API |
| **NOT called by** | `scan_jobs._run_job` final completion; MCP phase |
| **Connection** | **PARTIAL** — `JOB_FINISHED` while assessment may be INCOMPLETE |
| **Tests** | Indirect via automated validation |
| **Priority** | **P0** (Phase 5) |

---

### 24. Credential Service

| Field | Value |
|-------|-------|
| **Claimed capability** | Credential references, bindings, auth/role coverage |
| **Actual implementation** | `services/credentials.py` — metadata only, no secret storage |
| **Runtime caller** | REST API only; report/MCP read |
| **UI path** | Username/password → `with_auth_url()` — **not** CredentialReference |
| **Connection** | **DEAD** for automated scan flow |
| **Tests** | `test_credential_context.py` (API/MCP read) |
| **Priority** | P1 (Phase 3+) |

---

### 25. Authentication Context

| Field | Value |
|-------|-------|
| **Claimed capability** | Track authenticated session coverage per asset |
| **Actual implementation** | `AuthenticationContext`, `RoleContext` models |
| **Runtime caller** | REST `bind_session` only |
| **Connection** | **DEAD** in UI scan |
| **Priority** | P1 |

---

### 26. Background Job Service

| Field | Value |
|-------|-------|
| **Claimed capability** | Non-blocking full assessment |
| **Actual implementation** | `services/scan_jobs.py` — in-memory `_JOBS` dict |
| **Phases** | reconnaissance → planning → ai_validation → tool_validation → completed |
| **Gap** | Marks completed regardless of assessment completion status |
| **Priority** | **P0** |

---

### 27. Report Generator

| Field | Value |
|-------|-------|
| **Claimed capability** | Combined JSON assessment report |
| **Actual implementation** | `GET /scans/{id}/report` |
| **Present sections** | summary, assets, relationships, tasks, applicability (filtered), test_matrix, plans, executions, validation backlog/results, evidence_links, hypotheses, verdicts, findings, AI, auth/role coverage, completion |
| **Missing sections** | observations, surface_inventory, scanner_findings, finding_correlations, test_requirements (explicit), evidence_packages, change_events, coverage_gaps, rejected_hypotheses, inconclusive_tests, workflow/tool versions |
| **Connection** | **PARTIAL** — aggregation without full evidence chain |
| **Priority** | P2 (Phase 7) |

---

### 28. Web UI

| Field | Value |
|-------|-------|
| **Claimed capability** | Full assessment dashboard |
| **Actual tabs** | Overview, Assets, Attack Surface, Vulnerabilities, Hypotheses, Validation, Tool validation, AI advisory |
| **Missing tabs** | Surface Coverage, Test Matrix, Evidence, Confirmed Findings (partial in Vulns), Changes |
| **"Run full validation"** | Calls AI + MCP directly — **not** full assessment architecture |
| **Connection** | **PARTIAL** — displays DB state; orchestration shortcut |
| **Priority** | P2 (Phase 7) |

---

### 29. MCP Server (read-only)

| Field | Value |
|-------|-------|
| **Claimed capability** | External agent read boundary |
| **Actual implementation** | 14 read tools in `mcp/read_tools.py` |
| **Connection** | **E2E** for read path |
| **Tests** | `test_ai_mcp_coverage.py` |
| **Priority** | OK |

---

## Test Coverage Summary

| Area | Integration E2E | Unit |
|------|-----------------|------|
| Recon pipeline | Yes (with inline execution) | Partial |
| Surface completeness | Yes | No |
| Applicability | Yes | Yes |
| Test matrix | Yes | No |
| Test planner | Yes | No |
| Automated validation | Yes | No |
| Manual validation → verdict | Yes (1 test) | No |
| MCP validators | **No** | Parse only |
| Full-validate endpoint | **No** | No |
| UI scan_jobs | **No** | No |
| Correlation engine | **No** | No |
| Credential UI flow | **No** | API only |

**Required 22-step E2E test from spec: NOT IMPLEMENTED.**

---

## Priority Matrix

| Priority | Items |
|----------|-------|
| **P0** | Wire recon pipeline into full assessment; remove MCP bypass; connect Surface→Applicability→Matrix→Planner chain in orchestrator; refactor Run Full Assessment; job vs assessment completion; correlation engine activation |
| **P1** | Capability-based validator routing; evidence normalizer; credential context; applicability context enrichment; relationship types; ProviderSelectionDecision |
| **P2** | Report refactor; UI tabs; AI context builder |
