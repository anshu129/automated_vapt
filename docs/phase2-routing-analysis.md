# Phase 2 Routing Analysis

**Date:** 2026-07-07

## Current → Required Paths

| CURRENT CALLER | CURRENT VALIDATOR PATH | REQUIRED NEW PATH | FILES |
|----------------|------------------------|-------------------|-------|
| `scan_jobs._run_job` (run_mcp) | `McpValidationService.validate_scan()` → all connectors per asset | `FullAssessmentService.execute_automated_plans()` → `CapabilityValidationRouter` per TestPlan | `scan_jobs.py`, `full_assessment.py` |
| `POST /full-validate` | `AIValidationService` + `McpValidationService.validate_scan()` | V2: refresh + plan + router; AI advisory only | `ui.py` |
| `POST /mcp-validate` | `McpValidationService.validate_scan()` direct | Legacy only when `USE_LEGACY_MCP_VALIDATION=true` | `ui.py`, `mcp_validation.py` |
| `AIValidationService.run` | `AutomatedValidationOrchestrator.execute_scan()` (recon tasks) | V2: skip automated (already routed); advisory + assignment only | `ai_validation.py` |
| `McpValidationService` | Loops assets × connectors, bypasses TestPlan | Deprecated orchestrator; providers called only via router | `mcp_validation.py` |
| Nuclei | Unconditional when MCP enabled | `NucleiCapabilityProvider` when TestPlan requires `TEMPLATE_BASED_ASSESSMENT` | `providers/nuclei_provider.py` |
| Burp MCP | Same shortcut | `BurpCapabilityProvider` when plan requires `WEB_PASSIVE_ASSESSMENT` / `VULNERABILITY_FINDING_IMPORT` | `providers/burp_provider.py` |
| sqlmap MCP | Class-code substring + active_allowed | `SqlmapCapabilityProvider` when plan requires `INJECTION_VALIDATION` + policies pass | `providers/sqlmap_provider.py` |

## Unchanged in Phase 2

- Phase 1 `prepare_for_planning` / `TestPlanner.plan_scan`
- Evidence graph, verdict gating, report, UI layout
- MCP read server
