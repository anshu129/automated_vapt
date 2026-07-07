# Phase 3 Evidence Flow Analysis

**Date:** 2026-07-07

## Current → Phase 3 Path

| Provider | Raw output | Current parser | Current storage | Auto-confirms? | Phase 3 change |
|----------|------------|----------------|-----------------|----------------|----------------|
| **nuclei** | JSONL stdout | `NucleiValidator._parse()` → `ValidationFinding` | `McpValidationService._persist_outcome` → `Observation` only when findings | No (opens ValidationTask with recommended CONFIRMED) | `NucleiResultNormalizer` → typed artifacts → `EvidenceIngestionService` |
| **burp_mcp** | MCP JSON text | `_parse_scanner_issues`, `_parse_history_signals` | Same MCP path | No | `BurpResultNormalizer` → OBSERVATION / SCANNER_FINDING |
| **sqlmap_mcp** | MCP stdout text | `_looks_positive()` regex | Same MCP path | No | `SqlmapResultNormalizer` → SCANNER_FINDING / NEGATIVE / INCONCLUSIVE |

## Per-provider detail

### Nuclei
1. Raw: nuclei JSONL lines (`template-id`, `info`, `matched-at`)
2. Parser: `validators/nuclei.py::_parse`
3. Storage: `CapabilityValidationRouter._persist_corroboration` → `Observation` (MCP_VALIDATION_*)
4. Positive → not `ConfirmedFinding`; advisory ValidationTask only
5. Negative (`NO_EVIDENCE`) → not stored explicitly
6. Parser errors → `ERROR` status; indistinguishable from transport error in coverage
7. Asset URL in outcome; plan linkage weak
8. TestPlan/TestRequirement link via `reasoning_trace.requirement_id` only
9. No `EvidenceLink` SUPPORTS/CONTRADICTS to hypothesis
10. **Change:** normalize all outcomes; store negative/inconclusive; link provenance chain

### Burp MCP
1. Raw: scanner issues + proxy history JSON chunks
2. Parser: `validators/burp.py`
3. Storage: same MCP observation path
4. No direct confirmation
5. No negative evidence stored
6. Transport errors → `ERROR`; empty → `NO_EVIDENCE` (ambiguous)
7. Host matching only
8. Weak plan linkage
9. No hypothesis graph edges
10. **Change:** passive issue → SCANNER_FINDING; proxy → OBSERVATION; failures typed

### sqlmap MCP
1. Raw: sqlmap MCP stdout
2. Parser: regex positive/negative patterns
3. Storage: same MCP path
4. No direct confirmation
5. Clean negative not stored as NEGATIVE_EVIDENCE
6. Ambiguous empty conflated with negative
7. URL only; structured parameter context in plan not in artifact
8. Plan context in `required_context.endpoint`
9. No hypothesis links
10. **Change:** retain endpoint/parameter metadata; typed artifacts; no empty→negative

## Existing models reused
- `Observation`, `EvidenceLink`, `Hypothesis`, `Verdict`, `ConfirmedFinding`, `TestExecution`
- **New:** `ScannerFinding`, `EvidenceNode`, `VerdictTransition`, `ConfirmationDecision`, `ProviderRawResult`

## Gaps closed in Phase 3
- `ResultNormalizer` + `EvidenceIngestionService` replace `_persist_corroboration`
- `ConfirmationPolicy` gates verdict transitions
- `VerdictEngine.reevaluate_from_evidence()` — only path to auto `ConfirmedFinding` in V2
- `SensitiveDataRedactor` before persistence/logging
