# Phase 4 — Recursive Correlation Analysis

## 1. Current correlation entry points

| Location | Behavior |
|----------|----------|
| `RecursiveCorrelationEngine` (`assessment.py`) | Stub: `check_js_endpoint_gap()` only; **never called** |
| `ReconController` | Instantiates engine; no correlation processing |
| `EvidenceIngestionService` | Phase 3 ingestion + verdict; **no correlation events** |
| `VerdictEngine` | Emits legacy `VERDICT_ISSUED` Event; no correlation trigger |

## 2. Current rule representation

- `FindingCorrelation` ORM exists; **zero writers**
- `recursive-correlation.md` / ADR-0010 describe target rules; not implemented
- `Hypothesis.correlation_rule_ids` populated by `TestPlanner` only

## 3. Hypothesis creation path

1. `TestPlanner._create_from_requirement()` — primary (asset×class)
2. `RecursiveCorrelationEngine.check_js_endpoint_gap()` — unused stub

## 4. Hypothesis update path

- `VerdictEngine.evaluate_hypothesis()` / `apply_confirmation_decision()`
- `AutomatedValidationOrchestrator` sets INCONCLUSIVE on failure
- No `HypothesisEngine` class

## 5. Hypothesis uniqueness

- **None** — no `uniqueness_key`; dedup by title not enforced
- Phase 4 adds deterministic fingerprint on `hypotheses.uniqueness_key`

## 6. Relationship persistence

- `Relationship` model: source/target asset, type, confidence, evidence_ids, first/last_seen
- `ReconController._add_relationship()` writes rows; emits `RELATIONSHIP_ADDED`
- No update-on-duplicate semantics; Phase 4 adds idempotent upsert

## 7. Evidence-to-hypothesis linkage

- `EvidenceLink` with SUPPORTS/CONTRADICTS (Phase 3)
- `Hypothesis.supporting_evidence_ids` / `contradicting_evidence_ids` JSON lists
- Correlation rules read evidence via `CorrelationContext`

## 8. Change-event handling

- `ChangeEvent` model **documented only** — no ORM table
- Phase 4 uses `CorrelationEvent` with `CHANGE_EVENT_RECORDED` type; `safe_context` carries change category

## 9. Coverage-gap handling

- `SurfaceCompletenessEngine.missing_requirements()` — recon dimensions
- `TestRequirement.coverage_status` — matrix cell state
- No correlation-driven `CoverageGap` table — **Phase 4 adds `coverage_gaps`**

## 10. Existing recursive behavior

- Recon pipeline loop (bounded tasks) — **not assessment correlation**
- Matrix rebuild after verdict — one-hop, not event-driven rules

## 11. Direct correlation-to-ConfirmedFinding path

- **None today**; must remain blocked (rules cannot confirm)

## 12. Loop risks

- Relationship add → observation → relationship re-add without fingerprinting
- Hypothesis from requirement → evidence → same rule re-fire
- Mitigation: event idempotency, rule execution fingerprints, uniqueness keys, generation limits

## 13. Duplicate hypothesis risks

- Same JS endpoint gap on repeated ingestion
- Same auth coverage gap on repeated AUTH_COVERAGE_CHANGED

## 14. Duplicate TestRequirement risks

- Matrix constraint `(matrix_id, vulnerability_class_id)` — one per asset×class
- Correlation scoped work (parameter/endpoint) needs `uniqueness_key` dimension

## 15. Phase 4 integration points

| Component | Integration |
|-----------|-------------|
| `EvidenceIngestionService` | Emit typed events after commit |
| `VerdictEngine` | Emit `VERDICT_CHANGED` on real transition |
| `CorrelationEventService` | Persist + idempotent emit |
| `CorrelationEventProcessor` | Rule evaluation + result application |
| `HypothesisReevaluationService` | Selective reevaluation |
| `FullAssessmentService` | `run_recursive_assessment_loop()` |
| `TestPlanner` | Called after new requirements/gaps |
| `CapabilityValidationRouter` | Executes new automated plans only |

## Async execution choice

**Database-backed pending `correlation_events` table** with synchronous bounded drain during `run_recursive_assessment_loop()`. Restart-safe, no in-memory-only state. Existing `Event` table retained for legacy observability; correlation uses dedicated table.
