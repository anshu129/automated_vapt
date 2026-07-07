# Phase 5 — Assessment Completion Analysis

## 1. Current job completion flow

`scan_jobs._run_job()` runs recon → planning → capability routing → AI → legacy MCP, then sets `job.status = "COMPLETED"` with no call to `AssessmentCompletionEvaluator`.

## 2. Current assessment completion flow

`AssessmentCompletionEvaluator.evaluate()` in `assessment.py` checks:
- open `ValidationTask` count
- blocking `TestRequirement` coverage statuses
- blocking surface gaps via `SurfaceCompletenessEngine`

Sets `AssessmentCompletionRecord.status` to COMPLETE / COMPLETE_WITH_ACCEPTED_GAPS / INCOMPLETE only.

## 3. Conflation points

- Job `status=COMPLETED` implies assessment done to UI users
- `Scan.status` separate from completion record but not wired to evaluator
- No `assessment_status` on job payload

## 4. `bound_reached` storage

`CorrelationScanState.bound_reached` (string reason). **Not read** by current evaluator.

## 5. Pending correlation work

`CorrelationEvent.status = PENDING`. **Not counted** in completion today.

## 6. Backlog in completion

Manual `ValidationTask` backlog counted. Hypotheses, coverage gaps, correlation backlog **ignored**.

## 7. Incomplete coverage blocks completion

Yes — via test requirements and surface gaps.

## 8. Unresolved hypotheses

**Not considered** today.

## 9. Manual validation backlog

Counted via open validation tasks.

## 10. Authenticated coverage

Surface dimension `AUTHENTICATED_AREA_COVERAGE` checked; `AuthenticationContext` / `RoleContext` **not** directly aggregated.

## 11. Parameter-scoped outstanding work

`reasoning_trace.parameter_scopes` on requirements **not** evaluated.

## 12. Evaluator inputs today

Validation tasks, test requirements, surface gaps, accepted_gaps on record.

## 13. Data ignored today

CorrelationScanState, pending correlation events, CoverageGap, hypotheses backlog, role coverage, bound_reached, contradictions, test plans/executions pending state.

## 14. Phase 5 changes

- `PendingWorkAggregator` for categorized pending work
- `AcceptedGapPolicy` for explicit gap acceptance
- Refactored `AssessmentCompletionEvaluator` service (V2)
- Extend `AssessmentCompletionRecord` with reason_codes, pending_work_summary, bound_reached, evaluation_version
- `FullAssessmentService.finalize_assessment()` 
- `scan_jobs` calls finalize separately from job status
- Settings: `ASSESSMENT_COMPLETION_V2`, `PENDING_WORK_AWARE_COMPLETION`, `BIND_JOB_STATUS_TO_ASSESSMENT=false`
