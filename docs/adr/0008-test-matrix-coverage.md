# ADR-0008: Test Matrix as Assessment Coverage Source of Truth

## Status

Accepted

## Date

2026-07-06

## Context

Phase 0 `CoverageRecord` provides scan-level aggregate ratios. The extension requires per-asset knowledge of which vulnerability classes are applicable, tested, and confirmed.

Queue-empty is an unreliable completion signal.

## Decision

1. **AssetTestMatrix** + **TestRequirement** are the source of truth for assessment coverage
2. **SurfaceCoverageRecord** is source of truth for surface inventory completeness
3. **AssessmentCompletionEvaluator** uses matrix + surface + backlog — not queue depth
4. Scan-level `CoverageRecord` is derived for reporting only

## Consequences

**Positive:** Answers "what remains untested and why"; supports completion with accepted gaps.

**Negative:** More storage; matrix must be kept in sync via events.

## References

- `test-planner.md`
- `assessment-completion.md`
- `surface-completeness.md`
