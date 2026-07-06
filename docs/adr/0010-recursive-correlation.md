# ADR-0010: Recursive Correlation After Validation Results

## Status

Accepted

## Date

2026-07-06

## Context

One-pass correlation misses hypotheses created when validation results update trust relationships, coverage, or shared infrastructure understanding.

## Decision

1. **RecursiveCorrelationEngine** runs after `VALIDATION_RESULT_RECORDED`, `TEST_EXECUTION_COMPLETED`, and `VERDICT_ISSUED`
2. Results update evidence graph, relationship confidence, hypotheses, and test requirements
3. New hypotheses feed **TestPlanner** in a bounded loop (max depth, dedup keys)
4. Correlation remains deterministic; rule_id + facts required on every output

## Consequences

**Positive:** Cross-application and trust-boundary hypotheses emerge from validated evidence.

**Negative:** Cycle guards required; careful idempotency testing.

## References

- `recursive-correlation.md`
- `test-planner.md`
