# ADR-0001: Deterministic Event-Driven Recon Controller

## Status

Accepted

## Date

2026-07-06

## Context

The platform must correlate observations from multiple sources, maintain persistent environment state, and schedule assessment work without becoming a thin wrapper around security tools. Assessment quality depends on reproducible decisions about what to scan next, what constitutes duplicate work, and how observations update the asset model.

We need a central orchestration component that:

- Reacts to domain events rather than imperative scripts
- Operates on capabilities, not tool-specific CLI syntax
- Produces auditable, deterministic decisions
- Supports workflow and rule versioning per scan

Alternatives considered:

1. **Imperative pipeline script** — Simple but not event-driven; hard to resume, deduplicate, or extend.
2. **DAG-only orchestrator (e.g. Airflow)** — Good for batch pipelines; poor fit for dynamic asset-driven fan-out.
3. **Event-driven controller with declarative workflows** — Matches the product's correlation and coverage requirements.

## Decision

Implement a **Deterministic Event-Driven Recon Controller** as the sole authority for post-ingestion orchestration logic.

### Core equation

```
NEXT_ACTIONS = F(CURRENT_STATE, NEW_EVENT, WORKFLOW_RULES, OPERATIONAL_POLICY, SCOPE_POLICY)
```

### Processing pipeline (fixed order)

1. Validate event schema
2. Persist event (append-only, idempotent)
3. Create/update observations
4. Update asset inventory (via Asset Identity Resolution Engine)
5. Update relationships (non-destructive)
6. Match workflow transitions
7. Evaluate eligibility, operational, and stopping rules
8. Generate candidate tasks
9. Scope-validate each task
10. Deduplicate by uniqueness key
11. Persist tasks
12. Notify scheduler

### Determinism requirements

- Same event + same scan state + same workflow/rule versions → same tasks created
- Rule evaluations produce stored `RuleEvaluationResult` with inputs and outputs
- No randomness in task generation
- No AI involvement in controller decisions

### Boundaries

| In scope | Out of scope |
|----------|--------------|
| Event → observation → asset → task | Tool CLI construction (adapters) |
| Workflow transition matching | Parser implementation |
| Task deduplication | Worker execution |
| Scope validation invocation | Correlation/hypothesis logic (separate engines, triggered by events) |

## Consequences

### Positive

- Reproducible scan behavior aids debugging and compliance
- Event log enables replay and offline reprocessing
- Clear separation from tool adapters simplifies testing (fake adapters in Phase 2)
- Workflow versioning supports scan-to-scan comparison

### Negative

- Controller complexity requires careful idempotency design
- Event ordering per scan must be guaranteed (partitioned processing)
- Internal processing stages (hypothesis reevaluation) must not create circular event storms

### Mitigations

- Idempotency keys per event type (see event-catalog.md)
- Monotonic sequence numbers per scan
- Internal stages invoked synchronously within controller transaction where possible
- Property tests for duplicate task prevention

## Compliance

- Supports audit requirements via event store and rule evaluation records
- Prevents scanner output from directly creating confirmed vulnerabilities (observation-first path)

## References

- `docs/architecture.md` §4.4
- `docs/event-catalog.md`
- `docs/state-machines.md` §3
