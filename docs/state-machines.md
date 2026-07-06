# State Machines

## 1. Overview

This document defines lifecycle state machines for scan, controller processing, tasks, hypotheses, validation, and findings. All transitions are **deterministic** and auditable.

---

## 2. Scan lifecycle

```
                    ┌─────────────┐
                    │   CREATED   │
                    └──────┬──────┘
                           │ SCAN_STARTED
                           ▼
         ┌─────────────────────────────────┐
         │            RUNNING              │◄──── SCAN_RESUMED
         └──────┬───────────────┬──────────┘
                │               │
       SCAN_PAUSED         SCAN_COMPLETED
                │               │
                ▼               ▼
         ┌─────────────┐ ┌─────────────┐
         │   PAUSED    │ │  COMPLETED  │
         └─────────────┘ └─────────────┘
                │
       SCAN_CANCELLED (from CREATED, RUNNING, PAUSED)
                │
                ▼
         ┌─────────────┐
         │  CANCELLED  │
         └─────────────┘
```

### Transition rules

| From | Event/Action | To | Side Effects |
|------|--------------|-----|--------------|
| CREATED | `SCAN_STARTED` | RUNNING | Emit DOMAIN_ACCEPTED per scope; start event processor |
| RUNNING | `SCAN_PAUSED` | PAUSED | Defer READY tasks; wait for RUNNING lease expiry |
| PAUSED | `SCAN_RESUMED` | RUNNING | Promote deferred tasks |
| RUNNING | `SCAN_COMPLETED` | COMPLETED | Final coverage snapshot; change detection |
| CREATED, RUNNING, PAUSED | `SCAN_CANCELLED` | CANCELLED | Cancel pending tasks; audit |
| RUNNING | STOPPING_RULE satisfied | COMPLETED | Automatic completion |

**Invariant:** No new tasks created when status is PAUSED, COMPLETED, or CANCELLED.

---

## 3. Controller processing state machine

The controller maintains per-scan processing state separate from scan status.

```
    ┌──────────┐
    │  IDLE    │  (no pending events)
    └────┬─────┘
         │ event received
         ▼
    ┌──────────┐
    │ VALIDATE │  schema check
    └────┬─────┘
         │ valid
         ▼
    ┌──────────┐
    │ PERSIST  │  append event (if not duplicate)
    └────┬─────┘
         ▼
    ┌──────────┐
    │ OBSERVE  │  create/update observations
    └────┬─────┘
         ▼
    ┌──────────┐
    │  ASSET   │  identity resolution + inventory
    └────┬─────┘
         ▼
    ┌──────────┐
    │  GRAPH   │  relationship updates
    └────┬─────┘
         ▼
    ┌──────────┐
    │ WORKFLOW │  match transitions
    └────┬─────┘
         ▼
    ┌──────────┐
    │  RULES   │  eligibility, operational, stopping
    └────┬─────┘
         ▼
    ┌──────────┐
    │  TASKS   │  generate, dedup, scope-check, persist
    └────┬─────┘
         ▼
    ┌──────────┐
    │ SCHEDULE │  notify scheduler
    └────┬─────┘
         ▼
    ┌──────────┐
    │  IDLE    │
    └──────────┘
```

### Error handling

| Stage | Failure | Action |
|-------|---------|--------|
| VALIDATE | Schema error | Reject event; audit; no retry |
| PERSIST | DB error | Retry with backoff; dead-letter after N attempts |
| OBSERVE–GRAPH | Domain error | Partial rollback; event marked FAILED_PROCESSING |
| TASKS | Scope DENY | Skip task; audit scope decision |

### Idempotency

If event dedup key exists: skip OBSERVE–SCHEDULE for new side effects; update `last_seen` timestamps only.

---

## 4. Task lifecycle

```
                         ┌──────────┐
                         │ PENDING  │  (dependencies unmet)
                         └────┬─────┘
                              │ dependencies satisfied
                              ▼
                         ┌──────────┐
              ┌─────────│  READY   │─────────┐
              │         └────┬─────┘         │
              │ defer        │ claim         │ cancel
              ▼              ▼               ▼
         ┌──────────┐  ┌──────────┐    ┌───────────┐
         │ DEFERRED │  │ CLAIMED  │    │ CANCELLED │
         └────┬─────┘  └────┬─────┘    └───────────┘
              │             │ start
              │ promote     ▼
              │        ┌──────────┐
              └───────►│ RUNNING  │
                       └────┬─────┘
                            │
              ┌─────────────┼─────────────┐
              │ success     │ retryable   │ terminal
              ▼             ▼             ▼
         ┌──────────┐ ┌──────────────┐ ┌────────────────┐
         │COMPLETED │ │FAILED_RETRYABLE│ │FAILED_TERMINAL│
         └──────────┘ └──────┬───────┘ └────────────────┘
                               │ backoff elapsed
                               ▼
                          ┌──────────┐
                          │  READY   │
                          └──────────┘
```

### Task states

| State | Description |
|-------|-------------|
| `PENDING` | Created; waiting on TaskDependency |
| `READY` | Eligible for scheduling |
| `CLAIMED` | Worker holds lease |
| `RUNNING` | Tool execution in progress |
| `COMPLETED` | Success; parser events emitted |
| `FAILED_RETRYABLE` | Will retry after backoff |
| `FAILED_TERMINAL` | No further retries |
| `DEFERRED` | Operational policy delay (`defer_until`) |
| `CANCELLED` | Scan paused/cancelled or rule stop |

### Uniqueness

```
uniqueness_key = hash(scan_id + capability + normalized_target + configuration_hash)
```

Second task with same key: rejected at persistence (audit only).

### Lease and recovery

- Lease duration: configurable per capability (default 2× timeout)
- Worker heartbeat extends lease
- Expired lease: task returns to READY; `retry_count` unchanged unless RUNNING exceeded timeout (then FAILED_RETRYABLE)

### Concurrency gates (scheduler)

Checked before READY → CLAIMED:

1. Global concurrency limit
2. Per-capability limit
3. Per-target (normalized_target) limit
4. Per-domain limit (extracted from target)

---

## 5. Hypothesis lifecycle

```
    ┌───────────┐
    │ PROPOSED  │  initial creation from correlation/hypothesis rules
    └─────┬─────┘
          │
    ┌─────┴──────────────────┐
    │ insufficient evidence   │ sufficient evidence
    ▼                         ▼
┌─────────────────┐    ┌──────────────────────┐
│NEEDS_MORE_EVIDENCE│    │ READY_FOR_VALIDATION │
└────────┬────────┘    └──────────┬───────────┘
         │                          │ validation task assigned
         │ evidence arrives         ▼
         │                 ┌────────────────────────┐
         └────────────────►│ VALIDATION_IN_PROGRESS │
                           └──────────┬─────────────┘
                                      │
              ┌───────────────────────┼───────────────────────┐
              │ confirmed           │ rejected              │ inconclusive
              ▼                     ▼                       ▼
       ┌────────────┐        ┌────────────┐         ┌──────────────┐
       │ CONFIRMED  │        │  REJECTED  │         │ INCONCLUSIVE │
       └────────────┘        └────────────┘         └──────────────┘
```

### Transition table

| From | Trigger | To |
|------|---------|-----|
| PROPOSED | confidence < threshold | NEEDS_MORE_EVIDENCE |
| PROPOSED | confidence ≥ threshold, validation reqs defined | READY_FOR_VALIDATION |
| NEEDS_MORE_EVIDENCE | supporting evidence added | PROPOSED (re-evaluate) |
| READY_FOR_VALIDATION | ValidationTask → IN_PROGRESS | VALIDATION_IN_PROGRESS |
| VALIDATION_IN_PROGRESS | ValidationResult CONFIRMED | CONFIRMED |
| VALIDATION_IN_PROGRESS | ValidationResult REJECTED | REJECTED |
| VALIDATION_IN_PROGRESS | ValidationResult INCONCLUSIVE | INCONCLUSIVE |
| Any | contradicting evidence overwhelms | REJECTED |
| CONFIRMED | — | Terminal |
| REJECTED | — | Terminal |

**Invariant:** CONFIRMED requires ValidationResult with outcome CONFIRMED and linked evidence IDs.

---

## 6. Validation task lifecycle

```
    ┌──────┐
    │ OPEN │
    └──┬───┘
       │ assign
       ▼
    ┌──────────┐
    │ ASSIGNED │
    └────┬─────┘
         │ analyst starts
         ▼
    ┌─────────────┐
    │ IN_PROGRESS │
    └──────┬──────┘
           │
    ┌──────┼──────┬──────────┐
    │      │      │          │
    ▼      ▼      ▼          ▼
┌────────┐ ┌──────────┐ ┌─────────────┐ ┌────────────┐
│BLOCKED │ │VALIDATED │ │  REJECTED   │ │INCONCLUSIVE│
└────────┘ └──────────┘ └─────────────┘ └────────────┘
```

| State | Description |
|-------|-------------|
| OPEN | Created by hypothesis engine or coverage gap |
| ASSIGNED | `assigned_to` set |
| IN_PROGRESS | Analyst actively working |
| BLOCKED | Waiting on dependency or access |
| VALIDATED | Hypothesis confirmed |
| REJECTED | Hypothesis rejected |
| INCONCLUSIVE | Insufficient evidence after review |

**Invariant:** Platform never auto-transitions to VALIDATED. Only `ValidationService.record_result()` from authorized analyst action.

---

## 7. Normalized finding status

```
    ┌──────┐
    │ OPEN │◄──── REOPENED
    └──┬───┘
       │
   ┌───┴────┐
   │        │
   ▼        ▼
RESOLVED  SUPPRESSED
```

Findings transition to RESOLVED via analyst action or validation confirming remediation. REOPENED via change detection or new scanner import.

**Distinction:** OPEN finding ≠ hypothesis ≠ confirmed vulnerability.

---

## 8. Confirmed finding creation gate

```
ValidationTask.status == VALIDATED
        AND
ValidationResult.outcome == CONFIRMED
        AND
ValidationResult.evidence_ids.length > 0
        AND
Hypothesis.status == CONFIRMED (if hypothesis-linked)
        ↓
ConfirmedFinding created
```

Property test: `confirmed finding cannot exist without required validation state`.

---

## 9. Operational profile state

Per-scan or per-target profile affects scheduler and rule engine.

```
DEFAULT ──(RATE_LIMIT_OBSERVED)──► CAUTIOUS ──(recovery)──► DEFAULT
```

CAUTIOUS effects:
- Reduced concurrency
- Increased backoff
- Deferred non-critical capabilities

---

## 10. Workflow stage state (per scan)

Stages tracked in scan metadata:

```
DISCOVERY → DNS_VALIDATION → SERVICE_DISCOVERY → HTTP_CHARACTERIZATION
    → WEB_CRAWLING → JS_ANALYSIS → API_INVENTORY → FINDING_PROCESSING
    → CORRELATION → COMPLETE
```

Stages advance via `STAGE_COMPLETED` events. `STAGE_LOW_GAIN` may skip or halt stages per STOPPING_RULE.

Not all stages apply to all scopes (passive-only skips active stages).

---

## 11. AI enrichment status

```
REQUESTED → IN_PROGRESS → VALID | INVALID | FALLBACK
```

INVALID: output failed Pydantic validation; not stored as enrichment.
FALLBACK: AI unavailable; deterministic summary used if configured.

AI enrichment status does not affect any core state machine.
