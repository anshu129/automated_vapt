# State Machines — Extensions

## 1. Evidence quality decision flow

```
TASK_COMPLETED
      ↓
EVALUATING
      ↓
┌─────┴─────┬─────────┬──────────┐
│           │         │          │
POSITIVE  NEG_CONC  NEG_INCONC  FAILED/RATE_LIMITED/...
│           │         │          │
▼           ▼         ▼          ▼
CONTINUE  RECORD    SELECT     RETRY/DEFER/
WORKFLOW  NEGATIVE  ALTERNATE  MANUAL_REVIEW
          EVIDENCE  CAPABILITY
```

Terminal states per decision: stored in `evidence_quality_decisions`; does not replace task state.

---

## 2. Adaptive recon planning loop

```
STAGE_ACTIVE
      ↓
CAPABILITY_EXECUTING
      ↓
EVIDENCE_EVALUATED
      ↓
┌── sufficient ──► STAGE_ADVANCE
└── insufficient
      ↓
ALTERNATE_SELECTION
      ↓
┌── provider available + gain ok ──► CAPABILITY_EXECUTING
├── no provider ──► INCONCLUSIVE_STAGE
└── gain threshold not met ──► STAGE_COMPLETE (low gain)
```

Bounded by `MarginalDiscoveryGainEngine` and `STOPPING_RULE`.

---

## 3. TestPlan lifecycle

```
DRAFT
  ↓
PENDING_APPROVAL  (if STATE_CHANGING or policy requires)
  ↓                    ↓
APPROVED            CANCELLED
  ↓
SCHEDULED
  ↓
EXECUTING
  ↓
┌────────┬────────┐
▼        ▼        ▼
COMPLETED FAILED  CANCELLED
```

| State | Description |
|-------|-------------|
| `DRAFT` | Created by TestPlanner |
| `PENDING_APPROVAL` | Awaiting analyst |
| `APPROVED` | Ready for orchestrator |
| `SCHEDULED` | Tasks created |
| `EXECUTING` | TestExecution in progress |
| `COMPLETED` | Evidence collected; verdict pending |
| `FAILED` | Execution failed |
| `CANCELLED` | Analyst or scan cancel |

API: `POST /test-plans/{id}/approve` transitions `PENDING_APPROVAL → APPROVED`.

---

## 4. TestExecution lifecycle

```
PENDING → RUNNING → COMPLETED
                 → FAILED_RETRYABLE → RUNNING
                 → FAILED_TERMINAL
```

Same lease/recovery semantics as Task (inherits worker pool).

---

## 5. TestRequirement coverage status

```
NOT_APPLICABLE (terminal)
NOT_TESTED
PLANNED
TESTING
TESTED_NO_EVIDENCE
PARTIALLY_TESTED
CONFIRMED_ISSUE
INCONCLUSIVE
```

Transitions driven by TestExecution, VerdictEngine, and ValidationResult.

---

## 6. Verdict lifecycle

```
UNTESTED
    ↓ test plan starts
TESTING
    ↓ evidence evaluated
┌───┼───┬───────────┬──────────────┐
▼   ▼   ▼           ▼              ▼
CONFIRMED REJECTED INCONCLUSIVE PARTIALLY_VALIDATED REQUIRES_MANUAL_REVIEW
```

**Gate to ConfirmedFinding:**

```
Verdict.status == CONFIRMED
AND required evidence IDs present
AND (ValidationResult.outcome == CONFIRMED if manual path)
```

---

## 7. Recursive correlation cycle

```
IDLE
  ↓ trigger received
PROCESSING (depth = n)
  ↓
┌── new hypotheses/requirements ──► depth < max ──► PROCESSING (depth = n+1)
├── cycle limit ──► CYCLE_LIMIT_REACHED
└── no new items ──► IDLE
```

Max depth default: 10 per scan session.

---

## 8. Assessment completion state machine

```
EVALUATING
    ↓
┌── all criteria met ──► COMPLETE
├── accepted gaps documented ──► COMPLETE_WITH_ACCEPTED_GAPS
├── open blockers ──► INCOMPLETE or BLOCKED
└── unresolvable conflicts ──► INCONCLUSIVE
```

`SCAN_COMPLETED` only when:

```
AssessmentCompletionRecord.status IN (COMPLETE, COMPLETE_WITH_ACCEPTED_GAPS)
```

---

## 9. Credential reference lifecycle

```
ACTIVE → EXPIRED (time-based)
      → REVOKED (analyst action)
```

Revoked credentials cannot establish new AuthenticationContext.

---

## 10. Scan lifecycle extension

Add to scan completion paths:

| From | Condition | To |
|------|-----------|-----|
| RUNNING | `ASSESSMENT_COMPLETION_EVALUATED` + COMPLETE | COMPLETED |
| RUNNING | Queue empty but INCOMPLETE completion | RUNNING (do not auto-complete) |
| RUNNING | Analyst force complete + accepted_gaps | COMPLETED |

---

## 11. Cross-references

- Base state machines: `state-machines.md`
- Test planner: `test-planner.md`
- Assessment completion: `assessment-completion.md`
