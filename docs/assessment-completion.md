# Assessment Completion

## 1. Purpose

Determine when an assessment is truly complete based on surface coverage, vulnerability class coverage, test matrix state, validation backlog, and unresolved contradictions — **not** merely because the task queue is empty.

---

## 2. AssessmentCompletionEvaluator

```python
class AssessmentCompletionEvaluator(Protocol):
    def evaluate(self, scan_id: UUID) -> AssessmentCompletionRecord: ...
```

---

## 3. AssessmentCompletionRecord

| Field | Type | Description |
|-------|------|-------------|
| `id` | UUID | |
| `scan_id` | UUID | |
| `status` | CompletionStatus | See §4 |
| `completion_reasons` | JSONB | Structured reasons |
| `blocking_items` | UUID[] | Tasks, gaps, contradictions |
| `accepted_gaps` | JSONB | Analyst-accepted omissions |
| `metrics` | JSONB | Coverage summaries |
| `evaluated_at` | timestamp | |
| `evaluated_by` | string | system or analyst |

---

## 4. CompletionStatus

| Status | Meaning |
|--------|---------|
| `COMPLETE` | All required dimensions satisfied |
| `COMPLETE_WITH_ACCEPTED_GAPS` | Analyst accepted documented gaps |
| `INCOMPLETE` | Material gaps remain |
| `BLOCKED` | Waiting on external dependency (creds, approval) |
| `INCONCLUSIVE` | Unresolvable evidence conflicts |

---

## 5. Completion criteria checklist

| Dimension | Source |
|-----------|--------|
| Discovery coverage | SurfaceCompletenessEngine + gain metrics |
| DNS validation | Surface dimensions |
| Service discovery | Surface dimensions |
| HTTP characterization | Surface dimensions |
| Crawl / historical / content / parameter / JS / API | Surface dimensions |
| Authenticated coverage | CredentialContextManager |
| Role coverage | RoleContext |
| Applicable vulnerability class coverage | AssetTestMatrix |
| Automated validation completion | TestExecution records |
| Manual validation backlog | Open ValidationTasks |
| Inconclusive evidence | EvidenceQualityDecision count |
| Unresolved contradictions | CONFLICTING evidence links |
| Pending test plan approvals | STATE_CHANGING plans |

---

## 6. Scan completion interaction

`SCAN_COMPLETED` event may only fire when:

```
CompletionStatus in (COMPLETE, COMPLETE_WITH_ACCEPTED_GAPS)
OR analyst forces complete with documented accepted_gaps
```

Queue empty alone does **not** trigger completion. Controller calls AssessmentCompletionEvaluator periodically and on stage transitions.

---

## 7. API

`GET /scans/{id}/completion-status` → AssessmentCompletionRecord

MCP: `get_assessment_completion_status(scan_id)`

---

## 8. Report section

Final report includes:

- Completion status and reasons
- Accepted gaps with analyst sign-off
- Untested applicable classes
- Open manual backlog count
- Inconclusive hypotheses count

---

## 9. References

- `surface-completeness.md`
- `test-planner.md`
- `verdict-engine.md`
- ADR-0008
