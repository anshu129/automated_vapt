# Verdict Engine

## 1. Purpose

Formalize outcomes for hypotheses and test requirements using explicit evidence requirements. Separates **applicability**, **testing**, and **confirmation**.

---

## 2. VerdictEngine

```python
class VerdictEngine(Protocol):
    def evaluate(
        self,
        hypothesis_id: UUID,
        test_execution: TestExecution | None,
        validation_result: ValidationResult | None,
        evidence_graph: EvidenceSubgraph,
        requirements: EvidenceRequirements,
    ) -> Verdict: ...
```

---

## 3. Verdict entity

| Field | Type | Description |
|-------|------|-------------|
| `id` | UUID | |
| `hypothesis_id` | UUID | |
| `test_plan_id` | UUID | Optional |
| `validation_result_id` | UUID | Optional |
| `status` | VerdictStatus | See §4 |
| `confidence` | float | |
| `supporting_evidence_ids` | UUID[] | |
| `contradicting_evidence_ids` | UUID[] | |
| `rule_ids` | string[] | |
| `explanation` | text | |
| `issued_at` | timestamp | |

---

## 4. VerdictStatus

| Status | Meaning |
|--------|---------|
| `UNTESTED` | No validation attempted |
| `TESTING` | Plan in progress |
| `CONFIRMED` | Evidence requirements met |
| `REJECTED` | Hypothesis disproven |
| `INCONCLUSIVE` | Insufficient evidence |
| `PARTIALLY_VALIDATED` | Some requirements met |
| `REQUIRES_MANUAL_REVIEW` | Automated path exhausted |

---

## 5. Evidence requirements (example)

**Hypothesis:** Known component vulnerability may apply.

| Requirement | Threshold |
|-------------|-----------|
| Technology identity confidence | ≥ 0.8 |
| Version confidence | ≥ 0.7 |
| Applicability condition evidence | present |
| Scanner/template evidence | optional supporting |
| Contradicting version evidence | must not outweigh |

### Insufficient for CONFIRMED

- Product name fingerprint only
- CVE exists for some version of product (without version match)
- AI model believes likely
- Scanner severity alone

---

## 6. Verdict → downstream effects

| Verdict | Actions |
|---------|---------|
| CONFIRMED | Create ConfirmedFinding (if vuln class); update applicability state; emit `VERDICT_ISSUED` |
| REJECTED | Update hypothesis REJECTED; close validation tasks |
| INCONCLUSIVE | Keep backlog open; may trigger alternate test plan |
| Any | Recursive Correlation Engine reevaluates graph |

---

## 7. State machine

See `state-machines-extensions.md` §6.

Gate for ConfirmedFinding:

```
Verdict.status == CONFIRMED
AND ValidationResult.outcome == CONFIRMED (if manual path)
AND supporting_evidence_ids meets requirements
```

---

## 8. Distinction from applicability

| Layer | Question |
|-------|----------|
| Applicability | Should this class be tested? |
| Test matrix | Has testing been attempted? |
| Verdict | What was the outcome of testing? |

---

## 9. References

- ADR-0007
- `evidence-graph.md`
- `recursive-correlation.md`
