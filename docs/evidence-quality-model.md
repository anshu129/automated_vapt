# Evidence Quality Model

## 1. Purpose

Formalize how the platform interprets tool execution results before drawing conclusions or advancing workflow. Prevents false negatives from incomplete evidence.

---

## 2. EvidenceQualityEvaluator

### Interface

```python
class EvidenceQualityEvaluator(Protocol):
    def evaluate(
        self,
        task: Task,
        execution_result: TaskRunResult,
        observations: list[Observation],
        target_context: TargetContext,
        previous_attempts: list[EvidenceQualityDecision],
    ) -> EvidenceQualityDecision: ...
```

### EvidenceQualityDecision

| Field | Type | Description |
|-------|------|-------------|
| `id` | UUID | |
| `task_run_id` | UUID | |
| `status` | EvidenceQualityStatus | See §3 |
| `confidence` | float | 0.0–1.0 |
| `reason_codes` | string[] | Machine-readable codes |
| `explanation` | text | Deterministic human text |
| `recommended_next_capability` | Capability \| None | |
| `recommended_provider_id` | UUID \| None | |
| `eligible_alternate_profiles` | string[] | |
| `retry_allowed` | bool | |
| `manual_review_required` | bool | |
| `rule_ids` | string[] | Rules that fired |
| `evaluated_at` | timestamp | |

---

## 3. Evidence quality statuses

| Status | Definition |
|--------|------------|
| `POSITIVE` | Observations support claimed surface/asset state |
| `NEGATIVE_CONCLUSIVE` | Reliable evidence of absence |
| `NEGATIVE_INCONCLUSIVE` | Absence not established |
| `PARTIAL` | Some dimensions covered, others not |
| `CONFLICTING` | Mutually incompatible observations |
| `FAILED` | Execution failed without reliable observation |
| `RATE_LIMITED` | Throttling detected |
| `AUTH_REQUIRED` | Conclusive result needs authenticated context |
| `BLOCKED_BY_POLICY` | Safety or engagement policy blocks |
| `UNKNOWN` | Cannot classify |

---

## 4. Reason codes (examples)

| Code | Meaning |
|------|---------|
| `NO_RESPONSE_SINGLE_PROVIDER` | One provider, no data |
| `NXDOMAIN_MULTI_RESOLVER` | Conclusive DNS negative |
| `TIMEOUT_HIGH_LATENCY_CANDIDATE` | Suggest HIGH_LATENCY profile |
| `HTTP_429_RATIO_EXCEEDED` | Rate limited |
| `PARTIAL_PORT_SCAN` | Some ports scanned, not all eligible |
| `HISTORICAL_ONLY_URL` | URL from archive, not live-confirmed |
| `WILDCARD_DNS_SUSPECTED` | Resolution unreliable |
| `CONFLICTING_A_RECORDS` | Competing DNS data |
| `AUTH_WALL_DETECTED` | 401/403 consistent; auth needed |
| `TOOL_ERROR_NON_RETRYABLE` | Terminal failure |

---

## 5. Deterministic evaluation rules (examples)

### DNS resolution

```
IF observations contain A/AAAA/CNAME
THEN status = POSITIVE

IF all resolvers return NXDOMAIN
AND wildcard_check = negative
AND attempts >= min_resolver_count
THEN status = NEGATIVE_CONCLUSIVE

IF no response AND attempts < max_dns_attempts
AND policy != NO_DISCOVERY_ASSUMPTION
THEN status = NEGATIVE_INCONCLUSIVE
     recommended_next_capability = DNS_RESOLUTION
     eligible_alternate_profiles = [HIGH_LATENCY]

IF policy == NO_DISCOVERY_ASSUMPTION AND no response
THEN status = NEGATIVE_INCONCLUSIVE (never NEGATIVE_CONCLUSIVE from silence)
```

### HTTP probing

```
IF status_code in 200-399
THEN status = POSITIVE

IF connection refused from single probe
THEN status = NEGATIVE_INCONCLUSIVE (not conclusive closed)

IF consistent connection refused from N providers
THEN status = NEGATIVE_CONCLUSIVE
```

### Historical URL

```
IF observation_type == HISTORICAL_OBSERVATION
THEN status = PARTIAL
     recommended_next_capability = HTTP_PROBING or LIVE_CRAWLING
```

---

## 6. Integration with controller

On `TASK_COMPLETED`:

1. Parser emits observations
2. EvidenceQualityEvaluator runs
3. Decision persisted
4. Controller branches:
   - `POSITIVE` / `NEGATIVE_CONCLUSIVE` → normal workflow
   - `NEGATIVE_INCONCLUSIVE` / `PARTIAL` / `FAILED` → CapabilitySelectionEngine
   - `CONFLICTING` → store observations; emit `CONFLICTING_EVIDENCE_OBSERVED` event
   - `RATE_LIMITED` → operational profile → CAUTIOUS
   - `AUTH_REQUIRED` → check CredentialContextManager

Emit event: `EVIDENCE_QUALITY_EVALUATED`

---

## 7. Negative evidence storage

`NEGATIVE_CONCLUSIVE` creates `Observation` with `observation_type = NEGATIVE_EVIDENCE` linked to target asset. Does not delete positive competing observations.

---

## 8. Invariants

1. Single silent response ≠ `NEGATIVE_CONCLUSIVE` unless policy and rules explicitly allow
2. Evaluator is deterministic; no AI
3. Every decision references `rule_ids`
4. Historical observations never imply live surface without validation

---

## 9. References

- ADR-0006
- `adaptive-recon.md`
- `event-catalog-extensions.md` §3
