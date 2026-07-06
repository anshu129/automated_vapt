# Adaptive Reconnaissance

## 1. Purpose

Extend the deterministic Recon Controller into an **Adaptive Recon Controller** that selects capabilities and execution profiles based on evidence quality, marginal discovery gain, scope policy, and engagement constraints — without assuming absence from negative or empty tool output.

---

## 2. Problem statement

A tool returning no result does **not** imply:

- asset does not exist
- port is closed
- application is absent

The platform must distinguish evidence quality before advancing workflow or recording negative conclusions.

---

## 3. Adaptive Recon Controller

### Extended controller equation

```
NEXT_ACTIONS = F(
  CURRENT_STATE,
  NEW_EVENT,
  WORKFLOW_RULES,
  OPERATIONAL_POLICY,
  SCOPE_POLICY,
  EVIDENCE_QUALITY_STATE,      # NEW
  DISCOVERY_GAIN_STATE,        # NEW
  SURFACE_COMPLETENESS_STATE   # NEW (post-discovery)
)
```

### Processing pipeline (extended)

After worker task completion, before workflow transition:

```
TASK_COMPLETED
    ↓
EvidenceQualityEvaluator.evaluate()
    ↓
┌── POSITIVE / NEGATIVE_CONCLUSIVE ──► continue workflow
├── NEGATIVE_INCONCLUSIVE / PARTIAL / FAILED / RATE_LIMITED
│       ↓
│   CapabilitySelectionEngine.select_alternate()
│       ↓
│   MarginalDiscoveryGainEngine.should_continue_provider()? 
│       ↓
│   create alternate task OR mark INCONCLUSIVE OR manual review
└── CONFLICTING ──► store competing observations; hypothesis if rules match
```

### Adaptive Reconnaissance Planner

Orchestrates capability sequencing per asset/stage:

```python
class AdaptiveReconPlanner(Protocol):
    def plan_next_capabilities(
        self,
        scan_id: UUID,
        asset_id: UUID,
        stage: WorkflowStage,
        evidence_quality: EvidenceQualityDecision | None,
        gain_metrics: DiscoveryGainMetric | None,
        scope_snapshot: ScopeSnapshot,
        policy: EngagementPolicy,
    ) -> list[CapabilityPlanItem]: ...
```

`CapabilityPlanItem` fields: `capability`, `provider_id`, `execution_profile_id`, `priority`, `reasoning_trace`, `rule_ids`.

---

## 4. Evidence quality states

| Status | Meaning | Typical next action |
|--------|---------|---------------------|
| `POSITIVE` | Reliable positive observation | Continue workflow |
| `NEGATIVE_CONCLUSIVE` | Reliable absence (e.g. NXDOMAIN with multiple resolvers) | Record negative evidence; stop capability chain |
| `NEGATIVE_INCONCLUSIVE` | Absence not proven | Alternate profile or provider |
| `PARTIAL` | Incomplete surface | Complementary capability |
| `CONFLICTING` | Contradictory observations | Store both; correlation rules |
| `FAILED` | Tool/infra failure | Retry or alternate per FAILURE_RULE |
| `RATE_LIMITED` | Throttled | CAUTIOUS profile; defer |
| `AUTH_REQUIRED` | Auth needed for conclusive result | Credential context check |
| `BLOCKED_BY_POLICY` | Engagement policy blocks | Manual review or skip |
| `UNKNOWN` | Insufficient basis | Alternate capability or INCONCLUSIVE |

See `evidence-quality-model.md` for evaluator interface.

---

## 5. Execution profiles

Versioned, bounded, deterministic profiles:

| Profile | Behavior |
|---------|----------|
| `STANDARD` | Default timeouts and concurrency |
| `CAUTIOUS` | Reduced rate; longer backoff |
| `HIGH_LATENCY` | Extended timeouts for slow targets |
| `NO_DISCOVERY_ASSUMPTION` | Never infer absence from silence |
| `AUTHENTICATED` | Uses bound credential context |
| `PASSIVE_ONLY` | Passive capabilities only |

Profiles are **not** evasion techniques. They adjust timeouts, retry policy, resolver diversity, and provider selection within authorized scope.

Stored in `capability_execution_profiles` table; referenced by `Task.execution_profile_id`.

---

## 6. Example flow: hostname candidate

```
HOSTNAME_CANDIDATE (low confidence)
    ↓
DNS_RESOLUTION @ STANDARD profile
    ↓
NO RESPONSE
    ↓
EvidenceQualityEvaluator → NEGATIVE_INCONCLUSIVE
    ↓
Is absence conclusive? (rule: NO_DISCOVERY_ASSUMPTION policy)
    ├── NO → select alternate:
    │         - HIGH_LATENCY profile
    │         - alternate DNS provider (dnsx → massdns if gain justifies)
    ↓
Re-evaluate → POSITIVE (A record) | NEGATIVE_CONCLUSIVE (NXDOMAIN) | INCONCLUSIVE
    ↓
POSITIVE → SERVICE_DISCOVERY
NEGATIVE_CONCLUSIVE → record negative evidence; no further active DNS
INCONCLUSIVE → manual review flag; do not mark asset absent
```

---

## 7. Integration points

| Component | Role |
|-----------|------|
| `Capability Registry` | Eligible providers per capability |
| `Capability Selection Engine` | Deterministic provider pick |
| `Marginal Discovery Gain Engine` | Stop redundant providers |
| `Scope Manager` | Every planned capability scope-checked |
| `Test Safety Policy Engine` | Blocks unsafe automated validation |
| `Surface Completeness Engine` | Triggers gap-filling capabilities |

---

## 8. Controller invariants

1. Never infer asset absence from single-provider silence unless `NEGATIVE_CONCLUSIVE`
2. Historical observations require current-applicability validation
3. Provider selection is deterministic given same inputs + rule versions
4. AI does not select capabilities or profiles
5. MCP does not trigger capability execution

---

## 9. References

- ADR-0005: Capability routing
- ADR-0006: Evidence quality before alternate selection
- `capability-registry.md`
- `evidence-quality-model.md`
- `state-machines-extensions.md` §2
