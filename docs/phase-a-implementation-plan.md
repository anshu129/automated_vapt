# Phase A Implementation Plan — Capability Abstraction

## 1. Objective

Prove the **control plane** before real tool integration:

- Controller requests **capabilities**, not tools
- Providers are **replaceable** via Capability Registry
- **Evidence quality** drives alternate provider/profile selection deterministically
- **Scope rules** always applied
- Fake providers only

**Prerequisites:** Phase 1 core state model (or minimal subset: scans, tasks, task_runs, events, assets).

---

## 2. Scope

### In scope

| Deliverable | Package |
|-------------|---------|
| `Capability` enum + groups | `domain/enums.py` |
| `Capability`, `CapabilityProvider`, `CapabilityExecutionProfile` models | `domain/models/capability.py` |
| `EvidenceQualityDecision` model | `domain/models/evidence_quality.py` |
| Capability Registry | `capabilities/registry.py` |
| Capability Selection Engine | `capabilities/selection.py` |
| Evidence Quality Evaluator | `evidence/quality.py` |
| Marginal Discovery Gain Engine (stub metrics) | `planning/discovery_gain.py` |
| Fake provider adapters (2 per capability min) | `adapters/fake/` |
| Controller hook on TASK_COMPLETED | `controller/adaptive.py` |
| Migration 002 | `alembic/versions/002_capability_abstraction.py` |
| Seed capabilities + profiles | `alembic/versions/002a_seed_capabilities.py` |
| Unit + integration + property tests | `tests/` |

### Out of scope

- Real security tools (Phase J)
- Surface completeness, applicability, test matrix (Phases C–E)
- Verdict engine, recursive correlation (Phases G–H)
- Credentials (Phase I)
- MCP / Mistral extensions

---

## 3. Fake provider vertical slice

### Scenario

```
1. SCAN_STARTED → DOMAIN_ACCEPTED
2. Fake PASSIVE_SUBDOMAIN_DISCOVERY → HOSTNAME_DISCOVERED
3. Fake DNS_RESOLUTION @ STANDARD → no response
4. EVIDENCE_QUALITY_EVALUATED → NEGATIVE_INCONCLUSIVE
5. Selection engine → DNS_RESOLUTION @ HIGH_LATENCY via fake provider B
6. Fake provider B → DNS_RESOLVED
7. Fake HTTP_PROBING → HTTP_SERVICE_CONFIRMED
8. Discovery gain metrics recorded for both DNS providers
```

### Fake adapters required

| Capability | Fake Provider A | Fake Provider B |
|------------|-----------------|-----------------|
| `PASSIVE_SUBDOMAIN_DISCOVERY` | `fake-subfinder` | `fake-amass-passive` |
| `DNS_RESOLUTION` | `fake-dnsx-silent` (no response) | `fake-dnsx-resolve` (success) |
| `HTTP_PROBING` | `fake-httpx` | — |

Each fake adapter: manifest + adapter + parser + fixture JSON.

---

## 4. Implementation tasks

### Sprint A.1 — Domain and DB (3 days)

- [ ] Add capability enums and Pydantic models
- [ ] Alembic migration 002 (tables from database-migration-plan.md §3)
- [ ] Seed capabilities + execution profiles
- [ ] Repository: `CapabilityProviderRepository`, `EvidenceQualityDecisionRepository`, `DiscoveryGainMetricRepository`
- [ ] Extend `Task` ORM with provider_id, profile_id

### Sprint A.2 — Evidence quality (3 days)

- [ ] Implement `EvidenceQualityEvaluator` with rules from evidence-quality-model.md
- [ ] Unit tests per reason code
- [ ] Property test: single silent response ≠ NEGATIVE_CONCLUSIVE under NO_DISCOVERY_ASSUMPTION

### Sprint A.3 — Registry and selection (3 days)

- [ ] `CapabilityRegistry.get_eligible(capability, scope, policy)`
- [ ] `CapabilitySelectionEngine.select()` deterministic sort
- [ ] `MarginalDiscoveryGainEngine` stub (increment metrics; threshold check)
- [ ] Unit tests: same inputs → same provider

### Sprint A.4 — Fake adapters + controller hook (4 days)

- [ ] Fake adapter base class implementing manifest contract
- [ ] 5 fake providers with parsers emitting events
- [ ] Extend controller: on `TASK_COMPLETED` → evaluate → branch
- [ ] Integration test: full vertical slice scenario
- [ ] Property test: out-of-scope capability never scheduled

### Sprint A.5 — API and observability (2 days)

- [ ] `GET /capabilities` — list capabilities and enabled providers (no secrets)
- [ ] `GET /scans/{id}/discovery-gain` — metrics read
- [ ] Structured logs: `evidence_quality_status`, `selected_provider`
- [ ] CLI: `capabilities-list`

---

## 5. Key interfaces

```python
# capabilities/registry.py
class CapabilityRegistry(Protocol):
    def list_capabilities(self) -> list[CapabilityDefinition]: ...
    def get_eligible_providers(
        self, capability: Capability, ctx: SelectionContext
    ) -> list[CapabilityProvider]: ...

# capabilities/selection.py
class CapabilitySelectionEngine(Protocol):
    def select(
        self,
        capability: Capability,
        eligible: list[CapabilityProvider],
        ctx: SelectionContext,
    ) -> SelectedCapability: ...

# evidence/quality.py
class EvidenceQualityEvaluator(Protocol):
    def evaluate(self, ...) -> EvidenceQualityDecision: ...
```

---

## 6. Controller integration point

```python
# After task run completes and parser emits events:
decision = evidence_quality_evaluator.evaluate(...)
decision_repo.save(decision)
event_bus.emit(EVIDENCE_QUALITY_EVALUATED, decision)

if decision.status in INCONCLUSIVE_STATUSES:
    next_cap = capability_selection_engine.select_alternate(decision, ...)
    if next_cap:
        controller.create_task(next_cap)  # scope check inside
elif decision.status == POSITIVE:
    controller.continue_workflow(...)
```

---

## 7. Tests required

| Test | Type |
|------|------|
| Provider selection deterministic | Unit |
| Scope denies out-of-scope capability | Unit |
| Single DNS silence → INCONCLUSIVE not CONCLUSIVE | Property |
| Alternate provider scheduled after INCONCLUSIVE | Integration |
| Duplicate task not created for same uniqueness key | Property |
| Discovery gain threshold stops third provider | Integration |
| Fake parser malformed output → FAILED not crash | Failure |
| Controller requests capability code not tool name | Unit |

---

## 8. Definition of done

- [ ] Migration 002 applied
- [ ] Vertical slice integration test passes
- [ ] `make test lint typecheck` clean
- [ ] No real security tool binaries required
- [ ] architecture docs and ADRs 0005–0006 reflected in code
- [ ] Gap analysis items for Phase A marked addressable

---

## 9. Handoff to Phase B

Phase B adds full adaptive recon slice: service discovery → HTTP → crawl → endpoint inventory with evidence quality at each stage. Reuses Phase A registry, evaluator, and selection engine unchanged.

---

## 10. Directory additions (Phase A)

```
src/vapt_platform/
├── capabilities/
│   ├── registry.py
│   ├── selection.py
│   └── matcher.py          # stub for Phase B
├── evidence/
│   ├── quality.py
│   └── rules/              # YAML or Python rule modules
├── planning/
│   ├── adaptive_recon.py   # planner stub
│   └── discovery_gain.py
├── adapters/
│   └── fake/
│       ├── subfinder.py
│       ├── dnsx_silent.py
│       ├── dnsx_resolve.py
│       └── httpx.py
└── controller/
    └── adaptive.py         # TASK_COMPLETED hook
```

---

## 11. References

- `extension-gap-analysis.md`
- `adaptive-recon.md`
- `capability-registry.md`
- `evidence-quality-model.md`
- `database-migration-plan.md` §3
- ADR-0005, ADR-0006
