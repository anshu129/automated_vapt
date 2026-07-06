# VAPT Platform — System Architecture

## 1. Purpose

This document defines the production architecture for an **authorized** Vulnerability Assessment, Reconnaissance Correlation, Attack Surface Mapping, and Security Hypothesis Generation Platform.

The platform is **not** a scanner wrapper. It maintains a persistent model of the assessment environment, correlates observations from multiple sources, reasons over asset relationships, detects coverage gaps, produces evidence-backed vulnerability hypotheses, and generates a structured validation backlog for human analysts.

### Design principle

```
AUTHORIZED SCOPE
        ↓
ADAPTIVE RECONNAISSANCE
        ↓
ASSET IDENTITY RESOLUTION
        ↓
ATTACK SURFACE GRAPH
        ↓
SURFACE COMPLETENESS ANALYSIS
        ↓
VULNERABILITY CLASS APPLICABILITY
        ↓
PER-ASSET TEST MATRIX
        ↓
TEST PLANNER (AUTOMATED / ASSISTED / MANUAL)
        ↓
EVIDENCE COLLECTION → EVIDENCE GRAPH
        ↓
VERDICT ENGINE
        ↓
CONFIRMED / REJECTED / INCONCLUSIVE
        ↓
RECURSIVE CORRELATION → NEW HYPOTHESES → TEST PLANNER
        ↓
ASSESSMENT COMPLETION EVALUATOR
        ↓
COVERAGE-AWARE FINAL ASSESSMENT
```

### Explicitly out of scope

- Autonomous exploitation
- Persistence or destructive testing
- Credential theft
- Arbitrary command execution via AI, API, or MCP
- Firewall bypass or security-control evasion logic
- Unrestricted offensive automation

---

## 2. Architectural qualities

| Quality | Mechanism |
|---------|-----------|
| **Determinism** | Core workflow, scheduling, deduplication, correlation, and severity context are rule-driven and reproducible |
| **Provenance** | Three data layers: raw (immutable), normalized, derived |
| **Separation of concerns** | Ten distinct domain concepts; never collapsed into a generic "finding" |
| **Scope safety** | Mandatory scope validation at task persistence, scheduling, and execution |
| **Extensibility** | Capability-based tool registry; declarative workflows and rules |
| **Observability** | Structured logs, metrics, correlation IDs across all entities |
| **Optional enrichment** | AI and MCP are feature-flagged boundaries; core runs without them |

---

## 3. Logical architecture

```
┌─────────────┐  ┌─────────────┐  ┌─────────────┐
│  REST API   │  │     CLI     │  │ MCP Server  │  (optional)
└──────┬──────┘  └──────┬──────┘  └──────┬──────┘
       └────────────────┼────────────────┘
                        ▼
           ┌────────────────────────┐
           │  APPLICATION SERVICES  │
           │  (use-case orchestration) │
           └────────────┬───────────┘
                        ▼
           ┌────────────────────────┐
           │     SCOPE MANAGER      │  ← enforced at every mutation path
           └────────────┬───────────┘
                        ▼
           ┌────────────────────────┐
           │   RECON CONTROLLER     │  ← event-driven; tool-agnostic
           └────────────┬───────────┘
                        │
       ┌────────────────┼────────────────┐
       ▼                ▼                ▼
┌─────────────┐  ┌─────────────┐  ┌─────────────┐
│  WORKFLOW   │  │    RULE     │  │  COVERAGE   │
│   ENGINE    │  │   ENGINE    │  │   ENGINE    │
└──────┬──────┘  └──────┬──────┘  └──────┬──────┘
       └────────────────┼────────────────┘
                        ▼
           ┌────────────────────────┐
           │      SCHEDULER       │
           └────────────┬───────────┘
                        ▼
           ┌────────────────────────┐
           │   QUEUE (Redis)        │
           └────────────┬───────────┘
                        ▼
           ┌────────────────────────┐
           │     WORKER POOL        │
           │   (Celery/Dramatiq)    │
           └────────────┬───────────┘
                        ▼
           ┌────────────────────────┐
           │   TOOL ADAPTER LAYER   │  ← capabilities, not tool names
           └────────────┬───────────┘
                        ▼
           ┌────────────────────────┐
           │    APPROVED TOOLS      │
           └────────────┬───────────┘
                        ▼
           ┌────────────────────────┐
           │     PARSER LAYER       │
           └────────────┬───────────┘
                        ▼
           ┌────────────────────────┐
           │  NORMALIZATION ENGINE  │
           └────────────┬───────────┘
       ┌────────────────┼────────────────┐
       ▼                ▼                ▼
   EVENTS         OBSERVATIONS       METRICS
       └────────────────┼────────────────┘
                        ▼
           ┌────────────────────────┐
           │   ASSET INVENTORY +    │
           │ ASSET IDENTITY ENGINE  │
           └────────────┬───────────┘
                        ▼
           ┌────────────────────────┐
           │  RELATIONSHIP GRAPH    │
           │  (PostgreSQL + projection) │
           └────────────┬───────────┘
                        ▼
           ┌────────────────────────┐
           │  FINDING INGESTION +   │
           │ FINDING NORMALIZATION  │
           └────────────┬───────────┘
                        ▼
           ┌────────────────────────┐
           │  CORRELATION ENGINE    │
           └────────────┬───────────┘
                        ▼
           ┌────────────────────────┐
           │   HYPOTHESIS ENGINE    │
           └────────────┬───────────┘
                        ▼
           ┌────────────────────────┐
           │ VALIDATION BACKLOG MGR │
           └────────────┬───────────┘
                        ▼
           ┌────────────────────────┐
           │   ANALYST VALIDATION   │
           └────────────┬───────────┘
                        ▼
           ┌────────────────────────┐
           │  CONFIRMED FINDINGS +  │
           │  RISK PRIORITIZATION   │
           └────────────┬───────────┘
                        ▼
           ┌────────────────────────┐
           │  REPORTING + CHANGE    │
           │  DETECTION ENGINES     │
           └────────────────────────┘
```

---

## 4. Layer responsibilities

### 4.1 Ingress layer (API, CLI, MCP)

- Authenticate and authorize requests
- Validate input with Pydantic schemas
- Delegate to application services; **no business logic**
- MCP defaults to read-only; write operations require explicit configuration

### 4.2 Application service layer

Orchestrates use cases:

- `ProjectService`, `ScanService`, `AssetQueryService`
- `FindingImportService`, `CorrelationQueryService`
- `HypothesisService`, `ValidationService`
- `CoverageService`, `ChangeDetectionService`, `ReportService`

Services coordinate domain modules and enforce transactional boundaries. They call Scope Manager before any side effect.

### 4.3 Scope Manager

Single authority for authorization boundary decisions.

**Inputs:** scope rules, target descriptor, capability, operational profile  
**Outputs:** `ALLOW | DENY | DEFER` with audit record

Enforced at:
1. Task persistence (controller)
2. Task scheduling (scheduler)
3. Worker pre-execution (adapter invocation)

### 4.4 Recon Controller

Event-driven state machine executor. See ADR-0001.

```
NEXT_ACTIONS = F(CURRENT_STATE, NEW_EVENT, WORKFLOW_RULES, OPERATIONAL_POLICY, SCOPE_POLICY)
```

Responsibilities per event:
1. Validate event schema
2. Persist event (append-only)
3. Create/update observations
4. Update asset inventory via identity resolution
5. Create/update relationships (non-destructive; competing observations preserved)
6. Match workflow transitions
7. Evaluate eligibility, operational, and stopping rules
8. Generate candidate tasks
9. Deduplicate by uniqueness key
10. Scope-validate each task
11. Persist tasks
12. Notify scheduler

The controller knows **capabilities**, never tool CLI syntax.

### 4.5 Workflow Engine

Loads versioned YAML workflow definitions. Each scan records the workflow version used.

Transitions map event types (+ optional conditions) to capability tasks or internal processing stages.

### 4.6 Rule Engine

Evaluates versioned, deterministic rules across categories:

| Category | Purpose |
|----------|---------|
| `WORKFLOW_RULE` | Event → stage transitions |
| `ELIGIBILITY_RULE` | Whether a task may be created |
| `PARAMETER_RULE` | Task parameter derivation |
| `FAILURE_RULE` | Retry/defer/terminal on failure |
| `STOPPING_RULE` | Scan/stage halt conditions |
| `CORRELATION_RULE` | Finding/asset correlation |
| `HYPOTHESIS_RULE` | Hypothesis generation |
| `CONFIDENCE_RULE` | Confidence adjustments |
| `SEVERITY_CONTEXT_RULE` | Contextual priority (not source severity) |

Every evaluation produces an auditable `RuleEvaluationResult`.

### 4.7 Scheduler and queue

Manages task lifecycle, dependencies, concurrency limits, leases, backoff, and crash recovery.

Task uniqueness key:
```
scan_id + capability + normalized_target + relevant_configuration_hash
```

### 4.8 Worker pool and tool adapters

Workers claim leased tasks, re-validate scope, invoke adapters, store raw artifacts, invoke parsers, emit events back to the controller.

Adapters translate:
```
Generic Task + Operational Profile + Tool Manifest → Validated Tool Invocation
```

Parsers translate:
```
Tool Output → Normalized Observations + Events + Metrics
```

Tools never call other tools.

### 4.9 Data processing pipelines

#### Normalization Engine
Converts parser output into canonical observation and asset representations.

#### Asset Identity Resolution Engine
Determines MERGED | RELATED | POSSIBLY_SAME | DISTINCT | UNRESOLVED relationships between asset candidates using deterministic evidence.

#### Correlation Engine
Cross-entity correlation (not deduplication-only). See domain-model.md.

#### Hypothesis Engine
Produces testable security claims with evidence packages and validation requirements.

#### Coverage Engine
Tracks assessment completeness by asset type and capability.

#### Change Detection Engine
Compares scan snapshots; change events trigger coverage reevaluation and hypotheses.

#### Risk Prioritization Engine
Computes `CONTEXTUAL_PRIORITY` separately from `SOURCE_SEVERITY`.

### 4.10 Optional boundaries

- **Mistral AI Enrichment** (ADR-0003): summaries and explanations only
- **MCP Server** (ADR-0004): thin read wrappers over application services

### 4.11 Audit and observability

- `AuditEvent` for security-relevant decisions
- Structured JSON logging with correlation IDs
- Prometheus-compatible metrics (task durations, queue depth, rule evaluations, etc.)

---

## 5. Data architecture

### 5.1 Three data layers

| Layer | Mutability | Examples |
|-------|------------|----------|
| **Raw** | Immutable | stdout, stderr, JSON reports, redacted command metadata |
| **Normalized** | Append + versioned updates | observations, assets, relationships, normalized findings |
| **Derived** | Recomputable | correlations, hypotheses, coverage, risk scores |

Parser version changes trigger offline reprocessing from raw artifacts without rescanning.

### 5.2 Storage

| Store | Role |
|-------|------|
| **PostgreSQL** | System of record for all domain entities |
| **Redis** | Task queue, leases, rate-limit counters, AI response cache |
| **Object storage** (optional Phase 4+) | Large raw artifacts |

Relationships are stored relationally in PostgreSQL with a graph projection interface for future graph DB adoption (ADR-0002).

---

## 6. Technology stack

| Component | Choice | Rationale |
|-----------|--------|-----------|
| Language | Python 3.11+ | Ecosystem for security tooling integration |
| API | FastAPI | Async-capable, Pydantic-native |
| ORM | SQLAlchemy 2.x | Mature, explicit mapping |
| Migrations | Alembic | Versioned schema |
| Database | PostgreSQL | Relational integrity, JSONB for flexible evidence |
| Queue | Redis + Celery | Proven task distribution, lease patterns |
| CLI | Typer | Consistent with Python stack |
| Config | YAML + env + Pydantic Settings | Layered configuration |
| Testing | pytest, pytest-asyncio, Hypothesis | Unit, integration, property tests |
| Dev tooling | Docker Compose, Makefile, pre-commit, Ruff, mypy | Reproducible dev environment |
| Frontend | React + TypeScript (Phase 11) | After backend vertical slices stabilize |

---

## 7. Deployment topology (development)

```
docker-compose:
  api          → FastAPI (uvicorn)
  worker       → Celery workers
  scheduler    → Celery beat (periodic recovery/deferred promotion)
  postgres     → PostgreSQL 16
  redis        → Redis 7
```

Production deployment is out of Phase 0 scope; the architecture supports horizontal worker scaling and read replicas for query APIs.

---

## 8. Security architecture summary

- Secrets via environment / secret manager abstraction only
- Command argument redaction before persistence
- Tool output treated as untrusted input
- Container-isolated tool execution with timeouts and output size limits
- RBAC design at API/MCP layer (implementation in Phase 1+)
- SSRF-aware internal service calls
- Path traversal protection on artifact storage

See `threat-model.md` for full analysis.

---

## 9. Phase roadmap

| Phase | Deliverable |
|-------|-------------|
| **0** | Architecture documents |
| **1** | Core state model |
| **A** | Capability abstraction + evidence quality + fake providers |
| **B** | Adaptive recon vertical slice |
| **C** | Surface completeness engine |
| **D** | Vulnerability knowledge + applicability |
| **E** | Per-asset test matrix |
| **F** | Test planner (automated / assisted / manual) |
| **G** | Evidence graph + verdict engine |
| **H** | Recursive correlation |
| **I** | Credential context |
| **J** | First real free capability providers (minimal set) |
| **K** | MCP extension (read-only) |
| **L** | Mistral enrichment |
| **11** | Dashboard |

See `extension-gap-analysis.md` for mapping from original Phases 2–10.

---

## 10. Key invariants

1. A scanner observation never directly becomes a confirmed vulnerability.
2. Every task passes scope validation three times.
3. Conflicting relationships are stored, not overwritten.
4. AI cannot change task state, scope, or final severity.
5. MCP cannot execute arbitrary tools or SQL.
6. Every derived conclusion traces to evidence IDs.
7. Duplicate observations do not create duplicate identical tasks.
8. Workflow and rule versions are recorded per scan.
9. Scan completion requires AssessmentCompletionEvaluator — not empty queue alone.
10. Vulnerability applicability does not imply confirmed vulnerability.
11. Credentials never appear in task payloads, events, logs, AI, or MCP.
12. Automated tests require safety classification and policy approval where required.

---

## 11. Cross-references

- Domain entities: `domain-model.md`
- Event types: `event-catalog.md`, `event-catalog-extensions.md`
- State machines: `state-machines.md`, `state-machines-extensions.md`
- Threats: `threat-model.md`
- Extension gap analysis: `extension-gap-analysis.md`
- ADRs: `adr/`

---

## 12. Extended architecture (adaptive assessment)

### 12.1 Extended logical diagram

```
AUTHORIZED SCOPE
        │
        ▼
ADAPTIVE RECON CONTROLLER ◄────────────────────────────┐
        │                                              │
        ▼                                              │
CAPABILITY PLANNER (Registry + Selection + Gain)       │
        │                                              │
        ▼                                              │
DISCOVERY / ASSESSMENT CAPABILITIES (adapters)       │
        │                                              │
        ▼                                              │
EVIDENCE QUALITY EVALUATOR                           │
        ├── sufficient → continue                      │
        └── inconclusive → alternate provider/profile ─┘
        │
        ▼
NORMALIZATION → ASSET IDENTITY → ATTACK SURFACE GRAPH
        │
        ▼
SURFACE COMPLETENESS ENGINE
        │
        ▼
VULNERABILITY APPLICABILITY ENGINE
        │
        ▼
PER-ASSET TEST MATRIX
        │
        ▼
TEST PLANNER + TEST SAFETY POLICY
        ├── AUTOMATED (orchestrator)
        ├── ASSISTED (evidence package)
        └── MANUAL (validation backlog)
        │
        ▼
EVIDENCE GRAPH → VERDICT ENGINE
        │
        ▼
RECURSIVE CORRELATION ENGINE ──► NEW HYPOTHESES? ──► TEST PLANNER
        │
        ▼
ASSESSMENT COMPLETION EVALUATOR
```

### 12.2 New subsystems

| Subsystem | Document |
|-----------|----------|
| Adaptive Reconnaissance Planner | `adaptive-recon.md` |
| Evidence Quality Evaluator | `evidence-quality-model.md` |
| Capability Registry + Selection | `capability-registry.md` |
| Marginal Discovery Gain Engine | `adaptive-recon.md` §7 |
| Surface Completeness Engine | `surface-completeness.md` |
| Credential / Auth Context | `credential-context.md` |
| Vulnerability Knowledge Layer | `vulnerability-knowledge-layer.md` |
| Vulnerability Applicability Engine | `vulnerability-applicability.md` |
| Test Matrix + Test Planner | `test-planner.md` |
| Test Safety Policy | `test-safety-policy.md` |
| Evidence Graph | `evidence-graph.md` |
| Verdict Engine | `verdict-engine.md` |
| Recursive Correlation | `recursive-correlation.md` |
| Assessment Completion | `assessment-completion.md` |
| Zero-cost stack | `zero-cost-stack.md` |

### 12.3 Extended application services

| Service | Responsibility |
|---------|----------------|
| `CapabilityRegistryService` | List capabilities and providers |
| `DiscoveryGainQueryService` | Per-scan/provider metrics |
| `SurfaceCoverageService` | Per-asset surface dimensions |
| `ApplicabilityService` | Vulnerability class applicability |
| `TestMatrixService` | Asset × class matrix |
| `TestPlanService` | Plan CRUD, approve, cancel |
| `VerdictService` | Verdict issuance and queries |
| `AssessmentCompletionService` | Completion status |
| `CredentialService` | Reference metadata only |
| `RecursiveCorrelationService` | Post-validation correlation |

### 12.4 Extended API endpoints

| Endpoint | Purpose |
|----------|---------|
| `GET /capabilities` | Capability registry |
| `GET /scans/{id}/discovery-gain` | Provider gain metrics |
| `GET /assets/{id}/surface-coverage` | Surface completeness |
| `GET /assets/{id}/vulnerability-applicability` | Applicability states |
| `GET /assets/{id}/test-matrix` | Per-asset test matrix |
| `GET /scans/{id}/test-matrix` | Scan-wide matrix |
| `GET /scans/{id}/test-plans` | Test plans |
| `GET /test-plans/{id}` | Plan detail |
| `POST /test-plans/{id}/approve` | Approve state-changing plan |
| `POST /test-plans/{id}/cancel` | Cancel plan |
| `GET /hypotheses/{id}/evidence` | Evidence graph trace |
| `GET /scans/{id}/completion-status` | Assessment completion |

Credential endpoints return metadata only — never secret values.

### 12.5 Extended MCP tools (Phase K)

`get_asset_surface_coverage`, `get_asset_test_matrix`, `get_scan_test_matrix`, `get_applicable_vulnerability_classes`, `get_uncovered_test_requirements`, `get_test_plan`, `get_hypothesis_evidence`, `get_auth_coverage`, `get_role_coverage`, `get_assessment_completion_status`, `get_discovery_gain`, `explain_test_requirement`, `explain_coverage_gap`

See ADR-0012.

### 12.6 Database migrations

See `database-migration-plan.md` — migrations 002–009.

### 12.7 First coding goal (post-approval)

**Phase A:** Capability abstraction + evidence quality + adaptive fake-provider vertical slice. See `phase-a-implementation-plan.md`. No real security tools until Phase J.
