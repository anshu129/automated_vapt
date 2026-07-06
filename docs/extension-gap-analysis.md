# Extension Gap Analysis

## 1. Purpose

This document compares the Phase 0 architecture against the adaptive reconnaissance, vulnerability applicability, test planning, validation, and recursive correlation extension. It identifies reusable models, required extensions, and new subsystems before implementation.

---

## 2. Architecture alignment summary

| Extension requirement | Phase 0 status | Action |
|----------------------|----------------|--------|
| Authorized scope management | Planned (Scope Manager) | **Reuse** — extend for credential scope binding |
| Deterministic recon controller | Planned (ADR-0001) | **Extend** → Adaptive Recon Controller + Capability Planner |
| Workflow engine | Planned | **Reuse** — add evidence-quality branches |
| Rule engine | Planned (9 categories) | **Extend** — add applicability, safety, gain rules |
| Scheduler / queue / workers | Planned (Phases 2–3) | **Reuse** |
| Tool adapter layer | Planned (capability-based) | **Extend** → Capability Registry + Provider routing |
| Parser / normalizer | Planned | **Reuse** |
| Asset inventory | Planned | **Reuse** |
| Relationship graph | Planned (PostgreSQL) | **Extend** → Evidence Graph |
| Asset identity resolution | Planned | **Reuse** |
| Scanner finding ingestion | Planned (Phase 5) | **Reuse** |
| Correlation engine | Planned (Phase 6) | **Extend** → Recursive Correlation Engine |
| Hypothesis engine | Planned (Phase 7) | **Reuse** — fed by Test Planner |
| Coverage engine | Planned (Phase 8) | **Supersede partially** → Surface Completeness + Test Matrix |
| Change detection | Planned (Phase 8) | **Reuse** |
| Validation backlog | Planned | **Extend** → Manual + Assisted + Automated paths |
| Confirmed findings | Planned | **Extend** → Verdict Engine gate |
| Optional Mistral | Planned (ADR-0003) | **Extend** advisory scope only |
| Optional MCP | Planned (ADR-0004) | **Extend** read tools |
| Evidence quality evaluation | **Missing** | **New** |
| Capability provider routing | **Partial** (ToolManifest) | **New** Capability Registry |
| Marginal discovery gain | **Missing** | **New** |
| Surface completeness (per-asset) | **Partial** (CoverageRecord aggregate) | **New** SurfaceCompletenessEngine |
| Credential context | **Missing** | **New** |
| Vulnerability knowledge layer | **Missing** | **New** |
| Vulnerability applicability | **Missing** | **New** |
| Per-asset test matrix | **Missing** | **New** |
| Test planner | **Missing** | **New** |
| Test safety policy | **Missing** | **New** |
| Automated validation orchestrator | **Missing** | **New** (policy-approved only) |
| Evidence graph | **Partial** (Evidence entity) | **Extend** |
| Verdict engine | **Partial** (ValidationResult) | **New** formal engine |
| Assessment completion evaluator | **Missing** | **New** |
| Zero-cost stack documentation | **Missing** | **New** |

---

## 3. Reusable models (no structural change)

| Model | Reuse notes |
|-------|-------------|
| `Project`, `Scan`, `ScopeRule` | Direct reuse |
| `Asset`, `AssetIdentifier` | Direct reuse; add surface metadata fields |
| `Observation` | Direct reuse; add `HISTORICAL_OBSERVATION` type |
| `Evidence` | Direct reuse; Evidence Graph extends relationships |
| `Relationship` | Direct reuse; existing types cover trust/auth |
| `Event`, `Task`, `TaskRun`, `TaskDependency` | Direct reuse |
| `ToolManifest` | Extend with capability groups, safety class, cost tier |
| `RawArtifact` | Direct reuse |
| `ScannerFinding`, `NormalizedFinding`, `FindingInstance` | Direct reuse |
| `FindingCorrelation` | Extend correlation_type enum |
| `Hypothesis`, `HypothesisEvidence` | Direct reuse |
| `ValidationTask`, `ValidationResult` | Extend; link to TestPlan |
| `ConfirmedFinding` | Gate through VerdictEngine |
| `ChangeEvent` | Direct reuse; trigger recursive correlation |
| `RiskScenario` | Direct reuse |
| `MetricSnapshot` | Direct reuse; add discovery gain metrics |
| `AuditEvent`, `AIEnrichment` | Direct reuse |
| `Scope Manager` | Extend for credential binding checks |
| `GraphRepository` | Extend for evidence traversal |

---

## 4. Models requiring extension

| Model | Extension |
|-------|-----------|
| `ToolManifest` | Add `capability_group`, `safety_class`, `cost_tier`, `provider_priority`, `quota_policy` |
| `Task` | Add `capability_provider_id`, `execution_profile_id`, `evidence_quality_decision_id` |
| `CoverageRecord` | Remain for scan-level aggregates; delegate per-asset detail to `SurfaceCoverageRecord` |
| `FindingCorrelation.correlation_type` | Add 8 new categories (see recursive-correlation.md) |
| `Hypothesis` | Add `verdict_id`, `test_plan_id`, `vulnerability_class_ids[]` |
| `ValidationTask` | Add `test_plan_id`, `testing_mode`, `evidence_package_id` |
| `ValidationResult` | Link to `Verdict`; trigger recursive correlation event |
| `RuleEngine` categories | Add `APPLICABILITY_RULE`, `SAFETY_RULE`, `GAIN_RULE`, `EVIDENCE_QUALITY_RULE` |
| `Recon Controller` | Insert EvidenceQualityEvaluator + CapabilitySelectionEngine after task completion |
| `Scan.status` | Completion via AssessmentCompletionEvaluator, not queue-empty |
| `Operational profile` | Expand: STANDARD, CAUTIOUS, HIGH_LATENCY, NO_DISCOVERY_ASSUMPTION, AUTHENTICATED, PASSIVE_ONLY |
| `RelationshipType` | Add evidence-graph edge semantics via `EvidenceLink` entity |
| `MCP tools` | Add 12 read tools (see architecture.md extension) |
| `Mistral enrichment types` | Add test requirement / coverage gap explanations |

---

## 5. New subsystems required

| # | Subsystem | Package (proposed) |
|---|-----------|-------------------|
| 1 | Adaptive Reconnaissance Planner | `vapt_platform.planning.adaptive_recon` |
| 2 | Evidence Quality Evaluator | `vapt_platform.evidence.quality` |
| 3 | Capability Registry | `vapt_platform.capabilities.registry` |
| 4 | Capability Selection Engine | `vapt_platform.capabilities.selection` |
| 5 | Marginal Discovery Gain Engine | `vapt_platform.planning.discovery_gain` |
| 6 | Surface Completeness Engine | `vapt_platform.surface.completeness` |
| 7 | Credential Context Manager | `vapt_platform.auth.credentials` |
| 8 | Authentication Context Manager | `vapt_platform.auth.context` |
| 9 | Vulnerability Knowledge Layer | `vapt_platform.vuln.knowledge` |
| 10 | Vulnerability Class Applicability Engine | `vapt_platform.vuln.applicability` |
| 11 | Per-Asset Test Matrix Engine | `vapt_platform.testing.matrix` |
| 12 | Test Planner | `vapt_platform.testing.planner` |
| 13 | Test Capability Matcher | `vapt_platform.testing.matcher` |
| 14 | Test Safety Policy Engine | `vapt_platform.testing.safety` |
| 15 | Automated Validation Orchestrator | `vapt_platform.testing.automated` |
| 16 | Assisted Validation Workflow | `vapt_platform.testing.assisted` |
| 17 | Manual Validation Backlog | `vapt_platform.testing.manual` (extends ValidationService) |
| 18 | Evidence Graph | `vapt_platform.evidence.graph` |
| 19 | Verdict Engine | `vapt_platform.verdict` |
| 20 | Recursive Correlation Engine | `vapt_platform.correlation.recursive` |
| 21 | Assessment Completion Evaluator | `vapt_platform.assessment.completion` |

---

## 6. New database entities

See `database-migration-plan.md` for full schema. Summary:

| Entity | Replaces / complements |
|--------|------------------------|
| `Capability` | Formalizes capability enum from ToolManifest |
| `CapabilityProvider` | One provider per tool integration |
| `CapabilityExecutionProfile` | STANDARD, CAUTIOUS, etc. |
| `EvidenceQualityDecision` | Per task-run quality outcome |
| `DiscoveryGainMetric` | Per provider per scan |
| `SurfaceCoverageRecord` | Per-asset surface dimensions |
| `CredentialReference` | Secret backend pointer only |
| `CredentialScopeBinding` | Credential ↔ scope/asset |
| `AuthenticationContext` | Session/auth state metadata |
| `RoleContext` | Role-specific coverage |
| `VulnerabilityClass` | Taxonomy |
| `ApplicabilityRule` | Versioned rules |
| `AssetVulnerabilityApplicability` | Per asset per class |
| `AssetTestMatrix` | Matrix header per asset |
| `TestRequirement` | Matrix cell |
| `TestPlan` | Planned validation |
| `TestExecution` | Automated run record |
| `EvidencePackage` | Assisted validation bundle |
| `Verdict` | Formal outcome per hypothesis/test |
| `AssessmentCompletionRecord` | Scan completion state |
| `EvidenceLink` | Evidence graph edges |

---

## 7. What does NOT change

1. Ten distinct domain concepts (observation ≠ hypothesis ≠ confirmed finding)
2. Triple scope validation
3. Immutable raw artifacts
4. PostgreSQL as system of record
5. AI optional and advisory-only
6. MCP thin-wrapper pattern
7. No autonomous exploitation
8. Deterministic core (no AI for scheduling, dedup, verdicts)

---

## 8. Revised phase roadmap

| Phase | Name | Deliverable |
|-------|------|-------------|
| 0 | Architecture | Complete (extended) |
| 1 | Core state model | Unchanged from phase-1-implementation-plan.md |
| **A** | **Capability abstraction** | Registry, profiles, evidence quality, fake providers |
| **B** | **Adaptive recon slice** | DNS → service → HTTP → crawl with inconclusive handling |
| **C** | **Surface completeness** | Per-asset coverage dimensions |
| **D** | **Vulnerability knowledge** | Taxonomy + applicability rules |
| **E** | **Test matrix** | Asset × class × coverage |
| **F** | **Test planner** | Automated / assisted / manual |
| **G** | **Evidence + verdict** | Evidence graph, verdict lifecycle |
| **H** | **Recursive correlation** | Post-validation graph updates |
| **I** | **Credential context** | Secret references, auth coverage |
| 2–3 | Controller + scheduler | Merged into A–B with extensions |
| **J** | **First real free providers** | Minimal complementary set |
| **K** | **MCP extension** | Read-only tools |
| **L** | **Mistral extension** | Advisory enrichments |
| 5–8 | Finding ingestion, correlation, etc. | Integrated into D–H |
| 11 | Dashboard | After backend acceptance scenario passes |

---

## 9. Risk: scope creep mitigation

| Risk | Mitigation |
|------|------------|
| Integrating all tools at once | Phase J limits to 9 capability groups |
| Paid API dependency | zero-cost-stack.md; optional providers |
| Credential leakage | ADR-0009; secret provider abstraction |
| Scan-complete on empty queue | AssessmentCompletionEvaluator |
| Applicability → auto-vuln | Separate engines; VerdictEngine gate |

---

## 10. Cross-references

- Updated HLD: `architecture.md` §12
- New subsystem docs: `adaptive-recon.md` through `assessment-completion.md`
- ADRs: `adr/0005` through `adr/0012`
- Phase A plan: `phase-a-implementation-plan.md`
