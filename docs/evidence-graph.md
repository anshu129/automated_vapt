# Evidence Graph

## 1. Purpose

Extend the attack surface relationship graph with **evidence links** connecting observations, findings, validation results, hypotheses, coverage gaps, and change events. Every verdict must be traceable through this graph.

---

## 2. Evidence vs Relationship

| Layer | Entity | Purpose |
|-------|--------|---------|
| Asset graph | `Relationship` | Assets ↔ assets (RESOLVES_TO, TRUSTS, etc.) |
| Evidence graph | `EvidenceLink` | Entities ↔ claims (supports, contradicts, confirms) |

Phase 0 `Evidence` entity (observation → claim) is preserved. `EvidenceLink` generalizes to all entity types.

---

## 3. EvidenceLink entity

| Field | Type | Description |
|-------|------|-------------|
| `id` | UUID | |
| `scan_id` | UUID | |
| `source_type` | enum | OBSERVATION, SCANNER_FINDING, VALIDATION_RESULT, CHANGE_EVENT, COVERAGE_GAP, HYPOTHESIS |
| `source_id` | UUID | |
| `target_type` | enum | HYPOTHESIS, TEST_REQUIREMENT, VERDICT, RELATIONSHIP, ASSET |
| `target_id` | UUID | |
| `link_type` | EvidenceLinkType | See §4 |
| `weight` | float | Contribution to confidence |
| `created_at` | timestamp | |
| `provenance` | JSONB | task_run, analyst, rule |

---

## 4. EvidenceLinkType

```
SUPPORTS
CONTRADICTS
CONFIRMS
REJECTS
TRIGGERS
REQUIRES
CONTEXTUAL
DERIVED_FROM
```

### Required semantic mappings

| Source | Link | Target |
|--------|------|--------|
| OBSERVATION | SUPPORTS | HYPOTHESIS |
| OBSERVATION | CONTRADICTS | HYPOTHESIS |
| SCANNER_FINDING | SUPPORTS | HYPOTHESIS |
| VALIDATION_RESULT | CONFIRMS | HYPOTHESIS |
| VALIDATION_RESULT | REJECTS | HYPOTHESIS |
| CHANGE_EVENT | TRIGGERS | TEST_REQUIREMENT |
| COVERAGE_GAP | REQUIRES | VALIDATION_TASK |

Existing `RelationshipType` values `EVIDENCE_FOR`, `SUPPORTS_HYPOTHESIS`, `CONTRADICTS_HYPOTHESIS` remain for asset-graph edges; `EvidenceLink` is the canonical cross-entity evidence trace.

---

## 5. EvidenceGraph service

```python
class EvidenceGraph(Protocol):
    def add_link(self, link: EvidenceLink) -> EvidenceLink: ...
    def get_supporting(self, target_type, target_id) -> list[EvidenceLink]: ...
    def get_contradicting(self, target_type, target_id) -> list[EvidenceLink]: ...
    def trace_verdict(self, verdict_id: UUID) -> EvidenceTrace: ...
    def subgraph_for_hypothesis(self, hypothesis_id: UUID) -> EvidenceSubgraph: ...
```

`EvidenceTrace` is ordered list from verdict → validation → observations/findings with explanations.

---

## 6. Population rules

| Event | Evidence graph update |
|-------|----------------------|
| Observation created | Link to relevant hypotheses if rules match |
| Finding normalized | SUPPORTS hypothesis if correlated |
| ValidationResult recorded | CONFIRMS or REJECTS hypothesis |
| Verdict issued | Links all required evidence IDs |
| Surface gap identified | REQUIRES validation task |
| Change detected | TRIGGERS test requirement |

---

## 7. Secret handling

Observations containing secret indicators:

- Store redacted payload in observation
- Full artifact in protected storage with restricted ACL
- Evidence graph references observation ID only
- AI/MCP queries return redacted view

---

## 8. Reporting

Reports cite `evidence_ids` and `EvidenceLink` chains. Executive summary never embeds raw tool output.

---

## 9. References

- `domain-model.md` §5 (Evidence)
- `verdict-engine.md`
- `recursive-correlation.md`
