# ADR-0003: Optional AI Enrichment Boundary (Mistral)

## Status

Accepted

## Date

2026-07-06

## Context

AI can add value for summarization, explanation of deterministic correlations, and unstructured report parsing. However, the platform must remain fully functional without AI, and AI must not become a trust boundary failure — confirming vulnerabilities, bypassing scope, or scheduling offensive actions.

The product specification requires:

- `AI_ENABLED=false` by default
- Model name from configuration (`MISTRAL_MODEL`), not hardcoded
- API key from environment (`MISTRAL_API_KEY`)
- Deterministic fallback when AI unavailable
- All AI structured output validated with Pydantic

## Decision

Implement Mistral AI as an **optional enrichment layer** behind a strict architectural boundary. AI operates only on **read models** and writes only to `AIEnrichment` records.

### Allowed AI operations

| Operation | Input | Output storage |
|-----------|-------|----------------|
| Analyst summary generation | Scan snapshot (read model) | AIEnrichment |
| Scan change summaries | ChangeEvent list | AIEnrichment |
| Correlation explanations | FindingCorrelation + evidence refs | AIEnrichment |
| Text finding cluster suggestions | NormalizedFinding batch | AIEnrichment (suggestions only) |
| Unstructured report entity extraction | RawArtifact | AIEnrichment (validated schema) |
| Taxonomy mapping suggestions | Finding text | AIEnrichment |
| JS/text artifact summarization | RawArtifact (truncated) | AIEnrichment |
| Hypothesis generation explanations | Hypothesis + evidence | AIEnrichment |
| Coverage gap NL summaries | CoverageRecord | AIEnrichment |

### Prohibited AI operations

- Execute tools or shell commands
- Create, modify, or cancel tasks
- Change scope or authorization boundaries
- Confirm vulnerabilities or assign final severity
- Directly modify hypothesis/task/scan status
- Bypass Scope Manager
- Make unrestricted MCP calls

### Architecture

```
┌─────────────────────────────────────────┐
│           CORE PLATFORM                  │
│  (fully deterministic, no AI imports)  │
└──────────────────┬──────────────────────┘
                   │ read-only queries
                   ▼
┌─────────────────────────────────────────┐
│        AI ENRICHMENT SERVICE             │
│  - feature flag check                    │
│  - cache lookup (hash + prompt + model)  │
│  - Mistral client                        │
│  - Pydantic output validation            │
│  - rate limit / token budget             │
└──────────────────┬──────────────────────┘
                   │ write
                   ▼
            ai_enrichments table
```

### Caching

```
cache_key = SHA256(input_artifact_hash + prompt_template_version + model_config_json)
```

Stored in Redis with TTL; persisted `AIEnrichment` for audit.

### Configuration

```yaml
ai:
  enabled: false  # AI_ENABLED env override
  provider: mistral
  model: ${MISTRAL_MODEL}  # no default in business logic
  max_tokens: 1024
  token_budget_per_scan: 50000
  rate_limit_retries: 3
```

### Failure modes

| Condition | Behavior |
|-----------|----------|
| AI_ENABLED=false | Skip; no error |
| API key missing | Log warning; skip |
| Rate limited | Exponential backoff; then FALLBACK status |
| Invalid output schema | Store INVALID; do not expose to analysts as fact |
| Timeout | FALLBACK; optional deterministic template summary |

## Consequences

### Positive

- Core assessment pipeline testable without AI mocks in critical path
- Clear security boundary for threat modeling
- Free-tier friendly via caching and budgets
- Analysts can distinguish AI suggestions from deterministic conclusions

### Negative

- Duplicate summarization logic (deterministic fallback templates)
- Additional module to maintain
- Risk of developers accidentally coupling AI to controller (mitigated by code review + import lint rules)

### Enforcement

- `vapt_platform.enrichment` package must not be imported by `controller`, `scheduler`, or `scope` modules
- Property test: AI service has no write access to TaskRepository
- CI: mypy strict + import boundary check (ruff banned imports)

## References

- `docs/architecture.md` §4.10
- `docs/threat-model.md` §5.5
- `docs/domain-model.md` §14
