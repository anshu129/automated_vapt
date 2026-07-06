# ADR-0011: AI Advisory Only (Extension)

## Status

Accepted (extends ADR-0003)

## Date

2026-07-06

## Context

The extension adds test planning, verdicts, and evidence packages. AI could be misused to confirm vulnerabilities, select intrusive tests, or handle secrets.

## Decision

Extend ADR-0003 prohibitions:

**Mistral may assist with:**
- Evidence package summarization (redacted inputs only)
- Test requirement explanations
- Coverage gap natural language summaries
- Taxonomy mapping suggestions for noisy findings

**Mistral must not:**
- Decide scope or select intrusive tests
- Execute scanners or change verdict state
- Receive raw credentials or secret indicator values
- Override deterministic applicability, safety, or correlation rules

All structured output schema-validated; stored in `AIEnrichment` only.

## Consequences

No change to core determinism; additional prompt templates require redaction pipeline review.

## References

- ADR-0003
- `test-planner.md`
- `credential-context.md`
