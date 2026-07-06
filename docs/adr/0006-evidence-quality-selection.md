# ADR-0006: Evidence Quality Before Alternate Capability Selection

## Status

Accepted

## Date

2026-07-06

## Context

Negative or empty tool output is often interpreted as asset absence, causing false negatives in attack surface maps.

## Decision

1. After every task completion, **EvidenceQualityEvaluator** classifies result quality
2. Workflow advancement on negative results requires `NEGATIVE_CONCLUSIVE` unless engagement policy explicitly allows inference
3. `NEGATIVE_INCONCLUSIVE` triggers alternate **execution profile** or **provider** via deterministic rules — not AI
4. `NO_DISCOVERY_ASSUMPTION` profile never infers absence from silence

## Consequences

**Positive:** Fewer false negatives; auditable reason codes; supports adaptive recon without evasion logic.

**Negative:** More tasks per ambiguous target; requires gain engine to limit provider sprawl.

## References

- `evidence-quality-model.md`
- `adaptive-recon.md`
