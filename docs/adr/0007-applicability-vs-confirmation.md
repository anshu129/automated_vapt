# ADR-0007: Vulnerability Applicability Separated from Vulnerability Confirmation

## Status

Accepted

## Date

2026-07-06

## Context

Scanners and fingerprints often lead platforms to treat "product detected" or "CVE exists" as confirmed vulnerabilities.

## Decision

1. **VulnerabilityApplicabilityEngine** determines which classes warrant testing (`NOT_APPLICABLE` through `INCONCLUSIVE`)
2. Applicability states never create `ConfirmedFinding`
3. **VerdictEngine** is the only path to `CONFIRMED` applicability state for validated issues
4. Technology observations remain evidence, not vulnerabilities

## Consequences

**Positive:** Clear analyst workflow; reduced false positives; test matrix driven by applicability not scanner noise.

**Negative:** Additional computation and storage per asset per class.

## References

- `vulnerability-applicability.md`
- `verdict-engine.md`
