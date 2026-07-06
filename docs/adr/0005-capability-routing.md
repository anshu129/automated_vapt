# ADR-0005: Capability Routing Instead of Fixed Tool Pipelines

## Status

Accepted

## Date

2026-07-06

## Context

Security assessment tools are often integrated as sequential shell scripts (`subfinder | httpx | nuclei`). This creates brittle pipelines, redundant execution, and inability to substitute providers or respond to evidence quality.

Phase 0 introduced capability-based adapters but lacked formal provider registry and selection policy.

## Decision

1. All tool integrations register as **CapabilityProviders** in a **Capability Registry**
2. The controller and Test Planner request **capabilities**, never tool names
3. **CapabilitySelectionEngine** picks providers deterministically using scope, safety, cost policy, availability, and marginal discovery gain
4. Fixed tool chains are **prohibited** in workflow definitions

## Consequences

**Positive:** Replaceable providers; zero-cost stack viable; testable selection logic.

**Negative:** Registry maintenance overhead; selection policy must be documented and versioned.

## References

- `capability-registry.md`
- `zero-cost-stack.md`
