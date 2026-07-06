# ADR-0012: MCP as Controlled Integration Boundary (Extension)

## Status

Accepted (extends ADR-0004)

## Date

2026-07-06

## Context

Extension adds test matrix, surface coverage, applicability, and completion APIs. MCP clients remain untrusted.

## Decision

Extend ADR-0004 with read tools:

- `get_asset_surface_coverage`, `get_asset_test_matrix`, `get_scan_test_matrix`
- `get_applicable_vulnerability_classes`, `get_uncovered_test_requirements`
- `get_test_plan`, `get_hypothesis_evidence`
- `get_auth_coverage`, `get_role_coverage`
- `get_assessment_completion_status`, `get_discovery_gain`
- `explain_test_requirement`, `explain_coverage_gap`

**Additional prohibitions:**
- No arbitrary scanner execution via MCP
- No raw credential or secret values in responses
- No automatic exploit execution
- MCP must not bypass TestSafetyPolicyEngine or CredentialScopeBinding

Write operations unchanged from ADR-0004 (scan lifecycle only, explicitly enabled).

## Consequences

MCP schema sync burden increases; all handlers remain thin wrappers over application services.

## References

- ADR-0004
- `extension-gap-analysis.md` §6
