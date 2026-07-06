# ADR-0004: MCP Server as Thin Read-Only Integration Boundary

## Status

Accepted

## Date

2026-07-06

## Context

Model Context Protocol (MCP) enables AI assistants and external tools to query platform state. MCP clients and their prompts are **untrusted input**. The platform must expose useful read access for analysts without creating paths for arbitrary command execution, scope bypass, or unauthenticated state mutation.

Requirements:

- `MCP_ENABLED=false` by default
- `MCP_READ_ONLY=true` by default
- MCP handlers are thin wrappers over application services
- No business logic in MCP layer
- Write operations (if ever enabled) require explicit configuration and authorization

## Decision

Implement MCP as an **optional ingress adapter** parallel to REST API and CLI, defaulting to read-only.

### Architecture

```
MCP CLIENT (untrusted)
        ↓
MCP SERVER (transport + auth)
        ↓
AUTHORIZATION MIDDLEWARE
        ↓
APPLICATION SERVICE LAYER  ← same services as API/CLI
        ↓
SCOPE / POLICY VALIDATION (writes only)
        ↓
READ MODEL or CONTROLLER (writes only)
```

### Required read-only tools (Phase 10)

| Tool | Application Service |
|------|---------------------|
| `get_scan_status` | ScanService |
| `list_scan_assets` | AssetQueryService |
| `get_asset_details` | AssetQueryService |
| `get_asset_relationships` | GraphRepository via AssetQueryService |
| `get_scan_coverage` | CoverageService |
| `get_coverage_gaps` | CoverageService |
| `get_scan_metrics` | MetricsQueryService |
| `get_failed_tasks` | TaskQueryService |
| `get_deferred_tasks` | TaskQueryService |
| `get_hypotheses` | HypothesisService |
| `get_hypothesis_details` | HypothesisService |
| `get_validation_backlog` | ValidationService |
| `compare_scans` | ChangeDetectionService |
| `get_attack_surface_changes` | ChangeDetectionService |
| `get_tool_manifest` | ToolRegistryService |
| `validate_workflow_configuration` | WorkflowService |
| `validate_rule_configuration` | RuleEngineService |
| `explain_correlation` | CorrelationQueryService |

### Optional controlled write tools

Enabled only when `MCP_READ_ONLY=false` AND `MCP_WRITE_ENABLED=true`:

| Tool | Service | Additional checks |
|------|---------|-------------------|
| `create_scan` | ScanService | RBAC: scan_create role |
| `pause_scan` | ScanService | RBAC; scan must exist |
| `resume_scan` | ScanService | RBAC |
| `cancel_scan` | ScanService | RBAC |

Write tools **never** accept raw SQL, shell commands, scope blobs without validation, or arbitrary tool names.

### Explicitly prohibited MCP tools

These must never exist:

- `run_shell(command)`
- `execute_arbitrary_tool(command)`
- `run_sql(query)`
- `write_file(path, content)`
- `modify_scope_without_validation(...)`
- `record_validation_result` (analyst action via API only in v1)
- `confirm_finding`

### Security controls

| Control | Implementation |
|---------|----------------|
| Default off | `MCP_ENABLED=false` |
| Read-only default | Reject write tool registration when `MCP_READ_ONLY=true` |
| Auth | Same token validation as API |
| Input validation | Pydantic schemas per tool; scan_id UUID format |
| Output sanitization | No raw secrets from artifacts in responses |
| Rate limiting | Per-client limits on MCP server |
| Audit | AuditEvent for every MCP call with client identity |

### Read-only enforcement test

Property test: with `MCP_READ_ONLY=true`, invoking any write tool returns permission error and no database mutations occur.

## Consequences

### Positive

- Consistent behavior across API, CLI, MCP (single application service layer)
- Minimal attack surface when disabled (default)
- AI assistants can query assessment state safely
- Explain correlation tool supports analyst workflow without AI in core

### Negative

- Additional transport layer to maintain
- MCP schema must stay synchronized with API evolution
- Risk of scope creep (adding dangerous write tools)

### Guidelines for future MCP tools

1. Propose ADR amendment for any new write tool
2. Must call existing Application Service method
3. Must have integration test
4. Must not expose raw artifact content by default (use evidence IDs)

## References

- `docs/architecture.md` §4.1, §4.10
- `docs/threat-model.md` §5.6
- Product specification §26
