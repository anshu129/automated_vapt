# ADR-0002: PostgreSQL Relational Model for Attack Surface Graph

## Status

Accepted

## Date

2026-07-06

## Context

The platform models an attack surface as a graph of assets connected by typed, evidence-backed relationships. Queries include:

- Domain → hostname → IP → service → application → endpoint chains
- Shared certificate and shared infrastructure detection
- Trust and authentication relationships
- Finding and hypothesis correlation across graph paths

Options considered:

1. **Graph database (Neo4j, etc.)** — Native graph traversal; operational overhead; team may lack expertise.
2. **PostgreSQL with adjacency list / closure table** — Mature operations; sufficient for expected scale initially.
3. **Hybrid from day one** — Complexity without proven need.

Expected initial scale: thousands to low millions of relationships per project. Traversal depth typically ≤ 6 hops for assessment workflows.

## Decision

Store the relationship graph in **PostgreSQL** using normalized `relationships` and `assets` tables. Expose graph operations through a **`GraphRepository` protocol** (see domain-model.md §16) so a graph database adapter can be added later without changing domain logic.

### Schema approach

```sql
-- Conceptual (full schema in Phase 1 migrations)
relationships (
  id UUID PK,
  scan_id UUID,
  source_asset_id UUID FK,
  target_asset_id UUID FK,
  relationship_type TEXT,
  confidence FLOAT,
  evidence_ids UUID[],
  first_seen TIMESTAMPTZ,
  last_seen TIMESTAMPTZ,
  active BOOLEAN,
  superseded_by_id UUID FK NULL
)
```

### Indexing strategy

- `(scan_id, source_asset_id, relationship_type)`
- `(scan_id, target_asset_id, relationship_type)`
- `(scan_id, relationship_type)` for type-filtered scans
- `assets(scan_id, asset_type, normalized_key)` unique where active

### Non-destructive updates

Conflicting relationships are **not** overwritten. New evidence creates a new relationship row or supersedes via `superseded_by_id` while retaining history.

### Graph projection interface

Domain services depend on `GraphRepository`, not raw SQL:

- `get_neighbors(asset_id, rel_types)`
- `find_path(source, target, max_depth)` — recursive CTE in PostgreSQL implementation
- `get_shared_infrastructure(asset_id)` — queries for SHARES_IP_WITH, SHARES_CERTIFICATE_WITH, SHARES_INFRASTRUCTURE_WITH
- `project_subgraph(scan_id, root, depth)` — for API and future dashboard

### Traversal limits

- Default `max_depth = 6` in API
- Query timeouts enforced at repository layer

## Consequences

### Positive

- Single database technology reduces operational burden
- ACID transactions for asset + relationship updates in controller
- JSONB for flexible evidence and metadata
- Familiar backup/replication tooling

### Negative

- Deep graph analytics (centrality at scale) may be slower than native graph DB
- Recursive CTEs require careful query tuning
- N-hop correlation rules may need materialized views at scale

### Future migration path

If profiling shows graph query bottleneck:

1. Implement `Neo4jGraphRepository` adapter
2. Project relationships asynchronously from PostgreSQL (source of truth)
3. Domain logic unchanged

## Alternatives rejected

| Alternative | Reason |
|-------------|--------|
| Graph DB only | Premature; loses relational integrity for tabular entities |
| JSON document graph | Poor query performance; weak integrity |
| Adjacency in application memory | Not persistent; not multi-worker safe |

## References

- `docs/domain-model.md` §4, §16
- `docs/architecture.md` §5.2
