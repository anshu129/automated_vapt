# Phase 9 — Orchestration and Retention Analysis

## 1. Current report artifact storage

Phase 8 stores full report JSON on the local filesystem via `ReportArtifactStore` at
`{REPORT_ARTIFACT_ROOT}/{scan_id}/{snapshot_id}.json`. `ReportSnapshotService.create_snapshot`
writes the artifact after inserting the snapshot row and records reference metadata on the row.

## 2. Pluggability today

Storage is **filesystem-only**. `ReportArtifactStore` hardcodes path layout and is instantiated
inline inside `ReportSnapshotService` — no injectable backend, no object-store hook.

## 3. Retention

**None.** Artifacts accumulate indefinitely. Snapshot rows are never pruned. No TTL or max-version
policy exists.

## 4. Staleness checks

On-demand only via `ReportStalenessService.evaluate()` and `GET /scans/{id}/report-freshness`.
`mark_snapshot_stale_flags()` exists but is **not wired** into assessment completion or job end.

**Bug:** staleness compared `content_hash` (full report) against a live-fingerprint hash, causing
false `SNAPSHOT_MISMATCH` and blocking snapshot replay.

## 5. Background refresh

**None.** UI shows freshness from scan detail payload only. No polling service or scheduled job.

## 6. Parameter-scoped plan splitting

Phase 8 propagated `uniqueness_key` / `planning_fingerprint` into `TestPlan` and deduplicates via
`TestPlanUniquenessPolicy`. `RELATED` plans are skipped (not merged). No explicit split policy —
broad and parameter-scoped requirements remain distinct only when fingerprints differ.

## 7. Migration orchestration

`SqliteMigrationHelper` rebuilds `test_requirements` with the Phase 7/8 unique constraint. Detection
runs at startup (warning only). **No CLI or admin API** to run migration with dry-run.

## 8. Cross-scan integrity verification

**None.** Artifact hash is stored but not verified on load or audit.

## 9. Manual operator steps

| Task | Status |
|------|--------|
| Run SQLite migration | Manual Python / DB edit |
| Prune old report artifacts | Manual filesystem cleanup |
| Force report regeneration | API `?force_regenerate=true` (no UI button) |
| Verify artifact integrity | Not available |
| Check operational readiness | Partial via `/diagnostics/schema` |

## 10. Required file-level changes

| Area | Action |
|------|--------|
| `domain/report_artifact_backend.py` | Backend protocol + types |
| `domain/artifact_retention.py` | Retention policy types |
| `domain/plan_split_policy.py` | Split decision types |
| `domain/artifact_integrity.py` | Integrity status types |
| `services/report_artifact_backend_registry.py` | Config-driven backend selection |
| `services/filesystem_artifact_backend.py` | Filesystem backend |
| `services/object_store_artifact_backend.py` | Object-store stub |
| `services/report_artifact_store.py` | Delegate to registry |
| `services/report_artifact_retention_service.py` | TTL / max-version cleanup |
| `services/report_staleness_polling_service.py` | Cached freshness polling |
| `services/report_artifact_integrity_service.py` | Hash / existence audit |
| `services/test_plan_split_policy.py` | Planner split decisions |
| `services/sqlite_migration_command.py` | CLI/API migration wrapper |
| `services/report_staleness_service.py` | Fix fingerprint hash; full-hash fallback |
| `services/report_snapshot_service.py` | Backend injection; store `fingerprint_hash` |
| `services/report_hashing.py` | `compute_live_fingerprint_hash()` |
| `services/full_assessment.py` | Mark snapshots stale on completion change |
| `services/schema_compatibility_detector.py` | Phase 9 field detection |
| `db/tables/models.py` | Phase 9 columns |
| `db/schema_patches.py` | `apply_phase9_columns()` |
| `config/settings.py` | Phase 9 flags + retention settings |
| `api/routes/core.py` | Maintenance + operational endpoints |
| `api/routes/health.py` | Extended diagnostics |
| `cli/main.py` | Maintenance commands |
| `engines/assessment.py` | Split policy in planner |
| `web/app.js` | Operational signals + refresh |
| Tests | Unit + integration for Phase 9 scenarios A–E |
