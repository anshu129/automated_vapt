# Phase 8 — Report Artifacts, Staleness, TestPlan Identity, SQLite Migration

## 1. Report storage today
`GET /scans/{id}/report` generates live JSON; Phase 7 `report_snapshots` stores metadata + `content_summary` only — no full replayable artifact.

## 2. Full JSON artifact
Not persisted today. Phase 8 adds filesystem-backed `ReportArtifactStore`.

## 3. Snapshot replayability
Metadata-only until Phase 8 adds `artifact_reference` on `ReportSnapshot`.

## 4. Hash generation
`compute_report_content_hash()` in `report_snapshot_service.py` — canonical JSON, volatile timestamps stripped.

## 5. Staleness without full regeneration
Compare snapshot `content_hash` / `assessment_status` / `completion_version` / `latest_transition_id` against live completion record + lightweight live fingerprint.

## 6. TestPlan uniqueness
`reasoning_trace.requirement_id` only (Phase 7). No `uniqueness_key` column on `TestPlan` yet.

## 7. SQLite migration today
Additive `schema_patches.py` only; `create_all` on fresh DBs uses ORM constraints. Legacy DBs may retain `uq_test_requirement_matrix_class`.

## 8. Risk without migration
Parameter-scoped requirements cannot insert as distinct rows under legacy constraint.

## 9. Safe SQLite path
Explicit `SqliteMigrationHelper.migrate_test_requirements_unique_constraint()` — table rebuild, not startup auto-run.

## 10. File changes
`report_artifact_store.py`, `report_staleness_service.py`, `test_plan_uniqueness_policy.py`, `schema_compatibility_detector.py`, `sqlite_migration_helper.py`, models, schema_patches, core API, health diagnostics, planner, UI.
