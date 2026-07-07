# Phase 7 — Parameter Requirements, Report Snapshots, Completion Performance

## 1. Parameter-scoped requirement representation

`TestRequirement.reasoning_trace["parameter_scopes"]` holds merged parameter facts when a second scope cannot become its own row. `uniqueness_key` (SHA-256 over scan/asset/class/endpoint/parameter/role/auth dimensions) is indexed but **not** part of the DB unique constraint.

## 2. Where merging happens

`correlation_result_applier.py` `_upsert_test_requirement`: when `(matrix_id, vulnerability_class_id)` row exists with a different `uniqueness_key`, scope facts append to `parameter_scopes` instead of inserting.

## 3. Database constraint

`uq_test_requirement_matrix_class` on `(matrix_id, vulnerability_class_id)` prevents per-parameter rows today.

## 4. Report generation

`GET /scans/{id}/report` builds live JSON; no snapshot table exists.

## 5. Report snapshots

None — Phase 7 adds `report_snapshots` metadata table with content hash.

## 6. Report drift audit

Compare snapshot `content_hash` + `completion_version` across generations.

## 7. latest_transition

Phase 6 computes from `history[0]` on each payload build — Phase 7 denormalizes onto `AssessmentCompletionRecord`.

## 8. Read patterns

Overview/list endpoints load completion payload frequently; history query is heavier.

## 9. File changes

- `models.py`, `schema_patches.py`, `settings.py`
- `domain/test_requirement_uniqueness.py`, `domain/report_snapshot.py`
- `services/requirement_uniqueness_policy.py`, `services/report_snapshot_service.py`
- `correlation_result_applier.py`, `assessment.py` (matrix/planner)
- `completion_history_service.py`, `completion_serialization.py`
- `api/routes/core.py`, `web/app.js`

## 10. Safe additive migration

Replace unique constraint with `(matrix_id, vulnerability_class_id, uniqueness_key)`; legacy rows use `uniqueness_key=""`. Add columns only; no destructive rewrites.
