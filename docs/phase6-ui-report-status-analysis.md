# Phase 6 — UI / Report / Status Analysis

## 1. UI shows only job status today

`app.js` `updateProgress()` and `openScan()` set `scanStatusBadge` from `job.status` or `scan.status` only.

## 2. Assessment status availability

`GET /scans/{id}/completion-status` returns assessment fields (Phase 5). Not consumed by UI overview.

## 3. Report omits completion breakdown

`scan_report` includes minimal `completion: {status, blocking_items, metrics}` — no history, reason codes, or pending work summary.

## 4. `to_report_dict()` consumption point

`AssessmentCompletionResult.to_report_dict()` exists but unused; Phase 6 wires `CompletionSerializationService`.

## 5. scan.status alignment

`Scan.status` is lifecycle (`CREATED`/`RUNNING`/`COMPLETED`). Not synced to assessment completion. Phase 6 keeps separate; API exposes both.

## 6. Status history

No `AssessmentCompletionHistory` table today.

## 7. History storage

New `assessment_completion_history` table.

## 8. API changes

- Extend `GET /scans/{id}` with `assessment_completion` payload
- Add `GET /scans/{id}/assessment-state`
- Extend `scan_report` completion section
- Extend `GET /ui/jobs/{id}` (already has assessment fields from Phase 5)

## 9. UI changes

- Dual badges: Job status + Assessment status
- Overview completion card with summary, reasons, pending work, history timeline
- New tab or overview section for history

## 10. Report changes

Full `assessment_completion` + `assessment_completion_history` sections via serializer.

## 11. Files to modify

- `models.py`, `schema_patches.py`, `settings.py`
- `completion_history_service.py`, `completion_serialization.py` (new)
- `assessment_completion_evaluator.py`, `full_assessment.py`
- `api/routes/core.py`, `api/routes/ui.py`
- `web/app.js`, `web/index.html`, `web/styles.css`
