# Phase C Implementation Plan — Surface Completeness

## Status

**Complete** — eligibility-driven dimensions, gap classification, scan summary API.

## Objective

Per-asset surface coverage as source of truth for test planning and assessment completion, with structured gap metadata and analyst gap acceptance.

## Deliverables

| Deliverable | Location | Status |
|-------------|----------|--------|
| Surface completeness engine | `engines/surface_completeness.py` | Done |
| Eligibility-driven dimensions | web app + hostname rules | Done |
| `missing_requirements` + blocking classification | `SurfaceRequirement` | Done |
| `compute_scan_summary` | engine method | Done |
| Structured `SURFACE_GAP_IDENTIFIED` | `recon_controller.py` | Done |
| `SURFACE_COVERAGE_COMPUTED` events | `recon_controller.py` | Done |
| Endpoint inference from assets | surface engine | Done |
| Completion evaluator (accepted vs blocking) | `assessment.py` | Done |
| `GET /scans/{id}/surface-coverage` | `api/routes/core.py` | Done |
| `POST /scans/{id}/accepted-gaps` | `api/routes/core.py` | Done |
| Phase C integration tests | `tests/integration/test_phase_c_surface.py` | Done |

## Next: Phase D

Vulnerability applicability rules depth — condition JSON evaluation, evidence-linked applicability states.

See `docs/vulnerability-applicability.md` and `database-migration-plan.md` §5.
