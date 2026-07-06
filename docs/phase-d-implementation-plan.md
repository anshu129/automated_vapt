# Phase D Implementation Plan — Vulnerability Applicability

## Status

**Complete** — versioned rules, condition evaluator, evidence-linked applicability states.

## Objective

Determine which vulnerability classes apply to each asset from surface evidence and technology context — without confirming vulnerabilities.

## Deliverables

| Deliverable | Location | Status |
|-------------|----------|--------|
| Applicability rules YAML | `config/applicability/rules.yaml` | Done |
| Condition evaluator | `vuln/applicability_rules.py` | Done |
| `ApplicabilityRule` DB model | `db/tables/models.py` | Done |
| Rule seeding | `scripts/seed.py` | Done |
| `VulnerabilityApplicabilityEngine` | `engines/vulnerability_applicability.py` | Done |
| `reevaluate()` + triggers | engine + controller | Done |
| `APPLICABILITY_COMPUTED` events | `recon_controller.py` | Done |
| `GET /scans/{id}/vulnerability-applicability` | `api/routes/core.py` | Done |
| Enhanced asset applicability API | rule_ids, explanation, evidence | Done |
| Unit + integration tests | `tests/unit`, `tests/integration` | Done |

## Rules shipped (v1.0)

- Web app baseline (6 classes)
- TLS when HTTPS
- Upload surface / upload endpoints
- Object-level authorization (API + login patterns)
- GraphQL endpoint
- Known component (POSSIBLY_APPLICABLE without version confidence)
- Injection (when parameter inventory partial+)

## Next: Phase E

Test Matrix Engine depth — coverage status transitions, evidence requirements per class.

See `docs/test-planner.md` and `database-migration-plan.md` §6.
