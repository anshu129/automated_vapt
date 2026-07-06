# Phase B Implementation Plan — Full Adaptive Recon Slice

## Status

**In progress** — fake-provider pipeline through endpoint inventory and surface gaps.

## Objective

Extend Phase A with the complete discovery slice:

```
DOMAIN → subdomain → DNS → port/HTTP → WAF → crawl → endpoints → surface gaps → assessment hooks
```

Evidence quality and marginal discovery gain apply at **every stage**. No real security tools (Phase J).

## Prerequisites

- [x] Phase A: capability registry, evidence quality, fake DNS alternate, vertical slice
- [x] Phase 1 core: assets, events, tasks, observations

## In scope

| Deliverable | Package | Status |
|-------------|---------|--------|
| Adaptive Recon Planner | `planning/adaptive_recon.py` | Done |
| Capability Matcher (surface gaps) | `capabilities/matcher.py` | Done |
| Controller uses planner | `controller/recon_controller.py` | Done |
| Fake providers: naabu, wafw00f, paramspider, js-collect | `adapters/fake/` | Done |
| Surface gap → capability scheduling | controller + planner | Done |
| Marginal gain gate on provider chain | `_should_schedule_capability` | Done |
| Phase B integration test | `tests/integration/test_phase_b_pipeline.py` | Done |
| Surface / applicability / matrix hooks | `engines/assessment.py` | Exists (stub depth) |

## Out of scope (later phases)

| Phase | Focus |
|-------|--------|
| C | Surface completeness engine depth, gap acceptance |
| D–F | Vulnerability applicability rules, test matrix, test planner |
| G–H | Evidence graph, verdict engine, completion evaluator |
| I | Credentials / authenticated coverage |
| J | Real tool integration (deferred per user) |
| K | MCP read tools |

## Fake provider matrix (Phase B)

| Capability | Provider | Behavior |
|------------|----------|----------|
| PASSIVE_SUBDOMAIN_DISCOVERY | fake-subfinder | 2 hostnames |
| DNS_RESOLUTION | fake-dnsx-silent → fake-dnsx-resolve | Inconclusive then success |
| PORT_DISCOVERY | fake-naabu | Service on 443 |
| HTTP_PROBING | fake-httpx | HTTP + web app + tech |
| WAF_IDENTIFICATION | fake-wafw00f | WAF operational context |
| LIVE_CRAWLING | fake-katana | 2 endpoints |
| PARAMETER_DISCOVERY | fake-paramspider | Noop complete |
| JAVASCRIPT_COLLECTION | fake-js-collect | Noop complete |
| TEMPLATE_BASED_ASSESSMENT | fake-nuclei | Scanner observation |

## Definition of done

- [x] `test_phase_b_full_recon_pipeline` passes
- [x] `test_adaptive_recon_vertical_slice` still passes
- [ ] Alembic migration 002 applied (optional; SQLite uses `init_db`)
- [ ] `GET /scans/{id}/surface-coverage` returns Phase B dimensions

## Next: Phase C

Surface Completeness Engine drives **accepted gaps** vs **blocking gaps**, and emits `SURFACE_GAP_IDENTIFIED` with structured gap metadata for the test planner.

See `docs/surface-completeness.md` and `database-migration-plan.md` §4.
