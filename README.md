# VAPT Platform

Authorized vulnerability assessment, reconnaissance correlation, attack surface mapping, and security hypothesis generation platform.

## Quick Start

```bash
# Install
pip install -e ".[dev]"

# SQLite dev, no Docker
set DATABASE_URL=sqlite+aiosqlite:///./vapt.db
set DATABASE_URL_SYNC=sqlite+aiosqlite:///./vapt.db
python -m vapt_platform.scripts.seed

# Run API
uvicorn vapt_platform.main:app --reload

# Or Docker
docker compose up -d
docker compose exec api python -m vapt_platform.scripts.seed
```

## Tool Integration

Recon tools are declared in `config/tools/manifests.yaml`. The platform selects capabilities, not fixed pipelines:

- The capability registry picks providers by priority, cost, availability, and profile.
- The parameter engine adapts CLI flags from evidence and operational context.
- Fake providers keep the Phase A-E pipeline runnable without local security tools.

See `docs/parameter-selection.md` and `docs/capability-registry.md`.

## First Assessment Flow

```bash
# Confirm local tool visibility
vapt tools-readiness-local

# Create project and scan. --target accepts root domains, hostnames, URLs, or IPs.
vapt project-create "Example"
vapt scan-create <project_id> "Example scan" --target example.com
vapt scan-start <scan_id>
vapt scan-report <scan_id>
```

Run and export the complete authorized workflow in one command:

```bash
vapt assess-target example.com --output-dir reports/example.com
```

Or export an existing scan:

```bash
vapt scan-generate-plans <scan_id>
vapt scan-execute-automated <scan_id>
vapt scan-export <scan_id> --output-dir reports/example.com
```

The export bundle contains scan metadata, assets, relationships, events, tasks,
surface coverage, vulnerability applicability, the full test matrix, test plans and
executions, hypotheses, validation backlog and results, evidence packages and links,
verdicts, confirmed findings, discovery gain, completion status, and the combined
assessment report.

`assess-target` executes only pre-approved `PASSIVE` and `LOW_IMPACT` automated
plans. Automated scanner matches are routed to the analyst validation backlog and
cannot become confirmed findings without recorded evidence.

`SCAN_START_INLINE_EXECUTION=true` makes `scan-start` run the bounded adaptive pipeline immediately, using fake fallback providers when real tools are unavailable. Set it to `false` to only enqueue work, then execute tasks explicitly:

```bash
vapt scan-run-ready <scan_id> --limit 0
```

## API

- `GET /health` - health check
- `POST /api/v1/projects` - create project
- `POST /api/v1/scans?project_id=` - create scan
- `POST /api/v1/scans/{id}/start` - start or run the adaptive recon pipeline, depending on `SCAN_START_INLINE_EXECUTION`
- `POST /api/v1/scans/{id}/run-ready` - execute queued ready tasks
- `GET /api/v1/scans/{id}/assets` - asset inventory
- `GET /api/v1/scans/{id}/relationships` - attack surface graph edges
- `GET /api/v1/scans/{id}/tasks` - tasks with parameter decisions
- `GET /api/v1/scans/{id}/surface-coverage` - surface completeness
- `GET /api/v1/scans/{id}/vulnerability-applicability` - vulnerability class applicability
- `GET /api/v1/scans/{id}/test-matrix` - per-asset test matrix summary
- `POST /api/v1/scans/{id}/test-plans/generate` - generate automated, assisted, and manual plans from the matrix
- `POST /api/v1/scans/{id}/test-plans/execute-automated` - execute safe pre-approved automated plans
- `GET /api/v1/scans/{id}/test-plans` - list generated test plans
- `GET /api/v1/scans/{id}/test-executions` - normalized automated execution evidence
- `GET /api/v1/scans/{id}/hypotheses` - evidence-backed claims awaiting validation
- `GET /api/v1/scans/{id}/validation-backlog` - analyst validation work queue
- `GET /api/v1/scans/{id}/validation-results` - recorded analyst outcomes
- `GET /api/v1/scans/{id}/evidence-packages` - assisted validation evidence bundles
- `GET /api/v1/scans/{id}/evidence-links` - validation-to-hypothesis evidence graph
- `GET /api/v1/scans/{id}/verdicts` - formal hypothesis verdicts
- `GET /api/v1/scans/{id}/confirmed-findings` - evidence-gated confirmed findings
- `GET /api/v1/scans/{id}/report` - first JSON assessment report

## Architecture

See `docs/architecture.md` for the full design and phase roadmap.

## Tests

```bash
pytest tests/ -v
```
