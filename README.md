# VAPT Platform

Authorized vulnerability assessment, reconnaissance correlation, attack surface mapping, and security hypothesis generation platform.

## Quick start

```bash
# Install
pip install -e ".[dev]"

# SQLite dev (no Docker)
set DATABASE_URL=sqlite+aiosqlite:///./vapt.db
set DATABASE_URL_SYNC=sqlite+aiosqlite:///./vapt.db
python -m vapt_platform.scripts.seed

# Run API
uvicorn vapt_platform.main:app --reload

# Or Docker
docker compose up -d
docker compose exec api python -m vapt_platform.scripts.seed
```

## Tool integration

63 recon tools are declared in `config/tools/manifests.yaml` (Amass, Subfinder, nmap, httpx, katana, ffuf, Shodan, etc.). The platform selects **capabilities**, not fixed pipelines:

- **Capability registry** picks the best provider per task (priority, cost, marginal gain).
- **Parameter engine** (`config/parameters/rules.yaml`) adapts CLI flags from evidence — e.g. firewall inferred → nmap `--disable-arp-ping`.
- **Fake fallback** when a binary is not installed (dev/tests).

See `docs/parameter-selection.md` for the correlation model.

## API

- `GET /health` — health check
- `POST /api/v1/projects` — create project
- `POST /api/v1/scans?project_id=` — create scan
- `POST /api/v1/scans/{id}/start` — run adaptive recon pipeline
- `GET /api/v1/scans/{id}/assets` — asset inventory
- `GET /api/v1/capabilities` — capability registry
- `GET /api/v1/scans/{id}/tasks` — tasks with parameter decisions
- `GET /api/v1/tasks/{id}/parameter-decision` — explainable flag correlation audit
- `GET /api/v1/tools/parameter-references` — per-tool parameter research index
- `GET /api/v1/tools/{name}/parameter-reference` — full flag rationale for one tool

## First report flow

```bash
# Confirm tool visibility in your current shell
vapt tools-readiness-local

# Create project and scan. --target accepts root domains, hostnames, URLs, or IPs.
vapt project-create "Example"
vapt scan-create <project_id> "Example scan" --target example.com
vapt scan-start <scan_id>
vapt scan-report <scan_id>
```

Useful report/readiness endpoints:

- `GET /api/v1/tools/readiness`
- `GET /api/v1/scans/{id}/report`

## Architecture

See `docs/architecture.md` for full design.

## Tests

```bash
pytest tests/ -v
```
