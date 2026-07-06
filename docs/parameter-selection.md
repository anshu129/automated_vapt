# Parameter Selection Engine

Research-backed, deterministic CLI flag selection for every integrated recon tool.

## Design principles

1. **Every flag has a documented reason** — stored in `config/parameters/references/` with official doc URLs, `when_to_use`, `rationale`, and `operational_triggers`.
2. **Rules correlate evidence to flags** — `config/parameters/rules/*.yaml` maps `operational_context` facts to `add_args` with auditable `rule_id` and `explanation`.
3. **No opaque tuning** — the engine is rule-based, not ML. Analysts can trace any flag to a rule and reference entry.
4. **Tools are not pipelines** — parameters adapt per target based on prior observations (WAF, ICMP block, wildcard DNS, rate limits, etc.).

## Layout

```
config/parameters/
├── references/          # Per-tool parameter research (63 tools)
│   ├── subdomain-discovery.yaml
│   ├── dns.yaml
│   ├── host-service.yaml
│   ├── crawling.yaml
│   ├── content-discovery.yaml
│   ├── url-parameters.yaml
│   ├── js-secrets.yaml
│   ├── fingerprinting.yaml
│   ├── osint.yaml
│   ├── cloud.yaml
│   └── api.yaml
└── rules/               # Adaptive rules keyed by operational_context
    ├── subdomain.yaml
    ├── dns.yaml
    ├── host-service.yaml
    └── ...
```

## Full tool catalogs (nmap exemplar)

High-impact tools use **full CLI catalogs** mirroring official `-h` / man page structure:

- `parameter_groups[]` — sections (HOST_DISCOVERY, SCAN_TECHNIQUES, …)
- Each entry: `id`, `flags`, `description`, `rationale`, optional `when_to_use`, `operational_triggers`, `adaptive_rule_id`

**nmap** documents **112 parameters** in 11 groups (Nmap 7.99SVN help). Regenerate via:

```bash
python scripts/generate_nmap_reference.py
```

Inspect: `GET /api/v1/tools/nmap/parameter-reference`

Other tools use compact `parameters[]` until expanded to full catalogs using the same schema.

## Reference entry schema (compact tools)

Each tool in `references/` includes:

| Field | Purpose |
|-------|---------|
| `official_docs` | URLs to vendor README, man pages, API docs |
| `summary` | What the tool does in this platform |
| `parameters[].id` | Stable key linked from rules via `reference_param` |
| `parameters[].flags` | CLI flags this entry describes |
| `parameters[].when_to_use` | Conditions for applying the flag |
| `parameters[].rationale` | Why the flag exists (from official docs) |
| `parameters[].operational_triggers` | Maps to `operational_context` facts |
| `parameters[].avoid_when` | Facts that suppress the flag |

## Operational context

Facts merged into `target_descriptor.operational_context` after each task:

| Fact | Source | Example downstream effect |
|------|--------|----------------------------|
| `proxy_arp_suspected` | nmap ARP false positives | nmap `--disable-arp-ping` (nmap.org man page) |
| `icmp_blocked` | nmap "host down" with filtered ports | nmap `-Pn` |
| `firewall_inferred` | nmap filtered, wafw00f | nmap `-sS`, naabu `-rate` reduction |
| `waf_detected` | wafw00f, httpx 429 | ffuf `-rate 50`, katana `-d 2 -delay 1` |
| `rate_limited` | httpx 429 | httpx `-rate-limit`, gau `--threads 2` |
| `wildcard_dns_suspected` | dnsx wildcard | dnsx `-wd`, shuffledns `-wf` |
| `low_subdomain_gain` | discovery gain engine | subfinder `-all`, amass `-brute` |
| `cdn_detected` | httpx CDN field | httpx Host header, naabu `-scan-all-ips` |
| `passive_only` | PASSIVE_ONLY profile | blocks active brute rules |
| `graphql_endpoint` | endpoint patterns | inql `--generate` |

## Rule example (nmap)

Official documentation ([nmap host discovery](https://nmap.org/book/man-host-discovery.html)) states `--disable-arp-ping` is for networks using **proxy ARP** where every host appears up. Our rule:

```yaml
- id: param-nmap-disable-arp-ping-proxy-arp
  tool: nmap
  reference_param: disable-arp-ping
  when:
    any_of: [proxy_arp_suspected, local_network_target]
  add_args: ["--disable-arp-ping"]
```

## Audit trail

- `task.parameters.parameter_decision` — rule IDs, explanations, input facts, redacted command
- `GET /api/v1/tasks/{id}/parameter-decision` — per-task audit
- `GET /api/v1/tools/{name}/parameter-reference` — full research entry for a tool
- `GET /api/v1/tools/parameter-references` — index of all 63 tools

## Coverage

All tools in `config/tools/manifests.yaml` must have a matching entry in `config/parameters/references/`. Enforced by `tests/unit/test_parameter_engine.py::test_all_manifest_tools_have_parameter_references`.
