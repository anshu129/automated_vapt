# Threat Model

## 1. Scope and assumptions

### System context

The platform orchestrates **authorized** vulnerability assessment in defined scopes. It:

- Executes approved security tools via isolated adapters
- Ingests scanner reports
- Correlates observations and generates hypotheses for human validation
- Exposes REST API, CLI, and optional MCP interface

### Trust boundaries

```
┌─────────────────────────────────────────────────────────────┐
│                    TRUSTED ZONE                              │
│  API / CLI / Application Services / Controller / Scheduler  │
│  PostgreSQL / Redis / Internal workers                       │
└──────────────────────────┬──────────────────────────────────┘
                           │ scope-validated invocation only
┌──────────────────────────▼──────────────────────────────────┐
│                 SEMI-TRUSTED ZONE                            │
│  Approved tool containers / Parser sandbox                   │
└──────────────────────────┬──────────────────────────────────┘
                           │ untrusted output
┌──────────────────────────▼──────────────────────────────────┐
│                 UNTRUSTED ZONE                               │
│  Target systems (in-scope) / Scanner reports / AI responses  │
│  MCP client inputs / Imported files                          │
└─────────────────────────────────────────────────────────────┘
```

### Assumptions

- Operators have legitimate authorization for all in-scope targets
- Infrastructure (PostgreSQL, Redis) is operated securely
- Network egress from workers is controlled
- Analysts are authenticated authorized users

### Out of scope

- Attacks against targets beyond configured scope (prevented by design)
- Physical security of operator workstations

---

## 2. Assets to protect

| Asset | Sensitivity | Impact if compromised |
|-------|-------------|----------------------|
| Scope configuration | High | Unauthorized scanning of out-of-scope targets |
| API credentials / secrets | Critical | Full platform abuse |
| Raw scan artifacts | High | Intelligence leakage about target environment |
| Confirmed findings | High | Premature disclosure of vulnerabilities |
| Task queue | Medium | Scan disruption, resource exhaustion |
| AI API keys | Medium | Cost abuse, data exfiltration to third party |
| Audit logs | Medium | Evidence tampering, accountability loss |
| Tool manifests | Medium | Substitution of malicious tool images |

---

## 3. Threat actors

| Actor | Motivation | Capability |
|-------|------------|------------|
| **Malicious analyst** | Expand scope, extract data | Authenticated API/CLI access |
| **Compromised worker** | Lateral movement, data exfil | Container escape, network access |
| **Malicious tool output** | Parser exploitation, stored XSS in reports | Crafted stdout/JSON/XML |
| **Malicious import file** | Code execution via parser bugs | Upload oversized/malformed reports |
| **MCP client abuse** | Read sensitive data, trigger writes | MCP protocol access |
| **AI prompt injection** | Manipulate summaries (not core state) | Crafted artifact content in AI inputs |
| **External attacker** | API exploitation, SSRF | Unauthenticated or stolen credentials |

---

## 4. STRIDE analysis

### Spoofing

| Threat | Mitigation |
|--------|------------|
| Forged API requests | Authentication (JWT/API key); RBAC |
| Worker impersonation | Worker identity + lease tokens |
| Fake scanner findings | Import validation; schema checks; provenance tracking |

### Tampering

| Threat | Mitigation |
|--------|------------|
| Raw artifact modification | Immutable storage; content hashes |
| Scope rule tampering | Audit events; versioned scope snapshots per scan |
| Task parameter injection | Pydantic validation; adapter whitelist parameters |
| AI output altering severity | AI cannot assign final severity (ADR-0003) |

### Repudiation

| Threat | Mitigation |
|--------|------------|
| Deny creating scan | AuditEvent for all mutations |
| Deny scope decisions | Scope decision audit records |
| Deny validation actions | ValidationResult with analyst identity |

### Information disclosure

| Threat | Mitigation |
|--------|------------|
| Secrets in logs | Redaction pipeline for command args and env |
| Cross-project data leak | project_id isolation on all queries |
| MCP over-disclosure | Read-only default; explicit write flag |
| Error messages leaking internals | Structured errors; no stack traces in production API |

### Denial of service

| Threat | Mitigation |
|--------|------------|
| Task queue flooding | Rate limits; concurrency caps; task deduplication |
| Oversized tool output | Output size limits; streaming truncation |
| Parser bomb (XML entity expansion) | Safe parser libraries; size limits |
| AI rate limit exhaustion | Caching; token budgets; graceful fallback |
| DB connection exhaustion | Connection pooling; query timeouts |

### Elevation of privilege

| Threat | Mitigation |
|--------|------------|
| Arbitrary command via API/MCP/AI | No shell execution endpoints; capability-only adapters |
| Scope bypass | Triple scope check (persist, schedule, execute) |
| MCP write without auth | Write ops require config + authorization |
| Container escape to host | Minimal images; non-root; read-only root FS |

---

## 5. Critical abuse scenarios

### 5.1 Unauthorized scanning (CRITICAL)

**Scenario:** Attacker adds `*.gov` to scope and launches active scans.

**Controls:**
- Scope Manager mandatory validation
- Scope snapshots immutable per scan
- Audit trail for scope changes
- RBAC: scope modification restricted role
- Passive-only mode enforcement per target class

### 5.2 Arbitrary command execution (CRITICAL)

**Scenario:** API endpoint or MCP tool accepts shell commands.

**Controls:**
- **Prohibited by architecture:** no `run_shell`, `execute_arbitrary_tool` endpoints
- Adapters invoke only pre-approved container images with fixed entrypoints
- Parameters validated against ToolManifest schema
- AI cannot generate or execute commands

### 5.3 Parser code execution (HIGH)

**Scenario:** Malicious XML/JSON in tool output exploits parser.

**Controls:**
- Treat all tool output as untrusted
- Use safe parsing libraries (defusedxml, strict JSON schema)
- Output size limits
- Parser runs with minimal privileges
- Fuzz testing in CI

### 5.4 SSRF via tool adapters (HIGH)

**Scenario:** Worker instructed to scan internal metadata endpoints.

**Controls:**
- Scope validation on normalized target before execution
- Blocklist for RFC1918/link-local unless explicitly in scope
- Egress network policies on worker containers
- URL normalization rejects file://, gopher://, etc.

### 5.5 AI-driven state manipulation (HIGH)

**Scenario:** AI confirms vulnerabilities or schedules tasks.

**Controls:**
- AI_ENABLED=false by default
- AI output validated with Pydantic; invalid output discarded
- No AI code path touches TaskRepository, ScopeManager, or ValidationService write methods
- Property test: AI cannot change core task state

### 5.6 MCP write abuse (MEDIUM)

**Scenario:** MCP client pauses competitor scans or modifies scope.

**Controls:**
- MCP_ENABLED=false by default
- MCP_READ_ONLY=true by default
- Write operations call Application Services with same auth as API
- No direct database access from MCP handlers

### 5.7 Hypothesis → auto-exploitation (CRITICAL)

**Scenario:** Platform automatically validates hypotheses by attacking targets.

**Controls:**
- Validation backlog is analyst-driven only
- `suggested_safe_checks` are descriptive, not executable payloads
- No autonomous validation worker
- Hypothesis engine outputs questions, not exploitation steps

### 5.8 Data exfiltration via reports (MEDIUM)

**Scenario:** Report includes secrets from raw artifacts.

**Controls:**
- Secret pattern redaction in reporting engine
- Evidence references by ID, not raw content in executive summary
- RBAC on report export

---

## 6. Security controls summary

### Preventive

| Control | Phase |
|---------|-------|
| Pydantic input validation (API, events, imports) | 1+ |
| Scope Manager triple-check | 1+ |
| Parameterized SQL (SQLAlchemy) | 1 |
| Container isolation for tools | 4 |
| RBAC design | 1 (schema), 2+ (enforcement) |
| Feature flags (AI, MCP) | 9, 10 |
| Dependency pinning | 0+ |

### Detective

| Control | Phase |
|---------|-------|
| AuditEvent logging | 1 |
| Structured logging with correlation IDs | 1 |
| Parser failure metrics | 4 |
| Scope denial metrics | 1 |
| Anomaly: high out-of-scope denial rate | 3+ |

### Corrective

| Control | Phase |
|---------|-------|
| Task lease expiry / dead worker recovery | 3 |
| Scan pause/cancel | 1 |
| Immutable raw artifacts (reprocess, not mutate) | 4 |
| AI fallback when unavailable | 9 |

---

## 7. Data classification

| Class | Examples | Handling |
|-------|----------|----------|
| **Restricted** | API keys, credentials, raw auth tokens in artifacts | Never log; redact; encrypt at rest (production) |
| **Confidential** | Findings, hypotheses, raw scan data | RBAC; project isolation |
| **Internal** | Task metrics, workflow versions | Standard access |
| **Public** | Health endpoint, tool manifest names | Unrestricted |

---

## 8. Residual risks

| Risk | Likelihood | Impact | Acceptance |
|------|------------|--------|------------|
| Zero-day in approved tool | Low | High | Monitor tool CVEs; version pinning |
| Container escape | Low | Critical | Keep images updated; minimal attack surface |
| Analyst social engineering of scope | Medium | High | Dual-control for scope changes (future) |
| AI hallucination in summaries | Medium | Low | AI not used for decisions; analyst review |
| Incomplete scope on shared infrastructure | Medium | Medium | Coverage engine + shared infra correlation |

---

## 9. Security testing requirements

Aligned with testing strategy (architecture.md §34):

- Property: out-of-scope tasks never execute
- Property: confirmed finding requires validation state
- Property: MCP read-only cannot mutate state
- Property: AI cannot change task state
- Failure: malformed tool output does not crash controller
- Failure: duplicate event delivery is idempotent
- Integration: scope denial at all three checkpoints

---

## 10. Review cadence

- Threat model review: each major phase (especially before Phase 4 tool integration)
- ADR review: when adding MCP write ops or AI capabilities
- Dependency audit: monthly in production operations
