# Test Safety Policy

## 1. Purpose

Every automated validation capability has a **safety classification**. The Test Safety Policy Engine enforces which capabilities may run automatically, which require analyst approval, and which are prohibited — deterministically and without AI override.

---

## 2. SafetyClass enum

| Class | Description |
|-------|-------------|
| `PASSIVE` | No request mutation; observation only |
| `LOW_IMPACT` | Active but non-state-changing probes |
| `STATE_CHANGING` | May modify server-side state |
| `DESTRUCTIVE` | Could cause damage or data loss |
| `PROHIBITED` | Never execute in platform |

---

## 3. Default execution policy

| SafetyClass | Automatic execution |
|-------------|---------------------|
| `PASSIVE` | Allowed when in scope and engagement policy permits |
| `LOW_IMPACT` | Allowed when engagement policy permits |
| `STATE_CHANGING` | **Manual approval required** (`POST /test-plans/{id}/approve`) |
| `DESTRUCTIVE` | **Disabled** — never scheduled |
| `PROHIBITED` | **Never** — adapter registration rejected |

---

## 4. TestSafetyPolicyEngine

```python
class TestSafetyPolicyEngine(Protocol):
    def classify(self, capability: Capability, provider: CapabilityProvider) -> SafetyClass: ...

    def may_execute_automatically(
        self,
        plan: TestPlan,
        engagement_policy: EngagementPolicy,
    ) -> SafetyDecision: ...

    def may_schedule_task(
        self,
        task: Task,
        manifest: ToolManifest,
    ) -> SafetyDecision: ...
```

### SafetyDecision

| Field | Description |
|-------|-------------|
| `allowed` | bool |
| `reason_codes` | string[] |
| `required_approval` | bool |
| `rule_ids` | string[] |

---

## 5. Policy configuration (versioned YAML)

```yaml
version: "1.0"
engagement_policies:
  default:
    allow_passive: true
    allow_low_impact: true
    allow_state_changing: false  # requires per-plan approval
    allow_destructive: false

capability_overrides:
  TEMPLATE_BASED_ASSESSMENT:
    default_safety: LOW_IMPACT
    require_template_allowlist: true
  WEB_ACTIVE_ASSESSMENT:
    default_safety: STATE_CHANGING

template_safety_map:
  nuclei:
    tags:
      - "safe": LOW_IMPACT
      - "intrusive": STATE_CHANGING
      - "dos": PROHIBITED
```

---

## 6. Nuclei / template controls

- Templates must be categorized by safety class
- Execution uses allowlisted template sets per engagement policy
- Template ID + version stored in TestExecution
- AI and MCP **cannot** add templates to allowlist or change safety class

---

## 7. Integration points

| Checkpoint | Engine call |
|------------|-------------|
| CapabilityProvider registration | classify; reject PROHIBITED |
| TestPlanner.plan() | Sets safety_class on plan |
| Task persistence | may_schedule_task |
| AutomatedValidationOrchestrator pre-exec | may_execute_automatically |
| Scheduler | Reject tasks failing safety check |

---

## 8. Audit

Every denial produces `AuditEvent` with capability, safety_class, policy_version.

---

## 9. Invariants

1. AI cannot change safety classification
2. MCP cannot change safety classification
3. DESTRUCTIVE and PROHIBITED never execute
4. Safety policy version recorded per scan

---

## 10. References

- `capability-registry.md`
- `test-planner.md`
- `threat-model.md`
- ADR-0005
