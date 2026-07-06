# Credential Context

## 1. Purpose

Support explicitly authorized authenticated assessment while ensuring secrets never appear in events, logs, reports, AI prompts, MCP responses, or task payloads stored in the database.

---

## 2. Secret provider abstraction

```python
class SecretProvider(Protocol):
    def resolve(self, secret_backend_reference: str) -> SecretHandle: ...
    def revoke(self, handle: SecretHandle) -> None: ...

class SecretHandle:
    """Opaque; used only in worker memory during task execution."""
    reference: str
    expires_at: datetime
```

### Implementations

| Provider | Use case |
|----------|----------|
| `EnvSecretProvider` | Local dev (env vars) |
| `EncryptedFileSecretProvider` | Local dev encrypted store |
| `VaultSecretProvider` | Production (future) |

Workers receive **temporary scoped handles** at execution time only. Handles are never serialized to DB.

---

## 3. CredentialReference

| Field | Type | Description |
|-------|------|-------------|
| `id` | UUID | |
| `project_id` | UUID | |
| `credential_type` | CredentialType | See §4 |
| `label` | string | Analyst-friendly name |
| `secret_backend_reference` | string | Opaque pointer |
| `role_name` | string | e.g. `user`, `admin` |
| `expiry` | timestamp | |
| `allowed_capabilities` | Capability[] | Whitelist |
| `created_at` | timestamp | |
| `updated_at` | timestamp | |
| `status` | enum | ACTIVE, EXPIRED, REVOKED |

**Never stored:** password, token value, API key value, cookie value.

---

## 4. CredentialType

```
WEB_FORM
HTTP_BASIC
HTTP_BEARER
API_KEY
COOKIE_SESSION
OAUTH_CONTEXT
NETWORK_CREDENTIAL
CLOUD_CREDENTIAL_REFERENCE
```

---

## 5. CredentialScopeBinding

| Field | Type | Description |
|-------|------|-------------|
| `credential_id` | UUID | |
| `scope_rule_id` | UUID | Optional |
| `asset_id` | UUID | Optional specific asset |
| `application_id` | UUID | Optional web app binding |
| `url_prefix` | string | Optional path restriction |
| `assessment_mode` | enum | Must be CREDENTIALED |

**Invariant:** Credential use outside binding → Scope Manager DENY.

---

## 6. AuthenticationContext

Runtime metadata (no secrets):

| Field | Type | Description |
|-------|------|-------------|
| `id` | UUID | |
| `credential_id` | UUID | |
| `asset_id` | UUID | Target application |
| `auth_method` | CredentialType | |
| `session_established` | bool | |
| `session_expires_at` | timestamp | |
| `last_validated_at` | timestamp | |
| `coverage_dimensions` | string[] | What auth unlocked |

---

## 7. RoleContext

| Field | Type | Description |
|-------|------|-------------|
| `id` | UUID | |
| `authentication_context_id` | UUID | |
| `role_name` | string | |
| `authorized` | bool | Explicitly authorized for assessment |
| `coverage_status` | enum | per dimension |

Enables distinction:

| Coverage type | Meaning |
|---------------|---------|
| `UNAUTHENTICATED` | Public surface tested |
| `AUTHENTICATED` | At least one role tested |
| `ROLE_SPECIFIC` | Per-role coverage tracked |

Example:

```
Application A
  Unauthenticated crawl:     COMPLETE
  User-role crawl:           COMPLETE
  Admin-role crawl:          NOT AUTHORIZED
  Authorization comparison:  PARTIAL
```

---

## 8. CredentialContextManager

```python
class CredentialContextManager(Protocol):
    def get_eligible_credentials(
        self,
        asset_id: UUID,
        capability: Capability,
        scope_snapshot: ScopeSnapshot,
    ) -> list[CredentialReference]: ...

    def bind_session(
        self,
        credential_id: UUID,
        asset_id: UUID,
    ) -> AuthenticationContext: ...

    def check_auth_coverage_gap(
        self,
        application_id: UUID,
        scan_id: UUID,
    ) -> list[CoverageGap]: ...
```

---

## 9. API rules

- `POST /credentials` — create reference (secret via secure channel to provider, not in body logged)
- `GET /credentials/{id}` — metadata only; **never** secret values
- Credential endpoints redact all sensitive fields in audit logs

---

## 10. Prohibited flows

| Prohibited | Reason |
|------------|--------|
| Secret in task.parameters JSONB | DB exposure |
| Secret in Event payload | Event log exposure |
| Secret in AI prompt | Third-party leakage |
| Secret in MCP response | Client exposure |
| Auto-use credential outside binding | Scope violation |

---

## 11. References

- ADR-0009
- `threat-model.md` §5.1
- `test-planner.md`
- `recursive-correlation.md` (authenticated coverage rules)
