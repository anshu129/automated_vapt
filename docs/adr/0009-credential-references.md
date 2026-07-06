# ADR-0009: Credential References Separated from Task Payloads

## Status

Accepted

## Date

2026-07-06

## Context

Authenticated assessment requires credentials. Storing secrets in task parameters, events, or database fields risks leakage via logs, AI, MCP, and backups.

## Decision

1. Store **CredentialReference** with `secret_backend_reference` only — never plaintext secrets
2. **SecretProvider** resolves handles at worker execution time in memory
3. Task payloads contain `credential_context_reference` (UUID), not secret values
4. AI prompts and MCP responses must never include resolved secrets
5. Secret indicators from discovery stored redacted with protected artifact references

## Consequences

**Positive:** Reduced credential exposure; vault-ready design.

**Negative:** Worker secret injection complexity; dev needs EnvSecretProvider.

## References

- `credential-context.md`
- `threat-model.md`
