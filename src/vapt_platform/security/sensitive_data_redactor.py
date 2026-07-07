"""Deterministic redaction of sensitive data before persistence/logging."""

from __future__ import annotations

import re
from typing import Any

_REDACTED = "[REDACTED]"

_HEADER_PATTERNS = (
    (re.compile(r"(?i)(authorization\s*:\s*)([^\r\n]+)"), r"\1" + _REDACTED),
    (re.compile(r"(?i)(proxy-authorization\s*:\s*)([^\r\n]+)"), r"\1" + _REDACTED),
    (re.compile(r"(?i)(cookie\s*:\s*)([^\r\n]+)"), r"\1" + _REDACTED),
    (re.compile(r"(?i)(set-cookie\s*:\s*)([^\r\n]+)"), r"\1" + _REDACTED),
    (re.compile(r"(?i)(x-api-key\s*:\s*)([^\r\n]+)"), r"\1" + _REDACTED),
    (re.compile(r"(?i)(api-key\s*:\s*)([^\r\n]+)"), r"\1" + _REDACTED),
)

_BEARER = re.compile(r"(?i)\bbearer\s+[a-z0-9\-._~+/]+=*\b")
_BASIC_AUTH = re.compile(r"(?i)\bbasic\s+[a-z0-9+/]+=*\b")
_CREDENTIAL_FIELDS = ("password", "secret", "token", "api_key", "apikey", "access_token")


class SensitiveDataRedactor:
    def redact_text(self, value: str) -> str:
        if not value:
            return value
        redacted = value
        for pattern, replacement in _HEADER_PATTERNS:
            redacted = pattern.sub(replacement, redacted)
        redacted = _BEARER.sub(f"Bearer {_REDACTED}", redacted)
        redacted = _BASIC_AUTH.sub(f"Basic {_REDACTED}", redacted)
        return redacted

    def redact_dict(self, payload: dict[str, Any]) -> dict[str, Any]:
        return {key: self._redact_value(key, value) for key, value in payload.items()}

    def _redact_value(self, key: str, value: Any) -> Any:
        key_l = key.lower()
        if key_l in _CREDENTIAL_FIELDS or key_l.endswith("_token"):
            return _REDACTED
        if isinstance(value, dict):
            return self.redact_dict(value)
        if isinstance(value, list):
            return [self._redact_value(key, item) for item in value]
        if isinstance(value, str):
            return self.redact_text(value)
        return value
