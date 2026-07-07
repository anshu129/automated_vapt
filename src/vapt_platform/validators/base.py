"""Connector contracts and vulnerability-class -> tool mapping."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable
from urllib.parse import quote, urlparse, urlunparse

# Ordered heuristics mapping a vulnerability class code (substring match) to the
# nuclei template tags that best corroborate it. Kept intentionally conservative
# and low-impact; intrusive tags (dos/fuzz) are always excluded at run time.
_CLASS_TAG_RULES: list[tuple[tuple[str, ...], tuple[str, ...]]] = [
    (("SQL", "INJECTION"), ("sqli", "injection")),
    (("XSS", "CROSS_SITE_SCRIPTING"), ("xss",)),
    (("SSRF", "SERVER_SIDE_REQUEST"), ("ssrf",)),
    (("TRAVERSAL", "LFI", "LOCAL_FILE"), ("lfi",)),
    (("RCE", "COMMAND_INJECTION", "REMOTE_CODE"), ("rce",)),
    (("REDIRECT",), ("redirect",)),
    (("CORS", "CROSS_ORIGIN"), ("cors",)),
    (("TAKEOVER", "STALE", "HISTORICAL"), ("takeover",)),
    (("CREDENTIAL", "DEFAULT_LOGIN"), ("default-login",)),
    (("CVE", "KNOWN_VULN"), ("cve",)),
    (("TLS", "TRANSPORT", "SSL"), ("ssl",)),
    (("SECRET", "EXPOSED", "EXPOSURE", "DISCLOSURE", "INFORMATION"), ("exposure",)),
    (("MISCONFIG", "CONFIGURATION", "HEADER", "SECURITY_MISCONFIG"), ("misconfig",)),
    (("AUTHENTICATION", "SESSION"), ("default-login", "exposure")),
]

# Fallback tags when no rule matches: broad but still low-impact.
_DEFAULT_TAGS: tuple[str, ...] = ("misconfig", "exposure")


def with_auth_url(url: str, username: str | None, password: str | None) -> str:
    """Embed HTTP basic credentials into a URL when not already present."""
    if not url or not username or not password:
        return url
    parsed = urlparse(url)
    if parsed.username:
        return url
    host = parsed.hostname
    if not host:
        return url
    netloc = f"{quote(username, safe='')}:{quote(password, safe='')}@{host}"
    if parsed.port:
        netloc += f":{parsed.port}"
    return urlunparse(
        (parsed.scheme, netloc, parsed.path, parsed.params, parsed.query, parsed.fragment)
    )


def nuclei_tags_for_class(class_code: str) -> list[str]:
    """Return the nuclei tags most relevant to a vulnerability class code."""
    code = (class_code or "").upper()
    for needles, tags in _CLASS_TAG_RULES:
        if any(needle in code for needle in needles):
            return list(tags)
    return list(_DEFAULT_TAGS)


@dataclass
class ValidationFinding:
    """A single corroborating signal produced by a validation connector."""

    template_id: str | None
    name: str | None
    severity: str | None
    matched_at: str | None
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "template_id": self.template_id,
            "name": self.name,
            "severity": self.severity,
            "matched_at": self.matched_at,
            "tags": self.tags,
        }


@dataclass
class ValidationOutcome:
    """Result of running one connector against one target."""

    connector: str
    target_url: str
    asset_id: str | None
    class_codes: list[str]
    tags: list[str]
    status: str  # CORROBORATED | NO_EVIDENCE | ERROR | UNAVAILABLE
    findings: list[ValidationFinding] = field(default_factory=list)
    detail: str | None = None
    redacted_command: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "connector": self.connector,
            "target_url": self.target_url,
            "asset_id": self.asset_id,
            "class_codes": self.class_codes,
            "tags": self.tags,
            "status": self.status,
            "finding_count": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
            "detail": self.detail,
            "redacted_command": self.redacted_command,
        }


@runtime_checkable
class ValidationConnector(Protocol):
    """A tool-backed validator (nuclei, Burp MCP, sqlmap MCP, ...)."""

    name: str
    safety_class: str
    active: bool

    def is_available(self) -> bool:
        """Whether the underlying tool/MCP server is reachable right now."""
        ...

    async def validate(
        self,
        target_url: str,
        tags: list[str],
        class_codes: list[str],
        asset_id: str | None = None,
        username: str | None = None,
        password: str | None = None,
    ) -> ValidationOutcome:
        """Run the tool and return corroborating evidence."""
        ...
