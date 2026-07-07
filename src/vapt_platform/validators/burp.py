"""Burp Suite MCP validation connector (SSE).

Uses PortSwigger's Burp MCP extension ([PortSwigger/mcp-server](https://github.com/PortSwigger/mcp-server))
to read scanner issues and proxy history for the authorized target. Passive by default;
does not send new HTTP requests unless extended later with active_allowed.
"""

from __future__ import annotations

import json
import re
import socket
from typing import Any
from urllib.parse import urlparse

from vapt_platform.validators.base import ValidationFinding, ValidationOutcome, with_auth_url
from vapt_platform.validators.mcp_client import call_sse_tool, mcp_sdk_available

_SCANNER_TOOL = "get_scanner_issues"
_HISTORY_TOOL = "get_proxy_http_history_regex"


class BurpMcpValidator:
    """Read Burp scanner issues / proxy history via the official SSE MCP server."""

    name = "burp"
    safety_class = "PASSIVE"
    active = False

    def __init__(self, sse_url: str = "http://127.0.0.1:9876") -> None:
        self.sse_url = sse_url.rstrip("/")
        # Burp's MCP extension serves SSE at the root URL on :9876 for the Python
        # MCP SDK; /sse returns 404 on current Burp builds. Try root first, then /sse.
        if self.sse_url.endswith("/sse"):
            base = self.sse_url[: -len("/sse")]
            self._sse_candidates = [base, self.sse_url]
        else:
            self._sse_candidates = [self.sse_url, f"{self.sse_url}/sse"]

    @property
    def primary_sse_url(self) -> str:
        return self._sse_candidates[0]

    def is_available(self) -> bool:
        if not mcp_sdk_available():
            return False
        parsed = urlparse(self.primary_sse_url)
        host = parsed.hostname or "127.0.0.1"
        port = parsed.port or 9876
        try:
            with socket.create_connection((host, port), timeout=2.0):
                return True
        except OSError:
            return False

    async def validate(
        self,
        target_url: str,
        tags: list[str],
        class_codes: list[str],
        asset_id: str | None = None,
        username: str | None = None,
        password: str | None = None,
    ) -> ValidationOutcome:
        target_url = with_auth_url(target_url, username, password)
        hostname = urlparse(target_url).hostname or target_url
        outcome = ValidationOutcome(
            connector=self.name,
            target_url=target_url,
            asset_id=asset_id,
            class_codes=class_codes,
            tags=list(tags),
            status="NO_EVIDENCE",
            redacted_command=f"burp-mcp {_SCANNER_TOOL} + {_HISTORY_TOOL} @ {self.primary_sse_url}",
        )
        if not mcp_sdk_available():
            outcome.status = "UNAVAILABLE"
            outcome.detail = 'Install MCP SDK: pip install -e ".[mcp]"'
            return outcome

        findings: list[ValidationFinding] = []
        errors: list[str] = []

        issue_text, issue_err = await self._call_burp_tool(
            _SCANNER_TOOL,
            {"count": 50, "offset": 0},
        )
        if issue_err:
            errors.append(issue_err)
        else:
            findings.extend(self._parse_scanner_issues(issue_text, hostname, target_url))

        if not findings:
            history_text, history_err = await self._call_burp_tool(
                _HISTORY_TOOL,
                {"regex": re.escape(hostname), "count": 30, "offset": 0},
            )
            if history_err:
                errors.append(history_err)
            else:
                findings.extend(self._parse_history_signals(history_text, hostname, target_url))

        if findings:
            outcome.findings = findings
            outcome.status = "CORROBORATED"
            outcome.detail = f"Burp MCP returned {len(findings)} issue(s) for {hostname}."
        elif errors:
            outcome.status = "ERROR"
            outcome.detail = "; ".join(errors)[:400]
        else:
            outcome.detail = f"No Burp scanner issues or proxy history matched {hostname}."
        return outcome

    async def _call_burp_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> tuple[str, str | None]:
        last_error: str | None = None
        for url in self._sse_candidates:
            text, err = await call_sse_tool(url, tool_name, arguments)
            if not err:
                return text, None
            last_error = err
            if "404" not in (err or ""):
                break
        return "", last_error

    @staticmethod
    def _parse_scanner_issues(raw: str, hostname: str, target_url: str) -> list[ValidationFinding]:
        findings: list[ValidationFinding] = []
        host_l = hostname.lower()
        url_l = target_url.lower()
        for chunk in BurpMcpValidator._json_chunks(raw):
            host = str(
                chunk.get("host")
                or chunk.get("hostname")
                or chunk.get("origin")
                or chunk.get("url")
                or ""
            ).lower()
            path = str(chunk.get("path") or chunk.get("location") or "")
            if (
                host_l not in host
                and host_l not in path
                and host_l not in url_l
                and url_l not in json.dumps(chunk).lower()
            ):
                continue
            name = chunk.get("name") or chunk.get("issueName") or chunk.get("type")
            severity = chunk.get("severity") or chunk.get("confidence")
            findings.append(
                ValidationFinding(
                    template_id=str(chunk.get("type") or chunk.get("issueType") or "burp-scanner"),
                    name=str(name) if name else "Burp scanner issue",
                    severity=str(severity).lower() if severity else "medium",
                    matched_at=str(chunk.get("path") or chunk.get("url") or hostname),
                    tags=["burp", "scanner"],
                )
            )
        return findings

    @staticmethod
    def _parse_history_signals(raw: str, hostname: str, target_url: str) -> list[ValidationFinding]:
        """Treat suspicious proxy entries as weak corroboration only."""
        if not raw.strip() or "access denied" in raw.lower():
            return []
        host_l = hostname.lower()
        suspicious = ("error", "sql", "admin", "debug", "exception", "token", "password")
        findings: list[ValidationFinding] = []
        for chunk in BurpMcpValidator._json_chunks(raw):
            blob = json.dumps(chunk).lower()
            if host_l not in blob and host_l not in target_url.lower():
                continue
            if not any(word in blob for word in suspicious):
                continue
            url = chunk.get("url") or chunk.get("request") or hostname
            findings.append(
                ValidationFinding(
                    template_id="burp-proxy-history",
                    name="Suspicious proxy history entry",
                    severity="info",
                    matched_at=str(url)[:500],
                    tags=["burp", "proxy"],
                )
            )
        return findings[:5]

    @staticmethod
    def _json_chunks(raw: str) -> list[dict[str, Any]]:
        chunks: list[dict[str, Any]] = []
        if not raw.strip():
            return chunks
        for line in raw.splitlines():
            line = line.strip()
            if not line or line.startswith("No "):
                continue
            try:
                parsed = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(parsed, dict):
                chunks.append(parsed)
            elif isinstance(parsed, list):
                chunks.extend(item for item in parsed if isinstance(item, dict))
        if not chunks:
            try:
                parsed = json.loads(raw)
                if isinstance(parsed, dict):
                    chunks.append(parsed)
                elif isinstance(parsed, list):
                    chunks.extend(item for item in parsed if isinstance(item, dict))
            except json.JSONDecodeError:
                pass
        return chunks
