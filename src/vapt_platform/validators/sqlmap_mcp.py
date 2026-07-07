"""SQLMap MCP validation connector (stdio).

Wraps the FastMCP SQLMap server ([mohdhaji87/SQLMap-MCP](https://github.com/mohdhaji87/SQLMap-MCP))
for conservative SQL-injection corroboration. Marked active=True — only runs when the scan
request sets active_allowed=true.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from shutil import which

from vapt_platform.validators.base import ValidationFinding, ValidationOutcome, with_auth_url
from vapt_platform.validators.mcp_client import call_stdio_tool, mcp_sdk_available

_POSITIVE_PATTERNS = (
    r"is vulnerable",
    r"sql injection",
    r"parameter\s+'[^']+'\s+is injectable",
    r"type:\s*boolean-based",
    r"type:\s*error-based",
    r"type:\s*time-based",
    r"type:\s*union query",
)
_NEGATIVE_PATTERNS = (
    r"not injectable",
    r"does not appear to be injectable",
    r"all tested parameters",
)


class SqlmapMcpValidator:
    name = "sqlmap"
    safety_class = "ACTIVE"
    active = True

    def __init__(
        self,
        server_path: str,
        command: str = "python",
        extra_args: list[str] | None = None,
    ) -> None:
        self.server_path = server_path
        self.command = command
        self.extra_args = extra_args or []

    def _stdio_args(self) -> list[str]:
        return [*self.extra_args, self.server_path]

    def _venv_scripts_dir(self) -> Path | None:
        server = Path(self.server_path)
        scripts = server.parent / ".venv" / "Scripts"
        return scripts if scripts.is_dir() else None

    def _sqlmap_binary(self) -> Path | None:
        found = which("sqlmap")
        if found:
            return Path(found)
        scripts = self._venv_scripts_dir()
        if not scripts:
            return None
        for name in ("sqlmap.exe", "sqlmap"):
            candidate = scripts / name
            if candidate.is_file():
                return candidate
        return None

    def _stdio_env(self) -> dict[str, str] | None:
        scripts = self._venv_scripts_dir()
        if not scripts:
            return None
        path = os.environ.get("PATH", "")
        scripts_str = str(scripts)
        if scripts_str.lower() in path.lower():
            return None
        return {**os.environ, "PATH": f"{scripts_str};{path}"}

    def is_available(self) -> bool:
        if not mcp_sdk_available():
            return False
        if not self.server_path or not Path(self.server_path).is_file():
            return False
        return self._sqlmap_binary() is not None

    @staticmethod
    def _targets_sqli(class_codes: list[str]) -> bool:
        return any(
            "SQL" in code.upper() or "INJECTION" in code.upper() for code in class_codes
        )

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
        outcome = ValidationOutcome(
            connector=self.name,
            target_url=target_url,
            asset_id=asset_id,
            class_codes=class_codes,
            tags=list(tags),
            status="NO_EVIDENCE",
            redacted_command=(
                f"{self.command} {' '.join(self._stdio_args())} "
                f"-> sqlmap_scan_url (level=1 risk=1)"
            ),
        )
        if not self._targets_sqli(class_codes):
            outcome.detail = "Skipped: no SQL/INJECTION class applicability on this asset."
            return outcome
        if not mcp_sdk_available():
            outcome.status = "UNAVAILABLE"
            outcome.detail = 'Install MCP SDK: pip install -e ".[mcp]"'
            return outcome
        if not Path(self.server_path).is_file():
            outcome.status = "UNAVAILABLE"
            outcome.detail = f"SQLMap MCP server not found: {self.server_path}"
            return outcome
        if not self._sqlmap_binary():
            outcome.status = "UNAVAILABLE"
            outcome.detail = (
                "sqlmap binary not found (install via uv pip install sqlmap in SQLMap-MCP)."
            )
            return outcome

        text, err = await call_stdio_tool(
            self.command,
            self._stdio_args(),
            "sqlmap_scan_url",
            {
                "url": target_url,
                "level": 1,
                "risk": 1,
                "technique": "BEUSTQ",
            },
            read_timeout_seconds=600.0,
            env=self._stdio_env(),
        )
        if err:
            outcome.status = "ERROR"
            outcome.detail = err
            return outcome

        if self._looks_positive(text):
            outcome.findings = [
                ValidationFinding(
                    template_id="sqlmap-scan",
                    name="SQL injection signal (sqlmap MCP)",
                    severity="high",
                    matched_at=target_url,
                    tags=["sqlmap", "sqli"],
                )
            ]
            outcome.status = "CORROBORATED"
            outcome.detail = (
                "sqlmap MCP reported injectable parameter(s); analyst confirmation required."
            )
        else:
            outcome.detail = "sqlmap MCP completed with no injectable parameters detected."
        return outcome

    @staticmethod
    def _looks_positive(text: str) -> bool:
        lowered = text.lower()
        if any(re.search(pattern, lowered) for pattern in _NEGATIVE_PATTERNS):
            return False
        return any(re.search(pattern, lowered) for pattern in _POSITIVE_PATTERNS)
