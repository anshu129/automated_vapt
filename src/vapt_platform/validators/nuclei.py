"""Nuclei-backed validation connector.

Runs nuclei with class-targeted templates (low-impact only) against a single
authorized target and turns its JSONL output into corroborating evidence.
"""

from __future__ import annotations

import asyncio
import dataclasses
import json
from typing import Any

from vapt_platform.adapters.cli_executor import CliToolExecutor
from vapt_platform.config.settings import get_settings
from vapt_platform.tools.manifest import (
    ToolManifestSpec,
    load_tool_manifests,
    resolve_tool_binary,
)
from vapt_platform.validators.base import ValidationFinding, ValidationOutcome, with_auth_url


class NucleiValidator:
    name = "nuclei"
    safety_class = "LOW_IMPACT"
    active = False  # template matching is non-destructive

    def __init__(self, executor: CliToolExecutor | None = None) -> None:
        settings = get_settings()
        self._executor = executor or CliToolExecutor(
            timeout_seconds=max(settings.tool_timeout_seconds, 120),
            use_fake_fallback=False,
        )

    def is_available(self) -> bool:
        return resolve_tool_binary("nuclei") is not None

    def _spec(self, tags: list[str]) -> ToolManifestSpec:
        base = load_tool_manifests().get("nuclei")
        tag_arg = ",".join(dict.fromkeys(tags)) or "misconfig,exposure"
        args = [
            "-u",
            "{url}",
            "-jsonl",
            "-silent",
            "-tags",
            tag_arg,
            "-exclude-tags",
            "dos,fuzz,intrusive",
            "-severity",
            "low,medium,high,critical",
            "-no-interactsh",
            "-rate-limit",
            "10",
            "-concurrency",
            "5",
            "-timeout",
            "10",
            "-retries",
            "1",
            "-disable-update-check",
        ]
        if base:
            return dataclasses.replace(base, base_args=args)
        return ToolManifestSpec(
            name="nuclei",
            binary="nuclei",
            capabilities=["TEMPLATE_BASED_ASSESSMENT"],
            capability_group="VULNERABILITY_ASSESSMENT",
            safety_class="LOW_IMPACT",
            cost_tier="FREE",
            output_format="jsonl",
            base_args=args,
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
            tags=list(dict.fromkeys(tags)),
            status="NO_EVIDENCE",
        )
        if not self.is_available():
            outcome.status = "UNAVAILABLE"
            outcome.detail = "nuclei binary was not found on the configured tool paths."
            return outcome

        spec = self._spec(outcome.tags)
        target = {
            "url": target_url,
            "hostname": _hostname(target_url),
            "username": username,
            "password": password,
        }
        try:
            result = await asyncio.to_thread(
                self._executor.execute,
                spec,
                "nuclei",
                target,
                "STANDARD",
                capability="TEMPLATE_BASED_ASSESSMENT",
            )
        except Exception as exc:  # defensive: never crash the scan pipeline
            outcome.status = "ERROR"
            outcome.detail = f"nuclei execution failed: {exc}"[:400]
            return outcome

        if result.parameter_decision:
            outcome.redacted_command = result.parameter_decision.redacted_command
        exit_code = result.output.exit_code
        if exit_code not in (0, None):
            outcome.status = "ERROR"
            meta = result.command_metadata or {}
            detail = meta.get("error") or meta.get("stderr_preview") or f"exit {exit_code}"
            outcome.detail = str(detail)[:400]
            return outcome

        findings = self._parse(result.output.stdout or "")
        outcome.findings = findings
        outcome.status = "CORROBORATED" if findings else "NO_EVIDENCE"
        if not findings:
            outcome.detail = "nuclei completed with no template matches for the selected tags."
        return outcome

    @staticmethod
    def _parse(stdout: str) -> list[ValidationFinding]:
        findings: list[ValidationFinding] = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(record, dict):
                continue
            raw_info = record.get("info")
            info: dict[str, Any] = raw_info if isinstance(raw_info, dict) else {}
            findings.append(
                ValidationFinding(
                    template_id=record.get("template-id")
                    or record.get("template_id")
                    or record.get("template"),
                    name=info.get("name") or record.get("name"),
                    severity=info.get("severity") or record.get("severity"),
                    matched_at=record.get("matched-at")
                    or record.get("matched_at")
                    or record.get("host"),
                    tags=list(info.get("tags") or []),
                )
            )
        return findings


def _hostname(url: str) -> str | None:
    from urllib.parse import urlparse

    return urlparse(url).hostname
