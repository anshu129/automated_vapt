"""CLI tool execution with safety bounds."""

import hashlib
import subprocess
import time
from dataclasses import dataclass, field
from typing import Any

from vapt_platform.adapters.fake.providers import AdapterOutput, FakeAdapter, get_fake_adapter
from vapt_platform.parameters.context import OperationalContext
from vapt_platform.parameters.engine import ParameterDecision, ParameterSelectionEngine
from vapt_platform.parsers.registry import parse_tool_output
from vapt_platform.tools.manifest import ToolManifestSpec, resolve_tool_binary


@dataclass
class ExecutionResult:
    output: AdapterOutput
    parameter_decision: ParameterDecision | None = None
    used_fake: bool = False
    binary_missing: bool = False
    command_metadata: dict[str, Any] = field(default_factory=dict)


class CliToolExecutor:
    """Executes approved tools via subprocess or fake adapter fallback."""

    def __init__(
        self,
        param_engine: ParameterSelectionEngine | None = None,
        timeout_seconds: int = 300,
        max_output_bytes: int = 5_000_000,
        use_fake_fallback: bool = True,
    ) -> None:
        self.param_engine = param_engine or ParameterSelectionEngine()
        self.timeout_seconds = timeout_seconds
        self.max_output_bytes = max_output_bytes
        self.use_fake_fallback = use_fake_fallback

    def execute(
        self,
        manifest: ToolManifestSpec,
        provider_name: str,
        target: dict[str, Any],
        profile: str = "STANDARD",
        capability: str | None = None,
        fake_behavior: str | None = None,
    ) -> ExecutionResult:
        ctx = OperationalContext.from_target(target, profile, capability)
        decision = self.param_engine.derive(
            provider_name,
            list(manifest.base_args),
            target,
            ctx,
        )

        binary = manifest.binary
        binary_source = resolve_tool_binary(binary)
        if (manifest.wrapper and manifest.wrapper not in {"crtsh"}) or not binary_source:
            if self.use_fake_fallback:
                fake = self._fake_for_provider(provider_name, fake_behavior, manifest)
                if fake:
                    out = fake.execute(target, profile)
                    out.observations = out.observations or []
                    parsed = parse_tool_output(provider_name, out.stdout, target)
                    out.events = out.events or parsed.get("events", [])
                    out.observations.extend(parsed.get("observations", []))
                    return ExecutionResult(
                        output=out,
                        parameter_decision=decision,
                        used_fake=True,
                        binary_missing=binary_source is None,
                        command_metadata={"fallback": "fake", "provider": provider_name},
                    )
            return ExecutionResult(
                output=AdapterOutput(
                    stdout="",
                    exit_code=127,
                    observations=[],
                    events=[],
                ),
                parameter_decision=decision,
                binary_missing=True,
                command_metadata={"error": f"binary not found: {binary}"},
            )

        cmd = [binary_source, *decision.final_args]
        timeout = None if self.timeout_seconds <= 0 else self.timeout_seconds
        started = time.perf_counter()
        stdin_input = None
        if manifest.stdin:
            stdin_input = target.get("stdin") or (
                target.get("hostname") or target.get("domain") or target.get("ip")
            )
        try:
            proc = subprocess.run(
                cmd,
                input=stdin_input,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
            duration = round(time.perf_counter() - started, 3)
            stdout = (proc.stdout or "")[: self.max_output_bytes]
            stderr = (proc.stderr or "")[: self.max_output_bytes]
            parsed = parse_tool_output(provider_name, stdout, target)
            return ExecutionResult(
                output=AdapterOutput(
                    stdout=stdout,
                    exit_code=proc.returncode,
                    observations=parsed.get("observations", []),
                    events=parsed.get("events", []),
                ),
                parameter_decision=decision,
                used_fake=False,
                command_metadata={
                    "command": decision.redacted_command,
                    "binary": binary_source,
                    "exit_code": proc.returncode,
                    "duration_seconds": duration,
                    "timeout_seconds": timeout,
                    "stderr": stderr if stderr else None,
                    "stderr_preview": stderr[:500] if stderr else None,
                    "content_hash": hashlib.sha256(stdout.encode()).hexdigest(),
                },
            )
        except subprocess.TimeoutExpired:
            duration = round(time.perf_counter() - started, 3)
            return ExecutionResult(
                output=AdapterOutput(stdout="", exit_code=124, observations=[], events=[]),
                parameter_decision=decision,
                command_metadata={
                    "error": "timeout",
                    "command": decision.redacted_command,
                    "binary": binary_source,
                    "duration_seconds": duration,
                    "timeout_seconds": timeout,
                },
            )
        except OSError as e:
            duration = round(time.perf_counter() - started, 3)
            return ExecutionResult(
                output=AdapterOutput(stdout="", exit_code=1, observations=[], events=[]),
                parameter_decision=decision,
                command_metadata={
                    "error": str(e),
                    "command": decision.redacted_command,
                    "binary": binary_source,
                    "duration_seconds": duration,
                    "timeout_seconds": timeout,
                },
            )

    def _fake_for_provider(
        self,
        provider_name: str,
        fake_behavior: str | None,
        manifest: ToolManifestSpec,
    ) -> FakeAdapter | None:
        fake = get_fake_adapter(f"fake-{provider_name}")
        if fake:
            return fake
        fake = get_fake_adapter(provider_name)
        if fake:
            return fake
        if provider_name == "dnsx":
            return get_fake_adapter("fake-dnsx-resolve")
        if fake_behavior:
            from vapt_platform.domain.enums import Capability

            cap = (
                Capability(manifest.capabilities[0])
                if manifest.capabilities
                else Capability.DNS_RESOLUTION
            )
            return FakeAdapter(cap, provider_name, fake_behavior)
        return None
