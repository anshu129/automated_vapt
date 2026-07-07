"""Application services."""

import re
import uuid
from datetime import UTC, datetime
from ipaddress import ip_address
from typing import Any
from urllib.parse import unquote, urlparse, urlunparse

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from vapt_platform.config.settings import get_settings
from vapt_platform.controller.recon_controller import ReconController
from vapt_platform.db.tables.models import (
    CapabilityProvider,
    Event,
    Project,
    RawArtifact,
    Scan,
    ScopeRule,
    ScopeSnapshot,
    Task,
    TestPlan,
    ValidationResult,
    ValidationTask,
)
from vapt_platform.domain.enums import (
    Capability,
    ScanStatus,
    ScopeRuleType,
    TaskStatus,
    TestPlanStatus,
    ValidationOutcome,
    ValidationTaskStatus,
)
from vapt_platform.domain.exceptions import EntityNotFoundError
from vapt_platform.engines.assessment import VerdictEngine
from vapt_platform.scope.manager import ScopeManager, ScopeRuleData
from vapt_platform.tools.manifest import ToolManifestSpec, load_tool_manifests, resolve_tool_binary


class ProjectService:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def create(self, name: str, description: str | None = None) -> Project:
        project = Project(name=name, description=description)
        self.session.add(project)
        await self.session.flush()
        return project

    async def get(self, project_id: uuid.UUID) -> Project:
        project = await self.session.get(Project, project_id)
        if not project:
            raise EntityNotFoundError(f"Project {project_id} not found")
        return project


class ScanService:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def create(
        self,
        project_id: uuid.UUID,
        name: str,
        scope_rules: list[dict[str, Any]] | None = None,
    ) -> Scan:
        project = await self.session.get(Project, project_id)
        if not project:
            raise EntityNotFoundError("Project not found")

        snapshot_rules: list[dict[str, Any]] = []
        if scope_rules:
            for sr in scope_rules:
                snapshot_rules.append(
                    {
                        "rule_type": sr["rule_type"],
                        "pattern": sr["pattern"],
                        "assessment_mode": sr.get("assessment_mode", "ACTIVE"),
                        "priority": sr.get("priority", 10),
                    }
                )
                self.session.add(
                    ScopeRule(
                        project_id=project_id,
                        rule_type=sr["rule_type"],
                        pattern=sr["pattern"],
                        assessment_mode=sr.get("assessment_mode", "ACTIVE"),
                        priority=sr.get("priority", 10),
                    )
                )
        else:
            rules_stmt = select(ScopeRule).where(
                ScopeRule.project_id == project_id, ScopeRule.enabled.is_(True)
            )
            db_rules = list((await self.session.execute(rules_stmt)).scalars().all())
            snapshot_rules = [
                {
                    "rule_type": r.rule_type,
                    "pattern": r.pattern,
                    "assessment_mode": r.assessment_mode,
                    "priority": r.priority,
                }
                for r in db_rules
            ]
        snapshot = ScopeSnapshot(
            project_id=project_id,
            rules=snapshot_rules,
        )
        self.session.add(snapshot)
        await self.session.flush()

        scan = Scan(
            project_id=project_id,
            name=name,
            scope_snapshot_id=snapshot.id,
            status=ScanStatus.CREATED.value,
        )
        self.session.add(scan)
        await self.session.flush()
        return scan

    async def get(self, scan_id: uuid.UUID) -> Scan:
        scan = await self.session.get(Scan, scan_id)
        if not scan:
            raise EntityNotFoundError(f"Scan {scan_id} not found")
        return scan

    async def start(self, scan_id: uuid.UUID) -> Scan:
        scan = await self.get(scan_id)
        scan.status = ScanStatus.RUNNING.value
        scan.started_at = datetime.now(UTC)
        correlation_id = uuid.uuid4()

        snapshot = await self.session.get(ScopeSnapshot, scan.scope_snapshot_id)
        rules = [ScopeRuleData(**r) for r in (snapshot.rules if snapshot else [])]
        controller = ReconController(self.session, ScopeManager(rules))

        for rule in rules:
            if rule.rule_type == ScopeRuleType.ROOT_DOMAIN.value:
                await controller.emit_event(
                    scan_id,
                    "DOMAIN_ACCEPTED",
                    {"domain": rule.pattern, "scope_rule_id": rule.pattern},
                    correlation_id,
                )
            elif rule.rule_type == ScopeRuleType.HOSTNAME.value:
                await controller.emit_event(
                    scan_id,
                    "HOSTNAME_DISCOVERED",
                    {"hostname": rule.pattern, "source": "scope"},
                    correlation_id,
                )
            elif rule.rule_type == ScopeRuleType.URL_PREFIX.value:
                url = _normalize_url(rule.pattern)
                await controller.emit_event(
                    scan_id,
                    "HTTP_SERVICE_CONFIRMED",
                    {"url": url, "status_code": 0, "source": "scope"},
                    correlation_id,
                )
                await controller.emit_event(
                    scan_id,
                    "WEB_APPLICATION_CONFIRMED",
                    {"base_url": _base_url(url), "title": url, "source": "scope"},
                    correlation_id,
                )
            elif rule.rule_type == ScopeRuleType.IP.value:
                await controller.create_task(
                    scan_id,
                    Capability.PORT_DISCOVERY,
                    {"ip": rule.pattern},
                    correlation_id,
                )
            elif rule.rule_type == ScopeRuleType.CIDR.value:
                await controller.create_task(
                    scan_id,
                    Capability.CIDR_EXPANSION,
                    {"cidr": rule.pattern},
                    correlation_id,
                )

        if get_settings().scan_start_inline_execution:
            await controller.run_scan_pipeline(scan_id, correlation_id)
        return scan

    async def run_ready_tasks(
        self,
        scan_id: uuid.UUID,
        limit: int = 1,
        target_filter: str | None = None,
        provider_filter: str | None = None,
        username: str | None = None,
        password: str | None = None,
        timeout_seconds: int | None = None,
        verbose: bool = False,
    ) -> dict[str, Any]:
        scan = await self.get(scan_id)
        snapshot = await self.session.get(ScopeSnapshot, scan.scope_snapshot_id)
        rules = [ScopeRuleData(**r) for r in (snapshot.rules if snapshot else [])]
        controller = ReconController(self.session, ScopeManager(rules))
        if timeout_seconds is not None:
            controller.cli_executor.timeout_seconds = timeout_seconds
        task_stmt = (
            select(Task)
            .where(Task.scan_id == scan_id, Task.status == TaskStatus.READY.value)
            .order_by(Task.created_at)
        )
        tasks = list((await self.session.execute(task_stmt)).scalars().all())
        if target_filter:
            needle = target_filter.lower()
            tasks = [task for task in tasks if _task_matches_filter(task, needle)]
        if provider_filter:
            wanted = {item.strip().lower() for item in provider_filter.split(",") if item.strip()}
            filtered_tasks = []
            for task in tasks:
                provider = (
                    await self.session.get(CapabilityProvider, task.capability_provider_id)
                    if task.capability_provider_id
                    else None
                )
                if provider and provider.provider_name.lower() in wanted:
                    filtered_tasks.append(task)
            tasks = filtered_tasks
        if limit > 0:
            tasks = tasks[:limit]

        executed_items: list[dict[str, Any]] = []
        correlation_id = uuid.uuid4()
        for task in tasks:
            if username is not None or password is not None:
                task.target_descriptor = _with_credentials(
                    task.target_descriptor or {},
                    username=username,
                    password=password,
                )
            provider = (
                await self.session.get(CapabilityProvider, task.capability_provider_id)
                if task.capability_provider_id
                else None
            )
            run = await controller.execute_task(task.id, correlation_id)
            executed_items.append(await self._task_run_summary(task, run, provider, verbose))
        await controller.completion_evaluator.evaluate(scan_id)

        ready_stmt = select(Task).where(
            Task.scan_id == scan_id,
            Task.status == TaskStatus.READY.value,
        )
        remaining_ready = len(list((await self.session.execute(ready_stmt)).scalars().all()))
        return {
            "id": str(scan.id),
            "status": scan.status,
            "executed": len(executed_items),
            "remaining_ready": remaining_ready,
            "items": executed_items,
        }

    async def run_tools(
        self,
        scan_id: uuid.UUID,
        tool_names: list[str],
        target: str,
        username: str | None = None,
        password: str | None = None,
        timeout_seconds: int | None = None,
        verbose: bool = False,
    ) -> dict[str, Any]:
        scan = await self.get(scan_id)
        if scan.status == ScanStatus.CREATED.value:
            scan.status = ScanStatus.RUNNING.value
            scan.started_at = datetime.now(UTC)

        snapshot = await self.session.get(ScopeSnapshot, scan.scope_snapshot_id)
        rules = [ScopeRuleData(**r) for r in (snapshot.rules if snapshot else [])]
        controller = ReconController(self.session, ScopeManager(rules))
        if timeout_seconds is not None:
            controller.cli_executor.timeout_seconds = timeout_seconds

        target_descriptor = build_target_descriptor(
            target,
            username=username,
            password=password,
        )
        manifests = load_tool_manifests()
        selected_names = _select_tool_names(tool_names, manifests, target_descriptor)
        correlation_id = uuid.uuid4()
        items: list[dict[str, Any]] = []
        await _seed_direct_target_events(controller, scan_id, target_descriptor, correlation_id)

        for name in selected_names:
            spec = manifests[name]
            capability = _capability_for_target(spec, target_descriptor)
            if not capability:
                items.append(
                    {
                        "provider": name,
                        "status": "SKIPPED",
                        "reason": "No compatible capability for this target.",
                    }
                )
                continue
            provider = (
                await self.session.execute(
                    select(CapabilityProvider).where(
                        CapabilityProvider.provider_name == name,
                        CapabilityProvider.capability_code == capability.value,
                        CapabilityProvider.enabled.is_(True),
                    )
                )
            ).scalars().first()
            if not provider:
                items.append(
                    {
                        "provider": name,
                        "capability": capability.value,
                        "status": "SKIPPED",
                        "reason": "Provider is not seeded/enabled. Run vapt_platform.scripts.seed.",
                    }
                )
                continue
            task = await controller.create_task(
                scan_id,
                capability,
                dict(target_descriptor),
                correlation_id,
                provider_id=provider.id,
                configuration_salt=f"direct-{name}-{uuid.uuid4().hex}",
            )
            if not task:
                items.append(
                    {
                        "provider": name,
                        "capability": capability.value,
                        "status": "SKIPPED",
                        "reason": "Target is not allowed by this scan scope.",
                    }
                )
                continue
            run = await controller.execute_task(task.id, correlation_id)
            items.append(await self._task_run_summary(task, run, provider, verbose))

        await controller.completion_evaluator.evaluate(scan_id)
        return {
            "id": str(scan.id),
            "status": scan.status,
            "target": _redacted_target_for_response(target_descriptor),
            "requested_tools": tool_names,
            "selected_tools": selected_names,
            "executed": sum(1 for item in items if item.get("task_id")),
            "items": items,
        }

    async def _task_run_summary(
        self,
        task: Task,
        run: Any,
        provider: CapabilityProvider | None,
        verbose: bool,
    ) -> dict[str, Any]:
        artifact_stmt = select(RawArtifact).where(RawArtifact.task_run_id == run.id)
        artifact = (await self.session.execute(artifact_stmt)).scalars().first()
        metadata = artifact.metadata_ if artifact else {}
        stdout = artifact.content if artifact else ""
        item = {
            "task_id": str(task.id),
            "capability": task.capability,
            "status": task.status,
            "target": task.normalized_target,
            "provider": provider.provider_name if provider else None,
            "exit_code": run.exit_code,
            "error_summary": run.error_summary,
            "used_fake_fallback": (metadata or {}).get("fallback") == "fake",
            "command": (metadata or {}).get("command"),
            "binary": (metadata or {}).get("binary"),
            "duration_seconds": (metadata or {}).get("duration_seconds"),
            "timeout_seconds": (metadata or {}).get("timeout_seconds"),
            "stderr_preview": (metadata or {}).get("stderr_preview"),
            "stdout_preview": (stdout or "")[:1000],
        }
        if verbose:
            item["stderr"] = (metadata or {}).get("stderr")
            item["stdout"] = stdout
        return item

    async def pause(self, scan_id: uuid.UUID) -> Scan:
        scan = await self.get(scan_id)
        scan.status = ScanStatus.PAUSED.value
        return scan

    async def resume(self, scan_id: uuid.UUID) -> Scan:
        scan = await self.get(scan_id)
        scan.status = ScanStatus.RUNNING.value
        return scan

    async def cancel(self, scan_id: uuid.UUID) -> Scan:
        scan = await self.get(scan_id)
        scan.status = ScanStatus.CANCELLED.value
        return scan


class ValidationService:
    def __init__(self, session: AsyncSession) -> None:
        self.session = session
        self.verdict_engine = VerdictEngine(session)

    async def record_result(
        self,
        task_id: uuid.UUID,
        outcome: str,
        analyst_notes: str,
        evidence_ids: list[str],
        recorded_by: str = "analyst",
    ) -> ValidationResult:
        task = await self.session.get(ValidationTask, task_id)
        if not task:
            raise EntityNotFoundError("Validation task not found")
        try:
            normalized_outcome = ValidationOutcome(outcome.upper()).value
        except ValueError as exc:
            raise ValueError(f"Unsupported validation outcome: {outcome}") from exc
        if normalized_outcome == ValidationOutcome.CONFIRMED.value and not evidence_ids:
            raise ValueError("Confirmed validation result requires evidence")
        result = ValidationResult(
            validation_task_id=task_id,
            outcome=normalized_outcome,
            analyst_notes=analyst_notes,
            evidence_ids=list(dict.fromkeys(evidence_ids)),
            recorded_by=recorded_by,
        )
        self.session.add(result)
        await self.session.flush()
        task.status = {
            ValidationOutcome.CONFIRMED.value: ValidationTaskStatus.VALIDATED.value,
            ValidationOutcome.REJECTED.value: ValidationTaskStatus.REJECTED.value,
            ValidationOutcome.INCONCLUSIVE.value: ValidationTaskStatus.INCONCLUSIVE.value,
        }[normalized_outcome]
        if task.test_plan_id:
            plan = await self.session.get(TestPlan, task.test_plan_id)
            if plan:
                plan.status = TestPlanStatus.COMPLETED.value
        self.session.add(
            Event(
                scan_id=task.scan_id,
                event_type="VALIDATION_RESULT_RECORDED",
                payload={
                    "validation_task_id": str(task.id),
                    "validation_result_id": str(result.id),
                    "hypothesis_id": (
                        str(task.hypothesis_id) if task.hypothesis_id else None
                    ),
                    "outcome": normalized_outcome,
                },
                correlation_id=uuid.uuid4(),
                sequence_number=await self._next_event_sequence(task.scan_id),
                processed_at=datetime.now(UTC),
            )
        )
        await self.session.flush()
        if task.hypothesis_id:
            await self.verdict_engine.evaluate_hypothesis(
                task.hypothesis_id,
                normalized_outcome,
                result.evidence_ids,
                validation_result_id=result.id,
                test_plan_id=task.test_plan_id,
                recorded_by=recorded_by,
            )
        return result

    async def _next_event_sequence(self, scan_id: uuid.UUID) -> int:
        stmt = select(func.max(Event.sequence_number)).where(Event.scan_id == scan_id)
        current = (await self.session.execute(stmt)).scalar() or 0
        return int(current) + 1


def infer_scope_rule(target: str) -> dict[str, Any]:
    value = target.strip()
    if value.startswith(("http://", "https://")):
        return {"rule_type": ScopeRuleType.URL_PREFIX.value, "pattern": _normalize_url(value)}
    try:
        ip_address(value)
        return {"rule_type": ScopeRuleType.IP.value, "pattern": value}
    except ValueError:
        pass
    if "/" in value:
        return {"rule_type": ScopeRuleType.URL_PREFIX.value, "pattern": _normalize_url(value)}
    parts = value.split(".")
    if len(parts) > 2:
        return {"rule_type": ScopeRuleType.HOSTNAME.value, "pattern": value.lower()}
    return {"rule_type": ScopeRuleType.ROOT_DOMAIN.value, "pattern": value.lower()}


def _normalize_url(value: str) -> str:
    if not value.startswith(("http://", "https://")):
        value = f"https://{value}"
    return value.rstrip("/")


def _base_url(value: str) -> str:
    parsed = urlparse(_normalize_url(value))
    return f"{parsed.scheme}://{parsed.netloc}".rstrip("/")


def _task_matches_filter(task: Task, needle: str) -> bool:
    haystacks = [task.normalized_target or ""]
    for value in (task.target_descriptor or {}).values():
        if isinstance(value, (str, int, float)):
            haystacks.append(str(value))
    return any(needle in value.lower() for value in haystacks)


async def _seed_direct_target_events(
    controller: ReconController,
    scan_id: uuid.UUID,
    target: dict[str, Any],
    correlation_id: uuid.UUID,
) -> None:
    if target.get("url"):
        url = _normalize_url(target["url"])
        await controller.emit_event(
            scan_id,
            "HTTP_SERVICE_CONFIRMED",
            {"url": url, "status_code": 0, "source": "direct-tool-run"},
            correlation_id,
        )
        await controller.emit_event(
            scan_id,
            "WEB_APPLICATION_CONFIRMED",
            {"base_url": _base_url(url), "title": url, "source": "direct-tool-run"},
            correlation_id,
        )
        return

    if target.get("hostname"):
        await controller.emit_event(
            scan_id,
            "HOSTNAME_DISCOVERED",
            {"hostname": target["hostname"], "source": "direct-tool-run"},
            correlation_id,
        )
        return

    if target.get("ip"):
        await controller.emit_event(
            scan_id,
            "SERVICE_OBSERVED",
            {"host": target["ip"], "ip": target["ip"], "port": target.get("port") or 0},
            correlation_id,
        )


def build_target_descriptor(
    value: str,
    username: str | None = None,
    password: str | None = None,
) -> dict[str, Any]:
    target = value.strip()
    if target.startswith(("http://", "https://")) or "/" in target:
        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"
        parsed = urlparse(target)
        host = parsed.hostname or ""
        port = parsed.port
        if parsed.username and username is None:
            username = unquote(parsed.username)
        if parsed.password and password is None:
            password = unquote(parsed.password)
        netloc = host
        if port:
            netloc = f"{netloc}:{port}"
        clean_url = urlunparse(
            (
                parsed.scheme or "https",
                netloc,
                parsed.path or "",
                "",
                parsed.query or "",
                "",
            )
        ).rstrip("/")
        descriptor: dict[str, Any] = {
            "url": clean_url,
            "hostname": host,
            "target": host,
        }
        if port:
            descriptor["port"] = port
        if _looks_like_ip(host):
            descriptor["ip"] = host
        elif host:
            descriptor["domain"] = host
        return _with_credentials(descriptor, username=username, password=password)

    try:
        ip_address(target)
        return _with_credentials(
            {"ip": target, "target": target},
            username=username,
            password=password,
        )
    except ValueError:
        pass

    host = target.split(":")[0] if ":" in target else target
    descriptor = {
        "hostname": host,
        "domain": host,
        "url": f"https://{target}",
        "target": target,
    }
    return _with_credentials(descriptor, username=username, password=password)


def _with_credentials(
    target: dict[str, Any],
    username: str | None = None,
    password: str | None = None,
) -> dict[str, Any]:
    descriptor = dict(target)
    if username is None or password is None:
        parsed = urlparse(str(descriptor.get("url") or ""))
        if parsed.username and username is None:
            username = unquote(parsed.username)
        if parsed.password and password is None:
            password = unquote(parsed.password)
    if username is not None:
        descriptor["username"] = username
    if password is not None:
        descriptor["password"] = password
    if username is not None or password is not None:
        op = dict(descriptor.get("operational_context") or {})
        op["auth_required"] = True
        descriptor["operational_context"] = op
    return descriptor


def _select_tool_names(
    requested: list[str],
    manifests: dict[str, ToolManifestSpec],
    target: dict[str, Any],
) -> list[str]:
    normalized = [item.strip().lower() for item in requested if item.strip()]
    if not normalized:
        return []
    if normalized == ["all"] or "all" in normalized:
        names = [
            name
            for name, spec in sorted(manifests.items())
            if spec.enabled
            and resolve_tool_binary(spec.binary)
            and not spec.requires_api_key
            and not spec.wrapper
            and _tool_target_compatible(spec, target)
        ]
        return names
    missing = [name for name in normalized if name not in manifests]
    if missing:
        raise EntityNotFoundError(f"Unknown tool(s): {', '.join(missing)}")
    return normalized


def _tool_target_compatible(spec: ToolManifestSpec, target: dict[str, Any]) -> bool:
    blocked_without_explicit_value = {"cidr", "keyword", "path", "targets_file", "hosts_file"}
    values = {
        "domain": target.get("domain"),
        "hostname": target.get("hostname"),
        "url": target.get("url"),
        "target": target.get("target") or target.get("ip") or target.get("hostname") or target.get("domain"),
        "ip": target.get("ip"),
        "wordlist": target.get("wordlist", "config/wordlists/common.txt"),
        "resolvers": target.get("resolvers", "config/resolvers.txt"),
        "output": target.get("output", "-"),
        "payload": target.get("payload", "FUZZ"),
        "pattern": target.get("pattern", "xss"),
        "username": target.get("username"),
        "password": target.get("password"),
        "basic_auth_token": target.get("username") and target.get("password"),
        "token": target.get("token"),
    }
    placeholders = {
        match.group(1)
        for arg in spec.base_args
        for match in re.finditer(r"{([^}]+)}", arg)
    }
    for placeholder in placeholders:
        if placeholder in blocked_without_explicit_value and not target.get(placeholder):
            return False
        if not values.get(placeholder) and not target.get(placeholder):
            return False
    return True


def _capability_for_target(
    spec: ToolManifestSpec,
    target: dict[str, Any],
) -> Capability | None:
    if not spec.capabilities:
        return None
    if target.get("ip"):
        for cap in ("PORT_DISCOVERY", "SERVICE_IDENTIFICATION", "PROTOCOL_CONFIRMATION"):
            if cap in spec.capabilities:
                return Capability(cap)
    if target.get("url"):
        for cap in (
            "HTTP_PROBING",
            "LIVE_CRAWLING",
            "ENDPOINT_EXTRACTION",
            "CONTENT_DISCOVERY",
            "PARAMETER_DISCOVERY",
            "JAVASCRIPT_COLLECTION",
            "TEMPLATE_BASED_ASSESSMENT",
            "WAF_IDENTIFICATION",
            "TECHNOLOGY_IDENTIFICATION",
            "WEB_FINGERPRINTING",
        ):
            if cap in spec.capabilities:
                return Capability(cap)
    if target.get("hostname") or target.get("domain"):
        for cap in (
            "PASSIVE_SUBDOMAIN_DISCOVERY",
            "DNS_RESOLUTION",
            "HTTP_PROBING",
            "PORT_DISCOVERY",
        ):
            if cap in spec.capabilities:
                return Capability(cap)
    return Capability(spec.capabilities[0])


def _redacted_target_for_response(target: dict[str, Any]) -> dict[str, Any]:
    response = dict(target)
    if response.get("password"):
        response["password"] = "***"
    if response.get("url"):
        response["url"] = re.sub(
            r"://([^:/@\s]+):([^/@\s]+)@",
            r"://***:***@",
            str(response["url"]),
        )
    return response


def _looks_like_ip(value: str | None) -> bool:
    if not value:
        return False
    try:
        ip_address(value)
    except ValueError:
        return False
    return True
