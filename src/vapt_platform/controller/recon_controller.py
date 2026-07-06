"""Event-driven recon controller."""

import asyncio
import hashlib
import uuid
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from vapt_platform.adapters.cli_executor import CliToolExecutor
from vapt_platform.adapters.fake.providers import get_fake_adapter
from vapt_platform.capabilities.registry import (
    CapabilityRegistry,
    CapabilitySelectionEngine,
    SelectionContext,
)
from vapt_platform.config.settings import get_settings
from vapt_platform.db.tables.models import (
    Asset,
    AuditEvent,
    CapabilityProvider,
    Event,
    EvidenceQualityDecision,
    Observation,
    RawArtifact,
    Relationship,
    Scan,
    Task,
    TaskRun,
    TestRequirement,
)
from vapt_platform.domain.enums import (
    ApplicabilityState,
    ApplicabilityTrigger,
    AssetType,
    Capability,
    EventType,
    ExecutionProfile,
    RelationshipType,
    ScanStatus,
    TaskStatus,
    TestRequirementCoverageStatus,
)
from vapt_platform.engines.assessment import (
    AssessmentCompletionEvaluator,
    RecursiveCorrelationEngine,
    SurfaceCompletenessEngine,
    TestMatrixEngine,
    VulnerabilityApplicabilityEngine,
)
from vapt_platform.evidence.quality import (
    INCONCLUSIVE_STATUSES,
    EvidenceQualityEvaluator,
    TargetContext,
    TaskRunResult,
)
from vapt_platform.planning.adaptive_recon import AdaptiveReconPlanner
from vapt_platform.planning.discovery_gain import MarginalDiscoveryGainEngine
from vapt_platform.scope.manager import (
    ScopeManager,
    TargetDescriptor,
    task_uniqueness_key,
)
from vapt_platform.tools.manifest import load_tool_manifests

# Legacy export — planner is canonical for Phase B
WORKFLOW_TRANSITIONS: dict[str, list[Capability]] = {}


def _looks_like_ip(value: str | None) -> bool:
    if not value:
        return False
    parts = value.split(".")
    if len(parts) != 4:
        return False
    return all(part.isdigit() and 0 <= int(part) <= 255 for part in parts)


class ReconController:
    def __init__(
        self,
        session: AsyncSession,
        scope_manager: ScopeManager,
        no_discovery_assumption: bool = True,
    ) -> None:
        self.session = session
        self.scope = scope_manager
        self.evidence_evaluator = EvidenceQualityEvaluator(no_discovery_assumption)
        self.registry = CapabilityRegistry(session)
        self.selection = CapabilitySelectionEngine()
        self.gain_engine = MarginalDiscoveryGainEngine(session)
        self.surface_engine = SurfaceCompletenessEngine(session)
        self.applicability_engine = VulnerabilityApplicabilityEngine(session)
        self.matrix_engine = TestMatrixEngine(session)
        self.correlation_engine = RecursiveCorrelationEngine(session)
        self.completion_evaluator = AssessmentCompletionEvaluator(session)
        settings = get_settings()
        self.cli_executor = CliToolExecutor(
            timeout_seconds=settings.tool_timeout_seconds,
            use_fake_fallback=True,
        )
        self.max_pipeline_iterations = settings.scan_pipeline_max_iterations
        self.max_pipeline_tasks = settings.scan_pipeline_max_tasks
        self._manifests = load_tool_manifests()
        self.planner = AdaptiveReconPlanner()

    async def _next_sequence(self, scan_id: uuid.UUID) -> int:
        stmt = select(func.max(Event.sequence_number)).where(Event.scan_id == scan_id)
        result = await self.session.execute(stmt)
        current = result.scalar() or 0
        return int(current) + 1

    async def emit_event(
        self,
        scan_id: uuid.UUID,
        event_type: EventType | str,
        payload: dict[str, Any],
        correlation_id: uuid.UUID,
        causation_id: uuid.UUID | None = None,
    ) -> Event:
        event = Event(
            scan_id=scan_id,
            event_type=EventType(event_type).value
            if isinstance(event_type, EventType)
            else event_type,
            payload=payload,
            correlation_id=correlation_id,
            causation_id=causation_id,
            sequence_number=await self._next_sequence(scan_id),
        )
        self.session.add(event)
        await self.session.flush()
        await self.handle_event(event)
        return event

    async def handle_event(self, event: Event) -> None:
        event.processed_at = datetime.now(UTC)
        handler = {
            EventType.DOMAIN_ACCEPTED.value: self._on_domain_accepted,
            EventType.HOSTNAME_DISCOVERED.value: self._on_hostname_discovered,
            EventType.DNS_RESOLVED.value: self._on_dns_resolved,
            EventType.HTTP_SERVICE_CONFIRMED.value: self._on_http_confirmed,
            EventType.WEB_APPLICATION_CONFIRMED.value: self._on_web_app_confirmed,
            EventType.ENDPOINT_DISCOVERED.value: self._on_endpoint_discovered,
            EventType.SERVICE_OBSERVED.value: self._on_service_observed,
            EventType.TASK_COMPLETED.value: self._on_task_completed,
            "JAVASCRIPT_DISCOVERED": self._on_javascript_discovered,
        }.get(event.event_type)
        if handler:
            await handler(event)
        await self._schedule_workflow_tasks(event)

    async def _schedule_workflow_tasks(self, event: Event) -> None:
        plan_items = self.planner.plan_from_event(
            event.event_type,
            event.payload,
            scan_id=event.scan_id,
        )
        for item in plan_items:
            if not await self._should_schedule_capability(event.scan_id, item.capability):
                continue
            await self.create_task(
                event.scan_id,
                item.capability,
                item.target,
                event.correlation_id,
                profile=item.execution_profile,
            )

    async def _should_schedule_capability(
        self, scan_id: uuid.UUID, capability: Capability
    ) -> bool:
        """Skip provider chain when marginal gain exhausted (Phase B)."""
        metrics = await self.gain_engine.get_metrics(scan_id)
        cap_metrics = [m for m in metrics if m.capability_code == capability.value]
        if len(cap_metrics) < 2:
            return True
        low_gain = all((m.historical_unique_gain or 0) < 1 for m in cap_metrics)
        return not low_gain

    async def create_task(
        self,
        scan_id: uuid.UUID,
        capability: Capability,
        target: dict[str, Any],
        correlation_id: uuid.UUID,
        provider_id: uuid.UUID | None = None,
        profile: str = ExecutionProfile.STANDARD.value,
        exclude_provider_id: str | None = None,
        configuration_salt: str | None = None,
    ) -> Task | None:
        scan = await self.session.get(Scan, scan_id)
        if not scan or scan.status not in (ScanStatus.RUNNING.value, ScanStatus.CREATED.value):
            return None

        td = TargetDescriptor(
            hostname=target.get("hostname"),
            domain=target.get("domain"),
            url=target.get("url"),
            ip=target.get("ip"),
        )
        decision = self.scope.evaluate(td, capability)
        if not decision.allowed:
            self.session.add(
                AuditEvent(
                    event_type="SCOPE_DECISION",
                    resource_type="task",
                    details={
                        "decision": "DENY",
                        "reason": decision.reason,
                        "capability": capability.value,
                    },
                    correlation_id=correlation_id,
                )
            )
            return None

        config_key = (
            profile
            if not provider_id and not configuration_salt
            else f"{profile}:{provider_id or ''}:{configuration_salt or ''}"
        )
        config_hash = hashlib.sha256(config_key.encode()).hexdigest()[:16]
        norm = td.normalized_key()
        ukey = task_uniqueness_key(scan_id, capability.value, norm, config_hash)
        existing = await self.session.execute(select(Task).where(Task.uniqueness_key == ukey))
        if existing.scalar_one_or_none():
            return None

        if not provider_id:
            ctx = SelectionContext(scan_id=str(scan_id), execution_profile=profile)
            eligible = await self.registry.get_eligible(capability, ctx)
            selected = self.selection.select(capability, eligible, ctx, exclude_provider_id)
            if not selected:
                return None
            provider = await self.session.get(CapabilityProvider, uuid.UUID(selected.id))
        else:
            provider = await self.session.get(CapabilityProvider, provider_id)

        task = Task(
            scan_id=scan_id,
            capability=capability.value,
            capability_provider_id=provider.id if provider else None,
            execution_profile_id=profile,
            target_descriptor=target,
            normalized_target=norm,
            configuration_hash=config_hash,
            uniqueness_key=ukey,
            status=TaskStatus.READY.value,
            scope_decision_id=decision.audit_id,
        )
        self.session.add(task)
        await self.session.flush()
        return task

    async def execute_task(self, task_id: uuid.UUID, correlation_id: uuid.UUID) -> TaskRun:
        task = await self.session.get(Task, task_id)
        if not task:
            raise ValueError("Task not found")
        task.status = TaskStatus.RUNNING.value
        provider = await self.session.get(CapabilityProvider, task.capability_provider_id)

        run = TaskRun(task_id=task.id, attempt_number=task.retry_count + 1)
        self.session.add(run)
        await self.session.flush()

        if not provider:
            run.exit_code = 1
            run.error_summary = "No provider"
            task.status = TaskStatus.FAILED_TERMINAL.value
            return run

        manifest_spec = self._manifests.get(provider.provider_name)
        exec_result = None
        output = None

        if manifest_spec and not provider.provider_name.startswith("fake-"):
            exec_result = await asyncio.to_thread(
                self.cli_executor.execute,
                manifest_spec,
                provider.provider_name,
                task.target_descriptor,
                task.execution_profile_id or "STANDARD",
                capability=task.capability,
                fake_behavior=provider.fake_behavior,
            )
            output = exec_result.output
            if exec_result.parameter_decision:
                task.parameters = {
                    **(task.parameters or {}),
                    "parameter_decision": {
                        "rule_ids": exec_result.parameter_decision.rule_ids,
                        "explanations": exec_result.parameter_decision.explanations,
                        "redacted_command": exec_result.parameter_decision.redacted_command,
                        "input_facts": exec_result.parameter_decision.input_facts,
                    },
                }
        else:
            adapter = get_fake_adapter(provider.provider_name)
            if not adapter:
                run.exit_code = 1
                run.error_summary = "No adapter"
                task.status = TaskStatus.FAILED_TERMINAL.value
                return run
            output = adapter.execute(task.target_descriptor, task.execution_profile_id or "STANDARD")

        task.target_descriptor = self._merge_operational_observations(
            task.target_descriptor, output.observations
        )

        artifact = RawArtifact(
            task_run_id=run.id,
            artifact_type="STDOUT",
            content_hash=hashlib.sha256((output.stdout or "").encode()).hexdigest(),
            content=output.stdout or "",
            size_bytes=len(output.stdout or ""),
            metadata_=exec_result.command_metadata if exec_result else {},
        )
        self.session.add(artifact)
        run.exit_code = output.exit_code
        if output.exit_code != 0:
            metadata = exec_result.command_metadata if exec_result else {}
            stderr = (metadata or {}).get("stderr_preview")
            stdout = (output.stdout or "").strip()
            run.error_summary = (
                (metadata or {}).get("error")
                or stderr
                or (stdout[:500] if stdout else None)
                or f"Tool exited with code {output.exit_code}"
            )
        run.completed_at = datetime.now(UTC)

        for obs in output.observations:
            self.session.add(
                Observation(
                    scan_id=task.scan_id,
                    observation_type=obs.get("type", "GENERIC"),
                    payload=obs,
                    source_id=str(run.id),
                )
            )

        await self.gain_engine.record(
            task.scan_id,
            task.capability,
            provider.id if provider else None,
            raw_count=len(output.observations) + len(output.events),
            unique_assets=len(output.events),
        )

        child_corr = correlation_id
        for ev in output.events:
            await self.emit_event(task.scan_id, ev["type"], ev, child_corr, causation_id=run.id)

        eq = self.evidence_evaluator.evaluate(
            Capability(task.capability),
            TaskRunResult(output.exit_code, output.observations),
            TargetContext(
                hostname=task.target_descriptor.get("hostname"),
                capability=Capability(task.capability),
                execution_profile=task.execution_profile_id or "STANDARD",
            ),
            previous_attempts=task.retry_count,
            fake_behavior=provider.fake_behavior if provider else None,
        )
        if output.exit_code == 0:
            task.status = TaskStatus.COMPLETED.value
        elif eq.retry_allowed and task.retry_count < task.max_retries:
            task.status = TaskStatus.FAILED_RETRYABLE.value
        else:
            task.status = TaskStatus.FAILED_TERMINAL.value
        decision = EvidenceQualityDecision(
            scan_id=task.scan_id,
            task_run_id=run.id,
            status=eq.status.value,
            confidence=eq.confidence,
            reason_codes=eq.reason_codes,
            explanation=eq.explanation,
            recommended_next_capability=(
                eq.recommended_next_capability.value if eq.recommended_next_capability else None
            ),
            eligible_alternate_profiles=eq.eligible_alternate_profiles,
            retry_allowed=eq.retry_allowed,
            manual_review_required=eq.manual_review_required,
            rule_ids=eq.rule_ids,
        )
        self.session.add(decision)
        task.evidence_quality_decision_id = decision.id

        await self.emit_event(
            task.scan_id,
            EventType.EVIDENCE_QUALITY_EVALUATED,
            {"decision_id": str(decision.id), "status": eq.status.value},
            correlation_id,
            causation_id=run.id,
        )

        if (
            eq.status in INCONCLUSIVE_STATUSES
            and eq.recommended_next_capability
            and eq.retry_allowed
        ):
            alt_profile = (
                eq.eligible_alternate_profiles[0]
                if eq.eligible_alternate_profiles
                else "HIGH_LATENCY"
            )
            await self.create_task(
                task.scan_id,
                eq.recommended_next_capability,
                task.target_descriptor,
                correlation_id,
                profile=alt_profile,
                exclude_provider_id=str(provider.id) if provider else None,
            )
            task.retry_count += 1

        terminal_event = (
            EventType.TASK_COMPLETED
            if task.status == TaskStatus.COMPLETED.value
            else EventType.TASK_FAILED
        )
        await self.emit_event(
            task.scan_id,
            terminal_event,
            {
                "task_id": str(task.id),
                "task_run_id": str(run.id),
                "status": task.status,
                "exit_code": output.exit_code,
            },
            correlation_id,
            causation_id=run.id,
        )
        return run

    @staticmethod
    def _merge_operational_observations(
        target: dict[str, Any],
        observations: list[dict[str, Any]],
    ) -> dict[str, Any]:
        td = dict(target)
        op = dict(td.get("operational_context", {}))
        changed = False
        for obs in observations:
            if obs.get("type") != "OPERATIONAL_OBSERVATION":
                continue
            for key, val in obs.items():
                if key != "type" and op.get(key) != val:
                    op[key] = val
                    changed = True
        if changed:
            td["operational_context"] = op
            return td
        return target

    async def _on_domain_accepted(self, event: Event) -> None:
        domain = event.payload.get("domain", "")
        await self._upsert_asset(
            event.scan_id, AssetType.DOMAIN, domain.lower(), domain, event.correlation_id
        )

    async def _on_hostname_discovered(self, event: Event) -> None:
        hostname = event.payload.get("hostname", "")
        domain_asset = await self._upsert_asset(
            event.scan_id, AssetType.HOSTNAME, hostname.lower(), hostname, event.correlation_id
        )
        domain = ".".join(hostname.split(".")[-2:]) if "." in hostname else hostname
        parent = await self._find_asset(event.scan_id, AssetType.DOMAIN, domain)
        if parent:
            await self._add_relationship(
                event.scan_id, parent.id, domain_asset.id, RelationshipType.HAS_SUBDOMAIN
            )

    async def _on_dns_resolved(self, event: Event) -> None:
        hostname = event.payload.get("hostname", "")
        host_asset = await self._find_asset(event.scan_id, AssetType.HOSTNAME, hostname.lower())
        if not host_asset:
            host_asset = await self._upsert_asset(
                event.scan_id, AssetType.HOSTNAME, hostname.lower(), hostname, event.correlation_id
            )
        for rec in event.payload.get("records", []):
            if rec.get("type") == "A":
                ip = rec["value"]
                ip_asset = await self._upsert_asset(
                    event.scan_id, AssetType.IP_ADDRESS, ip, ip, event.correlation_id
                )
                await self._add_relationship(
                    event.scan_id, host_asset.id, ip_asset.id, RelationshipType.RESOLVES_TO
                )
        meta = host_asset.metadata_ or {}
        meta["dns_resolved"] = True
        meta["dns_status"] = "COMPLETE"
        host_asset.metadata_ = meta
        await self.surface_engine.compute(event.scan_id, host_asset.id)

    async def _on_http_confirmed(self, event: Event) -> None:
        url = event.payload.get("url", "")
        parsed = urlparse(url)
        scheme = parsed.scheme or "http"
        host = parsed.hostname or url.replace("https://", "").replace("http://", "").split("/")[0]
        port = parsed.port or (443 if scheme == "https" else 80)
        await self._upsert_asset(
            event.scan_id,
            AssetType.SERVICE,
            f"{host}:{port}",
            f"{scheme}-{host}:{port}",
            event.correlation_id,
            metadata={"url": url, "scheme": scheme, "hostname": host, "port": port},
        )

    async def _on_web_app_confirmed(self, event: Event) -> None:
        base_url = event.payload.get("base_url", "")
        normalized = base_url.lower().rstrip("/")
        asset = await self._upsert_asset(
            event.scan_id,
            AssetType.WEB_APPLICATION,
            normalized,
            event.payload.get("title", base_url),
            event.correlation_id,
            metadata={
                "http_confirmed": True,
                "technologies": ["nginx"],
                "base_url": normalized,
            },
        )
        surface = await self.surface_engine.compute(event.scan_id, asset.id)
        await self._compute_and_emit_applicability(
            event.scan_id, asset.id, event.correlation_id, ApplicabilityTrigger.SURFACE_UPDATED
        )

        requirements = await self.surface_engine.missing_requirements(asset.id, event.scan_id)
        gap_payload = self.surface_engine.gaps_payload(asset.id, requirements)

        gap_target = {
            "base_url": normalized,
            "url": base_url,
            "hostname": urlparse(base_url).hostname
            or base_url.replace("https://", "").replace("http://", "").split("/")[0],
        }
        if _looks_like_ip(gap_target["hostname"]):
            gap_target["ip"] = gap_target["hostname"]
        gap_items = self.planner.plan_from_surface_gaps(
            surface.dimensions or {},
            gap_target,
            scan_id=event.scan_id,
        )
        for item in gap_items:
            await self.create_task(
                event.scan_id,
                item.capability,
                item.target,
                event.correlation_id,
                profile=item.execution_profile,
            )
        await self.emit_event(
            event.scan_id,
            EventType.SURFACE_COVERAGE_COMPUTED,
            {
                "asset_id": str(asset.id),
                "overall_status": surface.overall_status,
                "gap_count": surface.gap_count,
                "dimensions": surface.dimensions,
            },
            event.correlation_id,
        )
        await self.emit_event(
            event.scan_id,
            EventType.SURFACE_GAP_IDENTIFIED,
            gap_payload,
            event.correlation_id,
        )

    async def _on_endpoint_discovered(self, event: Event) -> None:
        url = event.payload.get("url", "")
        base = "/".join(url.split("/")[:3])
        app = await self._find_asset(event.scan_id, AssetType.WEB_APPLICATION, base.lower())
        ep = await self._upsert_asset(
            event.scan_id,
            AssetType.ENDPOINT,
            url.lower(),
            url,
            event.correlation_id,
            metadata={"method": event.payload.get("method", "GET")},
        )
        if app:
            meta = app.metadata_ or {}
            endpoints = set(meta.get("endpoints", []))
            endpoints.add(url)
            meta["endpoints"] = list(endpoints)
            app.metadata_ = meta
            await self._add_relationship(event.scan_id, app.id, ep.id, RelationshipType.CONTAINS)
            await self.surface_engine.compute(event.scan_id, app.id)

    async def _on_service_observed(self, event: Event) -> None:
        host = event.payload.get("host") or event.payload.get("ip") or ""
        asset_type = AssetType.IP_ADDRESS if _looks_like_ip(host) else AssetType.HOSTNAME
        host_asset = await self._find_asset(event.scan_id, asset_type, host.lower())
        if not host_asset:
            host_asset = await self._upsert_asset(
                event.scan_id,
                asset_type,
                host.lower(),
                host,
                event.correlation_id,
            )
        meta = host_asset.metadata_ or {}
        meta["ports_discovered"] = True
        meta["services_identified"] = True
        meta["last_observed_port"] = event.payload.get("port")
        host_asset.metadata_ = meta
        await self.surface_engine.compute(event.scan_id, host_asset.id)

    async def _on_javascript_discovered(self, event: Event) -> None:
        url = event.payload.get("url", "")
        base = "/".join(url.split("/")[:3]).lower()
        app = await self._find_asset(event.scan_id, AssetType.WEB_APPLICATION, base)
        if not app:
            return
        meta = app.metadata_ or {}
        js_urls = set(meta.get("js_urls", []))
        js_urls.add(url)
        meta["js_urls"] = list(js_urls)
        app.metadata_ = meta

    async def _on_task_completed(self, event: Event) -> None:
        task_id = event.payload.get("task_id")
        if not task_id:
            return
        task = await self.session.get(Task, uuid.UUID(str(task_id)))
        if not task:
            return
        asset = await self._asset_for_task(task)
        if not asset:
            return
        if task.capability in (
            "PARAMETER_DISCOVERY",
            "JAVASCRIPT_COLLECTION",
            "LIVE_CRAWLING",
            "HTTP_CHARACTERIZATION",
        ):
            surface = await self.surface_engine.compute(task.scan_id, asset.id)
            if asset.asset_type == AssetType.WEB_APPLICATION.value:
                await self._compute_and_emit_applicability(
                    task.scan_id,
                    asset.id,
                    event.correlation_id,
                    ApplicabilityTrigger.SURFACE_UPDATED,
                )
            requirements = await self.surface_engine.missing_requirements(asset.id, task.scan_id)
            await self.emit_event(
                task.scan_id,
                EventType.SURFACE_COVERAGE_COMPUTED,
                {
                    "asset_id": str(asset.id),
                    "overall_status": surface.overall_status,
                    "gap_count": surface.gap_count,
                    "trigger": "task_completed",
                    "task_capability": task.capability,
                },
                event.correlation_id,
            )
            if requirements:
                await self.emit_event(
                    task.scan_id,
                    EventType.SURFACE_GAP_IDENTIFIED,
                    self.surface_engine.gaps_payload(asset.id, requirements),
                    event.correlation_id,
                )

    async def _compute_and_emit_applicability(
        self,
        scan_id: uuid.UUID,
        asset_id: uuid.UUID,
        correlation_id: uuid.UUID,
        trigger: ApplicabilityTrigger,
    ) -> None:
        rows = await self.applicability_engine.reevaluate(
            asset_id, scan_id, trigger=trigger
        )
        matrix = await self.matrix_engine.build(scan_id, asset_id)
        reqs = list(
            (
                await self.session.execute(
                    select(TestRequirement).where(TestRequirement.matrix_id == matrix.id)
                )
            )
            .scalars()
            .all()
        )
        uncovered_statuses = {
            TestRequirementCoverageStatus.NOT_TESTED.value,
            TestRequirementCoverageStatus.PARTIALLY_TESTED.value,
            TestRequirementCoverageStatus.INCONCLUSIVE.value,
        }
        uncovered = [r for r in reqs if r.coverage_status in uncovered_statuses]
        self.session.add(
            Event(
                scan_id=scan_id,
                event_type=EventType.TEST_MATRIX_UPDATED.value,
                payload={
                    "asset_id": str(asset_id),
                    "matrix_id": str(matrix.id),
                    "requirements_count": len(reqs),
                    "uncovered_count": len(uncovered),
                },
                correlation_id=correlation_id,
                sequence_number=await self._next_sequence(scan_id),
                processed_at=datetime.now(UTC),
            )
        )
        await self.session.flush()
        applicable = [
            r
            for r in rows
            if r.applicability_state
            in (
                ApplicabilityState.APPLICABLE.value,
                ApplicabilityState.POSSIBLY_APPLICABLE.value,
            )
        ]
        await self.emit_event(
            scan_id,
            EventType.APPLICABILITY_COMPUTED,
            {
                "asset_id": str(asset_id),
                "trigger": trigger.value,
                "applicable_count": len(applicable),
                "items": [
                    {
                        "vulnerability_class_id": str(r.vulnerability_class_id),
                        "state": r.applicability_state,
                        "rule_ids": r.rule_ids,
                        "confidence": r.confidence,
                    }
                    for r in applicable
                ],
            },
            correlation_id,
        )

    async def _asset_for_task(self, task: Task) -> Asset | None:
        td = task.target_descriptor or {}
        url = (td.get("url") or td.get("base_url") or "").lower().rstrip("/")
        if url:
            return await self._find_asset(task.scan_id, AssetType.WEB_APPLICATION, url)
        hostname = (td.get("hostname") or "").lower()
        if hostname:
            asset = await self._find_asset(task.scan_id, AssetType.HOSTNAME, hostname)
            if asset:
                return asset
        return None

    async def _upsert_asset(
        self,
        scan_id: uuid.UUID,
        asset_type: AssetType,
        normalized_key: str,
        display_name: str,
        correlation_id: uuid.UUID,
        metadata: dict[str, Any] | None = None,
    ) -> Asset:
        scan = await self.session.get(Scan, scan_id)
        stmt = select(Asset).where(Asset.scan_id == scan_id, Asset.normalized_key == normalized_key)
        asset = (await self.session.execute(stmt)).scalar_one_or_none()
        if asset:
            asset.last_seen = datetime.now(UTC)
            if metadata:
                asset.metadata_ = {**(asset.metadata_ or {}), **metadata}
            return asset
        asset = Asset(
            scan_id=scan_id,
            project_id=scan.project_id if scan else scan_id,
            asset_type=asset_type.value,
            normalized_key=normalized_key,
            display_name=display_name,
            metadata_=metadata or {},
        )
        self.session.add(asset)
        await self.session.flush()
        await self.emit_event(
            scan_id, EventType.ASSET_ADDED, {"asset_id": str(asset.id)}, correlation_id
        )
        return asset

    async def _find_asset(
        self, scan_id: uuid.UUID, asset_type: AssetType, normalized_key: str
    ) -> Asset | None:
        stmt = select(Asset).where(
            Asset.scan_id == scan_id,
            Asset.asset_type == asset_type.value,
            Asset.normalized_key == normalized_key,
        )
        return (await self.session.execute(stmt)).scalar_one_or_none()

    async def _add_relationship(
        self,
        scan_id: uuid.UUID,
        source_id: uuid.UUID,
        target_id: uuid.UUID,
        rel_type: RelationshipType,
    ) -> None:
        rel = Relationship(
            scan_id=scan_id,
            source_asset_id=source_id,
            target_asset_id=target_id,
            relationship_type=rel_type.value,
        )
        self.session.add(rel)
        await self.session.flush()
        await self.emit_event(
            scan_id,
            EventType.RELATIONSHIP_ADDED,
            {"relationship_id": str(rel.id), "type": rel_type.value},
            uuid.uuid4(),
        )

    async def run_pending_tasks(
        self,
        scan_id: uuid.UUID,
        correlation_id: uuid.UUID,
        limit: int | None = None,
    ) -> int:
        stmt = select(Task).where(
            Task.scan_id == scan_id,
            Task.status == TaskStatus.READY.value,
        )
        tasks = list((await self.session.execute(stmt)).scalars().all())
        if limit is not None:
            tasks = tasks[:limit]
        for task in tasks:
            await self.execute_task(task.id, correlation_id)
        return len(tasks)

    async def run_scan_pipeline(self, scan_id: uuid.UUID, correlation_id: uuid.UUID) -> None:
        """Execute workflow until no ready tasks remain (bounded iterations)."""
        executed = 0
        for _ in range(self.max_pipeline_iterations):
            remaining = self.max_pipeline_tasks - executed
            if remaining <= 0:
                break
            count = await self.run_pending_tasks(scan_id, correlation_id, limit=remaining)
            executed += count
            if count == 0:
                break
        await self.completion_evaluator.evaluate(scan_id)
