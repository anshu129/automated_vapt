"""SQLAlchemy ORM models."""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from vapt_platform.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin, utcnow


class Project(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "projects"

    name: Mapped[str] = mapped_column(String(256), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    owner: Mapped[str] = mapped_column(String(256), default="system")
    settings: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    scans: Mapped[list["Scan"]] = relationship(back_populates="project")
    scope_rules: Mapped[list["ScopeRule"]] = relationship(back_populates="project")


class ScopeRule(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "scope_rules"

    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id"), nullable=False)
    rule_type: Mapped[str] = mapped_column(String(64), nullable=False)
    pattern: Mapped[str] = mapped_column(String(512), nullable=False)
    assessment_mode: Mapped[str] = mapped_column(String(32), default="ACTIVE")
    priority: Mapped[int] = mapped_column(Integer, default=0)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)

    project: Mapped["Project"] = relationship(back_populates="scope_rules")


class ScopeSnapshot(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "scope_snapshots"

    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id"), nullable=False)
    rules: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Scan(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "scans"

    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="CREATED")
    workflow_version: Mapped[str] = mapped_column(String(32), default="1.0")
    rule_set_version: Mapped[str] = mapped_column(String(32), default="1.0")
    applicability_rule_version: Mapped[str] = mapped_column(String(32), default="1.0")
    safety_policy_version: Mapped[str] = mapped_column(String(32), default="1.0")
    operational_profile: Mapped[str] = mapped_column(String(64), default="STANDARD")
    scope_snapshot_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("scope_snapshots.id"))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    previous_scan_id: Mapped[uuid.UUID | None] = mapped_column(Uuid())

    project: Mapped["Project"] = relationship(back_populates="scans")


class Asset(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "assets"
    __table_args__ = (UniqueConstraint("scan_id", "normalized_key", name="uq_asset_scan_key"),)

    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id"), nullable=False, index=True)
    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id"), nullable=False)
    asset_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    normalized_key: Mapped[str] = mapped_column(String(512), nullable=False)
    display_name: Mapped[str] = mapped_column(String(512), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    metadata_: Mapped[dict[str, Any]] = mapped_column("metadata", JSON, default=dict)
    identity_status: Mapped[str] = mapped_column(String(32), default="DISTINCT")
    criticality: Mapped[str] = mapped_column(String(32), default="MEDIUM")


class Relationship(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "relationships"

    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id"), nullable=False, index=True)
    source_asset_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("assets.id"), nullable=False)
    target_asset_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("assets.id"), nullable=False)
    relationship_type: Mapped[str] = mapped_column(String(64), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    evidence_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    superseded_by_id: Mapped[uuid.UUID | None] = mapped_column(Uuid())


class Event(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "events"

    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id"), nullable=False, index=True)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    correlation_id: Mapped[uuid.UUID] = mapped_column(Uuid(), nullable=False)
    causation_id: Mapped[uuid.UUID | None] = mapped_column(Uuid())
    sequence_number: Mapped[int] = mapped_column(BigInteger, nullable=False)
    schema_version: Mapped[str] = mapped_column(String(16), default="1.0")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    processed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Observation(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "observations"

    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id"), nullable=False, index=True)
    subject_asset_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("assets.id"))
    observation_type: Mapped[str] = mapped_column(String(64), nullable=False)
    source_type: Mapped[str] = mapped_column(String(32), default="TOOL")
    source_id: Mapped[str | None] = mapped_column(String(256))
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    raw_artifact_id: Mapped[uuid.UUID | None] = mapped_column(Uuid())
    provenance: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


class Task(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "tasks"
    __table_args__ = (UniqueConstraint("uniqueness_key", name="uq_task_uniqueness"),)

    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id"), nullable=False, index=True)
    capability: Mapped[str] = mapped_column(String(128), nullable=False)
    capability_provider_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("capability_providers.id")
    )
    execution_profile_id: Mapped[str | None] = mapped_column(String(64))
    evidence_quality_decision_id: Mapped[uuid.UUID | None] = mapped_column(Uuid())
    target_descriptor: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    normalized_target: Mapped[str] = mapped_column(String(512), nullable=False)
    configuration_hash: Mapped[str] = mapped_column(String(64), default="")
    uniqueness_key: Mapped[str] = mapped_column(String(512), nullable=False)
    priority: Mapped[int] = mapped_column(Integer, default=100)
    status: Mapped[str] = mapped_column(String(32), default="PENDING", index=True)
    operational_profile: Mapped[str] = mapped_column(String(64), default="STANDARD")
    parameters: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    retry_count: Mapped[int] = mapped_column(Integer, default=0)
    max_retries: Mapped[int] = mapped_column(Integer, default=3)
    scheduled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    defer_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    scope_decision_id: Mapped[uuid.UUID | None] = mapped_column(Uuid())


class TaskRun(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "task_runs"

    task_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tasks.id"), nullable=False, index=True)
    attempt_number: Mapped[int] = mapped_column(Integer, default=1)
    worker_id: Mapped[str] = mapped_column(String(128), default="local-worker")
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    exit_code: Mapped[int | None] = mapped_column(Integer)
    raw_artifact_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    metrics: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    error_summary: Mapped[str | None] = mapped_column(Text)
    scope_revalidated: Mapped[bool] = mapped_column(Boolean, default=True)


class RawArtifact(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "raw_artifacts"

    task_run_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("task_runs.id"), nullable=False)
    artifact_type: Mapped[str] = mapped_column(String(32), nullable=False)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    content: Mapped[str] = mapped_column(Text, default="")
    size_bytes: Mapped[int] = mapped_column(Integer, default=0)
    metadata_: Mapped[dict[str, Any]] = mapped_column("metadata", JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ToolManifest(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "tool_manifests"

    name: Mapped[str] = mapped_column(String(128), nullable=False)
    version: Mapped[str] = mapped_column(String(32), nullable=False)
    capabilities: Mapped[list[str]] = mapped_column(JSON, default=list)
    capability_group: Mapped[str | None] = mapped_column(String(64))
    safety_class: Mapped[str] = mapped_column(String(32), default="PASSIVE")
    cost_tier: Mapped[str] = mapped_column(String(32), default="FREE")
    accepted_input_types: Mapped[list[str]] = mapped_column(JSON, default=list)
    produced_output_types: Mapped[list[str]] = mapped_column(JSON, default=list)
    supported_parameters: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    container_image: Mapped[str | None] = mapped_column(String(256))
    parser_version: Mapped[str] = mapped_column(String(32), default="1.0")
    negative_evidence_support: Mapped[bool] = mapped_column(Boolean, default=False)
    historical_only: Mapped[bool] = mapped_column(Boolean, default=False)


class CapabilityDefinition(Base):
    __tablename__ = "capabilities"

    code: Mapped[str] = mapped_column(String(128), primary_key=True)
    capability_group: Mapped[str] = mapped_column(String(64), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    default_safety_class: Mapped[str] = mapped_column(String(32), nullable=False)
    active: Mapped[bool] = mapped_column(Boolean, default=True)


class CapabilityProvider(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "capability_providers"
    __table_args__ = (
        UniqueConstraint("capability_code", "provider_name", name="uq_provider_capability"),
    )

    capability_code: Mapped[str] = mapped_column(
        ForeignKey("capabilities.code"), nullable=False, index=True
    )
    provider_name: Mapped[str] = mapped_column(String(128), nullable=False)
    manifest_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("tool_manifests.id"))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    cost_tier: Mapped[str] = mapped_column(String(32), default="FREE")
    requires_api_key: Mapped[bool] = mapped_column(Boolean, default=False)
    api_key_secret_ref: Mapped[str | None] = mapped_column(String(256))
    priority_weight: Mapped[int] = mapped_column(Integer, default=0)
    max_concurrent: Mapped[int] = mapped_column(Integer, default=5)
    supported_profiles: Mapped[list[str]] = mapped_column(JSON, default=list)
    fake_behavior: Mapped[str | None] = mapped_column(String(64))


class CapabilityExecutionProfile(Base):
    __tablename__ = "capability_execution_profiles"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    version: Mapped[str] = mapped_column(String(32), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    timeout_multiplier: Mapped[float] = mapped_column(Float, default=1.0)
    concurrency_multiplier: Mapped[float] = mapped_column(Float, default=1.0)
    retry_policy: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    policy_flags: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    active: Mapped[bool] = mapped_column(Boolean, default=True)


class EvidenceQualityDecision(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "evidence_quality_decisions"

    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id"), nullable=False, index=True)
    task_run_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("task_runs.id"), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    reason_codes: Mapped[list[str]] = mapped_column(JSON, default=list)
    explanation: Mapped[str | None] = mapped_column(Text)
    recommended_next_capability: Mapped[str | None] = mapped_column(String(128))
    recommended_provider_id: Mapped[uuid.UUID | None] = mapped_column(Uuid())
    eligible_alternate_profiles: Mapped[list[str]] = mapped_column(JSON, default=list)
    retry_allowed: Mapped[bool] = mapped_column(Boolean, default=False)
    manual_review_required: Mapped[bool] = mapped_column(Boolean, default=False)
    rule_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    evaluated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class DiscoveryGainMetric(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "discovery_gain_metrics"
    __table_args__ = (
        UniqueConstraint("scan_id", "capability_code", "provider_id", name="uq_gain_metric"),
    )

    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id"), nullable=False)
    capability_code: Mapped[str] = mapped_column(String(128), nullable=False)
    provider_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("capability_providers.id"))
    raw_observation_count: Mapped[int] = mapped_column(Integer, default=0)
    unique_asset_count: Mapped[int] = mapped_column(Integer, default=0)
    unique_endpoint_count: Mapped[int] = mapped_column(Integer, default=0)
    unique_relationship_count: Mapped[int] = mapped_column(Integer, default=0)
    duplicate_ratio: Mapped[float] = mapped_column(Float, default=0.0)
    execution_duration_ms: Mapped[int] = mapped_column(BigInteger, default=0)
    error_ratio: Mapped[float] = mapped_column(Float, default=0.0)
    rate_limit_ratio: Mapped[float] = mapped_column(Float, default=0.0)
    historical_unique_gain: Mapped[int] = mapped_column(Integer, default=0)
    confidence_contribution: Mapped[float] = mapped_column(Float, default=0.0)
    computed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class SurfaceCoverageRecord(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "surface_coverage_records"
    __table_args__ = (UniqueConstraint("scan_id", "asset_id", name="uq_surface_coverage"),)

    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id"), nullable=False, index=True)
    asset_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("assets.id"), nullable=False)
    asset_type: Mapped[str] = mapped_column(String(64), nullable=False)
    dimensions: Mapped[dict[str, str]] = mapped_column(JSON, default=dict)
    overall_status: Mapped[str] = mapped_column(String(32), nullable=False)
    gap_count: Mapped[int] = mapped_column(Integer, default=0)
    rule_version: Mapped[str] = mapped_column(String(32), default="1.0")
    computed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class VulnerabilityClass(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "vulnerability_classes"

    class_code: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    parent_class_id: Mapped[uuid.UUID | None] = mapped_column(Uuid())
    related_cwe_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    typical_evidence_types: Mapped[list[str]] = mapped_column(JSON, default=list)
    default_testing_mode: Mapped[str] = mapped_column(String(32), default="MANUAL")
    taxonomy_version: Mapped[str] = mapped_column(String(32), default="1.0")
    active: Mapped[bool] = mapped_column(Boolean, default=True)


class ApplicabilityRule(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "applicability_rules"
    __table_args__ = (UniqueConstraint("rule_id", "version", name="uq_applicability_rule_ver"),)

    rule_id: Mapped[str] = mapped_column(String(128), nullable=False)
    version: Mapped[str] = mapped_column(String(32), nullable=False, default="1.0")
    description: Mapped[str | None] = mapped_column(Text)
    condition: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    output_classes: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False, default=list)
    active: Mapped[bool] = mapped_column(Boolean, default=True)


class AssetVulnerabilityApplicability(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "asset_vulnerability_applicability"
    __table_args__ = (
        UniqueConstraint("scan_id", "asset_id", "vulnerability_class_id", name="uq_applicability"),
    )

    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id"), nullable=False)
    asset_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("assets.id"), nullable=False)
    vulnerability_class_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("vulnerability_classes.id"), nullable=False
    )
    applicability_state: Mapped[str] = mapped_column(String(32), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    supporting_evidence_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    rule_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    explanation: Mapped[str | None] = mapped_column(Text)
    computed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AssetTestMatrix(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "asset_test_matrices"
    __table_args__ = (UniqueConstraint("scan_id", "asset_id", name="uq_test_matrix"),)

    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id"), nullable=False)
    asset_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("assets.id"), nullable=False)
    computed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    rule_version: Mapped[str] = mapped_column(String(32), default="1.0")


class TestRequirement(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "test_requirements"
    __table_args__ = (
        UniqueConstraint(
            "matrix_id",
            "vulnerability_class_id",
            name="uq_test_requirement_matrix_class",
        ),
    )

    matrix_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("asset_test_matrices.id"), nullable=False, index=True
    )
    vulnerability_class_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("vulnerability_classes.id"), nullable=False
    )
    applicability_state: Mapped[str] = mapped_column(
        String(32), nullable=False, default="NOT_APPLICABLE"
    )
    testing_mode: Mapped[str] = mapped_column(String(32), nullable=False, default="MANUAL")
    coverage_status: Mapped[str] = mapped_column(
        String(32), nullable=False, default="NOT_TESTED"
    )
    required_evidence: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    eligible_capabilities: Mapped[list[str]] = mapped_column(JSON, default=list)
    latest_result_id: Mapped[uuid.UUID | None] = mapped_column(Uuid())
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    next_action: Mapped[str] = mapped_column(String(64), nullable=False, default="NONE")


class TestPlan(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "test_plans"

    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id"), nullable=False, index=True)
    hypothesis_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("hypotheses.id"))
    asset_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    vulnerability_class_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    testing_mode: Mapped[str] = mapped_column(String(32), nullable=False)
    required_capabilities: Mapped[list[str]] = mapped_column(JSON, default=list)
    eligible_adapters: Mapped[list[str]] = mapped_column(JSON, default=list)
    required_context: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    credential_context_reference: Mapped[uuid.UUID | None] = mapped_column(Uuid())
    evidence_requirements: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    completion_conditions: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    safety_class: Mapped[str] = mapped_column(String(32))
    authorization_requirement: Mapped[str] = mapped_column(String(32), default="PRE_APPROVED")
    priority: Mapped[int] = mapped_column(Integer, default=100)
    status: Mapped[str] = mapped_column(String(32), default="DRAFT")
    reasoning_trace: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


class TestExecution(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "test_executions"

    test_plan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("test_plans.id"), nullable=False)
    task_run_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("task_runs.id"))
    provider_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("capability_providers.id"))
    template_id: Mapped[str | None] = mapped_column(String(256))
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    result_summary: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    evidence_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    executed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class EvidencePackage(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "evidence_packages"

    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id"), nullable=False)
    hypothesis_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("hypotheses.id"))
    validation_task_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("validation_tasks.id"))
    package_data: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class EvidenceLink(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "evidence_links"

    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id"), nullable=False, index=True)
    source_type: Mapped[str] = mapped_column(String(64), nullable=False)
    source_id: Mapped[uuid.UUID] = mapped_column(Uuid(), nullable=False)
    target_type: Mapped[str] = mapped_column(String(64), nullable=False)
    target_id: Mapped[uuid.UUID] = mapped_column(Uuid(), nullable=False)
    link_type: Mapped[str] = mapped_column(String(32), nullable=False)
    weight: Mapped[float] = mapped_column(Float, default=1.0)
    provenance: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Hypothesis(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "hypotheses"

    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id"), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    hypothesis_type: Mapped[str] = mapped_column(String(64), nullable=False)
    affected_asset_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    supporting_evidence_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    contradicting_evidence_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    correlation_rule_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    impact_if_confirmed: Mapped[str | None] = mapped_column(Text)
    validation_requirements: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(32), default="PROPOSED")
    verdict_id: Mapped[uuid.UUID | None] = mapped_column(Uuid())
    test_plan_id: Mapped[uuid.UUID | None] = mapped_column(Uuid())


class ValidationTask(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "validation_tasks"

    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id"), nullable=False, index=True)
    hypothesis_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("hypotheses.id"))
    test_plan_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("test_plans.id"))
    evidence_package_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("evidence_packages.id")
    )
    asset_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    priority: Mapped[int] = mapped_column(Integer, default=100)
    validation_goal: Mapped[str] = mapped_column(Text, nullable=False)
    required_evidence: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    suggested_safe_checks: Mapped[list[str]] = mapped_column(JSON, default=list)
    testing_mode: Mapped[str] = mapped_column(String(32), default="MANUAL")
    assigned_to: Mapped[str | None] = mapped_column(String(256))
    status: Mapped[str] = mapped_column(String(32), default="OPEN")
    source_correlation_id: Mapped[uuid.UUID | None] = mapped_column(Uuid())


class ValidationResult(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "validation_results"

    validation_task_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("validation_tasks.id"), nullable=False
    )
    outcome: Mapped[str] = mapped_column(String(32), nullable=False)
    analyst_notes: Mapped[str | None] = mapped_column(Text)
    evidence_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    recorded_by: Mapped[str] = mapped_column(String(256), default="analyst")
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Verdict(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "verdicts"

    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id"), nullable=False)
    hypothesis_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("hypotheses.id"), nullable=False)
    test_plan_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("test_plans.id"))
    validation_result_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("validation_results.id")
    )
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    supporting_evidence_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    contradicting_evidence_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    rule_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    explanation: Mapped[str | None] = mapped_column(Text)
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ConfirmedFinding(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "confirmed_findings"

    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id"), nullable=False)
    hypothesis_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("hypotheses.id"))
    validation_result_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("validation_results.id"), nullable=False
    )
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    affected_asset_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    cve_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    cwe_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    source_severity: Mapped[str | None] = mapped_column(String(32))
    contextual_priority: Mapped[str | None] = mapped_column(String(32))
    evidence_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    confirmed_by: Mapped[str] = mapped_column(String(256))
    confirmed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class FindingCorrelation(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "finding_correlations"

    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id"), nullable=False)
    correlation_type: Mapped[str] = mapped_column(String(64), nullable=False)
    entity_type_a: Mapped[str] = mapped_column(String(64))
    entity_id_a: Mapped[uuid.UUID] = mapped_column(Uuid())
    entity_type_b: Mapped[str] = mapped_column(String(64))
    entity_id_b: Mapped[uuid.UUID] = mapped_column(Uuid())
    participating_entity_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    evidence_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    rule_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    explanation: Mapped[str | None] = mapped_column(Text)
    recommended_validation_action: Mapped[str | None] = mapped_column(Text)
    resulting_action: Mapped[str | None] = mapped_column(String(64))


class CredentialReference(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "credential_references"

    project_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("projects.id"), nullable=False)
    credential_type: Mapped[str] = mapped_column(String(64), nullable=False)
    label: Mapped[str | None] = mapped_column(String(256))
    secret_backend_reference: Mapped[str] = mapped_column(String(512), nullable=False)
    role_name: Mapped[str | None] = mapped_column(String(128))
    expiry: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    allowed_capabilities: Mapped[list[str]] = mapped_column(JSON, default=list)
    status: Mapped[str] = mapped_column(String(32), default="ACTIVE")


class CredentialScopeBinding(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "credential_scope_bindings"

    credential_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("credential_references.id"), nullable=False, index=True
    )
    scope_rule_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("scope_rules.id"))
    asset_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("assets.id"))
    application_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("assets.id"))
    url_prefix: Mapped[str | None] = mapped_column(String(512))
    assessment_mode: Mapped[str] = mapped_column(String(32), default="CREDENTIALED")


class AuthenticationContext(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "authentication_contexts"

    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id"), nullable=False, index=True)
    credential_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("credential_references.id"), nullable=False, index=True
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("assets.id"), nullable=False)
    auth_method: Mapped[str] = mapped_column(String(64), nullable=False)
    session_established: Mapped[bool] = mapped_column(Boolean, default=False)
    session_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_validated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    coverage_dimensions: Mapped[list[str]] = mapped_column(JSON, default=list)


class RoleContext(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "role_contexts"

    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id"), nullable=False, index=True)
    authentication_context_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("authentication_contexts.id"), nullable=False, index=True
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("assets.id"), nullable=False)
    role_name: Mapped[str] = mapped_column(String(128), nullable=False)
    authorized: Mapped[bool] = mapped_column(Boolean, default=True)
    coverage_status: Mapped[dict[str, str]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AssessmentCompletionRecord(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "assessment_completion_records"
    __table_args__ = (UniqueConstraint("scan_id", name="uq_completion_scan"),)

    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id"), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    completion_reasons: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    blocking_items: Mapped[list[str]] = mapped_column(JSON, default=list)
    accepted_gaps: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    metrics: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    evaluated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    evaluated_by: Mapped[str] = mapped_column(String(256), default="system")


class AuditEvent(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "audit_events"

    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    actor: Mapped[str] = mapped_column(String(256), default="system")
    resource_type: Mapped[str] = mapped_column(String(64))
    resource_id: Mapped[uuid.UUID | None] = mapped_column(Uuid())
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    correlation_id: Mapped[uuid.UUID | None] = mapped_column(Uuid())
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class AIEnrichment(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "ai_enrichments"
    __table_args__ = (UniqueConstraint("cache_key", name="uq_ai_enrichment_cache_key"),)

    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id"), nullable=False, index=True)
    enrichment_type: Mapped[str] = mapped_column(String(64), nullable=False)
    target_entity_type: Mapped[str] = mapped_column(String(64), nullable=False)
    target_entity_id: Mapped[uuid.UUID] = mapped_column(Uuid(), nullable=False)
    provider: Mapped[str] = mapped_column(String(64), default="mistral")
    prompt_template_version: Mapped[str] = mapped_column(String(32), nullable=False)
    model_config: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    input_artifact_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    cache_key: Mapped[str] = mapped_column(String(64), nullable=False)
    output: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    validation_status: Mapped[str] = mapped_column(String(32), nullable=False)
    cached: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class CoverageRecord(Base, UUIDPrimaryKeyMixin):
    __tablename__ = "coverage_records"

    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id"), nullable=False)
    coverage_type: Mapped[str] = mapped_column(String(64), nullable=False)
    asset_type: Mapped[str | None] = mapped_column(String(64))
    eligible_count: Mapped[int] = mapped_column(Integer, default=0)
    completed_count: Mapped[int] = mapped_column(Integer, default=0)
    coverage_ratio: Mapped[float] = mapped_column(Float, default=0.0)
    gap_asset_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    computed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
