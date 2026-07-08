"""Application configuration."""

from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    database_url: str = Field(
        default="postgresql+asyncpg://vapt:vapt@localhost:5432/vapt",
        alias="DATABASE_URL",
    )
    database_url_sync: str = Field(
        default="postgresql+psycopg://vapt:vapt@localhost:5432/vapt",
        alias="DATABASE_URL_SYNC",
    )
    redis_url: str = Field(default="redis://localhost:6379/0", alias="REDIS_URL")
    log_level: str = Field(default="INFO", alias="LOG_LEVEL")
    ai_enabled: bool = Field(default=False, alias="AI_ENABLED")
    mistral_api_key: SecretStr | None = Field(default=None, alias="MISTRAL_API_KEY")
    mistral_model: str = Field(default="mistral-small-latest", alias="MISTRAL_MODEL")
    mistral_base_url: str = Field(default="https://api.mistral.ai/v1", alias="MISTRAL_BASE_URL")
    ai_max_tokens: int = Field(
        default=0,
        alias="AI_MAX_TOKENS",
        description="0 = no practical limit (32768). Set a positive value to cap output.",
    )
    ai_timeout_seconds: int = Field(default=45, alias="AI_TIMEOUT_SECONDS")
    mcp_enabled: bool = Field(default=False, alias="MCP_ENABLED")
    mcp_read_only: bool = Field(default=True, alias="MCP_READ_ONLY")
    config_path: Path = Field(default=Path("config/default.yaml"))
    engagement_allow_state_changing: bool = Field(default=False)
    engagement_no_discovery_assumption: bool = Field(default=True)
    recursive_correlation_max_depth: int = Field(default=10)
    tool_timeout_seconds: int = Field(default=30, alias="TOOL_TIMEOUT_SECONDS")
    scan_pipeline_max_iterations: int = Field(default=10, alias="SCAN_PIPELINE_MAX_ITERATIONS")
    scan_pipeline_max_tasks: int = Field(default=30, alias="SCAN_PIPELINE_MAX_TASKS")
    scan_start_inline_execution: bool = Field(default=False, alias="SCAN_START_INLINE_EXECUTION")
    ui_scan_inline_recon: bool = Field(default=True, alias="UI_SCAN_INLINE_RECON")
    recon_commit_per_task: bool = Field(default=True, alias="RECON_COMMIT_PER_TASK")
    recon_tool_logging: bool = Field(default=True, alias="RECON_TOOL_LOGGING")
    tool_search_paths: str = Field(default="", alias="TOOL_SEARCH_PATHS")
    seclists_root: str = Field(default="SecLists-master", alias="SECLISTS_ROOT")
    use_fake_fallback: bool = Field(default=True, alias="USE_FAKE_FALLBACK")
    seed_on_startup: bool = Field(default=False, alias="SEED_ON_STARTUP")
    burp_mcp_enabled: bool = Field(default=False, alias="BURP_MCP_ENABLED")
    burp_mcp_sse_url: str = Field(
        default="http://127.0.0.1:9876",
        alias="BURP_MCP_SSE_URL",
    )
    sqlmap_mcp_enabled: bool = Field(default=False, alias="SQLMAP_MCP_ENABLED")
    sqlmap_mcp_server_path: str = Field(default="", alias="SQLMAP_MCP_SERVER_PATH")
    sqlmap_mcp_command: str = Field(default="python", alias="SQLMAP_MCP_COMMAND")
    sqlmap_mcp_extra_args: str = Field(default="", alias="SQLMAP_MCP_EXTRA_ARGS")
    full_assessment_v2: bool = Field(default=True, alias="FULL_ASSESSMENT_V2")
    use_legacy_mcp_validation: bool = Field(default=False, alias="USE_LEGACY_MCP_VALIDATION")
    recursive_correlation_enabled: bool = Field(default=True, alias="RECURSIVE_CORRELATION_ENABLED")
    correlation_max_generations: int = Field(default=5, alias="CORRELATION_MAX_GENERATIONS")
    correlation_max_events_per_scan: int = Field(default=200, alias="CORRELATION_MAX_EVENTS_PER_SCAN")
    correlation_max_rule_executions_per_scan: int = Field(
        default=500, alias="CORRELATION_MAX_RULE_EXECUTIONS_PER_SCAN"
    )
    correlation_max_new_hypotheses_per_scan: int = Field(
        default=100, alias="CORRELATION_MAX_NEW_HYPOTHESES_PER_SCAN"
    )
    correlation_max_new_test_requirements_per_scan: int = Field(
        default=200, alias="CORRELATION_MAX_NEW_TEST_REQUIREMENTS_PER_SCAN"
    )
    correlation_max_automated_executions_per_scan: int = Field(
        default=50, alias="CORRELATION_MAX_AUTOMATED_EXECUTIONS_PER_SCAN"
    )
    assessment_completion_v2: bool = Field(default=True, alias="ASSESSMENT_COMPLETION_V2")
    pending_work_aware_completion: bool = Field(default=True, alias="PENDING_WORK_AWARE_COMPLETION")
    bind_job_status_to_assessment: bool = Field(default=False, alias="BIND_JOB_STATUS_TO_ASSESSMENT")
    phase6_status_sync_enabled: bool = Field(default=True, alias="PHASE6_STATUS_SYNC_ENABLED")
    phase6_completion_history_enabled: bool = Field(
        default=True, alias="PHASE6_COMPLETION_HISTORY_ENABLED"
    )
    phase6_report_completion_payload: bool = Field(
        default=True, alias="PHASE6_REPORT_COMPLETION_PAYLOAD"
    )
    phase7_requirement_granularity_enabled: bool = Field(
        default=True, alias="PHASE7_REQUIREMENT_GRANULARITY_ENABLED"
    )
    phase7_report_snapshots_enabled: bool = Field(
        default=True, alias="PHASE7_REPORT_SNAPSHOTS_ENABLED"
    )
    phase7_latest_transition_denormalized: bool = Field(
        default=True, alias="PHASE7_LATEST_TRANSITION_DENORMALIZED"
    )
    phase7_legacy_requirement_merge_only: bool = Field(
        default=False, alias="PHASE7_LEGACY_REQUIREMENT_MERGE_ONLY"
    )
    phase8_report_artifact_storage_enabled: bool = Field(
        default=True, alias="PHASE8_REPORT_ARTIFACT_STORAGE_ENABLED"
    )
    phase8_report_staleness_detection_enabled: bool = Field(
        default=True, alias="PHASE8_REPORT_STALENESS_DETECTION_ENABLED"
    )
    phase8_testplan_uniqueness_enabled: bool = Field(
        default=True, alias="PHASE8_TESTPLAN_UNIQUENESS_ENABLED"
    )
    phase8_sqlite_migration_hardening_enabled: bool = Field(
        default=True, alias="PHASE8_SQLITE_MIGRATION_HARDENING_ENABLED"
    )
    report_artifact_root: str = Field(
        default="data/report_artifacts", alias="REPORT_ARTIFACT_ROOT"
    )
    report_artifact_backend: str = Field(
        default="filesystem", alias="REPORT_ARTIFACT_BACKEND"
    )
    report_artifact_object_bucket: str = Field(
        default="vapt-reports", alias="REPORT_ARTIFACT_OBJECT_BUCKET"
    )
    report_artifact_object_prefix: str = Field(
        default="report-artifacts", alias="REPORT_ARTIFACT_OBJECT_PREFIX"
    )
    report_artifact_max_versions_per_scan: int = Field(
        default=10, alias="REPORT_ARTIFACT_MAX_VERSIONS_PER_SCAN"
    )
    report_artifact_ttl_days: int = Field(default=90, alias="REPORT_ARTIFACT_TTL_DAYS")
    report_artifact_keep_latest: bool = Field(default=True, alias="REPORT_ARTIFACT_KEEP_LATEST")
    report_artifact_keep_terminal: bool = Field(
        default=True, alias="REPORT_ARTIFACT_KEEP_TERMINAL"
    )
    report_staleness_poll_interval_seconds: int = Field(
        default=30, alias="REPORT_STALENESS_POLL_INTERVAL_SECONDS"
    )
    phase9_artifact_backend_enabled: bool = Field(
        default=True, alias="PHASE9_ARTIFACT_BACKEND_ENABLED"
    )
    phase9_artifact_retention_enabled: bool = Field(
        default=True, alias="PHASE9_ARTIFACT_RETENTION_ENABLED"
    )
    phase9_staleness_polling_enabled: bool = Field(
        default=True, alias="PHASE9_STALENESS_POLLING_ENABLED"
    )
    phase9_staleness_full_hash_fallback_enabled: bool = Field(
        default=True, alias="PHASE9_STALENESS_FULL_HASH_FALLBACK_ENABLED"
    )
    phase9_plan_splitting_enabled: bool = Field(
        default=True, alias="PHASE9_PLAN_SPLITTING_ENABLED"
    )
    phase9_integrity_audit_enabled: bool = Field(
        default=True, alias="PHASE9_INTEGRITY_AUDIT_ENABLED"
    )
    phase9_sqlite_migration_command_enabled: bool = Field(
        default=True, alias="PHASE9_SQLITE_MIGRATION_COMMAND_ENABLED"
    )

    def incompatible_validation_paths(self) -> bool:
        """True when V2 routing and legacy MCP orchestration would both run."""
        return self.full_assessment_v2 and self.use_legacy_mcp_validation

    def sqlmap_mcp_extra_args_list(self) -> list[str]:
        raw = self.sqlmap_mcp_extra_args.strip()
        if not raw:
            return []
        if "," in raw:
            return [part.strip() for part in raw.split(",") if part.strip()]
        return raw.split()

    def effective_ai_max_tokens(self) -> int:
        """Return the Mistral max_tokens value (0 in settings means unlimited)."""
        if self.ai_max_tokens <= 0:
            return 32768
        return self.ai_max_tokens


def load_yaml_config(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    with path.open(encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


@lru_cache
def get_settings() -> Settings:
    settings = Settings()
    yaml_cfg = load_yaml_config(settings.config_path)
    engagement = yaml_cfg.get("engagement", {})
    if "allow_state_changing" in engagement:
        settings.engagement_allow_state_changing = engagement["allow_state_changing"]
    if "no_discovery_assumption" in engagement:
        settings.engagement_no_discovery_assumption = engagement["no_discovery_assumption"]
    rc = yaml_cfg.get("recursive_correlation", {})
    if "max_depth" in rc:
        settings.recursive_correlation_max_depth = rc["max_depth"]
    return settings
