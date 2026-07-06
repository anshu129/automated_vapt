"""Application configuration."""

from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from pydantic import Field
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
    tool_search_paths: str = Field(default="", alias="TOOL_SEARCH_PATHS")


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
