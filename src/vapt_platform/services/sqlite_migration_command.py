"""SQLite migration command wrapper (Phase 9)."""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy.engine import Connection

from vapt_platform.config.settings import get_settings
from vapt_platform.services.schema_compatibility_detector import SchemaCompatibilityDetector
from vapt_platform.services.sqlite_migration_helper import MigrationResult, SqliteMigrationHelper

logger = logging.getLogger(__name__)


class SqliteMigrationCommand:
    def check(self, connection: Connection) -> dict[str, Any]:
        settings = get_settings()
        report = SchemaCompatibilityDetector().inspect(connection)
        return {
            "phase9_sqlite_migration_command_enabled": settings.phase9_sqlite_migration_command_enabled,
            "schema": report.to_dict(),
            "safe_to_migrate": report.migration_required and connection.dialect.name == "sqlite",
        }

    def migrate_test_requirements(
        self, connection: Connection, *, dry_run: bool = True
    ) -> MigrationResult:
        settings = get_settings()
        if not settings.phase9_sqlite_migration_command_enabled:
            return MigrationResult(
                migrated=False,
                message="SQLite migration command disabled by configuration",
                details={},
            )
        if dry_run:
            logger.info("sqlite_migration_dry_run step=test_requirements_unique_constraint")
        else:
            logger.info("sqlite_migration_execute step=test_requirements_unique_constraint")
        result = SqliteMigrationHelper().migrate_test_requirements_unique_constraint(
            connection, dry_run=dry_run
        )
        if result.migrated:
            logger.info("sqlite_migration_completed message=%s", result.message)
        return result
