"""Explicit SQLite migration for test_requirements unique constraint (Phase 8)."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from sqlalchemy import inspect, text
from sqlalchemy.engine import Connection

from vapt_platform.services.schema_compatibility_detector import SchemaCompatibilityDetector

logger = logging.getLogger(__name__)


@dataclass
class MigrationResult:
    migrated: bool
    message: str
    details: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {"migrated": self.migrated, "message": self.message, "details": self.details}


class SqliteMigrationHelper:
    def migrate_test_requirements_unique_constraint(
        self, connection: Connection, *, dry_run: bool = False
    ) -> MigrationResult:
        detector = SchemaCompatibilityDetector()
        report = detector.inspect(connection)
        if connection.dialect.name != "sqlite":
            return MigrationResult(
                migrated=False,
                message="Migration only applies to SQLite",
                details=report.to_dict(),
            )
        if not report.legacy_test_requirement_constraint:
            return MigrationResult(
                migrated=False,
                message="No legacy constraint detected; migration not required",
                details=report.to_dict(),
            )
        inspector = inspect(connection)
        if "test_requirements" not in inspector.get_table_names():
            return MigrationResult(
                migrated=False,
                message="test_requirements table missing",
                details={},
            )
        if dry_run:
            return MigrationResult(
                migrated=False,
                message="Dry run: would rebuild test_requirements with Phase 7/8 unique constraint",
                details=report.to_dict(),
            )

        logger.info("sqlite_migration_started step=test_requirements_unique_constraint")
        connection.execute(text("PRAGMA foreign_keys=OFF"))
        cols = {c["name"] for c in inspector.get_columns("test_requirements")}
        connection.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS test_requirements_phase8 (
                    id TEXT PRIMARY KEY,
                    matrix_id TEXT NOT NULL,
                    vulnerability_class_id TEXT NOT NULL,
                    applicability_state VARCHAR(32) NOT NULL DEFAULT 'NOT_APPLICABLE',
                    testing_mode VARCHAR(32) NOT NULL DEFAULT 'MANUAL',
                    coverage_status VARCHAR(32) NOT NULL DEFAULT 'NOT_TESTED',
                    required_evidence TEXT,
                    eligible_capabilities TEXT,
                    required_capability VARCHAR(64),
                    source_rule_ids TEXT,
                    reasoning_trace TEXT,
                    safety_class VARCHAR(32),
                    authorization_requirement VARCHAR(32),
                    credential_requirement VARCHAR(32),
                    latest_result_id TEXT,
                    confidence REAL DEFAULT 0.5,
                    next_action VARCHAR(64) NOT NULL DEFAULT 'NONE',
                    uniqueness_key VARCHAR(64) DEFAULT '',
                    scope_granularity VARCHAR(32) DEFAULT 'SURFACE',
                    scope_dimensions TEXT,
                    is_legacy_merged BOOLEAN DEFAULT 0,
                    source_event_ids TEXT,
                    source_hypothesis_ids TEXT,
                    source_coverage_gap_ids TEXT,
                    source_change_event_ids TEXT,
                    created_at TIMESTAMP,
                    updated_at TIMESTAMP,
                    UNIQUE(matrix_id, vulnerability_class_id, uniqueness_key)
                )
                """
            )
        )
        col_list = [
            c
            for c in (
                "id",
                "matrix_id",
                "vulnerability_class_id",
                "applicability_state",
                "testing_mode",
                "coverage_status",
                "required_evidence",
                "eligible_capabilities",
                "required_capability",
                "source_rule_ids",
                "reasoning_trace",
                "safety_class",
                "authorization_requirement",
                "credential_requirement",
                "latest_result_id",
                "confidence",
                "next_action",
                "uniqueness_key",
                "scope_granularity",
                "scope_dimensions",
                "is_legacy_merged",
                "source_event_ids",
                "source_hypothesis_ids",
                "source_coverage_gap_ids",
                "source_change_event_ids",
                "created_at",
                "updated_at",
            )
            if c in cols or c in {"scope_granularity", "scope_dimensions", "is_legacy_merged"}
        ]
        select_exprs = []
        for c in col_list:
            if c in cols:
                select_exprs.append(c)
            elif c == "uniqueness_key":
                select_exprs.append("COALESCE(uniqueness_key, '')")
            elif c == "scope_granularity":
                select_exprs.append("'SURFACE'")
            elif c == "scope_dimensions":
                select_exprs.append("'{}'")
            elif c == "is_legacy_merged":
                select_exprs.append("0")
            else:
                select_exprs.append("NULL")
        connection.execute(
            text(
                f"INSERT INTO test_requirements_phase8 ({', '.join(col_list)}) "
                f"SELECT {', '.join(select_exprs)} FROM test_requirements"
            )
        )
        connection.execute(text("DROP TABLE test_requirements"))
        connection.execute(text("ALTER TABLE test_requirements_phase8 RENAME TO test_requirements"))
        connection.execute(
            text(
                "CREATE INDEX IF NOT EXISTS ix_test_requirements_matrix_id "
                "ON test_requirements (matrix_id)"
            )
        )
        connection.execute(
            text(
                "CREATE INDEX IF NOT EXISTS ix_test_requirements_uniqueness_key "
                "ON test_requirements (uniqueness_key)"
            )
        )
        connection.execute(text("PRAGMA foreign_keys=ON"))
        logger.info("sqlite_migration_completed step=test_requirements_unique_constraint")
        return MigrationResult(
            migrated=True,
            message="Rebuilt test_requirements with (matrix_id, vulnerability_class_id, uniqueness_key) constraint",
            details=detector.inspect(connection).to_dict(),
        )
