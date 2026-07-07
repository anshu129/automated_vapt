"""Database schema compatibility detection (Phase 8)."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import inspect, text
from sqlalchemy.engine import Connection

logger = logging.getLogger(__name__)

SCHEMA_VERSION_PHASE9 = "phase9-v1"
SCHEMA_VERSION_PHASE8 = "phase8-v1"


@dataclass
class SchemaCompatibilityReport:
    schema_version: str
    dialect: str
    legacy_test_requirement_constraint: bool
    phase7_requirement_fields: bool
    phase7_report_snapshots: bool
    phase8_report_artifact_fields: bool
    phase8_testplan_uniqueness_fields: bool
    phase9_fingerprint_hash: bool
    phase9_plan_split_fields: bool
    phase9_retention_fields: bool
    migration_required: bool
    warnings: list[str] = field(default_factory=list)
    recommended_action: str = "none"

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "dialect": self.dialect,
            "legacy_test_requirement_constraint": self.legacy_test_requirement_constraint,
            "phase7_requirement_fields": self.phase7_requirement_fields,
            "phase7_report_snapshots": self.phase7_report_snapshots,
            "phase8_report_artifact_fields": self.phase8_report_artifact_fields,
            "phase8_testplan_uniqueness_fields": self.phase8_testplan_uniqueness_fields,
            "phase9_fingerprint_hash": self.phase9_fingerprint_hash,
            "phase9_plan_split_fields": self.phase9_plan_split_fields,
            "phase9_retention_fields": self.phase9_retention_fields,
            "migration_required": self.migration_required,
            "warnings": self.warnings,
            "recommended_action": self.recommended_action,
        }


class SchemaCompatibilityDetector:
    def inspect(self, connection: Connection) -> SchemaCompatibilityReport:
        inspector = inspect(connection)
        dialect = connection.dialect.name
        tables = set(inspector.get_table_names())

        legacy_constraint = False
        if dialect == "sqlite" and "test_requirements" in tables:
            rows = connection.execute(
                text(
                    "SELECT name, sql FROM sqlite_master "
                    "WHERE type='index' AND tbl_name='test_requirements'"
                )
            ).fetchall()
            for name, sql in rows:
                if name == "uq_test_requirement_matrix_class":
                    legacy_constraint = True
                if sql and "uq_test_requirement_matrix_class" in (sql or ""):
                    if "uniqueness_key" not in (sql or ""):
                        legacy_constraint = True

        req_cols = (
            {c["name"] for c in inspector.get_columns("test_requirements")}
            if "test_requirements" in tables
            else set()
        )
        plan_cols = (
            {c["name"] for c in inspector.get_columns("test_plans")}
            if "test_plans" in tables
            else set()
        )
        snap_cols = (
            {c["name"] for c in inspector.get_columns("report_snapshots")}
            if "report_snapshots" in tables
            else set()
        )

        phase7_req = "scope_granularity" in req_cols
        phase7_snaps = "report_snapshots" in tables
        phase8_artifact = "artifact_reference" in snap_cols
        phase8_plan = "planning_fingerprint" in plan_cols
        phase9_fp = "fingerprint_hash" in snap_cols
        phase9_split = "split_from_plan_id" in plan_cols
        phase9_retention = "artifact_retention_status" in snap_cols

        warnings: list[str] = []
        migration_required = legacy_constraint
        recommended = "none"
        if legacy_constraint:
            warnings.append(
                "Legacy test_requirements unique constraint detected; "
                "run sqlite migration helper before enabling parameter-scoped rows."
            )
            recommended = "run_sqlite_test_requirements_migration"
        if phase7_snaps and not phase8_artifact:
            warnings.append("Report snapshots exist without Phase 8 artifact reference columns.")
        if phase8_artifact and not phase9_fp:
            warnings.append("Phase 9 fingerprint_hash column missing on report_snapshots.")

        schema_version = "legacy"
        if phase9_fp and phase9_split and phase8_plan and phase8_artifact:
            schema_version = SCHEMA_VERSION_PHASE9
        elif phase8_plan and phase8_artifact:
            schema_version = SCHEMA_VERSION_PHASE8

        report = SchemaCompatibilityReport(
            schema_version=schema_version,
            dialect=dialect,
            legacy_test_requirement_constraint=legacy_constraint,
            phase7_requirement_fields=phase7_req,
            phase7_report_snapshots=phase7_snaps,
            phase8_report_artifact_fields=phase8_artifact,
            phase8_testplan_uniqueness_fields=phase8_plan,
            phase9_fingerprint_hash=phase9_fp,
            phase9_plan_split_fields=phase9_split,
            phase9_retention_fields=phase9_retention,
            migration_required=migration_required,
            warnings=warnings,
            recommended_action=recommended,
        )
        logger.info(
            "schema_compatibility_detected schema_version=%s dialect=%s migration_required=%s "
            "legacy_constraint=%s",
            report.schema_version,
            dialect,
            migration_required,
            legacy_constraint,
        )
        return report
