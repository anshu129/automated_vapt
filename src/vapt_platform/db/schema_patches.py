"""Additive schema patches for existing SQLite/PostgreSQL databases."""

from __future__ import annotations

from sqlalchemy import inspect, text
from sqlalchemy.engine import Connection

_PHASE1_TEST_REQUIREMENT_COLUMNS: dict[str, str] = {
    "required_capability": "VARCHAR(64)",
    "source_rule_ids": "JSON",
    "reasoning_trace": "JSON",
    "safety_class": "VARCHAR(32)",
    "authorization_requirement": "VARCHAR(32)",
    "credential_requirement": "VARCHAR(32)",
}


def apply_phase1_test_requirement_columns(connection: Connection) -> None:
    inspector = inspect(connection)
    if "test_requirements" not in inspector.get_table_names():
        return
    existing = {col["name"] for col in inspector.get_columns("test_requirements")}
    dialect = connection.dialect.name
    for name, col_type in _PHASE1_TEST_REQUIREMENT_COLUMNS.items():
        if name in existing:
            continue
        if dialect == "sqlite":
            ddl_type = "TEXT" if "JSON" in col_type else col_type
            connection.execute(text(f"ALTER TABLE test_requirements ADD COLUMN {name} {ddl_type}"))
        else:
            connection.execute(text(f"ALTER TABLE test_requirements ADD COLUMN {name} {col_type}"))


_PHASE2_TEST_EXECUTION_COLUMNS: dict[str, str] = {
    "selected_provider_id": "VARCHAR(128)",
}


def _add_columns(
    connection: Connection,
    table: str,
    columns: dict[str, str],
) -> None:
    inspector = inspect(connection)
    if table not in inspector.get_table_names():
        return
    existing = {col["name"] for col in inspector.get_columns(table)}
    dialect = connection.dialect.name
    for name, col_type in columns.items():
        if name in existing:
            continue
        if dialect == "sqlite":
            ddl_type = "TEXT" if "JSON" in col_type else col_type
            connection.execute(text(f"ALTER TABLE {table} ADD COLUMN {name} {ddl_type}"))
        else:
            connection.execute(text(f"ALTER TABLE {table} ADD COLUMN {name} {col_type}"))


def apply_phase2_test_execution_columns(connection: Connection) -> None:
    _add_columns(connection, "test_executions", _PHASE2_TEST_EXECUTION_COLUMNS)


def apply_phase2_provider_selection_decisions(connection: Connection) -> None:
    inspector = inspect(connection)
    if "provider_selection_decisions" in inspector.get_table_names():
        return
    dialect = connection.dialect.name
    if dialect == "sqlite":
        connection.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS provider_selection_decisions (
                    id TEXT PRIMARY KEY,
                    scan_id TEXT NOT NULL,
                    test_plan_id TEXT NOT NULL,
                    required_capability TEXT,
                    eligible_providers TEXT,
                    rejected_providers TEXT,
                    rejection_reasons TEXT,
                    selected_provider TEXT,
                    selection_rule VARCHAR(64) DEFAULT 'CAPABILITY_MATCH_THEN_POLICY',
                    decision_context TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(scan_id) REFERENCES scans(id),
                    FOREIGN KEY(test_plan_id) REFERENCES test_plans(id)
                )
                """
            )
        )
    else:
        connection.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS provider_selection_decisions (
                    id UUID PRIMARY KEY,
                    scan_id UUID NOT NULL REFERENCES scans(id),
                    test_plan_id UUID NOT NULL REFERENCES test_plans(id),
                    required_capability VARCHAR(64),
                    eligible_providers JSON,
                    rejected_providers JSON,
                    rejection_reasons JSON,
                    selected_provider VARCHAR(128),
                    selection_rule VARCHAR(64) DEFAULT 'CAPABILITY_MATCH_THEN_POLICY',
                    decision_context JSON,
                    created_at TIMESTAMPTZ DEFAULT NOW()
                )
                """
            )
        )


_PHASE3_TEST_EXECUTION_COLUMNS: dict[str, str] = {
    "executed_capability": "VARCHAR(64)",
    "provider_selection_decision_id": "TEXT",
    "normalizer_version": "VARCHAR(16)",
    "raw_result_reference": "VARCHAR(128)",
}


def apply_phase3_columns(connection: Connection) -> None:
    _add_columns(connection, "test_executions", _PHASE3_TEST_EXECUTION_COLUMNS)


_PHASE4_HYPOTHESIS_COLUMNS: dict[str, str] = {
    "uniqueness_key": "VARCHAR(64)",
    "scope_dimensions": "JSON",
    "explanation_data": "JSON",
}

_PHASE4_TEST_REQUIREMENT_COLUMNS: dict[str, str] = {
    "uniqueness_key": "VARCHAR(64)",
    "source_event_ids": "JSON",
    "source_hypothesis_ids": "JSON",
    "source_coverage_gap_ids": "JSON",
    "source_change_event_ids": "JSON",
}


def apply_phase4_columns(connection: Connection) -> None:
    _add_columns(connection, "hypotheses", _PHASE4_HYPOTHESIS_COLUMNS)
    _add_columns(connection, "test_requirements", _PHASE4_TEST_REQUIREMENT_COLUMNS)


_PHASE5_COMPLETION_COLUMNS: dict[str, str] = {
    "job_id": "VARCHAR(64)",
    "reason_codes": "JSON",
    "pending_work_summary": "JSON",
    "bound_reached": "VARCHAR(64)",
    "evaluation_version": "VARCHAR(32)",
}


def apply_phase5_columns(connection: Connection) -> None:
    _add_columns(connection, "assessment_completion_records", _PHASE5_COMPLETION_COLUMNS)


def apply_phase6_completion_history(connection: Connection) -> None:
    inspector = inspect(connection)
    if "assessment_completion_history" in inspector.get_table_names():
        return
    dialect = connection.dialect.name
    if dialect == "sqlite":
        connection.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS assessment_completion_history (
                    id TEXT PRIMARY KEY,
                    scan_id TEXT NOT NULL,
                    job_id VARCHAR(64),
                    previous_status VARCHAR(32),
                    new_status VARCHAR(32) NOT NULL,
                    reason_codes TEXT,
                    pending_work_summary TEXT,
                    accepted_gaps TEXT,
                    bound_reached VARCHAR(64),
                    evaluation_version VARCHAR(32) DEFAULT '1.0',
                    triggered_by VARCHAR(64) DEFAULT 'system',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(scan_id) REFERENCES scans(id)
                )
                """
            )
        )
        connection.execute(
            text(
                "CREATE INDEX IF NOT EXISTS ix_assessment_completion_history_scan_id "
                "ON assessment_completion_history (scan_id)"
            )
        )
    else:
        connection.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS assessment_completion_history (
                    id UUID PRIMARY KEY,
                    scan_id UUID NOT NULL REFERENCES scans(id),
                    job_id VARCHAR(64),
                    previous_status VARCHAR(32),
                    new_status VARCHAR(32) NOT NULL,
                    reason_codes JSON,
                    pending_work_summary JSON,
                    accepted_gaps JSON,
                    bound_reached VARCHAR(64),
                    evaluation_version VARCHAR(32) DEFAULT '1.0',
                    triggered_by VARCHAR(64) DEFAULT 'system',
                    created_at TIMESTAMPTZ DEFAULT NOW()
                )
                """
            )
        )
        connection.execute(
            text(
                "CREATE INDEX IF NOT EXISTS ix_assessment_completion_history_scan_id "
                "ON assessment_completion_history (scan_id)"
            )
        )


_PHASE7_TEST_REQUIREMENT_COLUMNS: dict[str, str] = {
    "scope_granularity": "VARCHAR(32)",
    "scope_dimensions": "JSON",
    "is_legacy_merged": "BOOLEAN",
}

_PHASE7_COMPLETION_COLUMNS: dict[str, str] = {
    "latest_transition_at": "TIMESTAMP",
    "latest_transition_id": "TEXT",
    "latest_transition_summary": "JSON",
}

_PHASE7_HISTORY_COLUMNS: dict[str, str] = {
    "transition_fingerprint": "VARCHAR(64)",
    "report_snapshot_id": "TEXT",
}


def apply_phase7_columns(connection: Connection) -> None:
    _add_columns(connection, "test_requirements", _PHASE7_TEST_REQUIREMENT_COLUMNS)
    _add_columns(connection, "assessment_completion_records", _PHASE7_COMPLETION_COLUMNS)
    _add_columns(connection, "assessment_completion_history", _PHASE7_HISTORY_COLUMNS)
    apply_phase7_report_snapshots(connection)


def apply_phase7_report_snapshots(connection: Connection) -> None:
    inspector = inspect(connection)
    if "report_snapshots" in inspector.get_table_names():
        return
    dialect = connection.dialect.name
    if dialect == "sqlite":
        connection.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS report_snapshots (
                    id TEXT PRIMARY KEY,
                    scan_id TEXT NOT NULL,
                    report_version VARCHAR(32) NOT NULL,
                    completion_version VARCHAR(32) NOT NULL,
                    generation_version VARCHAR(32) DEFAULT 'phase7-v1',
                    content_hash VARCHAR(64) NOT NULL,
                    assessment_status VARCHAR(32),
                    job_status VARCHAR(64),
                    reason_codes TEXT,
                    bound_reached VARCHAR(64),
                    accepted_gaps_count INTEGER DEFAULT 0,
                    pending_work_count INTEGER DEFAULT 0,
                    generated_by VARCHAR(64) DEFAULT 'system',
                    content_summary TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(scan_id) REFERENCES scans(id)
                )
                """
            )
        )
        connection.execute(
            text(
                "CREATE INDEX IF NOT EXISTS ix_report_snapshots_scan_id "
                "ON report_snapshots (scan_id)"
            )
        )
    else:
        connection.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS report_snapshots (
                    id UUID PRIMARY KEY,
                    scan_id UUID NOT NULL REFERENCES scans(id),
                    report_version VARCHAR(32) NOT NULL,
                    completion_version VARCHAR(32) NOT NULL,
                    generation_version VARCHAR(32) DEFAULT 'phase7-v1',
                    content_hash VARCHAR(64) NOT NULL,
                    assessment_status VARCHAR(32),
                    job_status VARCHAR(64),
                    reason_codes JSON,
                    bound_reached VARCHAR(64),
                    accepted_gaps_count INTEGER DEFAULT 0,
                    pending_work_count INTEGER DEFAULT 0,
                    generated_by VARCHAR(64) DEFAULT 'system',
                    content_summary JSON,
                    created_at TIMESTAMPTZ DEFAULT NOW()
                )
                """
            )
        )
        connection.execute(
            text(
                "CREATE INDEX IF NOT EXISTS ix_report_snapshots_scan_id "
                "ON report_snapshots (scan_id)"
            )
        )


def apply_all_patches(connection: Connection) -> None:
    apply_phase1_test_requirement_columns(connection)
    apply_phase2_test_execution_columns(connection)
    apply_phase2_provider_selection_decisions(connection)
    apply_phase3_columns(connection)
    apply_phase4_columns(connection)
    apply_phase5_columns(connection)
    apply_phase6_completion_history(connection)
    apply_phase7_columns(connection)
    apply_phase8_columns(connection)
    apply_phase9_columns(connection)


_PHASE8_SNAPSHOT_COLUMNS: dict[str, str] = {
    "artifact_reference": "VARCHAR(512)",
    "artifact_hash": "VARCHAR(64)",
    "artifact_content_type": "VARCHAR(64)",
    "artifact_size": "INTEGER",
    "artifact_storage_backend": "VARCHAR(32)",
    "replayable": "BOOLEAN",
    "live_hash_at_generation": "VARCHAR(64)",
    "stale": "BOOLEAN",
}

_PHASE8_TESTPLAN_COLUMNS: dict[str, str] = {
    "uniqueness_key": "VARCHAR(64)",
    "source_requirement_uniqueness_keys": "JSON",
    "planning_fingerprint": "VARCHAR(64)",
    "plan_granularity": "VARCHAR(32)",
}


def apply_phase8_columns(connection: Connection) -> None:
    _add_columns(connection, "report_snapshots", _PHASE8_SNAPSHOT_COLUMNS)
    _add_columns(connection, "test_plans", _PHASE8_TESTPLAN_COLUMNS)


_PHASE9_SNAPSHOT_COLUMNS: dict[str, str] = {
    "fingerprint_hash": "VARCHAR(64)",
    "artifact_retention_status": "VARCHAR(32)",
    "integrity_status": "VARCHAR(32)",
}

_PHASE9_TESTPLAN_COLUMNS: dict[str, str] = {
    "split_from_plan_id": "TEXT",
    "split_reason_codes": "JSON",
    "split_policy_version": "VARCHAR(32)",
}


def apply_phase9_columns(connection: Connection) -> None:
    _add_columns(connection, "report_snapshots", _PHASE9_SNAPSHOT_COLUMNS)
    _add_columns(connection, "test_plans", _PHASE9_TESTPLAN_COLUMNS)
