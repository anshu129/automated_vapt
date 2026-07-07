"""Phase 2 schema patch compatibility."""

from sqlalchemy import create_engine, inspect, text

from vapt_platform.db.schema_patches import (
    apply_phase2_provider_selection_decisions,
    apply_phase2_test_execution_columns,
)


def test_phase2_schema_patches_are_additive() -> None:
    engine = create_engine("sqlite:///:memory:")
    with engine.begin() as conn:
        conn.execute(
            text(
                """
                CREATE TABLE test_executions (
                    id TEXT PRIMARY KEY,
                    test_plan_id TEXT NOT NULL,
                    status TEXT NOT NULL
                )
                """
            )
        )
        apply_phase2_test_execution_columns(conn)
        cols = {c["name"] for c in inspect(conn).get_columns("test_executions")}
        assert "selected_provider_id" in cols

        conn.execute(text("CREATE TABLE scans (id TEXT PRIMARY KEY)"))
        conn.execute(text("CREATE TABLE test_plans (id TEXT PRIMARY KEY)"))
        apply_phase2_provider_selection_decisions(conn)
        tables = inspect(conn).get_table_names()
        assert "provider_selection_decisions" in tables
