"""Phase 8 schema migration unit tests."""

from __future__ import annotations

import sqlite3
import tempfile
from pathlib import Path

from sqlalchemy import create_engine

from vapt_platform.services.schema_compatibility_detector import SchemaCompatibilityDetector
from vapt_platform.services.sqlite_migration_helper import SqliteMigrationHelper


def _legacy_db(path: Path) -> None:
    conn = sqlite3.connect(path)
    conn.execute(
        """
        CREATE TABLE test_requirements (
            id TEXT PRIMARY KEY,
            matrix_id TEXT NOT NULL,
            vulnerability_class_id TEXT NOT NULL,
            applicability_state TEXT,
            testing_mode TEXT,
            coverage_status TEXT,
            uniqueness_key TEXT DEFAULT '',
            UNIQUE(matrix_id, vulnerability_class_id)
        )
        """
    )
    conn.execute(
        "CREATE UNIQUE INDEX uq_test_requirement_matrix_class "
        "ON test_requirements (matrix_id, vulnerability_class_id)"
    )
    conn.commit()
    conn.close()


def test_legacy_schema_detected() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        db_path = Path(tmp) / "legacy.db"
        _legacy_db(db_path)
        engine = create_engine(f"sqlite:///{db_path}")
        with engine.connect() as conn:
            report = SchemaCompatibilityDetector().inspect(conn)
        engine.dispose()
        assert report.legacy_test_requirement_constraint
        assert report.migration_required


def test_migration_rebuilds_constraint() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        db_path = Path(tmp) / "legacy.db"
        _legacy_db(db_path)
        engine = create_engine(f"sqlite:///{db_path}")
        with engine.begin() as conn:
            result = SqliteMigrationHelper().migrate_test_requirements_unique_constraint(conn)
        with engine.connect() as conn:
            report = SchemaCompatibilityDetector().inspect(conn)
        engine.dispose()
        assert result.migrated
        assert not report.legacy_test_requirement_constraint
