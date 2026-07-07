"""Authorized single-host assessment runner (real tools, no fake fallback).

Scope is restricted to the single authorized hostname. Fake providers are
disabled so the report contains ONLY observations from real installed tools;
any missing tool simply contributes nothing (never fabricated data).
"""

import asyncio
import json
import os
import sys
from pathlib import Path

TARGET_HOST = "sahaj.sakra.co.in"
TARGET_URL = "https://sahaj.sakra.co.in/"
OUT = Path("reports/sahaj")

# Prefer ProjectDiscovery / go binaries (fixes httpx shadowed by anaconda).
GO_BIN = str(Path(os.environ["USERPROFILE"]) / "go" / "bin")
os.environ["TOOL_SEARCH_PATHS"] = GO_BIN
os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./vapt_sahaj.db"
os.environ["DATABASE_URL_SYNC"] = "sqlite+aiosqlite:///./vapt_sahaj.db"
os.environ["SCAN_START_INLINE_EXECUTION"] = "true"
os.environ["TOOL_TIMEOUT_SECONDS"] = "300"
os.environ["SCAN_PIPELINE_MAX_ITERATIONS"] = "25"
os.environ["SCAN_PIPELINE_MAX_TASKS"] = "80"

from sqlalchemy import select  # noqa: E402

from vapt_platform.api.routes.core import (  # noqa: E402
    list_assets,
    list_confirmed_findings,
    list_hypotheses,
    list_relationships,
    scan_report,
    scan_test_matrix,
    scan_vulnerability_applicability,
    validation_backlog,
)
from vapt_platform.db.session import init_db, session_scope  # noqa: E402
from vapt_platform.db.tables.models import CapabilityProvider  # noqa: E402
from vapt_platform.engines.assessment import TestPlanner  # noqa: E402
from vapt_platform.scripts.seed import seed_data  # noqa: E402
from vapt_platform.services.core import ProjectService, ScanService  # noqa: E402


async def main() -> None:
    await init_db(os.environ["DATABASE_URL"])
    async with session_scope() as session:
        await seed_data(session)
        # Disable fake providers -> only real installed tools run.
        # Disable fake providers and tools whose dependencies are missing
        # (puredns needs massdns, which is not installed).
        disabled_missing = {"puredns", "massdns"}
        disabled = 0
        for provider in (await session.execute(select(CapabilityProvider))).scalars().all():
            if provider.provider_name.startswith("fake-") or (
                provider.provider_name in disabled_missing
            ):
                provider.enabled = False
                disabled += 1
        await session.commit()
        print(f"disabled {disabled} fake/unavailable providers; using real tools only")

        project = await ProjectService(session).create(f"Authorized VAPT - {TARGET_HOST}")
        scan = await ScanService(session).create(
            project.id,
            f"{TARGET_HOST} authorized assessment",
            [
                {"rule_type": "HOSTNAME", "pattern": TARGET_HOST, "priority": 100},
                {"rule_type": "URL_PREFIX", "pattern": TARGET_URL.rstrip("/"), "priority": 90},
            ],
        )
        await session.commit()

        print(f"starting pipeline against {TARGET_HOST} (real tools) ...")
        await ScanService(session).start(scan.id)
        await TestPlanner(session).plan_scan(scan.id)
        await session.flush()

        assets = await list_assets(scan.id, session)
        relationships = await list_relationships(scan.id, session)
        applicability = await scan_vulnerability_applicability(scan.id, state=None, session=session)
        matrix = await scan_test_matrix(scan.id, session)
        hypotheses = await list_hypotheses(scan.id, session)
        backlog = await validation_backlog(scan.id, session)
        findings = await list_confirmed_findings(scan.id, session)
        report = await scan_report(scan.id, session)

        OUT.mkdir(parents=True, exist_ok=True)
        for name, data in {
            "assets": assets,
            "relationships": relationships,
            "vulnerability_applicability": applicability,
            "test_matrix": matrix,
            "hypotheses": hypotheses,
            "validation_backlog": backlog,
            "confirmed_findings": findings,
            "report": report,
        }.items():
            (OUT / f"{name}.json").write_text(json.dumps(data, indent=2, default=str))

        print("\n=== TOOL EXECUTION (real) ===")
        for task in report.get("tasks", []):
            print(
                f"  {task.get('capability'):<32} provider={task.get('provider')}"
                f"  exit={task.get('last_exit_code')}  fake={task.get('used_fake_fallback')}"
            )
            err = task.get("last_error_summary") or task.get("stderr_preview")
            if err:
                print(f"      note: {str(err)[:160]}")

        print("\n=== ASSETS ===")
        for item in assets["items"]:
            print(f"  [{item['asset_type']:<15}] {item['display_name']}")

        print("\n=== RELATIONSHIPS ===")
        for item in relationships["items"]:
            src = item["source"]["display_name"] if item["source"] else "?"
            dst = item["target"]["display_name"] if item["target"] else "?"
            print(f"  {src} --{item['relationship_type']}--> {dst}")

        backlog_total = backlog.get("total", len(backlog.get("items", [])))
        print("\n=== VULNERABILITY SIGNAL (hypotheses / backlog) ===")
        print(f"  hypotheses: {hypotheses['total']}  backlog: {backlog_total}"
              f"  confirmed_findings: {findings['total']}")

        print("\n=== REPORT SUMMARY ===")
        print(json.dumps(report["summary"], indent=2, default=str))
        print(f"\nArtifacts written to: {OUT.resolve()}")


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
