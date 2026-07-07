"""CLI assessment bundle export."""

import json
import uuid
from pathlib import Path

import httpx

from vapt_platform.cli import main as cli_main


def _response(method: str, url: str, payload: dict[str, object]) -> httpx.Response:
    request = httpx.Request(method, url)
    return httpx.Response(200, request=request, json=payload)


def test_export_scan_bundle_writes_all_artifacts(monkeypatch) -> None:
    def fake_post(api_url: str, path: str, **kwargs: object) -> httpx.Response:
        return _response("POST", f"{api_url}{path}", {"created": 3, "items": []})

    def fake_get(api_url: str, path: str, **kwargs: object) -> httpx.Response:
        return _response("GET", f"{api_url}{path}", {"path": path, "items": []})

    monkeypatch.setattr(cli_main, "_post", fake_post)
    monkeypatch.setattr(cli_main, "_get", fake_get)

    output_dir = Path("reports") / f"_pytest_export_{uuid.uuid4().hex}"
    try:
        manifest = cli_main._export_scan_bundle(
            "http://localhost:8000/api/v1",
            "scan-123",
            output_dir,
            generate_plans=True,
            execute_automated=True,
            enrich_with_ai=True,
        )

        files = manifest["files"]
        assert isinstance(files, dict)
        assert set(files) == {
            "generated_plans",
            "automated_executions",
            "ai_advisory",
            "scan",
            "assets",
            "relationships",
            "events",
            "tasks",
            "surface_coverage",
            "vulnerability_catalog",
            "vulnerability_coverage",
            "vulnerability_applicability",
            "auth_coverage",
            "role_coverage",
            "test_matrix",
            "test_plans",
            "test_executions",
            "hypotheses",
            "validation_backlog",
            "validation_results",
            "evidence_packages",
            "evidence_links",
            "ai_enrichments",
            "verdicts",
            "confirmed_findings",
            "completion_status",
            "discovery_gain",
            "report",
        }
        assert all(Path(path).is_file() for path in files.values())

        manifest_file = Path(str(manifest["manifest_file"]))
        assert manifest_file.is_file()
        stored_manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
        assert stored_manifest["scan_id"] == "scan-123"
        assert stored_manifest["files"]["relationships"].endswith("relationships.json")
    finally:
        if output_dir.exists():
            for file_path in output_dir.iterdir():
                if file_path.is_file():
                    file_path.unlink()
            output_dir.rmdir()


def test_safe_filename_normalizes_target() -> None:
    assert cli_main._safe_filename("https://API.Example.com/a?b=1") == (
        "https-api.example.com-a-b-1"
    )
