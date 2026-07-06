"""Typer CLI."""

import asyncio
import json
from datetime import datetime
from ipaddress import ip_address
from pathlib import Path

import httpx
import typer

from vapt_platform.tools.manifest import load_tool_manifests, resolve_tool_binary

app = typer.Typer(name="vapt", help="VAPT Platform CLI")

API_BASE = typer.Option("http://localhost:8000/api/v1", envvar="VAPT_API_URL")


def _run(coro):  # type: ignore[no-untyped-def]
    return asyncio.get_event_loop().run_until_complete(coro)


def _get(api_url: str, path: str, timeout: float | None = 10.0) -> httpx.Response:
    try:
        return httpx.get(f"{api_url}{path}", timeout=timeout)
    except httpx.ConnectError as e:
        raise typer.BadParameter(
            f"API is not reachable at {api_url}. Start it with: "
            "C:\\Users\\deepanshu\\anaconda3\\python.exe -m uvicorn "
            "vapt_platform.main:app --reload"
        ) from e
    except httpx.TimeoutException as e:
        wait = "without a client timeout" if timeout is None else f"after {timeout:g} seconds"
        raise typer.BadParameter(
            f"API request to {api_url}{path} timed out {wait}."
        ) from e


def _post(
    api_url: str,
    path: str,
    timeout: float | None = 10.0,
    **kwargs: object,
) -> httpx.Response:
    try:
        return httpx.post(f"{api_url}{path}", timeout=timeout, **kwargs)
    except httpx.ConnectError as e:
        raise typer.BadParameter(
            f"API is not reachable at {api_url}. Start it with: "
            "C:\\Users\\deepanshu\\anaconda3\\python.exe -m uvicorn "
            "vapt_platform.main:app --reload"
        ) from e
    except httpx.TimeoutException as e:
        wait = "without a client timeout" if timeout is None else f"after {timeout:g} seconds"
        raise typer.BadParameter(
            f"API request to {api_url}{path} timed out {wait}."
        ) from e


def _raise_for_status(response: httpx.Response) -> None:
    try:
        response.raise_for_status()
    except httpx.HTTPStatusError as e:
        body = response.text.strip()
        if len(body) > 500:
            body = f"{body[:500]}..."
        detail = f" API response: {body}" if body else ""
        raise typer.BadParameter(
            f"API returned HTTP {response.status_code} for {response.request.url}.{detail}"
        ) from e


def _emit_tool_response(data: dict[str, object], output_file: Path | None) -> None:
    if output_file:
        written = _write_tool_output_file(data, output_file)
        typer.echo(f"Saved verbose tool output to: {written}")
        typer.echo(json.dumps(_compact_tool_response(data), indent=2))
        return
    typer.echo(json.dumps(data, indent=2))


def _compact_tool_response(data: dict[str, object]) -> dict[str, object]:
    compact = {
        key: value
        for key, value in data.items()
        if key not in {"items"}
    }
    items = data.get("items")
    if not isinstance(items, list):
        items = []
    compact["items"] = [
        {
            key: item.get(key)
            for key in (
                "task_id",
                "provider",
                "capability",
                "status",
                "exit_code",
                "error_summary",
                "duration_seconds",
                "timeout_seconds",
                "command",
                "stdout_preview",
                "stderr_preview",
            )
            if key in item
        }
        for item in items
        if isinstance(item, dict)
    ]
    return compact


def _write_tool_output_file(data: dict[str, object], output_file: Path) -> Path:
    output_file.parent.mkdir(parents=True, exist_ok=True)
    resolved = output_file.resolve()
    lines = [
        "VAPT Tool Run Output",
        f"generated_at: {datetime.now().isoformat(timespec='seconds')}",
        f"scan_id: {data.get('id')}",
        f"status: {data.get('status')}",
        f"executed: {data.get('executed')}",
        f"remaining_ready: {data.get('remaining_ready')}",
        "",
        "target:",
        json.dumps(data.get("target"), indent=2),
        "",
        "requested_tools:",
        json.dumps(data.get("requested_tools"), indent=2),
        "",
        "selected_tools:",
        json.dumps(data.get("selected_tools"), indent=2),
        "",
    ]

    items = data.get("items")
    if not isinstance(items, list):
        items = []
    for index, item in enumerate(items, start=1):
        if not isinstance(item, dict):
            continue
        lines.extend(
            [
                "=" * 100,
                f"tool_index: {index}",
                f"provider: {item.get('provider')}",
                f"capability: {item.get('capability')}",
                f"task_id: {item.get('task_id')}",
                f"status: {item.get('status')}",
                f"exit_code: {item.get('exit_code')}",
                f"duration_seconds: {item.get('duration_seconds')}",
                f"timeout_seconds: {item.get('timeout_seconds')}",
                f"binary: {item.get('binary')}",
                f"command: {item.get('command')}",
                f"error_summary: {item.get('error_summary')}",
                f"stdout_bytes: {len(str(item.get('stdout') or item.get('stdout_preview') or ''))}",
                f"stderr_bytes: {len(str(item.get('stderr') or item.get('stderr_preview') or ''))}",
                f"analysis_note: {_tool_item_note(item)}",
                "",
                "--- STDERR ---",
                str(item.get("stderr") or item.get("stderr_preview") or ""),
                "",
                "--- STDOUT ---",
                str(item.get("stdout") or item.get("stdout_preview") or ""),
                "",
            ]
        )
    resolved.write_text("\n".join(lines), encoding="utf-8")
    return resolved


def _tool_item_note(item: dict[str, object]) -> str:
    provider = str(item.get("provider") or "").lower()
    stdout = str(item.get("stdout") or item.get("stdout_preview") or "")
    stderr = str(item.get("stderr") or item.get("stderr_preview") or "")
    exit_code = item.get("exit_code")
    if exit_code == 124:
        return "Tool was stopped by the configured subprocess timeout."
    if provider == "amass" and "plugin started" in stderr.lower() and not stdout.strip():
        return "Amass emitted lifecycle/plugin logs on stderr but no discovered hostnames on stdout."
    if provider in {"subfinder", "assetfinder", "amass"} and not stdout.strip():
        return "No subdomain/hostname lines were emitted on stdout."
    if stdout.strip():
        return "Tool emitted stdout; review the STDOUT section below."
    if stderr.strip():
        return "Tool emitted stderr only; review the STDERR section below."
    return "No captured stdout or stderr."


@app.command("project-create")
def project_create(name: str, api_url: str = API_BASE) -> None:
    """Create a new project."""
    r = _post(api_url, "/projects", json={"name": name})
    _raise_for_status(r)
    typer.echo(json.dumps(r.json(), indent=2))


@app.command("scan-create")
def scan_create(
    project_id: str,
    name: str,
    domain: str | None = typer.Option(None, help="Root domain for scope"),
    hostname: str | None = typer.Option(None, help="Single hostname for scope"),
    url: str | None = typer.Option(None, help="URL prefix for scope"),
    ip: str | None = typer.Option(None, help="Single IP address for scope"),
    target: str | None = typer.Option(None, help="Infer scope type from target"),
    api_url: str = API_BASE,
) -> None:
    """Create a scan with domain, host, URL, or IP scope."""
    scope_rules = []
    if target:
        scope_rules.append(_infer_scope_rule(target))
    if domain:
        scope_rules.append({"rule_type": "ROOT_DOMAIN", "pattern": domain, "priority": 100})
    if hostname:
        scope_rules.append({"rule_type": "HOSTNAME", "pattern": hostname, "priority": 100})
    if url:
        scope_rules.append({"rule_type": "URL_PREFIX", "pattern": _normalize_url(url), "priority": 100})
    if ip:
        scope_rules.append({"rule_type": "IP", "pattern": ip, "priority": 100})
    if not scope_rules:
        raise typer.BadParameter("Provide one of --target, --domain, --hostname, --url, or --ip")
    body = {
        "name": name,
        "scope_rules": scope_rules,
    }
    r = _post(api_url, "/scans", timeout=60.0, params={"project_id": project_id}, json=body)
    _raise_for_status(r)
    typer.echo(json.dumps(r.json(), indent=2))


@app.command("scan-start")
def scan_start(scan_id: str, api_url: str = API_BASE) -> None:
    """Start scan pipeline."""
    r = _post(api_url, f"/scans/{scan_id}/start", timeout=120.0)
    _raise_for_status(r)
    typer.echo(json.dumps(r.json(), indent=2))


@app.command("scan-run-ready")
def scan_run_ready(
    scan_id: str,
    limit: int = typer.Option(1, help="Maximum READY tasks to execute now. Use 0 for all matching tasks."),
    target: str | None = typer.Option(None, help="Only run tasks whose target contains this text"),
    tool: str | None = typer.Option(None, help="Only run queued tasks for these provider names, comma-separated"),
    username: str | None = typer.Option(None, help="Username to attach to selected HTTP tasks"),
    password: str | None = typer.Option(None, help="Password to attach to selected HTTP tasks"),
    timeout: int | None = typer.Option(0, help="Per-tool timeout seconds. Default 0 means no subprocess timeout."),
    verbose: bool = typer.Option(False, help="Include full captured stdout/stderr in the response"),
    output_file: Path | None = typer.Option(
        None,
        "--output-file",
        "-o",
        help="Save verbose tool output to this .txt file",
    ),
    api_url: str = API_BASE,
) -> None:
    """Run a bounded number of queued scan tasks."""
    if limit < 0 or limit > 1000:
        raise typer.BadParameter("--limit must be between 0 and 1000")
    params: dict[str, object] = {"limit": limit}
    if target:
        params["target"] = target
    if tool:
        params["tool"] = tool
    if username is not None:
        params["username"] = username
    if password is not None:
        params["password"] = password
    if timeout is not None:
        params["timeout"] = timeout
    if verbose or output_file:
        params["verbose"] = True
    request_timeout = None if timeout == 0 else max(30.0, float(max(limit, 1) * max(timeout or 30, 1) + 10))
    r = _post(
        api_url,
        f"/scans/{scan_id}/run-ready",
        params=params,
        timeout=request_timeout,
    )
    _raise_for_status(r)
    _emit_tool_response(r.json(), output_file)


@app.command("scan-run-tools")
def scan_run_tools(
    scan_id: str,
    tools: str = typer.Argument(..., help="Comma-separated tool names, e.g. httpx,nmap, or all"),
    target: str = typer.Option(..., help="URL, hostname, or IP to run tools against"),
    username: str | None = typer.Option(None, help="Username for HTTP Basic auth"),
    password: str | None = typer.Option(None, help="Password for HTTP Basic auth"),
    timeout: int | None = typer.Option(0, help="Per-tool timeout seconds. Default 0 means no subprocess timeout."),
    verbose: bool = typer.Option(False, help="Include full captured stdout/stderr in the response"),
    output_file: Path | None = typer.Option(
        None,
        "--output-file",
        "-o",
        help="Save verbose tool output to this .txt file",
    ),
    api_url: str = API_BASE,
) -> None:
    """Create and run scan tasks for specific tools immediately."""
    if timeout is not None and timeout < 0:
        raise typer.BadParameter("--timeout must be 0 or greater")
    params: dict[str, object] = {
        "tools": tools,
        "target": target,
    }
    if username is not None:
        params["username"] = username
    if password is not None:
        params["password"] = password
    if timeout is not None:
        params["timeout"] = timeout
    if verbose or output_file:
        params["verbose"] = True
    tool_count = len([item for item in tools.split(",") if item.strip()])
    request_timeout = None if timeout == 0 else max(
        60.0,
        float(max(tool_count, 1) * max(timeout or 60, 1) + 10),
    )
    r = _post(
        api_url,
        f"/scans/{scan_id}/run-tools",
        params=params,
        timeout=request_timeout,
    )
    _raise_for_status(r)
    _emit_tool_response(r.json(), output_file)


@app.command("scan-status")
def scan_status(scan_id: str, api_url: str = API_BASE) -> None:
    """Get scan status."""
    r = _get(api_url, f"/scans/{scan_id}")
    _raise_for_status(r)
    typer.echo(json.dumps(r.json(), indent=2))


@app.command("asset-list")
def asset_list(scan_id: str, api_url: str = API_BASE) -> None:
    """List scan assets."""
    r = _get(api_url, f"/scans/{scan_id}/assets")
    _raise_for_status(r)
    typer.echo(json.dumps(r.json(), indent=2))


@app.command("capabilities-list")
def capabilities_list(api_url: str = API_BASE) -> None:
    """List registered capabilities."""
    r = _get(api_url, "/capabilities")
    _raise_for_status(r)
    typer.echo(json.dumps(r.json(), indent=2))


@app.command("tools-readiness")
def tools_readiness(api_url: str = API_BASE) -> None:
    """Show which configured CLI tools are visible to the API process."""
    r = _get(api_url, "/tools/readiness")
    _raise_for_status(r)
    typer.echo(json.dumps(r.json(), indent=2))


@app.command("tools-readiness-local")
def tools_readiness_local() -> None:
    """Show which configured CLI tools are visible in this shell."""
    items = []
    for name, spec in sorted(load_tool_manifests().items()):
        source = resolve_tool_binary(spec.binary)
        items.append(
            {
                "tool": name,
                "binary": spec.binary,
                "available": source is not None,
                "source": source,
                "enabled": spec.enabled,
                "capabilities": spec.capabilities,
            }
        )
    typer.echo(
        json.dumps(
            {
                "available": sum(1 for item in items if item["available"]),
                "total": len(items),
                "items": items,
            },
            indent=2,
        )
    )


@app.command("scan-report")
def scan_report(scan_id: str, api_url: str = API_BASE) -> None:
    """Get the first JSON assessment report for a scan."""
    r = _get(api_url, f"/scans/{scan_id}/report")
    _raise_for_status(r)
    typer.echo(json.dumps(r.json(), indent=2))


def _infer_scope_rule(value: str) -> dict[str, object]:
    target = value.strip()
    if target.startswith(("http://", "https://")):
        return {"rule_type": "URL_PREFIX", "pattern": _normalize_url(target), "priority": 100}
    try:
        ip_address(target)
        return {"rule_type": "IP", "pattern": target, "priority": 100}
    except ValueError:
        pass
    if "/" in target:
        return {"rule_type": "URL_PREFIX", "pattern": _normalize_url(target), "priority": 100}
    if len(target.split(".")) > 2:
        return {"rule_type": "HOSTNAME", "pattern": target.lower(), "priority": 100}
    return {"rule_type": "ROOT_DOMAIN", "pattern": target.lower(), "priority": 100}


def _normalize_url(value: str) -> str:
    if not value.startswith(("http://", "https://")):
        value = f"https://{value}"
    return value.rstrip("/")


if __name__ == "__main__":
    app()
