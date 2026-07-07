"""Thin MCP client helpers for external validation servers (Burp SSE, sqlmap stdio)."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import timedelta
from typing import Any

import httpx

_MCP_IMPORT_ERROR: str | None = None
try:
    from mcp.client.session import ClientSession
    from mcp.client.sse import sse_client
    from mcp.client.stdio import StdioServerParameters, stdio_client
except ImportError as exc:
    ClientSession = None  # type: ignore[misc, assignment]
    sse_client = None  # type: ignore[misc, assignment]
    stdio_client = None  # type: ignore[misc, assignment]
    StdioServerParameters = None  # type: ignore[misc, assignment]
    _MCP_IMPORT_ERROR = str(exc)


def mcp_sdk_available() -> bool:
    return ClientSession is not None


def mcp_sdk_error() -> str | None:
    return _MCP_IMPORT_ERROR


def text_from_tool_result(result: Any) -> str:
    """Extract human-readable text from an MCP CallToolResult."""
    if result is None:
        return ""
    chunks: list[str] = []
    for block in getattr(result, "content", []) or []:
        text = getattr(block, "text", None)
        if text:
            chunks.append(text)
    if chunks:
        return "\n".join(chunks)
    structured = getattr(result, "structuredContent", None)
    if structured is not None:
        return json.dumps(structured, default=str)
    return ""


async def sse_server_reachable(sse_url: str, timeout_seconds: float = 2.0) -> bool:
    """Best-effort check that an SSE MCP host responds (Burp default :9876)."""
    base = sse_url.rstrip("/")
    if base.endswith("/sse"):
        base = base[: -len("/sse")]
    try:
        async with httpx.AsyncClient(timeout=timeout_seconds) as client:
            response = await client.get(base)
            return response.status_code < 500
    except httpx.HTTPError:
        return False


@asynccontextmanager
async def open_sse_session(
    sse_url: str,
    read_timeout_seconds: float = 120.0,
) -> AsyncIterator[ClientSession]:
    if not mcp_sdk_available():
        raise RuntimeError(_MCP_IMPORT_ERROR or "MCP SDK is not installed")
    async with sse_client(sse_url) as (read_stream, write_stream), ClientSession(
        read_stream,
        write_stream,
        read_timeout_seconds=timedelta(seconds=read_timeout_seconds),
    ) as session:
        await session.initialize()
        yield session


@asynccontextmanager
async def open_stdio_session(
    command: str,
    args: list[str],
    read_timeout_seconds: float = 300.0,
    env: dict[str, str] | None = None,
) -> AsyncIterator[ClientSession]:
    if not mcp_sdk_available():
        raise RuntimeError(_MCP_IMPORT_ERROR or "MCP SDK is not installed")
    params = StdioServerParameters(command=command, args=args, env=env)
    async with stdio_client(params) as (read_stream, write_stream), ClientSession(
        read_stream,
        write_stream,
        read_timeout_seconds=timedelta(seconds=read_timeout_seconds),
    ) as session:
        await session.initialize()
        yield session


async def call_sse_tool(
    sse_url: str,
    tool_name: str,
    arguments: dict[str, Any],
    *,
    read_timeout_seconds: float = 120.0,
) -> tuple[str, str | None]:
    try:
        async with open_sse_session(sse_url, read_timeout_seconds) as session:
            result = await session.call_tool(tool_name, arguments)
            if getattr(result, "isError", False):
                return "", text_from_tool_result(result) or f"{tool_name} returned an error"
            return text_from_tool_result(result), None
    except Exception as exc:
        return "", str(exc)[:500]


async def call_stdio_tool(
    command: str,
    args: list[str],
    tool_name: str,
    arguments: dict[str, Any],
    *,
    read_timeout_seconds: float = 300.0,
    env: dict[str, str] | None = None,
) -> tuple[str, str | None]:
    try:
        async with open_stdio_session(command, args, read_timeout_seconds, env=env) as session:
            result = await session.call_tool(tool_name, arguments)
            if getattr(result, "isError", False):
                return "", text_from_tool_result(result) or f"{tool_name} returned an error"
            return text_from_tool_result(result), None
    except Exception as exc:
        return "", str(exc)[:500]
