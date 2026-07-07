"""Launch the VAPT Platform web UI + API with a real-tool, long-scan profile.

Usage (PowerShell):
    python serve.py

Environment overrides (optional):
    HOST, PORT            bind address (default 127.0.0.1:8000)
    VAPT_DB               sqlite/postgres URL (default local sqlite file)
    AI_ENABLED=true       enable Mistral advisory (also set MISTRAL_API_KEY)
    MISTRAL_API_KEY=...   Mistral key (without it, a deterministic advisory is used)
    USE_FAKE_FALLBACK=true  allow synthetic data when a real tool is missing

Then open http://127.0.0.1:8000/ in a browser.
"""

from __future__ import annotations

import os
from pathlib import Path


def _default(key: str, value: str) -> None:
    os.environ.setdefault(key, value)


def configure_env() -> None:
    db = os.environ.get("VAPT_DB", "sqlite+aiosqlite:///./vapt_ui.db")
    _default("DATABASE_URL", db)
    _default("DATABASE_URL_SYNC", db)

    # Prefer Go-installed security tools (httpx, dnsx, nuclei, katana, ...).
    go_bin = str(Path(os.environ.get("USERPROFILE", str(Path.home()))) / "go" / "bin")
    _default("TOOL_SEARCH_PATHS", go_bin)

    # Real tools, honest results by default; scans run to natural completion.
    _default("USE_FAKE_FALLBACK", "false")
    _default("SEED_ON_STARTUP", "true")
    _default("SCAN_START_INLINE_EXECUTION", "true")

    # Generous budget so scans are not cut off early ("no time-limit boundation").
    _default("TOOL_TIMEOUT_SECONDS", "300")
    _default("SCAN_PIPELINE_MAX_ITERATIONS", "40")
    _default("SCAN_PIPELINE_MAX_TASKS", "200")


def main() -> None:
    configure_env()
    import uvicorn

    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8000"))
    print(f"VAPT Platform UI -> http://{host}:{port}/")
    print(f"  DATABASE_URL={os.environ['DATABASE_URL']}")
    print(f"  USE_FAKE_FALLBACK={os.environ['USE_FAKE_FALLBACK']}  AI_ENABLED={os.environ.get('AI_ENABLED', 'false')}")
    uvicorn.run("vapt_platform.main:app", host=host, port=port, reload=False)


if __name__ == "__main__":
    main()
