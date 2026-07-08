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

    # Security tool locations. Every directory below was verified to contain at
    # least one installed tool binary; only directories that still exist on disk
    # are included so the list stays portable across machines.
    home = Path(os.environ.get("USERPROFILE", str(Path.home())))
    candidate_tool_dirs = [
        home / "go" / "bin",
        home / "anaconda3" / "Scripts",
        home / "Downloads" / "amass_windows_amd64" / "amass_windows_amd64",
        home / "Downloads" / "dnsx_1.2.3_windows_amd64",
        home / "Downloads" / "ffuf_2.1.0_windows_amd64",
        home / "Downloads" / "gitleaks_8.30.1_windows_x64",
        home / "Downloads" / "katana_1.6.1_windows_amd64",
        home / "Downloads" / "trufflehog_3.95.8_windows_amd64",
        Path(r"C:\ProgramData\chocolatey\bin"),
        Path(r"C:\Program Files (x86)\Nmap"),
        Path(r"C:\WINDOWS\system32"),
    ]
    existing_tool_dirs = [str(p) for p in candidate_tool_dirs if p.is_dir()]
    _default("TOOL_SEARCH_PATHS", os.pathsep.join(existing_tool_dirs))

    seclists = Path("SecLists-master")
    if seclists.is_dir():
        _default("SECLISTS_ROOT", str(seclists.resolve()))

    # Real tools, honest results by default; scans run to natural completion.
    _default("USE_FAKE_FALLBACK", "false")
    _default("SEED_ON_STARTUP", "true")
    _default("SCAN_START_INLINE_EXECUTION", "true")

    # Per-tool wall-clock cap. Kept modest so a single brute-force tool (ffuf,
    # gobuster, feroxbuster) cannot stall the inline recon pipeline for minutes
    # on auth-gated or low-yield targets. Raise for large authorized engagements.
    _default("TOOL_TIMEOUT_SECONDS", "60")
    _default("SCAN_PIPELINE_MAX_ITERATIONS", "25")
    _default("SCAN_PIPELINE_MAX_TASKS", "120")
    _default("RECON_COMMIT_PER_TASK", "true")
    _default("RECON_TOOL_LOGGING", "true")


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
