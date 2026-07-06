"""
Download recon tool binaries and capture -h/--help output.

Binaries land in tools/bin/; help text in config/parameters/static_help/.
"""

from __future__ import annotations

import io
import json
import platform
import shutil
import subprocess
import zipfile
from pathlib import Path
from typing import Any
from urllib.request import urlopen

import yaml

ROOT = Path(__file__).resolve().parents[1]
BIN_DIR = ROOT / "tools" / "bin"
HELP_DIR = ROOT / "config" / "parameters" / "static_help"
MANIFEST_PATH = ROOT / "config" / "tools" / "manifests.yaml"
HELP_SOURCES = ROOT / "config" / "parameters" / "help_sources.yaml"

# GitHub release download templates (projectdiscovery + popular Go tools)
PD_REPO = {
    "subfinder": "subfinder",
    "dnsx": "dnsx",
    "httpx": "httpx",
    "katana": "katana",
    "naabu": "naabu",
    "tlsx": "tlsx",
    "mapcidr": "mapcidr",
    "nuclei": "nuclei",
    "chaos-client": "chaos-client",
    "shuffledns": "shuffledns",
}

GO_REPO = {
    "gau": ("lc", "gau"),
    "waybackurls": ("tomnomnom", "waybackurls"),
    "ffuf": ("ffuf", "ffuf"),
    "gobuster": ("OJ", "gobuster"),
    "rustscan": ("RustScan", "RustScan"),
    "trufflehog": ("trufflesecurity", "trufflehog"),
    "gitleaks": ("gitleaks", "gitleaks"),
    "hakrawler": ("hakluke", "hakrawler"),
}


def _os_asset() -> str:
    sys = platform.system().lower()
    arch = platform.machine().lower()
    if sys == "windows":
        return "windows_amd64.zip"
    if sys == "darwin":
        return "macOS_arm64.zip" if "arm" in arch else "macOS_amd64.zip"
    return "linux_arm64.zip" if "arm" in arch else "linux_amd64.zip"


def _download(url: str, dest: Path) -> bool:
    try:
        print(f"  downloading {url}")
        with urlopen(url, timeout=120) as resp:
            dest.write_bytes(resp.read())
        return True
    except Exception as exc:
        print(f"  download failed: {exc}")
        return False


def _extract_exe(zip_path: Path, exe_name: str, dest: Path) -> bool:
    try:
        with zipfile.ZipFile(zip_path) as zf:
            for name in zf.namelist():
                base = Path(name).name
                if base.lower() in (
                    exe_name.lower(),
                    f"{exe_name}.exe".lower(),
                    f"{exe_name}_windows_amd64.exe".lower(),
                ) or base.endswith(".exe"):
                    data = zf.read(name)
                    dest.write_bytes(data)
                    dest.chmod(0o755)
                    return True
        return False
    except Exception as exc:
        print(f"  extract failed: {exc}")
        return False


def download_pd_tool(name: str, repo: str) -> Path | None:
    asset = _os_asset()
    url = f"https://github.com/projectdiscovery/{repo}/releases/latest/download/{repo}_{asset}"
    zip_path = BIN_DIR / f"{name}.zip"
    exe = BIN_DIR / (f"{name}.exe" if platform.system() == "Windows" else name)
    if exe.exists():
        return exe
    BIN_DIR.mkdir(parents=True, exist_ok=True)
    if not _download(url, zip_path):
        return None
    if not _extract_exe(zip_path, repo, exe):
        # try alternate exe name inside zip
        if not _extract_exe(zip_path, name, exe):
            return None
    zip_path.unlink(missing_ok=True)
    return exe


def download_go_tool(name: str, owner: str, repo: str) -> Path | None:
    asset = _os_asset()
    url = f"https://github.com/{owner}/{repo}/releases/latest/download/{repo}_{asset}"
    zip_path = BIN_DIR / f"{name}.zip"
    exe = BIN_DIR / (f"{name}.exe" if platform.system() == "Windows" else name)
    if exe.exists():
        return exe
    BIN_DIR.mkdir(parents=True, exist_ok=True)
    if not _download(url, zip_path):
        return None
    if not _extract_exe(zip_path, repo, exe):
        return None
    zip_path.unlink(missing_ok=True)
    return exe


def resolve_binary(manifest_name: str, spec: dict[str, Any]) -> Path | None:
    """Return path to binary: local tools/bin, PATH, or download."""
    binary = spec.get("binary", manifest_name)
    local = BIN_DIR / (f"{binary}.exe" if platform.system() == "Windows" else binary)
    if local.exists():
        return local

    which = shutil.which(binary)
    if which:
        return Path(which)

    if manifest_name in PD_REPO:
        return download_pd_tool(manifest_name, PD_REPO[manifest_name])
    if manifest_name in GO_REPO:
        owner, repo = GO_REPO[manifest_name]
        return download_go_tool(manifest_name, owner, repo)

    # nmap on windows common path
    if binary == "nmap" and platform.system() == "Windows":
        for p in [
            Path(r"C:\Program Files (x86)\Nmap\nmap.exe"),
            Path(r"C:\Program Files\Nmap\nmap.exe"),
        ]:
            if p.exists():
                return p
    return None


def capture_help(
    manifest_name: str,
    binary: Path,
    help_cfg: dict[str, Any],
    defaults: dict[str, Any],
) -> tuple[str, str]:
    """Run help commands; return (help_text, source_label)."""
    tool_cfg = (help_cfg.get("tools") or {}).get(manifest_name, {})
    if tool_cfg.get("skip_live_help"):
        return "", "skipped"

    argv_lists = tool_cfg.get("help_argv") or defaults.get("help_argv", [["-h"]])
    timeout = tool_cfg.get("timeout_seconds", defaults.get("timeout_seconds", 30))

    for extra in argv_lists:
        cmd = [str(binary), *extra]
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
            out = (proc.stdout or "") + "\n" + (proc.stderr or "")
            out = out.strip()
            if len(out) > 80 and ("usage" in out.lower() or out.count("-") > 3):
                return out, f"live:{' '.join(extra)}"
        except Exception as exc:
            print(f"  help failed {cmd}: {exc}")
    return "", "failed"


def main() -> None:
    manifests = yaml.safe_load(MANIFEST_PATH.read_text(encoding="utf-8")) or {}
    help_cfg = yaml.safe_load(HELP_SOURCES.read_text(encoding="utf-8")) if HELP_SOURCES.exists() else {}
    defaults = help_cfg.get("defaults", {})
    HELP_DIR.mkdir(parents=True, exist_ok=True)
    BIN_DIR.mkdir(parents=True, exist_ok=True)

    results: dict[str, Any] = {}
    for name, spec in (manifests.get("tools") or {}).items():
        print(f"[{name}]")
        binary = resolve_binary(name, spec)
        if not binary:
            print("  no binary")
            results[name] = {"status": "no_binary"}
            continue
        print(f"  binary: {binary}")
        text, source = capture_help(name, binary, help_cfg, defaults)
        if text:
            out = HELP_DIR / f"{name}.txt"
            out.write_text(text, encoding="utf-8")
            print(f"  captured {len(text)} chars ({source}) -> {out.name}")
            results[name] = {"status": "ok", "source": source, "chars": len(text)}
        else:
            print("  help capture failed")
            results[name] = {"status": "help_failed", "binary": str(binary)}

    summary_path = HELP_DIR / "_download_summary.json"
    summary_path.write_text(json.dumps(results, indent=2), encoding="utf-8")
    ok = sum(1 for v in results.values() if v.get("status") == "ok")
    print(f"\nCaptured help for {ok}/{len(results)} tools -> {HELP_DIR}")


if __name__ == "__main__":
    main()
