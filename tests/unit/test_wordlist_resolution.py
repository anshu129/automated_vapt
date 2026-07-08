from pathlib import Path

from vapt_platform.tools.wordlists import (
    default_wordlist_relative_path,
    resolve_wordlist_path,
    wordlist_mappings,
)


def test_default_wordlist_relative_paths() -> None:
    assert default_wordlist_relative_path("ffuf") == "Discovery/Web-Content/common.txt"
    assert default_wordlist_relative_path("gobuster") == "Discovery/Web-Content/common.txt"
    assert default_wordlist_relative_path("shuffledns") == (
        "Discovery/DNS/subdomains-top1million-5000.txt"
    )


def test_resolve_wordlist_uses_seclists_when_present() -> None:
    root = Path("SecLists-master")
    if not (root / "Discovery/Web-Content/common.txt").is_file():
        return
    path = resolve_wordlist_path("ffuf", {})
    assert path.endswith("Discovery\\Web-Content\\common.txt") or path.endswith(
        "Discovery/Web-Content/common.txt"
    )
    assert Path(path).is_file()


def test_resolve_wordlist_honors_explicit_target_override(tmp_path: Path) -> None:
    custom = tmp_path / "custom.txt"
    custom.write_text("admin\n", encoding="utf-8")
    resolved = resolve_wordlist_path("ffuf", {"wordlist": str(custom)}, project_root=tmp_path)
    assert resolved == str(custom.resolve())


def test_wordlist_mappings_include_configured_tools() -> None:
    mappings = wordlist_mappings()
    assert set(mappings) >= {"ffuf", "feroxbuster", "gobuster", "wfuzz", "shuffledns"}
