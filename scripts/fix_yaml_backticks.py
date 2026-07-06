"""Fix rationale lines broken by single-quote flag notation in YAML."""

import re
from pathlib import Path


def fix_rationale_line(line: str) -> str:
    m = re.match(r"(\s*rationale:\s*)(.*)", line)
    if not m:
        return line
    prefix, val = m.group(1), m.group(2).strip()
    if not val or val.startswith(">-") or val.startswith("|"):
        return line
    # Strip outer quotes if present
    if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
        val = val[1:-1]
    # '-flag' or '--flag' inside text -> flag
    val = re.sub(r"'(-{1,2}[\w-]+)'", r"\1", val)
    val = val.replace("'", "")
    # Escape double quotes inside value
    val = val.replace('"', '\\"')
    return f'{prefix}"{val}"'


def main() -> None:
    for path in Path("config/parameters/references").glob("*.yaml"):
        lines = path.read_text(encoding="utf-8").splitlines()
        fixed = [fix_rationale_line(line) for line in lines]
        path.write_text("\n".join(fixed) + "\n", encoding="utf-8")
        print(f"processed {path.name}")


if __name__ == "__main__":
    main()
