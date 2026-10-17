"""Report maintained Python modules absent from the configured CI quality gates.

Usage: python scripts/quality_coverage_inventory.py
       python scripts/quality_coverage_inventory.py --json
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CI = ROOT / ".github" / "workflows" / "ci.yml"
PACKAGE = ROOT / "src" / "penx_app"


def coverage(ci_text: str, modules: list[str]) -> dict[str, list[str]]:
    """Locate existing Ruff F401 and mypy coverage without assuming full-tree."""
    lines = ci_text.splitlines()
    commands = {
        "ruff_f401": [line for line in lines
                       if "python -m ruff check --select F401 " in line],
        "mypy": [line for line in lines
                  if "python -m mypy --follow-imports=skip " in line],
    }
    result: dict[str, list[str]] = {}
    for gate, matches in commands.items():
        paths: set[str] = set()
        for command in matches:
            paths.update(re.findall(r"src/penx_app/[\w./-]+", command))
        result[gate] = sorted(
            module for module in modules
            if not any(module == path or module.startswith(path.rstrip("/") + "/")
                       for path in paths)
        )
    return result


def build_report(root: Path = ROOT) -> dict[str, object]:
    modules = sorted(path.relative_to(root).as_posix()
                     for path in (root / "src" / "penx_app").rglob("*.py"))
    missing = coverage(
        (root / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8"),
        modules,
    )
    return {
        "maintained_modules": len(modules),
        "uncovered": missing,
        "uncovered_counts": {gate: len(paths) for gate, paths in missing.items()},
        "note": "Inventory only: does not indicate lint/type success or field sign-off.",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="print machine-readable inventory")
    args = parser.parse_args()
    report = build_report()
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"Maintained modules: {report['maintained_modules']}")
        for gate, paths in report["uncovered"].items():
            print(f"{gate}: {len(paths)} uncovered")
            for path in paths:
                print(f"  {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
