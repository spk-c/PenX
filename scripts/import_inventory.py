"""Import inventory and migration for legacy compatibility shims.

The repository keeps a set of top-level compatibility modules (``src/<name>.py``)
that alias legacy import names onto the canonical ``penx_app`` package:

    import sys
    from penx_app.scanners import tools as _implementation
    sys.modules[__name__] = _implementation

Because each shim is a pure module alias, retiring one is behavior-preserving as
long as every consumer is pointed at the canonical module first. This tool
enumerates every remaining consumer of a legacy name -- both ``import`` /
``from`` statements and string-form module references such as
``patch("penx_app.scanners.tools.run_tool")`` -- and can migrate them to canonical paths.

A legacy shim may be retired only when ``--check`` reports no consumers of a
retired name. The legacy -> canonical mapping is derived from
``scripts/source_layout.py`` so there is a single source of truth.

Usage:
    python scripts/import_inventory.py            # report
    python scripts/import_inventory.py --check    # fail if a retired name is referenced
    python scripts/import_inventory.py --migrate  # rewrite consumers in place
"""
from __future__ import annotations

import argparse
import ast
import re
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
try:
    from scripts.source_layout import SOURCE_PATHS
except ImportError:  # executed directly as ``python scripts/import_inventory.py``
    from source_layout import SOURCE_PATHS

# Shims intentionally retained as public/pinned compatibility entrypoints.
# (As of 2026-10-31 none remain: ``llm`` and ``app_paths`` were migrated to
# ``penx_app.analysis.llm`` / ``penx_app.app_paths``; the ``penx`` module
# entrypoint is public API until v1 and is not part of LEGACY.)
KEPT: frozenset[str] = frozenset()


def _canonical(name: str) -> str:
    target = SOURCE_PATHS[f"src/{name}.py"]
    if not (target.startswith("src/") and target.endswith(".py")):
        raise ValueError(f"unexpected canonical target for {name}: {target}")
    return target[len("src/"):-len(".py")].replace("/", ".")


# Legacy top-level name -> canonical module path, for every src/*.py shim.
LEGACY: dict[str, str] = {}
for _key, _target in SOURCE_PATHS.items():
    if _key.startswith("src/"):
        _name = _key[len("src/"):-len(".py")]
        LEGACY[_name] = _canonical(_name)

# Names whose src/*.py shim is being retired in this pass.
REMOVED: frozenset[str] = frozenset(LEGACY) - KEPT


def _parent(module: str) -> str:
    return module.rsplit(".", 1)[0]


def consumer_files(root: Path) -> list[Path]:
    """Every Python file that may import a legacy name.

    This includes the canonical package (so a backwards import of a shim is
    caught), the shim single-files, the root entry points, and all tests and
    scripts. The thin public ``src/penx`` package and virtual environments are
    excluded.
    """
    skip = {
        ".venv", "venv", "__pycache__", ".git", ".mypy_cache", ".ruff_cache",
        ".qwen", ".tox", "site-packages", "node_modules", "dist", "build",
    }
    files: list[Path] = []
    for path in sorted(root.rglob("*.py")):
        if any(part in skip for part in path.parts):
            continue
        try:
            rel = path.relative_to(root)
        except ValueError:
            continue
        if rel.parts[:2] == ("src", "penx"):
            continue
        files.append(path)
    return files


def import_refs(path: Path) -> dict[str, int]:
    """Count legacy names imported via ``import`` / ``from`` statements."""
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (SyntaxError, UnicodeDecodeError, ValueError):
        return {}
    counts: dict[str, int] = {}
    for node in ast.walk(tree):
        tops: list[str] = []
        if isinstance(node, ast.Import):
            tops = [alias.name.split(".")[0] for alias in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module:
            tops = [node.module.split(".")[0]]
        for top in tops:
            if top in LEGACY:
                counts[top] = counts.get(top, 0) + 1
    return counts


def string_refs(path: Path) -> dict[str, int]:
    """Count legacy names used as module-path strings (patch/__import__/import).

    Only the first string argument of ``patch``, ``patch.object``, ``__import__``
    and ``importlib.import_module`` is considered, so display strings and file
    paths are not mistaken for module references.
    """
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (SyntaxError, UnicodeDecodeError, ValueError):
        return {}
    counts: dict[str, int] = {}

    def _module_arg(node: ast.Call) -> str | None:
        func = node.func
        is_ref = False
        if isinstance(func, ast.Name):
            is_ref = func.id in {"patch", "__import__", "import_module"}
        elif isinstance(func, ast.Attribute):
            # patch.object(target, attribute) receives an object, not a
            # module path. Only patch("package.symbol") and dynamic imports
            # can refer to legacy modules via their first string argument.
            is_ref = func.attr in {"patch", "__import__", "import_module"}
        if is_ref and node.args:
            first = node.args[0]
            if isinstance(first, ast.Constant) and isinstance(first.value, str):
                return first.value
        return None

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            target = _module_arg(node)
            if target is None:
                continue
            top = target.split(".")[0]
            if top in LEGACY:
                counts[top] = counts.get(top, 0) + 1
    return counts


def refs(path: Path) -> dict[str, int]:
    merged: dict[str, int] = {}
    for table in (import_refs(path), string_refs(path)):
        for name, count in table.items():
            merged[name] = merged.get(name, 0) + count
    return merged


def build_inventory(root: Path) -> dict[str, list[tuple[str, int]]]:
    """Map every referenced legacy name to the files that reference it."""
    inventory: dict[str, list[tuple[str, int]]] = {}
    for path in consumer_files(root):
        rel = path.relative_to(root).as_posix()
        for name, count in refs(path).items():
            inventory.setdefault(name, []).append((rel, count))
    return inventory


def violations(root: Path) -> list[tuple[str, str, int]]:
    """(name, file, count) triples where a RETIRED name is still referenced."""
    bad: list[tuple[str, str, int]] = []
    for name, users in sorted(build_inventory(root).items()):
        if name not in REMOVED:
            continue
        for rel, count in users:
            bad.append((name, rel, count))
    return bad


def _rewrite_imports(text: str) -> tuple[str, int]:
    """Point ``import`` / ``from`` statements at canonical modules."""
    changes = 0
    for name in sorted(REMOVED, key=len, reverse=True):
        canonical = LEGACY[name]
        # from <name> import ...   (covers "import (" continuation blocks)
        pattern = re.compile(
            r"^(?P<indent>\s*)from\s+" + re.escape(name) + r"(?P<rest>\s+import\b)",
            re.MULTILINE,
        )
        text, n = pattern.subn(r"\g<indent>from " + canonical + r"\g<rest>", text)
        changes += n
        # import <name> [as alias]   (whole statement; excludes "from" lines)
        pattern = re.compile(
            r"^(?P<indent>\s*)import\s+" + re.escape(name)
            + r"(?P<alias>\s+as\s+[A-Za-z_]\w*)?"
            + r"(?P<tail>\s*(?:#.*)?)?$",
            re.MULTILINE,
        )
        text, n = pattern.subn(r"\g<indent>from " + _parent(canonical) + " import " + name + r"\g<alias>\g<tail>", text)
        changes += n
    return text, changes


def _rewrite_strings(text: str) -> tuple[str, int]:
    """Rewrite dotted module-path strings so their leading segment is canonical.

    Only strings that *start* with ``"<name>."`` (e.g. ``"penx_app.scanners.tools.run_tool"``) are
    rewritten. A bare ``"name"`` string is deliberately left alone: in the
    repository every module-path string reference is dotted, and a bare string
    that merely equals a module name (a dict key, a path, a CLI argument) is a
    false positive.
    """
    changes = 0
    for name in sorted(REMOVED, key=len, reverse=True):
        canonical = LEGACY[name]
        pattern = re.compile(r'(["\'])' + re.escape(name) + r"\.(?=\w)")
        text, n = pattern.subn(r"\g<1>" + canonical + ".", text)
        changes += n
    return text, changes


def migrate_file(path: Path) -> int:
    text = path.read_text(encoding="utf-8")
    new, import_changes = _rewrite_imports(text)
    new, string_changes = _rewrite_strings(new)
    if new != text:
        path.write_text(new, encoding="utf-8")
    return import_changes + string_changes


def report(root: Path) -> int:
    inventory = build_inventory(root)
    if not inventory:
        print("No legacy-name references found.")
        return 0
    width = max(len(name) for name in inventory)
    print(f"{'legacy name':<{width}}  {'removed':<8}  consumers")
    print(f"{'-' * width}  {'-' * 8}  {'-' * 24}")
    for name in sorted(inventory):
        users = inventory[name]
        marker = "KEEP " if name in KEPT else ("REMOVED" if name in REMOVED else "???  ")
        summary = ", ".join(f"{rel}({count})" for rel, count in users)
        print(f"{name:<{width}}  {marker:<8}  {summary}")
    return 0


def check(root: Path) -> int:
    bad = violations(root)
    if not bad:
        print("OK: no consumers reference a retired legacy name.")
        return 0
    print(f"FAIL: {len(bad)} retired legacy name(s) still referenced:")
    for name, rel, count in bad:
        print(f"  {name:<24} {rel}  x{count}")
    return 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Inventory/migrate legacy shim imports")
    parser.add_argument("--check", action="store_true",
                        help="exit non-zero if any retired name is still referenced")
    parser.add_argument("--migrate", action="store_true",
                        help="rewrite consumers to canonical imports in place")
    parser.add_argument("--root", default=str(_ROOT), help="repository root (default: repo root)")
    args = parser.parse_args(argv)
    root = Path(args.root)
    if args.migrate:
        total = 0
        for path in consumer_files(root):
            changes = migrate_file(path)
            if changes:
                rel = path.relative_to(root).as_posix()
                print(f"[migrate] {rel}: {changes} reference(s) updated")
                total += changes
        remaining = len(violations(root))
        print(f"[migrate] {total} reference(s) updated; "
              f"{remaining} retired name(s) still referenced")
        return 1 if remaining else 0
    if args.check:
        return check(root)
    return report(root)


if __name__ == "__main__":
    raise SystemExit(main())
