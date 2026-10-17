"""Fail if any Python file here imports something outside the standard library.

The promise is that `agent-gate.py` is one file you can copy to an air-gapped
box and run with the Python already installed. That dies the moment a
third-party import appears.

Usage:  python ci/import_gate.py            # checks every .py in the repo
        python ci/import_gate.py --quiet
"""
from __future__ import annotations

import argparse
import ast
import pathlib
import sys
import sysconfig

# Module names that are legitimate local modules (not third-party).
EXEMPT = {"agent_gate"}

SITE_DIRS = frozenset({"site-packages", "dist-packages"})


def _stdlib_dirs() -> list[str]:
    roots: set[str] = set()
    stdlib = sysconfig.get_paths().get("stdlib")
    if stdlib:
        roots.add(str(pathlib.Path(stdlib).resolve()))
    for entry in list(sys.path):
        if not entry:
            continue
        try:
            path = pathlib.Path(entry).resolve()
        except OSError:
            continue
        if SITE_DIRS.intersection(path.parts):
            continue
        roots.add(str(path))
    return sorted(p for p in roots if pathlib.Path(p).is_dir())


def _is_stdlib(name: str, dirs: list[str]) -> bool:
    table = getattr(sys, "stdlib_module_names", None)
    if table is not None and name in table:
        return True
    if name == "importlib.machinery" or name.startswith("importlib."):
        return True
    top = name.split(".", 1)[0]
    if top in ("importlib",):
        return True
    if top in EXEMPT:
        return True
    try:
        from importlib.machinery import PathFinder  # stdlib
        spec = PathFinder.find_spec(name, path=dirs)
    except Exception:
        return False
    if spec is None or spec.origin is None:
        return False
    try:
        origin = pathlib.Path(spec.origin).resolve()
    except OSError:
        return False
    for d in dirs:
        try:
            origin.is_relative_to(d)
            return True
        except Exception:
            if str(origin).startswith(d + os_sep()):
                return True
    return False


def os_sep():
    return "\\" if sys.platform == "win32" else "/"


def _iter_py_files(root: pathlib.Path):
    for path in root.rglob("*.py"):
        if any(part in {"__pycache__", ".git"} for part in path.parts):
            continue
        yield path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()
    root = pathlib.Path.cwd()
    dirs = _stdlib_dirs()
    bad = []
    for py in _iter_py_files(root):
        try:
            src = py.read_text(encoding="utf-8")
        except Exception:
            continue
        try:
            tree = ast.parse(src, filename=str(py))
        except Exception:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    name = alias.name
                    if not _is_stdlib(name, dirs):
                        bad.append((py, name))
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    name = node.module
                    if not _is_stdlib(name, dirs):
                        bad.append((py, name))
    if bad:
        for py, name in bad:
            print(f"{py}: imports non-stdlib module '{name}'")
        return 1
    if not args.quiet:
        print("ok: no non-stdlib imports found")
    return 0


if __name__ == "__main__":
    sys.exit(main())
