"""Prove the selftest and the e2e suite can actually fail.

Break the code on purpose and require the suites to notice (named check
failures), not just non-zero exits.
"""
from __future__ import annotations

import pathlib
import subprocess
import sys

TOOL = pathlib.Path("agent-gate.py")
TESTS = pathlib.Path("tests") / "test_agent_gate.py"


def read_source() -> str:
    with open(TOOL, encoding="utf-8", newline="") as fh:
        return fh.read()


def write_source(text: str) -> None:
    with open(TOOL, "w", encoding="utf-8", newline="") as fh:
        fh.write(text)


def run_selftest():
    proc = subprocess.run([sys.executable, str(TOOL), "selftest"],
                          capture_output=True, text=True, timeout=600)
    return proc.returncode, proc.stdout + proc.stderr


def run_e2e():
    proc = subprocess.run([sys.executable, "-m", "unittest", "tests.test_agent_gate"],
                          capture_output=True, text=True, timeout=900)
    out = proc.stdout + proc.stderr
    if proc.returncode and "FAILED" not in out:
        return 1
    return proc.returncode


def named_check_failure(output: str):
    for line in output.splitlines():
        if line.startswith("  [FAIL]"):
            return line[2:].strip()
    for line in output.splitlines():
        if line.startswith("  FAIL "):
            return line[7:].strip()
    return None


def attempt(label, old, new, expect_check=True):
    src = read_source()
    if old not in src:
        print(f"{label}: pattern not found")
        return False
    try:
        write_source(src.replace(old, new, 1))
        rc, out = run_selftest()
        ok = rc != 0 and (named_check_failure(out) or not expect_check)
        if not ok:
            print(f"{label}: selftest did not fail as expected (rc={rc})")
            return False
        if expect_check and not named_check_failure(out):
            print(f"{label}: no named check failure found in selftest")
            return False
        rc2 = run_e2e()
        if rc2 == 0:
            print(f"{label}: e2e suite did not fail")
            return False
        return True
    finally:
        write_source(src)


def main():
    ok = True
    ok &= attempt("behaviour: monotonicity loosened",
                  '        if rank[after] > rank[before]:\n            monotone = False',
                  '        if rank[after] < rank[before]:\n            monotone = False')
    ok &= attempt("reporting: negative control injected",
                  '    passed = sum(1 for _n, ok in checks if ok)\n    total = len(checks)',
                  '    ck("negative control injected by CI", False)\n    passed = sum(1 for _n, ok in checks if ok)\n    total = len(checks)')
    if not ok:
        sys.exit(1)
    print("ok: both suites can fail as named checks")
    sys.exit(0)


if __name__ == "__main__":
    main()
