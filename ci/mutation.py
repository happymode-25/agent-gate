"""Mutation sweep for agent-gate, run against a SCRATCH COPY.

The live repo is hashed before and after; every mutation is applied to a
throwaway copy; the harness refuses to start if it cannot make one. A
provably-identical canary MUST survive — if it is reported killed, every other
verdict in the run is void.

Anchor discipline: each target must match EXACTLY one occurrence in
agent-gate.py. A PATTERN-MISS or PATTERN-AMBIGUOUS row fails the sweep.

Usage:
  python ci/mutation.py                    # full sweep
  python ci/mutation.py decision           # only these groups
  python ci/mutation.py CANARY             # prove the harness sees a survivor
"""
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile

SRC_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOL = os.path.join("agent-gate.py")
TESTS = os.path.join("tests", "test_agent_gate.py")

COPY = [TOOL, TESTS]

CANARY = "CANARY"

# Frozen baselines (the CI floors match these).
BASE_SELFTEST = 49
BASE_E2E = 39


def digest(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def clean_caches(root):
    for dirpath, dirnames, _ in os.walk(root):
        for d in list(dirnames):
            if d == "__pycache__":
                shutil.rmtree(os.path.join(dirpath, d), ignore_errors=True)
                dirnames.remove(d)


def read(path):
    with open(path, encoding="utf-8", newline="") as fh:
        return fh.read()


def write(path, text):
    with open(path, "w", encoding="utf-8", newline="") as fh:
        fh.write(text)


def run(root, args, timeout=900):
    return subprocess.run([sys.executable] + args, capture_output=True,
                          text=True, timeout=timeout, cwd=root)


def run_selftest(root):
    p = run(root, [TOOL, "selftest"], timeout=300)
    failed = sorted(set(
        m.group(1).strip() for m in re.finditer(r"^  \[FAIL\] (.+)$", p.stdout, re.M)
    ))
    ran = re.search(r"^\s*(\d+)/(\d+) checks passed", p.stdout, re.M)
    total = int(ran.group(2)) if ran else -1
    return p.returncode, failed, total, p.stdout[-700:]


def run_e2e(root):
    p = run(root, [TESTS], timeout=900)
    text = p.stdout + p.stderr
    names = sorted(set(
        m.group(1).strip()
        for m in re.finditer(r"^(?:FAIL|ERROR): (\S+)", text, re.M)
    ))
    ran = re.search(r"^Ran (\d+) tests?", text, re.M)
    return p.returncode, names, (int(ran.group(1)) if ran else -1), text[-700:]


SUITES = {"selftest": run_selftest, "e2e": run_e2e}


def check_green(root, label, expect_selftest, expect_e2e):
    ok = True
    for name, fn in SUITES.items():
        code, failures, count, tail = fn(root)
        want = expect_selftest if name == "selftest" else expect_e2e
        good = code == 0 and not failures and count == want
        ok = ok and good
        print(f"  {label} {name:9} exit={code} checks={count} failures={len(failures)} "
              f"{'OK' if good else 'BAD'}")
        if not good:
            for line in tail.strip().splitlines()[-10:]:
                print("      " + line)
    return ok


# --------------------------------------------------------------------------
# The mutation table. Each entry replaces exactly one occurrence.
#   (id, description, suite, target substring, replacement line body)
# --------------------------------------------------------------------------

M = [
    # -- canary: must SURVIVE, and proves the harness can see a survivor -----
    # Concatenating the empty string cannot change the digest value.
    (CANARY, "digest() + \"\" is the same string, so this cannot change behaviour",
     "selftest",
     "    return hashlib.sha256(canonical(obj)).hexdigest()",
     "    return hashlib.sha256(canonical(obj)).hexdigest() + \"\""),

    # -- the decision lattice ----------------------------------------------
    ("decision", "the closed world stops denying: an action matching no rule "
                 "is allowed",
     "selftest",
     'return {"effect": "deny", "default": True, "matched": matched,',
     'return {"effect": "allow", "default": True, "matched": matched,'),
    ("decision", "deny no longer overrides allow, so a matching deny rule is "
                 "ignored when an allow also matches",
     "selftest",
     '    if "deny" in effects:',
     '    if "deny" in effects and "allow" not in effects:'),
    ("decision", "an undeclared tool is allowed instead of denied",
     "e2e",
     'return {"effect": "deny", "default": False, "matched": [],\n'
     '                "reason": "tool %r is not declared by the policy" % tool,',
     'return {"effect": "allow", "default": False, "matched": [],\n'
     '                "reason": "tool %r is not declared by the policy" % tool,'),

    # -- constraint soundness ----------------------------------------------
    ("path", "path traversal is never collapsed, so /srv/data/../../etc/passwd "
             "is treated as inside the root",
     "e2e",
     "        comps.pop()",
     "        comps.append(comp)"),
    ("path", "path containment ignores the / separator, so /srv/database is "
             "mistaken for a child of /srv/data",
     "selftest",
     '    return p.startswith(r.rstrip("/") + "/")',
     '    return p.startswith(r.rstrip("/"))'),
    ("domain", "the exact host match degrades to a suffix test, so "
               "evil-example.com passes as example.com",
     "selftest",
     "    return labels == plabels",
     "    return host.endswith(pattern)"),
    ("pred", "the not() combinator is ignored, so a negated predicate returns "
             "its inner value",
     "e2e",
     "        return not eval_arg_predicate(param, value, present, ref=ref)",
     "        return eval_arg_predicate(param, value, present, ref=ref)"),
    ("pred", "num_lt becomes inclusive at the boundary (10 < 10 becomes true)",
     "selftest",
     "    return present and _is_num(v) and v < p",
     "    return present and _is_num(v) and v <= p"),

    # -- approval binding ---------------------------------------------------
    ("approve", "approval is keyed on the tool name, not the action digest, so "
                "one approval lifts every action for that tool",
     "selftest",
     "        if ad in approvals:",
     "        if action.get(\"tool\") in approvals:"),

    # -- fail-closed policy loading ----------------------------------------
    ("policy", "a policy whose default is \"allow\" is accepted instead of "
               "refused",
     "e2e",
     '    if pol.get("default") != "deny":',
     "    if False:"),

    # -- audit chain ---------------------------------------------------------
    ("audit", "every appended record carries a garbage hash, so the chain "
              "cannot verify and runs are refused",
     "e2e",
     '    full["hash"] = digest({k: v for k, v in full.items() if k != "hash"})',
     '    full["hash"] = "0" * 64'),
]


def main():
    wanted = set(sys.argv[1:])
    rows = [m for m in M if m[0] == CANARY or not wanted or m[0] in wanted]

    live_tool = os.path.join(SRC_REPO, TOOL)
    before = digest(live_tool)
    print(f"live repo: {SRC_REPO}")
    print(f"  tool sha256 before sweep: {before[:16]}")

    root = tempfile.mkdtemp(prefix="mutate-")
    for rel in COPY:
        dst = os.path.join(root, rel)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.copyfile(os.path.join(SRC_REPO, rel), dst)
    clean_caches(root)
    print(f"scratch copy: {root}")
    print()

    tool_path = os.path.join(root, TOOL)
    original = read(tool_path)

    print("== baseline ==")
    if not check_green(root, "baseline", BASE_SELFTEST, BASE_E2E):
        shutil.rmtree(root, ignore_errors=True)
        sys.exit("baseline is not green; the harness cannot be trusted")
    print()

    results = []
    try:
        for mid, desc, suite, target, repl in rows:
            clean_caches(root)
            n = original.count(target)
            if n != 1:
                verdict = "PATTERN-MISS" if n == 0 else "PATTERN-AMBIGUOUS"
                results.append((mid, desc, suite, verdict))
                print(f"  {verdict:15} {mid:9} {desc}  ({n} matches)")
                continue
            write(tool_path, original.replace(target, repl, 1))
            if read(tool_path) != original.replace(target, repl, 1):
                results.append((mid, desc, suite, "WRITE-FAILED"))
                print(f"  {'WRITE-FAILED':15} {mid:9} {desc}")
                continue
            c = subprocess.run([sys.executable, "-m", "py_compile", tool_path],
                               capture_output=True, text=True)
            if c.returncode != 0:
                results.append((mid, desc, suite, "WILL-NOT-COMPILE"))
                print(f"  {'WILL-NOT-COMPILE':15} {mid:9} {desc}")
                print("               " + c.stderr.strip().splitlines()[-1])
                continue
            clean_caches(root)
            code, failures, count, tail = SUITES[suite](root)
            killed = code != 0 and bool(failures)
            verdict = "KILLED" if killed else "SURVIVED"
            results.append((mid, desc, suite, verdict))
            print(f"  {verdict:15} {mid:9} {desc}")
            for f in list(failures)[:3]:
                print(f"               - {f}")
            if killed and count in (-1, 0):
                print(f"               (suite ran {count} tests)")
    finally:
        write(tool_path, original)
        print()

    print("== after revert ==")
    restored = check_green(root, "restored", BASE_SELFTEST, BASE_E2E)

    after = digest(live_tool)
    untouched = before == after
    print(f"\nlive repo tool sha256 after sweep: {after[:16]}  "
          f"{'UNTOUCHED' if untouched else 'CHANGED -- the sweep escaped the scratch copy'}")
    shutil.rmtree(root, ignore_errors=True)

    canary = [r for r in results if r[0] == CANARY]
    canary_ok = bool(canary) and canary[0][3] == "SURVIVED"
    if not canary_ok:
        print("\nCANARY DID NOT SURVIVE -- the harness kills things that cannot be "
              "killed, so no verdict above means anything.")

    killed = [r for r in results if r[3] == "KILLED"]
    broken = [r for r in results if r[3] in ("PATTERN-MISS", "PATTERN-AMBIGUOUS",
                                             "WRITE-FAILED", "WILL-NOT-COMPILE")]
    survivors = [r for r in results if r[3] == "SURVIVED" and r[0] != CANARY]

    print()
    print(f"killed {len(killed)} / {len(results) - len(broken)} runnable mutants")
    print(f"canary {'survived as required' if canary_ok else 'FAILED -- run is void'}")
    print(f"live repo {untouched and 'untouched' or 'MODIFIED'}")
    if broken:
        print(f"\n{len(broken)} mutant(s) never ran:")
        for r in broken:
            print(f"  {r[3]}: {r[0]} -- {r[1]}")
    if survivors:
        print(f"\n{len(survivors)} real survivor(s) -- these are weak tests, or bugs:")
        for r in survivors:
            print(f"  {r[0]}: {r[1]}  [{r[2]}]")

    bad = survivors or broken or not restored or not untouched or not canary_ok
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
