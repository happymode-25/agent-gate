# agent-gate — build report

**Version:** 1.0.0 · **Repo:** https://github.com/happymode-25/agent-gate (private) ·
**Built:** Oct 2026 · **Basis:** the AI-era sibling of egress-broker — a
fail-closed capability broker that decides what an AI agent's tool call is
allowed to do, before it executes, with a tamper-evident record of every
decision. Built to the egress-broker/worm-lab/patch-lab/clear-lab bar (single
file, stdlib only, fail-closed, tamper-evident, mutation-swept, CI-gated).

## 1. What was built

`agent-gate.py` is a one-file, zero-dependency (Python 3.9+ stdlib) policy
decision point for AI-agent tool calls. An agent proposes an action
(`{"tool": ..., "args": {...}, "agent": ...}`); the tool decides
ALLOW / DENY / REQUIRE-APPROVAL against a declarative JSON policy, explains
exactly which rules matched, and appends every decision to a hash-chained JSONL
audit store. A REQUIRE-APPROVAL verdict is lifted only by a human `approve`
record whose `action_digest` equals the digest of the canonical action.

No model, no network, no third-party imports: the decision is a pure,
deterministic function of `(action, policy, ledger)`.

## 2. Security-engineering stance

Same three fail-closed guarantees as the rest of the family:

- **Fail-closed input.** A malformed action, a malformed/unreadable policy, an
  unknown predicate operator, an unknown effect, a duplicate rule id, a
  `default` other than `deny`, and an undeclared tool all resolve to DENY or to
  a refusal to run (exit 1) — never an accidental ALLOW. Unknown commands exit 2.
- **Fail-closed decisions.** The world is closed: an action matching no rule is
  denied, and the "no rule matched" branch is the only default-allow candidate —
  it is locked to DENY. `check --enforce` turns a non-ALLOW verdict into exit 1.
- **Fail-closed evidence.** If the audit chain does not verify *immediately
  after a write*, the tool refuses to report the run. A store that no longer
  verifies is refused for new runs, not silently re-appended.

Input files (`policy`, `action`) tolerate a Windows BOM (`utf-8-sig`); the ledger
store stays strict UTF-8, so a BOM cannot mask a tamper.

## 3. The decision lattice, and how it is proved

```
DENY  >  REQUIRE-APPROVAL  >  ALLOW  >  (closed world) DENY
```

Every matching rule contributes its effect; the verdict is the top of that set
under the lattice. Two structural properties follow and are checked in the
selftest:

| Property | How it is checked |
|---|---|
| Closed world | an empty rule set denies every action (the default is DENY) |
| Deny overrides allow | a matching deny beats a matching allow |
| Approval overrides allow | a matching `require-approval` yields REQUIRE-APPROVAL, not ALLOW |
| Deny overrides approval | a matching deny beats an approved `require-approval` |
| Order independence | the verdict is identical across **all 24 permutations** of a four-rule policy |
| Monotone denial | adding a deny rule never moves a verdict from DENY toward ALLOW |
| Three evaluators agree | the production engine, a set-based reference, and a boolean normal-form over a match matrix return the same effect on every enumerated case |
| Determinism | identical inputs give an identical decision and action digest |

The lattice is what makes evaluation order-independent — a property the family
did **not** have (its planners were sequential), and one worth proving because
it means a policy author cannot create a surprising precedence by reordering
rules.

## 4. Constraint soundness (the security-critical predicates)

| Property | How it is checked |
|---|---|
| No path traversal | `path_within` rejects `/srv/data/../../etc/passwd` and `/srv/data/./../secret` |
| No prefix confusion | `/srv/database/x` is **not** inside `/srv/data` |
| Relative-vs-absolute | a relative path never satisfies an absolute root |
| Normalisation | double slashes and `.` collapse before containment |
| NUL bytes | rejected |
| No domain suffix confusion | `example.com.evil.net` does not match `*.example.com` or `example.com` |
| No domain substring confusion | `evil-example.com` does not match `example.com` |
| Wildcard boundary | `*.example.com` matches `api.example.com`, not the bare base `example.com` |
| URL parsing | userinfo and port are stripped; a trailing dot is normalised |
| IP literals | an IP host never matches a domain pattern |
| Numeric boundaries | `num_le` is inclusive, `num_lt` exclusive; a boolean is not a number |
| Fail-closed predicates | a missing argument under a value predicate is false; a non-numeric value under `num_*` is false |

These are real bug classes: a `path_within` implemented with a naive
`startswith` allows `/srv/database`, and a `domain_in` implemented with a naive
`endswith` allows `example.com.evil.net`. Both mutations are in the sweep, and
both are killed.

## 5. Approval binds to the action

A REQUIRE-APPROVAL verdict is lifted only by an `approve` record whose
`action_digest` equals the digest of the canonical action
(`{tool, agent, args}`, sorted-key JSON, SHA-256). Changing a single argument
changes the digest, so an approval for one email cannot authorise a different
one. The selftest checks both directions: the exact digest lifts the gate, a
different digest does not, and the sweep's "approval keyed on the tool name"
mutant is killed.

## 6. Audit trail

`{seq, ts, tool, version, command, policy_digest, action_digest, decision,
reason, matched, prev, hash}` with `hash = sha256(canonical(record minus hash))`;
record 0's `prev` is a fixed genesis anchor. `verify` checks seq contiguity,
prev linkage, and content hash, and names exactly what is wrong. Editing a
number, deleting the oldest record, and inserting a forged record are all
caught.

Honest limitation: trimming the *tail* of the file cannot be detected from
inside the file. External anchoring (log shipper, SIEM, append-only media) is
the documented answer if that matters.

## 7. Defects found and fixed during bring-up

| Defect | Symptom | Fix |
|---|---|---|
| policy digest over an internal set | the digest was computed over the normalised policy object, which carries a `frozenset` of tools — `TypeError: Object of type frozenset is not JSON serializable`, and the selftest died before its first check | the digest covers only the policy *as authored* (`version`, `default`, `tools`, `rules`), not the internal `_tools` set |
| a wrong selftest expectation | the "approval binds to the action" check asserted that an approval for `x=1` left `x=2` at REQUIRE-APPROVAL, but `x=2` was not covered by the approval rule and was legitimately ALLOW | the check uses a policy where *every* action requires approval, so the assertion tests the digest binding rather than rule coverage |
| a BOM was mistaken for malformed input | PowerShell `Set-Content -Encoding utf8` writes a UTF-8 BOM; the tool correctly failed closed ("Unexpected UTF-8 BOM") but every hand-authored action file on Windows was unusable | `policy` and `action` inputs are read as `utf-8-sig` (identical to `utf-8` when no BOM is present); the ledger store stays strict `utf-8` |
| the import gate flagged its own stdlib submodule | `sys.stdlib_module_names` does not contain the submodule name `importlib.machinery`, so the gate reported its own `from importlib.machinery import PathFinder` as a third-party import | the gate recognises any `importlib.*` name as standard-library |
| ambiguous mutation anchors | `ad = action_digest(action)` appears four times and `if tool not in policy["_tools"]:` three times, so those would be PATTERN-AMBIGUOUS rows | the sweep targets anchors that are unique by construction (`if ad in approvals:` for approval binding; the unique multi-line "undeclared tool" return for the tool mutant), and any residual ambiguity is a failing row, not a silent miss |

## 8. Verification — what the green is, and that it can fail

| Gate | Result |
|---|---|
| `ci/import_gate.py` | 0 non-stdlib imports across the repo |
| `selftest` | 49/49 checks |
| `tests/test_agent_gate.py` | 39/39 tests, real subprocess runs of the CLI |
| `ci/prove_suites_can_fail.py` | a loosened-monotonicity mutation and an injected negative-control check both turn the suites red *as named checks*; restore is green again |
| `ci/mutation.py` | 11 real mutants killed, semantically-identical canary survives, live file hash unchanged (scratch-copy only) |
| CI matrix | Python 3.9 / 3.11 / 3.13 × linux / macos / windows (5 cells), count floors: 49 selftest checks, 39 e2e tests, import gate and mutation sweep gated |

The mutants killed: default-deny → allow, deny stops overriding allow, unknown
tool allowed, traversal not collapsed, path prefix confusion, exact-host match
degraded to a suffix test, `not()` ignored, `num_lt` made inclusive, approval
keyed on the tool name, `default: "allow"` accepted, and garbage ledger hashes.

The suite is not trusted on a green run alone: `prove_suites_can_fail` breaks
the code on purpose and requires the failures to be *named checks*, not
crashes, and the mutation sweep requires the canary to survive, otherwise every
verdict in the run is void.

## 9. Reproduce

```powershell
git clone https://github.com/happymode-25/agent-gate   # private; needs access
cd agent-gate
python ci/import_gate.py
python agent-gate.py selftest
python tests/test_agent_gate.py
python ci/prove_suites_can_fail.py
python ci/mutation.py
```

CI runs the same gates on every push; the mutation sweep runs on one cell
(ubuntu + 3.11) because it is the slowest gate.

## 10. Relationship to the previous builds

The family is now a quintet, one discipline across five claims:
[egress-broker](https://github.com/happymode-25/egress-broker) proves egress
decisions and audit rows are trustworthy (prevent),
[worm-lab](https://github.com/happymode-25/worm-lab) proves propagation numbers
(model), [patch-lab](https://github.com/happymode-25/patch-lab) proves the
containment answer (contain), [clear-lab](https://github.com/happymode-25/clear-lab)
proves the stand-down question containment sets up (eradicate), and agent-gate
proves what an **autonomous agent is allowed to do** — the same
decision-plus-audit shape as egress-broker, moved from the network boundary to
the agent's tool boundary.

The patterns carried over deliberately: a pure selftest plus a subprocess e2e
suite, count floors in CI, an import gate, a prove-suites-can-fail harness, a
canary-anchored mutation sweep on a scratch copy with the live file hashed
before and after, a `.gitattributes` with `eol=lf` from the first commit, and a
README that states guarantees *and* their limits. The one new lesson bought
this session: a decision that is a **pure function** can be pinned three ways
(engine, reference, normal-form) and proved order-independent across all rule
permutations — so a policy cannot smuggle a surprising precedence past review
by reordering rules.
