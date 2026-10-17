# agent-gate

A fail-closed capability broker for AI-agent tool calls, built to the same bar
as [egress-broker](https://github.com/happymode-25/egress-broker),
[worm-lab](https://github.com/happymode-25/worm-lab),
[patch-lab](https://github.com/happymode-25/patch-lab), and
[clear-lab](https://github.com/happymode-25/clear-lab):

- **One file, zero dependencies.** `agent-gate.py` runs on Python 3.9+ with the
  standard library alone — the policy engine, the predicates, the audit ledger.
  No numpy, no ML, nothing to pip-install.
- **Fail-closed by default.** The world is closed and denial is the default. A
  policy whose `default` is anything other than `deny` is rejected outright.
  Malformed actions, malformed policies, unknown operators/effects and unknown
  tools all resolve to DENY (or to a refusal to run) — never an accidental
  ALLOW.
- **Tamper-evident audit trail.** Every decision is appended to a hash-chained
  JSONL store. `verify` rebuilds the chain and names exactly what is wrong if
  anything was edited, deleted, or forged.
- **Provably testable.** A 49-check selftest, a 39-test end-to-end suite, a
  `prove_suites_can_fail` harness, and an 11-mutant + canary mutation sweep —
  all enforced in CI with count floors.

## What it does

An AI agent wants to do something — fetch a URL, write a file, send an email,
run a command. It proposes an action:

```json
{"tool": "fs.write", "agent": "researcher", "args": {"path": "/srv/data/report.md"}}
```

`agent-gate` decides **ALLOW / DENY / REQUIRE-APPROVAL** against a declarative
policy, explains exactly which rules matched, and appends the decision to an
auditable, hash-chained ledger. A REQUIRE-APPROVAL verdict is only lifted by a
human `approve` record bound to the exact action digest.

This is the AI-era sibling of [egress-broker](https://github.com/happymode-25/egress-broker):
where egress-broker mediates network egress, agent-gate mediates **agent
tool-call egress** — what an autonomous agent is allowed to touch, decided
before the call executes, with a tamper-evident record of every decision.

### The decision lattice

Every matching rule contributes an effect. Effects compose in a fixed lattice:

```
DENY  >  REQUIRE-APPROVAL  >  ALLOW  >  (closed world) DENY
```

Two properties follow, and the selftest proves both:

- **Order independence.** The decision depends only on the *set* of matching
  effects, never on rule order. Permuting the rules cannot change a verdict
  (checked across all 24 permutations of a four-rule policy).
- **Monotone denial.** Adding a deny rule can only ever make a decision
  stricter; it can never turn a DENY into an ALLOW.

### Provable constraint soundness

Allowing an action by `path_within` proves the action's path cannot escape the
root; allowing by `domain_in` proves the host is genuinely inside the listed
domains. The selftest checks these against real attack classes, not just the
happy path:

- `path_within` rejects `../` traversal, `.` handling, relative paths against
  an absolute root, prefix confusion (`/srv/database` is not inside
  `/srv/data`), and NUL bytes.
- `domain_in` rejects suffix confusion (`example.com.evil.net` never matches
  `*.example.com` or `example.com`), substring confusion (`evil-example.com`
  never matches `example.com`), and IP literals against domain patterns;
  `*.example.com` matches `api.example.com` but not the bare base `example.com`.

### Approval binds to the action, not the tool

A REQUIRE-APPROVAL verdict is lifted only by a human `approve` record whose
`action_digest` equals the digest of the canonical action. Changing a single
argument changes the digest, so a stale approval can never authorise a
different action — one approval for `send.email` does not unlock every email.

### Three evaluators agree

The decision is not believed on faith. Three independent compositions of the
same atomic predicates — the production engine, a set-based reference, and a
boolean normal-form over a match matrix — are checked to agree on every
enumerated case.

## When to use it

- As a **policy decision point** for an AI agent: mediate every tool call
  (http, fs, shell, email, db) before it executes, fail-closed.
- As a **human-in-the-loop gate**: force specific actions (outbound email,
  destructive writes) through an approval that is cryptographically bound to
  the exact action.
- As an **auditable record**: every decision lands in the hash-chained store,
  so a decision made weeks ago can be proved to be that decision.
- As a **policy linter**: `lint` validates a policy and refuses one that is
  not fail-closed (unknown operators, unknown effects, `default != deny`).

## Quick start

```powershell
python agent-gate.py selftest                 # 49 checks: lattice, constraints, audit

# Write a policy (see policy.json for a complete example), then:
python agent-gate.py lint --policy policy.json

python agent-gate.py check --policy policy.json --action action.json
python agent-gate.py explain --policy policy.json --action action.json   # why

# For a REQUIRE-APPROVAL verdict, a human approves the exact action digest:
python agent-gate.py approve --policy policy.json --action action.json --as alice
python agent-gate.py check --policy policy.json --action action.json      # now ALLOW

# Stream a batch of proposed actions (newline-delimited JSON) from an agent:
Get-Content proposed.jsonl | python agent-gate.py check --policy policy.json --stdin

python agent-gate.py stats                    # decisions from the audit store
python agent-gate.py verify                   # prove the chain is untampered
```

The audit store lives at `~/.agentgate/audit.jsonl`, or wherever
`AGENT_GATE_STORE` points, or where `--store` says. The policy is read from
`--policy`, or `AGENT_GATE_POLICY`, or `./policy.json`.

## Policy format

```json
{
  "version": 1,
  "default": "deny",
  "tools": ["http.get", "fs.write", "send.email", "shell.run"],
  "rules": [
    {
      "id": "allow-research-web",
      "effect": "allow",
      "agents": ["researcher"],
      "tool": "http.get",
      "when": {
        "url":  {"domain_in": ["*.corp.example", "example.org"]},
        "method": {"in": ["GET", "HEAD"]}
      }
    },
    {
      "id": "guard-secret-files",
      "effect": "deny",
      "tool": "fs.write",
      "when": { "path": {"suffix": ".pem"} }
    }
  ]
}
```

- `default` **must** be `"deny"` (fail-closed; a policy with any other default
  is refused).
- `tools` declares the tool universe; an action naming an undeclared tool is
  denied.
- A rule may constrain by `agents` (list) and/or `tool` (string), and a `when`
  map of `argument -> predicate`. All `when` conditions are ANDed; an argument
  not listed is unconstrained.
- Effects: `allow`, `deny`, `require-approval`.

Predicates: `eq`, `in`, `prefix`, `suffix`, `contains`, `glob`, `present`,
`num_lt/le/gt/ge`, `len_le/ge`, `domain_in`, `path_within`, plus a `not`
combinator that inverts a predicate. Every predicate fails closed: a missing
argument under a value predicate is false; a non-numeric value under a `num_*`
bound is false.

## Commands

| Command | What it gives you |
|---|---|
| `selftest` | 49 checks: the decision lattice (order independence, monotone denial, three evaluators agreeing), path/domain constraint soundness against attack classes, policy validation, approval binding, audit tamper detection, determinism |
| `check [--action FILE] [--stdin]` | Evaluate an action (or a batch) and append the decision; `--json` for machine-readable output, `--enforce` to exit 1 unless allowed |
| `explain --action FILE` | Show every rule, its match/no-match, and each condition's result — the proof of the verdict |
| `lint` | Validate a policy; refuse one that is not well-formed or not fail-closed |
| `approve --action FILE --as NAME` | Record a human approval bound to the exact action digest |
| `stats` | Decisions, commands and policy digests from the audit store |
| `verify` | Rebuild the hash chain; exit 1 and name the tamper if anything is wrong |

## Fail-closed behaviour

- Unknown commands → exit 2. Missing/malformed/unreadable policy or action,
  unknown operator, unknown effect, duplicate rule id, `default != deny`,
  undeclared tool → exit 1 with a reason, no ledger append.
- `check --enforce` exits 1 unless every action is allowed.
- If the audit chain does not verify *immediately after a write*, the tool
  refuses to report the run rather than record one it cannot evidence.
- Input files (`policy`, `action`) tolerate a Windows BOM (`utf-8-sig`); the
  ledger store stays strict UTF-8 so a BOM cannot mask tampering.

## Audit trail

Each record is `{seq, ts, tool, version, command, policy_digest, action_digest,
decision, reason, matched, prev, hash}` where
`hash = sha256(canonical(record minus hash))`. Record 0's `prev` is a fixed
genesis anchor. `verify` checks three independent things per record — seq
contiguity, prev linkage, and content hash — so it reports *all* problems, not
just the first. Editing a number, deleting the oldest record, and inserting a
forged record are all caught and named.

What it cannot do, stated honestly: trimming the *tail* of the file is not
detectable from inside the file. If that matters, anchor the last hash
externally (log shipper, SIEM, append-only media).

## Verification

| Gate | What it proves | Floor |
|---|---|---|
| `ci/import_gate.py` | zero third-party imports anywhere | — |
| `selftest` | decision lattice, constraint soundness, policy validation, approval binding, audit, determinism | 49 checks |
| `tests/test_agent_gate.py` | real CLI behaviour over subprocesses | 39 tests |
| `ci/prove_suites_can_fail.py` | the suites fail when the code breaks and pass when restored | — |
| `ci/mutation.py` | 11 real mutants killed, semantically-identical canary survives | 12 rows |

Run them locally from the repo root:

```powershell
python ci/import_gate.py
python agent-gate.py selftest
python tests/test_agent_gate.py
python ci/prove_suites_can_fail.py
python ci/mutation.py
```

The mutation sweep works on a scratch copy — the live `agent-gate.py` is hashed
before and after, so a sweep can never leave a mutant behind in the repo.
