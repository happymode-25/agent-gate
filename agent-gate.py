#!/usr/bin/env python3
"""agent-gate -- a fail-closed capability broker for AI-agent tool calls.

An AI agent proposes an action (``{"tool": ..., "args": {...}, "agent": ...}``).
agent-gate decides ALLOW / DENY / REQUIRE-APPROVAL against a declarative policy,
explains exactly which rules matched, and appends every decision to a
hash-chained audit ledger.

Security stance (the whole point)
---------------------------------
The world is closed and denial is the default.  An action that matches no rule
is DENIED.  A policy whose ``default`` is anything other than ``deny`` is
rejected outright -- there is no "fail open" switch.  Malformed actions,
malformed policies, unknown operators/effects and unknown tools all resolve to
DENY (or to a refusal to run), never to an accidental ALLOW.

Decision lattice
----------------
Every matching rule contributes an effect.  Effects compose in a fixed lattice::

    DENY  >  REQUIRE-APPROVAL  >  ALLOW  >  (closed world) DENY

Two properties follow, and are checked in ``selftest``:

* **Order independence** -- the decision depends only on the *set* of matching
  effects, never on rule order.  Permuting the rules cannot change a verdict.
* **Monotone denial** -- adding a deny rule can only ever make a decision
  stricter; it can never turn a DENY into an ALLOW.

Approval binds to the exact action.  A REQUIRE-APPROVAL verdict is only lifted
by a human ``approve`` record whose ``action_digest`` equals the digest of the
*canonical* action.  Changing a single argument changes the digest, so a stale
approval can never authorise a different action.

Constraint soundness.  Allowing an action by ``path_within`` proves the action's
path cannot escape the root (``../`` traversal, ``.`` handling, relative paths
and prefix confusion are all rejected).  Allowing by ``domain_in`` proves the
host is genuinely inside the listed domains (no ``example.com.evil.net`` suffix
confusion, no ``evil-example.com`` substring confusion, no ``*.example.com``
matching the bare base).  These are checked against real attack classes.

Hashing.  The ledger chains records with SHA-256 over a canonical JSON encoding
(sorted keys, no whitespace, UTF-8).  Each record links to the previous hash and
the first record links to a fixed genesis anchor.  Every append is re-verified
immediately after writing; the tool refuses to report a run it cannot evidence.
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import sys
import tempfile
import time

VERSION = "1.0.0"
TOOL = "agent-gate"

# Fixed genesis anchor: the "prev" of the first record in a store.
GENESIS = "0" * 64

# Default store / policy locations.
STORE_DIR = ".agentgate"
STORE_FILE = "audit.jsonl"
DEFAULT_POLICY = "policy.json"

EFFECTS = ("allow", "deny", "require-approval")


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class GateError(Exception):
    """Base class for fail-closed errors."""


class PolicyError(GateError):
    """The policy is missing, unreadable or invalid.  Fail closed."""


class ActionError(GateError):
    """The proposed action is missing, unreadable or malformed.  Fail closed."""


class StoreError(GateError):
    """The audit ledger is unreadable, does not verify, or cannot be written."""


# ---------------------------------------------------------------------------
# Canonical encoding and hashing
# ---------------------------------------------------------------------------

def canonical(obj) -> bytes:
    """Canonical JSON bytes: sorted keys, no insignificant whitespace, UTF-8."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def digest(obj) -> str:
    """SHA-256 hex digest of the canonical encoding of ``obj``."""
    return hashlib.sha256(canonical(obj)).hexdigest()


def normalize_action(action: dict) -> dict:
    """The canonical, approval-bound view of an action."""
    return {
        "tool": action.get("tool"),
        "agent": action.get("agent", ""),
        "args": action.get("args", {}),
    }


def action_digest(action: dict) -> str:
    return digest(normalize_action(action))


# ---------------------------------------------------------------------------
# Audit ledger
# ---------------------------------------------------------------------------

def store_path(args) -> str:
    p = getattr(args, "store", None) or os.environ.get("AGENT_GATE_STORE")
    if not p:
        p = os.path.join(os.path.expanduser("~"), STORE_DIR, STORE_FILE)
    return p


def policy_path(args) -> str:
    p = getattr(args, "policy", None) or os.environ.get("AGENT_GATE_POLICY")
    if not p:
        p = os.path.join(os.getcwd(), DEFAULT_POLICY)
    return p


def load_store(path: str):
    """Read a ledger into a list of records.  A malformed line is a StoreError."""
    records = []
    if not os.path.exists(path):
        return records
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for i, line in enumerate(fh):
                line = line.strip()
                if not line:
                    continue
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError as exc:
                    raise StoreError(
                        "record %d in %s is not valid JSON: %s" % (i, path, exc))
    except OSError as exc:
        raise StoreError("cannot read store %s: %s" % (path, exc))
    return records


def verify_records(records):
    """Return (ok, message).  Checks seq, prev linkage, genesis and hashes."""
    prev = GENESIS
    for i, rec in enumerate(records):
        if not isinstance(rec, dict):
            return False, "record %d is not an object" % i
        if rec.get("seq") != i:
            return False, "record %d has seq %r, expected %d" % (i, rec.get("seq"), i)
        if rec.get("prev") != prev:
            return False, ("record %d prev %s does not link to %s"
                           % (i, str(rec.get("prev"))[:12], prev[:12]))
        body = {k: v for k, v in rec.items() if k != "hash"}
        if rec.get("hash") != digest(body):
            return False, "record %d hash mismatch (chain is broken here)" % i
        prev = rec["hash"]
    return True, "chain ok (%d record%s)" % (len(records), "" if len(records) == 1 else "s")


def append_record(path: str, record: dict) -> dict:
    """Append a record, re-verifying the whole store first and afterwards."""
    records = load_store(path)
    ok, msg = verify_records(records)
    if not ok:
        raise StoreError("refusing to append to a store that does not verify: " + msg)
    prev = records[-1]["hash"] if records else GENESIS
    full = dict(record)
    full["seq"] = len(records)
    full["prev"] = prev
    full["ts"] = int(time.time())
    full["tool"] = TOOL
    full["version"] = VERSION
    full["hash"] = digest({k: v for k, v in full.items() if k != "hash"})
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    try:
        with open(path, "a", encoding="utf-8", newline="\n") as fh:
            fh.write(json.dumps(full, sort_keys=True, ensure_ascii=False) + "\n")
    except OSError as exc:
        raise StoreError("cannot write store %s: %s" % (path, exc))
    ok, msg = verify_records(load_store(path))
    if not ok:
        raise StoreError("post-write verification failed: " + msg)
    return full


def approvals_from_records(records):
    """The set of action digests with a human approval record."""
    approved = set()
    for rec in records:
        if rec.get("command") == "approve" and isinstance(rec.get("action_digest"), str):
            approved.add(rec["action_digest"])
    return frozenset(approved)


# ---------------------------------------------------------------------------
# Predicate helpers: paths and domains (security-critical)
# ---------------------------------------------------------------------------

def normalize_path(path):
    """POSIX-normalise a path: collapse ``.`` and ``..``.  None if unrunnable."""
    if not isinstance(path, str) or "\x00" in path:
        return None
    absolute = path.startswith("/")
    comps = []
    for comp in path.replace("\\", "/").split("/"):
        if comp == "" or comp == ".":
            continue
        if comp == "..":
            if comps and comps[-1] != "..":
                comps.pop()
            else:
                comps.append("..")
        else:
            comps.append(comp)
    out = "/".join(comps)
    if absolute:
        out = "/" + out
    return out


def path_within(path, root):
    """True iff ``path`` is the root or lies strictly beneath it.

    Rejects traversal (``../``), relative paths against an absolute root,
    prefix confusion (``/srv/database`` is not inside ``/srv/data``) and NUL
    bytes.  A root of ``/`` admits any absolute path (lint warns about it).
    """
    p = normalize_path(path)
    r = normalize_path(root)
    if p is None or r is None:
        return False
    if r == "/":
        return p.startswith("/")
    if p == r:
        return True
    return p.startswith(r.rstrip("/") + "/")


_HOST_CHARS = set("abcdefghijklmnopqrstuvwxyz0123456789.-")
_IPV6_CHARS = set("abcdefghijklmnopqrstuvwxyz0123456789:.")


def extract_host(raw):
    """Extract a lowercase host from a URL or bare host.  None if not a host."""
    if not isinstance(raw, str):
        return None
    s = raw.strip()
    if not s:
        return None
    rest = s.split("://", 1)[1] if "://" in s else s
    for sep in ("/", "?", "#"):
        idx = rest.find(sep)
        if idx != -1:
            rest = rest[:idx]
    if "@" in rest:
        rest = rest.rsplit("@", 1)[1]
    if rest.startswith("["):  # IPv6 literal
        end = rest.find("]")
        if end == -1:
            return None
        host = rest[1:end].lower()
        return host if host and set(host) <= _IPV6_CHARS else None
    if ":" in rest:
        host, port = rest.rsplit(":", 1)
        if port.isdigit():
            rest = host
        else:
            return None
    host = rest.lower()
    if host.endswith("."):
        host = host[:-1]
    if not host or not set(host) <= _HOST_CHARS:
        return None
    return host


def host_matches(host, pattern):
    """Label-boundary host match.  ``*.a.b`` matches ``x.a.b`` but not ``a.b``."""
    if not host or not pattern:
        return False
    pattern = pattern.lower()
    labels = host.split(".")
    plabels = pattern.split(".")
    if plabels and plabels[0] == "*":
        base = plabels[1:]
        if not base:
            return False
        if len(labels) < len(base) + 1:
            return False
        return labels[len(labels) - len(base):] == base
    return labels == plabels


def host_matches_any(raw, patterns):
    host = extract_host(raw)
    if host is None:
        return False
    return any(host_matches(host, pat) for pat in patterns)


# ---------------------------------------------------------------------------
# Predicates
# ---------------------------------------------------------------------------

def _is_num(v):
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _v_any(_p):
    return None


def _v_str(p):
    return None if isinstance(p, str) else "requires a string argument"


def _v_bool(p):
    return None if isinstance(p, bool) else "requires a boolean argument"


def _v_num(p):
    return None if _is_num(p) else "requires a numeric argument"


def _v_nonneg_int(p):
    if isinstance(p, int) and not isinstance(p, bool) and p >= 0:
        return None
    return "requires a non-negative integer argument"


def _v_list(p):
    return None if isinstance(p, list) else "requires a list argument"


def _v_strlist(p):
    if isinstance(p, list) and all(isinstance(x, str) for x in p):
        return None
    return "requires a list-of-strings argument"


def _f_eq(v, p, present):
    return present and canonical(v) == canonical(p)


def _f_in(v, p, present):
    return present and any(canonical(v) == canonical(x) for x in p)


def _f_prefix(v, p, present):
    return present and isinstance(v, str) and v.startswith(p)


def _f_suffix(v, p, present):
    return present and isinstance(v, str) and v.endswith(p)


def _f_contains(v, p, present):
    return present and isinstance(v, str) and p in v


def _f_glob(v, p, present):
    return present and isinstance(v, str) and fnmatch.fnmatchcase(v, p)


def _f_present(v, p, present):
    return present == bool(p)


def _f_num_lt(v, p, present):
    return present and _is_num(v) and v < p


def _f_num_le(v, p, present):
    return present and _is_num(v) and v <= p


def _f_num_gt(v, p, present):
    return present and _is_num(v) and v > p


def _f_num_ge(v, p, present):
    return present and _is_num(v) and v >= p


def _f_len_le(v, p, present):
    return present and isinstance(v, (str, list)) and len(v) <= p


def _f_len_ge(v, p, present):
    return present and isinstance(v, (str, list)) and len(v) >= p


def _f_domain_in(v, p, present):
    return present and isinstance(v, str) and host_matches_any(v, p)


def _f_path_within(v, p, present):
    return present and isinstance(v, str) and path_within(v, p)


PREDICATES = {
    "eq": {"param": _v_any, "fn": _f_eq},
    "in": {"param": _v_list, "fn": _f_in},
    "prefix": {"param": _v_str, "fn": _f_prefix},
    "suffix": {"param": _v_str, "fn": _f_suffix},
    "contains": {"param": _v_str, "fn": _f_contains},
    "glob": {"param": _v_str, "fn": _f_glob},
    "present": {"param": _v_bool, "fn": _f_present},
    "num_lt": {"param": _v_num, "fn": _f_num_lt},
    "num_le": {"param": _v_num, "fn": _f_num_le},
    "num_gt": {"param": _v_num, "fn": _f_num_gt},
    "num_ge": {"param": _v_num, "fn": _f_num_ge},
    "len_le": {"param": _v_nonneg_int, "fn": _f_len_le},
    "len_ge": {"param": _v_nonneg_int, "fn": _f_len_ge},
    "domain_in": {"param": _v_strlist, "fn": _f_domain_in},
    "path_within": {"param": _v_str, "fn": _f_path_within},
}

# A deliberately separate implementation of the same operators, used by the
# reference evaluator.  The two must agree on every enumerated case.
_REF_PREDICATES = {
    "eq": lambda v, p, present: bool(present) and canonical(v) == canonical(p),
    "in": lambda v, p, present: bool(present) and canonical(v) in [canonical(x) for x in p],
    "prefix": lambda v, p, present: bool(present) and isinstance(v, str) and v[:len(p)] == p,
    "suffix": lambda v, p, present: bool(present) and isinstance(v, str) and (p == v[len(v) - len(p):] if len(p) <= len(v) else False),
    "contains": lambda v, p, present: bool(present) and isinstance(v, str) and v.find(p) != -1,
    "glob": lambda v, p, present: bool(present) and isinstance(v, str) and fnmatch.fnmatchcase(v, p),
    "present": lambda v, p, present: bool(present) == bool(p),
    "num_lt": lambda v, p, present: bool(present) and _is_num(v) and not (v >= p),
    "num_le": lambda v, p, present: bool(present) and _is_num(v) and not (v > p),
    "num_gt": lambda v, p, present: bool(present) and _is_num(v) and not (v <= p),
    "num_ge": lambda v, p, present: bool(present) and _is_num(v) and not (v < p),
    "len_le": lambda v, p, present: bool(present) and isinstance(v, (str, list)) and len(v) - p <= 0,
    "len_ge": lambda v, p, present: bool(present) and isinstance(v, (str, list)) and len(v) - p >= 0,
    "domain_in": lambda v, p, present: bool(present) and isinstance(v, str) and host_matches_any(v, p),
    "path_within": lambda v, p, present: bool(present) and isinstance(v, str) and path_within(v, p),
}


def validate_predicate(pred, where):
    """Return an error string, or None if the predicate object is well-formed."""
    if not isinstance(pred, dict):
        return where + ": predicate must be an object"
    if len(pred) != 1:
        return where + ": predicate must have exactly one operator"
    op, param = next(iter(pred.items()))
    if op == "not":
        return validate_predicate(param, where + ".not")
    if op not in PREDICATES:
        return where + ": unknown operator %r" % op
    err = PREDICATES[op]["param"](param)
    if err:
        return where + ": operator %r %s" % (op, err)
    return None


def eval_arg_predicate(pred, value, present, ref=False):
    op, param = next(iter(pred.items()))
    if op == "not":
        return not eval_arg_predicate(param, value, present, ref=ref)
    table = _REF_PREDICATES if ref else {k: v["fn"] for k, v in PREDICATES.items()}
    return table[op](value, param, present)


# ---------------------------------------------------------------------------
# Rules and policy
# ---------------------------------------------------------------------------

RULE_KEYS = {"id", "effect", "agents", "tool", "when"}
POLICY_KEYS = {"version", "default", "tools", "rules"}


def _check_policy(pol):
    """Return (normalized_policy, errors, warnings).  Never raises."""
    errors = []
    warnings = []
    if not isinstance(pol, dict):
        return None, ["policy must be a JSON object"], warnings
    unknown = set(pol) - POLICY_KEYS
    if unknown:
        errors.append("unknown top-level key(s): %s" % ", ".join(sorted(unknown)))
    if pol.get("default") != "deny":
        errors.append("policy 'default' must be \"deny\" (fail-closed); found %r"
                      % pol.get("default"))
    tools = pol.get("tools", [])
    if not isinstance(tools, list) or not all(isinstance(t, str) for t in tools):
        errors.append("'tools' must be a list of strings")
        tools = []
    rules = pol.get("rules", [])
    if not isinstance(rules, list):
        errors.append("'rules' must be a list")
        rules = []
    seen_ids = set()
    norm_rules = []
    for i, rule in enumerate(rules):
        where = "rule %d" % i
        if not isinstance(rule, dict):
            errors.append(where + ": must be an object")
            continue
        rid = rule.get("id")
        if not isinstance(rid, str) or not rid:
            errors.append(where + ": needs a non-empty string 'id'")
        elif rid in seen_ids:
            errors.append(where + ": duplicate rule id %r" % rid)
        else:
            seen_ids.add(rid)
            where = "rule %r" % rid
        unknown = set(rule) - RULE_KEYS
        if unknown:
            errors.append(where + ": unknown key(s): %s" % ", ".join(sorted(unknown)))
        effect = rule.get("effect")
        if effect not in EFFECTS:
            errors.append(where + ": effect must be one of %s; found %r"
                          % (", ".join(EFFECTS), effect))
        if "agents" in rule:
            ag = rule["agents"]
            if not isinstance(ag, list) or not all(isinstance(a, str) for a in ag):
                errors.append(where + ": 'agents' must be a list of strings")
        if "tool" in rule:
            tl = rule["tool"]
            if not isinstance(tl, str):
                errors.append(where + ": 'tool' must be a string")
            elif tools and tl not in tools:
                errors.append(where + ": tool %r is not declared in 'tools'" % tl)
        when = rule.get("when", {})
        if not isinstance(when, dict):
            errors.append(where + ": 'when' must be an object")
            when = {}
        for argname, pred in when.items():
            if not isinstance(argname, str):
                errors.append(where + ": argument names in 'when' must be strings")
                continue
            err = validate_predicate(pred, "%s.when.%s" % (where, argname))
            if err:
                errors.append(err)
        if effect == "allow" and not when and "tool" not in rule:
            warnings.append(where + ": allow rule matches every tool and every "
                                   "argument (very broad)")
        elif effect == "allow" and "tool" not in rule:
            warnings.append(where + ": allow rule applies to all declared tools")
        norm_rules.append(rule)
    if not errors:
        # The digest covers only the policy as authored -- not the internal
        # _tools set -- so it is a stable fingerprint of the source policy.
        source = {
            "version": pol.get("version", 1),
            "default": "deny",
            "tools": list(tools),
            "rules": norm_rules,
        }
        normalized = {
            "version": source["version"],
            "default": "deny",
            "tools": list(tools),
            "_tools": frozenset(tools),
            "rules": norm_rules,
            "_digest": digest(source),
        }
        return normalized, [], warnings
    return None, errors, warnings


def load_policy(path):
    try:
        # utf-8-sig tolerates a Windows BOM on hand-authored input files; it is
        # identical to utf-8 when no BOM is present.
        with open(path, "r", encoding="utf-8-sig") as fh:
            raw = fh.read()
    except OSError as exc:
        raise PolicyError("cannot read policy %s: %s" % (path, exc))
    try:
        pol = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise PolicyError("policy %s is not valid JSON: %s" % (path, exc))
    normalized, errors, _warnings = _check_policy(pol)
    if errors:
        raise PolicyError("policy %s is invalid: %s" % (path, "; ".join(errors)))
    return normalized


# ---------------------------------------------------------------------------
# Actions
# ---------------------------------------------------------------------------

ACTION_KEYS = {"tool", "args", "agent"}


def parse_action(obj):
    if not isinstance(obj, dict):
        raise ActionError("action must be a JSON object")
    unknown = set(obj) - ACTION_KEYS
    if unknown:
        raise ActionError("action has unknown key(s): %s" % ", ".join(sorted(unknown)))
    tool = obj.get("tool")
    if not isinstance(tool, str) or not tool:
        raise ActionError("action needs a non-empty string 'tool'")
    if "args" in obj and not isinstance(obj["args"], dict):
        raise ActionError("action 'args' must be an object")
    if "agent" in obj and not isinstance(obj["agent"], str):
        raise ActionError("action 'agent' must be a string")
    return {"tool": tool, "args": obj.get("args", {}), "agent": obj.get("agent", "")}


# ---------------------------------------------------------------------------
# Rule evaluation and decisions
# ---------------------------------------------------------------------------

def rule_matches(rule, action, ref=False):
    """(matched, detail) where detail lists per-condition results for explain."""
    detail = []
    if "agents" in rule:
        ok = action.get("agent", "") in rule["agents"]
        detail.append(("agent", "in", ok))
        if not ok:
            return False, detail
    if "tool" in rule:
        ok = action.get("tool") == rule["tool"]
        detail.append(("tool", "eq", ok))
        if not ok:
            return False, detail
    args = action.get("args", {})
    if not isinstance(args, dict):
        args = {}
    for argname, pred in rule.get("when", {}).items():
        present = argname in args
        value = args.get(argname)
        ok = eval_arg_predicate(pred, value, present, ref=ref)
        detail.append((argname, _op_name(pred), ok))
        if not ok:
            return False, detail
    return True, detail


def _op_name(pred):
    """A human label for a (possibly negated) predicate."""
    op = next(iter(pred))
    if op == "not":
        return "not(" + _op_name(pred["not"]) + ")"
    return op


def decide(policy, action, approvals=frozenset()):
    """The production evaluator.  Returns a decision dict."""
    tool = action.get("tool")
    if tool not in policy["_tools"]:
        return {"effect": "deny", "default": False, "matched": [],
                "reason": "tool %r is not declared by the policy" % tool,
                "unknown_tool": True}
    effects = []
    matched = []
    for rule in policy["rules"]:
        ok, _detail = rule_matches(rule, action)
        if ok:
            effects.append(rule["effect"])
            matched.append(rule["id"])
    if "deny" in effects:
        rid = matched[effects.index("deny")]
        return {"effect": "deny", "default": False, "matched": matched,
                "reason": "denied by rule %r" % rid}
    if "require-approval" in effects:
        rid = matched[effects.index("require-approval")]
        ad = action_digest(action)
        if ad in approvals:
            return {"effect": "allow", "default": False, "matched": matched,
                    "approved": True,
                    "reason": "approved by a human record for action digest %s "
                              "(rule %r)" % (ad[:12], rid)}
        return {"effect": "require-approval", "default": False, "matched": matched,
                "reason": "approval required by rule %r; no approval on record "
                          "for action digest %s" % (rid, ad[:12])}
    if "allow" in effects:
        rid = matched[effects.index("allow")]
        return {"effect": "allow", "default": False, "matched": matched,
                "reason": "allowed by rule %r" % rid}
    return {"effect": "deny", "default": True, "matched": matched,
            "reason": "no rule matched; the closed world denies by default"}


def decide_reference(policy, action, approvals=frozenset()):
    """Independent composition via explicit effect sets.  Returns an effect."""
    tool = action.get("tool")
    if tool not in policy["_tools"]:
        return "deny"
    denies, approvals_rules, allows = [], [], []
    for rule in policy["rules"]:
        ok, _detail = rule_matches(rule, action, ref=True)
        if not ok:
            continue
        if rule["effect"] == "deny":
            denies.append(rule["id"])
        elif rule["effect"] == "require-approval":
            approvals_rules.append(rule["id"])
        else:
            allows.append(rule["id"])
    if denies:
        return "deny"
    if approvals_rules:
        return "allow" if action_digest(action) in approvals else "require-approval"
    if allows:
        return "allow"
    return "deny"


def decide_normal_form(policy, action, approvals=frozenset()):
    """Boolean-algebra composition over a precomputed match matrix."""
    tool = action.get("tool")
    if tool not in policy["_tools"]:
        return "deny"
    deny = approval = allow = False
    for rule in policy["rules"]:
        ok, _detail = rule_matches(rule, action)
        if not ok:
            continue
        deny = deny or (rule["effect"] == "deny")
        approval = approval or (rule["effect"] == "require-approval")
        allow = allow or (rule["effect"] == "allow")
    if deny:
        return "deny"
    if approval:
        return "allow" if action_digest(action) in approvals else "require-approval"
    if allow:
        return "allow"
    return "deny"


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def _read_json_file(path, what):
    try:
        with open(path, "r", encoding="utf-8-sig") as fh:
            raw = fh.read()
    except OSError as exc:
        raise ActionError("cannot read %s %s: %s" % (what, path, exc))
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ActionError("%s %s is not valid JSON: %s" % (what, path, exc))


def _emit_human(action, decision, pd, ad, store, seq):
    print("%s %s" % (TOOL, VERSION))
    print("  tool          : %s" % action["tool"])
    print("  agent         : %s" % (action.get("agent", "") or "(anonymous)"))
    print("  decision      : %s" % decision["effect"].upper())
    print("  reason        : %s" % decision["reason"])
    print("  matched       : %s" % (", ".join(decision["matched"]) or "(none)"))
    print("  action digest : %s" % ad)
    print("  policy digest : %s" % pd)
    print("  recorded      : seq %d in %s" % (seq, os.path.abspath(store)))


def _emit_json(action, decision, pd, ad, seq):
    print(json.dumps({
        "tool": action["tool"],
        "agent": action.get("agent", ""),
        "decision": decision["effect"],
        "reason": decision["reason"],
        "matched": decision["matched"],
        "action_digest": ad,
        "policy_digest": pd,
        "seq": seq,
    }, sort_keys=True, ensure_ascii=False))


def cmd_check(args):
    policy = load_policy(policy_path(args))
    pd = policy["_digest"]
    store = store_path(args)
    records = load_store(store)
    ok, msg = verify_records(records)
    if not ok:
        print("%s: error: audit store does not verify: %s" % (TOOL, msg), file=sys.stderr)
        return 1
    approvals = approvals_from_records(records)

    actions = []
    if getattr(args, "stdin", False):
        if sys.stdin.isatty():
            print("%s: error: --stdin expects piped actions" % TOOL, file=sys.stderr)
            return 2
        for i, line in enumerate(sys.stdin):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as exc:
                print("%s: error: stdin line %d is not valid JSON: %s"
                      % (TOOL, i + 1, exc), file=sys.stderr)
                return 1
            actions.append(parse_action(obj))
    elif getattr(args, "action", None):
        actions.append(parse_action(_read_json_file(args.action, "action")))
    else:
        print("%s: error: check needs --action FILE or --stdin" % TOOL, file=sys.stderr)
        return 2

    counts = {}
    worst = 0
    for action in actions:
        decision = decide(policy, action, approvals)
        ad = action_digest(action)
        counts[decision["effect"]] = counts.get(decision["effect"], 0) + 1
        if decision["effect"] != "allow":
            worst = 1
        full = append_record(store, {
            "command": "check",
            "policy_digest": pd,
            "action_digest": ad,
            "tool_name": action["tool"],
            "agent": action.get("agent", ""),
            "decision": decision["effect"],
            "reason": decision["reason"],
            "matched": decision["matched"],
        })
        if getattr(args, "json", False):
            _emit_json(action, decision, pd, ad, full["seq"])
        else:
            _emit_human(action, decision, pd, ad, store, full["seq"])
            print("")

    if len(actions) > 1:
        print("%s: %d action(s): %s" % (
            TOOL, len(actions),
            ", ".join("%s=%d" % (k, v) for k, v in sorted(counts.items()))),
            file=sys.stderr)
    if getattr(args, "enforce", False) and worst:
        return 1
    return 0


def cmd_explain(args):
    policy = load_policy(policy_path(args))
    action = parse_action(_read_json_file(args.action, "action"))
    store = store_path(args)
    records = load_store(store)
    ok, msg = verify_records(records)
    if not ok:
        print("%s: error: audit store does not verify: %s" % (TOOL, msg), file=sys.stderr)
        return 1
    approvals = approvals_from_records(records)
    ad = action_digest(action)
    print("%s %s -- explain" % (TOOL, VERSION))
    print("  tool          : %s" % action["tool"])
    print("  agent         : %s" % (action.get("agent", "") or "(anonymous)"))
    print("  action digest : %s" % ad)
    print("  policy digest : %s" % policy["_digest"])
    print("  rules:")
    for rule in policy["rules"]:
        ok, detail = rule_matches(rule, action)
        conds = ", ".join("%s %s%s" % (a, op, "" if good else " [NO]")
                          for a, op, good in detail) or "(no conditions)"
        print("    %-24s %-16s %s  %s" % (
            rule["id"], rule["effect"], "match" if ok else "no   ", conds))
    decision = decide(policy, action, approvals)
    print("  decision      : %s" % decision["effect"].upper())
    print("  reason        : %s" % decision["reason"])
    return 0


def cmd_lint(args):
    path = policy_path(args)
    try:
        with open(path, "r", encoding="utf-8-sig") as fh:
            raw = fh.read()
    except OSError as exc:
        print("%s: error: cannot read policy %s: %s" % (TOOL, path, exc), file=sys.stderr)
        return 1
    try:
        pol = json.loads(raw)
    except json.JSONDecodeError as exc:
        print("%s: error: policy %s is not valid JSON: %s" % (TOOL, path, exc),
              file=sys.stderr)
        return 1
    normalized, errors, warnings = _check_policy(pol)
    print("%s %s -- policy lint: %s" % (TOOL, VERSION, path))
    rules = pol.get("rules", []) if isinstance(pol, dict) else []
    print("  rules         : %s" % (len(rules) if isinstance(rules, list) else "?"))
    print("  default       : %s" % (pol.get("default") if isinstance(pol, dict) else "?"))
    tools = pol.get("tools", []) if isinstance(pol, dict) else []
    if isinstance(tools, list):
        print("  tools declared: %s" % (", ".join(tools) or "(none)"))
    for w in warnings:
        print("  warning       : %s" % w)
    for e in errors:
        print("  error         : %s" % e)
    if errors:
        print("  result        : INVALID (%d error%s)" % (len(errors), "" if len(errors) == 1 else "s"))
        return 1
    print("  result        : ok (well-formed and fail-closed)")
    return 0


def cmd_approve(args):
    policy = load_policy(policy_path(args))
    action = parse_action(_read_json_file(args.action, "action"))
    store = store_path(args)
    records = load_store(store)
    ok, msg = verify_records(records)
    if not ok:
        print("%s: error: audit store does not verify: %s" % (TOOL, msg), file=sys.stderr)
        return 1
    decision = decide(policy, action, approvals_from_records(records))
    ad = action_digest(action)
    if decision["effect"] != "require-approval":
        print("%s: warning: action does not currently require approval "
              "(decision %s); recording the approval anyway"
              % (TOOL, decision["effect"].upper()), file=sys.stderr)
    who = getattr(args, "as_", None) or os.environ.get("USER") or "operator"
    full = append_record(store, {
        "command": "approve",
        "policy_digest": policy["_digest"],
        "action_digest": ad,
        "tool_name": action["tool"],
        "as": who,
        "decision": "approve",
        "reason": "human approval recorded by %s" % who,
    })
    print("%s: recorded approval for action digest %s (by %s, seq %d)"
          % (TOOL, ad, who, full["seq"]))
    return 0


def cmd_stats(args):
    store = store_path(args)
    records = load_store(store)
    ok, msg = verify_records(records)
    if not ok:
        print("%s: error: audit store does not verify: %s" % (TOOL, msg), file=sys.stderr)
        return 1
    counts = {}
    commands = {}
    policies = set()
    first = last = None
    for rec in records:
        counts[rec.get("decision", "?")] = counts.get(rec.get("decision", "?"), 0) + 1
        commands[rec.get("command", "?")] = commands.get(rec.get("command", "?"), 0) + 1
        if rec.get("policy_digest"):
            policies.add(rec["policy_digest"])
        if first is None:
            first = rec.get("ts")
        last = rec.get("ts")
    print("%s %s -- audit stats: %s" % (TOOL, VERSION, os.path.abspath(store)))
    print("  records       : %d" % len(records))
    print("  %s" % msg)
    print("  decisions     : %s" % (", ".join("%s=%d" % (k, v) for k, v in sorted(counts.items())) or "(none)"))
    print("  commands      : %s" % (", ".join("%s=%d" % (k, v) for k, v in sorted(commands.items())) or "(none)"))
    print("  policy digests: %d distinct" % len(policies))
    if first is not None:
        print("  first         : %s" % time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(first)))
        print("  last          : %s" % time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(last)))
    return 0


def cmd_verify(args):
    store = store_path(args)
    records = load_store(store)
    ok, msg = verify_records(records)
    print("%s %s -- verify: %s" % (TOOL, VERSION, os.path.abspath(store)))
    print("  %s: %s" % ("ok" if ok else "FAIL", msg))
    return 0 if ok else 1


# ---------------------------------------------------------------------------
# Selftest
# ---------------------------------------------------------------------------

def _pol(rules, tools=("t",)):
    normalized, errors, _warnings = _check_policy(
        {"version": 1, "default": "deny", "tools": list(tools), "rules": rules})
    assert not errors, errors
    return normalized


def _act(tool="t", **args):
    return {"tool": tool, "args": args, "agent": args.pop("agent", "") if "agent" in args else "a1"}


def _action(tool="t", agent="a1", args=None):
    return {"tool": tool, "agent": agent, "args": args or {}}


def selftest():
    checks = []

    def ck(name, cond):
        checks.append((name, bool(cond)))

    # --- decision lattice -------------------------------------------------
    p_empty = _pol([])
    a = _action("t", args={"x": 1})
    d = decide(p_empty, a)
    ck("closed world: no rule matched -> default deny",
       d["effect"] == "deny" and d["default"] is True)

    p_allow = _pol([{"id": "a1", "effect": "allow", "tool": "t"}])
    ck("a single matching allow rule yields allow",
       decide(p_allow, a)["effect"] == "allow")

    p_deny_top = _pol([
        {"id": "a1", "effect": "allow", "tool": "t"},
        {"id": "d1", "effect": "deny", "tool": "t", "when": {"x": {"eq": 1}}},
    ])
    ck("deny overrides allow",
       decide(p_deny_top, a)["effect"] == "deny")

    p_appr = _pol([
        {"id": "a1", "effect": "allow", "tool": "t"},
        {"id": "p1", "effect": "require-approval", "tool": "t",
         "when": {"x": {"eq": 1}}},
    ])
    ck("require-approval overrides allow (no approval)",
       decide(p_appr, a)["effect"] == "require-approval")
    ck("a human approval lifts require-approval to allow",
       decide(p_appr, a, frozenset({action_digest(a)}))["effect"] == "allow")
    ck("an approval for a different action does not authorise",
       decide(p_appr, a, frozenset({digest({"nope": 1})}))["effect"] == "require-approval")

    p_deny_appr = _pol([
        {"id": "p1", "effect": "require-approval", "tool": "t"},
        {"id": "d1", "effect": "deny", "tool": "t"},
    ])
    ck("deny overrides require-approval even when approved",
       decide(p_deny_appr, a, frozenset({action_digest(a)}))["effect"] == "deny")

    # order independence
    import itertools
    rules = [
        {"id": "a1", "effect": "allow", "tool": "t"},
        {"id": "d1", "effect": "deny", "tool": "t", "when": {"x": {"eq": 1}}},
        {"id": "p1", "effect": "require-approval", "tool": "t",
         "when": {"y": {"num_gt": 0}}},
        {"id": "a2", "effect": "allow", "tool": "t", "when": {"x": {"eq": 2}}},
    ]
    base = decide(_pol(rules), a)["effect"]
    same = all(decide(_pol(list(perm)), a)["effect"] == base
               for perm in itertools.permutations(rules))
    ck("rule order does not change the decision (24 permutations)", same)

    # three evaluators agree
    actions = []
    for xv in (1, 2, 3):
        for yv in (0, 5):
            for ag in ("a1", "a2"):
                actions.append(_action("t", agent=ag, args={"x": xv, "y": yv}))
    approvals = frozenset({action_digest(actions[0])})
    agree = True
    for act in actions:
        e = decide(_pol(rules), act, approvals)["effect"]
        r = decide_reference(_pol(rules), act, approvals)
        n = decide_normal_form(_pol(rules), act, approvals)
        if not (e == r == n):
            agree = False
    ck("engine, reference and normal-form evaluators agree on every case", agree)

    # monotone denial: adding a deny rule never loosens
    loose = [
        {"id": "a1", "effect": "allow", "tool": "t"},
        {"id": "p1", "effect": "require-approval", "tool": "t",
         "when": {"x": {"eq": 2}}},
    ]
    extra_denies = [
        {"id": "d1", "effect": "deny", "tool": "t", "when": {"x": {"eq": 1}}},
        {"id": "d2", "effect": "deny", "tool": "t", "when": {"y": {"num_gt": 0}}},
        {"id": "d3", "effect": "deny", "tool": "t"},
    ]
    rank = {"allow": 2, "require-approval": 1, "deny": 0}
    monotone = True
    for extra in extra_denies:
        before = decide(_pol(loose), a, approvals)["effect"]
        after = decide(_pol(loose + [extra]), a, approvals)["effect"]
        if rank[after] > rank[before]:
            monotone = False
    ck("monotone denial: adding a deny rule never loosens a decision", monotone)

    # determinism
    d1 = decide(_pol(rules), a, approvals)
    d2 = decide(_pol(rules), a, approvals)
    ck("determinism: identical inputs give identical decision and digest",
       (d1["effect"], d1["reason"], action_digest(a))
       == (d2["effect"], d2["reason"], action_digest(a)))

    # --- path_within ------------------------------------------------------
    ck("path_within allows a nested path",
       path_within("/srv/data/x/y.txt", "/srv/data"))
    ck("path_within allows the root itself",
       path_within("/srv/data", "/srv/data"))
    ck("path_within rejects ../ traversal",
       not path_within("/srv/data/../../etc/passwd", "/srv/data"))
    ck("path_within rejects encoded-ish traversal after normalisation",
       not path_within("/srv/data/./../secret", "/srv/data"))
    ck("path_within rejects a relative path against an absolute root",
       not path_within("srv/data/x", "/srv/data"))
    ck("path_within rejects prefix confusion (/srv/database)",
       not path_within("/srv/database/x", "/srv/data"))
    ck("path_within normalises double slashes and dots",
       path_within("/srv//data/./x", "/srv/data"))
    ck("path_within rejects NUL bytes",
       not path_within("/srv/data/x\x00", "/srv/data"))

    # --- domain_in --------------------------------------------------------
    ck("domain_in matches an exact domain",
       host_matches_any("https://example.com/a?b=1", ["example.com"]))
    ck("domain_in wildcard matches a subdomain",
       host_matches_any("api.example.com", ["*.example.com"]))
    ck("domain_in wildcard does not match the bare base",
       not host_matches_any("example.com", ["*.example.com"]))
    ck("domain_in rejects suffix confusion (example.com.evil.net)",
       not host_matches_any("example.com.evil.net", ["*.example.com", "example.com"]))
    ck("domain_in rejects substring confusion (evil-example.com)",
       not host_matches_any("evil-example.com", ["example.com"]))
    ck("domain_in ignores userinfo and port",
       host_matches_any("http://user:pw@a.example.com:8443/x", ["*.example.com"]))
    ck("domain_in does not match an IP literal against a domain pattern",
       not host_matches_any("192.168.1.1", ["*.example.com"]))
    ck("domain_in handles a trailing dot",
       host_matches_any("a.example.com.", ["*.example.com"]))

    # --- numeric / present / not -----------------------------------------
    ck("num_le is inclusive at the boundary",
       eval_arg_predicate({"num_le": 10}, 10, True))
    ck("num_lt is exclusive at the boundary",
       not eval_arg_predicate({"num_lt": 10}, 10, True))
    ck("a non-numeric value under num_* fails closed",
       not eval_arg_predicate({"num_lt": 10}, "9", True))
    ck("a boolean is not treated as a number",
       not eval_arg_predicate({"num_ge": 0}, True, True))
    ck("a missing argument under a value predicate fails closed",
       not eval_arg_predicate({"eq": 1}, None, False))
    ck("present:true reports existence",
       eval_arg_predicate({"present": True}, "v", True))
    ck("present:false reports absence",
       eval_arg_predicate({"present": False}, None, False))
    ck("not inverts its inner predicate",
       not eval_arg_predicate({"not": {"eq": 1}}, 1, True))
    ck("not(not(x)) is x",
       eval_arg_predicate({"not": {"not": {"eq": 1}}}, 1, True))

    # --- policy validation ------------------------------------------------
    _n, errs, _w = _check_policy({"version": 1, "default": "allow", "rules": []})
    ck("policy with default != deny is refused", bool(errs))

    _n, errs, _w = _check_policy({"default": "deny", "rules": [
        {"id": "r", "effect": "allow", "when": {"x": {"bogus_op": 1}}}]})
    ck("unknown predicate operator is refused", any("unknown operator" in e for e in errs))

    _n, errs, _w = _check_policy({"default": "deny", "rules": [
        {"id": "r", "effect": "maybe"}]})
    ck("unknown effect is refused", any("effect must be" in e for e in errs))

    _n, errs, _w = _check_policy({"default": "deny", "rules": [
        {"id": "r", "effect": "allow"}, {"id": "r", "effect": "deny"}]})
    ck("duplicate rule id is refused", any("duplicate" in e for e in errs))

    with tempfile.TemporaryDirectory() as td:
        bad = os.path.join(td, "bad.json")
        with open(bad, "w", encoding="utf-8") as fh:
            fh.write("{not json")
        try:
            load_policy(bad)
            raised = False
        except PolicyError:
            raised = True
        ck("malformed policy JSON is refused", raised)

    # --- unknown tool -----------------------------------------------------
    ck("an undeclared tool is denied",
       decide(_pol([{"id": "a", "effect": "allow", "tool": "t"}],
                   tools=("t",)), _action("other"))["effect"] == "deny")

    # --- ledger -----------------------------------------------------------
    with tempfile.TemporaryDirectory() as td:
        st = os.path.join(td, "audit.jsonl")
        r0 = append_record(st, {"command": "check", "decision": "allow"})
        ok, _msg = verify_records(load_store(st))
        ck("a fresh store verifies and starts after the genesis anchor",
           ok and r0["prev"] == GENESIS and r0["seq"] == 0)
        append_record(st, {"command": "check", "decision": "deny"})
        ok, _msg = verify_records(load_store(st))
        ck("a single append leaves the chain valid", ok)

        # tamper: edit a field
        with open(st, "r", encoding="utf-8") as fh:
            lines = fh.read().splitlines()
        lines[0] = json.dumps({"seq": 0, "prev": GENESIS, "command": "check",
                               "decision": "deny", "ts": 0, "tool": TOOL,
                               "version": VERSION, "hash": json.loads(lines[0])["hash"]},
                              sort_keys=True)
        with open(st, "w", encoding="utf-8", newline="\n") as fh:
            fh.write("\n".join(lines) + "\n")
        ok, msg = verify_records(load_store(st))
        ck("editing a record breaks the chain", (not ok) and "hash mismatch" in msg)

        # tamper: delete the first record
        st2 = os.path.join(td, "audit2.jsonl")
        append_record(st2, {"command": "check", "decision": "allow"})
        append_record(st2, {"command": "check", "decision": "allow"})
        with open(st2, "r", encoding="utf-8") as fh:
            ls = fh.read().splitlines()
        with open(st2, "w", encoding="utf-8", newline="\n") as fh:
            fh.write("\n".join(ls[1:]) + "\n")
        ok, msg = verify_records(load_store(st2))
        ck("deleting the first record breaks the genesis anchor",
           (not ok) and ("prev" in msg or "seq" in msg))

        # tamper: insert a forged record
        st3 = os.path.join(td, "audit3.jsonl")
        append_record(st3, {"command": "check", "decision": "allow"})
        forged = {"seq": 1, "prev": "f" * 64, "command": "check",
                  "decision": "allow", "ts": 0, "tool": TOOL, "version": VERSION,
                  "hash": "e" * 64}
        with open(st3, "a", encoding="utf-8", newline="\n") as fh:
            fh.write(json.dumps(forged, sort_keys=True) + "\n")
        ok, msg = verify_records(load_store(st3))
        ck("inserting a forged record breaks the chain", not ok)

        # refusing to append to a broken store
        st4 = os.path.join(td, "audit4.jsonl")
        append_record(st4, {"command": "check", "decision": "allow"})
        with open(st4, "r", encoding="utf-8") as fh:
            ls = fh.read().splitlines()
        with open(st4, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(json.dumps({"seq": 0, "prev": "x", "command": "check",
                                 "decision": "allow", "ts": 0, "tool": TOOL,
                                 "version": VERSION, "hash": "y"}) + "\n")
        try:
            append_record(st4, {"command": "check"})
            refused = False
        except StoreError:
            refused = True
        ck("appending to a broken store is refused", refused)

    # --- approvals end to end --------------------------------------------
    with tempfile.TemporaryDirectory() as td:
        st = os.path.join(td, "audit.jsonl")
        act = _action("t", args={"x": 1})
        append_record(st, {"command": "approve", "action_digest": action_digest(act)})
        appr = approvals_from_records(load_store(st))
        p_appr_all = _pol([{"id": "p1", "effect": "require-approval", "tool": "t"}])
        ck("an approval record authorises exactly its action digest",
           decide(p_appr_all, act, appr)["effect"] == "allow"
           and decide(p_appr_all, _action("t", args={"x": 2}), appr)["effect"]
           == "require-approval")

    passed = sum(1 for _n, ok in checks if ok)
    total = len(checks)
    print("%s %s -- selftest" % (TOOL, VERSION))
    for name, ok in checks:
        print("  [%s] %s" % ("pass" if ok else "FAIL", name))
    print("  %d/%d checks passed" % (passed, total))
    return 0 if passed == total else 1


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser():
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--store", metavar="FILE",
                        help="audit ledger path (env AGENT_GATE_STORE; "
                             "default ~/.agentgate/audit.jsonl)")
    common.add_argument("--policy", metavar="FILE",
                        help="policy path (env AGENT_GATE_POLICY; default ./policy.json)")

    parser = argparse.ArgumentParser(
        prog=TOOL,
        description="A fail-closed capability broker for AI-agent tool calls.")
    parser.add_argument("--version", action="version", version="%s %s" % (TOOL, VERSION))
    sub = parser.add_subparsers(dest="command")

    p = sub.add_parser("selftest", help="run built-in checks")
    p.set_defaults(func=lambda _a: selftest())

    p = sub.add_parser("check", parents=[common],
                       help="evaluate one or more proposed actions")
    p.add_argument("--action", metavar="FILE", help="action JSON file")
    p.add_argument("--stdin", action="store_true",
                   help="read newline-delimited actions from stdin")
    p.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    p.add_argument("--enforce", action="store_true",
                   help="exit 1 unless every action is allowed")
    p.set_defaults(func=cmd_check)

    p = sub.add_parser("explain", parents=[common],
                       help="show which rules matched and why")
    p.add_argument("--action", metavar="FILE", required=True)
    p.set_defaults(func=cmd_explain)

    p = sub.add_parser("lint", parents=[common], help="validate a policy")
    p.set_defaults(func=cmd_lint)

    p = sub.add_parser("approve", parents=[common],
                       help="record a human approval for an action")
    p.add_argument("--action", metavar="FILE", required=True)
    p.add_argument("--as", dest="as_", metavar="NAME", help="approver name")
    p.set_defaults(func=cmd_approve)

    p = sub.add_parser("stats", parents=[common], help="summarise the audit ledger")
    p.set_defaults(func=cmd_stats)

    p = sub.add_parser("verify", parents=[common], help="verify the audit ledger")
    p.set_defaults(func=cmd_verify)

    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return 2
    try:
        return args.func(args)
    except GateError as exc:
        print("%s: error: %s" % (TOOL, exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
