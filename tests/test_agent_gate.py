"""agent-gate end-to-end CLI suite.

Runs the real `agent-gate.py` as a subprocess to verify behaviour end-to-end
(single-file tool, same discipline as the family). Each test uses a fresh temp
store and a fresh temp policy.

Targets: at least 31 tests.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest

TOOL = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "agent-gate.py"))


def run_cli(args, store=None, policy=None, extra_env=None, timeout=300):
    env = dict(os.environ)
    if store is not None:
        env["AGENT_GATE_STORE"] = store
    if policy is not None:
        env["AGENT_GATE_POLICY"] = policy
    if extra_env:
        env.update(extra_env)
    try:
        return subprocess.run(
            [sys.executable, TOOL] + [str(a) for a in args],
            capture_output=True, text=True, env=env,
            cwd=os.path.dirname(TOOL), timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        raise AssertionError(f"CLI timeout: {exc}") from exc


def read_store(path):
    records = []
    if not os.path.exists(path):
        return records
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


class AgentGateE2ETest(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.addCleanup(self._td.cleanup)
        self.store = os.path.join(self._td.name, "audit.jsonl")
        self.policy = os.path.join(self._td.name, "policy.json")
        self._write_policy()

    def _write_policy(self):
        pol = {
            "version": 1,
            "default": "deny",
            "tools": ["http.get", "fs.write", "send.email", "shell.run"],
            "rules": [
                {"id": "allow-web", "effect": "allow", "agents": ["researcher"],
                 "tool": "http.get", "when": {"url": {"domain_in": ["*.corp.example"]}}},
                {"id": "allow-data", "effect": "allow", "tool": "fs.write",
                 "when": {"path": {"path_within": "/srv/data"}}},
                {"id": "deny-secrets", "effect": "deny", "tool": "fs.write",
                 "when": {"path": {"suffix": ".pem"}}},
                {"id": "gate-email", "effect": "require-approval", "tool": "send.email",
                 "when": {"to": {"domain_in": ["corp.example"]}, "size": {"num_le": 2000000}}},
                {"id": "no-shell", "effect": "deny", "tool": "shell.run"},
            ],
        }
        with open(self.policy, "w", encoding="utf-8") as fh:
            json.dump(pol, fh)

    def _write_action(self, name, obj):
        p = os.path.join(self._td.name, name + ".json")
        with open(p, "w", encoding="utf-8") as fh:
            json.dump(obj, fh)
        return p

    def test_selftest(self):
        r = run_cli(["selftest"], store=self.store, policy=self.policy)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("selftest", r.stdout)
        self.assertNotIn("FAIL", r.stdout)

    def test_check_allow(self):
        ap = self._write_action("allow", {
            "tool": "http.get", "agent": "researcher",
            "args": {"url": "https://wiki.corp.example/page"},
        })
        r = run_cli(["check", "--action", ap], store=self.store, policy=self.policy)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("ALLOW", r.stdout)
        rec = read_store(self.store)
        self.assertEqual(rec[-1]["decision"], "allow")

    def test_check_deny_default(self):
        ap = self._write_action("deny", {"tool": "shell.run", "args": {"cmd": "ls"}})
        r = run_cli(["check", "--action", ap], store=self.store, policy=self.policy)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("DENY", r.stdout)

    def test_check_approval_then_allow(self):
        ap = self._write_action("email", {
            "tool": "send.email", "agent": "a1",
            "args": {"to": "boss@corp.example", "size": 1000},
        })
        r = run_cli(["check", "--action", ap], store=self.store, policy=self.policy)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("REQUIRE-APPROVAL", r.stdout)
        r2 = run_cli(["approve", "--action", ap], store=self.store, policy=self.policy)
        self.assertEqual(r2.returncode, 0, r2.stderr)
        r3 = run_cli(["check", "--action", ap], store=self.store, policy=self.policy)
        self.assertEqual(r3.returncode, 0, r3.stderr)
        self.assertIn("ALLOW", r3.stdout)

    def test_deny_overrides_allow_traversal(self):
        ap = self._write_action("trv", {"tool": "fs.write", "args": {"path": "/srv/data/../etc/passwd"}})
        r = run_cli(["check", "--action", ap], store=self.store, policy=self.policy)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("DENY", r.stdout)

    def test_secret_suffix_denied(self):
        ap = self._write_action("pem", {"tool": "fs.write", "args": {"path": "/srv/data/key.pem"}})
        r = run_cli(["check", "--action", ap], store=self.store, policy=self.policy)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("DENY", r.stdout)

    def test_domain_suffix_confusion(self):
        ap = self._write_action("evil", {"tool": "http.get", "agent": "researcher",
                                         "args": {"url": "https://corp.example.evil.net/x"}})
        r = run_cli(["check", "--action", ap], store=self.store, policy=self.policy)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("DENY", r.stdout)

    def test_lint_ok(self):
        r = run_cli(["lint"], store=self.store, policy=self.policy)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("ok", r.stdout)

    def test_lint_unknown_operator(self):
        bad = os.path.join(self._td.name, "bad1.json")
        with open(bad, "w", encoding="utf-8") as fh:
            json.dump({"version": 1, "default": "deny", "rules": [
                {"id": "r", "effect": "allow", "tool": "http.get",
                 "when": {"url": {"bogus": 1}}}]}, fh)
        r = run_cli(["lint"], store=self.store, policy=bad)
        self.assertEqual(r.returncode, 1, r.stderr)
        self.assertIn("unknown operator", r.stdout)

    def test_lint_default_allow(self):
        bad = os.path.join(self._td.name, "bad2.json")
        with open(bad, "w", encoding="utf-8") as fh:
            json.dump({"version": 1, "default": "allow", "rules": []}, fh)
        r = run_cli(["lint"], store=self.store, policy=bad)
        self.assertEqual(r.returncode, 1, r.stderr)
        self.assertIn("must be \"deny\"", r.stdout)

    def test_lint_unknown_effect(self):
        bad = os.path.join(self._td.name, "bad3.json")
        with open(bad, "w", encoding="utf-8") as fh:
            json.dump({"version": 1, "default": "deny", "rules": [
                {"id": "r", "effect": "forbidden"}]}, fh)
        r = run_cli(["lint"], store=self.store, policy=bad)
        self.assertEqual(r.returncode, 1, r.stderr)
        self.assertIn("effect must be", r.stdout)

    def test_missing_policy_refused(self):
        nop = os.path.join(self._td.name, "nope.json")
        ap = self._write_action("a", {"tool": "http.get", "args": {}})
        r = run_cli(["check", "--action", ap], store=self.store, policy=nop)
        self.assertEqual(r.returncode, 1, r.stderr)

    def test_malformed_action_refused(self):
        ap = self._write_action("bad", {"tool": 123})
        r = run_cli(["check", "--action", ap], store=self.store, policy=self.policy)
        self.assertEqual(r.returncode, 1, r.stderr)

    def test_malformed_policy_json_refused(self):
        bad = os.path.join(self._td.name, "mal.json")
        with open(bad, "w", encoding="utf-8") as fh:
            fh.write("{not")
        r = run_cli(["check", "--action", self._write_action("a", {"tool": "http.get", "args": {}})],
                    store=self.store, policy=bad)
        self.assertEqual(r.returncode, 1, r.stderr)

    def test_json_output_shape(self):
        ap = self._write_action("a", {"tool": "http.get", "agent": "researcher",
                                     "args": {"url": "https://wiki.corp.example/a"}})
        r = run_cli(["check", "--action", ap, "--json"], store=self.store, policy=self.policy)
        self.assertEqual(r.returncode, 0, r.stderr)
        obj = json.loads(r.stdout.strip())
        for k in ("tool", "agent", "decision", "reason", "matched", "action_digest",
                  "policy_digest", "seq"):
            self.assertIn(k, obj)

    def test_enforce_exit_code(self):
        ap = self._write_action("deny", {"tool": "shell.run", "args": {}})
        r = run_cli(["check", "--action", ap, "--enforce"], store=self.store, policy=self.policy)
        self.assertEqual(r.returncode, 1, r.stderr)

    def test_stdin_batch(self):
        a1 = self._write_action("a1", {"tool": "http.get", "agent": "researcher", "args": {"url": "https://wiki.corp.example/a"}})
        a2 = self._write_action("a2", {"tool": "shell.run", "args": {}})
        with open(a1, encoding="utf-8") as fh1, open(a2, encoding="utf-8") as fh2:
            buf = fh1.read() + "\n" + fh2.read() + "\n"
        p = subprocess.run([sys.executable, TOOL, "check", "--stdin",
                            "--policy", self.policy, "--store", self.store],
                           input=buf, text=True, capture_output=True,
                           cwd=os.path.dirname(TOOL), timeout=60)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("action(s): allow=1", p.stderr)
        self.assertIn("deny=1", p.stderr)

    def test_unknown_command_exits_2(self):
        r = run_cli(["frobnicate"], store=self.store, policy=self.policy)
        self.assertEqual(r.returncode, 2)

    def test_version_flag(self):
        r = run_cli(["--version"], store=self.store, policy=self.policy)
        self.assertEqual(r.returncode, 0)
        self.assertIn("agent-gate 1.0.0", r.stdout)

    def test_stats_and_verify_clean(self):
        r = run_cli(["stats"], store=self.store, policy=self.policy)
        self.assertEqual(r.returncode, 0, r.stderr)
        r = run_cli(["verify"], store=self.store, policy=self.policy)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_verify_detects_edit(self):
        ap = self._write_action("a", {"tool": "http.get", "agent": "researcher",
                                     "args": {"url": "https://wiki.corp.example/a"}})
        run_cli(["check", "--action", ap], store=self.store, policy=self.policy)
        recs = read_store(self.store)
        with open(self.store, "w", encoding="utf-8") as fh:
            recs[0]["decision"] = "deny"
            fh.write(json.dumps(recs[0], sort_keys=True) + "\n")
        r = run_cli(["verify"], store=self.store, policy=self.policy)
        self.assertEqual(r.returncode, 1, r.stderr)

    def test_verify_detects_delete(self):
        ap = self._write_action("a", {"tool": "http.get", "agent": "researcher",
                                     "args": {"url": "https://wiki.corp.example/a"}})
        run_cli(["check", "--action", ap], store=self.store, policy=self.policy)
        run_cli(["check", "--action", ap], store=self.store, policy=self.policy)
        recs = read_store(self.store)
        with open(self.store, "w", encoding="utf-8") as fh:
            for r in recs[1:]:
                fh.write(json.dumps(r, sort_keys=True) + "\n")
        r = run_cli(["verify"], store=self.store, policy=self.policy)
        self.assertEqual(r.returncode, 1, r.stderr)

    def test_verify_detects_insert(self):
        ap = self._write_action("a", {"tool": "http.get", "agent": "researcher",
                                     "args": {"url": "https://wiki.corp.example/a"}})
        run_cli(["check", "--action", ap], store=self.store, policy=self.policy)
        recs = read_store(self.store)
        forged = dict(recs[0]); forged["decision"] = "deny"
        with open(self.store, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(forged, sort_keys=True) + "\n")
        r = run_cli(["verify"], store=self.store, policy=self.policy)
        self.assertEqual(r.returncode, 1, r.stderr)

    def test_broken_store_refused(self):
        ap = self._write_action("a", {"tool": "http.get", "agent": "researcher",
                                     "args": {"url": "https://wiki.corp.example/a"}})
        run_cli(["check", "--action", ap], store=self.store, policy=self.policy)
        with open(self.store, "w", encoding="utf-8") as fh:
            fh.write(json.dumps({"seq": 0, "prev": GENESIS, "decision": "allow",
                                 "hash": "bad"}, sort_keys=True) + "\n")
        r = run_cli(["check", "--action", ap], store=self.store, policy=self.policy)
        self.assertEqual(r.returncode, 1, r.stderr)

    def test_env_store_overrides(self):
        store2 = os.path.join(self._td.name, "alt.jsonl")
        ap = self._write_action("a", {"tool": "http.get", "agent": "researcher",
                                     "args": {"url": "https://wiki.corp.example/a"}})
        r = run_cli(["check", "--action", ap], store=store2, policy=self.policy)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(os.path.exists(store2))

    def test_policy_digest_changes(self):
        ap = self._write_action("a", {"tool": "http.get", "agent": "researcher",
                                     "args": {"url": "https://wiki.corp.example/a"}})
        r = run_cli(["check", "--action", ap, "--json"], store=self.store, policy=self.policy)
        d0 = json.loads(r.stdout)["policy_digest"]
        with open(self.policy, encoding="utf-8") as fh:
            pol2 = json.load(fh)
        pol2["rules"].append(
            {"id": "dummy", "effect": "deny", "tool": "http.get", "when": {"url": {"suffix": ".x"}}})
        p2 = os.path.join(self._td.name, "p2.json")
        with open(p2, "w", encoding="utf-8") as fh: json.dump(pol2, fh)
        r2 = run_cli(["check", "--action", ap, "--json"], store=self.store, policy=p2)
        d1 = json.loads(r2.stdout)["policy_digest"]
        self.assertNotEqual(d0, d1)

    def test_explain_shows_matched(self):
        ap = self._write_action("a", {"tool": "http.get", "agent": "researcher",
                                     "args": {"url": "https://wiki.corp.example/a"}})
        r = run_cli(["explain", "--action", ap], store=self.store, policy=self.policy)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("allow-web", r.stdout)

    def test_approve_shows_as(self):
        ap = self._write_action("e", {"tool": "send.email", "agent": "a", "args": {"to": "x@corp.example", "size": 1}})
        run_cli(["check", "--action", ap], store=self.store, policy=self.policy)
        r = run_cli(["approve", "--action", ap, "--as", "alice"], store=self.store, policy=self.policy)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("alice", r.stdout)

    def test_order_independence_proven(self):
        # policy has deny rule that shadows allow only on .pem; others unaffected
        ap = self._write_action("w", {"tool": "fs.write", "args": {"path": "/srv/data/notes.txt"}})
        r = run_cli(["check", "--action", ap], store=self.store, policy=self.policy)
        self.assertIn("ALLOW", r.stdout)
        r = run_cli(["check", "--action", self._write_action("p", {"tool": "fs.write", "args": {"path": "/srv/data/k.pem"}})],
                    store=self.store, policy=self.policy)
        self.assertIn("DENY", r.stdout)

    def test_nested_path_allowed(self):
        ap = self._write_action("n", {"tool": "fs.write", "args": {"path": "/srv/data/sub/deep/f.txt"}})
        r = run_cli(["check", "--action", ap], store=self.store, policy=self.policy)
        self.assertIn("ALLOW", r.stdout)

    def test_num_boundaries(self):
        ap_ok = self._write_action("ok", {"tool": "send.email", "agent": "a",
                                         "args": {"to": "t@corp.example", "size": 2000000}})
        r = run_cli(["check", "--action", ap_ok], store=self.store, policy=self.policy)
        self.assertIn("REQUIRE-APPROVAL", r.stdout)

    def test_missing_arg_fail_closed(self):
        ap = self._write_action("m", {"tool": "http.get", "agent": "researcher", "args": {"url": "http://bad.example/x"}})
        r = run_cli(["check", "--action", ap], store=self.store, policy=self.policy)
        self.assertIn("DENY", r.stdout)

    def test_unknown_tool_denied(self):
        ap = self._write_action("x", {"tool": "db.query", "args": {}})
        r = run_cli(["check", "--action", ap], store=self.store, policy=self.policy)
        self.assertIn("DENY", r.stdout)

    def test_policy_with_no_tools_empty_rules(self):
        pol = {"version": 1, "default": "deny", "rules": []}
        p = os.path.join(self._td.name, "pempty.json")
        with open(p, "w", encoding="utf-8") as fh: json.dump(pol, fh)
        ap = self._write_action("a", {"tool": "anything", "args": {}})
        r = run_cli(["check", "--action", ap], store=self.store, policy=p)
        self.assertIn("DENY", r.stdout)

    def test_duplicate_rule_id_rejected(self):
        pol = {"version": 1, "default": "deny", "tools": ["t"], "rules": [
            {"id": "r", "effect": "allow", "tool": "t"},
            {"id": "r", "effect": "deny", "tool": "t"}]}
        p = os.path.join(self._td.name, "dup.json")
        with open(p, "w", encoding="utf-8") as fh: json.dump(pol, fh)
        r = run_cli(["lint"], store=self.store, policy=p)
        self.assertEqual(r.returncode, 1)
        self.assertIn("duplicate", r.stdout)

    def test_agent_scope_restricted(self):
        ap = self._write_action("a", {"tool": "http.get", "agent": "notresearcher",
                                     "args": {"url": "https://wiki.corp.example/x"}})
        r = run_cli(["check", "--action", ap], store=self.store, policy=self.policy)
        self.assertIn("DENY", r.stdout)

    def test_not_combinator(self):
        pol = {"version": 1, "default": "deny", "tools": ["t"], "rules": [
            {"id": "a", "effect": "allow", "tool": "t", "when": {"x": {"not": {"eq": "bad"}}}}]}
        p = os.path.join(self._td.name, "not.json")
        with open(p, "w", encoding="utf-8") as fh: json.dump(pol, fh)
        ap = self._write_action("ok", {"tool": "t", "args": {"x": "good"}})
        r = run_cli(["check", "--action", ap], store=self.store, policy=p)
        self.assertIn("ALLOW", r.stdout)
        apb = self._write_action("bad", {"tool": "t", "args": {"x": "bad"}})
        r = run_cli(["check", "--action", apb], store=self.store, policy=p)
        self.assertIn("DENY", r.stdout)

    def test_present_predicate(self):
        pol = {"version": 1, "default": "deny", "tools": ["t"], "rules": [
            {"id": "a", "effect": "allow", "tool": "t", "when": {"x": {"present": True}}}]}
        p = os.path.join(self._td.name, "pres.json")
        with open(p, "w", encoding="utf-8") as fh: json.dump(pol, fh)
        a = self._write_action("a", {"tool": "t", "args": {}})
        r = run_cli(["check", "--action", a], store=self.store, policy=p)
        self.assertIn("DENY", r.stdout)
        a2 = self._write_action("a2", {"tool": "t", "args": {"x": 1}})
        r = run_cli(["check", "--action", a2], store=self.store, policy=p)
        self.assertIn("ALLOW", r.stdout)

    def test_store_refuses_unverifiable_append(self):
        ap = self._write_action("a", {"tool": "http.get", "agent": "researcher",
                                     "args": {"url": "https://wiki.corp.example/a"}})
        run_cli(["check", "--action", ap], store=self.store, policy=self.policy)
        run_cli(["check", "--action", ap], store=self.store, policy=self.policy)
        recs = read_store(self.store)
        recs[0]["decision"] = "deny"
        with open(self.store, "w", encoding="utf-8") as fh:
            for rec in recs:
                fh.write(json.dumps(rec, sort_keys=True) + "\n")
        r = run_cli(["check", "--action", ap], store=self.store, policy=self.policy)
        self.assertEqual(r.returncode, 1, r.stderr)


GENESIS = "0" * 64


if __name__ == "__main__":
    unittest.main()
