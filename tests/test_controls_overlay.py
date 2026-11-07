"""Operator switches, authenticated state, approvals and UI integration regression."""
from __future__ import annotations

import json
import os
import sqlite3
import sys
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from catl.crypto import digest
from catl.policy import Policy
from catl.gateway import Gateway
from catl.store import State


def tool(name):
    return {"name": name, "description": "pinned", "inputSchema": {"type": "object"}}


class FakeBackend:
    def __init__(self):
        self.tools = [tool("safe"), tool("sensitive"), tool("verified")]
        self.calls = []
        self.notifies = []
    def request(self, method, params=None):
        self.calls.append((method, params))
        if method == "initialize":
            return {"jsonrpc": "2.0", "id": 1, "result": {"protocolVersion": "2025-11-25", "capabilities": {"tools": {}}, "serverInfo": {"name": "fake", "version": "1"}}}
        if method == "tools/list":
            return {"jsonrpc": "2.0", "id": 2, "result": {"tools": self.tools}}
        if method == "tools/call":
            return {"jsonrpc": "2.0", "id": 3, "result": {"content": [{"type": "text", "text": "ok"}]}}
        raise RuntimeError(method)
    def notify(self, method, params=None):
        self.notifies.append(method)
    def close(self):
        pass


def req(name, args=None):
    return {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": name, "arguments": args or {}}}


class TestControls(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.db = Path(temp.name) / "control.sqlite3"
        self.state = State(self.db, b"Z" * 32)
        self.state.set_feature("gateway_enabled", True, "test-bootstrap")
        pins = {n: digest(tool(n)) for n in ("safe", "sensitive", "verified")}
        data = {"agent_id": "test-agent", "tool_pins": pins,
                "rules": [{"tool": "safe", "effect": "allow", "conditions": []},
                          {"tool": "sensitive", "effect": "approve", "conditions": []},
                          {"tool": "verified", "effect": "allow", "conditions": []}]}
        self.policy = Policy.from_dict(data)
        self.backend = FakeBackend()
        self.gw = Gateway(self.policy, self.state, self.backend)

    def test_defaults_are_explicit_and_signed(self):
        c = self.state.controls()
        self.assertTrue(all(c[key] for key in ("gateway_enabled", "approvals_enabled", "verification_enabled", "audit_enabled")))
        self.assertEqual(c["disabled_tools"], [])

    def test_pause_denies_execution_and_hides_tools(self):
        self.state.set_feature("gateway_enabled", False, "operator")
        self.assertEqual(self.gw.handle({"jsonrpc":"2.0","id":5,"method":"tools/list"})["result"]["tools"], [])
        self.assertEqual(self.gw.handle(req("safe"))["error"]["message"], "operator_disabled_gateway_or_audit")
        self.assertEqual(len([x for x in self.backend.calls if x[0]=="tools/call"]), 0)

    def test_resume_allows_only_pinned_policy(self):
        self.state.set_feature("gateway_enabled", False, "operator")
        self.state.set_feature("gateway_enabled", True, "operator")
        self.assertIn("result", self.gw.handle(req("safe")))
        self.assertEqual(self.state.verify()["valid"], True)

    def test_audit_off_blocks_new_tool_calls(self):
        self.state.set_feature("audit_enabled", False, "operator")
        self.assertEqual(self.gw.handle(req("safe"))["error"]["message"], "operator_disabled_gateway_or_audit")

    def test_approval_off_never_falls_back_to_allow(self):
        self.state.set_feature("approvals_enabled", False, "operator")
        self.assertEqual(self.gw.handle(req("sensitive"))["error"]["message"], "approvals_disabled_by_operator")
        self.assertEqual(len(self.state.list_pending()), 0)

    def test_tool_off_blocks_and_hides(self):
        self.state.set_tool("safe", False, "operator", set(self.policy.tool_pins))
        out = self.gw.handle({"jsonrpc":"2.0","id":5,"method":"tools/list"})
        self.assertNotIn("safe", [x["name"] for x in out["result"]["tools"]])
        self.assertEqual(self.gw.handle(req("safe"))["error"]["message"], "tool_disabled_by_operator")
        self.assertIn("result", self.gw.handle(req("verified")))
        self.state.set_tool("safe", True, "operator", set(self.policy.tool_pins))
        self.assertIn("result", self.gw.handle(req("safe")))

    def test_unpinned_cannot_be_enabled(self):
        with self.assertRaises(ValueError):
            self.state.set_tool("evil", True, "operator", set(self.policy.tool_pins))

    def test_feature_fields_rejected(self):
        with self.assertRaises(ValueError):
            self.state.set_feature("disable_all_security", False, "operator")
        with self.assertRaises(ValueError):
            self.state.set_feature("gateway_enabled", 1, "operator")

    def test_database_control_body_tamper_fails_closed(self):
        with closing(sqlite3.connect(self.db)) as conn:
            conn.execute("UPDATE operator_controls SET body=? WHERE id=1", (json.dumps({"gateway_enabled":True}),))
            conn.commit()
        self.assertEqual(self.gw.handle(req("safe"))["error"]["message"], "preflight_failed")
        self.assertNotIn("tools/call", [x[0] for x in self.backend.calls])

    def test_control_signature_change_fails_closed(self):
        with closing(sqlite3.connect(self.db)) as conn:
            conn.execute("UPDATE operator_controls SET mac='0' WHERE id=1")
            conn.commit()
        self.assertEqual(self.gw.handle(req("safe"))["error"]["message"], "preflight_failed")

    def test_deleted_controls_fail_closed_not_reset_to_allow(self):
        with closing(sqlite3.connect(self.db)) as conn:
            conn.execute("DELETE FROM operator_controls WHERE id=1")
            conn.commit()
        self.assertEqual(self.gw.handle(req("safe"))["error"]["message"], "preflight_failed")
        State(self.db, b"Z" * 32)
        # Recovery is disarmed, but the previous signed control history no
        # longer matches; re-arming requires trusted repair, not auto-healing.
        with self.assertRaises(PermissionError):
            self.state.controls()

    def test_approval_record_forgery_blocked(self):
        self.state.request("binding", {"tool":"sensitive"})
        with closing(sqlite3.connect(self.db)) as conn:
            conn.execute("UPDATE approvals SET status='approved', approved_by='admin' WHERE binding='binding'")
            conn.commit()
        with self.assertRaises(PermissionError):
            self.state.consume("binding")

    def test_approval_request_arg_tamper_blocked(self):
        rid = self.state.request("binding", {"tool":"sensitive", "arguments":{"amount": 10}})
        with closing(sqlite3.connect(self.db)) as conn:
            conn.execute("UPDATE approvals SET detail=? WHERE id=?", ('{"tool":"sensitive","arguments":{"amount":100000}}',rid))
            conn.commit()
        with self.assertRaises(PermissionError):
            self.state.decide(rid, "operator", True)

    def test_approval_decision_mac_tamper_blocked(self):
        rid = self.state.request("binding", {"tool":"sensitive"})
        self.state.decide(rid, "operator", True)
        with closing(sqlite3.connect(self.db)) as conn:
            conn.execute("UPDATE approvals SET decision_mac='0' WHERE id=?", (rid,))
            conn.commit()
        with self.assertRaises(PermissionError):
            self.state.consume("binding")

    def test_disabled_tool_even_with_prior_approval(self):
        first = self.gw.handle(req("sensitive"))
        approval_id = first["error"]["data"]["approval_id"]
        self.state.decide(approval_id, "operator", True)
        self.state.set_tool("sensitive", False, "operator", set(self.policy.tool_pins))
        self.assertEqual(self.gw.handle(req("sensitive"))["error"]["message"], "tool_disabled_by_operator")

    def test_approval_off_even_with_prior_approval(self):
        first = self.gw.handle(req("sensitive"))
        rid = first["error"]["data"]["approval_id"]
        self.state.decide(rid, "operator", True)
        self.state.set_feature("approvals_enabled", False, "operator")
        self.assertEqual(self.gw.handle(req("sensitive"))["error"]["message"], "approvals_disabled_by_operator")

    def test_legacy_initialized_is_handled_locally(self):
        self.gw.handle({"jsonrpc":"2.0", "id":7, "method":"initialize", "params":{"protocolVersion":"2025-11-25"}})
        self.assertEqual(self.backend.notifies, [])
        self.gw.handle({"jsonrpc":"2.0", "method":"notifications/initialized"})
        self.assertEqual(self.backend.notifies, [])

    def test_modern_tool_list_zero_cache(self):
        params = {"_meta": {"io.modelcontextprotocol/protocolVersion":"2026-07-28",
           "io.modelcontextprotocol/clientCapabilities":{}}}
        resp = self.gw.handle({"jsonrpc":"2.0", "id":2,"method":"tools/list","params":params})
        self.assertEqual(resp["result"]["ttlMs"], 0)
        self.assertEqual(resp["result"]["cacheScope"], "private")

    def test_audit_contains_operator_control_event(self):
        self.state.set_tool("safe", False, "operator", set(self.policy.tool_pins))
        self.assertTrue(self.state.verify()["valid"])
        with closing(sqlite3.connect(self.db)) as conn:
            body = conn.execute("SELECT body FROM receipts ORDER BY seq DESC LIMIT 1").fetchone()[0]
        self.assertEqual(json.loads(body)["decision"], "operator_control_change")

    def test_securely_disabled_audit_is_not_unlogged_execution(self):
        self.state.set_feature("audit_enabled", False, "operator")
        out = self.gw.handle(req("safe"))
        self.assertIn("error", out)
        self.assertGreaterEqual(self.state.verify()["count"],2)


class TestGUI(unittest.TestCase):
    @unittest.skipUnless(os.environ.get("DISPLAY") or os.name=="nt" or sys.platform=="darwin", "GUI display unavailable")
    def test_tk_overlay_constructs_minimises_and_controls_live_gateway(self):
        import tkinter as tk
        from catl.overlay import OperatorOverlay
        with tempfile.TemporaryDirectory() as temp:
            state = State(Path(temp)/"s.sqlite3", b"K"*32)
            pins={"safe":digest(tool("safe"))}
            policy=Policy.from_dict({"agent_id":"gui", "tool_pins":pins,
                         "rules":[{"tool":"safe","effect":"allow","conditions":[]}]})
            try:
                root=tk.Tk()
            except tk.TclError as exc:
                self.skipTest("GUI display not available: " + str(exc))
            try:
                app=OperatorOverlay(root,state,policy,topmost=False)
                app.toggle_feature("gateway_enabled",False)
                self.assertFalse(state.controls()["gateway_enabled"])
                app.toggle_tool("safe",False)
                self.assertIn("safe",state.controls()["disabled_tools"])
                app.toggle_compact()
                self.assertTrue(app.compact)
                app.toggle_compact()
                self.assertFalse(app.compact)
                root.update()
            finally:
                root.destroy()


if __name__ == "__main__": unittest.main()

class TestSchemaSecurity(unittest.TestCase):
    def test_required_field_missing_denied(self):
        from catl.schema import validate_arguments
        t={"inputSchema":{"type":"object","required":["message"],"properties":{"message":{"type":"string"}}}}
        with self.assertRaises(ValueError): validate_arguments(t,{})
        with self.assertRaises(ValueError): validate_arguments(t,{"message":123})
        validate_arguments(t,{"message":"correct"})

    def test_external_schema_refs_denied_before_resolution(self):
        from catl.schema import validate_arguments
        t={"inputSchema":{"$ref":"https://example.invalid/secret"}}
        with self.assertRaisesRegex(ValueError,"external_or_dynamic"):
            validate_arguments(t,{})

    def test_local_schema_reference_supported(self):
        from catl.schema import validate_arguments
        t={"inputSchema":{"$defs":{"payload":{"type":"string"}},"type":"object",
           "properties":{"data":{"$ref":"#/$defs/payload"}},"required":["data"]}}
        validate_arguments(t,{"data":"value"})
        with self.assertRaises(ValueError): validate_arguments(t,{"data":123})

    def test_schema_disallowed_recursion_depth(self):
        from catl.schema import validate_arguments
        t={"inputSchema":{"type":"object","description":"ok"}}
        tree=t["inputSchema"]
        for _ in range(66):
            tree["properties"]={}
            tree=tree["properties"]
        with self.assertRaises(ValueError): validate_arguments(t,{})

    def test_multiple_tool_switch_atomic(self):
        with tempfile.TemporaryDirectory() as t:
            state=State(Path(t)/"s.db",b"Z"*32)
            state.set_all_tools(False,"operator",{"tool.a","tool.b"})
            self.assertEqual(state.controls()["disabled_tools"],["tool.a","tool.b"])
            state.set_all_tools(True,"operator",{"tool.a","tool.b"})
            self.assertEqual(state.controls()["disabled_tools"],[])

class TestRateLimits(unittest.TestCase):
    def test_exact_limit_and_explicit_reset(self):
        with tempfile.TemporaryDirectory() as temp:
            state=State(Path(temp)/"state.db",b'K'*32)
            self.assertTrue(state.acquire_rate('agent','tool',2))
            self.assertTrue(state.acquire_rate('agent','tool',2))
            self.assertFalse(state.acquire_rate('agent','tool',2))
            self.assertTrue(state.acquire_rate('other','tool',2))

    def test_existing_database_migration_defaults_paused(self):
        with tempfile.TemporaryDirectory() as temp:
            db=Path(temp)/'old.db'
            with closing(sqlite3.connect(db)) as conn:
                conn.execute('CREATE TABLE old_marker (a INTEGER)')
            if os.name == "posix":
                db.chmod(0o600)
            state=State(db,b'K'*32)
            self.assertFalse(state.controls()['gateway_enabled'])
            state.set_feature('gateway_enabled',True,'operator')
            self.assertTrue(state.controls()['gateway_enabled'])

    def test_new_database_defaults_disarmed(self):
        with tempfile.TemporaryDirectory() as temp:
            state = State(Path(temp) / "audit.sqlite3", b"Z" * 32)
            self.assertFalse(state.controls()["gateway_enabled"])

    def test_removed_database_does_not_auto_rearm(self):
        with tempfile.TemporaryDirectory() as temp:
            db = Path(temp) / "audit.sqlite3"
            state = State(db, b"Z" * 32)
            state.set_feature("gateway_enabled", True, "operator")
            self.assertTrue(state.controls()["gateway_enabled"])
            db.unlink()
            for suffix in ("-shm", "-wal"):
                (Path(str(db) + suffix)).unlink(missing_ok=True)
            recovered = State(db, b"Z" * 32)
            self.assertFalse(recovered.controls()["gateway_enabled"])

    def test_gateway_rate_bound_blocks_dispatch(self):
        with tempfile.TemporaryDirectory() as temp:
            state=State(Path(temp)/'state.db',b'K'*32)
            state.set_feature('gateway_enabled', True, 'test-bootstrap')
            backend=FakeBackend()
            pin=digest(tool('safe'))
            policy=Policy.from_dict({'agent_id':'ratetest','tool_pins':{'safe':pin},
                'rules':[{'tool':'safe','effect':'allow','conditions':[]}],
                'rate_limits':{'safe':2}})
            gateway=Gateway(policy,state,backend)
            self.assertIn('result',gateway.handle(req('safe')))
            self.assertIn('result',gateway.handle(req('safe')))
            self.assertEqual(gateway.handle(req('safe'))['error']['message'],'rate_limit_exceeded')
            self.assertEqual([x[0] for x in backend.calls].count('tools/call'),2)

class TestSubprocessHardening(unittest.TestCase):
    def test_child_stderr_cannot_spoof_operator_terminal(self):
        import subprocess
        from catl.gateway import SubprocessBackend
        with patch.object(subprocess, "Popen", wraps=subprocess.Popen) as popen:
            backend = SubprocessBackend([sys.executable, "-c", "import time;time.sleep(.1)"],
                                        timeout=2, allow_unsandboxed=True)
            try:
                self.assertEqual(popen.call_args.kwargs["stderr"], subprocess.DEVNULL)
            finally:
                backend.close()

    @unittest.skipUnless(os.name=="posix", "Pipe saturation regression verified on POSIX")
    def test_child_that_never_reads_stdin_cannot_hang_gateway_forever(self):
        from catl.gateway import SubprocessBackend
        backend=SubprocessBackend([sys.executable,"-c","import time;time.sleep(10)"],
                                  timeout=0.3, allow_unsandboxed=True)
        try:
            with self.assertRaises(TimeoutError):
                backend.request("tools/call", {"payload":"x"*150000})
            self.assertIsNotNone(backend.proc.poll())
        finally:
            backend.close()
