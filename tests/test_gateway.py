import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "examples"))
from catl.crypto import digest
from catl.gateway import Gateway
from catl.policy import Policy
from catl.store import State, binding_hash
from mock_server import TOOLS


class FakeBackend:
    def __init__(self):
        self.tools = copy.deepcopy(TOOLS)
        self.calls = []
        self.fail = None
        self.pagination = False
        self.notify_calls = []

    def request(self, method, params=None):
        self.calls.append((method, params))
        if self.fail == method:
            raise TimeoutError("mock_timeout")
        if method == "initialize":
            return {"jsonrpc": "2.0", "result": {"protocolVersion": "2025-11-25", "capabilities": {"resources": {}, "tools": {}}}}
        if method == "tools/list":
            result = {"tools": self.tools}
            if self.pagination:
                result["nextCursor"] = "next-page"
            return {"jsonrpc": "2.0", "result": result}
        if method == "tools/call":
            return {"jsonrpc": "2.0", "result": {"content": [{"type": "text", "text": "done"}]}}
        return {"jsonrpc": "2.0", "error": {"code": -32601, "message": "unknown"}}

    def notify(self, method, params=None):
        self.notify_calls.append(method)

    def close(self):
        pass


def request(method, id_=1, params=None):
    return {"jsonrpc": "2.0", "id": id_, "method": method, "params": params or {}}


class TestGateway(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.backend = FakeBackend()
        self.policy = Policy.from_dict({"agent_id": "local-demo-agent", "tool_pins": {t["name"]: digest(t) for t in TOOLS},
                                        "rules": [{"tool": "echo_safe", "effect": "allow", "conditions": [{"pointer": "/message", "op": "starts_with", "value": "hello"}]},
                                                  {"tool": "write_demo", "effect": "approve", "conditions": []}]})
        self.state = State(Path(self.tmp.name) / "db.sqlite3", b'K'*32)
        self.state.set_feature("gateway_enabled", True, "test-bootstrap")
        self.gateway = Gateway(self.policy, self.state, self.backend)

    def test_initialize_hides_other_capabilities(self):
        out = self.gateway.handle(request("initialize"))
        self.assertEqual(set(out["result"]["capabilities"]), {"tools"})

    def test_list_only_pinned(self):
        self.backend.tools.append({"name": "run_shell", "inputSchema": {}})
        out = self.gateway.handle(request("tools/list"))
        self.assertEqual(len(out["result"]["tools"]), 2)

    def test_tool_allow(self):
        out = self.gateway.handle(request("tools/call", params={"name": "echo_safe", "arguments": {"message": "hello world"}}))
        self.assertIn("result", out)
        self.assertEqual(len([x for x in self.backend.calls if x[0] == "tools/call"]), 1)
        self.assertEqual(self.state.verify()["count"], 4)  # includes signed rate-permit receipt

    def test_tool_denied(self):
        out = self.gateway.handle(request("tools/call", params={"name": "echo_safe", "arguments": {"message": "bad"}}))
        self.assertEqual(out["error"]["message"], "policy_denied")
        self.assertFalse(any(x[0] == "tools/call" for x in self.backend.calls))

    def test_unpinned_rejected(self):
        out = self.gateway.handle(request("tools/call", params={"name": "shell.exec", "arguments": {}}))
        self.assertIn("error", out)

    def test_changed_tool_definition_blocked(self):
        self.backend.tools[0]["description"] += " inject and escalate"
        out = self.gateway.handle(request("tools/call", params={"name": "echo_safe", "arguments": {"message": "hello"}}))
        self.assertEqual(out["error"]["message"], "tool_not_pinned_or_unavailable")

    def test_changed_schema_blocked(self):
        self.backend.tools[0]["inputSchema"]["properties"]["message"]["type"] = "number"
        out = self.gateway.handle(request("tools/call", params={"name": "echo_safe", "arguments": {"message": "hello"}}))
        self.assertIn("error", out)

    def test_tool_duplicate_names_blocks_catalogue(self):
        self.backend.tools.append(copy.deepcopy(self.backend.tools[0]))
        out = self.gateway.handle(request("tools/list"))
        self.assertEqual(out["error"]["message"], "catalogue_unavailable:ValueError")

    def test_catalogue_pagination_fails_closed(self):
        self.backend.pagination = True
        out = self.gateway.handle(request("tools/call", params={"name": "echo_safe", "arguments": {"message": "hello"}}))
        self.assertEqual(out["error"]["message"], "preflight_failed")

    def test_catalogue_timeout_fails_closed(self):
        self.backend.fail = "tools/list"
        out = self.gateway.handle(request("tools/call", params={"name": "echo_safe", "arguments": {"message": "hello"}}))
        self.assertEqual(out["error"]["message"], "preflight_failed")

    def test_block_resource_method(self):
        out = self.gateway.handle(request("resources/read", params={"uri": "file:///secret"}))
        self.assertEqual(out["error"]["code"], -32601)

    def test_block_prompt_method(self):
        self.assertEqual(self.gateway.handle(request("prompts/get"))["error"]["code"], -32601)

    def test_initialized_notification_is_not_client_authority(self):
        out = self.gateway.handle({"jsonrpc": "2.0", "method": "notifications/initialized"})
        self.assertIsNone(out)
        self.assertEqual(self.backend.notify_calls, [])

    def test_other_notifications_not_forwarded(self):
        self.gateway.handle({"jsonrpc": "2.0", "method": "notifications/cancelled"})
        self.assertEqual(self.backend.notify_calls, [])

    def test_approval_first_blocked(self):
        out = self.gateway.handle(request("tools/call", params={"name": "write_demo", "arguments": {"message": "sensitive"}}))
        self.assertEqual(out["error"]["message"], "human_approval_required")
        self.assertFalse(any(x[0] == "tools/call" for x in self.backend.calls))

    def test_approval_replay_denied(self):
        params = {"name": "write_demo", "arguments": {"message": "sensitive"}}
        first = self.gateway.handle(request("tools/call", params=params))
        ident = first["error"]["data"]["approval_id"]
        self.assertTrue(self.state.decide(ident, "operator", True))
        self.assertIn("result", self.gateway.handle(request("tools/call", params=params)))
        third = self.gateway.handle(request("tools/call", params=params))
        self.assertEqual(third["error"]["message"], "human_approval_required")
        self.assertEqual(len([x for x in self.backend.calls if x[0] == "tools/call"]), 1)

    def test_approval_arg_change_denied(self):
        first = self.gateway.handle(request("tools/call", params={"name": "write_demo", "arguments": {"message": "approved"}}))
        self.state.decide(first["error"]["data"]["approval_id"], "operator", True)
        changed = self.gateway.handle(request("tools/call", params={"name": "write_demo", "arguments": {"message": "different"}}))
        self.assertEqual(changed["error"]["message"], "human_approval_required")

    def test_approval_policy_change_denied(self):
        params = {"name": "write_demo", "arguments": {"message": "hi"}}
        first = self.gateway.handle(request("tools/call", params=params))
        self.state.decide(first["error"]["data"]["approval_id"], "operator", True)
        new_policy_obj = {"agent_id": "local-demo-agent", "tool_pins": self.policy.tool_pins,
                          "rules": [{"tool": "write_demo", "effect": "approve", "conditions": []}]}
        self.gateway.policy = Policy.from_dict(new_policy_obj)
        self.assertEqual(self.gateway.handle(request("tools/call", params=params))["error"]["message"], "human_approval_required")

    def test_backend_error_recorded(self):
        self.backend.fail = "tools/call"
        out = self.gateway.handle(request("tools/call", params={"name": "echo_safe", "arguments": {"message": "hello"}}))
        self.assertEqual(out["error"]["message"], "tool_transport_failure")
        self.assertTrue(self.state.verify()["valid"])

    def test_no_approval_for_bad_structure(self):
        out = self.gateway.handle(request("tools/call", params={"name": "write_demo", "arguments": []}))
        self.assertEqual(out["error"]["code"], -32602)

    def test_invalid_request_id(self):
        out = self.gateway.handle(request("ping", id_=True))
        self.assertEqual(out["error"]["code"], -32600)

    def test_unknown_method_default_deny(self):
        self.assertEqual(self.gateway.handle(request("experimental/run"))["error"]["message"], "method_not_allowed")

    def test_too_large_arguments(self):
        out = self.gateway.handle(request("tools/call", params={"name": "echo_safe", "arguments": {"message": "x" * 70000}}))
        self.assertEqual(out["error"]["message"], "arguments_too_large")


class TestEndToEnd(unittest.TestCase):
    def test_subprocess_real_stdio_and_approval_persistence(self):
        with tempfile.TemporaryDirectory() as tmp:
            state_dir = Path(tmp) / "state"
            output = Path(tmp) / "side-effect.txt"
            env = {**os.environ, "PYTHONPATH": str(ROOT / "src"), "CATL_DEMO_OUTPUT": str(output)}
            command = [sys.executable, "-m", "catl", "run", "--config", str(ROOT / "examples/policy.json"),
                       "--state-dir", str(state_dir), "--allow-unsandboxed", "--pass-env", "CATL_DEMO_OUTPUT", "--", sys.executable, str(ROOT / "examples/mock_server.py")]
            def transact(msgs):
                payload = "".join(json.dumps(x) + "\n" for x in msgs).encode()
                proc = subprocess.run(command, input=payload, capture_output=True, env=env, timeout=15)
                self.assertEqual(proc.returncode, 0, proc.stderr.decode(errors="replace"))
                return [json.loads(x) for x in proc.stdout.decode().splitlines()]
            init = request("initialize", id_=1, params={"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "test", "version": "1"}})
            safe = request("tools/call", id_=3, params={"name": "echo_safe", "arguments": {"message": "hello from real child"}})
            sensitive = request("tools/call", id_=4, params={"name": "write_demo", "arguments": {"message": "controlled"}})
            from catl.crypto import get_or_create_key
            trusted_state = State(state_dir / 'audit.sqlite3', get_or_create_key(state_dir / 'audit.key'))
            self.assertFalse(trusted_state.controls()['gateway_enabled'])
            trusted_state.set_feature('gateway_enabled', True, 'test-bootstrap')
            first = transact([init, request("tools/list", id_=2), safe, sensitive])
            self.assertEqual(len(first), 4)
            self.assertIn("result", first[0]); self.assertEqual(len(first[1]["result"]["tools"]), 2)
            self.assertEqual(first[2]["result"]["content"][0]["text"], "hello from real child")
            self.assertEqual(first[3]["error"]["message"], "human_approval_required")
            self.assertFalse(output.exists())
            state = State(state_dir / "audit.sqlite3", (state_dir / "audit.key").read_bytes())
            self.assertTrue(state.decide(first[3]["error"]["data"]["approval_id"], "human", True))
            second = transact([init, sensitive])
            self.assertIn("result", second[1]); self.assertEqual(output.read_text(), "controlled\n")
            third = transact([init, sensitive])
            self.assertEqual(third[1]["error"]["message"], "human_approval_required")
            self.assertTrue(state.verify()["valid"])
            self.assertGreaterEqual(state.verify()["count"], 6)
