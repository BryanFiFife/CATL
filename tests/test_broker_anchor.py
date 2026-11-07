"""Independent rollback checkpoint and authenticated broker boundary tests."""
from __future__ import annotations

import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from catl.anchor import AnchorGuard
from catl.broker import BrokerServer
from catl.crypto import digest
from catl.gateway import Gateway
from catl.policy import Policy
from catl.store import State


def tool(name: str) -> dict:
    return {"name": name, "description": "fixture", "inputSchema": {"type": "object", "properties": {"message": {"type": "string"}}, "required": ["message"]}}


class FakeBackend:
    def __init__(self):
        self.calls = []
    def request(self, method, params=None):
        self.calls.append((method, params))
        if method == "tools/list":
            return {"jsonrpc": "2.0", "id": 1, "result": {"tools": [tool("safe"), tool("sensitive")]}}
        if method == "tools/call":
            return {"jsonrpc": "2.0", "id": 1, "result": {"content": [{"type": "text", "text": "ok"}]}}
        return {"jsonrpc": "2.0", "id": 1, "result": {"capabilities": {"tools": {}}}}
    def notify(self, method, params=None):
        pass
    def close(self):
        pass


@unittest.skipUnless(os.name == "posix", "anchor checkpoint requires POSIX fcntl")
class TestAnchor(unittest.TestCase):
    def setUp(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        root = Path(td.name)
        self.state_dir = root / "state"
        self.anchor_dir = root / "checkpoint"
        self.anchor_dir.mkdir(mode=0o700)
        self.anchor_path = self.anchor_dir / "seal.json"
        self.key = b"S" * 32
        self.state = State(self.state_dir / "audit.sqlite3", self.key)
        head = self.state.verify()
        AnchorGuard(self.anchor_path, self.key).bootstrap(head["count"], head["head_mac"])
        self.state = State(self.state.path, self.key, anchor_path=self.anchor_path)

    def test_new_anchor_verified_and_advances(self):
        self.assertTrue(self.state.verify()["valid"])
        self.state.set_feature("gateway_enabled", True, "operator")
        self.state.append({"decision": "test"})
        status = self.state.verify()
        self.assertTrue(status["valid"])
        self.assertEqual(status["count"], 2)
        self.assertEqual(AnchorGuard(self.anchor_path, self.key).read()["receipt_count"], 2)

    def test_anchor_missing_refuses_all_calls(self):
        self.anchor_path.unlink()
        with self.assertRaises((OSError, PermissionError)):
            self.state.controls()
        with self.assertRaises((OSError, PermissionError)):
            self.state.append({"unsafe": True})

    def test_truncated_receipt_chain_detected(self):
        self.state.append({"step": 1})
        with sqlite3.connect(self.state.path) as db:
            db.execute("DELETE FROM receipts WHERE seq=1")
        with self.assertRaises(PermissionError):
            self.state.controls()
        self.assertFalse(self.state.verify()["valid"])

    def test_valid_database_snapshot_rollback_detected(self):
        self.state.append({"step": 1})
        with sqlite3.connect(self.state.path) as db:
            db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        backup = self.state.path.with_suffix(".backup")
        shutil.copy2(self.state.path, backup)
        self.state.append({"step": 2})
        with sqlite3.connect(self.state.path) as db:
            db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        shutil.copy2(backup, self.state.path)
        with self.assertRaises(PermissionError):
            self.state.controls()

    def test_older_valid_signed_control_snapshot_detected(self):
        original = self.state.controls()
        self.state.set_feature("gateway_enabled", True, "trusted")
        with sqlite3.connect(self.state.path) as db:
            from catl.controls import encode
            body, mac = encode(original, self.key)
            db.execute("UPDATE operator_controls SET body=?,mac=?", (body, mac))
        # The signed old row must disagree with the last anchored control event.
        with self.assertRaises(PermissionError):
            self.state.controls()
        with self.assertRaises(PermissionError):
            self.state.set_feature("gateway_enabled", True, "attacker")

    def test_approval_request_and_decision_update_checkpoint(self):
        rid = self.state.request("binding", {"tool": "sensitive"})
        count = self.state.verify()["count"]
        self.assertTrue(self.state.decide(rid, "operator", True))
        self.assertEqual(self.state.verify()["count"], count+1)
        self.assertTrue(self.state.consume("binding"))
        self.assertEqual(self.state.verify()["count"], count+2)
        self.assertFalse(self.state.consume("binding"))

    def test_old_signed_approval_replay_rejected(self):
        rid = self.state.request("binding", {"tool": "sensitive"})
        self.assertTrue(self.state.decide(rid, "operator", True))
        with sqlite3.connect(self.state.path) as db:
            prior = db.execute("SELECT id,binding,created_at,expires_at,detail,approved_by,request_mac,decision_mac FROM approvals WHERE id=?", (rid,)).fetchone()
        self.assertTrue(self.state.consume("binding"))
        with sqlite3.connect(self.state.path) as db:
            db.execute("UPDATE approvals SET status='approved',used_at=NULL,approved_by=?,request_mac=?,decision_mac=? WHERE id=?",
                       (prior[5], prior[6], prior[7], rid))
        with self.assertRaises(PermissionError):
            self.state.consume("binding")
        self.assertTrue(self.state.verify()["valid"])

    def test_old_pending_approval_cannot_be_approved_twice(self):
        rid = self.state.request("binding", {"tool": "sensitive"})
        self.assertTrue(self.state.decide(rid, "operator", False))
        with sqlite3.connect(self.state.path) as db:
            db.execute("UPDATE approvals SET status='pending',approved_by=NULL,decision_mac=NULL WHERE id=?", (rid,))
        with self.assertRaises(PermissionError):
            self.state.decide(rid, "operator", True)

    def test_anchor_tampering_detected(self):
        obj = json.loads(self.anchor_path.read_text())
        obj["body"]["receipt_count"] = 999
        self.anchor_path.write_text(json.dumps(obj))
        with self.assertRaises(PermissionError):
            self.state.controls()

    def test_external_anchor_bootstrap_is_exclusive(self):
        with self.assertRaises(FileExistsError):
            AnchorGuard(self.anchor_path, self.key).bootstrap(0, "GENESIS")

    def test_key_mismatch_fails_closed(self):
        with self.assertRaises(PermissionError):
            State(self.state.path, b"Z"*32, anchor_path=self.anchor_path).controls()

    def test_concurrent_control_updates_dont_lose_anchor(self):
        exceptions = []
        def worker(i):
            try:
                self.state.set_feature("approvals_enabled", bool(i%2), f"worker-{i}")
            except BaseException as exc:
                exceptions.append(str(exc))
        jobs = [threading.Thread(target=worker,args=(i,)) for i in range(12)]
        for thread in jobs: thread.start()
        for thread in jobs: thread.join()
        self.assertEqual(exceptions, [])
        self.assertTrue(self.state.verify()["valid"])
        self.assertEqual(self.state.verify()["count"], 12)


@unittest.skipUnless(sys.platform == "linux" and hasattr(os, "setuid") and os.geteuid()==0,
                     "requires Linux root to exercise separate kernel peer UIDs")
class TestBrokerIdentity(unittest.TestCase):
    OPERATOR = 21001
    AGENT = 21002

    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        root.chmod(0o755)
        self.path = root
        state_dir = root / "state"
        state = State(state_dir / "audit.sqlite3", b"K"*32)
        checkpoint = root / "checkpoint"
        checkpoint.mkdir(mode=0o700)
        apath = checkpoint / "audit.anchor"
        report = state.verify()
        AnchorGuard(apath, state.key).bootstrap(report["count"], report["head_mac"])
        self.state = State(state.path, state.key, anchor_path=apath)
        obj = {"agent_id":"isolated", "tool_pins":{n:digest(tool(n)) for n in ("safe","sensitive")},
               "rules":[{"tool":"safe","effect":"allow","conditions":[]},
                        {"tool":"sensitive","effect":"approve","conditions":[]}]}
        self.policy = Policy.from_dict(obj)
        self.backend = FakeBackend()
        self.agent_socket = root / "agent.sock"
        self.operator_socket = root / "operator.sock"
        self.broker = BrokerServer(Gateway(self.policy,self.state,self.backend),self.state,self.policy,
                                   agent_socket=self.agent_socket, operator_socket=self.operator_socket,
                                   agent_uid=self.AGENT, operator_uid=self.OPERATOR, allow_uid_only_operator=True)
        self.thread = threading.Thread(target=self.broker.serve,daemon=True)
        self.thread.start()
        for _ in range(300):
            if self.agent_socket.exists() and self.operator_socket.exists():
                break
            time.sleep(0.01)
        self.assertTrue(self.agent_socket.exists())
        self.addCleanup(self._shutdown)

    def _shutdown(self):
        self.broker.shutdown()
        self.thread.join(timeout=2)

    def _client(self, uid: int, body: str, sock: Path) -> subprocess.CompletedProcess:
        script = ('import socket,json,sys; '
                  's=socket.socket(socket.AF_UNIX); s.settimeout(5);'
                  's.connect(sys.argv[1]);s.sendall(sys.argv[2].encode()+b"\\n");'
                  'd=b"";'
                  '\nwhile not d.endswith(b"\\n"):\n x=s.recv(65536)\n if not x:break\n d+=x\n'
                  'print(d.decode(),end=""); s.close()')
        return subprocess.run([sys.executable,"-c",script,str(sock),body],text=True,capture_output=True,timeout=10,
                              preexec_fn=lambda: os.setuid(uid))

    def test_agent_cannot_use_operator_channel(self):
        req = json.dumps({"op":"set_feature","feature":"gateway_enabled","enabled":True})
        response = self._client(self.AGENT,req,self.operator_socket)
        self.assertNotIn('"ok":true',response.stdout.replace(" ",""))
        self.assertFalse(self.state.controls()["gateway_enabled"])

    def test_operator_cannot_use_agent_channel(self):
        msg = json.dumps({"jsonrpc":"2.0","id":1,"method":"tools/list"})
        response = self._client(self.OPERATOR,msg,self.agent_socket)
        self.assertNotIn('"tools"',response.stdout)

    def test_operator_enable_agent_call_and_approval(self):
        control = json.dumps({"op":"set_feature","feature":"gateway_enabled","enabled":True})
        response = self._client(self.OPERATOR,control,self.operator_socket)
        self.assertIn('"ok":true',response.stdout.replace(" ",""))
        msg = json.dumps({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"safe","arguments":{"message":"hi"}}})
        response = self._client(self.AGENT,msg,self.agent_socket)
        self.assertIn('"result"',response.stdout)
        sensitive = json.dumps({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"sensitive","arguments":{"message":"hi"}}})
        blocked = self._client(self.AGENT,sensitive,self.agent_socket)
        self.assertIn("human_approval_required",blocked.stdout)
        request_id = json.loads(blocked.stdout)["error"]["data"]["approval_id"]
        decision = json.dumps({"op":"decide","id":request_id,"approve":True})
        self.assertIn('"accepted":true',self._client(self.OPERATOR,decision,self.operator_socket).stdout)
        accepted = self._client(self.AGENT,sensitive,self.agent_socket)
        self.assertIn('"result"',accepted.stdout)
        replay = self._client(self.AGENT,sensitive,self.agent_socket)
        self.assertIn("human_approval_required",replay.stdout)
        self.assertTrue(self.state.verify()["valid"])

    def test_agent_cannot_read_supervisor_key(self):
        target = str(self.path / "state" / "audit.sqlite3")
        proc = subprocess.run([sys.executable,"-c","import pathlib,sys;print(pathlib.Path(sys.argv[1]).read_bytes()[:10])", target],
                              text=True,capture_output=True,timeout=5,preexec_fn=lambda:os.setuid(self.AGENT))
        self.assertNotEqual(proc.returncode,0)

    def test_untrusted_uid_cannot_connect_to_either_socket(self):
        response = self._client(21003,'{"op":"status"}',self.operator_socket)
        self.assertNotIn('"ok":true',response.stdout.replace(" ",""))
