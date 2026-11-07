import os
import sqlite3
from contextlib import closing
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from catl.store import State, binding_hash


class TestState(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = Path(self.tmp.name) / "audit.db"
        self.key = b'z' * 32
        self.state = State(self.db, self.key)

    def test_empty_chain(self):
        self.assertEqual(self.state.verify()["head_mac"], "GENESIS")

    def test_chain_normal(self):
        self.state.append({"decision": "deny"})
        self.state.append({"decision": "allow"})
        self.assertEqual(self.state.verify()["count"], 2)
        self.assertTrue(self.state.verify()["valid"])

    def test_body_tampering_detected(self):
        self.state.append({"decision": "deny"})
        with closing(sqlite3.connect(self.db)) as db:
            db.execute("UPDATE receipts SET body=? WHERE seq=1", ('{"decision":"allow"}',))
            db.commit()
        self.assertFalse(self.state.verify()["valid"])

    def test_reorder_detected(self):
        self.state.append({"a": 1}); self.state.append({"a": 2})
        with closing(sqlite3.connect(self.db)) as db:
            db.execute("UPDATE receipts SET seq=10 WHERE seq=1")
            db.commit()
        self.assertFalse(self.state.verify()["valid"])

    def test_wrong_key_detected(self):
        self.state.append({"decision": "deny"})
        other = State(self.db, b'y' * 32)
        self.assertFalse(other.verify()["valid"])

    def test_id_unique(self):
        b = binding_hash("agent", "tool", {}, "p", "q")
        ids = {self.state.request(f"{b}-{i}", {"agent": "a", "tool": "t", "arguments": {"index": i}}) for i in range(30)}
        self.assertEqual(len(ids), 30)

    def test_approval_one_shot(self):
        req = self.state.request("binding", {"tool": "x"})
        self.assertTrue(self.state.decide(req, "admin", True))
        self.assertTrue(self.state.consume("binding"))
        self.assertFalse(self.state.consume("binding"))

    def test_rejection_never_consumed(self):
        req = self.state.request("binding", {"tool": "x"})
        self.assertTrue(self.state.decide(req, "admin", False))
        self.assertFalse(self.state.consume("binding"))

    def test_approval_not_reusable_other_binding(self):
        req = self.state.request("request-A", {"tool": "x"})
        self.state.decide(req, "admin", True)
        self.assertFalse(self.state.consume("request-B"))
        self.assertTrue(self.state.consume("request-A"))

    def test_duplicate_approve_denied(self):
        req = self.state.request("bind", {"tool": "x"})
        self.assertTrue(self.state.decide(req, "admin", True))
        self.assertFalse(self.state.decide(req, "admin", True))

    def test_expired_request_cannot_approve(self):
        req = self.state.request("bind", {"tool": "x"})
        with closing(sqlite3.connect(self.db)) as db:
            db.execute("UPDATE approvals SET expires_at=0 WHERE id=?", (req,))
            db.commit()
        self.assertFalse(self.state.decide(req, "admin", True))
        self.assertFalse(self.state.consume("bind"))

    def test_pending_exposes_details_only_to_local_operator(self):
        req = self.state.request("bind", {"tool": "x", "arguments": {"amount": 35}})
        rows = self.state.list_pending()
        self.assertEqual(rows[0]["id"], req)
        self.assertEqual(rows[0]["detail"]["arguments"]["amount"], 35)

    def test_concurrent_one_shot(self):
        req = self.state.request("binding", {"tool": "x"})
        self.state.decide(req, "admin", True)
        with ThreadPoolExecutor(max_workers=16) as pool:
            results = list(pool.map(lambda _: self.state.consume("binding"), range(32)))
        self.assertEqual(sum(results), 1)

    def test_concurrent_receipts(self):
        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(lambda i: self.state.append({"i": i}), range(50)))
        self.assertTrue(self.state.verify()["valid"])
        self.assertEqual(self.state.verify()["count"], 50)

    def test_approval_ttl_restricted(self):
        with self.assertRaises(ValueError): self.state.request("b", {"tool": "x"}, ttl=3601)

    def test_approval_detail_bounded(self):
        with self.assertRaises(ValueError): self.state.request("b", {"secret": "X" * 20000})

    @unittest.skipUnless(os.name == "posix", "POSIX permissions")
    def test_database_permissions(self):
        self.assertEqual(self.db.stat().st_mode & 0o777, 0o600)

    @unittest.skipUnless(os.name == "posix", "POSIX permissions")
    def test_world_readable_db_rejected(self):
        self.db.chmod(0o644)
        with self.assertRaises(PermissionError): State(self.db, self.key)

    def test_approval_same_request_deduplicated(self):
        detail = {"tool": "x", "arguments": {"x": 2}}
        a = self.state.request("same", detail)
        b = self.state.request("same", detail)
        self.assertEqual(a, b)

    def test_approval_queue_bounded(self):
        for i in range(100):
            self.state.request(f"unique-{i}", {"tool": "t"})
        with self.assertRaises(ValueError):
            self.state.request("overflow", {"tool": "t"})
